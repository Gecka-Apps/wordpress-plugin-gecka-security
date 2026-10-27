# Gecka Security for developers

How the protections sit on the hooks of WordPress, how the address of the
visitor is read, the filters and actions, what the plugin stores, and how to
work on it. What a site administrator needs is in [README.md](../README.md).

## The login gate

Every login that fails on its login or its password counts for the address
it came from: the login form of WordPress, `wp_login_form()`, a form of a
theme or a plugin calling `wp_signon()`, WooCommerce, XML-RPC, and the REST
API with an application password. At the maximum of failures within the
window, the address is locked out: its logins are refused before the
password is checked, and so are its registrations and password resets.
Lockouts count within a longer window; at their maximum the lockout is the
long one, and the count starts over.

An empty form, a refused captcha (Privacy CAPTCHA for Cap) and a refused
antispam check (Gecka Antispam) do not count: their error codes are in
`gecka_security_ignored_errors`. A successful login does not clear the
failures: on a site open to registration, a bot owning one account would
log into it between two runs of guesses.

A failure is counted in one SQL statement, so that parallel requests all
count and one of them starts the lockout. A failure while the address is
locked out counts for nothing, and a lockout in place is never shortened:
requests already past the gate when it started cannot turn a long lockout
into a short one. A failed login on a reserved name weighs double whether an
account carries it or not, since a lockout coming later would tell.

The gate sits on two hooks:

- `wp_authenticate_user` fires once the account is found, before the
  password is checked: a locked-out address is refused there, ahead of a
  captcha or a second factor.
- `authenticate` at `PHP_INT_MAX - 1` (`Login::GATE_PRIORITY`) runs after
  every handler, those of WordPress (the password and the application
  passwords at 20, the cookie at 30) and those of other plugins, an LDAP or
  single sign-on one included. It refuses what the first hook never saw, a
  login on an account that does not exist or an application password, and
  it beats any handler that would have let the login in. It has to come
  after them: the password handler of WordPress ignores an error it is given
  and checks the password anyway.

An application password on the REST API takes neither hook: WordPress checks
it from `determine_current_user` and reports a failure through
`application_password_failed_authentication`. The gate unhooks that check
for a locked-out address, and the failures are counted from the action. On
XML-RPC, an application password refused fires that action and then
`wp_login_failed`: the attempt is counted once, from the second.

Registrations are gated on `registration_errors`,
`woocommerce_registration_errors` and, on a network, `wpmu_validate_user_signup`
outside the admin, which validates the accounts an administrator creates
too. Password resets are gated on `lostpassword_post`.

The checks on the hooks other plugins share run at priority 5
(`Integration::PRIORITY`), so that a refusal comes before a captcha is
verified or a remote service called.

## The address of the visitor

`REMOTE_ADDR` is the only value the server vouches for. A forwarding header
(`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`) is read only when the
settings name it and the request comes from one of the trusted proxies
(`ClientIp::read()`). `X-Forwarded-For` is read from the right, past the
trusted hops. Behind Cloudflare, the setting to use is `CF-Connecting-IP`
with the published Cloudflare ranges as trusted proxies: a Cloudflare
Worker, which anyone can run, reaches the site from those ranges and writes
what it likes in `X-Forwarded-For`. When no address can be trusted, the
loopback included, nothing is locked out, and Site Health says so.

The loopback given by a trusted proxy is another matter
(`ClientIp::onServer()`): the visitor browses from the machine of the
server, as a developer whose hosts file points the site at it, and is the
only one seen under it. The warning of the plugin pages stays silent, Site
Health says the visitors are told apart, and the settings page says that
visitor is never locked out.

A private address read while no proxy is trusted (`ClientIp::behindProxy()`)
is the address of a proxy every visitor comes through: Site Health flags it
as critical, and the "Add my address" button refuses it, since on the
safelist it would let everyone in. That button adds the key the address is
watched under, the /64 of an IPv6 one, whose last bits the system rotates. A
trusted proxy or safelist network wider than a /8 for IPv4 or a /16 for IPv6
is refused: a few of them cover every address.

`GECKA_SECURITY_SAFELIST`, a string of addresses and networks separated by
commas, semicolons or blanks, adds to the safelist from wp-config.php.

## Blocklist and countries

The gate of `Login` refuses for good, with the error `gecka_security_refused`
(`Login::REFUSED`) and one message whatever the reason, the addresses and
networks of `blocklist`, and, with `countries_mode` at `allow` or `deny`,
the addresses whose country, as Gecka Geolocation tells it, is not in
`countries` or is in it (`Access::refusal()`). An address whose country is
unknown is never refused for it, so that a missing database never refuses
everyone. Without Gecka Geolocation, the countries and the new network alert
are shown disabled on the settings page, their values kept for when it comes
back. The safelist and an address the server cannot vouch for pass, as for a
lockout.

The same hooks as the lockouts carry it, the brute-force protection on or
off: the login, XML-RPC, application passwords, registrations and password
resets. A refusal is not a failure (`gecka_security_refused` is among the
ignored codes). The refusals of one address, reason and login within the
hour fold into one row of kind `refused`, detail `refused.address` or
`refused.country` with the country; the login is kept only when it names an
account or a reserved name, so that a bot varying the login makes one row.

`Settings::sanitize()` drops a blocklist network wider than a /8 or a /16 or
holding the address of the administrator saving, keeps the previous
countries when the new ones would refuse that address, unless the safelist
holds it, and leaves the countries unchecked when allow names none. The
address of the administrator is read as the source and the trusted proxies
being saved read it.

## Account enumeration

Each closed by a setting:

- the archive of an author: a 404 to visitors, and `?author=1` does not
  redirect to it
- the `/wp/v2/users` route of the REST API: a 401 to visitors; off by
  default, some plugins read the route to show content
- the author in the oEmbed data of a post
- the users in the sitemap

A visitor, for the first two, is anyone without `edit_posts`: on a site open
to registration a bot becomes a subscriber in one form, so being logged in
proves nothing. The accounts that can write posts keep the archives and the
route, as the block editor lists the authors to them; the capability is the
`gecka_security_enumeration_capability` filter. An account keeps its own
archive and its own routes, `/wp/v2/users/me` and `/wp/v2/users/{id}`, which
the profile screen calls for the application passwords. A refusal to a
logged-in account carries its login in the journal: an address can only be
watched, an account can be deleted.

The messages of a failed login get one text whether the login or the
password was wrong, on the login form, WooCommerce and XML-RPC; those of a
password reset one text whether the account exists or not. A reset asked on
wp-login.php for an unknown account is sent to the same
`checkemail=confirm` screen as a known one, since the error page itself
would tell. The lost-password form of WooCommerce gets the same treatment:
an unknown account, error free so far, is sent to its `reset-link-sent`
confirmation from `lostpassword_post`, at priority 99, before WooCommerce
shows its own error.

What remains is time: `retrieve_password()` sends the mail before answering,
so a known account answers slower than an unknown one, a limit of WordPress
the plugin does not paper over (deferring the mail would hang the resets on
WP-Cron). The messages of a registration still say when a login or an email
address is taken.

## XML-RPC, pingbacks and trackbacks

`xmlrpc_disabled`, off by default, answers every call of `xmlrpc.php` with a
403 on `init`, sets `xmlrpc_enabled` to false and drops the `X-Pingback`
header. A bot tries hundreds of passwords in one call through
`system.multicall`; Jetpack and the mobile app need the endpoint.

`pingback_disabled`, on by default, takes `pingback.ping` and
`pingback.extensions.getPingbacks` out of `xmlrpc_methods` and drops the
`X-Pingback` header: a pingback makes the server fetch an address a stranger
chose, the usual way to bounce a site into a denial of service or to probe
the network behind it.

`trackback_disabled`, on by default, answers `wp-trackback.php` on
`pre_trackback_post`, before it looks the post up or fetches the source,
with a 403 and the error response of the protocol.

## Request limits

`limit_requests`, on by default, counts the password resets and the
registrations of an address over an hour, in a counter keyed by its network,
and refuses them past `resets_per_hour` and `registrations_per_hour` (5
each) on `lostpassword_post`, `registration_errors`,
`woocommerce_registration_errors` and `wpmu_validate_user_signup`. The
counters live in the options table and are counted up in one statement. On
wp-login.php the limit applies before the account is looked up, and sends a
known and an unknown account to the same confirmation screen, since an error
for one and not the other would tell them apart. The first refusal of the
hour goes in the journal, every one in the statistics; an address that
cannot be read, or on the safelist, is never limited.

## Breached passwords

`pwned_passwords`, off by default since switching it on is the consent to
reach a third party, asks the Pwned Passwords range API of Have
I Been Pwned: the first five characters of the SHA-1 of the password go out
with the `Add-Padding` header, the suffixes come back, the comparison is
made here. The user agent names the plugin and its version, nothing of the
site.

A breached password is refused on `user_profile_update_errors`,
`validate_password_reset`, `woocommerce_registration_errors` and
`woocommerce_save_account_details_errors`. On `wp_authenticate_user`, after
the brute-force gate and only once the password proved right, a login is
checked once a month per account, the verdict kept in the
`gecka_security_pwned` user meta with a fingerprint of the stored hash: a
breached one is recorded in the journal and the user sees a warning on the
dashboard, the profile and the screens of the plugin, or on the WooCommerce
account screen, until they change it. The
service silent, the password goes through. Site Health asks the service from
the server, as an asynchronous test.

## Security headers and file editor

`security_headers`, on by default, sends `X-Content-Type-Options: nosniff`,
`Referrer-Policy: strict-origin-when-cross-origin`, `X-Frame-Options:
SAMEORIGIN` and `Content-Security-Policy: frame-ancestors 'self'` on the
front, the admin and the login screen, and leaves the two framing headers off
the embeds, which other sites are meant to frame. `hsts`, off by default,
adds `Strict-Transport-Security: max-age=15552000` over HTTPS only.

A header the server or another plugin already sent is left alone: those PHP
sees through `headers_list()`, and those the web server adds on its own,
which PHP never sees. For those, a probe of the home page records their
names in the autoloaded option `gecka_security_server_headers`:

- the probe carries a token good for one request in `gecka-security-probe`
  (transient `gecka_security_probe`, a minute at most), so that the plugin
  adds none of its own headers to that response and nobody else can have a
  page served without them
- while the plugin sends headers, the response must carry the token back in
  an `X-Gecka-Security-Probe` header, or the probe keeps what it recorded
  last, since a page cache or a second probe would show the headers of the
  plugin as the server's
- it runs from the Site Health test of the headers, when the settings of the
  headers are saved, and from the daily task
- a header a CDN adds in front is not seen

`file_edit_disabled`, on by default, answers `do_not_allow` to
`edit_plugins`, `edit_themes` and `edit_files` through `map_meta_cap`, as
`DISALLOW_FILE_EDIT` does; installs and updates stay possible.

## Logins from a new network

With `alert_new_network` on (the default) and Gecka Geolocation active, a
login of an account that manages the site (`manage_options`, or
`manage_network_options` on a network, or on any site of the network the
account belongs to; filter `gecka_security_watch_networks`), by password
(`wp_login`) or application password
(`application_password_did_authenticate`), is looked up. A network, by
autonomous system number, the account never logged in from is mailed to the
account, in its language, with the network, the country, the address and
the way in.

The networks are kept in the user meta `gecka_security_networks`, the 20
last seen, a known one written again once a day at most since an integration
authenticates on every request. Each entry records whether its alert went
out: a mail that failed is tried again on the next login from that network,
once the day is over. The first login of an account only learns its
network, and an address with no network known teaches nothing. The meta goes
with the personal data export and erasure.

## Login alerts

With `alert_logins` on (off by default), every account is mailed at each of
its logins by password (`wp_login`, priority 6), in its language, with the
date, the address, the operating system the user agent names and, with Gecka
Geolocation, the country and the network, and a link to the lost password
form, which WooCommerce points at its own. Application passwords are left
out, an integration authenticating on every request. A login the new network
alert mailed in the same request gets no second mail
(`NewNetworks::alerted()`). The filter `gecka_security_alert_login` keeps the
mails to some accounts. Nothing is stored.

## Reserved names

The logins of the `reserved_names` setting are added to
`illegal_user_logins`: no account can be registered or created with them,
through the registration form, the users screen or WP-CLI alike. A failed
login on one of them counts double whether an account carries it or not,
and is recorded as a reserved name when none does.

## Journal

The journal keeps every event with the address, the way in, a detail, and
the login tried when it names an account or a reserved name: what names
neither may be a password typed in the wrong field, and is kept only with
`log_unknown_logins` on (off by default). Events are kept `events_days`
days, and 10,000 rows of each kind at most (filter
`gecka_security_max_entries`), so that a flood of one kind never pushes
another out.

- **Successful logins**, with `log_logins` on (the default): `wp_login` and
  `application_password_did_authenticate`, with the roles of the account and
  the name of the application password. The logins of one application
  password within the hour fold into one counted row, since every request of
  an integration authenticates.
- **Last login**, with `last_login` on (the default): `wp_login` writes the
  time in user meta `gecka_security_last_login` (`LastLogin::META`), shown in
  a sortable column of the users list, that of the network admin too. The
  sort joins the meta on its key in `pre_user_query`, so the accounts without
  one stay in the list, last when the most recent come first. Application
  passwords do not count.
- **Lockouts**: the refusals of one lockout fold into one row, counted, with
  the time of the last, matched on the key the address is watched under (the
  /64 for IPv6, column `net`, indexed with the kind) while the row keeps the
  address of the first refusal.
- **Enumeration**: the refusals of the author archives or of the users
  routes fold into one counted row per key of the address, account and way
  in within the hour, whatever the target asked (`Events::bumpScan()`): a
  scan of `?author=1` to `?author=500` is one row, which keeps the first
  target. The statistics count every refusal.
- **Accounts**, with `log_accounts` on (the default): `user_register`,
  `set_user_role`, `add_user_role` and `remove_user_role` (the two last held
  back until the request ends, since WordPress adds and removes roles on its
  way to setting one), `profile_update` for an email address or a password
  changed, `after_password_reset`, `deleted_user`, and on a network
  `granted_super_admin` and `revoked_super_admin`, each with who did it: the
  account logged in, WP-CLI or nobody. With `alert_admins` on (the default),
  an account created as administrator, promoted to it, or granted super
  administrator, is mailed to the address of the site.

The login is kept as typed and, in lower case, in an indexed `login` column
that the filters, the export and the erasure match on; the dropdown of
logins of the journal is grouped once every ten minutes (transient
`gecka_security_logins`). The search takes an address, a login, or the /64
key a lockout of an IPv6 network carries.

The detail of a row is a code with its parameters as JSON, worded by
`Events::describe()` in the language of the reader:

| Code | Parameters |
|---|---|
| `lockout.long`, `lockout.short` | |
| `enumeration.lost_password` | |
| `refused.address`, `refused.country` | The country |
| `login.application_password` | The roles, the name of the application password |
| `breached.seen` | The count |
| `limited.reset`, `limited.register` | The limit |
| `account.created`, `account.role_set`, `account.role_set_none`, `account.role_added`, `account.role_removed`, `account.email`, `account.password`, `account.reset`, `account.deleted`, `account.super_admin_granted`, `account.super_admin_revoked` | The roles, the addresses, who did it |

The error codes of a failed login and the roles of a plain login stay as
free text.

## Statistics

The statistics keep daily counts by way in and by kind for `stats_days`
days, and draw the failures and the lockouts over the period: one chart for
the whole, then one per way in on the same scale once two ways saw events.

Below the first chart, the attempts (failed logins, reserved names, refusals
while locked out, addresses refused, enumeration, requests limited) or the
successful logins are counted by country, by network and by operating
system, on the `gecka_security_event` action: the system from the user
agent, which the client chooses, the country and the autonomous system from
Gecka Geolocation when it is active (`gecka_geolocation()`), with its flags,
the logos of the networks when its setting is on, and the credit its data
asks for. Once a day is over, the networks past the 200 most seen of that
day, for each kind of event, fold into one "other networks" row
(`Origins::foldNetworks()`, run by the daily task), so that an attack spread
over thousands of networks does not grow the table by as many rows a day.

The counters keep the code of the country and the number of the network with
the name of its organisation, never the address, for `stats_days` days like
the other counters; those of the successful logins go after `events_days`,
with the journal, since they tell where the people with an account connect
from.

## Admin

The statistics, the journal and the lockouts are pages of a `Security` menu
declared through [gecka/wp-admin-menu](https://github.com/Gecka-Apps/wp-admin-menu):
a menu other plugins share, each page made of the tabs the plugins bring, a
lone tab shown without a tab bar. Another plugin adds its tab to the
Statistics page with
`Menus::menu('security')->page('security-stats')->tab('my-plugin')`. The
settings stay under Settings > Security, rendered by the same library.

The admin classes are loaded under `is_admin()` only, and an integration only
when one of its settings is on. The tests and the Info section of Site
Health, and the exporter and the eraser of the personal data tools, are
hooked on every request, their classes loaded when they are asked: the
weekly check of WP-Cron and WP-CLI run outside the admin.

## Site Health

Site Health tests the address of the visitor (left out under WP-Cron and
WP-CLI, which have no visitor), the brute-force protection, the daily task,
the countries when the settings check some, the role of the registrations,
the admin forced over HTTPS, and, asked of the site itself after the page,
the breach service, the files and listings exposed (`readme.html`,
`license.txt`, the uploads directory) and the security headers the visitors
get, from the server or from the plugin. It describes the state of the
plugin in its Info tab.

## Privacy

The rows carrying the login or the email address of a person go out with the
personal data export of WordPress and away with its erasure, together with
the verdict kept on the password of their account, the date of its last
login and the networks it logged in from (`wp_privacy_personal_data_exporters`,
`wp_privacy_personal_data_erasers`). The match ignores the case of the
login, and the address goes out only with the logins the person made, since
an attempt on their login may be someone else's.

The erasure also takes the login of the person out of the changes they made
on other accounts (`Events::forgetActor()`): those rows belong to the journal
of the other accounts and stay, naming an erased account (`Accounts::ERASED`)
as who made the change.

A paragraph for the privacy policy is offered through
`wp_add_privacy_policy_content()`, worded after `log_logins`, `last_login`,
`log_unknown_logins`, `log_accounts`, `pwned_passwords`, `alert_new_network`
and `events_days` (`SettingsPage::PRIVACY_SETTINGS`): a save that changes
one of them says so in its notice, with a link to the policy guide.

## Multisite

The accounts of a network are shared by its sites, so the plugin works for
the whole network (`Scope`): one set of tables under the base prefix, the
settings in a network option, the transients and the counters of the
network, the journal noting the site of each event, the screens in the
network admin for the super administrators (`manage_network_options` by
default), the dashboard widget on the network dashboard, the daily task on
the main site, and the alerts mailed to the address of the network.

The plugin header says `Network: true`, so it is activated for the network,
never for one site; an activation asked for one site from WP-CLI is refused.
The settings form of the network admin posts to
`edit.php?action=gecka-security` and is saved on
`network_admin_edit_gecka-security`, since `options.php` does not exist
there.

## Filters and actions

| Hook | Kind | What for |
|---|---|---|
| `gecka_security_protect` | filter | Whether a protection is on: `bruteforce`, `author_archives`, `rest_users`, `oembed_author`, `sitemap_users`, `login_errors`, `xmlrpc_disabled`, `pingback_disabled`, `trackback_disabled`, `security_headers`, `hsts`, `file_edit_disabled`, `log_logins`, `last_login`, `log_unknown_logins`, `pwned_passwords`, `log_accounts`, `alert_admins`, `alert_new_network`, `alert_logins`, `limit_requests`. |
| `gecka_security_watch_networks` | filter | Whether a login from a new network is mailed to the account; receives the account. By default, the accounts that manage the site or the network. |
| `gecka_security_alert_login` | filter | Whether a login is mailed to the account, with `alert_logins` on; receives the account. True for every account by default. |
| `gecka_security_enumeration_capability` | filter | The capability an account needs to see the author archives and the users routes of the REST API, `edit_posts` by default. |
| `gecka_security_ignored_errors` | filter | The `WP_Error` codes a failed login is not counted for. |
| `gecka_security_event` | action | An event was recorded: type, address, login, way in, detail (a code such as `lockout.long` or `account.role_set`, or free text), parameters of the code. |
| `gecka_security_max_entries` | filter | Rows of each kind the journal keeps at most, 10,000. |
| `gecka_security_lockout` | action | An address was locked out: address, end as a timestamp, whether long, login tried. |
| `gecka_security_capability` | filter | The capability a screen asks for, `manage_options` for every one, `manage_network_options` on a network; receives the screen: `stats` (statistics, dashboard widget, the button resetting the statistics), `events` (journal, its deletions, the button clearing it), `lockouts` (lockouts page, releases), `settings` (settings tab, the safelist button and bulk action, the button restoring the defaults, the save of the network admin). Read on `init`, when the screens are declared: add the filter from a plugin or the `functions.php` of the theme. |

```php
// Count the refusals of a two-factor plugin as no guess.
add_filter('gecka_security_ignored_errors', fn(array $codes): array => [...$codes, 'two_factor_invalid']);

// Open the statistics to the editors, keep the journal and its addresses to administrators.
add_filter('gecka_security_capability', fn(string $capability, string $screen): string => $screen === 'stats' ? 'edit_posts' : $capability, 10, 2);

// Tell the administrator of a long lockout.
add_action('gecka_security_lockout', function (string $ip, int $until, bool $long): void {
    if ($long) {
        wp_mail(get_option('admin_email'), 'Long lockout', "$ip is locked out until " . wp_date('c', $until));
    }
}, 10, 3);
```

## Data

| What | Where |
|---|---|
| Events | `{prefix}gecka_security_events`, the base prefix on a network |
| Addresses watched: failures and lockouts | `{prefix}gecka_security_lockouts`, the base prefix on a network |
| Daily counters | `{prefix}gecka_security_stats`, the base prefix on a network |
| Daily counters by country, network and system | `{prefix}gecka_security_origins`, the base prefix on a network |
| Settings | option `gecka_security_settings`, autoloaded, a network option on a network |
| Versions of the plugin and of its tables | option `gecka_security_version`, a network option on a network |
| Security headers the web server sends on its own | option `gecka_security_server_headers`, autoloaded, a network option on a network |
| Hourly counters of the requests | options `gecka_security_req_*` of the main site, never autoloaded |
| Daily purge | event `gecka_security_purge`, on the main site of a network |
| Short-lived caches | transients `gecka_security_logins`, `gecka_security_probe`, `gecka_security_pwned_down`, of the network on a network |
| Screen options of the lists | user meta `gecka_security_events_per_page`, `gecka_security_lockouts_per_page`, and the hidden columns of the Journal and Lockouts lists |
| Verdict on the password of an account, networks it logged in from | user meta `gecka_security_pwned`, `gecka_security_networks` |

Deleting the plugin removes all of it, on every site of a network.

## Development

The plugin runs on PHP 8.2 and later; the tests need PHP 8.3, for Pest 4.

```sh
composer install
composer format          # Pint
composer lint:php        # Pint check, then PHPCS
composer analyse         # PHPStan
composer test            # Pest, WordPress on SQLite in .tests/
composer test:multisite  # the same on a network, in .tests/wordpress-multisite/
```

Translations, with WP-CLI:

```sh
composer i18n            # template, catalogs, .mo and .l10n.php, from the code
composer i18n:check      # what the CI runs: every string in the template, translated and compiled
```

WordPress loads the `.l10n.php` file before the `.mo` one; the `.mo` still
ships for the tools that read it, Loco Translate for one.

gecka/wp-admin-menu, which draws the screens, comes from
[Packagist](https://packagist.org/packages/gecka/), at the version
`composer.lock` pins.

## Package and release

What ships is what `.distignore` leaves: no tests, CI, tooling nor
`README.md`, and the dependencies without the dev ones. `bin/package <dir>`
copies it into a directory, from a tree whose `vendor/` was installed with
`composer install --no-dev`; `bin/zip <dir> <archive>` zips such a
directory under a `gecka-security/` top folder, as WordPress installs a
plugin from a zip; `bin/build [dir]` does both, into `builds/` by default.
`bin/changelog <version>` prints the changelog entry of a version from
`readme.txt`. `bin/check-version [version]` checks that the header of
`bootstrap.php`, `Plugin::VERSION` and the Stable tag of `readme.txt` agree,
and match the version given.

The GitHub workflows and the GitLab CI run the checks on PHP 8.3 to 8.5,
lint the syntax on 8.2, check the translations, and run Plugin Check on the
package.

WordPress.org reads the Stable tag in `trunk/readme.txt`, then shows the
`readme.txt` of `tags/<version>/`: a change to the page goes out with a
release. Banners, icons and screenshots of the page go in `.wordpress-org/`
(`icon.svg`, `icon-256x256.png`, `banner-772x250.png`,
`banner-1544x500.png`, `screenshot-1.png`...), published to the `assets`
directory of the SVN.

A release:

1. set the version in the header of `bootstrap.php`, in `Plugin::VERSION` and
   in the Stable tag of `readme.txt`, and add its changelog entry;
2. tag it `vX.Y.Z` and push the tag to GitHub and GitLab: once the checks
   passed, each makes the release of the tag, titled after the message of
   the tag, with the changelog entry and `gecka-security-X.Y.Z.zip`, the zip
   to install from the admin of WordPress (on GitLab, the zip sits in the
   package registry of the project);
3. start the publication by hand, on that tag: the "Publish on
   WordPress.org" workflow on GitHub (Actions, Run workflow, the tag as
   ref), or the `wordpress.org` job of the tag pipeline on GitLab.

Both check the versions and refuse a version WordPress.org already has, so
whichever runs second stops; then they copy the package to `trunk`,
`.wordpress-org/` to `assets`, and `trunk` to `tags/X.Y.Z`. They need the
WordPress.org account and its SVN password (Account & Security on
WordPress.org) as `SVN_USERNAME` and `SVN_PASSWORD`: secrets of the GitHub
repository, masked and protected variables on GitLab, where the `v*` tags
must then be protected.

The first version is not published this way: the zip of its release goes
through the submission form of WordPress.org, and the SVN repository exists
once the plugin is approved.

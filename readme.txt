=== Gecka Security ===
Contributors: gecka, ldinclaux
Tags: security, brute force, login, lockout, breached passwords
Requires at least: 6.8
Tested up to: 7.1
Requires PHP: 8.2
Stable tag: 1.2.0
License: GPL-3.0-or-later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Stops password guessing on every way in, keeps account names private and refuses breached passwords, with a journal. Runs on your server.

== Description ==

Any WordPress site exposed to the internet receives automated login attempts. Gecka Security locks out the addresses behind them, removes the places where WordPress discloses account names, and records what happens in a journal with statistics. It runs entirely on your server, sets no cookie and requires no external account. The defaults suit most sites.

= Brute-force protection =

A failed login counts for the address it came from, wherever it was typed: the login form, the login forms of themes and plugins, WooCommerce, XML-RPC and the REST API with application passwords. An address that fails 5 logins within an hour is locked out for 20 minutes: its logins, registrations and password resets are refused before any password is checked. An address locked out 4 times within 24 hours is then locked out for 24 hours. Every threshold is a setting.

* A failed login on a commonly targeted name such as `admin` counts double.
* Empty forms, refused captchas and refused antispam checks are not counted as attempts.
* IPv6 addresses are tracked by /64 network, so rotating addresses within a block does not reset the count.
* Addresses on the safelist are never locked out.

= Reliable visitor addresses =

Behind a reverse proxy, a load balancer or a CDN such as Cloudflare, the visitor address travels in a header anyone can forge. Gecka Security reads it only when it comes from a proxy you declare, so a bot can neither hide behind another address nor get someone else locked out. Site Health warns when every visitor shows up under the same address.

= Account names kept private =

Knowing the account names leaves an attacker only the passwords to guess. WordPress discloses them in several places, each of which the plugin can close:

* author archives, whose URL contains the login
* the users endpoint of the REST API (off by default, as some plugins rely on it to display content)
* the author in the oEmbed data of posts
* the users in the XML sitemap
* login errors that distinguish an unknown user from a wrong password
* password reset responses that reveal whether an account exists, on WordPress and WooCommerce

= Breached passwords =

Passwords found in known data breaches are refused when they are set or changed, and users who still log in with one are asked to change it. The check uses the Have I Been Pwned range API with k-anonymity: only the first five characters of a hash leave the server. It is off until an administrator switches it on.

= Blocklist and countries =

Addresses and networks on the blocklist are refused logins, registrations and password resets. With Gecka Geolocation, logins can be restricted to a list of countries, or refused from some. The settings reject any rule that would lock out the administrator saving it.

= Alerts =

* **New administrator**: an account created with the administrator role, or promoted to it, is reported by mail to the site address.
* **Login from a new network**: with Gecka Geolocation, an administrator who logs in from a network their account never used receives a mail with the network, the country and the address.
* **Every login** (off by default): each user receives a mail at each of their logins, with the date, the address, the system and, with Gecka Geolocation, the country and the network.

= Hardening =

* XML-RPC can be disabled entirely. It allows hundreds of password attempts in a single request; Jetpack and the WordPress mobile app need it.
* Pingbacks and trackbacks are disabled by default.
* The theme and plugin file editors are disabled by default, so a compromised administrator account cannot be used to write PHP on the server. Updates and installs are unaffected.
* Security headers are sent by default, except those your web server already sends. HSTS is available as an option.
* Password resets and registrations are limited to 5 per hour per address.
* No account can be created with a reserved name such as `admin`.

= Journal and statistics =

* **Journal**: failed logins, lockouts, refused requests, successful logins with the account roles, and account changes (creation, role, email, password, deletion) with who made them.
* **Last login** of each account in a sortable column of the users list, to spot the accounts nobody uses any more.
* **Statistics** over 7, 30, 90 or 365 days, with charts by entry point and, with Gecka Geolocation, the countries and networks the attempts come from.
* **Lockouts**: the addresses currently locked out, to release or add to the safelist.
* **Dashboard widget** summarising the last seven days.
* **Site Health tests** for the plugin's own configuration, and for what the site exposes: readme.html, a browsable uploads directory, an admin not forced over HTTPS, registrations open with a role above subscriber.

= Multisite =

On a network, the plugin is activated network-wide and configured from the network admin. Lockouts apply to every site, and the journal records which site each event occurred on.

= Works with =

* **Gecka Geolocation** locates the addresses on your server. It enables the country rules and the new network alert, and adds countries and networks to the journal, the alerts and the statistics.
* **Gecka Antispam** stops bots on the forms of the site without a captcha. A login it refuses is not counted as a failed password, and both plugins share the Security menu.

= Privacy =

No cookie is set. Visitor IP addresses are stored in the journal and purged after 30 days by default; the statistics contain none. Personal data is included in the WordPress export and erasure tools. A privacy policy paragraph is provided under Settings > Privacy.

= External services =

The breached-password check asks the Pwned Passwords API of Have I Been Pwned (https://haveibeenpwned.com/API/v3#PwnedPasswords), from the server, when a password is set or changed and, once a month per account at most, when a login succeeds with it, while the `pwned_passwords` setting is on. That setting is off by default: nothing is sent before an administrator switches it on. The request carries the first five characters of the SHA-1 hash of the password, with the padding the service offers, and nothing else: neither the password, nor the login, nor the address of the visitor. Site Health asks the service the same way to tell whether it answers. Terms of use: https://haveibeenpwned.com/API/v3#License, privacy policy: https://haveibeenpwned.com/Privacy.

The plugin also requests the home page of the site itself, from the server, to find which security headers the web server already sends and which files it exposes.

= Development =

The plugin is developed on GitHub, where bugs can be reported and changes suggested: https://github.com/Gecka-Apps/wordpress-plugin-gecka-security. Questions on using it are welcome in the support forum.

== Installation ==

1. Install the plugin from the plugins screen, or copy its folder into `wp-content/plugins/`.
2. Activate it. On a multisite network, activate it network-wide.
3. Behind a proxy, a load balancer or Cloudflare, declare the header and the trusted proxies under Settings > Security, then check Site Health.
4. Add the addresses of your office to the safelist.

== Frequently Asked Questions ==

= I locked myself out. =

The lockout expires after 20 minutes by default, and another administrator can release your address from Security > Lockouts. With shell access, `wp gecka-security unlock 203.0.113.5` releases one address and `wp gecka-security unlock` all of them. Networks listed in a `GECKA_SECURITY_SAFELIST` constant in wp-config.php are never locked out or refused, whatever the settings say.

= Every visitor is locked out at once, or no one ever is. =

The site sits behind a proxy and sees every visitor under its address. Site Health reports it as critical. Under Settings > Security, choose the header the proxy sends and list its address among the trusted proxies. Behind Cloudflare, choose CF-Connecting-IP and trust the address ranges Cloudflare publishes, not X-Forwarded-For: a Cloudflare Worker, which anyone can run, reaches the site from those ranges and can write any address in that header.

= Does it replace a captcha? =

No. A captcha keeps bots off a form; this plugin limits what an address can try, on every way in. Both work together, and Gecka Antispam stops bots on forms without a captcha.

= Who sees the journal and the statistics? =

Administrators: every screen asks for the manage_options capability, manage_network_options on a network. A developer can open a screen to another capability through the `gecka_security_capability` filter.

= Does it relocate the login page or add two-factor authentication? =

No. Those are better handled by dedicated plugins, and Gecka Security works alongside them.

== Screenshots ==

1. The statistics: failed logins, lockouts, refusals and successful logins over the period, with the chart of the failures and the lockouts.
2. Where the attempts come from: countries, networks and systems, with the flags and logos of Gecka Geolocation.
3. The journal: every event with its address, its origin, the login tried and the way in.
4. The addresses locked out right now, to release one by one or all at once.
5. The dashboard widget: the last seven days at a glance.
6. Logins: how many failures lock an address out, for how long, when a long lockout follows, and how many password resets and registrations an hour an address gets.
7. Addresses: where the visitor address comes from behind a proxy or a CDN, the safelist, the blocklist and the countries allowed or refused.
8. Accounts: the login names refused, passwords checked against known breaches, alerts on a new administrator, a login from a new network or every login.
9. Account enumeration: author archives, the REST users route, oEmbed and sitemaps, login error messages.
10. Exposed surface: XML-RPC, pingbacks and trackbacks, security headers and HSTS, the file editor of the admin.
11. Journal and statistics: which logins and account changes are recorded, and for how long the journal and the statistics are kept.

== Changelog ==

= 1.2.0 =

* Last login of each account in a sortable column of the users list, that of the network admin included. Logins with an application password do not count. A setting under Journal and statistics switches it off.

= 1.1.1 =

* Notices above the header of the admin pages spaced like those of Site Health.

= 1.1.0 =

* Author archives and the REST users route closed to subscribers and customers too: only the accounts that can write posts see them, a capability the gecka_security_enumeration_capability filter changes. An account keeps its own archive and routes.
* The journal names the account behind an enumeration refused to someone logged in.
* A scan of the author archives or of the users route is one journal row per hour, counted, instead of one row per request.
* Admin pages styled again on sites that install the plugin through their own Composer.
* The breached-password check is off until an administrator switches it on, and Site Health recommends it. Sites that never saved the settings had it on by default: switch it on again under Settings > Security.
* The breached-password warning shows on the dashboard, the profile and the screens of the plugin only.

= 1.0.0 =

* Brute-force lockouts per address on every way in: login form, WooCommerce, XML-RPC and application passwords, with a longer lockout for repeat offenders.
* Visitor address read from trusted proxies only, with Cloudflare support.
* Blocklist, and logins allowed or refused by country with Gecka Geolocation.
* Account names kept private: author archives, REST users route, oEmbed, sitemap, login and lost password messages.
* Breached passwords refused through Have I Been Pwned, by k-anonymity.
* Reserved login names, refused at registration and counted double on a failed login.
* XML-RPC, pingback and trackback switches, security headers, file editors off.
* Password resets and registrations limited per address.
* Mail alerts on a new administrator, a login from a new network and, as an option, every login.
* Journal of the logins and the account changes, statistics by entry point, country, network and system, dashboard widget.
* Site Health tests, personal data export and erasure, privacy policy paragraph.
* WP-CLI unlock command, safelist constant in wp-config.php, multisite support.

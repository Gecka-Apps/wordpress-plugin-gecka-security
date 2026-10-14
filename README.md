![](.github/banner.svg)

[![CI](https://github.com/Gecka-Apps/wordpress-plugin-gecka-security/actions/workflows/ci.yml/badge.svg)](https://github.com/Gecka-Apps/wordpress-plugin-gecka-security/actions/workflows/ci.yml)
[![WordPress 6.8+](https://img.shields.io/badge/WordPress-6.8%2B-21759b?logo=wordpress&logoColor=white)](readme.txt)
[![PHP 8.2+](https://img.shields.io/badge/PHP-8.2%2B-777bb4?logo=php&logoColor=white)](readme.txt)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

# Gecka Security for WordPress

Any WordPress site exposed to the internet receives automated login
attempts. Gecka Security locks out the addresses behind them, removes the
places where WordPress discloses account names, and records what happens in
a journal with statistics. It runs entirely on your server, sets no cookie
and requires no external account.

## 🛡️ Principles

- **Every entry point is covered.** Failed logins are counted on the login
  form, XML-RPC, the REST API with application passwords, WooCommerce and
  the login forms of themes and plugins, not only on `wp-login.php`.
- **The visitor address is read reliably.** Behind a reverse proxy or a CDN,
  the forwarded address is trusted only when it comes from a proxy you
  declare. A plugin that trusts it blindly can be made to lock out any
  address, or none.
- **Administrators keep a way back in.** A safelist, a WP-CLI command and a
  wp-config.php constant let you recover access whatever the settings say.
- **Low footprint.** No login page relocation, no extra step for users, no
  third-party service, and the features you disable are not loaded.
- **Sensible defaults.** Most sites need no configuration beyond the
  activation.

## 🔐 Brute-force protection

An address that fails 5 logins within an hour is locked out for 20 minutes:
its logins, registrations and password resets are refused before any
password is checked. An address locked out 4 times within 24 hours is then
locked out for 24 hours. Every threshold is a setting.

A failed login on a commonly targeted name such as `admin` counts double.
Empty forms and refused captchas are not counted as attempts. IPv6 addresses
are tracked by /64 network, so rotating addresses within a block does not
reset the count.

## 🕵️ Account enumeration

Knowing the account names leaves an attacker only the passwords to guess.
WordPress discloses them in several places, each of which the plugin can
close:

- author archives, whose URL contains the login
- the users endpoint of the REST API (off by default, as some plugins rely
  on it to display content)
- the author in the oEmbed data of posts
- the users in the XML sitemap
- login errors that distinguish an unknown user from a wrong password
- password reset responses that reveal whether an account exists, on
  WordPress and WooCommerce

## 🔑 Breached passwords

Passwords found in known data breaches are refused when they are set or
changed, and users who still log in with one are asked to change it. The
check uses the [Have I Been Pwned](https://haveibeenpwned.com/Passwords)
range API with k-anonymity: only the first five characters of a hash leave
the server, never the password, the login or the visitor's address. This is
the only external request the plugin makes, and it is off until an
administrator switches it on.

## 🚫 Blocklist and countries

Addresses and networks on the blocklist are refused logins, registrations
and password resets. With the
[Gecka Geolocation](https://github.com/Gecka-Apps/wordpress-plugin-gecka-geolocation)
plugin, logins can be restricted to a list of countries, or refused from
some. The settings reject any rule that would lock out the administrator
saving it.

## 📬 Alerts

- **New administrator.** An account created with the administrator role, or
  promoted to it, is reported by mail to the site address: creating a second
  administrator is a common way to keep access after a compromise.
- **Login from a new network.** With Gecka Geolocation, an administrator who
  logs in from a network never used by their account receives a mail with
  the network, the country and the address.
- **Every login** (off by default). Each user receives a mail at each of
  their logins, with the date, the address, the system and, with Gecka
  Geolocation, the country and the network.

## 🧱 Hardening

- **XML-RPC** can be disabled entirely. It allows hundreds of password
  attempts in a single request; Jetpack and the WordPress mobile app need it.
- **Pingbacks and trackbacks** are disabled by default. Pingbacks are used to
  involve sites in denial-of-service attacks, trackbacks carry little more
  than spam.
- **The theme and plugin file editors** are disabled by default, so a
  compromised administrator account cannot be used to write PHP on the
  server. Updates and installs are unaffected.
- **Security headers** (`X-Content-Type-Options`, `Referrer-Policy`,
  `X-Frame-Options`, `frame-ancestors`) are sent by default, except those
  your web server already sends. HSTS is available as an option.
- **Password resets and registrations** are limited to 5 per hour per
  address, which prevents mailbox flooding and mass account creation.

## 📊 Journal and statistics

- **Journal**: failed logins, lockouts, refused requests, successful logins
  with the account roles, and account changes (creation, role, email,
  password, deletion) with who made them.
- **Statistics** over 7, 30, 90 or 365 days, with charts by entry point and,
  with Gecka Geolocation, the countries and networks the attempts come from.
- **Lockouts**: the addresses currently locked out, to release or add to the
  safelist.
- **Dashboard widget** summarising the last seven days.
- **Site Health tests** for the plugin's own configuration, and for what the
  site exposes: `readme.html`, a browsable uploads directory, an admin not
  forced over HTTPS, registrations open with a role above subscriber.

## 🌐 Reverse proxies and CDNs

When the site sits behind a proxy, a load balancer or Cloudflare, declare
the header that carries the visitor address and the proxies allowed to set
it, under Settings > Security. Until then, Site Health reports the issue as
critical, and the plugin refuses to safelist the shared proxy address.

## 🆘 Recovering access

A lockout expires after 20 minutes by default. Another administrator can
release an address from Security > Lockouts, and with shell access:

```sh
wp gecka-security unlock 203.0.113.5
```

Networks listed in wp-config.php are never locked out or refused:

```php
define('GECKA_SECURITY_SAFELIST', '203.0.113.0/24, 2001:db8:1234::/48');
```

## 🌍 Multisite

On a network, the plugin is activated network-wide and configured from the
network admin. Lockouts apply to every site, and the journal records which
site each event occurred on.

## 🔒 Privacy

No cookie is set. Visitor IP addresses are stored in the journal and purged
after 30 days by default; the statistics contain none. Personal data is
included in the WordPress export and erasure tools. A privacy policy
paragraph is provided under Settings > Privacy, and saving a setting that
affects it displays a reminder.

## 🧩 Works with

- **[Gecka Geolocation](https://github.com/Gecka-Apps/wordpress-plugin-gecka-geolocation)**
  locates the addresses on your server. It enables the country rules and the
  new network alert, adds the country and the network under each address of
  the journal and in the login alerts, and breaks the statistics down by
  country and network.
- **[Gecka Antispam](https://github.com/Gecka-Apps/wordpress-plugin-gecka-antispam)**
  stops bots on the forms of the site, login included, without a captcha.
  The two cover different ground: Antispam refuses the submissions that look
  automated, Security limits what an address can try and locks out the ones
  that keep trying. A login refused by Antispam is not counted as a failed
  password. Both plugins share the Security menu, each adding its tabs to the
  Statistics and Journal pages.

## 🙅 Out of scope

Gecka Security does not relocate the login page, add two-factor
authentication or show a captcha. Those are better handled by dedicated
plugins, Gecka Antispam for the bots on forms, and it works alongside them.

## 📋 Requirements

- WordPress 6.8 or later, single site or multisite
- PHP 8.2 or later
- [Gecka Geolocation](https://github.com/Gecka-Apps/wordpress-plugin-gecka-geolocation)
  (optional) for country rules, new network alerts and attack origins

Hooks and stored data are documented in [docs/DEVELOPERS.md](docs/DEVELOPERS.md).

## 📜 License

Copyright 2026 Gecka. GPL-3.0-or-later.

---
Built with 🥥 and ☕ by [Gecka](https://gecka.nc) — Kanaky-New Caledonia 🇳🇨

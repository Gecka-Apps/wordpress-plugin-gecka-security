<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Admin;

/**
 * The tabs of the Help of the settings page: how the lockouts are counted,
 * how the address of the visitor is read and which addresses are refused
 * for good, what each enumeration protection closes, and the reserved
 * names.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Help
{
    /**
     * Id of the tab of the brute-force protection.
     */
    public const BRUTE_FORCE = 'gecka-security-brute-force';

    /**
     * Id of the tab of the addresses.
     */
    public const ADDRESSES = 'gecka-security-addresses';

    /**
     * Id of the tab of the enumeration protections.
     */
    public const ENUMERATION = 'gecka-security-enumeration';

    /**
     * Id of the tab of the reserved names.
     */
    public const RESERVED = 'gecka-security-reserved';

    /**
     * Adds the tabs of the settings page to the Help of the screen.
     *
     * @param \WP_Screen $screen Screen of the settings page.
     *
     * @return void
     */
    public static function add(\WP_Screen $screen): void
    {
        $contents = [
            self::BRUTE_FORCE => self::bruteForce(),
            self::ADDRESSES => self::addresses(),
            self::ENUMERATION => self::enumeration(),
            self::RESERVED => self::reserved(),
        ];

        foreach (self::titles() as $id => $title) {
            $screen->add_help_tab(['id' => $id, 'title' => $title, 'content' => $contents[$id]]);
        }
    }

    /**
     * Titles of the tabs, by id
     *
     * @return array<string, string>
     */
    private static function titles(): array
    {
        return [
            self::BRUTE_FORCE => __('Brute force', 'gecka-security'),
            self::ADDRESSES => __('Addresses', 'gecka-security'),
            self::ENUMERATION => __('Account enumeration', 'gecka-security'),
            self::RESERVED => __('Reserved names', 'gecka-security'),
        ];
    }

    /**
     * A link opening a tab of the Help
     *
     * @param string $id Id of the tab, one of the constants.
     *
     * @return string HTML.
     */
    public static function link(string $id): string
    {
        return sprintf(
            // The library draws the link as a question mark; the text stays for the screen readers and the tooltip.
            '<a href="#tab-panel-%1$s" class="gecka-admin-help-link" data-help-tab="%1$s" title="%2$s">%2$s</a>',
            esc_attr($id),
            /* translators: %s: title of a help tab */
            esc_attr(sprintf(__('Help: %s', 'gecka-security'), self::titles()[$id] ?? '')),
        );
    }

    /**
     * How the failures and the lockouts are counted
     *
     * @return string HTML.
     */
    private static function bruteForce(): string
    {
        return self::paragraphs(
            [
                __('Every login that fails on its login or its password counts for the address it came from, whichever way it came in: the login form of WordPress, a login form of a theme or plugin, WooCommerce, XML-RPC and the REST API with an application password; the registration form of WooCommerce is refused while locked out too. An empty form, a refused captcha and a refused antispam check do not count: they are not a guess.', 'gecka-security'),
                __('Failures are counted within a window; at the maximum the address is locked out and its failures go back to zero. While locked out, its logins are refused before the password is checked, and so are its registrations and password resets. A successful login does not clear the failures: on a site open to registration, a bot owning one account would log into it between two runs of guesses.', 'gecka-security'),
                __('Lockouts are counted within a longer window; at their maximum the lockout is the long one, and the count starts over. An IPv6 address is watched as the /64 it belongs to, the block a provider hands a subscriber, so that a bot rotating inside it does not escape the count.', 'gecka-security'),
                __('Addresses on the safelist are never locked out, and neither is an address the server cannot vouch for: see the Addresses tab.', 'gecka-security'),
            ],
        );
    }

    /**
     * How the address of the visitor is read
     *
     * @return string HTML.
     */
    private static function addresses(): string
    {
        return self::paragraphs(
            [
                __('The server vouches for one address only, the one it is talking to. Behind a reverse proxy, a load balancer or a CDN, that address is the proxy, the same for every visitor, and the address of the visitor travels in a header the proxy adds.', 'gecka-security'),
                __('That header is read only when the settings name it and the request comes from one of the trusted proxies. Anyone can send such a header: read blindly, it lets a bot choose the address it is seen under, or get someone else locked out. X-Forwarded-For lists every hop; it is read from the end, past the trusted proxies, so that what the proxy wrote counts and not what the client wrote before it.', 'gecka-security'),
                __('Behind Cloudflare, read CF-Connecting-IP and trust the address ranges Cloudflare publishes. X-Forwarded-For is no good there: a Cloudflare Worker, run by anyone, reaches the site from those same ranges and writes in that header the address it likes.', 'gecka-security'),
                __('When no address can be trusted, nothing is locked out: a wrong lockout would hit every visitor at once. Site Health tells when the site is in that state.', 'gecka-security'),
                __('The blocklist and the countries refuse a login, a registration and a password reset for good, on every way in, with one message whatever the reason. A visitor already logged in stays so. The country of an address comes from Gecka Geolocation: an address it cannot place, a private one for instance, is never refused for its country. The settings refuse to save a blocklist or countries that would refuse the administrator saving them, unless the safelist holds their address. Locked out of the site anyway, name your address in the GECKA_SECURITY_SAFELIST constant of wp-config.php.', 'gecka-security'),
            ],
        );
    }

    /**
     * What each enumeration protection closes
     *
     * @return string HTML.
     */
    private static function enumeration(): string
    {
        return self::paragraphs(
            [
                __('A bot that knows the logins of a site only has the passwords left to guess. WordPress gives the logins away in several places, each closed by a setting: the archive of an author, whose address holds the login and which ?author=1 redirects to; the users route of the REST API; the author of a post in its oEmbed data; and the users in the sitemap.', 'gecka-security'),
                __('The messages of a failed login tell whether the login or the password was wrong, and those of a password reset whether the account exists: the setting gives each one message instead. The messages of a registration still say when a login or an email address is taken, as a person registering needs to know.', 'gecka-security'),
                __('Logged-in users keep the REST route and the archives. The REST setting is off by default: some plugins read the route to show the authors of the site to visitors, and closing it gains little while the author archives still answer.', 'gecka-security'),
            ],
        );
    }

    /**
     * The reserved names
     *
     * @return string HTML.
     */
    private static function reserved(): string
    {
        return self::paragraphs(
            [
                __('Bots try a handful of logins first, admin above all. No account can be registered or created with a reserved name, through the registration form, the users screen or WP-CLI alike. An account that already carries one keeps it: WordPress does not rename an account, so create another administrator and delete that one.', 'gecka-security'),
                __('A failed login on a reserved name counts double towards a lockout, whether an account carries it or not: a lockout coming sooner on a name that exists would tell that it does. When no account carries it, the failure is recorded as a reserved name.', 'gecka-security'),
            ],
        );
    }

    /**
     * Paragraphs of escaped text
     *
     * @param string[] $texts Paragraphs, plain text.
     *
     * @return string HTML.
     */
    private static function paragraphs(array $texts): string
    {
        return implode('', array_map(static fn(string $text): string => '<p>' . esc_html($text) . '</p>', $texts));
    }
}

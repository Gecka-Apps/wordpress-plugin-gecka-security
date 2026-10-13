<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Value;
use Gecka\WP\Plugin\Security\Request;

/**
 * Security headers on every response of the site, the front, the admin and
 * the login screen alike: the browser then neither guesses the type of a
 * file, nor tells a third party the page it comes from, nor shows the site
 * inside another. HSTS, which commits the site to HTTPS for six months, is
 * a setting of its own, off by default, sent over HTTPS only. A header the
 * server or another plugin already sent is left alone: the ones PHP can see
 * through headers_list(), and the ones the web server adds on its own,
 * which a probe of the home page records, since PHP never sees those.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Headers extends Integration
{
    /**
     * Six months, in seconds.
     */
    private const HSTS_MAX_AGE = 15552000;

    /**
     * Option holding the names, in lower case, of the security headers the
     * web server sends on its own, as the last probe of the home page saw
     * them. Autoloaded, since every response reads it.
     */
    public const SERVER_OPTION = 'gecka_security_server_headers';

    /**
     * Query parameter of the probe, carrying a token good for one request:
     * the response to it goes without the headers of the plugin, so that
     * only those of the server show. A token it takes, or anyone could
     * have a visitor load a page without the headers refusing frames.
     */
    public const PROBE = 'gecka-security-probe';

    /**
     * Transient holding the token of the probe under way.
     */
    public const PROBE_TOKEN = 'gecka_security_probe';

    /**
     * Header a response to the probe carries back, holding its token: a
     * response without it was not rendered for the probe under way, as one
     * a page cache kept, or one answering an earlier probe.
     */
    public const PROOF = 'X-Gecka-Security-Probe';

    /**
     * Always available: it needs nothing beyond WordPress.
     *
     * @return bool
     */
    public function available(): bool
    {
        return true;
    }

    /**
     * Sends the headers on the front, the admin and the login screen, when
     * either setting is on.
     *
     * @return void
     */
    public function setup(): void
    {
        if (! $this->plugin->settings()->enabled('security_headers') && ! $this->plugin->settings()->enabled('hsts')) {
            return;
        }

        add_action('send_headers', [$this, 'send'], self::PRIORITY);
        add_action('admin_init', [$this, 'send'], self::PRIORITY);
        add_action('login_init', [$this, 'send'], self::PRIORITY);
    }

    /**
     * The headers to send, by name
     *
     * @param bool $headers Whether the security headers are on.
     * @param bool $hsts    Whether HSTS is on.
     * @param bool $ssl     Whether the request came over HTTPS.
     *
     * @return array<string, string>
     */
    public static function list(bool $headers, bool $hsts, bool $ssl): array
    {
        $list = [];

        if ($headers) {
            $list['X-Content-Type-Options'] = 'nosniff';
            $list['Referrer-Policy'] = 'strict-origin-when-cross-origin';
            $list['X-Frame-Options'] = 'SAMEORIGIN';
            $list['Content-Security-Policy'] = "frame-ancestors 'self'";
        }

        if ($hsts && $ssl) {
            $list['Strict-Transport-Security'] = 'max-age=' . self::HSTS_MAX_AGE;
        }

        return $list;
    }

    /**
     * The headers to send once those already sent are left out: by PHP on
     * this response, or by the web server on every response. An embed, a
     * post meant to be framed by other sites, goes without the headers
     * refusing frames.
     *
     * @param array<string, string> $wanted  The headers the settings ask for, as list() gives them.
     * @param string[]              $already Names of the headers sent already, in any case.
     * @param bool                  $embed   Whether the response is an embed.
     *
     * @return array<string, string>
     */
    public static function toSend(array $wanted, array $already, bool $embed): array
    {
        $already = array_map('strtolower', $already);
        $send = [];

        foreach ($wanted as $name => $value) {
            if ($embed && in_array($name, ['X-Frame-Options', 'Content-Security-Policy'], true)) {
                continue;
            }

            if (! in_array(strtolower($name), $already, true)) {
                $send[$name] = $value;
            }
        }

        return $send;
    }

    /**
     * Names of the security headers the web server sends on its own, in
     * lower case, as the last probe saw them
     *
     * @return string[]
     */
    public static function server(): array
    {
        $names = Scope::option(self::SERVER_OPTION, []);

        return is_array($names) ? array_values(array_filter($names, 'is_string')) : [];
    }

    /**
     * Asks the home page which security headers the web server sends on its
     * own, and records their names. The request carries the probe parameter,
     * so the plugin adds none of its own to that response; a header another
     * plugin sends counts as the server's, being left alone the same way.
     *
     * While the plugin sends headers, a response that does not carry the
     * token back is ignored: its headers may be those of the plugin.
     *
     * @return string[]|null The names seen, in lower case, or null when the home page did not answer, or not to this probe.
     */
    public static function probe(): ?array
    {
        $token = wp_generate_password(32, false);
        Scope::setTransient(self::PROBE_TOKEN, $token, MINUTE_IN_SECONDS);
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- A filter of core, read as core reads it for its own loopback requests.
        $response = wp_remote_get(add_query_arg(self::PROBE, $token, Scope::home()), ['timeout' => 3, 'redirection' => 2, 'limit_response_size' => 1024, 'sslverify' => (bool) apply_filters('https_local_ssl_verify', false)]);
        Scope::deleteTransient(self::PROBE_TOKEN);

        if (is_wp_error($response)) {
            return null;
        }

        $received = wp_remote_retrieve_headers($response);
        $settings = gecka_security()->settings();
        $sending = $settings->enabled('security_headers') || $settings->enabled('hsts');

        if ($sending && Value::string(($received[strtolower(self::PROOF)] ?? '')) !== $token) {
            return null;
        }

        $names = [];

        foreach (array_keys(self::list(true, true, true)) as $name) {
            if (isset($received[strtolower($name)])) {
                $names[] = strtolower($name);
            }
        }

        Scope::saveOption(self::SERVER_OPTION, $names, true);

        return $names;
    }

    /**
     * Whether the request is the probe under way: it carries the token
     * the probe set a moment ago, which no one else knows.
     *
     * @return bool
     */
    public static function isProbe(): bool
    {
        $token = Request::query(self::PROBE);

        if ($token === '') {
            return false;
        }

        $expected = Scope::transient(self::PROBE_TOKEN);

        return is_string($expected) && $expected !== '' && hash_equals($expected, $token);
    }

    /**
     * Sends the headers not sent yet; on a response to the probe, only the
     * header carrying its token back.
     *
     * @param mixed $wp The request, on the front.
     *
     * @return void
     */
    public function send(mixed $wp = null): void
    {
        if (headers_sent()) {
            return;
        }

        if (self::isProbe()) {
            header(self::PROOF . ': ' . Request::query(self::PROBE));

            return;
        }

        // The embed query var only asks for an embed: anyone can add it to
        // any address, and the query, not run yet, decides whether the
        // embed template renders. The headers refusing frames wait for it.
        $embed = $wp instanceof \WP && isset($wp->query_vars['embed']);

        if ($embed) {
            add_action('template_redirect', [$this, 'frames'], self::PRIORITY);
        }

        $this->emit($embed);
    }

    /**
     * Sends the headers refusing frames held back for an embed asked, once
     * the query tells that the response is no embed.
     *
     * @return void
     */
    public function frames(): void
    {
        if (! headers_sent() && ! is_embed()) {
            $this->emit(false);
        }
    }

    /**
     * Sends the headers the settings ask for, but those sent already.
     *
     * @param bool $embed Whether to leave out the headers refusing frames.
     *
     * @return void
     */
    private function emit(bool $embed): void
    {
        $sent = [];

        foreach (headers_list() as $header) {
            $sent[] = trim((string) strstr($header, ':', true));
        }

        $settings = $this->plugin->settings();
        $wanted = self::list($settings->enabled('security_headers'), $settings->enabled('hsts'), is_ssl());

        foreach (self::toSend($wanted, [...$sent, ...self::server()], $embed) as $name => $value) {
            header($name . ': ' . $value);
        }
    }
}

<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Admin;

use Gecka\WP\Plugin\Security\Access;
use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Base;
use Gecka\WP\Plugin\Security\ClientIp;
use Gecka\WP\Plugin\Security\Network;
use Gecka\WP\Plugin\Security\Integrations\Headers;
use Gecka\WP\Plugin\Security\Integrations\Pwned;
use Gecka\WP\Plugin\Security\Plugin;
use Gecka\WP\Plugin\Security\Schema;
use Gecka\WP\Plugin\Security\Settings;
use Gecka\WP\Plugin\Security\Setup;
use Gecka\WP\Plugin\Security\Value;
use Gecka\WP\Plugin\Security\Request;

/**
 * Tools > Site Health: tests telling what keeps the plugin from working as
 * it should, each failing one with a link to fix it, the daily task aside,
 * and a section of the Info tab describing its state, ready to be copied
 * for support.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class SiteHealth extends Base
{
    /**
     * Seconds the daily task may be late before it counts as not running.
     */
    private const LATE = DAY_IN_SECONDS;

    /**
     * Answers the asynchronous tests, which the script of Site Health asks
     * of admin-ajax.php. The tests themselves and the section of the Info
     * tab are hooked by the plugin, wherever they are asked.
     *
     * @return void
     */
    public function setup(): void
    {
        add_action(self::action('gecka_security_pwned'), [$this, 'ajaxPwned']);
        add_action(self::action('gecka_security_exposure'), [$this, 'ajaxExposure']);
        add_action(self::action('gecka_security_headers'), [$this, 'ajaxHeaders']);
    }

    /**
     * The admin-ajax action Site Health calls for an asynchronous test: its
     * script turns the first underscore of the name into a dash, and only
     * that one.
     *
     * @param string $test Name of the test, as tests() registers it.
     *
     * @return string
     */
    public static function action(string $test): string
    {
        return 'wp_ajax_health-check-' . preg_replace('/_/', '-', $test, 1);
    }

    /**
     * Adds the tests of the plugin.
     *
     * @param mixed $tests Tests of Site Health, by kind: direct and async.
     *
     * @return mixed The tests, those of the plugin added when they are an array.
     */
    public function tests(mixed $tests): mixed
    {
        if (! is_array($tests)) {
            return $tests;
        }

        $tests['direct'] = is_array($tests['direct'] ?? null) ? $tests['direct'] : [];
        $tests['async'] = is_array($tests['async'] ?? null) ? $tests['async'] : [];
        // WP-Cron and WP-CLI have no visitor: the address read would be that of the server.
        if (! wp_doing_cron() && ! (defined('WP_CLI') && WP_CLI)) {
            $tests['direct']['gecka_security_address'] = ['label' => __('The address of the visitor, as Gecka Security reads it', 'gecka-security'), 'test' => [$this, 'testAddress']];
        }

        $tests['direct']['gecka_security_bruteforce'] = ['label' => __('The brute-force protection of Gecka Security', 'gecka-security'), 'test' => [$this, 'testBruteForce']];
        $tests['direct']['gecka_security_schedule'] = ['label' => __('The daily task of Gecka Security', 'gecka-security'), 'test' => [$this, 'testSchedule']];
        $tests['direct']['gecka_security_registration'] = ['label' => __('The role of the accounts that register', 'gecka-security'), 'test' => [$this, 'testRegistration']];

        if ($this->plugin->settings()->string('countries_mode') !== '') {
            $tests['direct']['gecka_security_countries'] = ['label' => __('The countries Gecka Security checks', 'gecka-security'), 'test' => [$this, 'testCountries']];
        }

        // Asked of a third party: run after the page, like the tests of WordPress that reach out.
        $tests['async']['gecka_security_pwned'] = ['label' => __('The breach service Gecka Security asks', 'gecka-security'), 'test' => 'gecka_security_pwned'];
        $tests['direct']['gecka_security_ssl_admin'] = ['label' => __('The admin of the site over HTTPS', 'gecka-security'), 'test' => [$this, 'testSslAdmin']];
        $tests['async']['gecka_security_exposure'] = ['label' => __('Files and listings the site exposes', 'gecka-security'), 'test' => 'gecka_security_exposure'];
        $tests['async']['gecka_security_headers'] = ['label' => __('The security headers the visitors get', 'gecka-security'), 'test' => 'gecka_security_headers'];

        return $tests;
    }

    /**
     * Whether the address of the visitor can be told apart from everyone
     * else's: behind a local proxy with no header read, every visitor has
     * the same, and the protection either locks everyone out or no one.
     *
     * @return array{label: string, status: string, badge: array{label: string, color: string}, description: string, actions: string, test: string}
     */
    public function testAddress(): array
    {
        $ip = $this->plugin->clientIp();
        $settings = $this->plugin->settings();
        $peer = Network::normalize(Request::server('REMOTE_ADDR')) ?? '';

        if ($ip->onServer()) {
            return $this->result(
                'gecka_security_address',
                'good',
                __('Gecka Security tells the visitors apart', 'gecka-security'),
                /* translators: %s: IP address */
                sprintf(__('This request comes from the server itself, %s, through a trusted proxy: the other visitors are seen under their own address.', 'gecka-security'), $ip->get()),
            );
        }

        if (! $ip->reliable()) {
            return $this->result(
                'gecka_security_address',
                'recommended',
                __('Gecka Security cannot tell the visitors apart', 'gecka-security'),
                $peer !== '' && ! Network::isUsable($peer)
                    /* translators: %s: IP address */
                    ? sprintf(__('The server sees every visitor as %s: a proxy on the same machine stands in front of it. Name the header that proxy sends and list its address among the trusted proxies, or the brute-force protection cannot act on anyone.', 'gecka-security'), $peer)
                    : __('The request carries no usable address with the current settings: the header named is missing or ill-formed. Check the header the proxy sends and the trusted proxies.', 'gecka-security'),
            );
        }

        if ($ip->behindProxy()) {
            return $this->result(
                'gecka_security_address',
                'critical',
                __('Gecka Security sees every visitor behind a proxy', 'gecka-security'),
                sprintf(
                    /* translators: %s: IP address */
                    __('This request comes from %s, a private address, while no proxy is trusted: a proxy or a load balancer on the local network stands in front of the server, and every visitor is seen under its address. A lockout would lock everyone out at once. Name the header that proxy sends and list its address among the trusted proxies.', 'gecka-security'),
                    $ip->get(),
                ),
            );
        }

        if ($settings->string('ip_source') !== ClientIp::REMOTE_ADDR && ! Network::inList($peer, $settings->strings('trusted_proxies'))) {
            return $this->result(
                'gecka_security_address',
                'recommended',
                __('Gecka Security reads a header, but this request did not come from a trusted proxy', 'gecka-security'),
                sprintf(
                    /* translators: 1: IP address the server saw, 2: IP address used */
                    __('The server saw %1$s, which is not in the trusted proxies, so the header is left aside and %2$s is used. If the site is always behind the proxy, add that address to the trusted proxies; if it is not, choose the address the server saw.', 'gecka-security'),
                    $peer,
                    $ip->get(),
                ),
            );
        }

        return $this->result(
            'gecka_security_address',
            'good',
            __('Gecka Security tells the visitors apart', 'gecka-security'),
            /* translators: %s: IP address */
            sprintf(__('This request comes from %s.', 'gecka-security'), $ip->get()),
        );
    }

    /**
     * Whether the brute-force protection is on.
     *
     * @return array{label: string, status: string, badge: array{label: string, color: string}, description: string, actions: string, test: string}
     */
    public function testBruteForce(): array
    {
        if (! $this->plugin->settings()->enabled('bruteforce')) {
            return $this->result(
                'gecka_security_bruteforce',
                'recommended',
                __('The brute-force protection of Gecka Security is off', 'gecka-security'),
                __('An address can try passwords without limit on the login form, WooCommerce, XML-RPC and the REST API.', 'gecka-security'),
            );
        }

        $failures = $this->plugin->settings()->int('max_failures');
        $minutes = $this->plugin->settings()->int('lockout_minutes');

        return $this->result(
            'gecka_security_bruteforce',
            'good',
            __('The brute-force protection of Gecka Security is on', 'gecka-security'),
            sprintf(
                /* translators: 1: number of failed logins, as "5 failed logins", 2: duration, as "20 minutes" */
                __('An address is locked out after %1$s, for %2$s, on every way in.', 'gecka-security'),
                /* translators: %s: number of failed logins */
                self::count(_n('%s failed login', '%s failed logins', $failures, 'gecka-security'), $failures),
                /* translators: %s: number of minutes */
                self::count(_n('%s minute', '%s minutes', $minutes, 'gecka-security'), $minutes),
            ),
        );
    }

    /**
     * Whether anyone can register, and with which role: a role above
     * subscriber hands its rights to every registration.
     *
     * @return array{label: string, status: string, badge: array{label: string, color: string}, description: string, actions: string, test: string}
     */
    public function testRegistration(): array
    {
        $role = Value::string(get_option('default_role', 'subscriber'));
        $names = wp_roles()->get_names();
        $name = isset($names[$role]) ? translate_user_role($names[$role]) : $role;
        $open = Scope::network() ? ! in_array(Value::string(get_site_option('registration', 'none')), ['none', 'blog'], true) : (bool) get_option('users_can_register');

        if (! $open) {
            return $this->result('gecka_security_registration', 'good', __('Registrations are closed', 'gecka-security'), __('Nobody can create an account by themselves.', 'gecka-security'));
        }

        if (in_array($role, ['subscriber', 'customer'], true)) {
            /* translators: %s: name of the role */
            return $this->result('gecka_security_registration', 'good', sprintf(__('Registrations are open, a new account gets the %s role', 'gecka-security'), $name), __('That role can do nothing in the admin.', 'gecka-security'));
        }

        return $this->result(
            'gecka_security_registration',
            'critical',
            /* translators: %s: name of the role */
            sprintf(__('Anyone can register and gets the %s role', 'gecka-security'), $name),
            __('Every registration becomes an account with the rights of that role. In Settings > General, set the default role back to Subscriber, or close the registrations.', 'gecka-security'),
            admin_url('options-general.php'),
        );
    }

    /**
     * Whether the countries of the settings are checked: they need Gecka
     * Geolocation, without which every country gets in.
     *
     * @return array{label: string, status: string, badge: array{label: string, color: string}, description: string, actions: string, test: string}
     */
    public function testCountries(): array
    {
        if (Access::geolocation()) {
            return $this->result('gecka_security_countries', 'good', __('The countries of the logins are checked', 'gecka-security'), __('Gecka Geolocation tells the country of each address, and the logins are kept to the countries of the settings.', 'gecka-security'));
        }

        return $this->result(
            'gecka_security_countries',
            'recommended',
            __('The countries of the logins are not checked', 'gecka-security'),
            __('The settings of Gecka Security keep the logins to some countries, or refuse some, but Gecka Geolocation, which tells the country of an address, is not active: every country gets in. Activate it, or set the countries back to every country.', 'gecka-security'),
            Scope::network() ? network_admin_url('plugins.php') : admin_url('plugins.php'),
        );
    }

    /**
     * Whether the breach service answers from this server.
     *
     * @return array{label: string, status: string, badge: array{label: string, color: string}, description: string, actions: string, test: string}
     */
    public function testPwned(): array
    {
        if (! $this->plugin->settings()->enabled('pwned_passwords')) {
            return $this->result('gecka_security_pwned', 'recommended', __('The breached passwords are not checked', 'gecka-security'), __('A password known from data breaches is accepted; anyone can try it.', 'gecka-security'));
        }

        if ((new Pwned($this->plugin))->count('password') === null) {
            return $this->result('gecka_security_pwned', 'recommended', __('The breach service does not answer', 'gecka-security'), __('Have I Been Pwned could not be reached from this server: the passwords go through unchecked until it answers.', 'gecka-security'));
        }

        return $this->result('gecka_security_pwned', 'good', __('The breach service answers', 'gecka-security'), __('A password known from data breaches is refused when set, and a user logging in with one is warned.', 'gecka-security'));
    }

    /**
     * Answers Site Health asking for the test of the breach service.
     *
     * @return void
     */
    public function ajaxPwned(): void
    {
        check_ajax_referer('health-check-site-status');

        if (! current_user_can('view_site_health_checks')) {
            wp_send_json_error();
        }

        wp_send_json_success($this->testPwned());
    }

    /**
     * Whether the admin is forced over HTTPS on a site that has it. The
     * errors shown to the visitors are a test of WordPress itself.
     *
     * @param bool|null $https  Whether the site runs over HTTPS, its address when null.
     * @param bool|null $forced Whether the admin is forced over HTTPS, the constant when null.
     *
     * @return array{label: string, status: string, badge: array{label: string, color: string}, description: string, actions: string, test: string}
     */
    public function testSslAdmin(?bool $https = null, ?bool $forced = null): array
    {
        $https ??= str_starts_with(Value::string(get_option('siteurl')), 'https://');
        $forced ??= force_ssl_admin();

        if (! $https) {
            return $this->result('gecka_security_ssl_admin', 'good', __('Nothing to force: the site does not run over HTTPS', 'gecka-security'), __('WordPress reports a site without HTTPS on its own.', 'gecka-security'));
        }

        if (! $forced) {
            return $this->result('gecka_security_ssl_admin', 'recommended', __('The admin is not forced over HTTPS', 'gecka-security'), __('The site runs over HTTPS, but a login typed on an http:// address would still travel in clear. Set FORCE_SSL_ADMIN to true in wp-config.php.', 'gecka-security'), admin_url('site-health.php?tab=debug'));
        }

        return $this->result('gecka_security_ssl_admin', 'good', __('The admin is forced over HTTPS', 'gecka-security'), __('The admin and the logins travel encrypted, even when typed on an http:// address.', 'gecka-security'));
    }

    /**
     * Whether readme.html and license.txt answer, and whether the uploads
     * directory lists its files: what tells the version of WordPress to
     * anyone, and what shows every file ever uploaded.
     *
     * @return array{label: string, status: string, badge: array{label: string, color: string}, description: string, actions: string, test: string}
     */
    public function testExposure(): array
    {
        $exposed = [];

        foreach (['readme.html', 'license.txt'] as $file) {
            if ($this->answers(site_url('/' . $file)) !== null) {
                $exposed[] = $file;
            }
        }

        $uploads = wp_get_upload_dir();
        $listing = $this->answers(trailingslashit((string) $uploads['baseurl']));

        if ($listing !== null && stripos($listing, 'index of') !== false) {
            $exposed[] = __('the listing of the uploads directory', 'gecka-security');
        }

        if (! $exposed) {
            return $this->result('gecka_security_exposure', 'good', __('Nothing is exposed that need not be', 'gecka-security'), __('readme.html and license.txt do not answer, and the uploads directory lists nothing.', 'gecka-security'));
        }

        return $this->result(
            'gecka_security_exposure',
            'recommended',
            /* translators: %s: what is exposed */
            sprintf(__('Exposed: %s', 'gecka-security'), implode(', ', $exposed)),
            __('readme.html and license.txt tell the version of WordPress to anyone, and a listed uploads directory shows every file ever uploaded. Have the server refuse them: a few lines in the configuration of the virtual host or in .htaccess.', 'gecka-security'),
            admin_url('site-health.php?tab=debug'),
        );
    }

    /**
     * Whether every security header reaches the visitors, from the web
     * server or from the plugin: the home page is asked, and what the
     * server sends on its own is recorded for the settings and the
     * responses.
     *
     * @return array{label: string, status: string, badge: array{label: string, color: string}, description: string, actions: string, test: string}
     */
    public function testHeaders(): array
    {
        $server = Headers::probe();

        if ($server === null) {
            return $this->result('gecka_security_headers', 'recommended', __('The security headers could not be checked', 'gecka-security'), __('The home page did not answer the server asking for it, so what the visitors get is unknown.', 'gecka-security'));
        }

        $settings = $this->plugin->settings();
        $plugin = array_map('strtolower', array_keys(Headers::toSend(Headers::list($settings->enabled('security_headers'), $settings->enabled('hsts'), str_starts_with(home_url(), 'https://')), $server, false)));
        $missing = [];

        foreach (array_keys(Headers::list(true, str_starts_with(home_url(), 'https://'), true)) as $name) {
            if (! in_array(strtolower($name), $server, true) && ! in_array(strtolower($name), $plugin, true)) {
                $missing[] = $name;
            }
        }

        $sources = implode(' ', array_filter([
            /* translators: %s: names of HTTP headers */
            $server ? sprintf(__('Sent by the server: %s.', 'gecka-security'), implode(', ', $server)) : '',
            /* translators: %s: names of HTTP headers */
            $plugin ? sprintf(__('Sent by Gecka Security: %s.', 'gecka-security'), implode(', ', $plugin)) : '',
        ]));

        if (! $missing) {
            return $this->result('gecka_security_headers', 'good', __('The security headers reach the visitors', 'gecka-security'), $sources);
        }

        return $this->result(
            'gecka_security_headers',
            'recommended',
            /* translators: %s: names of HTTP headers */
            sprintf(__('Security headers missing: %s', 'gecka-security'), implode(', ', $missing)),
            trim($sources . ' ' . __('Switch the missing ones on in the settings of Gecka Security, or have the server send them. A header added by a CDN in front of the server is not seen from here.', 'gecka-security')),
        );
    }

    /**
     * Answers Site Health asking for the test of the security headers.
     *
     * @return void
     */
    public function ajaxHeaders(): void
    {
        check_ajax_referer('health-check-site-status');

        if (! current_user_can('view_site_health_checks')) {
            wp_send_json_error();
        }

        wp_send_json_success($this->testHeaders());
    }

    /**
     * Answers Site Health asking for the test of the exposed files.
     *
     * @return void
     */
    public function ajaxExposure(): void
    {
        check_ajax_referer('health-check-site-status');

        if (! current_user_can('view_site_health_checks')) {
            wp_send_json_error();
        }

        wp_send_json_success($this->testExposure());
    }

    /**
     * The body of an address that answers 200, as a visitor would get it
     *
     * @param string $url Address requested, without following redirects.
     *
     * @return string|null The first 4 KB of the body; null when it does not answer 200.
     */
    private function answers(string $url): ?string
    {
        // The verification of the certificate follows the filter core applies to its own loopback requests.
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- A filter of core, read as core reads it.
        $response = wp_remote_get($url, ['timeout' => 3, 'redirection' => 0, 'limit_response_size' => 4096, 'sslverify' => (bool) apply_filters('https_local_ssl_verify', false)]);

        if (is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        return (string) wp_remote_retrieve_body($response);
    }

    /**
     * Whether the daily task is scheduled and runs.
     *
     * @return array{label: string, status: string, badge: array{label: string, color: string}, description: string, actions: string, test: string}
     */
    public function testSchedule(): array
    {
        $next = Value::int(Scope::onMainSite(static fn() => wp_next_scheduled(Setup::PURGE_EVENT)));

        if (! $next) {
            return $this->result(
                'gecka_security_schedule',
                'recommended',
                __('The daily task of Gecka Security is not scheduled', 'gecka-security'),
                __('Without it, the journal, the statistics and the addresses watched are never purged. The plugin schedules it again on the next page load; if this persists, WordPress cannot save its scheduled tasks.', 'gecka-security'),
            );
        }

        if ($next < time() - self::LATE) {
            return $this->result(
                'gecka_security_schedule',
                'recommended',
                __('The daily task of Gecka Security does not run', 'gecka-security'),
                sprintf(
                    /* translators: %s: date */
                    __('It was due on %s. The scheduled tasks of WordPress do not run on this site: without them, the journal, the statistics and the addresses watched are never purged.', 'gecka-security'),
                    Scope::dateTime($next),
                ),
            );
        }

        return $this->result(
            'gecka_security_schedule',
            'good',
            __('The daily task of Gecka Security runs', 'gecka-security'),
            __('It purges the journal, the statistics and the addresses watched when due.', 'gecka-security'),
        );
    }

    /**
     * Adds the section of the plugin to the Info tab.
     *
     * @param mixed $info Sections of the Info tab.
     *
     * @return mixed The sections, that of the plugin added when they are an array.
     */
    public function information(mixed $info): mixed
    {
        if (! is_array($info)) {
            return $info;
        }

        $settings = $this->plugin->settings();
        $failures = $settings->int('max_failures');
        $minutes = $settings->int('lockout_minutes');
        $lockouts = $settings->int('max_lockouts');
        $hours = $settings->int('long_lockout_hours');
        $journal = $settings->int('events_days');
        $statistics = $settings->int('stats_days');
        $on = [];

        foreach (['bruteforce' => __('Brute force', 'gecka-security'), 'author_archives' => __('Author archives', 'gecka-security'), 'rest_users' => __('REST API users', 'gecka-security'), 'oembed_author' => __('oEmbed', 'gecka-security'), 'sitemap_users' => __('Sitemap', 'gecka-security'), 'login_errors' => __('Login errors', 'gecka-security'), 'xmlrpc_disabled' => __('XML-RPC off', 'gecka-security'), 'pingback_disabled' => __('Pingbacks refused', 'gecka-security'), 'trackback_disabled' => __('Trackbacks refused', 'gecka-security'), 'security_headers' => __('Security headers', 'gecka-security'), 'hsts' => __('HSTS', 'gecka-security'), 'file_edit_disabled' => __('File editor off', 'gecka-security'), 'pwned_passwords' => __('Breached passwords', 'gecka-security'), 'limit_requests' => __('Request limits', 'gecka-security'), 'alert_admins' => __('Administrator alert', 'gecka-security'), 'alert_new_network' => __('New network alert', 'gecka-security'), 'alert_logins' => __('Login alert', 'gecka-security')] as $key => $label) {
            if ($settings->enabled($key)) {
                $on[] = $label;
            }
        }

        $info['gecka-security'] = [
            'label' => __('Gecka Security', 'gecka-security'),
            'fields' => [
                'version' => ['label' => __('Version', 'gecka-security'), 'value' => Plugin::VERSION . ' / ' . Schema::VERSION],
                'protections' => ['label' => __('Protections on', 'gecka-security'), 'value' => $on ? implode(', ', $on) : __('none', 'gecka-security')],
                'thresholds' => [
                    'label' => __('Lockouts', 'gecka-security'),
                    'value' => sprintf(
                        /* translators: 1: failures, as "5 failures", 2: minutes, as "20 minutes", 3: lockouts, as "4 lockouts", 4: hours, as "24 hours" */
                        __('%1$s: %2$s; %3$s: %4$s', 'gecka-security'),
                        /* translators: %s: number of failures */
                        self::count(_n('%s failure', '%s failures', $failures, 'gecka-security'), $failures),
                        /* translators: %s: number of minutes */
                        self::count(_n('%s minute', '%s minutes', $minutes, 'gecka-security'), $minutes),
                        /* translators: %s: number of lockouts */
                        self::count(_n('%s lockout', '%s lockouts', $lockouts, 'gecka-security'), $lockouts),
                        /* translators: %s: number of hours */
                        self::count(_n('%s hour', '%s hours', $hours, 'gecka-security'), $hours),
                    ),
                    'debug' => sprintf('%d/%dm %d/%dh', $settings->int('max_failures'), $settings->int('lockout_minutes'), $settings->int('max_lockouts'), $settings->int('long_lockout_hours')),
                ],
                'locked' => ['label' => __('Addresses locked out', 'gecka-security'), 'value' => number_format_i18n($this->plugin->lockouts()->countActive()), 'debug' => $this->plugin->lockouts()->countActive()],
                'ip_source' => ['label' => __('Address of the visitor', 'gecka-security'), 'value' => Settings::ipSources()[$settings->string('ip_source')] ?? $settings->string('ip_source'), 'debug' => $settings->string('ip_source')],
                'trusted_proxies' => ['label' => __('Trusted proxies', 'gecka-security'), 'value' => number_format_i18n(count($settings->strings('trusted_proxies'))), 'private' => true],
                'safelist' => ['label' => __('Safelist', 'gecka-security'), 'value' => number_format_i18n(count($settings->strings('safelist'))), 'private' => true],
                'reserved_names' => ['label' => __('Reserved names', 'gecka-security'), 'value' => number_format_i18n(count($settings->strings('reserved_names')))],
                'blocklist' => ['label' => __('Blocklist', 'gecka-security'), 'value' => number_format_i18n(count($settings->strings('blocklist'))), 'private' => true],
                'countries' => [
                    'label' => __('Countries', 'gecka-security'),
                    'value' => match ($settings->string('countries_mode')) {
                        /* translators: %s: country codes */
                        Access::ALLOW => sprintf(__('only %s', 'gecka-security'), implode(', ', $settings->strings('countries'))),
                        /* translators: %s: country codes */
                        Access::DENY => sprintf(__('all but %s', 'gecka-security'), implode(', ', $settings->strings('countries'))),
                        default => __('every country', 'gecka-security'),
                    },
                    'debug' => trim($settings->string('countries_mode') . ' ' . implode(',', $settings->strings('countries'))),
                ],
                'geolocation' => ['label' => __('Gecka Geolocation', 'gecka-security'), 'value' => Access::geolocation() ? __('active: countries and networks known', 'gecka-security') : __('not active: no country check, no new network alert', 'gecka-security'), 'debug' => Access::geolocation() ? 'active' : 'inactive'],
                'retention' => [
                    'label' => __('Kept for', 'gecka-security'),
                    'value' => sprintf(
                        /* translators: 1: how long the journal is kept, as "30 days", 2: how long the statistics are kept, as "365 days" */
                        __('journal %1$s, statistics %2$s', 'gecka-security'),
                        /* translators: %s: number of days */
                        self::count(_n('%s day', '%s days', $journal, 'gecka-security'), $journal),
                        /* translators: %s: number of days */
                        self::count(_n('%s day', '%s days', $statistics, 'gecka-security'), $statistics),
                    ),
                    'debug' => sprintf('%d/%d', $settings->int('events_days'), $settings->int('stats_days')),
                ],
            ],
        ];

        return $info;
    }

    /**
     * A result of a test, with the badge of the plugin and, unless all is
     * well or the test is the daily task, a link: to the address given, or
     * to the settings of the plugin
     *
     * @param string $test        Name of the test, as tests() registers it.
     * @param string $status      good, recommended or critical.
     * @param string $label       Title of the result.
     * @param string $description Explanation, plain text.
     * @param string $url         Address of the link, empty for the settings of the plugin.
     *
     * @return array{label: string, status: string, badge: array{label: string, color: string}, description: string, actions: string, test: string}
     */
    private function result(string $test, string $status, string $label, string $description, string $url = ''): array
    {
        $action = $url !== ''
            ? sprintf('<p><a href="%s">%s</a></p>', esc_url($url), esc_html(match (true) {
                str_contains($url, 'site-health') => __('Site Health info', 'gecka-security'),
                str_contains($url, 'plugins.php') => __('Plugins', 'gecka-security'),
                default => __('General settings', 'gecka-security'),
            }))
            : sprintf('<p><a href="%s">%s</a></p>', esc_url(SettingsPage::url('settings')), esc_html__('Settings of Gecka Security', 'gecka-security'));

        return [
            'label' => $label,
            'status' => $status,
            'badge' => ['label' => __('Security', 'gecka-security'), 'color' => 'blue'],
            'description' => '<p>' . esc_html($description) . '</p>',
            'actions' => $status === 'good' || $test === 'gecka_security_schedule' ? '' : $action,
            'test' => $test,
        ];
    }

    /**
     * A number in a phrase _n() chose for it, as "5 failures"
     *
     * @param string $phrase The phrase, its number as %s.
     * @param int    $number Number put in the phrase, formatted for the locale.
     *
     * @return string
     */
    private static function count(string $phrase, int $number): string
    {
        return sprintf($phrase, number_format_i18n($number));
    }
}

<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * The settings of the plugin, held in one option.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Settings
{
    /**
     * Option holding every setting.
     */
    public const OPTION = 'gecka_security_settings';

    /**
     * Lowest and highest value of each number setting.
     */
    public const BOUNDS = [
        'max_failures' => [1, 100],
        'failures_window' => [1, 1440],
        'lockout_minutes' => [1, 1440],
        'max_lockouts' => [1, 100],
        'lockouts_window' => [1, 720],
        'long_lockout_hours' => [1, 720],
        'resets_per_hour' => [1, 100],
        'registrations_per_hour' => [1, 100],
        'events_days' => [1, 365],
        'stats_days' => [30, 3650],
    ];

    /**
     * Settings each form of the settings page posts, by the value of its form
     * field. A box of that form left unticked is not posted at all: it reads
     * as false for the settings of the form, and leaves the others as stored.
     */
    public const SECTIONS = [
        'settings' => [
            'bruteforce', 'max_failures', 'failures_window', 'lockout_minutes', 'max_lockouts', 'lockouts_window', 'long_lockout_hours',
            'ip_source', 'trusted_proxies', 'safelist', 'blocklist', 'countries_mode', 'countries',
            'author_archives', 'rest_users', 'oembed_author', 'sitemap_users', 'login_errors', 'xmlrpc_disabled', 'pingback_disabled', 'trackback_disabled',
            'security_headers', 'hsts', 'file_edit_disabled', 'log_logins', 'log_unknown_logins', 'pwned_passwords',
            'log_accounts', 'alert_admins', 'alert_new_network', 'alert_logins', 'limit_requests', 'resets_per_hour', 'registrations_per_hour',
            'reserved_names', 'events_days', 'stats_days',
        ],
    ];

    /**
     * Logins bots try first, refused at registration and counted double when
     * a login on them fails.
     */
    public const RESERVED_NAMES = ['admin', 'administrator', 'root', 'superadmin', 'sysadmin', 'webmaster', 'support', 'test', 'user', 'demo', 'guest', 'info', 'contact'];

    /**
     * Settings read, kept for the request.
     *
     * @var array<string, mixed>|null
     */
    private ?array $settings = null;

    /**
     * Where the address of the visitor is read, by the value of the setting
     *
     * @return array<string, string>
     */
    public static function ipSources(): array
    {
        return [
            ClientIp::REMOTE_ADDR => __('The address the server saw (REMOTE_ADDR)', 'gecka-security'),
            'x_forwarded_for' => __('X-Forwarded-For, sent by a reverse proxy or a load balancer', 'gecka-security'),
            'x_real_ip' => __('X-Real-IP, sent by nginx', 'gecka-security'),
            'cf_connecting_ip' => __('CF-Connecting-IP, sent by Cloudflare', 'gecka-security'),
        ];
    }

    /**
     * Default values
     *
     * @return array<string, mixed>
     */
    public function defaults(): array
    {
        return [
            'bruteforce' => true,
            'max_failures' => 5,
            'failures_window' => 60,
            'lockout_minutes' => 20,
            'max_lockouts' => 4,
            'lockouts_window' => 24,
            'long_lockout_hours' => 24,

            'ip_source' => ClientIp::REMOTE_ADDR,
            'trusted_proxies' => [],
            'safelist' => [],
            'blocklist' => [],
            'countries_mode' => '',
            'countries' => [],

            'author_archives' => true,
            'rest_users' => false,
            'oembed_author' => true,
            'sitemap_users' => true,
            'login_errors' => true,
            'xmlrpc_disabled' => false,
            'pingback_disabled' => true,
            'trackback_disabled' => true,

            'security_headers' => true,
            'hsts' => false,
            'file_edit_disabled' => true,
            'log_logins' => true,
            'log_unknown_logins' => false,
            'pwned_passwords' => false,
            'log_accounts' => true,
            'alert_admins' => true,
            'alert_new_network' => true,
            'alert_logins' => false,
            'limit_requests' => true,
            'resets_per_hour' => 5,
            'registrations_per_hour' => 5,

            'reserved_names' => self::RESERVED_NAMES,

            'events_days' => 30,
            'stats_days' => 365,
        ];
    }

    /**
     * Every setting, the defaults filling the gaps
     *
     * @return array<string, mixed>
     */
    public function all(): array
    {
        if ($this->settings === null) {
            $this->settings = $this->stored();
        }

        return $this->settings;
    }

    /**
     * The settings saved, the defaults filling the gaps
     *
     * @return array<string, mixed>
     */
    private function stored(): array
    {
        $saved = (array) Scope::option(self::OPTION, []);
        $defaults = $this->defaults();

        return array_merge($defaults, array_intersect_key($saved, $defaults));
    }

    /**
     * One setting
     *
     * @param string $key Name of the setting.
     *
     * @return mixed Null for an unknown setting.
     */
    public function get(string $key): mixed
    {
        return $this->all()[$key] ?? null;
    }

    /**
     * A number setting
     *
     * @param string $key Name of the setting.
     *
     * @return int
     */
    public function int(string $key): int
    {
        return Value::int($this->get($key));
    }

    /**
     * A text setting
     *
     * @param string $key Name of the setting.
     *
     * @return string
     */
    public function string(string $key): string
    {
        return Value::string($this->get($key));
    }

    /**
     * A list setting: the proxies, the safelist, the blocklist, the
     * countries, the reserved names
     *
     * @param string $key Name of the setting.
     *
     * @return list<string>
     */
    public function strings(string $key): array
    {
        return Value::strings($this->get($key));
    }

    /**
     * Whether a protection is on
     *
     * @param string $key One of bruteforce, author_archives, rest_users, oembed_author, sitemap_users, login_errors, xmlrpc_disabled, pingback_disabled, trackback_disabled, security_headers, hsts, file_edit_disabled, log_logins, log_unknown_logins, pwned_passwords, log_accounts, alert_admins, alert_new_network, alert_logins, limit_requests.
     *
     * @return bool
     */
    public function enabled(string $key): bool
    {
        $enabled = ! empty($this->all()[$key]);

        /**
         * Filters whether a protection is on.
         *
         * @param bool   $enabled Whether the protection is ticked in the settings.
         * @param string $key     The protection: bruteforce, author_archives, rest_users...
         */
        return (bool) apply_filters('gecka_security_protect', $enabled, $key);
    }

    /**
     * Whether the settings refuse some addresses for good: a blocklist, or
     * countries checked
     *
     * @return bool
     */
    public function restricts(): bool
    {
        return $this->strings('blocklist') !== [] || $this->string('countries_mode') !== '';
    }

    /**
     * Whether a login is one of the reserved names
     *
     * @param string $login Login typed, compared trimmed and in lower case.
     *
     * @return bool
     */
    public function isReserved(string $login): bool
    {
        return in_array(strtolower(trim($login)), (array) $this->get('reserved_names'), true);
    }

    /**
     * Saves the settings as given, the keys unknown dropped by the next read.
     *
     * @param array<string, mixed> $settings Settings by name.
     *
     * @return void
     */
    public function save(array $settings): void
    {
        Scope::saveOption(self::OPTION, $settings, true);
        $this->flush();
    }

    /**
     * Saves some settings, the others kept as stored.
     *
     * @param array<string, mixed> $changes Settings to change, by name.
     *
     * @return void
     */
    public function merge(array $changes): void
    {
        /** @var array<string, mixed> $stored The option holds the settings by name. */
        $stored = (array) Scope::option(self::OPTION, []);

        $this->save(array_merge($stored, $changes));
    }

    /**
     * Puts every setting back to its default.
     *
     * @return void
     */
    public function reset(): void
    {
        Scope::deleteOption(self::OPTION);
        $this->flush();
    }

    /**
     * Forgets the settings read, once they were saved.
     *
     * @return void
     */
    public function flush(): void
    {
        $this->settings = null;
    }

    /**
     * Cleans the settings before they are saved.
     *
     * A form of the settings page posts every field it shows, a box left
     * unticked being absent, along with its `form` field naming its section
     * of SECTIONS. Any other write only holds the keys it changes, the others
     * keep their value.
     *
     * @param mixed $input Settings to save: those a form posts, with its form field, or only the keys a write changes.
     *
     * @return array<string, mixed> Every setting, cleaned.
     */
    public function sanitize(mixed $input): array
    {
        $input = is_array($input) ? $input : [];
        $posted = self::SECTIONS[Value::string($input['form'] ?? '')] ?? [];
        $current = $this->stored();

        $flag = static fn(string $key): bool => in_array($key, $posted, true) ? ! empty($input[$key]) : (bool) ($input[$key] ?? $current[$key]);
        $number = static fn(string $key): int => self::clamp($input[$key] ?? $current[$key], ...self::BOUNDS[$key]);
        $list = static fn(string $key): array => Network::parseList($input[$key] ?? $current[$key]);

        $source = Value::string($input['ip_source'] ?? $current['ip_source']);
        $source = isset(self::ipSources()[$source]) ? $source : ClientIp::REMOTE_ADDR;
        $proxies = $list('trusted_proxies');

        if ($proxies !== Network::withoutTooWide($proxies)) {
            add_settings_error(self::OPTION, 'trusted_proxies', __('A trusted proxy network cannot be wider than a /8 for IPv4 or a /16 for IPv6: with it, anyone could choose the address they are seen under. The list is kept without it.', 'gecka-security'));
            $proxies = Network::withoutTooWide($proxies);
        }

        $safelist = $list('safelist');

        if ($safelist !== Network::withoutTooWide($safelist)) {
            add_settings_error(self::OPTION, 'safelist', __('A safelist network cannot be wider than a /8 for IPv4 or a /16 for IPv6: with it, almost nothing would ever be locked out. The list is kept without it.', 'gecka-security'));
            $safelist = Network::withoutTooWide($safelist);
        }

        $blocklist = $list('blocklist');

        if ($blocklist !== Network::withoutTooWide($blocklist)) {
            add_settings_error(self::OPTION, 'blocklist', __('A blocklist network cannot be wider than a /8 for IPv4 or a /16 for IPv6: refuse a whole region by its country instead. The list is kept without it.', 'gecka-security'));
            $blocklist = Network::withoutTooWide($blocklist);
        }

        $mode = Value::string($input['countries_mode'] ?? $current['countries_mode']);
        $mode = in_array($mode, [Access::ALLOW, Access::DENY], true) ? $mode : '';
        $countries = Access::parseCountries($input['countries'] ?? $current['countries']);

        if ($mode === Access::ALLOW && $countries === []) {
            add_settings_error(self::OPTION, 'countries', __('Name the countries allowed to log in: with none, every country would be refused. The countries are not checked.', 'gecka-security'));
            $mode = '';
        }

        if ($source !== ClientIp::REMOTE_ADDR && $proxies === []) {
            add_settings_error(self::OPTION, 'ip_source', __('A header is read only from a proxy you trust: list the addresses of your proxies, or keep the address the server saw. The address the server saw is kept.', 'gecka-security'));
            $source = ClientIp::REMOTE_ADDR;
        }

        // The settings never refuse the administrator saving them, read as
        // the source and the proxies saved read them, unless the safelist
        // lets them in anyway.
        $ip = ClientIp::read($source, $proxies);
        $ip = Network::isUsable($ip) ? $ip : '';

        if ($ip !== '' && ! Network::inList($ip, array_merge($safelist, ClientIp::constantSafelist()))) {
            $kept = array_values(array_filter($blocklist, static fn(string $network): bool => ! Network::inList($ip, [$network])));

            if ($kept !== $blocklist) {
                /* translators: %s: IP address */
                add_settings_error(self::OPTION, 'blocklist_self', sprintf(__('The blocklist would refuse your own address, %s. The list is kept without the networks holding it.', 'gecka-security'), $ip));
                $blocklist = $kept;
            }

            $refusal = Access::refusal($ip, [], $mode, $countries);

            if ($refusal !== null) {
                /* translators: %s: country code */
                add_settings_error(self::OPTION, 'countries_self', sprintf(__('The countries would refuse your own address, from %s. They are kept as they were.', 'gecka-security'), $refusal['country']));
                $mode = Value::string($current['countries_mode']);
                $countries = Access::parseCountries($current['countries']);
            }
        }

        return [
            'bruteforce' => $flag('bruteforce'),
            'max_failures' => $number('max_failures'),
            'failures_window' => $number('failures_window'),
            'lockout_minutes' => $number('lockout_minutes'),
            'max_lockouts' => $number('max_lockouts'),
            'lockouts_window' => $number('lockouts_window'),
            'long_lockout_hours' => $number('long_lockout_hours'),

            'ip_source' => $source,
            'trusted_proxies' => $proxies,
            'safelist' => $safelist,
            'blocklist' => $blocklist,
            'countries_mode' => $mode,
            'countries' => $countries,

            'author_archives' => $flag('author_archives'),
            'rest_users' => $flag('rest_users'),
            'oembed_author' => $flag('oembed_author'),
            'sitemap_users' => $flag('sitemap_users'),
            'login_errors' => $flag('login_errors'),
            'xmlrpc_disabled' => $flag('xmlrpc_disabled'),
            'pingback_disabled' => $flag('pingback_disabled'),
            'trackback_disabled' => $flag('trackback_disabled'),
            'security_headers' => $flag('security_headers'),
            'hsts' => $flag('hsts'),
            'file_edit_disabled' => $flag('file_edit_disabled'),
            'log_logins' => $flag('log_logins'),
            'log_unknown_logins' => $flag('log_unknown_logins'),
            'pwned_passwords' => $flag('pwned_passwords'),
            'log_accounts' => $flag('log_accounts'),
            'alert_admins' => $flag('alert_admins'),
            'alert_new_network' => $flag('alert_new_network'),
            'alert_logins' => $flag('alert_logins'),
            'limit_requests' => $flag('limit_requests'),
            'resets_per_hour' => $number('resets_per_hour'),
            'registrations_per_hour' => $number('registrations_per_hour'),

            'reserved_names' => self::logins($input['reserved_names'] ?? $current['reserved_names']),

            'events_days' => $number('events_days'),
            'stats_days' => $number('stats_days'),
        ];
    }

    /**
     * The logins of a list typed one per line or separated by commas, in
     * lowercase, each once
     *
     * @param mixed $value A string, or a list.
     *
     * @return string[]
     */
    public static function logins(mixed $value): array
    {
        $entries = is_array($value) ? $value : preg_split('/[\s,;]+/', Value::string($value));
        $logins = array_map(static fn(mixed $login): string => strtolower(Value::string(sanitize_user(trim(Value::string($login)), true))), $entries ?: []);

        return array_values(array_unique(array_filter($logins, static fn(string $login): bool => $login !== '')));
    }

    /**
     * An integer kept within bounds
     *
     * @param mixed $value Value, read as an integer.
     * @param int   $min   Lowest value allowed.
     * @param int   $max   Highest value allowed.
     *
     * @return int
     */
    private static function clamp(mixed $value, int $min, int $max): int
    {
        return max($min, min($max, Value::int($value)));
    }
}

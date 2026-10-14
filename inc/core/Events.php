<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * The journal: what the protections saw and did, one row per event, with
 * the address, the login tried and the way in, kept for the days the
 * settings say and MAX_ENTRIES rows of each kind at most, the oldest of that
 * kind pushed out past that: a flood of one kind never pushes another out.
 * The refusals of one lockout fold into one row, counted in its hits, the
 * time of the last one kept; they are matched on the key the address is
 * watched under, so the refusals of one IPv6 /64 make one row.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Events
{
    /**
     * A login that failed on its credentials.
     */
    public const FAILED = 'failed';

    /**
     * A login that failed on a reserved name no account carries.
     */
    public const RESERVED = 'reserved';

    /**
     * An address locked out, after too many failures.
     */
    public const LOCKOUT = 'lockout';

    /**
     * An attempt refused while the address was locked out.
     */
    public const BLOCKED = 'blocked';

    /**
     * A request listing the accounts, refused.
     */
    public const ENUMERATION = 'enumeration';

    /**
     * A login that succeeded.
     */
    public const LOGIN = 'login';

    /**
     * A login made with a password known from data breaches.
     */
    public const BREACHED = 'breached';

    /**
     * An account created, changed or deleted.
     */
    public const ACCOUNT = 'account';

    /**
     * A request refused past the limit of the hour.
     */
    public const LIMITED = 'limited';

    /**
     * An attempt of an address the settings refuse for good: on the
     * blocklist, or from a country refused.
     */
    public const REFUSED = 'refused';

    /**
     * Rows of each kind kept at most, the most recent ones.
     */
    public const MAX_ENTRIES = 10000;

    /**
     * Transient holding the logins seen most, for the filter of the journal:
     * grouping the whole journal on each view would weigh on a large one.
     */
    public const LOGINS_CACHE = 'gecka_security_logins';

    /**
     * Seconds the logins seen most are kept.
     */
    private const LOGINS_CACHE_SECONDS = 600;

    /**
     * Characters of a login kept.
     */
    private const USERNAME_LENGTH = 60;

    /**
     * Characters of a detail kept.
     */
    private const DETAIL_LENGTH = 191;

    /**
     * Table of the journal
     *
     * @return string
     */
    public static function table(): string
    {
        return Schema::events();
    }

    /**
     * The kinds of event, with their labels, kept for the request in each
     * language asked
     *
     * @return array<string, string>
     */
    public static function types(): array
    {
        /** @var array<string, array<string, string>> $labels */
        static $labels = [];

        return $labels[determine_locale()] ??= [
            self::FAILED => __('Failed login', 'gecka-security'),
            self::RESERVED => __('Reserved name', 'gecka-security'),
            self::LOCKOUT => __('Lockout', 'gecka-security'),
            self::BLOCKED => __('Refused while locked out', 'gecka-security'),
            self::ENUMERATION => __('Enumeration refused', 'gecka-security'),
            self::LOGIN => __('Successful login', 'gecka-security'),
            self::BREACHED => __('Breached password', 'gecka-security'),
            self::ACCOUNT => __('Account change', 'gecka-security'),
            self::LIMITED => __('Request limited', 'gecka-security'),
            self::REFUSED => __('Address refused', 'gecka-security'),
        ];
    }

    /**
     * Label of a kind of event
     *
     * @param string $type Kind of event, one of the constants.
     *
     * @return string The label, or the kind itself when it is unknown.
     */
    public static function typeLabel(string $type): string
    {
        return self::types()[$type] ?? $type;
    }

    /**
     * The ways a request came in, with their labels, kept for the request
     * in each language asked
     *
     * @return array<string, string>
     */
    public static function vectors(): array
    {
        /** @var array<string, array<string, string>> $labels */
        static $labels = [];

        return $labels[determine_locale()] ??= [
            Request::LOGIN_FORM => __('Login form', 'gecka-security'),
            Request::WOOCOMMERCE => __('WooCommerce', 'gecka-security'),
            Request::XMLRPC => __('XML-RPC', 'gecka-security'),
            Request::REST => __('REST API', 'gecka-security'),
            Request::OTHER => __('Other', 'gecka-security'),
            'author' => __('Author archive', 'gecka-security'),
            'rest_users' => __('REST API users', 'gecka-security'),
        ];
    }

    /**
     * Label of a way in
     *
     * @param string $vector Way in, a key of vectors().
     *
     * @return string The label, or the way in itself when it is unknown.
     */
    public static function vectorLabel(string $vector): string
    {
        return self::vectors()[$vector] ?? $vector;
    }

    /**
     * Records an event.
     *
     * @param string $type     One of the type constants.
     * @param string $ip       Address of the visitor, empty when unknown.
     * @param string $username Login tried, if any.
     * @param string $vector   The way in.
     * @param string $detail   A code describe() words, or free text.
     * @param array<string, mixed> $params What the code needs, if anything.
     *
     * @return void
     */
    public function record(string $type, string $ip, string $username = '', string $vector = '', string $detail = '', array $params = []): void
    {
        $wpdb = Scope::db();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->insert(
            self::table(),
            [
                'site' => get_current_blog_id(),
                'created' => current_time('mysql', true),
                'type' => $type,
                'ip' => $ip,
                'net' => $ip === '' ? '' : Network::key($ip),
                'username' => mb_substr($username, 0, self::USERNAME_LENGTH),
                'login' => self::loginKey($username),
                'way' => $vector,
                'detail' => mb_substr($detail, 0, self::DETAIL_LENGTH),
                'params' => self::encode($params),
            ],
            ['%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s'],
        );

        if ($wpdb->insert_id % 100 === 0 && $this->count(['type' => $type]) > self::maxEntries()) {
            $this->trim($type);
        }
    }

    /**
     * Counts one more hit on the latest event of a kind for an address,
     * when it came after the latest event of another kind for it: the
     * refusals of one lockout fold into the row of the first. The address
     * is matched as the key it is watched under, the /64 for IPv6, the
     * same key the lockout holds; the row keeps the address of its first
     * refusal.
     *
     * @param string $type  Kind of the event counted up.
     * @param string $ip    Address of the visitor.
     * @param string $after Kind of the event starting the series.
     *
     * @return bool Whether a row was counted up, its last time set; false calls for a new row.
     */
    public function bump(string $type, string $ip, string $after): bool
    {
        $wpdb = Scope::db();

        $net = Network::key($ip);

        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $start = (int) $wpdb->get_var($wpdb->prepare('SELECT MAX(id) FROM %i WHERE net = %s AND type = %s', self::table(), $net, $after));
        $id = (int) $wpdb->get_var($wpdb->prepare('SELECT id FROM %i WHERE net = %s AND type = %s AND id > %d ORDER BY id DESC LIMIT 1', self::table(), $net, $type, $start));

        if (! $id) {
            return false;
        }

        $wpdb->query($wpdb->prepare('UPDATE %i SET hits = hits + 1, last = %s WHERE id = %d', self::table(), current_time('mysql', true), $id));
        // phpcs:enable

        return true;
    }

    /**
     * Counts one more hit on the latest event that is the same, kind, key
     * of the address, login, detail and parameters alike, when that row was
     * created within the last seconds given.
     *
     * @param string $type     Kind of event, one of the constants.
     * @param string $ip       Address of the visitor, matched as the key it is watched under.
     * @param string $username Login, matched in lower case.
     * @param string $detail   Detail of the event, matched as stored.
     * @param int    $seconds  How long ago the row may have been created.
     * @param array<string, mixed> $params Parameters of the code, matched as stored.
     *
     * @return bool Whether a row was counted up; false calls for a new row.
     */
    public function bumpRecent(string $type, string $ip, string $username, string $detail, int $seconds, array $params = []): bool
    {
        $wpdb = Scope::db();

        $since = gmdate('Y-m-d H:i:s', time() - $seconds);

        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $id = (int) $wpdb->get_var($wpdb->prepare('SELECT id FROM %i WHERE net = %s AND type = %s AND login = %s AND detail = %s AND params = %s AND created >= %s ORDER BY id DESC LIMIT 1', self::table(), Network::key($ip), $type, self::loginKey($username), mb_substr($detail, 0, self::DETAIL_LENGTH), self::encode($params), $since));

        if (! $id) {
            return false;
        }

        $wpdb->query($wpdb->prepare('UPDATE %i SET hits = hits + 1, last = %s WHERE id = %d', self::table(), current_time('mysql', true), $id));
        // phpcs:enable

        return true;
    }

    /**
     * Counts one more hit on the latest event of a kind for the key of an
     * address, a login and a way in, when that row was created within the
     * last seconds given, whatever its detail: a scan asking one target
     * after another folds into the row of its first target.
     *
     * @param string $type     Kind of event, one of the constants.
     * @param string $ip       Address of the visitor, matched as the key it is watched under.
     * @param string $username Login, matched in lower case.
     * @param string $way      The way in, matched as stored.
     * @param int    $seconds  How long ago the row may have been created.
     *
     * @return bool Whether a row was counted up; false calls for a new row.
     */
    public function bumpScan(string $type, string $ip, string $username, string $way, int $seconds): bool
    {
        $wpdb = Scope::db();

        $since = gmdate('Y-m-d H:i:s', time() - $seconds);

        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $id = (int) $wpdb->get_var($wpdb->prepare('SELECT id FROM %i WHERE net = %s AND type = %s AND login = %s AND way = %s AND created >= %s ORDER BY id DESC LIMIT 1', self::table(), Network::key($ip), $type, self::loginKey($username), $way, $since));

        if (! $id) {
            return false;
        }

        $wpdb->query($wpdb->prepare('UPDATE %i SET hits = hits + 1, last = %s WHERE id = %d', self::table(), current_time('mysql', true), $id));
        // phpcs:enable

        return true;
    }

    /**
     * The detail of an event in words: a known code is worded with its
     * parameters, anything else is given as recorded. The person who made
     * an account change goes last, and can be left out, for an export that
     * must not name a third party.
     *
     * @param object $row       A row of entries().
     * @param bool   $withActor Whether to name who did it.
     *
     * @return string
     */
    public static function describe(object $row, bool $withActor = true): string
    {
        $code = Value::string($row->detail ?? '');
        $params = self::decode($row->params ?? null);
        $roles = implode(', ', Value::strings($params['roles'] ?? []));
        $role = Value::string($params['role'] ?? '');
        $count = Value::int($params['count'] ?? 0);

        $text = match ($code) {
            'lockout.long' => __('long lockout', 'gecka-security'),
            'lockout.short' => __('short lockout', 'gecka-security'),
            'enumeration.lost_password' => __('lost password', 'gecka-security'),
            'refused.address' => __('on the blocklist', 'gecka-security'),
            /* translators: %s: country name */
            'refused.country' => sprintf(__('from %s, a country refused', 'gecka-security'), self::countryName(Value::string($params['country'] ?? ''))),
            /* translators: %s: name of the application password */
            'login.application_password' => implode(' · ', array_filter([$roles, sprintf(__('application password %s', 'gecka-security'), Value::string($params['name'] ?? ''))])),
            /* translators: %s: number of times the password was seen in breaches */
            'breached.seen' => sprintf(_n('seen %s time in breaches', 'seen %s times in breaches', $count, 'gecka-security'), number_format_i18n($count)),
            /* translators: %s: number allowed an hour */
            'limited.reset' => sprintf(__('password resets: more than %s an hour', 'gecka-security'), number_format_i18n(Value::int($params['limit'] ?? 0))),
            /* translators: %s: number allowed an hour */
            'limited.register' => sprintf(__('registrations: more than %s an hour', 'gecka-security'), number_format_i18n(Value::int($params['limit'] ?? 0))),
            /* translators: %s: roles */
            'account.created' => sprintf(__('created with the %s role', 'gecka-security'), $roles !== '' ? $roles : __('no role', 'gecka-security')),
            /* translators: 1: new role, 2: former roles */
            'account.role_set' => sprintf(__('role %1$s set in place of %2$s', 'gecka-security'), $role, implode(', ', Value::strings($params['old'] ?? []))),
            /* translators: %s: role */
            'account.role_set_none' => sprintf(__('role %s set, the account having none', 'gecka-security'), $role),
            /* translators: %s: role */
            'account.role_added' => sprintf(__('role %s added', 'gecka-security'), $role),
            /* translators: %s: role */
            'account.role_removed' => sprintf(__('role %s removed', 'gecka-security'), $role),
            /* translators: 1: former address, 2: new address */
            'account.email' => sprintf(__('e-mail address changed from %1$s to %2$s', 'gecka-security'), Value::string($params['from'] ?? ''), Value::string($params['to'] ?? '')),
            'account.password' => __('password changed', 'gecka-security'),
            'account.reset' => __('password reset through the form', 'gecka-security'),
            'account.deleted' => __('deleted', 'gecka-security'),
            'account.super_admin_granted' => __('made super administrator of the network', 'gecka-security'),
            'account.super_admin_revoked' => __('no longer super administrator of the network', 'gecka-security'),
            default => $code,
        };

        if ($withActor && array_key_exists('actor', $params)) {
            /* translators: 1: what happened, 2: who did it */
            $text = sprintf(__('%1$s by %2$s', 'gecka-security'), $text, self::actorLabel(Value::string($params['actor'])));
        }

        return $text;
    }

    /**
     * The name of a country, as Gecka Geolocation gives it in the language
     * of the reader
     *
     * @param string $code Code of the country.
     *
     * @return string The name, or the code without Gecka Geolocation.
     */
    public static function countryName(string $code): string
    {
        $name = $code !== '' && function_exists('gecka_geolocation_country_name') ? gecka_geolocation_country_name($code) : null;

        return $name ?? $code;
    }

    /**
     * Who made a change, in words: the login recorded, WP-CLI, nobody, or an
     * account whose data was erased
     *
     * @param string $actor A login, Accounts::CLI, Accounts::ERASED, or an empty string for nobody logged in.
     *
     * @return string
     */
    public static function actorLabel(string $actor): string
    {
        return match ($actor) {
            '' => __('nobody logged in', 'gecka-security'),
            Integrations\Accounts::CLI => 'WP-CLI',
            Integrations\Accounts::ERASED => __('an account whose data was erased', 'gecka-security'),
            default => $actor,
        };
    }

    /**
     * A login as the login column keeps it: cut to the length of the
     * column and in lower case, as WordPress reads a login whatever its
     * case. Filters, export and erasure match on it.
     *
     * @param string $login Login as typed.
     *
     * @return string
     */
    public static function loginKey(string $login): string
    {
        return mb_strtolower(mb_substr($login, 0, self::USERNAME_LENGTH));
    }

    /**
     * The parameters of an event as stored
     *
     * @param array<string, mixed> $params Parameters of the code of the event.
     *
     * @return string JSON, or an empty string for none.
     */
    private static function encode(array $params): string
    {
        return $params ? (string) wp_json_encode($params) : '';
    }

    /**
     * The parameters of an event as recorded
     *
     * @param mixed $stored The params column.
     *
     * @return array<string, mixed>
     */
    private static function decode(mixed $stored): array
    {
        $decoded = is_string($stored) && $stored !== '' ? json_decode($stored, true) : null;
        $params = [];

        foreach (is_array($decoded) ? $decoded : [] as $key => $value) {
            if (is_string($key)) {
                $params[$key] = $value;
            }
        }

        return $params;
    }

    /**
     * Rows of each kind kept at most
     *
     * @return int
     */
    public static function maxEntries(): int
    {
        /**
         * Filters the number of rows of each kind the journal keeps at most.
         *
         * @param int $max The maximum, 10 000 unless filtered.
         */
        return max(1, (int) apply_filters('gecka_security_max_entries', self::MAX_ENTRIES));
    }

    /**
     * Events, the most recent first
     *
     * @param int                        $page    From 1.
     * @param int                        $perPage Events per page.
     * @param array{type?: string, ip?: string, net?: string, username?: string[]} $filters Filters of the list, as EventsView::filters() gives them; none lists every event.
     *
     * @return list<\stdClass> Rows of id, site, created, type, ip, username, way, detail, params, hits and last, as the database gives them.
     */
    public function entries(int $page, int $perPage, array $filters = []): array
    {
        $wpdb = Scope::db();

        [$where, $values] = self::where($filters);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table of the plugin; $where is made of placeholders, one value each.
        $rows = $wpdb->get_results($wpdb->prepare("SELECT id, site, created, type, ip, username, way, detail, params, hits, last FROM %i $where ORDER BY id DESC LIMIT %d OFFSET %d", self::table(), ...[...$values, $perPage, max(0, $page - 1) * $perPage]));

        return $rows ?? [];
    }

    /**
     * Number of events
     *
     * @param array{type?: string, ip?: string, net?: string, username?: string[]} $filters Filters, as entries() takes them; none counts every event.
     *
     * @return int
     */
    public function count(array $filters = []): int
    {
        $wpdb = Scope::db();

        [$where, $values] = self::where($filters);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table of the plugin; $where is made of placeholders, one value each.
        return (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM %i $where", self::table(), ...$values));
    }

    /**
     * Number of events of each kind
     *
     * @param array{ip?: string, net?: string, username?: string[]} $filters Filters of the list, the kind left out.
     *
     * @return array<string, int> Keyed by kind; a kind with no event is missing.
     */
    public function countsByType(array $filters = []): array
    {
        $wpdb = Scope::db();

        [$where, $values] = self::where($filters);
        $counts = [];

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table of the plugin; $where is made of placeholders, one value each.
        foreach ((array) $wpdb->get_results($wpdb->prepare("SELECT type, COUNT(*) AS hits FROM %i $where GROUP BY type", self::table(), ...$values)) as $row) {
            $counts[Value::string($row->type)] = Value::int($row->hits);
        }

        return $counts;
    }

    /**
     * Deletes events.
     *
     * @param int[] $ids Ids of the events.
     *
     * @return void
     */
    public function delete(array $ids): void
    {
        $wpdb = Scope::db();

        foreach (array_chunk(array_map('intval', $ids), 500) as $chunk) {
            $in = implode(',', array_fill(0, count($chunk), '%d'));

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Table of the plugin; $in is one placeholder per id.
            $wpdb->query($wpdb->prepare("DELETE FROM %i WHERE id IN ($in)", self::table(), ...$chunk));
        }

        self::forgetLogins();
    }

    /**
     * The logins seen most in the journal, in lower case as WordPress reads
     * them, with their number of events
     *
     * @param int $limit Logins returned at most.
     *
     * @return array<string, int> Keyed by login, the most seen first.
     */
    public function logins(int $limit = 100): array
    {
        $wpdb = Scope::db();

        $logins = [];

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, read on the journal screen only.
        foreach ((array) $wpdb->get_results($wpdb->prepare("SELECT login, COUNT(*) AS hits FROM %i WHERE login <> '' GROUP BY login ORDER BY hits DESC, login ASC LIMIT %d", self::table(), $limit)) as $row) {
            $logins[Value::string($row->login)] = Value::int($row->hits);
        }

        return $logins;
    }

    /**
     * The logins seen most, as logins() gives them, computed every ten
     * minutes at most
     *
     * @return array<string, int> Keyed by login, the most seen first.
     */
    public function knownLogins(): array
    {
        $logins = Scope::transient(self::LOGINS_CACHE);

        if (! is_array($logins)) {
            $logins = $this->logins();
            Scope::setTransient(self::LOGINS_CACHE, $logins, self::LOGINS_CACHE_SECONDS);
        }

        $known = [];

        foreach ($logins as $login => $hits) {
            $known[(string) $login] = Value::int($hits);
        }

        return $known;
    }

    /**
     * Takes logins out of the changes they made on other accounts: the rows
     * stay, as they belong to the journal of those accounts, and name
     * Accounts::ERASED as who made the change.
     *
     * @param string[] $logins Logins, in any case.
     *
     * @return int Rows changed.
     */
    public function forgetActor(array $logins): int
    {
        $wpdb = Scope::db();
        $changed = 0;

        foreach ($logins as $login) {
            $fragment = '"actor":' . wp_json_encode($login);

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, read when a person's data is erased.
            $rows = $wpdb->get_results($wpdb->prepare('SELECT id, params FROM %i WHERE type = %s AND params LIKE %s', self::table(), self::ACCOUNT, '%' . $wpdb->esc_like($fragment) . '%')) ?? [];

            foreach ($rows as $row) {
                $params = self::decode($row->params);

                if (mb_strtolower(Value::string($params['actor'] ?? '')) !== mb_strtolower($login)) {
                    continue;
                }

                $params['actor'] = Integrations\Accounts::ERASED;
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
                $changed += (int) $wpdb->update(self::table(), ['params' => self::encode($params)], ['id' => Value::int($row->id)]);
            }
        }

        return $changed;
    }

    /**
     * Deletes the events carrying one of the logins, whatever their case.
     *
     * @param string[] $logins Logins, in any case.
     *
     * @return int Rows deleted.
     */
    public function deleteByLogin(array $logins): int
    {
        $wpdb = Scope::db();

        if (! $logins) {
            return 0;
        }

        $in = implode(',', array_fill(0, count($logins), '%s'));

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Table of the plugin; $in is one placeholder per login.
        $deleted = (int) $wpdb->query($wpdb->prepare("DELETE FROM %i WHERE login IN ($in)", self::table(), ...array_map([self::class, 'loginKey'], array_values($logins))));
        self::forgetLogins();

        return $deleted;
    }

    /**
     * Deletes every event.
     *
     * @return void
     */
    public function clear(): void
    {
        $wpdb = Scope::db();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->query($wpdb->prepare('DELETE FROM %i', self::table()));
        self::forgetLogins();
    }

    /**
     * Deletes the events older than the days kept, and the oldest of each
     * kind past the maximum.
     *
     * @param int $days Days the events are kept.
     *
     * @return void
     */
    public function purge(int $days): void
    {
        $wpdb = Scope::db();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, purged once a day.
        $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE created < %s', self::table(), gmdate('Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS)));

        foreach (array_keys(self::types()) as $type) {
            $this->trim($type);
        }

        self::forgetLogins();
    }

    /**
     * Drops the cached logins seen most, once rows are deleted.
     *
     * @return void
     */
    private static function forgetLogins(): void
    {
        Scope::deleteTransient(self::LOGINS_CACHE);
    }

    /**
     * Deletes the oldest events of a kind past the maximum.
     *
     * @param string $type Kind of event, one of the constants.
     *
     * @return void
     */
    private function trim(string $type): void
    {
        $wpdb = Scope::db();

        $table = self::table();

        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $last = $wpdb->get_var($wpdb->prepare('SELECT id FROM %i WHERE type = %s ORDER BY id DESC LIMIT 1 OFFSET %d', $table, $type, self::maxEntries() - 1));

        if ($last) {
            $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE type = %s AND id < %d', $table, $type, (int) $last));
        }
        // phpcs:enable
    }

    /**
     * The WHERE clause of the filters, and its values
     *
     * @param array{type?: string, ip?: string, net?: string, username?: string[]} $filters Filters, as entries() takes them.
     *
     * @return array{0: string, 1: string[]} The clause, empty for no filter, and one value per placeholder.
     */
    private static function where(array $filters): array
    {
        $clauses = [];
        $values = [];

        if (! empty($filters['type'])) {
            $clauses[] = 'type = %s';
            $values[] = $filters['type'];
        }

        if (! empty($filters['ip'])) {
            $clauses[] = 'ip = %s';
            $values[] = $filters['ip'];
        }

        if (! empty($filters['net'])) {
            $clauses[] = 'net = %s';
            $values[] = $filters['net'];
        }

        if (! empty($filters['username'])) {
            $logins = array_values((array) $filters['username']);
            $clauses[] = 'login IN (' . implode(',', array_fill(0, count($logins), '%s')) . ')';
            array_push($values, ...array_map([self::class, 'loginKey'], $logins));
        }

        return [$clauses ? 'WHERE ' . implode(' AND ', $clauses) : '', $values];
    }
}

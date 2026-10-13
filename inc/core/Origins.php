<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * Daily counters of the events by where they came from: the country and the
 * network of the address, as Gecka Geolocation tells them when it is
 * active, and the operating system the user agent names. Only counts:
 * the address itself is not kept.
 *
 * A network is kept under its autonomous system number, with the name of
 * its organisation as recorded. An address the geolocation knows nothing
 * of, a private one for instance, counts under an empty value. Once a day
 * is over, the networks past the NETWORKS_PER_DAY most seen of that day
 * fold into OTHER_NETWORKS: an attack spread over thousands of networks
 * cannot grow the table by thousands of rows a day for as long as the
 * statistics are kept.
 *
 * The counts of the successful logins tell where the people with an account
 * connect from: they go with the journal, the other counts with the
 * statistics.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Origins
{
    /**
     * Facet of the country of the address.
     */
    public const COUNTRY = 'country';

    /**
     * Facet of the network of the address, by autonomous system number.
     */
    public const NETWORK = 'network';

    /**
     * Facet of the operating system the user agent names.
     */
    public const SYSTEM = 'os';

    /**
     * The events counted as attempts: what the protections refused or saw
     * fail.
     */
    public const ATTEMPTS = [Events::FAILED, Events::RESERVED, Events::BLOCKED, Events::REFUSED, Events::ENUMERATION, Events::LIMITED];

    /**
     * The events counted: the attempts and the successful logins.
     */
    public const COUNTED = [...self::ATTEMPTS, Events::LOGIN];

    /**
     * Characters of the name of a network kept.
     */
    private const NAME_LENGTH = 191;

    /**
     * Networks of a day kept apart, for each kind of event.
     */
    public const NETWORKS_PER_DAY = 200;

    /**
     * Value the networks past the most seen of a day fold into.
     */
    public const OTHER_NETWORKS = 'other';

    /**
     * Counts an event under its system, and under its country and network
     * when Gecka Geolocation gives a record of the address. Only the events
     * of COUNTED are counted, and none without an address.
     *
     * @param string $type One of the Events constants.
     * @param string $ip   Address of the visitor, empty when unknown.
     *
     * @return void
     */
    public function count(string $type, string $ip): void
    {
        if ($ip === '' || ! in_array($type, self::COUNTED, true)) {
            return;
        }

        $this->record(self::SYSTEM, self::system(Request::serverRaw('HTTP_USER_AGENT')), $type);

        $record = function_exists('gecka_geolocation') ? gecka_geolocation($ip) : null;

        if ($record === null) {
            return;
        }

        $asn = $record->asn();

        $this->record(self::COUNTRY, (string) $record->country(), $type);
        $this->record(self::NETWORK, $asn !== null ? (string) $asn : '', $type, (string) $record->asOrganization());
    }

    /**
     * Counts one hit.
     *
     * @param string $facet One of the facet constants.
     * @param string $value Value under the facet: a country code, an AS number or a key of systems(); empty when unknown.
     * @param string $type  Kind of event, one of the Events constants.
     * @param string $name  Name of the value, for a network.
     *
     * @return void
     */
    public function record(string $facet, string $value, string $type, string $name = ''): void
    {
        $wpdb = Scope::db();

        $name = mb_substr($name, 0, self::NAME_LENGTH);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin; a counter is no cache candidate.
        $wpdb->query($wpdb->prepare('INSERT INTO %i (day, facet, value, type, name, hits) VALUES (%s, %s, %s, %s, %s, 1) ON DUPLICATE KEY UPDATE hits = hits + 1, name = %s', Schema::origins(), current_time('Y-m-d'), $facet, $value, $type, $name, $name));
    }

    /**
     * The values of a facet seen most over the last days, for some kinds of
     * event
     *
     * @param string   $facet One of the facet constants.
     * @param int      $days  Length of the period, today included.
     * @param string[] $types Kinds of event counted, Events constants; none gives an empty list.
     * @param int      $limit Values returned at most.
     *
     * @return array<int, array{value: string, name: string, hits: int}> The most seen first.
     */
    public function top(string $facet, int $days, array $types, int $limit = 100): array
    {
        $wpdb = Scope::db();

        if ($types === []) {
            return [];
        }

        $in = implode(',', array_fill(0, count($types), '%s'));

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table of the plugin, read on the statistics screen only; $in is one placeholder per kind.
        $rows = $wpdb->get_results($wpdb->prepare("SELECT value, MAX(name) AS name, SUM(hits) AS hits FROM %i WHERE facet = %s AND day >= %s AND type IN ($in) GROUP BY value ORDER BY hits DESC, value ASC LIMIT %d", Schema::origins(), $facet, Stats::since($days), ...[...$types, $limit]));

        $top = [];

        foreach ((array) $rows as $row) {
            $top[] = ['value' => Value::string($row->value), 'name' => Value::string($row->name), 'hits' => Value::int($row->hits)];
        }

        return $top;
    }

    /**
     * Number of hits of a facet over the last days, for some kinds of event
     *
     * @param string   $facet One of the facet constants.
     * @param int      $days  Length of the period, today included.
     * @param string[] $types Kinds of event counted, Events constants; none gives 0.
     *
     * @return int
     */
    public function total(string $facet, int $days, array $types): int
    {
        $wpdb = Scope::db();

        if ($types === []) {
            return 0;
        }

        $in = implode(',', array_fill(0, count($types), '%s'));

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table of the plugin, read on the statistics screen only; $in is one placeholder per kind.
        return (int) $wpdb->get_var($wpdb->prepare("SELECT SUM(hits) FROM %i WHERE facet = %s AND day >= %s AND type IN ($in)", Schema::origins(), $facet, Stats::since($days), ...$types));
    }

    /**
     * Drops the counters older than the days kept, those of the successful
     * logins after the days of the journal.
     *
     * @param int $keep   Days the counters are kept.
     * @param int $logins Days the counters of the successful logins are kept.
     *
     * @return void
     */
    public function purge(int $keep, int $logins): void
    {
        $wpdb = Scope::db();

        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE day < %s', Schema::origins(), Stats::since($keep)));
        $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE type = %s AND day < %s', Schema::origins(), Events::LOGIN, Stats::since($logins)));
        // phpcs:enable
    }

    /**
     * Folds, for each day over and each kind of event, the networks past the
     * most seen into OTHER_NETWORKS, their hits added up.
     *
     * @param int $keep Networks of a day kept apart, for each kind of event.
     *
     * @return void
     */
    public function foldNetworks(int $keep = self::NETWORKS_PER_DAY): void
    {
        $wpdb = Scope::db();
        $table = Schema::origins();
        $today = Stats::since(1);

        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- Table of the plugin, folded once a day.
        $groups = $wpdb->get_results($wpdb->prepare('SELECT day, type FROM %i WHERE facet = %s AND day < %s AND value <> %s GROUP BY day, type HAVING COUNT(*) > %d', $table, self::NETWORK, $today, self::OTHER_NETWORKS, $keep)) ?? [];

        foreach ($groups as $group) {
            $day = Value::string($group->day);
            $type = Value::string($group->type);
            $rows = $wpdb->get_results($wpdb->prepare('SELECT value, hits FROM %i WHERE facet = %s AND day = %s AND type = %s AND value <> %s ORDER BY hits DESC, value ASC', $table, self::NETWORK, $day, $type, self::OTHER_NETWORKS)) ?? [];
            $folded = array_slice($rows, $keep);
            $hits = array_sum(array_map(static fn(\stdClass $row): int => Value::int($row->hits), $folded));

            foreach (array_chunk(array_map(static fn(\stdClass $row): string => Value::string($row->value), $folded), 500) as $values) {
                $in = implode(',', array_fill(0, count($values), '%s'));

                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- $in is one placeholder per value.
                $wpdb->query($wpdb->prepare("DELETE FROM %i WHERE facet = %s AND day = %s AND type = %s AND value IN ($in)", $table, self::NETWORK, $day, $type, ...$values));
            }

            $wpdb->query($wpdb->prepare('INSERT INTO %i (day, facet, value, type, name, hits) VALUES (%s, %s, %s, %s, %s, %d) ON DUPLICATE KEY UPDATE hits = hits + %d', $table, $day, self::NETWORK, self::OTHER_NETWORKS, $type, '', $hits, $hits));
        }
        // phpcs:enable
    }

    /**
     * Drops every counter.
     *
     * @return void
     */
    public function reset(): void
    {
        $wpdb = Scope::db();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->query($wpdb->prepare('DELETE FROM %i', Schema::origins()));
    }

    /**
     * The operating systems told apart, with their labels
     *
     * @return array<string, string>
     */
    public static function systems(): array
    {
        return [
            'windows' => 'Windows',
            'macos' => 'macOS',
            'ios' => 'iOS',
            'ipados' => 'iPadOS',
            'android' => 'Android',
            'chromeos' => 'ChromeOS',
            'linux' => 'Linux',
            'other' => __('Other, or a script', 'gecka-security'),
            '' => __('No user agent', 'gecka-security'),
        ];
    }

    /**
     * The operating system a user agent names. The user agent is what the
     * client says of itself: a robot claims whatever it likes.
     *
     * @param string $agent User agent of the request, as sent.
     *
     * @return string A key of systems().
     */
    public static function system(string $agent): string
    {
        $agent = trim($agent);

        return match (true) {
            $agent === '' => '',
            str_contains($agent, 'iPad') => 'ipados',
            (bool) preg_match('/iPhone|iPod/', $agent) => 'ios',
            str_contains($agent, 'Android') => 'android',
            str_contains($agent, 'CrOS') => 'chromeos',
            (bool) preg_match('/Macintosh|Mac OS X/', $agent) => 'macos',
            str_contains($agent, 'Windows') => 'windows',
            str_contains($agent, 'Linux') => 'linux',
            default => 'other',
        };
    }
}

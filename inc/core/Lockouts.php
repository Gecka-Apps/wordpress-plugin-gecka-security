<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * The addresses the brute-force protection watches: how many logins each
 * failed lately, and until when it is locked out.
 *
 * An address is watched under its key, the address itself or the /64 of an
 * IPv6 one. Its failures count within a window; at the maximum they start a
 * lockout and go back to zero. Lockouts count within a longer window: at
 * their maximum, the lockout is a long one, and the count starts over.
 *
 * A failure is counted in one statement, so that failures landing at the
 * same instant all count, and one of them starts the lockout. A lockout in
 * place is never shortened: requests already past the gate when it started
 * may still fail, and a short lockout they would start must not replace a
 * long one.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Lockouts
{
    /**
     * Settings the windows, maximums and durations are read from.
     *
     * @var Settings
     */
    private Settings $settings;

    /**
     * Keeps the settings the lockouts are counted with.
     *
     * @param Settings $settings Settings the windows, maximums and durations are read from.
     */
    public function __construct(Settings $settings)
    {
        $this->settings = $settings;
    }

    /**
     * Table of the addresses watched
     *
     * @return string
     */
    public static function table(): string
    {
        return Schema::lockouts();
    }

    /**
     * Seconds left of the lockout of an address, 0 when it is not locked out
     *
     * @param string $key Key the address is watched under, as Network::key() gives it.
     *
     * @return int
     */
    public function remaining(string $key): int
    {
        $row = $this->row($key);

        return $row ? max(0, self::time($row->locked_until) - time()) : 0;
    }

    /**
     * Counts a failure, and locks the address out when it reaches the
     * maximum.
     *
     * @param string $key    Key the address is watched under, as Network::key() gives it.
     * @param int    $weight How many failures it counts for.
     *
     * @return array{until: int, long: bool}|null The lockout started, if any.
     */
    public function fail(string $key, int $weight = 1): ?array
    {
        $wpdb = Scope::db();

        $now = time();
        $stamp = gmdate('Y-m-d H:i:s', $now);
        $failuresWindow = gmdate('Y-m-d H:i:s', $now - $this->settings->int('failures_window') * MINUTE_IN_SECONDS);

        // One statement counts the failure, so that parallel requests all
        // count: a row read and written back would let a burst through. A
        // window of failures that ended starts over.
        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->query($wpdb->prepare(
            'INSERT INTO %i (ip, failures, first_failure, locked_until, lockouts, first_lockout, updated) VALUES (%s, %d, %s, NULL, 0, NULL, %s)
            ON DUPLICATE KEY UPDATE
                failures = CASE WHEN first_failure IS NULL OR first_failure < %s THEN %d ELSE failures + %d END,
                first_failure = CASE WHEN first_failure IS NULL OR first_failure < %s THEN %s ELSE first_failure END,
                updated = %s',
            self::table(),
            $key,
            $weight,
            $stamp,
            $stamp,
            $failuresWindow,
            $weight,
            $weight,
            $failuresWindow,
            $stamp,
            $stamp,
        ));

        $row = $this->row($key);

        if (! $row || Value::int($row->failures) < $this->settings->int('max_failures')) {
            return null;
        }

        $lockoutsWindow = $now - $this->settings->int('lockouts_window') * HOUR_IN_SECONDS;
        $lockouts = $row->first_lockout && self::time($row->first_lockout) >= $lockoutsWindow ? (int) $row->lockouts : 0;
        $firstLockout = $lockouts ? (string) $row->first_lockout : $stamp;
        ++$lockouts;
        $long = $lockouts >= $this->settings->int('max_lockouts');
        $duration = $long
            ? $this->settings->int('long_lockout_hours') * HOUR_IN_SECONDS
            : $this->settings->int('lockout_minutes') * MINUTE_IN_SECONDS;
        $lockedUntil = gmdate('Y-m-d H:i:s', $now + $duration);

        // Of the parallel requests reaching the maximum, one starts the
        // lockout: the update applies while the failures still stand and no
        // lockout runs, and the first to get through clears them. A long
        // lockout starts the count of lockouts over.
        $started = $long
            ? $wpdb->query($wpdb->prepare('UPDATE %i SET failures = 0, first_failure = NULL, locked_until = %s, lockouts = 0, first_lockout = NULL, updated = %s WHERE ip = %s AND failures >= %d AND (locked_until IS NULL OR locked_until <= %s)', self::table(), $lockedUntil, $stamp, $key, $this->settings->int('max_failures'), $stamp))
            : $wpdb->query($wpdb->prepare('UPDATE %i SET failures = 0, first_failure = NULL, locked_until = %s, lockouts = %d, first_lockout = %s, updated = %s WHERE ip = %s AND failures >= %d AND (locked_until IS NULL OR locked_until <= %s)', self::table(), $lockedUntil, $lockouts, $firstLockout, $stamp, $key, $this->settings->int('max_failures'), $stamp));
        // phpcs:enable

        return $started ? ['until' => $now + $duration, 'long' => $long] : null;
    }

    /**
     * Ends the lockouts of addresses, and forgets their failures.
     *
     * @param string[] $keys Keys the addresses are watched under.
     *
     * @return int Addresses that were locked out.
     */
    public function unlock(array $keys): int
    {
        $wpdb = Scope::db();

        $done = 0;

        foreach ($keys as $key) {
            if ($this->remaining($key) > 0) {
                ++$done;
            }

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
            $wpdb->update(self::table(), ['failures' => 0, 'first_failure' => null, 'locked_until' => null, 'updated' => gmdate('Y-m-d H:i:s')], ['ip' => $key]);
        }

        return $done;
    }

    /**
     * Ends every lockout and forgets every failure; the count of lockouts
     * stays.
     *
     * @return void
     */
    public function clear(): void
    {
        $wpdb = Scope::db();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->query($wpdb->prepare('UPDATE %i SET failures = 0, first_failure = NULL, locked_until = NULL, updated = %s', self::table(), gmdate('Y-m-d H:i:s')));
    }

    /**
     * The addresses locked out, the latest to be released first
     *
     * @param int $page    From 1.
     * @param int $perPage Addresses per page.
     *
     * @return list<\stdClass> Rows of ip, failures, first_failure, locked_until, lockouts, first_lockout and updated, as the database gives them.
     */
    public function active(int $page, int $perPage): array
    {
        $wpdb = Scope::db();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, read on the lockouts screen.
        $rows = $wpdb->get_results($wpdb->prepare('SELECT ip, failures, first_failure, locked_until, lockouts, first_lockout, updated FROM %i WHERE locked_until > %s ORDER BY locked_until DESC LIMIT %d OFFSET %d', self::table(), gmdate('Y-m-d H:i:s'), $perPage, max(0, $page - 1) * $perPage));

        return $rows ?? [];
    }

    /**
     * Number of addresses locked out
     *
     * @return int
     */
    public function countActive(): int
    {
        $wpdb = Scope::db();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        return (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i WHERE locked_until > %s', self::table(), gmdate('Y-m-d H:i:s')));
    }

    /**
     * Forgets the addresses that are not locked out and were not seen for
     * longer than any window.
     *
     * @return void
     */
    public function purge(): void
    {
        $wpdb = Scope::db();

        $now = time();
        $idle = max($this->settings->int('failures_window') * MINUTE_IN_SECONDS, $this->settings->int('lockouts_window') * HOUR_IN_SECONDS);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, purged once a day.
        $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE (locked_until IS NULL OR locked_until < %s) AND updated < %s', self::table(), gmdate('Y-m-d H:i:s', $now), gmdate('Y-m-d H:i:s', $now - $idle)));
    }

    /**
     * The row of an address
     *
     * @param string $key Key the address is watched under.
     *
     * @return object{ip: string, failures: string, first_failure: string|null, locked_until: string|null, lockouts: string, first_lockout: string|null, updated: string}|null Null when the address is not watched.
     */
    public function row(string $key): ?object
    {
        $wpdb = Scope::db();

        /** @var object{ip: string, failures: string, first_failure: string|null, locked_until: string|null, lockouts: string, first_lockout: string|null, updated: string}|null $row */
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, one row by key.
        $row = $wpdb->get_row($wpdb->prepare('SELECT ip, failures, first_failure, locked_until, lockouts, first_lockout, updated FROM %i WHERE ip = %s', self::table(), $key));

        return $row;
    }

    /**
     * A date of the table as a timestamp, 0 for none
     *
     * @param mixed $date A DATETIME of the table, in UTC, or null.
     *
     * @return int
     */
    public static function time(mixed $date): int
    {
        return $date ? (int) strtotime(Value::string($date) . ' UTC') : 0;
    }
}

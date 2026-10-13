<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * Counters of requests per address and per hour, held in the options
 * table and counted up in one SQL statement, so that parallel requests
 * all count: a transient read and written back would let a burst through.
 * A counter is named after its kind, the hour and the network of the
 * address; the counters of past hours go with the daily purge, and now
 * and then with a hit, so that a flood from many addresses does not pile
 * them up for a day. The rows live in the options table of the main site,
 * read and written by SQL only, so that every site of a network counts
 * together and no option cache stands in the way.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Throttle
{
    /**
     * Prefix of the options holding the counters.
     */
    public const PREFIX = 'gecka_security_req_';

    /**
     * One hit in this many also drops the counters of the past hours.
     */
    private const PURGE_EVERY = 100;

    /**
     * Length of the window, in seconds.
     */
    private const WINDOW = HOUR_IN_SECONDS;

    /**
     * Counts a request and gives the count of the hour so far, the
     * request included.
     *
     * @param string $kind Counter: reset or register.
     * @param string $key  Key the address is watched under, as Network::key() gives it.
     *
     * @return int
     */
    public function hit(string $kind, string $key): int
    {
        $wpdb = Scope::db();

        $name = self::name($kind, $key);

        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- One statement each, so that parallel requests all count.
        $wpdb->query($wpdb->prepare("INSERT IGNORE INTO %i (option_name, option_value, autoload) VALUES (%s, '0', 'off')", self::table(), $name));
        $wpdb->query($wpdb->prepare('UPDATE %i SET option_value = option_value + 1 WHERE option_name = %s', self::table(), $name));
        $count = (int) $wpdb->get_var($wpdb->prepare('SELECT option_value FROM %i WHERE option_name = %s', self::table(), $name));
        // phpcs:enable

        if (wp_rand(1, self::PURGE_EVERY) === 1) {
            $this->purge();
        }

        return max(1, $count);
    }

    /**
     * Deletes the counters of the past hours.
     *
     * @return void
     */
    public function purge(): void
    {
        $wpdb = Scope::db();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Options of the plugin, daily and on one hit in a hundred.
        $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE option_name LIKE %s AND option_name NOT LIKE %s', self::table(), $wpdb->esc_like(self::PREFIX) . '%', $wpdb->esc_like(self::PREFIX . self::hour() . '_') . '%'));
    }

    /**
     * Deletes every counter.
     *
     * @return void
     */
    public static function clear(): void
    {
        $wpdb = Scope::db();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Options of the plugin.
        $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE option_name LIKE %s', self::table(), $wpdb->esc_like(self::PREFIX) . '%'));
    }

    /**
     * The options table the counters live in: that of the main site
     *
     * @return string
     */
    private static function table(): string
    {
        return Scope::prefix() . 'options';
    }

    /**
     * Name of the option holding a counter for the current hour
     *
     * @param string $kind Counter: reset or register.
     * @param string $key  Key the address is watched under, hashed into the name.
     *
     * @return string
     */
    private static function name(string $kind, string $key): string
    {
        return self::PREFIX . self::hour() . '_' . $kind . '_' . md5($key);
    }

    /**
     * The current hour, as the windows are cut
     *
     * @return int
     */
    private static function hour(): int
    {
        return (int) floor(time() / self::WINDOW);
    }
}

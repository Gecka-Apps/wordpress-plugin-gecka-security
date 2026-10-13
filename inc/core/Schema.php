<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * The tables of the plugin, one set per site, or per network on a multisite
 * whose sites share their accounts: the journal of the events, the state of
 * each address the brute-force protection watches, and the daily counters
 * of the statistics. The way a request came in is stored as `way`:
 * `vector` is a reserved word since MariaDB 11.7 and MySQL 9. Each event
 * carries the address it came from and, as `net`, the key that address is
 * watched under, the /64 for IPv6: the rows that fold together are looked
 * up on that key. The login is kept as typed in `username` and in lower
 * case in `login`, the column the filters and the erasure match on, since
 * WordPress reads a login whatever its case. The detail of an event is a
 * code, with its parameters as JSON in `params`, worded in the language of
 * the reader when shown; free text, the error codes of a failed login or
 * the roles of an account, stays as it is. The counters by origin hold the
 * country, the network and the system of the events, never the address.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Schema
{
    /**
     * Version of the tables. The setup runs again on a site whose recorded
     * version differs, whatever the version of the plugin.
     */
    public const VERSION = 4;

    /**
     * Table of the events
     *
     * @return string
     */
    public static function events(): string
    {
        return Scope::prefix() . 'gecka_security_events';
    }

    /**
     * Table of the addresses watched: their failures and their lockouts
     *
     * @return string
     */
    public static function lockouts(): string
    {
        return Scope::prefix() . 'gecka_security_lockouts';
    }

    /**
     * Table of the daily counters
     *
     * @return string
     */
    public static function stats(): string
    {
        return Scope::prefix() . 'gecka_security_stats';
    }

    /**
     * Table of the daily counters by origin: country, network, system
     *
     * @return string
     */
    public static function origins(): string
    {
        return Scope::prefix() . 'gecka_security_origins';
    }

    /**
     * Creates the tables, or brings them up to date.
     *
     * @return void
     */
    public static function install(): void
    {
        $wpdb = Scope::db();

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $collate = $wpdb->get_charset_collate();
        $events = self::events();

        dbDelta(
            "CREATE TABLE $events (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            site bigint(20) unsigned NOT NULL DEFAULT 0,
            created datetime NOT NULL,
            type varchar(20) NOT NULL,
            ip varchar(45) NOT NULL,
            net varchar(45) NOT NULL DEFAULT '',
            username varchar(60) NOT NULL DEFAULT '',
            login varchar(60) NOT NULL DEFAULT '',
            way varchar(20) NOT NULL DEFAULT '',
            detail varchar(191) NOT NULL DEFAULT '',
            params text NOT NULL,
            hits int unsigned NOT NULL DEFAULT 1,
            last datetime DEFAULT NULL,
            PRIMARY KEY  (id),
            KEY created (created),
            KEY ip (ip),
            KEY net (net,type),
            KEY login (login),
            KEY type (type),
            KEY site (site)
            ) $collate;",
        );

        $lockouts = self::lockouts();

        dbDelta(
            "CREATE TABLE $lockouts (
            ip varchar(45) NOT NULL,
            failures smallint(5) unsigned NOT NULL DEFAULT 0,
            first_failure datetime DEFAULT NULL,
            locked_until datetime DEFAULT NULL,
            lockouts smallint(5) unsigned NOT NULL DEFAULT 0,
            first_lockout datetime DEFAULT NULL,
            updated datetime NOT NULL,
            PRIMARY KEY  (ip),
            KEY locked_until (locked_until),
            KEY updated (updated)
            ) $collate;",
        );

        $stats = self::stats();

        dbDelta(
            "CREATE TABLE $stats (
            day date NOT NULL,
            way varchar(20) NOT NULL,
            type varchar(20) NOT NULL,
            hits int(10) unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (day,way,type)
            ) $collate;",
        );

        $origins = self::origins();

        dbDelta(
            "CREATE TABLE $origins (
            day date NOT NULL,
            facet varchar(10) NOT NULL,
            value varchar(20) NOT NULL,
            type varchar(20) NOT NULL,
            name varchar(191) NOT NULL DEFAULT '',
            hits int(10) unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (day,facet,value,type),
            KEY facet (facet,type,day,value)
            ) $collate;",
        );
    }

    /**
     * Drops the tables.
     *
     * @return void
     */
    public static function drop(): void
    {
        $wpdb = Scope::db();

        foreach ([self::events(), self::lockouts(), self::stats(), self::origins()] as $table) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, dropped on uninstall.
            $wpdb->query($wpdb->prepare('DROP TABLE IF EXISTS %i', $table));
        }
    }
}

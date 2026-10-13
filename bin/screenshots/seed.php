<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

/**
 * Fills a fresh site for the screenshots of the plugin, required by WP-CLI
 * (`wp eval 'require "...";'`): three months of counters and origins, a
 * month of journal, a handful of lockouts under way, lists in the settings.
 *
 * The figures are drawn from a fixed sequence, so that two runs give the
 * same screens. The rows are written straight into the tables: the
 * recorders of the plugin only stamp the current time.
 */

// phpcs:disable WordPress.DB -- Seed data written straight into the tables of the plugin.

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Lockouts;
use Gecka\WP\Plugin\Security\Network;
use Gecka\WP\Plugin\Security\Origins;
use Gecka\WP\Plugin\Security\Request;
use Gecka\WP\Plugin\Security\Schema;

(static function (): void {
    global $wpdb;

    $plugin = gecka_security();
    $state = 20261013;
    $draw = static function (int $min, int $max) use (&$state): int {
        $state = ($state * 1103515245 + 12345) % 2147483648;

        return $min + $state % ($max - $min + 1);
    };
    $pick = static fn(array $list) => $list[$draw(0, count($list) - 1)];
    $today = new DateTimeImmutable('today', wp_timezone());
    $day = static fn(int $ago): string => $today->modify("-{$ago} days")->format('Y-m-d');
    $count = static function (string $table, array $row) use ($wpdb): void {
        $columns = implode(', ', array_keys($row));
        $values = implode(', ', array_fill(0, count($row), '%s'));
        $wpdb->query($wpdb->prepare("INSERT INTO {$table} ({$columns}) VALUES ({$values}) ON DUPLICATE KEY UPDATE hits = hits + VALUES(hits)", array_values($row))); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
    };

    // The journal starts empty: the browser taking the shots signed in
    // before this runs, and the site is not where it logs in from.
    $plugin->events()->clear();

    // The settings: a proxy in front of the site, so that the address of
    // the browser taking the shots counts as usable, and the lists filled.
    $plugin->settings()->merge([
        'trusted_proxies' => ['172.16.0.0/12'],
        'safelist' => ['203.0.113.0/24', '2001:db8:1::/48'],
        'blocklist' => ['198.51.100.0/24', '45.142.212.0/24', '2001:db8:bad::/48'],
        'countries_mode' => 'deny',
        'countries' => ['KP'],
    ]);

    // Attackers: real public addresses, so that the journal shows what the
    // databases say of them; the names below are those of the counters.
    $attackers = [
        ['222.186.30.76', 'CN', '4134', 'Chinanet', 'other'],
        ['222.186.42.137', 'CN', '4134', 'Chinanet', 'linux'],
        ['45.142.212.61', 'NL', '9009', 'M247 Europe SRL', 'linux'],
        ['185.220.101.34', 'DE', '60729', 'Zwiebelfreunde e.V.', 'other'],
        ['193.32.162.157', 'RU', '12389', 'PJSC Rostelecom', 'windows'],
        ['141.98.10.63', 'LT', '209605', 'UAB Host Baltic', 'linux'],
        ['91.240.118.72', 'GB', '9009', 'M247 Europe SRL', 'other'],
        ['167.71.13.196', 'US', '14061', 'DigitalOcean, LLC', 'linux'],
        ['159.65.142.88', 'SG', '14061', 'DigitalOcean, LLC', 'linux'],
        ['5.9.152.110', 'DE', '24940', 'Hetzner Online GmbH', 'linux'],
        ['51.68.120.44', 'FR', '16276', 'OVH SAS', 'other'],
        ['3.120.181.9', 'DE', '16509', 'Amazon.com, Inc.', 'linux'],
        ['103.149.192.14', 'ID', '136052', 'PT Cloud Hosting Indonesia', 'windows'],
        ['117.4.242.90', 'VN', '7552', 'Viettel Group', 'windows'],
        ['47.242.11.203', 'HK', '45102', 'Alibaba (US) Technology Co., Ltd.', 'other'],
        ['201.17.88.140', 'BR', '28573', 'Claro NXT Telecomunicacoes Ltda', 'android'],
        ['122.161.52.9', 'IN', '24560', 'Bharti Airtel Ltd., Telemedia Services', 'windows'],
        ['77.88.8.8', 'RU', '13238', 'YANDEX LLC', 'other'],
        ['2001:4860:4860::8888', 'US', '15169', 'Google LLC', 'other'],
    ];
    // People of the site, from New Caledonia and France.
    $people = [
        ['202.22.233.17', 'NC', '56055', 'Micro Logic Systems', 'windows', 'laurent', 'administrator'],
        ['202.22.150.40', 'NC', '56089', 'OFFRATEL', 'macos', 'marie', 'editor'],
        ['202.22.128.201', 'NC', '56089', 'OFFRATEL', 'ios', 'jean', 'author'],
        ['90.63.112.55', 'FR', '3215', 'Orange S.A.', 'windows', 'sophie', 'editor'],
    ];
    $logins = ['admin', 'admin', 'administrator', 'wpadmin', 'test', 'root', 'user', 'editor', 'gecka', 'support', 'info', 'webmaster', 'demo', 'laurent'];
    $reserved = ['admin', 'administrator', 'root', 'test', 'user', 'webmaster', 'info', 'support'];
    $ways = [Request::LOGIN_FORM, Request::LOGIN_FORM, Request::LOGIN_FORM, Request::XMLRPC, Request::REST];

    // The journal rows are gathered first and written in the order of
    // their time, as the plugin would have written them.
    $pending = [];
    $events = static function (int $ago, string $type, string $ip, string $username, string $way, string $detail, array $params = [], int $hits = 1) use (&$pending, $draw): void {
        $created = time() - $ago * DAY_IN_SECONDS - $draw(0, 86399);
        $pending[] = [
            'site' => get_current_blog_id(),
            'created' => gmdate('Y-m-d H:i:s', $created),
            'type' => $type,
            'ip' => $ip,
            'net' => Network::key($ip),
            'username' => $username,
            'login' => strtolower($username),
            'way' => $way,
            'detail' => $detail,
            'params' => $params === [] ? '' : (string) wp_json_encode($params),
            'hits' => $hits,
            'last' => $hits > 1 ? gmdate('Y-m-d H:i:s', $created + $draw(0, 3600)) : null,
        ];
    };

    $origins = static function (int $ago, string $type, array $who, int $hits) use ($count, $day): void {
        $count(Schema::origins(), ['day' => $day($ago), 'facet' => Origins::COUNTRY, 'value' => $who[1], 'type' => $type, 'name' => '', 'hits' => $hits]);
        $count(Schema::origins(), ['day' => $day($ago), 'facet' => Origins::NETWORK, 'value' => $who[2], 'type' => $type, 'name' => $who[3], 'hits' => $hits]);
        $count(Schema::origins(), ['day' => $day($ago), 'facet' => Origins::SYSTEM, 'value' => $who[4], 'type' => $type, 'name' => '', 'hits' => $hits]);
    };

    for ($ago = 89; $ago >= 0; $ago--) {
        $wave = $ago >= 11 && $ago <= 16 ? 4 : 1;
        $journal = $ago <= 29;

        // Failed and reserved logins, lockouts and the attempts refused
        // meanwhile, by a dozen attackers a day.
        for ($i = 0, $n = $draw(6, 14) * $wave; $i < $n; $i++) {
            $who = $pick($attackers);
            $way = $pick($ways);
            $login = $pick($logins);
            $failures = $draw(1, 7);
            $type = in_array($login, $reserved, true) ? Events::RESERVED : Events::FAILED;

            $count(Schema::stats(), ['day' => $day($ago), 'way' => $way, 'type' => $type, 'hits' => $failures]);
            $origins($ago, $type, $who, $failures);

            if ($journal && $draw(0, 3) === 0) {
                $events($ago, $type, $who[0], $login, $way, $type === Events::RESERVED ? 'invalid_username' : 'incorrect_password');
            }

            if ($failures >= 5) {
                $blocked = $draw(3, 40);
                $count(Schema::stats(), ['day' => $day($ago), 'way' => $way, 'type' => Events::LOCKOUT, 'hits' => 1]);
                $count(Schema::stats(), ['day' => $day($ago), 'way' => $way, 'type' => Events::BLOCKED, 'hits' => $blocked]);
                $origins($ago, Events::BLOCKED, $who, $blocked);

                if ($journal) {
                    $events($ago, Events::LOCKOUT, $who[0], $login, $way, $draw(0, 5) === 0 ? 'lockout.long' : 'lockout.short');
                    $events($ago, Events::BLOCKED, $who[0], '', $way, '', [], $blocked);
                }
            }
        }

        // Enumeration, refusals and limits, a few a day.
        for ($i = 0, $n = $draw(0, 4); $i < $n; $i++) {
            $who = $pick($attackers);
            $kind = $draw(0, 5);
            [$type, $username, $way, $detail, $params] = match (true) {
                $kind === 0 => [Events::ENUMERATION, '', 'author', (string) $draw(1, 9), []],
                $kind === 1 => [Events::ENUMERATION, '', 'rest_users', '/wp/v2/users', []],
                $kind === 2 => [Events::ENUMERATION, $pick($logins), Request::LOGIN_FORM, 'enumeration.lost_password', []],
                $kind === 3 => [Events::REFUSED, $pick($logins), Request::LOGIN_FORM, 'refused.address', []],
                $kind === 4 => [Events::REFUSED, $pick($logins), Request::LOGIN_FORM, 'refused.country', ['country' => 'KP']],
                default => [Events::LIMITED, $pick($logins), Request::LOGIN_FORM, $draw(0, 1) === 0 ? 'limited.reset' : 'limited.register', ['limit' => 5]],
            };

            $count(Schema::stats(), ['day' => $day($ago), 'way' => $way, 'type' => $type, 'hits' => 1]);
            $origins($ago, $type, $who, 1);

            if ($journal) {
                $events($ago, $type, $who[0], $username, $way, $detail, $params);
            }
        }

        // The people of the site signing in.
        for ($i = 0, $n = $draw(1, 4); $i < $n; $i++) {
            $who = $pick($people);
            $count(Schema::stats(), ['day' => $day($ago), 'way' => Request::LOGIN_FORM, 'type' => Events::LOGIN, 'hits' => 1]);
            $origins($ago, Events::LOGIN, $who, 1);

            if ($journal) {
                $events($ago, Events::LOGIN, $who[0], $who[5], Request::LOGIN_FORM, $who[6]);
            }
        }
    }

    // A few things that happen once in a while.
    $events(3, Events::ACCOUNT, $people[0][0], 'marie', Request::OTHER, 'account.role_set', ['role' => 'editor', 'old' => ['author'], 'actor' => 'laurent']);
    $events(9, Events::ACCOUNT, $people[0][0], 'jean', Request::OTHER, 'account.created', ['roles' => ['author'], 'actor' => 'laurent']);
    $events(12, Events::ACCOUNT, $people[3][0], 'sophie', Request::OTHER, 'account.password');
    $events(6, Events::BREACHED, $people[2][0], 'jean', Request::LOGIN_FORM, 'breached.seen', ['count' => 3817]);
    $count(Schema::stats(), ['day' => $day(3), 'way' => Request::OTHER, 'type' => Events::ACCOUNT, 'hits' => 1]);
    $count(Schema::stats(), ['day' => $day(9), 'way' => Request::OTHER, 'type' => Events::ACCOUNT, 'hits' => 1]);
    $count(Schema::stats(), ['day' => $day(12), 'way' => Request::OTHER, 'type' => Events::ACCOUNT, 'hits' => 1]);
    $count(Schema::stats(), ['day' => $day(6), 'way' => Request::LOGIN_FORM, 'type' => Events::BREACHED, 'hits' => 1]);

    usort($pending, static fn(array $a, array $b): int => strcmp($a['created'], $b['created']));

    foreach ($pending as $row) {
        $wpdb->insert(Schema::events(), $row);
    }

    // Lockouts under way: short ones ending within the hour, a long one.
    foreach ([[0, 14, 1], [1, 7, 2], [2, 19, 1], [3, 3, 3], [4, 1380, 0], [8, 11, 4]] as [$index, $minutes, $lockouts]) {
        $who = $attackers[$index];
        $now = time();
        $wpdb->replace(Lockouts::table(), [
            'ip' => Network::key($who[0]),
            'failures' => $lockouts === 0 ? 5 : 5 * ($lockouts + 1),
            'first_failure' => gmdate('Y-m-d H:i:s', $now - 20 * MINUTE_IN_SECONDS + $minutes * MINUTE_IN_SECONDS - 25 * MINUTE_IN_SECONDS),
            'locked_until' => gmdate('Y-m-d H:i:s', $now + $minutes * MINUTE_IN_SECONDS),
            'lockouts' => $lockouts,
            'first_lockout' => gmdate('Y-m-d H:i:s', $now - 5 * HOUR_IN_SECONDS),
            'updated' => gmdate('Y-m-d H:i:s', $now - $draw(1, 15) * MINUTE_IN_SECONDS),
        ]);
    }

    delete_transient(Events::LOGINS_CACHE);

    // The logos of the networks counted, when Gecka Geolocation provides them.
    if (function_exists('gecka_geolocation_network_logo_url') && function_exists('gecka_geolocation_plugin')) {
        foreach (array_merge($attackers, $people) as $who) {
            gecka_geolocation_network_logo_url((int) $who[2]);
        }

        gecka_geolocation_plugin()->logos()->download();
    }

    WP_CLI::success('seeded');
})();

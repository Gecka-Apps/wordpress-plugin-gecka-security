<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * Daily counters of the events, by the way they came in and by kind. Only
 * counts: nothing that tells who did what, which the journal keeps for a
 * shorter time.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Stats
{
    /**
     * Counts an event.
     *
     * @param string $vector The way the request came in.
     * @param string $type   The kind of event, one of the Events constants.
     *
     * @return void
     */
    public function record(string $vector, string $type): void
    {
        $wpdb = Scope::db();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin; a counter is no cache candidate.
        $wpdb->query($wpdb->prepare('INSERT INTO %i (day, way, type, hits) VALUES (%s, %s, %s, 1) ON DUPLICATE KEY UPDATE hits = hits + 1', Schema::stats(), current_time('Y-m-d'), $vector, $type));
    }

    /**
     * Events of the last days, by way in and by kind
     *
     * @param int $days Length of the period, today included.
     *
     * @return array<string, array<string, int>> Hits by kind, by way in.
     */
    public function totals(int $days): array
    {
        $wpdb = Scope::db();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, read on the statistics screen only.
        $rows = $wpdb->get_results($wpdb->prepare('SELECT way, type, SUM(hits) AS hits FROM %i WHERE day >= %s GROUP BY way, type', Schema::stats(), self::since($days)));

        $totals = [];

        foreach ((array) $rows as $row) {
            $totals[Value::string($row->way)][Value::string($row->type)] = Value::int($row->hits);
        }

        return $totals;
    }

    /**
     * Events of the last days, by kind
     *
     * @param array<string, array<string, int>> $totals Totals by way in, as totals() gives them.
     *
     * @return array<string, int> Hits by kind, the largest first.
     */
    public static function byType(array $totals): array
    {
        $types = [];

        foreach ($totals as $byType) {
            foreach ($byType as $type => $hits) {
                $types[$type] = ($types[$type] ?? 0) + $hits;
            }
        }

        arsort($types);

        return $types;
    }

    /**
     * Events day by day, by way in and by kind, the days with none included
     *
     * @param int $days Length of the period, today included.
     *
     * @return array<string, array<string, array<string, int>>> Hits by kind, by way in, keyed by date, oldest first.
     */
    public function daily(int $days): array
    {
        $wpdb = Scope::db();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, read on the statistics screen only.
        $rows = $wpdb->get_results($wpdb->prepare('SELECT day, way, type, hits FROM %i WHERE day >= %s', Schema::stats(), self::since($days)));

        $daily = [];
        $day = new \DateTimeImmutable(self::since($days), wp_timezone());

        for ($i = 0; $i < $days; $i++) {
            $daily[$day->modify("+$i days")->format('Y-m-d')] = [];
        }

        foreach ((array) $rows as $row) {
            $date = Value::string($row->day);

            if (isset($daily[$date])) {
                $daily[$date][Value::string($row->way)][Value::string($row->type)] = Value::int($row->hits);
            }
        }

        return $daily;
    }

    /**
     * Events day by day, by kind, every way in together
     *
     * @param array<string, array<string, array<string, int>>> $daily As daily() gives it.
     *
     * @return array<string, array<string, int>> Hits by kind, keyed by date.
     */
    public static function byDay(array $daily): array
    {
        $days = [];

        foreach ($daily as $day => $byWay) {
            $days[$day] = [];

            foreach ($byWay as $byType) {
                foreach ($byType as $type => $hits) {
                    $days[$day][$type] = ($days[$day][$type] ?? 0) + $hits;
                }
            }
        }

        return $days;
    }

    /**
     * Events day by day, by kind, for one way in
     *
     * @param array<string, array<string, array<string, int>>> $daily As daily() gives it.
     * @param string                                            $way   The way in.
     *
     * @return array<string, array<string, int>> Hits by kind, keyed by date.
     */
    public static function byWay(array $daily, string $way): array
    {
        return array_map(static fn(array $byWay) => $byWay[$way] ?? [], $daily);
    }

    /**
     * Drops the counters older than the days kept.
     *
     * @param int $keep Days kept.
     *
     * @return void
     */
    public function purge(int $keep): void
    {
        $wpdb = Scope::db();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE day < %s', Schema::stats(), self::since($keep)));
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
        $wpdb->query($wpdb->prepare('DELETE FROM %i', Schema::stats()));
    }

    /**
     * First day of a period ending today, in the time zone of the site
     *
     * @param int $days Length of the period, today included.
     *
     * @return string
     */
    public static function since(int $days): string
    {
        return (new \DateTimeImmutable('today', wp_timezone()))->modify('-' . max(0, $days - 1) . ' days')->format('Y-m-d');
    }
}

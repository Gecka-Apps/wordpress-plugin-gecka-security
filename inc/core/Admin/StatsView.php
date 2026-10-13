<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Admin;

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Origins;
use Gecka\WP\Plugin\Security\Plugin;
use Gecka\WP\Plugin\Security\Stats;
use Gecka\WP\Plugin\Security\Value;
use Gecka\WP\Plugin\Security\Request;

/**
 * The statistics tab: totals of the period, failures and lockouts over
 * time, where the attempts or the logins came from, the counts by way in and
 * by kind, and the same curve for each way in.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class StatsView
{
    use Controls;

    /**
     * Width of a chart, in the units of its view box.
     */
    private const WIDTH = 1040;

    /**
     * Height of a chart, in the units of its view box.
     */
    private const HEIGHT = 240;

    /**
     * Room left of the plot, for the axis labels.
     */
    private const GUTTER_LEFT = 40;

    /**
     * Room below the plot, for the dates.
     */
    private const GUTTER_BOTTOM = 24;

    /**
     * Room above the plot, for the top label.
     */
    private const GUTTER_TOP = 12;

    /**
     * Widest a bar gets, when the period has few of them.
     */
    private const MAX_BAR = 40;

    /**
     * Past this many days, a bar covers a week.
     */
    private const WEEKLY_PAST = 90;

    /**
     * The kinds of event the light segment of a bar sums up: the failures.
     */
    private const FAILURES = [Events::FAILED, Events::RESERVED, Events::BLOCKED, Events::REFUSED];

    /**
     * Rows a list of origins shows at most.
     */
    private const ORIGINS_LIMIT = 100;

    /**
     * The plugin instance.
     *
     * @var Plugin
     */
    private Plugin $plugin;

    /**
     * Keeps the plugin whose statistics the tab shows.
     *
     * @param Plugin $plugin The plugin instance.
     */
    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    /**
     * Prints the tab.
     *
     * @return void
     */
    public function render(): void
    {
        $days = absint(Request::query('days') ?: 30);
        $days = in_array($days, SettingsPage::PERIODS, true) ? $days : 30;

        if (sanitize_key(Request::query('reset')) === 'stats') {
            wp_admin_notice(__('The statistics were reset.', 'gecka-security'), ['type' => 'success', 'dismissible' => true]);
        }

        echo '<div class="gecka-security-periods">';

        foreach (SettingsPage::PERIODS as $period) {
            printf(
                '<a href="%s" class="button%s"%s>%s</a> ',
                esc_url(SettingsPage::url('stats', ['days' => $period])),
                $period === $days ? ' button-primary' : '',
                $period === $days ? ' aria-current="true"' : '',
                /* translators: %d: number of days */
                esc_html(sprintf(_n('%d day', '%d days', $period, 'gecka-security'), $period)),
            );
        }

        echo '</div>';

        $totals = $this->plugin->stats()->totals($days);
        $daily = $this->plugin->stats()->daily($days);
        $weekly = $days > self::WEEKLY_PAST;
        $whole = self::buckets(Stats::byDay($daily), $weekly);
        $max = self::niceCeiling(self::peak($whole));

        $this->tiles(Stats::byType($totals));

        printf('<h2>%s</h2>', esc_html__('Failures and lockouts', 'gecka-security'));
        $this->legend();
        $this->chart($whole, $max, $weekly, __('Failed logins and lockouts over the period. The same figures follow in a table.', 'gecka-security'));

        $this->origins($days);

        $this->table($totals);
        $this->charts($daily, $totals, $max, $weekly);

        echo '<div class="gecka-admin-buttons">';
        $this->actionButton('gecka_security_reset_stats', __('Reset the statistics', 'gecka-security'), __('Drop every counter?', 'gecka-security'));
        echo '</div>';
    }

    /**
     * Prints the totals of the period, one tile per kind of event, and the
     * addresses locked out right now.
     *
     * @param array<string, int> $byType Hits by kind over the period, as Stats::byType() gives them.
     *
     * @return void
     */
    private function tiles(array $byType): void
    {
        $locked = $this->plugin->lockouts()->countActive();

        echo '<div class="gecka-security-tiles">';

        foreach (Events::types() as $type => $label) {
            printf('<div class="gecka-security-tile card"><span class="gecka-security-tile-value">%s</span><span class="gecka-security-tile-label">%s</span></div>', esc_html(number_format_i18n($byType[$type] ?? 0)), esc_html($label));
        }

        printf('<div class="gecka-security-tile card"><span class="gecka-security-tile-value">%s</span><span class="gecka-security-tile-label">%s</span></div>', esc_html(number_format_i18n($locked)), esc_html__('Locked out right now', 'gecka-security'));
        echo '</div>';
    }

    /**
     * Prints a chart for each way in that saw events over the period, on
     * the scale of the chart of the whole so that the ways compare. A
     * single way would repeat that chart: none is printed then.
     *
     * @param array<string, array<string, array<string, int>>> $daily  Hits by kind, by way in, by day.
     * @param array<string, array<string, int>>                $totals Hits by kind, by way in.
     * @param int                                              $max    Top of the scale.
     * @param bool                                             $weekly Whether a bar covers a week.
     *
     * @return void
     */
    private function charts(array $daily, array $totals, int $max, bool $weekly): void
    {
        $ways = array_filter(array_keys(Events::vectors()), static fn($way) => ! empty($totals[$way]));

        if (count($ways) < 2) {
            return;
        }

        $this->legend();

        foreach ($ways as $way) {
            $label = Events::vectorLabel($way);

            printf('<h3 class="gecka-security-way">%s</h3>', esc_html($label));
            $this->chart(
                self::buckets(Stats::byWay($daily, $way), $weekly),
                $max,
                $weekly,
                /* translators: %s: way in, like the login form */
                sprintf(__('Failed logins and lockouts through %s over the period. The same figures follow in a table.', 'gecka-security'), $label),
            );
        }
    }

    /**
     * Prints the key to the two segments of a bar.
     *
     * @return void
     */
    private function legend(): void
    {
        echo '<div class="gecka-security-legend">';
        printf('<span><i class="gecka-security-swatch is-failures"></i>%s</span>', esc_html__('Failed logins', 'gecka-security'));
        printf('<span><i class="gecka-security-swatch is-lockouts"></i>%s</span>', esc_html__('Lockouts', 'gecka-security'));
        echo '</div>';
    }

    /**
     * Sums the failures and the lockouts of each bar: one per day, one per
     * week when a bar covers a week.
     *
     * @param array<string, array<string, int>> $daily  Hits by kind, by day.
     * @param bool                              $weekly Whether a bar covers a week.
     *
     * @return array<string, array{failures: int, lockouts: int, period: string, date: string}> Keyed by the first day of the bar.
     */
    private static function buckets(array $daily, bool $weekly): array
    {
        $buckets = [];

        // Weeks are cut back from today, so that the last bar is a whole
        // week and the first one takes what is left.
        foreach (array_reverse(array_chunk(array_reverse($daily, true), $weekly ? 7 : 1, true)) as $chunk) {
            $chunk = array_reverse($chunk, true);
            $day = (string) array_key_first($chunk);
            $time = (new \DateTimeImmutable($day . ' 12:00', wp_timezone()))->getTimestamp();
            $period = Value::string(wp_date(Value::string(get_option('date_format')), $time));
            $failures = 0;
            $lockouts = 0;

            foreach ($chunk as $byType) {
                foreach ($byType as $type => $hits) {
                    if ($type === Events::LOCKOUT) {
                        $lockouts += $hits;
                    } elseif (in_array($type, self::FAILURES, true)) {
                        $failures += $hits;
                    }
                }
            }

            $buckets[$day] = [
                'failures' => $failures,
                'lockouts' => $lockouts,
                /* translators: %s: first day of the week */
                'period' => $weekly ? sprintf(__('Week of %s', 'gecka-security'), $period) : $period,
                /* translators: short date on the axis of the chart, see https://www.php.net/manual/datetime.format.php */
                'date' => (string) wp_date(_x('j M', 'chart axis', 'gecka-security'), $time),
            ];
        }

        return $buckets;
    }

    /**
     * Highest bar, 1 at least so that an empty chart keeps a scale.
     *
     * @param array<string, array{failures: int, lockouts: int, period: string, date: string}> $buckets Bars, as buckets() gives them.
     *
     * @return int
     */
    private static function peak(array $buckets): int
    {
        return max(1, ...array_map(static fn($bucket) => $bucket['failures'] + $bucket['lockouts'], array_values($buckets)));
    }

    /**
     * Prints failures and lockouts as stacked bars, the same figures
     * following in a table, folded.
     *
     * @param array<string, array{failures: int, lockouts: int, period: string, date: string}> $buckets Bars, as buckets() gives them.
     * @param int                                                                             $max     Top of the scale.
     * @param bool                                                                             $weekly  Whether a bar covers a week.
     * @param string                                                                           $summary What the chart shows, for the screen readers.
     *
     * @return void
     */
    private function chart(array $buckets, int $max, bool $weekly, string $summary): void
    {
        $plotWidth = self::WIDTH - self::GUTTER_LEFT;
        $baseline = self::HEIGHT - self::GUTTER_BOTTOM;
        $plotHeight = $baseline - self::GUTTER_TOP;
        $step = $plotWidth / max(1, count($buckets));
        $barWidth = max(1.0, min(self::MAX_BAR, $step - 2));

        echo '<div class="gecka-security-chart-frame card">';
        printf('<svg class="gecka-security-chart" viewBox="0 0 %d %d" role="img" aria-label="%s">', (int) self::WIDTH, (int) self::HEIGHT, esc_attr($summary));

        foreach ([0, 0.5, 1] as $fraction) {
            $y = $baseline - $fraction * $plotHeight;

            printf('<line class="grid" x1="%d" x2="%d" y1="%.1f" y2="%.1f"/>', (int) self::GUTTER_LEFT, (int) self::WIDTH, (float) $y, (float) $y);
            printf('<text class="axis" x="%d" y="%.1f" text-anchor="end" dominant-baseline="middle">%s</text>', (int) self::GUTTER_LEFT - 6, (float) $y, esc_html(number_format_i18n($max * $fraction)));
        }

        $index = 0;
        $labelEvery = max(1, (int) ceil(count($buckets) / 8));

        foreach ($buckets as $bucket) {
            $slot = self::GUTTER_LEFT + $index * $step;
            $x = $slot + ($step - $barWidth) / 2;
            $failuresHeight = $bucket['failures'] / $max * $plotHeight;
            $lockoutsHeight = $bucket['lockouts'] / $max * $plotHeight;
            echo '<g class="bar">';
            printf(
                '<title>%s</title>',
                /* translators: 1: day or week, 2: failed logins, 3: lockouts */
                esc_html(sprintf(__('%1$s. Failed logins: %2$s, lockouts: %3$s', 'gecka-security'), $bucket['period'], number_format_i18n($bucket['failures']), number_format_i18n($bucket['lockouts']))),
            );
            printf('<rect class="hit" x="%.1f" y="0" width="%.1f" height="%d"/>', (float) $slot, (float) $step, (int) $baseline);

            if ($failuresHeight > 0) {
                self::bar($x, $baseline - $failuresHeight, $barWidth, $failuresHeight, 'failures', $lockoutsHeight <= 0);
            }

            if ($lockoutsHeight > 0) {
                // 2 units of the surface between the two segments.
                self::bar($x, $baseline - $failuresHeight - $lockoutsHeight, $barWidth, max(0.5, $lockoutsHeight - ($failuresHeight > 0 ? 2 : 0)), 'lockouts', true);
            }

            echo '</g>';

            if ($index % $labelEvery === 0) {
                printf('<text class="axis" x="%.1f" y="%d" text-anchor="middle">%s</text>', (float) ($x + $barWidth / 2), (int) self::HEIGHT - 6, esc_html($bucket['date']));
            }

            $index++;
        }

        echo '</svg></div>';

        printf('<details class="gecka-security-figures"><summary>%s</summary>', esc_html($weekly ? __('Figures week by week', 'gecka-security') : __('Figures day by day', 'gecka-security')));
        echo '<div class="gecka-security-scroll"><table class="widefat striped gecka-security-table"><thead><tr>';
        printf('<th scope="col">%s</th>', esc_html($weekly ? __('Week', 'gecka-security') : __('Day', 'gecka-security')));
        printf('<th scope="col" class="num">%s</th><th scope="col" class="num">%s</th>', esc_html__('Failed logins', 'gecka-security'), esc_html__('Lockouts', 'gecka-security'));
        echo '</tr></thead><tbody>';

        foreach (array_reverse($buckets) as $bucket) {
            printf(
                '<tr><th scope="row">%s</th><td class="num">%s</td><td class="num">%s</td></tr>',
                esc_html($bucket['period']),
                esc_html(number_format_i18n($bucket['failures'])),
                esc_html(number_format_i18n($bucket['lockouts'])),
            );
        }

        echo '</tbody></table></div></details>';
    }

    /**
     * Prints a segment of a bar, its top rounded when it ends the bar.
     *
     * @param float  $x      Left edge.
     * @param float  $y      Top edge.
     * @param float  $width  Width of the segment.
     * @param float  $height Height of the segment.
     * @param string $series Class of the segment: failures or lockouts.
     * @param bool   $top    Whether the segment ends the bar.
     *
     * @return void
     */
    private static function bar(float $x, float $y, float $width, float $height, string $series, bool $top): void
    {
        $radius = $top ? min(4, $width / 2, $height) : 0;

        $path = sprintf(
            'M%.1f %.1f V%.1f Q%.1f %.1f %.1f %.1f H%.1f Q%.1f %.1f %.1f %.1f V%.1f Z',
            $x,
            $y + $height,
            $y + $radius,
            $x,
            $y,
            $x + $radius,
            $y,
            $x + $width - $radius,
            $x + $width,
            $y,
            $x + $width,
            $y + $radius,
            $y + $height,
        );

        printf('<path class="%s" d="%s"/>', esc_attr($series), esc_attr($path));
    }

    /**
     * A round number above the highest value of the chart, even so the
     * middle line of the grid falls on a whole number
     *
     * @param int $value Highest value of the chart, 1 at least.
     *
     * @return int
     */
    private static function niceCeiling(int $value): int
    {
        $magnitude = 10 ** (int) floor(log10($value));

        // Below 10, 1 and 5 would put the middle line on a half.
        foreach ($magnitude > 1 ? [1, 2, 5, 10] : [2, 4, 6, 8, 10] as $factor) {
            if ($value <= $factor * $magnitude) {
                return (int) ($factor * $magnitude);
            }
        }

        return $value;
    }

    /**
     * Prints the events by way in and by kind.
     *
     * @param array<string, array<string, int>> $totals Hits by kind, by way in, as Stats::totals() gives them.
     *
     * @return void
     */
    private function table(array $totals): void
    {
        printf('<h2>%s</h2>', esc_html__('By way in', 'gecka-security'));

        if (! $totals) {
            printf('<p>%s</p>', esc_html__('No event over this period.', 'gecka-security'));

            return;
        }

        $types = Events::types();

        echo '<div class="gecka-security-scroll"><table class="widefat striped gecka-security-table"><thead><tr>';
        printf('<th scope="col">%s</th>', esc_html__('Way in', 'gecka-security'));

        foreach ($types as $label) {
            printf('<th scope="col" class="num">%s</th>', esc_html($label));
        }

        echo '</tr></thead><tbody>';

        foreach (array_keys(Events::vectors()) as $vector) {
            if (empty($totals[$vector])) {
                continue;
            }

            printf('<tr><th scope="row">%s</th>', esc_html(Events::vectorLabel($vector)));

            foreach (array_keys($types) as $type) {
                printf('<td class="num">%s</td>', esc_html(number_format_i18n($totals[$vector][$type] ?? 0)));
            }

            echo '</tr>';
        }

        echo '</tbody></table></div>';
    }

    /**
     * Prints where the events came from: the countries and the networks, as
     * Gecka Geolocation tells them, and the systems the user agents name,
     * for the attempts or for the successful logins.
     *
     * @param int $days Length of the period, today included.
     *
     * @return void
     */
    private function origins(int $days): void
    {
        $logins = sanitize_key(Request::query('origins')) === 'logins';
        $types = $logins ? [Events::LOGIN] : Origins::ATTEMPTS;
        $origins = $this->plugin->origins();
        $located = function_exists('gecka_geolocation');

        printf('<h2>%s</h2>', esc_html__('Origins', 'gecka-security'));

        echo '<div class="gecka-security-periods">';

        foreach (['attempts' => __('Attempts', 'gecka-security'), 'logins' => __('Successful logins', 'gecka-security')] as $key => $label) {
            $current = ($key === 'logins') === $logins;

            printf(
                '<a href="%s" class="button%s"%s>%s</a> ',
                esc_url(SettingsPage::url('stats', ['days' => $days, 'origins' => $key])),
                $current ? ' button-primary' : '',
                $current ? ' aria-current="true"' : '',
                esc_html($label),
            );
        }

        echo '</div><div class="gecka-security-origins">';

        $facets = [Origins::COUNTRY => __('Countries', 'gecka-security'), Origins::NETWORK => __('Networks', 'gecka-security'), Origins::SYSTEM => __('Systems', 'gecka-security')];

        foreach ($facets as $facet => $title) {
            $rows = $origins->top($facet, $days, $types, self::ORIGINS_LIMIT);

            if ($facet !== Origins::SYSTEM && ! $located && $rows === []) {
                continue;
            }

            $this->originPanel($facet, $title, $rows, $origins->total($facet, $days, $types));
        }

        echo '</div>';

        if (! $located) {
            printf('<p class="description">%s</p>', esc_html__('With the Gecka Geolocation plugin, the countries and the networks the events come from are counted too.', 'gecka-security'));
        } elseif (function_exists('gecka_geolocation_credit') && is_array($credit = gecka_geolocation_credit())) {
            printf(
                '<p class="description gecka-security-credit">%s</p>',
                $credit['url'] ? sprintf('<a href="%s">%s</a>', esc_url($credit['url']), esc_html($credit['text'])) : esc_html($credit['text']),
            );
        }
    }

    /**
     * Prints a list of origins, each with its share drawn behind it.
     *
     * @param string                                              $facet One of the facet constants of Origins.
     * @param string                                              $title Heading of the panel.
     * @param array<int, array{value: string, name: string, hits: int}> $rows Values of the facet, the most seen first, as Origins::top() gives them.
     * @param int                                                 $total Hits of the facet over the period, the base of the shares.
     *
     * @return void
     */
    private function originPanel(string $facet, string $title, array $rows, int $total): void
    {
        echo '<div class="gecka-security-origin-panel card">';
        printf('<h3>%s</h3>', esc_html($title));

        if ($rows === []) {
            printf('<p class="description">%s</p></div>', esc_html__('No event over this period.', 'gecka-security'));

            return;
        }

        echo '<ol class="gecka-security-origin-list">';

        foreach ($rows as $row) {
            $share = $total > 0 ? $row['hits'] / $total * 100 : 0;

            printf(
                '<li style="--gecka-security-share:%s%%">%s<span class="gecka-security-origin-label">%s</span><span class="num">%s</span><span class="num gecka-security-origin-share">%s</span></li>',
                esc_attr(number_format(max(1.0, $share), 1, '.', '')),
                self::originIcon($facet, $row['value']), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped when built.
                self::originLabel($facet, $row), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped when built.
                esc_html(number_format_i18n($row['hits'])),
                esc_html($share > 0 && $share < 1 ? __('<1%', 'gecka-security') : sprintf(
                    /* translators: %s: share of the events, a number */
                    _x('%s%%', 'share', 'gecka-security'),
                    number_format_i18n($share),
                )),
            );
        }

        echo '</ol></div>';
    }

    /**
     * The image of an origin: the flag of a country, the logo of a network,
     * a globe when there is none; nothing for a system
     *
     * @param string $facet One of the facet constants of Origins.
     * @param string $value Value of the facet: a country code or an AS number.
     *
     * @return string Markup, escaped.
     */
    private static function originIcon(string $facet, string $value): string
    {
        $url = null;

        if ($facet === Origins::COUNTRY && $value !== '' && function_exists('gecka_geolocation_flag_url')) {
            $url = gecka_geolocation_flag_url($value, '1x1');
        } elseif ($facet === Origins::NETWORK && $value !== '' && $value !== Origins::OTHER_NETWORKS && function_exists('gecka_geolocation_network_logo_url')) {
            $url = gecka_geolocation_network_logo_url((int) $value);
        } elseif ($facet === Origins::SYSTEM) {
            return '';
        }

        if ($url === null) {
            return '<span class="gecka-security-origin-icon dashicons dashicons-admin-site-alt3" aria-hidden="true"></span>';
        }

        return sprintf('<img class="gecka-security-origin-icon is-%s" src="%s" alt="" width="18" height="18" loading="lazy">', esc_attr($facet), esc_url($url));
    }

    /**
     * The name of an origin
     *
     * @param string                                         $facet One of the facet constants of Origins.
     * @param array{value: string, name: string, hits: int} $row   Row of Origins::top().
     *
     * @return string Markup, escaped.
     */
    private static function originLabel(string $facet, array $row): string
    {
        $value = $row['value'];

        if ($facet === Origins::SYSTEM) {
            return esc_html(Origins::systems()[$value] ?? $value);
        }

        if ($value === '') {
            return sprintf('<span class="description">%s</span>', esc_html__('Unknown or private address', 'gecka-security'));
        }

        if ($facet === Origins::NETWORK && $value === Origins::OTHER_NETWORKS) {
            return sprintf('<span class="description">%s</span>', esc_html__('Other networks', 'gecka-security'));
        }

        if ($facet === Origins::COUNTRY) {
            $name = function_exists('gecka_geolocation_country_name') ? (string) gecka_geolocation_country_name($value) : '';

            return esc_html($name !== '' ? $name : $value);
        }

        $asn = 'AS' . $value;

        return $row['name'] !== ''
            ? sprintf('%s <span class="gecka-security-origin-asn">%s</span>', esc_html($row['name']), esc_html($asn))
            : esc_html($asn);
    }
}

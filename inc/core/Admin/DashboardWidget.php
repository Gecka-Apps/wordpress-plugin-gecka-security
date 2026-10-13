<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Admin;

use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Base;
use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Stats;

/**
 * Dashboard widget: the events of the last seven days, the addresses
 * locked out, and links to the statistics and the lockouts.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class DashboardWidget extends Base
{
    /**
     * Days the widget covers.
     */
    private const DAYS = 7;

    /**
     * Adds the widget to the dashboard, or to that of the network.
     *
     * @return void
     */
    public function setup(): void
    {
        add_action(Scope::network() ? 'wp_network_dashboard_setup' : 'wp_dashboard_setup', [$this, 'add']);
    }

    /**
     * Registers the widget and its style sheet for those who may see the
     * statistics.
     *
     * @return void
     */
    public function add(): void
    {
        if (! current_user_can(SettingsPage::capability('stats'))) {
            return;
        }

        wp_add_dashboard_widget('gecka_security', __('Security', 'gecka-security'), [$this, 'render']);
        add_action('admin_enqueue_scripts', [Styles::class, 'style']);
    }

    /**
     * Prints the counts of the last days by kind, the addresses locked out
     * when there are any, and the links.
     *
     * @return void
     */
    public function render(): void
    {
        $byType = Stats::byType($this->plugin->stats()->totals(self::DAYS));
        $locked = $this->plugin->lockouts()->countActive();

        /* translators: %d: number of days */
        printf('<p class="gecka-security-widget-total">%s</p>', esc_html(sprintf(_n('Last %d day', 'Last %d days', self::DAYS, 'gecka-security'), self::DAYS)));

        echo '<table class="widefat striped gecka-security-table"><tbody>';

        foreach (Events::types() as $type => $label) {
            printf('<tr><th scope="row">%s</th><td class="num">%s</td></tr>', esc_html($label), esc_html(number_format_i18n($byType[$type] ?? 0)));
        }

        echo '</tbody></table>';

        if ($locked) {
            printf(
                '<p><a href="%s">%s</a></p>',
                esc_url(SettingsPage::url('lockouts')),
                /* translators: %s: number of addresses */
                esc_html(sprintf(_n('%s address locked out right now', '%s addresses locked out right now', $locked, 'gecka-security'), number_format_i18n($locked))),
            );
        }

        printf('<p><a href="%s">%s</a></p>', esc_url(SettingsPage::url('stats')), esc_html__('See the statistics', 'gecka-security'));
    }
}

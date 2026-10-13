<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Admin;

use Gecka\WP\Plugin\Security\Lockouts;
use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Plugin;
use Gecka\WP\Plugin\Security\Value;

/**
 * The list of the addresses locked out, the latest to be released first.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class LockoutsTable extends \WP_List_Table
{
    /**
     * The plugin instance.
     *
     * @var Plugin
     */
    private Plugin $plugin;

    /**
     * Sets the list up.
     *
     * @param Plugin $plugin The plugin instance.
     */
    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;

        parent::__construct(
            [
                'singular' => 'lockout',
                'plural' => 'lockouts',
                'ajax' => false,
            ],
        );
    }

    /**
     * Reads the addresses of the page.
     *
     * @return void
     */
    public function prepare_items(): void
    {
        $lockouts = $this->plugin->lockouts();
        $perPage = $this->get_items_per_page(LockoutsView::PER_PAGE_OPTION, LockoutsView::PER_PAGE);

        $this->set_pagination_args(
            [
                'total_items' => $lockouts->countActive(),
                'per_page' => $perPage,
            ],
        );

        $this->items = $lockouts->active($this->get_pagenum(), $perPage);
    }

    /**
     * Columns of the list
     *
     * @return array<string, string>
     */
    public function get_columns(): array
    {
        return [
            'cb' => '<input type="checkbox">',
            'ip' => __('Address', 'gecka-security'),
            'until' => __('Locked out until', 'gecka-security'),
            'lockouts' => __('Lockouts', 'gecka-security'),
        ];
    }

    /**
     * The column holding the row actions: the address
     *
     * @return string
     */
    protected function get_default_primary_column_name(): string
    {
        return 'ip';
    }

    /**
     * Classes of the table, that of the plugin added
     *
     * @return string[]
     */
    protected function get_table_classes(): array
    {
        return [...parent::get_table_classes(), 'gecka-security-lockouts'];
    }

    /**
     * The bulk actions, the safelist one for those who may change the
     * settings
     *
     * @return array<string, string>
     */
    protected function get_bulk_actions(): array
    {
        $actions = ['unlock' => __('Release', 'gecka-security')];

        // The safelist is a setting: offered to those who may change the settings.
        if (current_user_can(SettingsPage::capability('settings'))) {
            $actions['safelist'] = __('Release and add to the safelist', 'gecka-security');
        }

        return $actions;
    }

    /**
     * Prints the text of an empty list.
     *
     * @return void
     */
    public function no_items(): void
    {
        esc_html_e('No address is locked out.', 'gecka-security');
    }

    /**
     * The box selecting the address
     *
     * @param object $item Row of the lockouts, as Lockouts::active() gives it.
     *
     * @return string
     */
    protected function column_cb($item): string
    {
        $ip = Value::string($item->ip ?? '');

        return sprintf(
            '<input type="checkbox" name="ips[]" value="%1$s" id="gecka-security-lockout-%2$s"><label for="gecka-security-lockout-%2$s"><span class="screen-reader-text">%3$s</span></label>',
            esc_attr($ip),
            esc_attr(sanitize_key(str_replace(['.', ':', '/'], '-', $ip))),
            esc_html__('Select this address', 'gecka-security'),
        );
    }

    /**
     * The address, as a link to its events
     *
     * @param object $item Row of the lockouts, as Lockouts::active() gives it.
     *
     * @return string
     */
    protected function column_ip(object $item): string
    {
        $ip = Value::string($item->ip ?? '');

        return sprintf('<a href="%s">%s</a>', esc_url(SettingsPage::url('events', ['s' => $ip])), esc_html($ip));
    }

    /**
     * When the lockout ends, and how long is left
     *
     * @param object $item Row of the lockouts, as Lockouts::active() gives it.
     *
     * @return string
     */
    protected function column_until(object $item): string
    {
        $until = Lockouts::time($item->locked_until ?? null);

        return esc_html(Scope::dateTime($until))
            /* translators: %s: how long is left */
            . '<br><span class="description">' . esc_html(sprintf(__('%s left', 'gecka-security'), human_time_diff(time(), max($until, time() + MINUTE_IN_SECONDS)))) . '</span>';
    }

    /**
     * Lockouts within the window, this one included
     *
     * @param object $item Row of the lockouts, as Lockouts::active() gives it.
     *
     * @return string
     */
    protected function column_lockouts(object $item): string
    {
        $count = Value::int($item->lockouts ?? 0);

        // A long lockout starts the count over: it is the last of its run.
        return esc_html($count ? number_format_i18n($count) : __('long lockout', 'gecka-security'));
    }
}

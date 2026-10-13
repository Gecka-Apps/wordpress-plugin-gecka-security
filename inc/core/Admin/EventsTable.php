<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Admin;

use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Plugin;
use Gecka\WP\Plugin\Security\Value;

/**
 * The list of the events, the most recent first, one view per kind,
 * searched by address, network or login, and filtered by login. The number
 * of events per page and the columns shown are screen options.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class EventsTable extends \WP_List_Table
{
    /**
     * The plugin instance.
     *
     * @var Plugin
     */
    private Plugin $plugin;

    /**
     * The filters of the list.
     *
     * @var array{type?: string, ip?: string, net?: string, username?: string[]}
     */
    private array $filters;

    /**
     * Reads the filters of the request and sets the list up.
     *
     * @param Plugin $plugin The plugin instance.
     */
    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
        $this->filters = EventsView::filters();

        parent::__construct(
            [
                'singular' => 'event',
                'plural' => 'events',
                'ajax' => false,
            ],
        );
    }

    /**
     * Reads the events of the page.
     *
     * @return void
     */
    public function prepare_items(): void
    {
        $events = $this->plugin->events();
        $perPage = $this->get_items_per_page(EventsView::PER_PAGE_OPTION, EventsView::PER_PAGE);

        $this->set_pagination_args(
            [
                'total_items' => $events->count($this->filters),
                'per_page' => $perPage,
            ],
        );

        $this->items = $events->entries($this->get_pagenum(), $perPage, $this->filters);
    }

    /**
     * Columns of the list, the site one on a network only
     *
     * @return array<string, string>
     */
    public function get_columns(): array
    {
        $columns = [
            'cb' => '<input type="checkbox">',
            'date' => __('Date', 'gecka-security'),
            'type' => __('Event', 'gecka-security'),
            'ip' => __('Address', 'gecka-security'),
            'username' => __('Login tried', 'gecka-security'),
            'vector' => __('Way in', 'gecka-security'),
            'site' => __('Site', 'gecka-security'),
            'detail' => __('Detail', 'gecka-security'),
        ];

        if (! Scope::network()) {
            unset($columns['site']);
        }

        return $columns;
    }

    /**
     * The column holding the row actions: the date
     *
     * @return string
     */
    protected function get_default_primary_column_name(): string
    {
        return 'date';
    }

    /**
     * Classes of the table, that of the plugin added
     *
     * @return string[]
     */
    protected function get_table_classes(): array
    {
        return [...parent::get_table_classes(), 'gecka-security-events'];
    }

    /**
     * Links to every kind of event, with their counts
     *
     * @return array<string, string>
     */
    protected function get_views(): array
    {
        $base = $this->filters;
        unset($base['type']);
        $counts = $this->plugin->events()->countsByType($base);
        $args = EventsView::args($this->filters, false);
        $current = $this->filters['type'] ?? '';
        /* translators: %s: number of events */
        $views = ['' => sprintf(__('All (%s)', 'gecka-security'), number_format_i18n(array_sum($counts)))];

        foreach (Events::types() as $type => $label) {
            if (! empty($counts[$type])) {
                /* translators: 1: kind of event, 2: number of events */
                $views[$type] = sprintf(__('%1$s (%2$s)', 'gecka-security'), $label, number_format_i18n($counts[$type]));
            }
        }

        $links = [];

        foreach ($views as $type => $label) {
            $links[$type === '' ? 'all' : $type] = sprintf(
                '<a href="%s"%s>%s</a>',
                esc_url(SettingsPage::url('events', $args + ($type === '' ? [] : ['type' => $type]))),
                $type === $current ? ' class="current" aria-current="page"' : '',
                esc_html($label),
            );
        }

        return $links;
    }

    /**
     * The bulk action: deleting the events picked
     *
     * @return array<string, string>
     */
    protected function get_bulk_actions(): array
    {
        return ['delete' => __('Delete', 'gecka-security')];
    }

    /**
     * Prints the text of an empty list.
     *
     * @return void
     */
    public function no_items(): void
    {
        esc_html_e('No event.', 'gecka-security');
    }

    /**
     * The box selecting the event
     *
     * @param object $item Row of the journal, as Events::entries() gives it.
     *
     * @return string
     */
    protected function column_cb($item): string
    {
        $id = Value::int($item->id ?? 0);

        return sprintf(
            '<input type="checkbox" name="ids[]" value="%1$d" id="gecka-security-event-%1$d"><label for="gecka-security-event-%1$d"><span class="screen-reader-text">%2$s</span></label>',
            $id,
            esc_html__('Select this event', 'gecka-security'),
        );
    }

    /**
     * When the event happened, and its last repeat
     *
     * @param object $item Row of the journal, as Events::entries() gives it.
     *
     * @return string
     */
    protected function column_date(object $item): string
    {
        $date = self::date(Value::string($item->created ?? ''));
        $last = Value::string($item->last ?? '');

        if ($last === '') {
            return esc_html($date);
        }

        /* translators: %s: date and time of the last repeat of the event */
        return esc_html($date) . '<br><span class="gecka-security-hits">' . esc_html(sprintf(__('until %s', 'gecka-security'), self::date($last))) . '</span>';
    }

    /**
     * A time of the journal in the format and the time zone of the site
     *
     * @param string $date UTC, as stored.
     *
     * @return string
     */
    private static function date(string $date): string
    {
        $time = strtotime($date . ' UTC');

        return $time !== false ? Scope::dateTime($time) : $date;
    }

    /**
     * The kind of event, and how many times it repeated
     *
     * @param object $item Row of the journal, as Events::entries() gives it.
     *
     * @return string
     */
    protected function column_type(object $item): string
    {
        $type = Value::string($item->type ?? '');

        $hits = Value::int($item->hits ?? 1);

        return sprintf('<span class="gecka-security-event is-%s">%s</span>', esc_attr($type), esc_html(Events::typeLabel($type)))
            /* translators: %s: number of times the event repeated */
            . ($hits > 1 ? sprintf(' <span class="gecka-security-hits">%s</span>', esc_html(sprintf(_x('× %s', 'repeated event', 'gecka-security'), number_format_i18n($hits)))) : '');
    }

    /**
     * The address, as a link to its events, and where it is
     *
     * @param object $item Row of the journal, as Events::entries() gives it.
     *
     * @return string
     */
    protected function column_ip(object $item): string
    {
        $ip = Value::string($item->ip ?? '');

        if ($ip === '') {
            return '<span class="description">' . esc_html__('unknown', 'gecka-security') . '</span>';
        }

        return sprintf('<a href="%s">%s</a>', esc_url(SettingsPage::url('events', ['s' => $ip])), esc_html($ip)) . self::origin($ip);
    }

    /**
     * Where an address is, as Gecka Geolocation tells it today: the flag
     * and the country, the network
     *
     * @param string $ip Address of the event.
     *
     * @return string Markup, escaped; empty when nothing is known.
     */
    private static function origin(string $ip): string
    {
        $record = function_exists('gecka_geolocation') ? gecka_geolocation($ip) : null;

        if ($record === null) {
            return '';
        }

        $parts = [];
        $country = $record->country();

        if ($country !== null) {
            $flag = $record->flagUrl();
            $name = (string) ($record->countryName() ?? $country);

            $parts[] = ($flag !== null ? sprintf('<img src="%s" alt="" width="16" height="12" loading="lazy"> ', esc_url($flag)) : '')
                . sprintf('<span title="%s">%s</span>', esc_attr($name), esc_html($country));
        }

        $asn = $record->asn();

        if ($asn !== null) {
            $organization = (string) $record->asOrganization();

            $parts[] = esc_html($organization !== '' ? $organization : 'AS' . $asn);
        }

        return $parts ? '<br><span class="gecka-security-origin">' . implode(' · ', $parts) . '</span>' : '';
    }

    /**
     * The login tried, as a link to its events
     *
     * @param object $item Row of the journal, as Events::entries() gives it.
     *
     * @return string
     */
    protected function column_username(object $item): string
    {
        $login = Value::string($item->username ?? '');

        if ($login === '') {
            return '';
        }

        return sprintf('<a href="%s">%s</a>', esc_url(SettingsPage::url('events', ['user' => $login])), esc_html($login));
    }

    /**
     * The logins seen in the journal, to pick one, above the list.
     *
     * @param string $which Where the navigation goes: top or bottom.
     *
     * @return void
     */
    protected function extra_tablenav($which): void
    {
        if ($which !== 'top') {
            return;
        }

        $logins = $this->plugin->events()->knownLogins();

        if (! $logins) {
            return;
        }

        $current = (string) ($this->filters['username'][0] ?? '');

        echo '<div class="alignleft actions">';
        printf('<label for="gecka-security-events-user" class="screen-reader-text">%s</label>', esc_html__('Filter by login', 'gecka-security'));
        echo '<select name="user" id="gecka-security-events-user">';
        printf('<option value="">%s</option>', esc_html__('All logins', 'gecka-security'));

        foreach ($logins as $login => $hits) {
            /* translators: 1: login, 2: number of events */
            printf('<option value="%s"%s>%s</option>', esc_attr($login), selected($login, $current, false), esc_html(sprintf(__('%1$s (%2$s)', 'gecka-security'), $login, number_format_i18n($hits))));
        }

        echo '</select> ';
        submit_button(__('Filter', 'gecka-security'), '', 'filter_action', false, ['id' => 'gecka-security-events-filter']);
        echo '</div>';
    }

    /**
     * The way in
     *
     * @param object $item Row of the journal, as Events::entries() gives it.
     *
     * @return string
     */
    protected function column_vector(object $item): string
    {
        return esc_html(Events::vectorLabel(Value::string($item->way ?? '')));
    }

    /**
     * The site of the network the event happened on
     *
     * @param object $item Row of the journal, as Events::entries() gives it.
     *
     * @return string
     */
    protected function column_site(object $item): string
    {
        $site = get_site(Value::int($item->site ?? 0));

        return esc_html($site instanceof \WP_Site ? Value::string($site->blogname) : Value::string($item->site ?? ''));
    }

    /**
     * The detail of the event, in words
     *
     * @param object $item Row of the journal, as Events::entries() gives it.
     *
     * @return string
     */
    protected function column_detail(object $item): string
    {
        return esc_html(Events::describe($item));
    }
}

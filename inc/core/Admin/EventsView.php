<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Admin;

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Network;
use Gecka\WP\Plugin\Security\Plugin;
use Gecka\WP\Plugin\Security\Value;
use Gecka\WP\Plugin\Security\Request;

/**
 * The Journal tab: the list of the events, its screen options and its bulk
 * action, and the button deleting them all.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class EventsView
{
    /**
     * User meta holding the events per page, a screen option.
     */
    public const PER_PAGE_OPTION = 'gecka_security_events_per_page';

    /**
     * Events per page until the screen options say otherwise.
     */
    public const PER_PAGE = 50;

    /**
     * The plugin instance.
     *
     * @var Plugin
     */
    private Plugin $plugin;

    /**
     * The list, built when the page loads.
     *
     * @var EventsTable|null
     */
    private ?EventsTable $table = null;

    /**
     * Keeps the plugin whose journal the tab shows.
     *
     * @param Plugin $plugin The plugin instance.
     */
    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    /**
     * The filters of the list: the kind of event, the login picked, and
     * what was searched, an address or a login
     *
     * @return array{type?: string, ip?: string, net?: string, username?: string[]}
     */
    public static function filters(): array
    {
        $type = sanitize_key(Request::query('type'));
        $search = Request::query('s');
        $user = Request::query('user');

        $filters = [];

        if (isset(Events::types()[$type])) {
            $filters['type'] = $type;
        }

        $network = explode('/', $search, 2)[0];

        if ($search !== '' && filter_var($search, FILTER_VALIDATE_IP) !== false) {
            $filters['ip'] = $search;
        } elseif (str_contains($search, '/') && filter_var($network, FILTER_VALIDATE_IP) !== false) {
            // A network: the key an address is watched under, the /64 of
            // an IPv6 one, matches every address of it.
            $key = Network::key($network);
            $filters += str_contains($key, '/') ? ['net' => $key] : ['ip' => $network];
        } elseif ($search !== '') {
            $user = $search;
        }

        if ($user !== '') {
            $filters['username'] = [$user];
        }

        return $filters;
    }

    /**
     * The query arguments carrying the filters, for a link back to the list
     *
     * @param array{type?: string, ip?: string, net?: string, username?: string[]} $filters Filters, as filters() gives them.
     * @param bool                                                     $type    Whether to carry the kind of event.
     *
     * @return array<string, string>
     */
    public static function args(array $filters, bool $type = true): array
    {
        $args = [];

        if ($type && isset($filters['type'])) {
            $args['type'] = $filters['type'];
        }

        if (isset($filters['ip'])) {
            $args['s'] = $filters['ip'];
        }

        if (isset($filters['net'])) {
            $args['s'] = $filters['net'];
        }

        if (! empty($filters['username'])) {
            $args['user'] = (string) $filters['username'][0];
        }

        return $args;
    }

    /**
     * Sets the screen up before anything is printed: the screen options and
     * the bulk action submitted, which redirects.
     *
     * @return void
     */
    public function load(): void
    {
        require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';

        add_screen_option('per_page', ['default' => self::PER_PAGE, 'option' => self::PER_PAGE_OPTION]);

        $this->table = new EventsTable($this->plugin);
        $this->bulk();
    }

    /**
     * Prints the tab.
     *
     * @return void
     */
    public function render(): void
    {
        $table = $this->table;

        if (! $table) {
            return;
        }

        $this->notice();

        $days = $this->plugin->settings()->int('events_days');

        printf(
            '<p>%s</p>',
            esc_html(
                sprintf(
                    /* translators: %s: number of days */
                    _n('What the protections saw and what changed on the accounts: the logins, failed or successful, the addresses locked out and what they tried meanwhile, the addresses refused, the requests limited or listing the accounts, the breached passwords, the account changes. Kept for %s day.', 'What the protections saw and what changed on the accounts: the logins, failed or successful, the addresses locked out and what they tried meanwhile, the addresses refused, the requests limited or listing the accounts, the breached passwords, the account changes. Kept for %s days.', $days, 'gecka-security'),
                    number_format_i18n($days),
                ),
            ),
        );

        $table->prepare_items();
        $table->views();

        echo '<form method="get">';
        printf('<input type="hidden" name="page" value="%s">', esc_attr(SettingsPage::pageSlug('events')));

        $filters = self::filters();

        if (isset($filters['type'])) {
            printf('<input type="hidden" name="type" value="%s">', esc_attr($filters['type']));
        }

        $table->search_box(__('Search an address or a login', 'gecka-security'), 'gecka-security-events');
        $table->display();
        echo '</form>';

        if (! $this->plugin->events()->count()) {
            return;
        }

        printf('<form method="post" action="%s" class="gecka-admin-buttons">', esc_url(admin_url('admin-post.php')));
        echo '<input type="hidden" name="action" value="gecka_security_clear_events">';
        wp_nonce_field('gecka_security_clear_events');
        printf(
            '<button type="submit" class="button" onclick="return confirm(%s)">%s</button>',
            esc_attr((string) wp_json_encode(__('Delete every event of the journal? The statistics are kept.', 'gecka-security'))),
            esc_html__('Delete everything', 'gecka-security'),
        );
        echo '</form>';
    }

    /**
     * Runs the bulk action submitted, then redirects to the list with a
     * notice. A form submitted without an action, from the page number
     * field or the search box, comes back without the nonce and the
     * referer in its address.
     *
     * @return void
     */
    private function bulk(): void
    {
        $op = $this->table ? $this->table->current_action() : false;
        $args = self::args(self::filters());

        if (! $op) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only drops the arguments of a form submitted without an action.
            if (! empty($_GET['_wp_http_referer'])) {
                wp_safe_redirect(remove_query_arg(['_wp_http_referer', '_wpnonce', 'action', 'action2', 'ids'], Request::serverRaw('REQUEST_URI')));
                exit;
            }

            return;
        }

        if (! current_user_can(SettingsPage::capability('events'))) {
            wp_die(esc_html__('Sorry, you are not allowed to do that.', 'gecka-security'), 403);
        }

        check_admin_referer('bulk-events');

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Each id goes through absint().
        $ids = array_filter(array_map('absint', Value::strings(wp_unslash($_GET['ids'] ?? []))));

        if ($ids && $op === 'delete') {
            $this->plugin->events()->delete($ids);
            $args += ['done' => count($ids), 'op' => 'delete'];
        }

        wp_safe_redirect(SettingsPage::url('events', $args));
        exit;
    }

    /**
     * Prints the notice of the action done.
     *
     * @return void
     */
    private function notice(): void
    {
        $count = absint(Request::query('done'));
        $op = sanitize_key(Request::query('op'));

        if ($op === '') {
            return;
        }

        if ($op === 'delete') {
            /* translators: %s: number of events */
            wp_admin_notice(sprintf(_n('%s event deleted.', '%s events deleted.', $count, 'gecka-security'), number_format_i18n($count)), ['type' => 'success', 'dismissible' => true]);
        } elseif ($op === 'clear') {
            wp_admin_notice(__('Every event was deleted.', 'gecka-security'), ['type' => 'success', 'dismissible' => true]);
        }
    }
}

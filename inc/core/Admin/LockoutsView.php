<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Admin;

use Gecka\WP\Plugin\Security\Plugin;
use Gecka\WP\Plugin\Security\Value;
use Gecka\WP\Plugin\Security\Request;

/**
 * The Lockouts tab: the addresses locked out, released one by one or all
 * at once, or put on the safelist.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class LockoutsView
{
    /**
     * User meta holding the addresses per page, a screen option.
     */
    public const PER_PAGE_OPTION = 'gecka_security_lockouts_per_page';

    /**
     * Addresses per page until the screen options say otherwise.
     */
    public const PER_PAGE = 50;

    /**
     * The plugin instance.
     *
     * @var Plugin
     */
    private Plugin $plugin;

    /**
     * The settings page, which holds the safelist action.
     *
     * @var SettingsPage
     */
    private SettingsPage $page;

    /**
     * The list, built when the page loads.
     *
     * @var LockoutsTable|null
     */
    private ?LockoutsTable $table = null;

    /**
     * Keeps the plugin and the page the tab belongs to.
     *
     * @param Plugin       $plugin The plugin instance.
     * @param SettingsPage $page   The page, which holds the safelist action.
     */
    public function __construct(Plugin $plugin, SettingsPage $page)
    {
        $this->plugin = $plugin;
        $this->page = $page;
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

        $this->table = new LockoutsTable($this->plugin);
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

        printf('<p>%s</p>', esc_html__('The addresses locked out right now, and until when. An IPv6 address is watched as the /64 it belongs to. Release an address, or put it on the safelist so that it is never locked out again.', 'gecka-security'));

        $table->prepare_items();

        echo '<form method="get">';
        printf('<input type="hidden" name="page" value="%s">', esc_attr(SettingsPage::pageSlug('lockouts')));
        $table->display();
        echo '</form>';

        if (! $this->plugin->lockouts()->countActive()) {
            return;
        }

        printf('<form method="post" action="%s" class="gecka-admin-buttons">', esc_url(admin_url('admin-post.php')));
        echo '<input type="hidden" name="action" value="gecka_security_unlock_all">';
        wp_nonce_field('gecka_security_unlock_all');
        printf(
            '<button type="submit" class="button" onclick="return confirm(%s)">%s</button>',
            esc_attr((string) wp_json_encode(__('Release every address?', 'gecka-security'))),
            esc_html__('Release everything', 'gecka-security'),
        );
        echo '</form>';
    }

    /**
     * Runs the bulk action submitted, then redirects to the list with a
     * notice.
     *
     * @return void
     */
    private function bulk(): void
    {
        $op = $this->table ? $this->table->current_action() : false;

        if (! $op) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only drops the arguments of a form submitted without an action.
            if (! empty($_GET['_wp_http_referer'])) {
                wp_safe_redirect(remove_query_arg(['_wp_http_referer', '_wpnonce', 'action', 'action2', 'ips'], Request::serverRaw('REQUEST_URI')));
                exit;
            }

            return;
        }

        if (! current_user_can(SettingsPage::capability('lockouts'))) {
            wp_die(esc_html__('Sorry, you are not allowed to do that.', 'gecka-security'), 403);
        }

        check_admin_referer('bulk-lockouts');

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Each address is sanitized by the closure.
        $keys = array_filter(array_map(static fn($ip): string => sanitize_text_field(Value::string($ip)), (array) wp_unslash($_GET['ips'] ?? [])));
        $args = [];

        if ($keys && $op === 'unlock') {
            $args = ['done' => $this->plugin->lockouts()->unlock($keys), 'op' => 'unlock'];
        } elseif ($keys && $op === 'safelist') {
            // The safelist is a setting: releasing an address is not enough to change it.
            if (! current_user_can(SettingsPage::capability('settings'))) {
                wp_die(esc_html__('Sorry, you are not allowed to do that.', 'gecka-security'), 403);
            }

            $this->page->safelist($keys);
            $args = ['done' => count($keys), 'op' => 'safelist'];
        }

        wp_safe_redirect(SettingsPage::url('lockouts', $args));
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

        $messages = [
            /* translators: %s: number of addresses */
            'unlock' => _n('%s address released.', '%s addresses released.', $count, 'gecka-security'),
            /* translators: %s: number of addresses */
            'safelist' => _n('%s address released and put on the safelist.', '%s addresses released and put on the safelist.', $count, 'gecka-security'),
            'clear' => __('Every address was released.', 'gecka-security'),
        ];

        if (isset($messages[$op])) {
            wp_admin_notice(sprintf($messages[$op], number_format_i18n($count)), ['type' => 'success', 'dismissible' => true]);
        }
    }
}

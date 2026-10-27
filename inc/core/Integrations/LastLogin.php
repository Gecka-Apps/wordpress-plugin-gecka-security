<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Value;

/**
 * The date of the last login of each account, kept in its user meta and
 * shown in a sortable column of the users list, that of the network admin
 * included. Only the logins made with the password of the account count:
 * an application password authenticates on every request of the tool
 * using it.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class LastLogin extends Integration
{
    /**
     * User meta holding the time of the last login.
     */
    public const META = 'gecka_security_last_login';

    /**
     * Column of the users list, also the value of its orderby.
     */
    public const COLUMN = 'gecka_security_last_login';

    /**
     * Always available: it needs nothing beyond WordPress.
     *
     * @return bool
     */
    public function available(): bool
    {
        return true;
    }

    /**
     * Keeps the logins, and adds the column in the admin, when the setting
     * is on.
     *
     * @return void
     */
    public function setup(): void
    {
        if (! $this->plugin->settings()->enabled('last_login')) {
            return;
        }

        add_action('wp_login', [$this, 'login'], self::PRIORITY, 2);

        if (! is_admin()) {
            return;
        }

        foreach (['users', 'users-network'] as $screen) {
            add_filter("manage_{$screen}_columns", [$this, 'columns']);
            add_filter("manage_{$screen}_sortable_columns", [$this, 'sortable']);
        }

        add_filter('manage_users_custom_column', [$this, 'cell'], 10, 3);
        add_action('pre_user_query', [$this, 'order']);
    }

    /**
     * Keeps the time of a login made with the password of the account.
     *
     * @param mixed $login Login of the account.
     * @param mixed $user  The account logged in.
     *
     * @return void
     */
    public function login(mixed $login, mixed $user): void
    {
        if ($user instanceof \WP_User) {
            update_user_meta($user->ID, self::META, time());
        }
    }

    /**
     * Time of the last login of an account
     *
     * @param int $userId Id of the account.
     *
     * @return int 0 when none was kept.
     */
    public static function time(int $userId): int
    {
        return Value::int(get_user_meta($userId, self::META, true));
    }

    /**
     * Adds the column to the users list.
     *
     * @param mixed $columns Columns of the list, by name.
     *
     * @return mixed The columns, that of the last login added when they are an array.
     */
    public function columns(mixed $columns): mixed
    {
        if (is_array($columns)) {
            $columns[self::COLUMN] = __('Last login', 'gecka-security');
        }

        return $columns;
    }

    /**
     * Makes the column sortable, the most recent first on the first click.
     *
     * @param mixed $columns Sortable columns of the list, by name.
     *
     * @return mixed
     */
    public function sortable(mixed $columns): mixed
    {
        if (is_array($columns)) {
            $columns[self::COLUMN] = [self::COLUMN, true];
        }

        return $columns;
    }

    /**
     * The cell of the column: the date of the last login, how long ago in
     * its title.
     *
     * @param mixed $output Content of the cell given by another plugin.
     * @param mixed $column Name of the column.
     * @param mixed $userId Id of the account of the row.
     *
     * @return mixed
     */
    public function cell(mixed $output, mixed $column, mixed $userId): mixed
    {
        if ($column !== self::COLUMN) {
            return $output;
        }

        $time = self::time(Value::int($userId));

        if ($time === 0) {
            return sprintf('<span aria-hidden="true">&#8212;</span><span class="screen-reader-text">%s</span>', esc_html__('No login recorded', 'gecka-security'));
        }

        return sprintf(
            '<time datetime="%s" title="%s">%s</time>',
            esc_attr(gmdate('c', $time)),
            /* translators: %s: human-readable time difference, as "3 hours" */
            esc_attr(sprintf(__('%s ago', 'gecka-security'), human_time_diff($time))),
            esc_html(Scope::dateTime($time)),
        );
    }

    /**
     * Sorts the users on the time of their last login when the list asks
     * for it, the accounts with none at the end of the most recent first.
     * The meta is joined on its key in the ON clause: the accounts without
     * it stay in the list with a NULL, which an orderby on meta_key would
     * drop.
     *
     * @param mixed $query The query of the users list, its clauses built.
     *
     * @return void
     */
    public function order(mixed $query): void
    {
        if (! $query instanceof \WP_User_Query || $query->get('orderby') !== self::COLUMN) {
            return;
        }

        $wpdb = Scope::db();
        $order = strtoupper(Value::string($query->get('order'))) === 'ASC' ? 'ASC' : 'DESC';

        $query->query_from = Value::string($query->query_from) . $wpdb->prepare(' LEFT JOIN %i AS gecka_security_last_login ON (gecka_security_last_login.user_id = %i.ID AND gecka_security_last_login.meta_key = %s)', $wpdb->usermeta, $wpdb->users, self::META);
        $query->query_orderby = sprintf('ORDER BY CAST(gecka_security_last_login.meta_value AS UNSIGNED) %s, %s.user_login ASC', $order, $wpdb->users);
    }
}

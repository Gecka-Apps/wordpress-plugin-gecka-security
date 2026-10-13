<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Value;

/**
 * The successful logins, recorded in the journal with the address, the way
 * in and the roles of the account, application passwords included. A
 * password stolen elsewhere passes every other protection, since the
 * login succeeds at once: the journal is where an administrator logging
 * in from an unusual address shows.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Logins extends Integration
{
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
     * Records the logins, when the setting is on.
     *
     * @return void
     */
    public function setup(): void
    {
        if (! $this->plugin->settings()->enabled('log_logins')) {
            return;
        }

        add_action('wp_login', [$this, 'login'], self::PRIORITY, 2);
        add_action('application_password_did_authenticate', [$this, 'applicationPassword'], self::PRIORITY, 2);
    }

    /**
     * Records a login made with the password of the account.
     *
     * @param mixed $login Login of the account.
     * @param mixed $user  The account logged in, whose roles go in the detail.
     *
     * @return void
     */
    public function login(mixed $login, mixed $user): void
    {
        $this->record(Events::LOGIN, Value::string($login), $user instanceof \WP_User ? implode(', ', $user->roles) : '');
    }

    /**
     * Records a login made with an application password.
     *
     * @param mixed $user The account authenticated.
     * @param mixed $item The application password used.
     *
     * @return void
     */
    public function applicationPassword(mixed $user, mixed $item): void
    {
        if (! $user instanceof \WP_User) {
            return;
        }

        $name = is_array($item) ? Value::string($item['name'] ?? '') : '';

        // Every request of an integration authenticates: those of the hour
        // make one line, or the journal would fill with them.
        $this->fold(Events::LOGIN, HOUR_IN_SECONDS, $user->user_login, 'login.application_password', params: ['roles' => array_values($user->roles), 'name' => $name]);
    }
}

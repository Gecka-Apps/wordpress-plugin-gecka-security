<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Origins;
use Gecka\WP\Plugin\Security\Request;
use Gecka\WP\Plugin\Security\Scope;

/**
 * Mails a user at each of their logins with the password of their account,
 * with the address, the system and, through Gecka Geolocation, the country
 * and the network: the owner of an account sees a login they did not make.
 *
 * Application passwords are left out, an integration authenticating on
 * every request. A login the new network alert already mailed gets no
 * second mail.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class LoginAlerts extends Integration
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
     * Watches the logins, when the setting is on. After the new network
     * alert, which runs at the priority of the protections.
     *
     * @return void
     */
    public function setup(): void
    {
        if (! $this->plugin->settings()->enabled('alert_logins')) {
            return;
        }

        add_action('wp_login', [$this, 'login'], self::PRIORITY + 1, 2);
    }

    /**
     * Mails the account of a login, unless the new network alert did.
     *
     * @param mixed $login Login of the account.
     * @param mixed $user  The account logged in.
     *
     * @return void
     */
    public function login(mixed $login, mixed $user): void
    {
        if (! $user instanceof \WP_User || $user->user_email === '') {
            return;
        }

        $networks = $this->plugin->integration(NewNetworks::class);

        if ($networks instanceof NewNetworks && $networks->alerted($user->ID)) {
            return;
        }

        /**
         * Filters whether a login is mailed to the account.
         *
         * @param bool     $mail Whether to mail it, true for every account.
         * @param \WP_User $user The account logged in.
         */
        if (! apply_filters('gecka_security_alert_login', true, $user)) {
            return;
        }

        $this->mail($user);
    }

    /**
     * Mails the account about a login, in its language.
     *
     * @param \WP_User $user The account logged in.
     *
     * @return bool Whether the mail went out.
     */
    public function mail(\WP_User $user): bool
    {
        $switched = switch_to_user_locale($user->ID);
        $site = Scope::name();
        $ip = $this->plugin->clientIp()->get();
        $record = $ip !== '' && function_exists('gecka_geolocation') ? gecka_geolocation($ip) : null;
        $systems = Origins::systems();

        $lines = [
            /* translators: 1: login, 2: site name */
            sprintf(__('Your account %1$s logged in to %2$s.', 'gecka-security'), $user->user_login, $site),
            '',
            /* translators: %s: date and time */
            sprintf(__('Date: %s', 'gecka-security'), Scope::dateTime(time())),
            /* translators: %s: IP address */
            sprintf(__('Address: %s', 'gecka-security'), $ip !== '' ? $ip : _x('unknown', 'address', 'gecka-security')),
        ];

        if ($record !== null) {
            $country = Events::countryName((string) $record->country());
            $asn = $record->asn();
            $name = (string) $record->asOrganization();
            /* translators: %s: country name */
            $lines[] = sprintf(__('Country: %s', 'gecka-security'), $country !== '' ? $country : _x('unknown', 'country', 'gecka-security'));

            if ($asn !== null) {
                /* translators: %s: name and number of the network */
                $lines[] = sprintf(__('Network: %s', 'gecka-security'), $name !== '' ? sprintf('%s (AS%d)', $name, $asn) : 'AS' . $asn);
            }
        }

        /* translators: %s: operating system, as the browser names it */
        $lines[] = sprintf(__('System: %s', 'gecka-security'), $systems[Origins::system(Request::serverRaw('HTTP_USER_AGENT'))] ?? $systems['other']);
        $lines[] = '';
        $lines[] = __('If it was you, there is nothing to do. Otherwise, change your password at once:', 'gecka-security');
        $lines[] = wp_lostpassword_url();

        /* translators: %s: site name */
        $sent = wp_mail($user->user_email, sprintf(__('[%s] Login to your account', 'gecka-security'), $site), implode("\n", $lines));

        if ($switched) {
            restore_previous_locale();
        }

        return $sent;
    }
}

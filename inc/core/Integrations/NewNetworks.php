<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Value;

/**
 * Mails an administrator who logs in from a network their account never
 * logged in from: a password stolen elsewhere passes every other check,
 * since the login succeeds at once, but comes from somewhere else.
 *
 * The networks an account logged in from are kept in its user meta, by
 * autonomous system number, with the country, the name of the network,
 * when it was last seen and whether its alert went out, the KEPT most
 * recent ones. The first login of an account only learns its network. An
 * alert the mail did not take is tried again at a login from that network
 * a day later at the soonest. Gecka Geolocation tells the network of an
 * address: without it, or for an address it does not know, nothing is
 * learnt nor sent.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class NewNetworks extends Integration
{
    /**
     * User meta holding the networks an account logged in from.
     */
    public const META = 'gecka_security_networks';

    /**
     * Networks of an account kept, the most recently seen.
     */
    public const KEPT = 20;

    /**
     * Seconds before a known network is written as seen again, and an alert
     * not sent tried again: an integration authenticates on every request,
     * which would write the meta and try the mail as often.
     */
    private const SEEN_EVERY = DAY_IN_SECONDS;

    /**
     * Ids of the accounts mailed during the request.
     *
     * @var array<int, true>
     */
    private array $alerted = [];

    /**
     * Always available: Gecka Geolocation is looked for at each login, as
     * it may load after this plugin.
     *
     * @return bool
     */
    public function available(): bool
    {
        return true;
    }

    /**
     * Watches the logins, when the setting is on.
     *
     * @return void
     */
    public function setup(): void
    {
        if (! $this->plugin->settings()->enabled('alert_new_network')) {
            return;
        }

        add_action('wp_login', [$this, 'login'], self::PRIORITY, 2);
        add_action('application_password_did_authenticate', [$this, 'applicationPassword'], self::PRIORITY, 2);
    }

    /**
     * Checks a login made with the password of the account.
     *
     * @param mixed $login Login of the account.
     * @param mixed $user  The account logged in.
     *
     * @return void
     */
    public function login(mixed $login, mixed $user): void
    {
        if ($user instanceof \WP_User) {
            $this->check($user);
        }
    }

    /**
     * Checks a login made with an application password.
     *
     * @param mixed $user The account authenticated.
     * @param mixed $item The application password used.
     *
     * @return void
     */
    public function applicationPassword(mixed $user, mixed $item): void
    {
        if ($user instanceof \WP_User) {
            $this->check($user, is_array($item) ? Value::string($item['name'] ?? '') : '');
        }
    }

    /**
     * Learns the network of a login of a watched account, and mails the
     * account when it is new to it, or when its alert did not go out a day
     * ago or more.
     *
     * @param \WP_User $user        The account logged in.
     * @param string   $application Name of the application password used, empty for the password of the account.
     *
     * @return bool Whether an alert was sent.
     */
    public function check(\WP_User $user, string $application = ''): bool
    {
        $ip = $this->plugin->clientIp()->get();
        $record = $ip !== '' && function_exists('gecka_geolocation') ? gecka_geolocation($ip) : null;
        $asn = $record?->asn();

        if ($record === null || $asn === null) {
            return false;
        }

        $known = self::networks($user->ID);
        $entry = $known[$asn] ?? null;

        if (($entry !== null && time() - $entry['seen'] < self::SEEN_EVERY) || ! self::watched($user)) {
            return false;
        }

        $alert = $known !== [] && ($entry === null || ! $entry['alerted']);
        $network = ['country' => (string) $record->country(), 'name' => (string) $record->asOrganization(), 'seen' => time(), 'alerted' => true];

        if ($alert) {
            $network['alerted'] = $this->mail($user, $ip, $asn, $network, $application);

            if ($network['alerted']) {
                $this->alerted[$user->ID] = true;
            }
        }

        unset($known[$asn]);
        uasort($known, static fn(array $a, array $b): int => $b['seen'] <=> $a['seen']);
        update_user_meta($user->ID, self::META, array_slice([$asn => $network] + $known, 0, self::KEPT, true));

        return $alert && $network['alerted'];
    }

    /**
     * Whether an account was mailed about a new network during the request.
     *
     * @param int $userId Id of the account.
     *
     * @return bool
     */
    public function alerted(int $userId): bool
    {
        return isset($this->alerted[$userId]);
    }

    /**
     * The networks an account logged in from
     *
     * @param int $userId Id of the account.
     *
     * @return array<int, array{country: string, name: string, seen: int, alerted: bool}> By autonomous system number, the most recently seen first.
     */
    public static function networks(int $userId): array
    {
        $networks = [];
        $stored = get_user_meta($userId, self::META, true);

        foreach (is_array($stored) ? $stored : [] as $asn => $network) {
            if (is_array($network)) {
                $networks[(int) $asn] = [
                    'country' => Value::string($network['country'] ?? ''),
                    'name' => Value::string($network['name'] ?? ''),
                    'seen' => Value::int($network['seen'] ?? 0),
                    'alerted' => (bool) ($network['alerted'] ?? true),
                ];
            }
        }

        return $networks;
    }

    /**
     * Whether the logins of an account are watched: by default those of
     * the accounts that manage the site, one of the sites of the network,
     * or the network
     *
     * @param \WP_User $user The account.
     *
     * @return bool
     */
    public static function watched(\WP_User $user): bool
    {
        $watched = user_can($user, 'manage_options') || is_super_admin($user->ID);

        if (! $watched && is_multisite()) {
            foreach (array_keys(get_blogs_of_user($user->ID)) as $site) {
                if (user_can_for_site($user, (int) $site, 'manage_options')) {
                    $watched = true;
                    break;
                }
            }
        }

        /**
         * Filters whether a login from a new network is mailed to the account.
         *
         * @param bool     $watched Whether the account manages the site, one of the sites of the network, or the network.
         * @param \WP_User $user    The account logged in.
         */
        return (bool) apply_filters('gecka_security_watch_networks', $watched, $user);
    }

    /**
     * Mails the account about a login from a new network, in its language.
     *
     * @param \WP_User                                                       $user        The account logged in.
     * @param string                                                         $ip          Address of the login.
     * @param int                                                            $asn         Autonomous system number of the network.
     * @param array{country: string, name: string, seen: int, alerted: bool} $network     The network, as kept.
     * @param string                                                         $application Name of the application password used, empty for the password of the account.
     *
     * @return bool Whether the mail went out.
     */
    private function mail(\WP_User $user, string $ip, int $asn, array $network, string $application): bool
    {
        $switched = switch_to_user_locale($user->ID);
        $site = Scope::name();
        $name = $network['name'] !== '' ? sprintf('%s (AS%d)', $network['name'], $asn) : 'AS' . $asn;
        $country = Events::countryName($network['country']);

        $lines = [
            /* translators: 1: login, 2: site name */
            sprintf(__('Your account %1$s logged in to %2$s from a network it never logged in from before.', 'gecka-security'), $user->user_login, $site),
            '',
            /* translators: %s: name and number of the network */
            sprintf(__('Network: %s', 'gecka-security'), $name),
            /* translators: %s: country name */
            sprintf(__('Country: %s', 'gecka-security'), $country !== '' ? $country : _x('unknown', 'country', 'gecka-security')),
            /* translators: %s: IP address */
            sprintf(__('Address: %s', 'gecka-security'), $ip),
            /* translators: %s: date and time */
            sprintf(__('Date: %s', 'gecka-security'), Scope::dateTime(time())),
            $application !== ''
                /* translators: %s: name of the application password */
                ? sprintf(__('With the application password %s.', 'gecka-security'), $application)
                : __('With the password of the account.', 'gecka-security'),
            '',
            __('If it was you, there is nothing to do. Otherwise, change your password at once and log out everywhere else from your profile:', 'gecka-security'),
            admin_url('profile.php'),
        ];

        /* translators: 1: site name, 2: name of the network */
        $sent = wp_mail($user->user_email, sprintf(__('[%1$s] Login from a new network: %2$s', 'gecka-security'), $site, $name), implode("\n", $lines));

        if ($switched) {
            restore_previous_locale();
        }

        return $sent;
    }
}

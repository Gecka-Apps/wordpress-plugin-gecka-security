<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * WordPress installed once for the whole run, SQLite standing for MySQL, the
 * plugin loaded as a site loads it. The installation lands in .tests/ unless
 * WP_CORE_DIR names another directory; WP_MULTISITE=1 installs a network
 * instead, in a directory of its own.
 */

declare(strict_types=1);

use Mantle\Testkit\TestCase;

if (! getenv('WP_CORE_DIR')) {
    putenv('WP_CORE_DIR=' . dirname(__DIR__) . (getenv('WP_MULTISITE') === '1' ? '/.tests/wordpress-multisite' : '/.tests/wordpress'));
}

uses(TestCase::class)
    ->beforeEach(fn() => gecka_security()->flush())
    ->in(__DIR__);

\Mantle\Testing\manager()
    ->with_sqlite()
    ->with_multisite(getenv('WP_MULTISITE') === '1')
    ->loaded(static function (): void {
        require dirname(__DIR__) . '/bootstrap.php';
    })
    ->install();

/**
 * Changes some settings of the plugin.
 *
 * @param array<string, mixed> $settings Settings to change, by name.
 *
 * @return void
 */
function security_settings(array $settings): void
{
    gecka_security()->settings()->merge($settings);
    gecka_security()->flush();
}

/**
 * An administrator logged in: a super administrator on a network, where
 * the screens of the plugin ask for the rights of the network.
 *
 * @return int Id of the account.
 */
function admin_user(): int
{
    $id = (int) \Mantle\Testkit\TestCase::factory()->user->create(['role' => 'administrator']);

    if (is_multisite()) {
        grant_super_admin($id);
    }

    wp_set_current_user($id);

    return $id;
}

/**
 * Opens or closes the registrations, of the site or of the network.
 *
 * @param bool $open Whether anyone can register.
 *
 * @return void
 */
function registrations_open(bool $open): void
{
    if (is_multisite()) {
        update_site_option('registration', $open ? 'all' : 'none');
    } else {
        update_option('users_can_register', $open ? 1 : 0);
    }
}

/**
 * Makes the request come from an address.
 *
 * @param string $ip Address the request comes from.
 *
 * @return void
 */
function from_ip(string $ip): void
{
    $_SERVER['REMOTE_ADDR'] = $ip;
    gecka_security()->flush();
}

// Gecka Geolocation is not loaded here: this stands for it, answering the
// addresses of $GLOBALS['gecka_security_geolocation'] and none other.
if (! function_exists('gecka_geolocation')) {
    /**
     * The record of an address, as Gecka Geolocation gives it
     *
     * @param string|null $ip       Address looked up.
     * @param string|null $provider Provider asked, unused here.
     *
     * @return object|null Null when no address is known at all.
     */
    function gecka_geolocation(?string $ip = null, ?string $provider = null): ?object
    {
        $known = $GLOBALS['gecka_security_geolocation'] ?? null;

        if (! is_array($known)) {
            return null;
        }

        $data = $known[$ip] ?? [];

        return new class ($data) {
            /**
             * Keeps what is known of the address.
             *
             * @param array<string, mixed> $data Country, asn and organization, when known.
             */
            public function __construct(private array $data) {}

            /**
             * Code of the country
             *
             * @return string|null
             */
            public function country(): ?string
            {
                return $this->data['country'] ?? null;
            }

            /**
             * Number of the autonomous system
             *
             * @return int|null
             */
            public function asn(): ?int
            {
                return $this->data['asn'] ?? null;
            }

            /**
             * Name of the organisation of the network
             *
             * @return string|null
             */
            public function asOrganization(): ?string
            {
                return $this->data['organization'] ?? null;
            }
        };
    }
}

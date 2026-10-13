<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Plugin;
use Gecka\WP\Plugin\Security\Schema;
use Gecka\WP\Plugin\Security\Settings;
use Gecka\WP\Plugin\Security\Setup;

it('creates the tables and schedules the daily task on activation', function () {
    global $wpdb;

    Setup::activate(is_multisite());

    foreach ([Schema::events(), Schema::lockouts(), Schema::stats(), Schema::origins()] as $table) {
        expect($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)))->toBe($table);
    }

    expect(wp_next_scheduled(Setup::PURGE_EVENT))->toBeInt()
        ->and(Scope::option(Setup::VERSION_OPTION))->toBe(Plugin::VERSION . '/' . Schema::VERSION);
});

it('runs the setup again when the recorded version differs', function () {
    Scope::saveOption(Setup::VERSION_OPTION, '0.1.0/1');

    Setup::upgrade(Plugin::VERSION);

    expect(Scope::option(Setup::VERSION_OPTION))->toBe(Setup::installed(Plugin::VERSION));
});

it('stops the daily task on deactivation and leaves nothing on uninstall', function () {
    global $wpdb;

    Setup::activate(is_multisite());
    Scope::saveOption(Settings::OPTION, ['max_failures' => 3]);

    Setup::deactivate();
    expect(wp_next_scheduled(Setup::PURGE_EVENT))->toBeFalse();

    Setup::uninstall();

    foreach ([Schema::events(), Schema::lockouts(), Schema::stats(), Schema::origins()] as $table) {
        expect($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)))->toBeNull();
    }

    expect(Scope::option(Settings::OPTION))->toBeFalse()
        ->and(Scope::option(Setup::VERSION_OPTION))->toBeFalse()
        ->and(Scope::option(\Gecka\WP\Plugin\Security\Integrations\Headers::SERVER_OPTION))->toBeFalse();

    Setup::activate(is_multisite());
});

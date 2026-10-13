<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Integrations\Editor;
use Gecka\WP\Plugin\Security\Integrations\Login;
use Gecka\WP\Plugin\Security\Integrations\XmlRpc;
use Gecka\WP\Plugin\Security\Plugin;

// A request of the front: no admin screen left over by another test.
beforeEach(function () {
    $this->screen = $GLOBALS['current_screen'] ?? null;
    unset($GLOBALS['current_screen']);
});

afterEach(function () {
    $GLOBALS['current_screen'] = $this->screen;
});

/*
 * A protection switched off is not loaded, nor are the screens outside the
 * admin: a request of the front pays for what it uses only.
 */
it('loads only the protections the settings switch on, and no screen outside the admin', function () {
    global $wp_filter;

    // Other tests set screens up by hand: what counts is what this plugin adds.
    $admin = ['admin_post_gecka_security_reset_settings', 'wp_dashboard_setup', 'wp_ajax_health-check-gecka-security_pwned'];
    $callbacks = static fn(): array => array_map(static fn(string $tag): int => isset($wp_filter[$tag]) ? array_sum(array_map('count', $wp_filter[$tag]->callbacks)) : 0, $admin);
    security_settings(['xmlrpc_disabled' => false, 'file_edit_disabled' => false]);
    $before = $callbacks();
    $plugin = new Plugin(gecka_security()->file());

    expect($plugin->integration(XmlRpc::class))->toBeNull()
        ->and($plugin->integration(Editor::class))->toBeNull()
        ->and($plugin->integration(Login::class))->toBeInstanceOf(Login::class)
        ->and($callbacks())->toBe($before);

    security_settings(['file_edit_disabled' => true]);
});

it('declares the tests of Site Health and the personal data tools outside the admin too', function () {
    new Plugin(gecka_security()->file());
    $tests = apply_filters('site_status_tests', ['direct' => [], 'async' => []]);

    expect($tests['direct'])->toHaveKey('gecka_security_address')
        ->and(apply_filters('debug_information', []))->toHaveKey('gecka-security')
        ->and(apply_filters('wp_privacy_personal_data_exporters', []))->toHaveKey('gecka-security')
        ->and(apply_filters('wp_privacy_personal_data_erasers', []))->toHaveKey('gecka-security');
});

it('gates the logins for a blocklist alone, the brute-force protection off', function () {
    security_settings(['bruteforce' => false, 'blocklist' => ['198.51.100.7']]);

    expect((new Plugin(gecka_security()->file()))->integration(Login::class))->toBeInstanceOf(Login::class);

    security_settings(['blocklist' => []]);

    expect((new Plugin(gecka_security()->file()))->integration(Login::class))->toBeNull();

    security_settings(['bruteforce' => true]);
});

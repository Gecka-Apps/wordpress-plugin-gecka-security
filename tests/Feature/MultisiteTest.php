<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\AdminMenu\Menus;
use Gecka\WP\Plugin\Security\Admin\SettingsPage;
use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Integrations\Login;
use Gecka\WP\Plugin\Security\Integrations\Requests;
use Gecka\WP\Plugin\Security\Plugin;
use Gecka\WP\Plugin\Security\Schema;
use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Settings;
use Gecka\WP\Plugin\Security\Setup;
use Gecka\WP\Plugin\Security\Throttle;

/*
 * What a network gets on top of the suite: run with WP_MULTISITE=1, where
 * WordPress is installed as a multisite; skipped on a single site.
 */
beforeEach(function () {
    if (! is_multisite()) {
        $this->markTestSkipped('A network only.');
    }

    $this->second ??= (int) wpmu_create_blog('example.org', '/second/', 'Second site', 1);
    gecka_security()->events()->clear();
    gecka_security()->lockouts()->clear();
});

it('keeps its tables, settings and transients for the whole network', function () {
    global $wpdb;

    security_settings(['max_failures' => 4]);

    expect(Schema::events())->toBe($wpdb->base_prefix . 'gecka_security_events')
        ->and(Schema::lockouts())->toBe($wpdb->base_prefix . 'gecka_security_lockouts')
        ->and(get_site_option(Settings::OPTION)['max_failures'])->toBe(4)
        ->and(get_option(Settings::OPTION))->toBeFalse()
        ->and(Scope::capability())->toBe('manage_network_options');
});

it('counts the failures of an address on every site together, and notes the site of each event', function () {
    switch_to_blog($this->second);

    for ($i = 0; $i < 5; $i++) {
        gecka_security()->lockouts()->fail('203.0.113.77');
    }

    gecka_security()->events()->record(Events::FAILED, '203.0.113.77', 'editor', 'login_form');
    $throttle = gecka_security()->throttle()->hit('reset', '203.0.113.77');
    restore_current_blog();

    expect(gecka_security()->lockouts()->remaining('203.0.113.77'))->toBeGreaterThan(0)
        ->and((int) gecka_security()->events()->entries(1, 1)[0]->site)->toBe($this->second)
        ->and(gecka_security()->throttle()->hit('reset', '203.0.113.77'))->toBe($throttle + 1);

    Throttle::clear();
});

it('schedules the daily task on the main site, whichever site runs the setup', function () {
    wp_clear_scheduled_hook(Setup::PURGE_EVENT);

    switch_to_blog($this->second);
    Setup::install(Plugin::VERSION);
    $onSecond = wp_next_scheduled(Setup::PURGE_EVENT);
    restore_current_blog();

    expect($onSecond)->toBeFalse()
        ->and(wp_next_scheduled(Setup::PURGE_EVENT))->toBeInt();
});

it('puts its menu and its settings in the network admin, for the super administrators', function () {
    // The suite loads the plugin as a front request: the declaration is made here as the admin makes it.
    admin_user();
    set_current_screen('dashboard-network');
    (new SettingsPage(gecka_security()))->declare();
    unset($GLOBALS['current_screen']);

    expect(Menus::menu(SettingsPage::MENU)->isNetwork())->toBeTrue()
        ->and(Menus::options(SettingsPage::PAGE)->isNetwork())->toBeTrue()
        ->and(SettingsPage::url('settings'))->toContain('/network/settings.php?page=gecka-security')
        ->and(SettingsPage::url('events'))->toContain('/network/admin.php?page=security-journal');
});

it('notes a super administrator granted or revoked, and mails the network about the first', function () {
    $mails = [];
    add_filter('pre_wp_mail', function ($pre, $atts) use (&$mails) {
        $mails[] = $atts;

        return true;
    }, 10, 2);
    admin_user();
    $id = static::factory()->user->create(['role' => 'subscriber', 'user_login' => 'rising']);
    gecka_security()->events()->clear();
    $mails = [];

    grant_super_admin($id);
    revoke_super_admin($id);
    remove_all_filters('pre_wp_mail');

    $rows = array_reverse(gecka_security()->events()->entries(1, 5, ['type' => Events::ACCOUNT]));

    expect(array_column($rows, 'detail'))->toBe(['account.super_admin_granted', 'account.super_admin_revoked'])
        ->and(Events::describe($rows[0]))->toContain('made super administrator of the network by')
        ->and($mails)->toHaveCount(1)
        ->and($mails[0]['to'])->toBe(get_site_option('admin_email'))
        ->and($mails[0]['message'])->toContain('was made super administrator of the network by');
});

it('refuses the sign-ups of wp-signup.php to a refused address, and limits them by the hour', function () {
    $screen = $GLOBALS['current_screen'] ?? null;
    unset($GLOBALS['current_screen']);
    security_settings(['blocklist' => ['192.0.2.44'], 'registrations_per_hour' => 1]);

    from_ip('192.0.2.44');
    gecka_security()->integration(Login::class)?->forget();
    $refused = wpmu_validate_user_signup('newcomer', 'newcomer@example.org')['errors']->get_error_codes();

    from_ip('203.0.113.77');
    gecka_security()->integration(Requests::class)?->forget();
    $first = wpmu_validate_user_signup('another', 'another@example.org')['errors']->get_error_codes();
    gecka_security()->integration(Requests::class)?->forget();
    $second = wpmu_validate_user_signup('third', 'third@example.org')['errors']->get_error_codes();

    $GLOBALS['current_screen'] = $screen;
    security_settings(['blocklist' => [], 'registrations_per_hour' => 5]);
    from_ip('127.0.0.1');

    expect($refused)->toContain(Login::REFUSED)
        ->and($first)->not->toContain(Requests::ERROR)
        ->and($second)->toContain(Requests::ERROR);
});

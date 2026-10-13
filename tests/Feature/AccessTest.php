<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Access;
use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Integrations\Login;

beforeEach(function () {
    // A login that passes would ask Have I Been Pwned.
    security_settings(['pwned_passwords' => false]);
    gecka_security()->lockouts()->clear();
    static::factory()->user->create(['user_login' => 'editor', 'user_pass' => 'correct horse']);
    gecka_security()->events()->clear();
    // Each test is a new request: its refusal is recorded.
    gecka_security()->integration(Login::class)?->forget();
    $GLOBALS['gecka_security_geolocation'] = [
        '203.0.113.5' => ['country' => 'NC', 'asn' => 17480],
        '198.51.100.7' => ['country' => 'FR', 'asn' => 3215],
    ];
});

afterEach(function () {
    $GLOBALS['wp_settings_errors'] = [];
    unset($GLOBALS['gecka_security_geolocation']);
    gecka_security()->integration(Login::class)?->forget();
    security_settings(['blocklist' => [], 'countries_mode' => '', 'countries' => [], 'safelist' => [], 'bruteforce' => true, 'pwned_passwords' => true]);
    from_ip('127.0.0.1');
});

it('refuses an address of the blocklist, even with the right password, without counting a failure', function () {
    security_settings(['blocklist' => ['203.0.113.0/24']]);
    from_ip('203.0.113.5');

    $result = wp_authenticate('editor', 'correct horse');

    expect($result)->toBeInstanceOf(WP_Error::class)
        ->and($result->get_error_code())->toBe(Login::REFUSED)
        ->and(gecka_security()->events()->countsByType())->toBe([Events::REFUSED => 1])
        ->and(gecka_security()->events()->entries(1, 1)[0]->detail)->toBe('refused.address')
        ->and(gecka_security()->lockouts()->row('203.0.113.5'))->toBeNull();
});

it('folds the refusals of an hour into one row', function () {
    security_settings(['blocklist' => ['203.0.113.5']]);
    from_ip('203.0.113.5');

    wp_authenticate('editor', 'wrong');
    gecka_security()->integration(Login::class)?->forget();
    wp_authenticate('editor', 'wrong');

    expect(gecka_security()->events()->count())->toBe(1)
        ->and((int) gecka_security()->events()->entries(1, 1)[0]->hits)->toBe(2);
});

it('lets an address of the safelist through the blocklist and the countries', function () {
    security_settings(['blocklist' => ['203.0.113.5'], 'countries_mode' => Access::DENY, 'countries' => ['NC'], 'safelist' => ['203.0.113.5']]);
    from_ip('203.0.113.5');

    expect(wp_authenticate('editor', 'correct horse'))->toBeInstanceOf(WP_User::class);
});

it('refuses the countries not allowed, and never an address whose country is unknown', function () {
    security_settings(['countries_mode' => Access::ALLOW, 'countries' => ['NC']]);

    from_ip('203.0.113.5');
    expect(wp_authenticate('editor', 'correct horse'))->toBeInstanceOf(WP_User::class);

    from_ip('192.0.2.9');
    expect(wp_authenticate('editor', 'correct horse'))->toBeInstanceOf(WP_User::class);

    from_ip('198.51.100.7');
    gecka_security()->events()->clear();
    $result = wp_authenticate('editor', 'correct horse');

    expect($result)->toBeInstanceOf(WP_Error::class)
        ->and($result->get_error_code())->toBe(Login::REFUSED)
        ->and(Events::describe(gecka_security()->events()->entries(1, 1)[0]))->toBe('from FR, a country refused');
});

it('refuses the countries listed', function () {
    security_settings(['countries_mode' => Access::DENY, 'countries' => ['FR']]);

    from_ip('203.0.113.5');
    expect(wp_authenticate('editor', 'correct horse'))->toBeInstanceOf(WP_User::class);

    from_ip('198.51.100.7');
    expect(wp_authenticate('editor', 'correct horse'))->toBeInstanceOf(WP_Error::class);
});

it('refuses with the brute-force protection off, and the registrations and password resets too', function () {
    security_settings(['bruteforce' => false, 'blocklist' => ['198.51.100.7']]);
    from_ip('198.51.100.7');

    $errors = apply_filters('registration_errors', new WP_Error(), 'newcomer', 'newcomer@example.org');
    $reset = new WP_Error();
    do_action('lostpassword_post', $reset, false);

    expect(wp_authenticate('editor', 'correct horse'))->toBeInstanceOf(WP_Error::class)
        ->and($errors->get_error_codes())->toContain(Login::REFUSED)
        ->and($reset->get_error_codes())->toContain(Login::REFUSED);
});

it('keeps the settings from refusing the administrator saving them', function () {
    from_ip('203.0.113.5');

    $clean = gecka_security()->settings()->sanitize([
        'blocklist' => "203.0.113.0/24\n192.0.2.1\n10.0.0.0/4",
        'countries_mode' => Access::ALLOW,
        'countries' => 'fr, au',
    ]);

    expect($clean['blocklist'])->toBe(['192.0.2.1'])
        ->and($clean['countries_mode'])->toBe('')
        ->and($clean['countries'])->toBe([])
        ->and(array_column(get_settings_errors(), 'code'))->toContain('blocklist', 'blocklist_self', 'countries_self');

    $clean = gecka_security()->settings()->sanitize(['countries_mode' => Access::ALLOW, 'countries' => "nc\nfr\nxyz"]);

    expect($clean['countries_mode'])->toBe(Access::ALLOW)
        ->and($clean['countries'])->toBe(['NC', 'FR']);

    $GLOBALS['wp_settings_errors'] = [];
});

it('turns the countries off when none is allowed', function () {
    $clean = gecka_security()->settings()->sanitize(['countries_mode' => Access::ALLOW, 'countries' => '']);

    expect($clean['countries_mode'])->toBe('');

    $GLOBALS['wp_settings_errors'] = [];
});

it('records the account a refusal tried, and folds the logins naming none into one row', function () {
    security_settings(['blocklist' => ['203.0.113.5'], 'log_unknown_logins' => true]);
    from_ip('203.0.113.5');

    wp_authenticate('editor', 'correct horse');

    foreach (['bot-one', 'bot-two', 'bot-three'] as $login) {
        gecka_security()->integration(Login::class)?->forget();
        wp_authenticate($login, 'wrong');
    }

    $rows = gecka_security()->events()->entries(1, 10);

    expect(array_column($rows, 'username'))->toBe(['', 'editor'])
        ->and((int) $rows[0]->hits)->toBe(3);

    security_settings(['log_unknown_logins' => false]);
});

it('reads the address of the administrator saving as the proxy settings saved read it', function () {
    // Behind a proxy at 10.0.0.8, the administrator is at 203.0.113.5: the save that names the proxy and blocks that address keeps it out.
    from_ip('10.0.0.8');
    $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5';

    $clean = gecka_security()->settings()->sanitize(['ip_source' => 'x_forwarded_for', 'trusted_proxies' => '10.0.0.8', 'blocklist' => "203.0.113.0/24\n192.0.2.1"]);

    unset($_SERVER['HTTP_X_FORWARDED_FOR']);
    $GLOBALS['wp_settings_errors'] = [];

    expect($clean['blocklist'])->toBe(['192.0.2.1']);
});

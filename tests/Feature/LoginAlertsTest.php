<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Integrations\Integration;
use Gecka\WP\Plugin\Security\Integrations\LoginAlerts;
use Gecka\WP\Plugin\Security\Integrations\NewNetworks;

beforeEach(function () {
    security_settings(['alert_logins' => true]);
    // A login that passes asks Have I Been Pwned, which knows none of these passwords.
    add_filter('pre_http_request', fn() => ['headers' => [], 'body' => '', 'response' => ['code' => 200, 'message' => 'OK'], 'cookies' => []]);
    $this->mails = [];
    add_filter('pre_wp_mail', function ($pre, $atts) {
        $this->mails[] = $atts;

        return true;
    }, 10, 2);
    $GLOBALS['gecka_security_geolocation'] = [
        '203.0.113.5' => ['country' => 'NC', 'asn' => 17480, 'organization' => 'CANL'],
        '198.51.100.7' => ['country' => 'FR', 'asn' => 3215, 'organization' => 'Orange'],
    ];
    $this->alerts = new LoginAlerts(gecka_security());
    $this->alerts->setup();
    $this->user = static::factory()->user->create_and_get(['role' => 'subscriber', 'user_login' => 'reader', 'user_email' => 'reader@example.org', 'user_pass' => 'correct horse']);
});

afterEach(function () {
    remove_action('wp_login', [$this->alerts, 'login'], Integration::PRIORITY + 1);
    remove_all_filters('pre_wp_mail');
    remove_all_filters('pre_http_request');
    remove_all_filters('gecka_security_alert_login');
    security_settings(['alert_logins' => false]);
    unset($GLOBALS['gecka_security_geolocation'], $_SERVER['HTTP_USER_AGENT']);
    from_ip('127.0.0.1');
});

it('is off by default', function () {
    expect(gecka_security()->settings()->defaults()['alert_logins'])->toBeFalse();
});

it('mails a user at each login, with the address, the country, the network and the system', function () {
    from_ip('203.0.113.5');
    $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';

    wp_signon(['user_login' => 'reader', 'user_password' => 'correct horse']);
    wp_signon(['user_login' => 'reader', 'user_password' => 'correct horse']);

    expect($this->mails)->toHaveCount(2)
        ->and($this->mails[0]['to'])->toBe('reader@example.org')
        ->and($this->mails[0]['subject'])->toContain('Login to your account')
        ->and($this->mails[0]['message'])->toContain('203.0.113.5')
        ->and($this->mails[0]['message'])->toContain('CANL (AS17480)')
        ->and($this->mails[0]['message'])->toContain('Windows')
        ->and($this->mails[0]['message'])->toContain(wp_lostpassword_url());
});

it('mails no failed login', function () {
    wp_signon(['user_login' => 'reader', 'user_password' => 'wrong']);

    expect($this->mails)->toBe([]);
});

it('sends no second mail for a login the new network alert reported', function () {
    $admin = static::factory()->user->create_and_get(['role' => 'administrator', 'user_login' => 'boss', 'user_email' => 'boss@example.org', 'user_pass' => 'correct horse']);
    update_user_meta($admin->ID, NewNetworks::META, [17480 => ['country' => 'NC', 'name' => 'CANL', 'seen' => time() - 2 * DAY_IN_SECONDS, 'alerted' => true]]);
    from_ip('198.51.100.7');
    $this->mails = [];

    wp_signon(['user_login' => 'boss', 'user_password' => 'correct horse']);

    expect($this->mails)->toHaveCount(1)
        ->and($this->mails[0]['subject'])->toContain('Login from a new network');
});

it('leaves the accounts the filter excludes alone', function () {
    add_filter('gecka_security_alert_login', fn(bool $mail, \WP_User $user): bool => user_can($user, 'manage_options'), 10, 2);

    wp_signon(['user_login' => 'reader', 'user_password' => 'correct horse']);

    expect($this->mails)->toBe([]);
});

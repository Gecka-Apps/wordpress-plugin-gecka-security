<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Integrations\NewNetworks;
use Gecka\WP\Plugin\Security\Privacy;

beforeEach(function () {
    // A login that passes would ask Have I Been Pwned.
    security_settings(['pwned_passwords' => false]);
    $this->mails = [];
    add_filter('pre_wp_mail', function ($pre, $atts) {
        if (str_contains((string) ($atts['subject'] ?? ''), 'new network')) {
            $this->mails[] = $atts;
        }

        return true;
    }, 10, 2);
    $GLOBALS['gecka_security_geolocation'] = [
        '203.0.113.5' => ['country' => 'NC', 'asn' => 17480, 'organization' => 'CANL'],
        '198.51.100.7' => ['country' => 'FR', 'asn' => 3215, 'organization' => 'Orange'],
        '192.0.2.9' => ['country' => 'NC', 'asn' => 17480, 'organization' => 'CANL'],
    ];
    $this->admin = static::factory()->user->create_and_get(['role' => 'administrator', 'user_login' => 'boss', 'user_email' => 'boss@example.org', 'user_pass' => 'correct horse']);
});

afterEach(function () {
    remove_all_filters('pre_wp_mail');
    security_settings(['pwned_passwords' => true]);
    unset($GLOBALS['gecka_security_geolocation']);
    from_ip('127.0.0.1');
});

it('learns the network of a first login without a mail, then mails a login from a new one', function () {
    from_ip('203.0.113.5');
    wp_signon(['user_login' => 'boss', 'user_password' => 'correct horse']);

    expect($this->mails)->toBe([])
        ->and(array_keys(NewNetworks::networks($this->admin->ID)))->toBe([17480]);

    // Another address of the same network is no news.
    from_ip('192.0.2.9');
    wp_signon(['user_login' => 'boss', 'user_password' => 'correct horse']);

    expect($this->mails)->toBe([]);

    from_ip('198.51.100.7');
    wp_signon(['user_login' => 'boss', 'user_password' => 'correct horse']);

    expect($this->mails)->toHaveCount(1)
        ->and($this->mails[0]['to'])->toBe('boss@example.org')
        ->and($this->mails[0]['subject'])->toContain('Login from a new network: Orange (AS3215)')
        ->and($this->mails[0]['message'])->toContain('198.51.100.7')
        ->and(array_keys(NewNetworks::networks($this->admin->ID)))->toBe([3215, 17480]);
});

it('watches only the accounts that manage the site', function () {
    $reader = static::factory()->user->create_and_get(['role' => 'subscriber']);
    update_user_meta($reader->ID, NewNetworks::META, [3215 => ['country' => 'FR', 'name' => 'Orange', 'seen' => time()]]);
    from_ip('203.0.113.5');

    expect((new NewNetworks(gecka_security()))->check($reader))->toBeFalse()
        ->and(get_user_meta($reader->ID, NewNetworks::META, true))->toHaveKey(3215)
        ->and($this->mails)->toBe([]);
});

it('learns nothing of an address the geolocation does not know', function () {
    from_ip('192.0.2.200');

    expect((new NewNetworks(gecka_security()))->check($this->admin))->toBeFalse()
        ->and(NewNetworks::networks($this->admin->ID))->toBe([]);
});

it('keeps the most recent networks only', function () {
    $known = [];

    for ($asn = 1; $asn <= NewNetworks::KEPT; $asn++) {
        $known[$asn] = ['country' => 'NC', 'name' => '', 'seen' => time() - DAY_IN_SECONDS * (100 - $asn)];
    }

    update_user_meta($this->admin->ID, NewNetworks::META, $known);
    from_ip('203.0.113.5');

    expect((new NewNetworks(gecka_security()))->check($this->admin))->toBeTrue()
        ->and(NewNetworks::networks($this->admin->ID))->toHaveCount(NewNetworks::KEPT)
        ->and(NewNetworks::networks($this->admin->ID))->not->toHaveKey(1)
        ->and(array_key_first(NewNetworks::networks($this->admin->ID)))->toBe(17480);
});

it('exports and erases the networks of an account', function () {
    from_ip('203.0.113.5');
    (new NewNetworks(gecka_security()))->check($this->admin);
    $privacy = new Privacy(gecka_security());

    $export = $privacy->export('boss@example.org');

    expect(array_column($export['data'], 'group_id'))->toContain('gecka-security-networks')
        ->and($privacy->erase('boss@example.org')['items_removed'])->toBeGreaterThanOrEqual(1)
        ->and(NewNetworks::networks($this->admin->ID))->toBe([]);
});

it('tries an alert the mail did not take again a day later, not at every login', function () {
    from_ip('203.0.113.5');
    (new NewNetworks(gecka_security()))->check($this->admin);

    remove_all_filters('pre_wp_mail');
    add_filter('pre_wp_mail', '__return_false');
    from_ip('198.51.100.7');

    expect((new NewNetworks(gecka_security()))->check($this->admin))->toBeFalse()
        ->and(NewNetworks::networks($this->admin->ID)[3215]['alerted'])->toBeFalse()
        // The same day: no new try.
        ->and((new NewNetworks(gecka_security()))->check($this->admin))->toBeFalse();

    $networks = get_user_meta($this->admin->ID, NewNetworks::META, true);
    $networks[3215]['seen'] = time() - DAY_IN_SECONDS;
    update_user_meta($this->admin->ID, NewNetworks::META, $networks);
    remove_all_filters('pre_wp_mail');
    add_filter('pre_wp_mail', '__return_true');

    expect((new NewNetworks(gecka_security()))->check($this->admin))->toBeTrue()
        ->and(NewNetworks::networks($this->admin->ID)[3215]['alerted'])->toBeTrue();
});

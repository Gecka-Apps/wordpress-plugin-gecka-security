<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Integrations\Pwned;

/*
 * The service is faked with the range of the SHA-1 of "password", whose
 * prefix is 5BAA6 and suffix 1E4C9B93F3F0682250B6CF8331B7EE68FD8; a null
 * count makes it fail.
 */
function pwned_service(?int $count, int &$calls): void
{
    remove_all_filters('pre_http_request');
    add_filter('pre_http_request', function ($pre, $args, $url) use ($count, &$calls) {
        if (! str_contains((string) $url, 'pwnedpasswords.com')) {
            return $pre;
        }

        $calls++;

        return $count === null
            ? new WP_Error('http_request_failed', 'down')
            : ['response' => ['code' => 200], 'body' => "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:$count\r\n"];
    }, 10, 3);
}

afterEach(function () {
    remove_all_filters('pre_http_request');
});

it('refuses a breached password when it is set, and lets a clean one through', function () {
    $calls = 0;
    pwned_service(3730471, $calls);
    $pwned = new Pwned(gecka_security());

    $errors = new WP_Error();
    $pwned->profile($errors, true, (object) ['user_pass' => 'password']);

    expect($errors->get_error_code())->toBe(Pwned::ERROR)
        ->and($errors->get_error_message())->toContain('3');

    $errors = new WP_Error();
    $pwned->profile($errors, true, (object) ['user_pass' => 'correct horse battery staple']);

    expect($errors->has_errors())->toBeFalse()
        ->and($pwned->count('password'))->toBe(3730471)
        ->and($pwned->count('correct horse battery staple'))->toBe(0)
        ->and($calls)->toBe(4);
});

it('lets a password through when the service does not answer', function () {
    $calls = 0;
    pwned_service(null, $calls);
    $pwned = new Pwned(gecka_security());

    $errors = new WP_Error();
    $pwned->profile($errors, true, (object) ['user_pass' => 'password']);

    expect($errors->has_errors())->toBeFalse()
        ->and($pwned->count('password'))->toBeNull();
});

it('warns a user who logs in with a breached password, checked once a month and only once the password proved right', function () {
    $calls = 0;
    pwned_service(3730471, $calls);
    gecka_security()->events()->clear();
    $user = static::factory()->user->create_and_get(['user_login' => 'breached', 'user_pass' => 'password', 'role' => 'editor']);

    expect(wp_authenticate('breached', 'wrong'))->toBeInstanceOf(WP_Error::class)
        ->and($calls)->toBe(0)
        ->and(wp_authenticate('breached', 'password'))->toBeInstanceOf(WP_User::class)
        ->and($calls)->toBe(1)
        ->and(wp_authenticate('breached', 'password'))->toBeInstanceOf(WP_User::class)
        ->and($calls)->toBe(1)
        ->and(Pwned::breached($user))->toBeTrue()
        ->and(gecka_security()->events()->countsByType(['type' => Events::BREACHED]))->toBe([Events::BREACHED => 1]);

    wp_set_current_user($user->ID);
    ob_start();
    (new Pwned(gecka_security()))->notice();
    $html = ob_get_clean();

    expect($html)->toContain('known data breaches')
        ->toContain('profile.php');

    wp_set_password('correct horse battery staple', $user->ID);

    expect(Pwned::breached(get_user_by('id', $user->ID)))->toBeFalse();
});

it('keeps the verdict when WordPress rehashes an outdated hash after the login', function () {
    global $wpdb;

    $calls = 0;
    pwned_service(3730471, $calls);
    require_once ABSPATH . WPINC . '/class-phpass.php';
    $user = static::factory()->user->create_and_get(['user_login' => 'legacy', 'user_pass' => 'x', 'role' => 'editor']);
    $wpdb->update($wpdb->users, ['user_pass' => (new PasswordHash(8, true))->HashPassword('password')], ['ID' => $user->ID]);
    clean_user_cache($user->ID);

    expect(wp_authenticate('legacy', 'password'))->toBeInstanceOf(WP_User::class)
        ->and(get_user_by('id', $user->ID)->user_pass)->not->toStartWith('$P$')
        ->and(Pwned::breached(get_user_by('id', $user->ID)))->toBeTrue();
});

it('checks the password of the reset form of WooCommerce', function () {
    $calls = 0;
    pwned_service(3730471, $calls);
    $_POST['password_1'] = 'password';
    $errors = new WP_Error();
    (new Pwned(gecka_security()))->reset($errors, null);
    unset($_POST['password_1']);

    expect($errors->get_error_code())->toBe(Pwned::ERROR);
});

it('asks nothing of the service for a registration refused already', function () {
    $calls = 0;
    pwned_service(3730471, $calls);
    $_POST['password'] = 'password';
    $pwned = new Pwned(gecka_security());

    $refused = $pwned->registration(new WP_Error('limited', 'no'));
    $checked = $pwned->registration(new WP_Error());
    unset($_POST['password']);

    expect($refused->get_error_codes())->toBe(['limited'])
        ->and($checked->get_error_code())->toBe(Pwned::ERROR)
        ->and($calls)->toBe(1);
});

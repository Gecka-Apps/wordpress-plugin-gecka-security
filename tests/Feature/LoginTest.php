<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Integrations\Login;

beforeEach(function () {
    security_settings(['max_failures' => 3, 'lockout_minutes' => 20]);
    gecka_security()->lockouts()->clear();
    $this->user = get_user_by('id', static::factory()->user->create(['user_login' => 'editor', 'user_pass' => 'correct horse']));
    gecka_security()->events()->clear();
    $GLOBALS['pagenow'] = 'wp-login.php';
    $_SERVER['REQUEST_METHOD'] = 'POST';
    from_ip('203.0.113.5');
});

afterEach(function () {
    $GLOBALS['pagenow'] = 'index.php';
    unset($_SERVER['REQUEST_METHOD']);
    from_ip('127.0.0.1');
});

it('keeps the login of a failure only when it names an account or a reserved name', function () {
    // A reserved name weighs double: the maximum is raised so that no lockout joins the rows.
    security_settings(['max_failures' => 10]);
    wp_authenticate('editor', 'wrong');
    wp_authenticate('correct horse battery staple', 'wrong');
    wp_authenticate('admin', 'wrong');

    expect(array_column(gecka_security()->events()->entries(1, 3), 'username'))->toBe(['admin', '', 'editor']);
});

it('keeps every login of a failure when told to', function () {
    security_settings(['max_failures' => 10, 'log_unknown_logins' => true]);
    wp_authenticate('editor', 'wrong');
    wp_authenticate('nobody', 'wrong');

    expect(array_column(gecka_security()->events()->entries(1, 2), 'username'))->toBe(['nobody', 'editor']);
});

it('counts the failed logins of an address and locks it out at the maximum', function () {
    for ($i = 0; $i < 3; $i++) {
        $result = wp_authenticate('editor', 'wrong');
        expect($result)->toBeInstanceOf(WP_Error::class);
    }

    expect($result->get_error_code())->toBe('incorrect_password')
        ->and(gecka_security()->lockouts()->remaining('203.0.113.5'))->toBeGreaterThan(0)
        ->and(gecka_security()->events()->countsByType())->toBe([Events::FAILED => 3, Events::LOCKOUT => 1]);
});

it('refuses a correct password while locked out, and records the attempt once', function () {
    for ($i = 0; $i < 3; $i++) {
        wp_authenticate('editor', 'wrong');
    }

    $result = wp_authenticate('editor', 'correct horse');

    expect($result)->toBeInstanceOf(WP_Error::class)
        ->and($result->get_error_code())->toBe(Login::ERROR)
        ->and($result->get_error_message())->toContain('Too many failed login attempts')
        ->and(gecka_security()->events()->count(['type' => Events::BLOCKED]))->toBe(1);
});

it('refuses a login on an account that does not exist while locked out', function () {
    for ($i = 0; $i < 3; $i++) {
        wp_authenticate('editor', 'wrong');
    }

    expect(wp_authenticate('nobody', 'wrong')->get_error_code())->toBe(Login::ERROR);
});

it('does not count the refusals of this plugin or of a captcha as a guess', function () {
    for ($i = 0; $i < 3; $i++) {
        wp_authenticate('editor', 'wrong');
    }

    $blocked = gecka_security()->events()->count(['type' => Events::BLOCKED]);
    wp_authenticate('editor', 'wrong');
    wp_authenticate('editor', 'wrong');

    expect(gecka_security()->events()->count(['type' => Events::FAILED]))->toBe(3);

    do_action('wp_login_failed', 'editor', new WP_Error('cap_captcha_failed', 'captcha'));

    expect(gecka_security()->events()->count(['type' => Events::FAILED]))->toBe(3);
});

it('does not forget the failures after a successful login', function () {
    wp_authenticate('editor', 'wrong');
    wp_authenticate('editor', 'wrong');

    $user = wp_authenticate('editor', 'correct horse');
    expect($user)->toBeInstanceOf(WP_User::class);
    do_action('wp_login', $user->user_login, $user);

    wp_authenticate('editor', 'wrong');

    expect(gecka_security()->lockouts()->remaining('203.0.113.5'))->toBeGreaterThan(0);
});

it('counts an application password refused on the REST API and keeps one from being checked while locked out', function () {
    $_SERVER['PHP_AUTH_USER'] = 'editor';

    do_action('application_password_failed_authentication', new WP_Error('invalid_application_password', 'nope'));

    expect(gecka_security()->events()->entries(1, 1)[0])->toMatchObject(['type' => Events::FAILED, 'username' => 'editor']);

    for ($i = 0; $i < 3; $i++) {
        wp_authenticate('editor', 'wrong');
    }

    expect(has_filter('determine_current_user', 'wp_validate_application_password'))->toBe(20);
    apply_filters('determine_current_user', false);
    // The refused attempt is recorded once per request, and the process of
    // the suite already recorded one in a test above.
    expect(has_filter('determine_current_user', 'wp_validate_application_password'))->toBeFalse();

    unset($_SERVER['PHP_AUTH_USER']);
    add_filter('determine_current_user', 'wp_validate_application_password', 20);
});

it('refuses the WooCommerce registration of a locked-out address', function () {
    for ($i = 0; $i < 3; $i++) {
        wp_authenticate('editor', 'wrong');
    }

    expect(apply_filters('woocommerce_registration_errors', new WP_Error(), 'newbie', 'newbie@example.org')->get_error_code())->toBe(Login::ERROR);
});

it('counts a failed login on a reserved name double, whether an account carries it or not', function () {
    wp_authenticate('root', 'wrong');

    expect(gecka_security()->events()->countsByType())->toBe([Events::RESERVED => 1]);

    wp_authenticate('root', 'wrong');

    expect(gecka_security()->lockouts()->remaining('203.0.113.5'))->toBeGreaterThan(0);

    // The same pace on an account carrying a reserved name: a lockout coming later would tell it exists.
    gecka_security()->lockouts()->clear();
    gecka_security()->events()->clear();
    security_settings(['reserved_names' => ['root', 'editor']]);

    wp_authenticate('editor', 'wrong');
    wp_authenticate('editor', 'wrong');

    expect(gecka_security()->events()->countsByType())->toBe([Events::FAILED => 2, Events::LOCKOUT => 1])
        ->and(gecka_security()->lockouts()->remaining('203.0.113.5'))->toBeGreaterThan(0);

    security_settings(['reserved_names' => \Gecka\WP\Plugin\Security\Settings::RESERVED_NAMES]);
});

it('never locks out an address on the safelist, nor the loopback', function () {
    security_settings(['safelist' => ['203.0.113.5']]);

    for ($i = 0; $i < 4; $i++) {
        wp_authenticate('editor', 'wrong');
    }

    expect(gecka_security()->lockouts()->remaining('203.0.113.5'))->toBe(0)
        ->and(wp_authenticate('editor', 'correct horse'))->toBeInstanceOf(WP_User::class);

    from_ip('127.0.0.1');

    for ($i = 0; $i < 4; $i++) {
        wp_authenticate('editor', 'wrong');
    }

    expect(wp_authenticate('editor', 'correct horse'))->toBeInstanceOf(WP_User::class);
});

it('refuses the registration and the password reset of a locked-out address', function () {
    for ($i = 0; $i < 3; $i++) {
        wp_authenticate('editor', 'wrong');
    }

    $errors = apply_filters('registration_errors', new WP_Error(), 'newbie', 'newbie@example.org');
    expect($errors->get_error_code())->toBe(Login::ERROR);

    $errors = new WP_Error();
    do_action('lostpassword_post', $errors);
    expect($errors->get_error_code())->toBe(Login::ERROR);
});

it('tells a locked-out visitor on the login screen before the form', function () {
    for ($i = 0; $i < 3; $i++) {
        wp_authenticate('editor', 'wrong');
    }

    $_SERVER['REQUEST_METHOD'] = 'GET';

    expect(apply_filters('login_message', ''))->toContain('Too many failed login attempts');
});

it('records the way the login came in', function () {
    unset($_SERVER['REQUEST_METHOD']);
    $_POST['woocommerce-login-nonce'] = 'x';
    wp_authenticate('editor', 'wrong');
    unset($_POST['woocommerce-login-nonce']);

    expect(gecka_security()->events()->entries(1, 1)[0]->way)->toBe('woocommerce');
});

it('records the refusals of one lockout as one row, counted', function () {
    for ($i = 0; $i < 3; $i++) {
        wp_authenticate('editor', 'wrong');
    }

    gecka_security()->events()->clear();

    foreach ([1, 2, 3] as $attempt) {
        // A fresh instance per attempt, as each request gets one.
        expect((new Login(gecka_security()))->gateUser($this->user))->toBeInstanceOf(WP_Error::class);
    }

    $entries = gecka_security()->events()->entries(1, 10);

    expect($entries)->toHaveCount(1)
        ->and($entries[0]->type)->toBe(Events::BLOCKED)
        ->and((int) $entries[0]->hits)->toBe(3);
});

it('counts nothing that fails while the address is locked out', function () {
    for ($i = 0; $i < 3; $i++) {
        wp_authenticate('editor', 'wrong');
    }

    do_action('application_password_failed_authentication', new WP_Error('incorrect_password', 'nope'));
    do_action('wp_login_failed', 'editor', new WP_Error('incorrect_password', 'nope'));

    expect((int) gecka_security()->lockouts()->row('203.0.113.5')->failures)->toBe(0)
        ->and((int) gecka_security()->lockouts()->row('203.0.113.5')->lockouts)->toBe(1);
});

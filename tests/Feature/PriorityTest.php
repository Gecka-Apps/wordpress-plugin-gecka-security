<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Integrations\Integration;

/*
 * The checks on the hooks other plugins share run ahead of the default
 * priority, so a refusal comes before a captcha is verified; the final gate
 * on authenticate runs after the handlers of WordPress, which would let a
 * correct password through an earlier error.
 */
it('hooks the checks ahead of the default priority', function (string $hook) {
    global $wp_filter;

    $priorities = array_keys($wp_filter[$hook]->callbacks ?? []);
    $ours = array_filter($priorities, static fn(int $priority): bool => $priority === Integration::PRIORITY);

    expect($ours)->not->toBeEmpty()
        ->and(Integration::PRIORITY)->toBeLessThan(10);
})->with(['wp_authenticate_user', 'wp_login_failed', 'registration_errors', 'lostpassword_post', 'illegal_user_logins']);

it('gates authenticate after every handler, those of WordPress and of other plugins', function () {
    global $wp_filter;

    $login = gecka_security()->integration(\Gecka\WP\Plugin\Security\Integrations\Login::class);

    expect(has_filter('authenticate', [$login, 'gate']))->toBe(\Gecka\WP\Plugin\Security\Integrations\Login::GATE_PRIORITY)
        ->and(max(array_keys($wp_filter['authenticate']->callbacks)))->toBe(\Gecka\WP\Plugin\Security\Integrations\Login::GATE_PRIORITY);
});

it('refuses a locked-out address whatever a later handler returns', function () {
    security_settings(['max_failures' => 1]);
    from_ip('203.0.113.41');
    $user = static::factory()->user->create_and_get(['user_login' => 'sso-user']);
    wp_authenticate('sso-user', 'wrong');
    // A handler of a single sign-on plugin, at a priority past the default ones.
    add_filter('authenticate', static fn() => $user, 1000);

    $result = wp_authenticate('sso-user', 'anything');

    remove_all_filters('authenticate', 1000);
    gecka_security()->lockouts()->clear();
    from_ip('127.0.0.1');
    security_settings(['max_failures' => 5]);

    expect($result)->toBeInstanceOf(WP_Error::class)
        ->and($result->get_error_code())->toBe(\Gecka\WP\Plugin\Security\Integrations\Login::ERROR);
});

it('tells a REST request apart before WordPress names it', function () {
    $_GET['rest_route'] = '/wp/v2/users/me';
    expect(\Gecka\WP\Plugin\Security\Request::vector())->toBe(\Gecka\WP\Plugin\Security\Request::REST);
    unset($_GET['rest_route']);

    $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/users/me';
    expect(\Gecka\WP\Plugin\Security\Request::vector())->toBe(\Gecka\WP\Plugin\Security\Request::REST);

    $_SERVER['REQUEST_URI'] = '/wp-jsonish/';
    expect(\Gecka\WP\Plugin\Security\Request::vector())->toBe(\Gecka\WP\Plugin\Security\Request::OTHER);
    unset($_SERVER['REQUEST_URI']);
});

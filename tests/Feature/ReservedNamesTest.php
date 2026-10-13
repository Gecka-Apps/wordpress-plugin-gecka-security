<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

it('refuses a reserved name to a new account', function () {
    $result = wp_insert_user(['user_login' => 'root', 'user_pass' => 'x', 'user_email' => 'root@example.org']);

    expect($result)->toBeInstanceOf(WP_Error::class)
        ->and($result->get_error_code())->toBe('invalid_username')
        ->and(wp_insert_user(['user_login' => 'writer', 'user_pass' => 'x', 'user_email' => 'writer@example.org']))->toBeInt();
});

it('reads the list of the settings', function () {
    security_settings(['reserved_names' => ['batman']]);

    expect(wp_insert_user(['user_login' => 'batman', 'user_pass' => 'x', 'user_email' => 'batman@example.org']))->toBeInstanceOf(WP_Error::class)
        ->and(wp_insert_user(['user_login' => 'root', 'user_pass' => 'x', 'user_email' => 'root@example.org']))->toBeInt();
});

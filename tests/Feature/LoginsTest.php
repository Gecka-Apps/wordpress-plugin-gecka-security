<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Events;

beforeEach(function () {
    $this->events = gecka_security()->events();
    $this->events->clear();
});

it('records a successful login with the roles of the account', function () {
    $user = static::factory()->user->create_and_get(['role' => 'editor', 'user_login' => 'writer']);
    $this->events->clear();

    do_action('wp_login', 'writer', $user);

    $entries = $this->events->entries(1, 10);

    expect($entries)->toHaveCount(1)
        ->and($entries[0]->type)->toBe(Events::LOGIN)
        ->and($entries[0]->username)->toBe('writer')
        ->and($entries[0]->detail)->toBe('editor');
});

it('records a login made with an application password, named', function () {
    $user = static::factory()->user->create_and_get(['role' => 'administrator', 'user_login' => 'robot']);
    $this->events->clear();

    do_action('application_password_did_authenticate', $user, ['name' => 'Backup tool']);

    $entries = $this->events->entries(1, 10);

    expect($entries)->toHaveCount(1)
        ->and($entries[0]->type)->toBe(Events::LOGIN)
        ->and($entries[0]->detail)->toBe('login.application_password')
        ->and(Events::describe($entries[0]))->toBe('administrator · application password Backup tool');
});

it('folds the logins of one application password within the hour into one row', function () {
    $user = static::factory()->user->create_and_get(['role' => 'administrator', 'user_login' => 'poller']);
    $this->events->clear();

    foreach ([1, 2, 3] as $call) {
        do_action('application_password_did_authenticate', $user, ['name' => 'Poller']);
    }

    do_action('application_password_did_authenticate', $user, ['name' => 'Another']);

    $entries = $this->events->entries(1, 10);

    expect($entries)->toHaveCount(2)
        ->and((int) $entries[1]->hits)->toBe(3)
        ->and((int) $entries[0]->hits)->toBe(1);
});

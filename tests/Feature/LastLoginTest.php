<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Integrations\LastLogin;
use Gecka\WP\Plugin\Security\Privacy;

beforeEach(function () {
    $this->lastLogin = new LastLogin(gecka_security());
});

it('keeps the time of a login made with the password of the account', function () {
    $user = static::factory()->user->create_and_get(['user_login' => 'writer']);

    expect(LastLogin::time($user->ID))->toBe(0);

    $this->lastLogin->login('writer', $user);

    expect(LastLogin::time($user->ID))->toBeGreaterThanOrEqual(time() - 5);
});

it('hooks the login, and leaves the application passwords out', function () {
    $user = static::factory()->user->create_and_get(['user_login' => 'robot']);

    do_action('application_password_did_authenticate', $user, ['name' => 'Backup tool']);
    expect(LastLogin::time($user->ID))->toBe(0);

    do_action('wp_login', 'robot', $user);
    expect(LastLogin::time($user->ID))->toBeGreaterThan(0);
});

it('adds a sortable column to the users list', function () {
    expect($this->lastLogin->columns(['username' => 'Username']))->toBe(['username' => 'Username', LastLogin::COLUMN => 'Last login'])
        ->and($this->lastLogin->sortable([]))->toBe([LastLogin::COLUMN => [LastLogin::COLUMN, true]]);
});

it('shows the date of the last login, and a dash for an account with none', function () {
    $user = static::factory()->user->create_and_get();

    expect($this->lastLogin->cell('', LastLogin::COLUMN, $user->ID))->toContain('No login recorded')
        ->and($this->lastLogin->cell('other', 'posts', $user->ID))->toBe('other');

    update_user_meta($user->ID, LastLogin::META, 1767225600);

    expect($this->lastLogin->cell('', LastLogin::COLUMN, $user->ID))->toContain('datetime="2026-01-01T00:00:00+00:00"');
});

it('sorts the users on their last login, keeping those with none', function () {
    $old = static::factory()->user->create(['user_login' => 'sort_old']);
    $recent = static::factory()->user->create(['user_login' => 'sort_recent']);
    $never = static::factory()->user->create(['user_login' => 'sort_never']);
    update_user_meta($old, LastLogin::META, time() - DAY_IN_SECONDS);
    update_user_meta($recent, LastLogin::META, time());
    // A meta whose value would sort it first, were the join not on the key.
    update_user_meta($never, 'sort_noise', '9999999999');

    add_action('pre_user_query', [$this->lastLogin, 'order']);
    $ids = static fn(string $order): array => array_map('intval', (new WP_User_Query(['include' => [$old, $recent, $never], 'orderby' => LastLogin::COLUMN, 'order' => $order, 'fields' => 'ID']))->get_results());
    $desc = $ids('DESC');
    $asc = $ids('ASC');
    remove_action('pre_user_query', [$this->lastLogin, 'order']);

    expect($desc)->toBe([$recent, $old, $never])
        ->and($asc)->toBe([$never, $old, $recent]);
});

it('goes out with the export of the person and away with their erasure', function () {
    $user = static::factory()->user->create_and_get(['user_login' => 'reader', 'user_email' => 'reader@example.com']);
    update_user_meta($user->ID, LastLogin::META, time());
    $privacy = new Privacy(gecka_security());

    expect(array_column($privacy->export('reader@example.com')['data'], 'group_id'))->toContain('gecka-security-last-login');

    $privacy->erase('reader@example.com');

    expect(LastLogin::time($user->ID))->toBe(0);
});

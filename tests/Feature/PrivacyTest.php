<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Integrations\Pwned;
use Gecka\WP\Plugin\Security\Plugin;
use Gecka\WP\Plugin\Security\Privacy;

beforeEach(function () {
    $this->events = gecka_security()->events();
    $this->privacy = new Privacy(gecka_security());
    $this->user = static::factory()->user->create_and_get(['user_login' => 'writer', 'user_email' => 'writer@example.com']);
    $this->events->clear();
});

it('registers with the personal data tools of WordPress', function () {
    new Plugin(gecka_security()->file());

    expect(apply_filters('wp_privacy_personal_data_exporters', []))->toHaveKey('gecka-security')
        ->and(apply_filters('wp_privacy_personal_data_erasers', []))->toHaveKey('gecka-security');
});

it('exports the rows carrying the login or the e-mail address of a person, and nothing of the others', function () {
    $this->events->record(Events::FAILED, '203.0.113.7', 'Writer', 'login_form', 'incorrect_password');
    $this->events->record(Events::LOGIN, '203.0.113.5', 'writer@example.com', 'login_form', 'editor');
    $this->events->record(Events::FAILED, '203.0.113.6', 'someone', 'login_form');
    $this->events->record(Events::LOCKOUT, '203.0.113.6', '', 'login_form');

    $export = $this->privacy->export('writer@example.com');

    expect($export['done'])->toBeTrue()
        ->and($export['data'])->toHaveCount(2)
        ->and($export['data'][0]['group_id'])->toBe('gecka-security')
        ->and(array_column($export['data'][0]['data'], 'value', 'name'))->toMatchArray(['Event' => 'Successful login', 'Login' => 'writer@example.com', 'Address' => '203.0.113.5', 'Detail' => 'editor'])
        ->and(array_column($export['data'][1]['data'], 'value', 'name'))->toMatchArray(['Event' => 'Failed login', 'Login' => 'Writer'])
        ->and(array_column($export['data'][1]['data'], 'name'))->not->toContain('Address')
        ->and($this->privacy->export('nobody@example.com')['data'])->toBe([]);
});

it('erases the rows of a person and the verdict on their password, keeping the rest', function () {
    $this->events->record(Events::FAILED, '203.0.113.5', 'WRITER', 'login_form');
    $this->events->record(Events::LOGIN, '203.0.113.5', 'Writer@Example.com', 'login_form');
    $this->events->record(Events::FAILED, '203.0.113.6', 'someone', 'login_form');
    update_user_meta($this->user->ID, Pwned::META, ['hash' => 'x', 'pwned' => 3, 'checked' => time()]);

    $result = $this->privacy->erase('writer@example.com');

    expect($result['items_removed'])->toBe(3)
        ->and($result['done'])->toBeTrue()
        ->and($this->events->count())->toBe(1)
        ->and(get_user_meta($this->user->ID, Pwned::META, true))->toBe('');
});

it('takes the person out of the changes they made on other accounts, keeping those rows', function () {
    $this->events->record(Events::ACCOUNT, '203.0.113.5', 'someone', 'other', 'account.role_set', ['role' => 'editor', 'old' => ['author'], 'actor' => $this->user->user_login]);
    $this->events->record(Events::ACCOUNT, '203.0.113.5', 'someone', 'other', 'account.password', ['actor' => 'boss']);

    $result = $this->privacy->erase('writer@example.com');
    $rows = $this->events->entries(1, 10, ['username' => ['someone']]);

    expect($result['items_removed'])->toBe(1)
        ->and($rows)->toHaveCount(2)
        ->and(\Gecka\WP\Plugin\Security\Events::describe($rows[1]))->toContain('an account whose data was erased')
        ->and(\Gecka\WP\Plugin\Security\Events::describe($rows[0]))->toContain('boss');
});

it('leaves the person who changed an account out of the export', function () {
    $this->events->record(Events::ACCOUNT, '203.0.113.5', 'writer', 'other', 'account.role_set', ['role' => 'editor', 'old' => ['author'], 'actor' => 'boss']);

    $export = $this->privacy->export('writer@example.com');
    $details = array_column($export['data'][0]['data'], 'value', 'name');

    expect($details['Detail'])->toBe('role editor set in place of author')
        ->and(Events::describe($this->events->entries(1, 1)[0]))->toBe('role editor set in place of author by boss');
});

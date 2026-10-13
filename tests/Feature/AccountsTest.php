<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Events;

beforeEach(function () {
    $this->events = gecka_security()->events();
    $this->events->clear();
    $this->mails = [];
    // WordPress mails on its own about an address or a password changed: only the alerts are kept.
    add_filter('pre_wp_mail', function ($pre, $atts) {
        if (str_contains((string) ($atts['subject'] ?? ''), 'New administrator')) {
            $this->mails[] = $atts;
        }

        return true;
    }, 10, 2);
    wp_set_current_user(static::factory()->user->create(['role' => 'administrator', 'user_login' => 'boss']));
    $this->events->clear();
    // The creation of boss, an administrator, alerted too.
    $this->mails = [];
});

afterEach(function () {
    remove_all_filters('pre_wp_mail');
});

it('notes a created account with its role and who did it, and mails a new administrator', function () {
    static::factory()->user->create(['role' => 'editor', 'user_login' => 'writer']);
    static::factory()->user->create(['role' => 'administrator', 'user_login' => 'second']);

    $rows = $this->events->entries(1, 10, ['type' => Events::ACCOUNT]);
    $details = array_combine(array_column($rows, 'username'), array_map([Events::class, 'describe'], $rows));

    expect($details)->toBe(['second' => 'created with the administrator role by boss', 'writer' => 'created with the editor role by boss'])
        ->and($rows[0]->detail)->toBe('account.created')
        ->and(json_decode($rows[0]->params, true))->toBe(['roles' => ['administrator'], 'actor' => 'boss'])
        ->and($this->mails)->toHaveCount(1)
        ->and($this->mails[0]['subject'])->toContain('New administrator: second')
        ->and($this->mails[0]['message'])->toContain('was created as administrator by boss');
});

it('notes a promotion, a demotion, an e-mail address and a password changed, and a deletion', function () {
    require_once ABSPATH . 'wp-admin/includes/user.php';
    $id = static::factory()->user->create(['role' => 'editor', 'user_login' => 'writer', 'user_email' => 'writer@example.com']);
    $this->events->clear();

    $user = get_user_by('id', $id);
    $user->set_role('administrator');
    $user->add_role('editor');
    $user->remove_role('editor');
    wp_update_user(['ID' => $id, 'user_email' => 'new@example.com']);
    wp_set_password('correct horse battery staple', $id);
    wp_update_user(['ID' => $id, 'user_pass' => 'another correct horse']);
    wp_delete_user($id);

    $rows = array_reverse($this->events->entries(1, 20, ['type' => Events::ACCOUNT]));
    $details = array_map([Events::class, 'describe'], $rows);

    expect(array_column($rows, 'detail'))->toBe(['account.role_set', 'account.role_added', 'account.role_removed', 'account.email', 'account.password', 'account.deleted'])
        ->and($details)->toBe([
            'role administrator set in place of editor by boss',
            'role editor added by boss',
            'role editor removed by boss',
            'e-mail address changed from writer@example.com to new@example.com by boss',
            'password changed by boss',
            'deleted by boss',
        ])
        ->and($this->mails)->toHaveCount(1)
        ->and($this->mails[0]['message'])->toContain('was made administrator by boss');
});

it('notes nothing and mails nobody when switched off', function () {
    $id = static::factory()->user->create(['role' => 'administrator']);
    security_settings(['log_accounts' => false, 'alert_admins' => false]);
    (new \Gecka\WP\Plugin\Security\Integrations\Accounts(gecka_security()))->registered($id);
    security_settings(['log_accounts' => true, 'alert_admins' => true]);

    expect($this->events->count(['type' => Events::ACCOUNT]))->toBe(1)
        ->and($this->mails)->toHaveCount(1);
});

it('holds the roles added or removed until the request ends', function () {
    $id = static::factory()->user->create(['role' => 'editor', 'user_login' => 'writer']);
    $this->events->clear();

    get_user_by('id', $id)->add_role('author');

    expect($this->events->count(['type' => Events::ACCOUNT]))->toBe(0);

    $accounts = new \Gecka\WP\Plugin\Security\Integrations\Accounts(gecka_security());
    $accounts->flush();

    expect(array_map([Events::class, 'describe'], $this->events->entries(1, 5, ['type' => Events::ACCOUNT])))->toBe(['role author added by boss'])
        ->and($this->mails)->toHaveCount(0);

    get_user_by('id', $id)->add_role('administrator');
    $accounts->flush();

    expect($this->mails)->toHaveCount(1)
        ->and($this->mails[0]['message'])->toContain('was made administrator by boss');
});

it('notes and alerts when an account with no role is made administrator', function () {
    $id = static::factory()->user->create(['role' => '', 'user_login' => 'ghost']);
    $this->events->clear();
    $this->mails = [];

    get_user_by('id', $id)->set_role('administrator');
    (new \Gecka\WP\Plugin\Security\Integrations\Accounts(gecka_security()))->flush();

    expect(array_map([Events::class, 'describe'], $this->events->entries(1, 5, ['type' => Events::ACCOUNT])))->toBe(['role administrator set, the account having none by boss'])
        ->and($this->mails)->toHaveCount(1)
        ->and($this->mails[0]['subject'])->toContain('ghost');
});

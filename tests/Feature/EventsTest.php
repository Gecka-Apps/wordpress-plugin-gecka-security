<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Events;

beforeEach(function () {
    $this->events = gecka_security()->events();
    $this->events->clear();
    gecka_security()->stats()->reset();
});

it('records, lists, counts and filters the events', function () {
    $this->events->record(Events::FAILED, '203.0.113.5', 'editor', 'login_form', 'incorrect_password');
    $this->events->record(Events::FAILED, '203.0.113.6', 'editor', 'xmlrpc');
    $this->events->record(Events::LOCKOUT, '203.0.113.5', 'editor', 'login_form');

    expect($this->events->count())->toBe(3)
        ->and($this->events->count(['ip' => '203.0.113.5']))->toBe(2)
        ->and($this->events->count(['type' => Events::LOCKOUT]))->toBe(1)
        ->and($this->events->countsByType(['ip' => '203.0.113.5']))->toBe([Events::FAILED => 1, Events::LOCKOUT => 1])
        ->and(array_column($this->events->entries(1, 10), 'type'))->toBe([Events::LOCKOUT, Events::FAILED, Events::FAILED])
        ->and($this->events->entries(2, 2))->toHaveCount(1);
});

it('deletes events and purges the old ones', function () {
    global $wpdb;

    $this->events->record(Events::FAILED, '203.0.113.5');
    $this->events->record(Events::FAILED, '203.0.113.5');
    $ids = array_column($this->events->entries(1, 10), 'id');

    $this->events->delete([(int) $ids[0]]);
    expect($this->events->count())->toBe(1);

    $wpdb->update(Events::table(), ['created' => gmdate('Y-m-d H:i:s', time() - 40 * DAY_IN_SECONDS)], ['id' => (int) $ids[1]]);
    $this->events->purge(30);
    expect($this->events->count())->toBe(0);
});

it('keeps daily counters by way in and by kind', function () {
    $stats = gecka_security()->stats();

    $stats->record('login_form', Events::FAILED);
    $stats->record('login_form', Events::FAILED);
    $stats->record('xmlrpc', Events::LOCKOUT);

    $totals = $stats->totals(7);
    $daily = $stats->daily(7);

    expect($totals['login_form'][Events::FAILED])->toBe(2)
        ->and($totals['xmlrpc'][Events::LOCKOUT])->toBe(1)
        ->and(\Gecka\WP\Plugin\Security\Stats::byType($totals))->toBe([Events::FAILED => 2, Events::LOCKOUT => 1])
        ->and($daily)->toHaveCount(7)
        ->and(end($daily))->toEqual(['login_form' => [Events::FAILED => 2], 'xmlrpc' => [Events::LOCKOUT => 1]])
        ->and(array_values(\Gecka\WP\Plugin\Security\Stats::byDay($daily))[6])->toBe([Events::FAILED => 2, Events::LOCKOUT => 1])
        ->and(array_values(\Gecka\WP\Plugin\Security\Stats::byWay($daily, 'xmlrpc'))[6])->toBe([Events::LOCKOUT => 1])
        ->and(array_values(\Gecka\WP\Plugin\Security\Stats::byWay($daily, 'rest'))[6])->toBe([]);
});

it('counts the days in the time zone of the site', function () {
    update_option('timezone_string', 'Pacific/Noumea');

    $today = (new DateTimeImmutable('now', new DateTimeZone('Pacific/Noumea')))->format('Y-m-d');
    gecka_security()->stats()->record('login_form', Events::FAILED);
    $daily = gecka_security()->stats()->daily(2);

    update_option('timezone_string', '');

    expect(array_key_last($daily))->toBe($today)
        ->and(end($daily))->toBe(['login_form' => [Events::FAILED => 1]]);
});

it('cuts the weeks of a long period back from today, the last bar a whole week', function () {
    $daily = [];

    for ($i = 365; $i >= 0; $i--) {
        $daily[(new DateTimeImmutable('today'))->modify("-$i days")->format('Y-m-d')] = [Events::FAILED => 1];
    }

    $buckets = (new ReflectionMethod(\Gecka\WP\Plugin\Security\Admin\StatsView::class, 'buckets'))->invoke(null, $daily, true);

    expect(end($buckets)['failures'])->toBe(7)
        ->and(array_sum(array_column($buckets, 'failures')))->toBe(366)
        ->and(array_key_last($buckets))->toBe((new DateTimeImmutable('today'))->modify('-6 days')->format('Y-m-d'));
});

it('folds the refusals of one lockout into one row, counted', function () {
    $this->events->record(Events::LOCKOUT, '203.0.113.5', 'editor', 'login_form');

    expect($this->events->bump(Events::BLOCKED, '203.0.113.5', Events::LOCKOUT))->toBeFalse();

    $this->events->record(Events::BLOCKED, '203.0.113.5', 'editor', 'login_form');

    expect($this->events->bump(Events::BLOCKED, '203.0.113.5', Events::LOCKOUT))->toBeTrue()
        ->and((int) $this->events->entries(1, 1)[0]->hits)->toBe(2)
        ->and($this->events->entries(1, 1)[0]->last)->toMatch('/^\d{4}-\d{2}-\d{2} /')
        ->and($this->events->entries(1, 2)[1]->last)->toBeNull()
        ->and($this->events->count())->toBe(2);

    $this->events->record(Events::LOCKOUT, '203.0.113.5', 'editor', 'login_form');

    expect($this->events->bump(Events::BLOCKED, '203.0.113.5', Events::LOCKOUT))->toBeFalse();
});

it('folds the refusals of one IPv6 /64 together, the row keeping the address of the first', function () {
    $this->events->record(Events::LOCKOUT, '2001:db8:1::1', 'editor', 'login_form');
    $this->events->record(Events::BLOCKED, '2001:db8:1::2', 'editor', 'login_form');

    expect($this->events->bump(Events::BLOCKED, '2001:db8:1::3', Events::LOCKOUT))->toBeTrue()
        ->and($this->events->bump(Events::BLOCKED, '2001:db8:2::3', Events::LOCKOUT))->toBeFalse()
        ->and($this->events->entries(1, 1, ['ip' => '2001:db8:1::2'])[0]->hits)->toBe('2');
});

it('words a detail from its code and its parameters, the rest as recorded', function () {
    $this->events->record(Events::LOCKOUT, '203.0.113.5', 'editor', 'login_form', 'lockout.long');
    $this->events->record(Events::BREACHED, '203.0.113.5', 'editor', 'login_form', 'breached.seen', ['count' => 12345]);
    $this->events->record(Events::FAILED, '203.0.113.5', 'editor', 'login_form', 'incorrect_password');
    $this->events->record(Events::ACCOUNT, '203.0.113.5', 'editor', 'other', 'account.deleted', ['actor' => '']);
    $this->events->record(Events::ACCOUNT, '203.0.113.5', 'editor', 'other', 'account.password', ['actor' => \Gecka\WP\Plugin\Security\Integrations\Accounts::CLI]);

    expect(array_map([Events::class, 'describe'], $this->events->entries(1, 5)))->toBe([
        'password changed by WP-CLI',
        'deleted by nobody logged in',
        'incorrect_password',
        'seen 12,345 times in breaches',
        'long lockout',
    ]);
});

it('caps each kind of event on its own', function () {
    add_filter('gecka_security_max_entries', static fn(): int => 50);

    for ($i = 0; $i < 120; $i++) {
        $this->events->record(Events::FAILED, '203.0.113.5');
    }

    for ($i = 0; $i < 10; $i++) {
        $this->events->record(Events::LOCKOUT, '203.0.113.5');
    }

    remove_all_filters('gecka_security_max_entries');

    expect($this->events->count(['type' => Events::FAILED]))->toBeLessThan(120)
        ->and($this->events->count(['type' => Events::LOCKOUT]))->toBe(10);
});

it('finds the events of an IPv6 /64 from the key a lockout carries', function () {
    $this->events->record(Events::FAILED, '2001:db8:1:2::a', 'editor', 'login_form');
    $this->events->record(Events::FAILED, '2001:db8:1:2::b', 'editor', 'login_form');
    $this->events->record(Events::FAILED, '2001:db8:1:3::a', 'editor', 'login_form');

    expect($this->events->count(['net' => '2001:db8:1:2::/64']))->toBe(2);
});

it('matches a login longer than its column as the column keeps it', function () {
    $long = str_repeat('a', 70) . '@example.com';
    $this->events->record(Events::FAILED, '203.0.113.5', $long, 'login_form');

    expect($this->events->count(['username' => [strtoupper($long)]]))->toBe(1)
        ->and($this->events->deleteByLogin([$long]))->toBe(1);
});

it('lists the logins seen most, and filters on one whatever its case', function () {
    $this->events->record(Events::FAILED, '203.0.113.5', 'editor', 'login_form');
    $this->events->record(Events::FAILED, '203.0.113.5', 'Editor', 'login_form');
    $this->events->record(Events::LOGIN, '203.0.113.6', 'admin', 'login_form');
    $this->events->record(Events::LOCKOUT, '203.0.113.5', '', 'login_form');

    expect($this->events->logins())->toBe(['editor' => 2, 'admin' => 1])
        ->and($this->events->count(['username' => ['EDITOR']]))->toBe(2)
        ->and($this->events->countsByType(['username' => ['admin']]))->toBe([Events::LOGIN => 1]);
});

it('reads the filters of the journal: a kind, a login picked, an address or a login searched', function () {
    $_GET = ['type' => Events::FAILED, 'user' => 'editor'];
    expect(\Gecka\WP\Plugin\Security\Admin\EventsView::filters())->toBe(['type' => Events::FAILED, 'username' => ['editor']]);

    $_GET = ['s' => '203.0.113.5'];
    expect(\Gecka\WP\Plugin\Security\Admin\EventsView::filters())->toBe(['ip' => '203.0.113.5']);

    $_GET = ['s' => '2001:db8:1:2::/64'];
    expect(\Gecka\WP\Plugin\Security\Admin\EventsView::filters())->toBe(['net' => '2001:db8:1:2::/64']);

    $_GET = ['s' => 'someone@example.com'];
    expect(\Gecka\WP\Plugin\Security\Admin\EventsView::filters())->toBe(['username' => ['someone@example.com']])
        ->and(\Gecka\WP\Plugin\Security\Admin\EventsView::args(['type' => 'failed', 'ip' => '1.2.3.4', 'username' => ['x']]))->toBe(['type' => 'failed', 's' => '1.2.3.4', 'user' => 'x']);

    $_GET = [];
});

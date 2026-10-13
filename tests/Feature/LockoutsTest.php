<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Lockouts;

beforeEach(function () {
    security_settings(['max_failures' => 3, 'lockout_minutes' => 20, 'max_lockouts' => 2, 'long_lockout_hours' => 24]);
    $this->lockouts = gecka_security()->lockouts();
    $this->lockouts->clear();
});

it('locks an address out at the maximum of failures and counts from zero after', function () {
    expect($this->lockouts->fail('203.0.113.5'))->toBeNull()
        ->and($this->lockouts->fail('203.0.113.5'))->toBeNull()
        ->and($this->lockouts->remaining('203.0.113.5'))->toBe(0);

    $lockout = $this->lockouts->fail('203.0.113.5');

    expect($lockout)->toBeArray()
        ->and($lockout['long'])->toBeFalse()
        ->and($lockout['until'])->toBeGreaterThan(time() + 19 * MINUTE_IN_SECONDS)
        ->and($this->lockouts->remaining('203.0.113.5'))->toBeGreaterThan(19 * MINUTE_IN_SECONDS)
        ->and((int) $this->lockouts->row('203.0.113.5')->failures)->toBe(0)
        ->and($this->lockouts->countActive())->toBe(1);
});

it('weighs a failure', function () {
    expect($this->lockouts->fail('203.0.113.5', 2))->toBeNull()
        ->and($this->lockouts->fail('203.0.113.5', 2))->toBeArray();
});

it('gives the long lockout once the lockouts reach their maximum, then starts over', function () {
    $ip = '203.0.113.5';

    for ($i = 0; $i < 3; $i++) {
        $lockout = $this->lockouts->fail($ip);
    }

    expect($lockout['long'])->toBeFalse();
    lockout_over($ip);

    for ($i = 0; $i < 3; $i++) {
        $lockout = $this->lockouts->fail($ip);
    }

    expect($lockout['long'])->toBeTrue()
        ->and($lockout['until'])->toBeGreaterThan(time() + 23 * HOUR_IN_SECONDS)
        ->and((int) $this->lockouts->row($ip)->lockouts)->toBe(0);
});

it('never shortens a lockout in place, whatever fails meanwhile', function () {
    $ip = '203.0.113.5';

    for ($i = 0; $i < 3; $i++) {
        $this->lockouts->fail($ip);
    }

    lockout_over($ip);

    for ($i = 0; $i < 3; $i++) {
        $long = $this->lockouts->fail($ip);
    }

    $until = $long['until'];

    for ($i = 0; $i < 6; $i++) {
        expect($this->lockouts->fail($ip))->toBeNull();
    }

    expect($this->lockouts->remaining($ip))->toBeGreaterThan($until - time() - 5);
});

it('forgets failures older than the window', function () {
    global $wpdb;

    $this->lockouts->fail('203.0.113.5');
    $this->lockouts->fail('203.0.113.5');
    $wpdb->update(Lockouts::table(), ['first_failure' => gmdate('Y-m-d H:i:s', time() - 2 * HOUR_IN_SECONDS)], ['ip' => '203.0.113.5']);

    expect($this->lockouts->fail('203.0.113.5'))->toBeNull();
});

it('releases addresses, one by one or all at once', function () {
    foreach (['203.0.113.5', '203.0.113.6'] as $ip) {
        for ($i = 0; $i < 3; $i++) {
            $this->lockouts->fail($ip);
        }
    }

    expect($this->lockouts->countActive())->toBe(2)
        ->and($this->lockouts->unlock(['203.0.113.5', '203.0.113.9']))->toBe(1)
        ->and($this->lockouts->remaining('203.0.113.5'))->toBe(0)
        ->and($this->lockouts->countActive())->toBe(1);

    $this->lockouts->clear();

    expect($this->lockouts->countActive())->toBe(0);
});

it('lists the addresses locked out and purges the idle ones', function () {
    global $wpdb;

    for ($i = 0; $i < 3; $i++) {
        $this->lockouts->fail('203.0.113.5');
    }

    $this->lockouts->fail('203.0.113.6');

    expect(array_column($this->lockouts->active(1, 10), 'ip'))->toBe(['203.0.113.5']);

    $wpdb->update(Lockouts::table(), ['updated' => gmdate('Y-m-d H:i:s', time() - 3 * DAY_IN_SECONDS)], ['ip' => '203.0.113.6']);
    $this->lockouts->purge();

    expect($this->lockouts->row('203.0.113.6'))->toBeNull()
        ->and($this->lockouts->row('203.0.113.5'))->not->toBeNull();
});

/**
 * Ends the lockout of an address, as time would.
 *
 * @param string $ip Key of the address.
 *
 * @return void
 */
function lockout_over(string $ip): void
{
    global $wpdb;

    $wpdb->update(Lockouts::table(), ['locked_until' => gmdate('Y-m-d H:i:s', time() - 1)], ['ip' => $ip]);
}

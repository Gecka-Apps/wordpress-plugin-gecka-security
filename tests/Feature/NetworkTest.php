<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Network;

it('normalizes addresses and drops what is not one', function () {
    expect(Network::normalize(' 203.0.113.5 '))->toBe('203.0.113.5')
        ->and(Network::normalize('2001:DB8:0:0:0:0:0:1'))->toBe('2001:db8::1')
        ->and(Network::normalize('::ffff:203.0.113.5'))->toBe('203.0.113.5')
        ->and(Network::normalize('203.0.113.5:443'))->toBe('203.0.113.5')
        ->and(Network::normalize('[2001:db8::1]:443'))->toBe('2001:db8::1')
        ->and(Network::normalize('fe80::1%eth0'))->toBe('fe80::1')
        ->and(Network::normalize('not an address'))->toBeNull()
        ->and(Network::normalize(''))->toBeNull();
});

it('tells the addresses a local proxy gives everyone from usable ones', function () {
    expect(Network::isUsable('127.0.0.1'))->toBeFalse()
        ->and(Network::isUsable('::1'))->toBeFalse()
        ->and(Network::isUsable(''))->toBeFalse()
        ->and(Network::isUsable('10.0.0.8'))->toBeTrue()
        ->and(Network::isUsable('203.0.113.5'))->toBeTrue();
});

it('matches an address against an address or a network', function () {
    expect(Network::matches('203.0.113.5', '203.0.113.5'))->toBeTrue()
        ->and(Network::matches('203.0.113.5', '203.0.113.0/24'))->toBeTrue()
        ->and(Network::matches('203.0.114.5', '203.0.113.0/24'))->toBeFalse()
        ->and(Network::matches('203.0.113.5', '203.0.113.0/31'))->toBeFalse()
        ->and(Network::matches('2001:db8:1::1', '2001:db8::/32'))->toBeTrue()
        ->and(Network::matches('2001:db9::1', '2001:db8::/32'))->toBeFalse()
        ->and(Network::matches('203.0.113.5', '2001:db8::/32'))->toBeFalse()
        ->and(Network::matches('203.0.113.5', '203.0.113.0/33'))->toBeFalse()
        ->and(Network::matches('203.0.113.5', 'junk'))->toBeFalse();
});

it('watches an IPv6 address as its /64 and an IPv4 one as itself', function () {
    expect(Network::key('203.0.113.5'))->toBe('203.0.113.5')
        ->and(Network::key('2001:db8:1:2:3:4:5:6'))->toBe('2001:db8:1:2::/64')
        ->and(Network::key('2001:db8:1:2:ffff::1'))->toBe('2001:db8:1:2::/64');
});

it('tells a private address from a public one', function () {
    expect(Network::isPrivate('10.1.2.3'))->toBeTrue()
        ->and(Network::isPrivate('172.31.255.1'))->toBeTrue()
        ->and(Network::isPrivate('192.168.0.9'))->toBeTrue()
        ->and(Network::isPrivate('fd12::1'))->toBeTrue()
        ->and(Network::isPrivate('172.32.0.1'))->toBeFalse()
        ->and(Network::isPrivate('203.0.113.5'))->toBeFalse()
        ->and(Network::isPrivate('2001:db8::1'))->toBeFalse();
});

it('reads a list of addresses and networks, leaving the ill-formed out', function () {
    expect(Network::parseList("203.0.113.5\n2001:db8::/32, 10.0.0.0/8\njunk\n203.0.113.5\n203.0.113.0/40"))
        ->toBe(['203.0.113.5', '2001:db8::/32', '10.0.0.0/8']);

    expect(Network::tooWide('0.0.0.0/0'))->toBeTrue()
        ->and(Network::tooWide('128.0.0.0/1'))->toBeTrue()
        ->and(Network::tooWide('8000::/1'))->toBeTrue()
        ->and(Network::tooWide('10.0.0.0/8'))->toBeFalse()
        ->and(Network::tooWide('2001:db8::/32'))->toBeFalse()
        ->and(Network::tooWide('203.0.113.5'))->toBeFalse()
        ->and(Network::withoutTooWide(['0.0.0.0/1', '128.0.0.0/1', '10.0.0.0/8']))->toBe(['10.0.0.0/8']);
});

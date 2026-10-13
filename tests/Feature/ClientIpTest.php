<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

afterEach(function () {
    unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_REAL_IP']);
    from_ip('127.0.0.1');
});

it('takes the address the server saw by default, whatever the headers say', function () {
    from_ip('203.0.113.5');
    $_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.7';

    expect(gecka_security()->clientIp()->get())->toBe('203.0.113.5')
        ->and(gecka_security()->clientIp()->reliable())->toBeTrue();
});

it('reads the header only from a trusted proxy', function () {
    security_settings(['ip_source' => 'x_forwarded_for', 'trusted_proxies' => ['10.0.0.0/8']]);
    $_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.7';

    from_ip('203.0.113.5');
    expect(gecka_security()->clientIp()->get())->toBe('203.0.113.5');

    from_ip('10.0.0.8');
    expect(gecka_security()->clientIp()->get())->toBe('198.51.100.7');
});

it('reads X-Forwarded-For from the end, past the trusted hops', function () {
    security_settings(['ip_source' => 'x_forwarded_for', 'trusted_proxies' => ['10.0.0.0/8']]);
    $_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, 198.51.100.7, 10.0.0.9';

    from_ip('10.0.0.8');

    expect(gecka_security()->clientIp()->get())->toBe('198.51.100.7');
});

it('has no usable address behind a trusted proxy that sends no header', function () {
    security_settings(['ip_source' => 'x_real_ip', 'trusted_proxies' => ['127.0.0.1']]);

    from_ip('127.0.0.1');

    expect(gecka_security()->clientIp()->get())->toBe('')
        ->and(gecka_security()->clientIp()->reliable())->toBeFalse();

    $_SERVER['HTTP_X_REAL_IP'] = '198.51.100.7';
    gecka_security()->flush();

    expect(gecka_security()->clientIp()->get())->toBe('198.51.100.7');
});

it('is never reliable on the loopback', function () {
    from_ip('127.0.0.1');

    expect(gecka_security()->clientIp()->reliable())->toBeFalse();
});

it('tells a private address behind which every visitor hides, unless a proxy is trusted', function () {
    from_ip('192.168.1.20');
    expect(gecka_security()->clientIp()->behindProxy())->toBeTrue();

    security_settings(['trusted_proxies' => ['192.168.1.20']]);
    gecka_security()->flush();
    expect(gecka_security()->clientIp()->behindProxy())->toBeFalse();

    security_settings(['trusted_proxies' => []]);
    from_ip('203.0.113.5');
    expect(gecka_security()->clientIp()->behindProxy())->toBeFalse();
});

it('tells an address on the safelist', function () {
    security_settings(['safelist' => ['203.0.113.0/24']]);

    from_ip('203.0.113.5');
    expect(gecka_security()->clientIp()->safelisted())->toBeTrue();

    from_ip('198.51.100.7');
    expect(gecka_security()->clientIp()->safelisted())->toBeFalse();
});

it('never locks out the addresses GECKA_SECURITY_SAFELIST names', function () {
    define('GECKA_SECURITY_SAFELIST', '198.51.100.0/24, 2001:db8:1::/48');
    security_settings(['safelist' => []]);

    from_ip('198.51.100.7');
    expect(gecka_security()->clientIp()->safelisted())->toBeTrue();

    from_ip('203.0.113.5');
    expect(gecka_security()->clientIp()->safelisted())->toBeFalse();

    from_ip('127.0.0.1');
});

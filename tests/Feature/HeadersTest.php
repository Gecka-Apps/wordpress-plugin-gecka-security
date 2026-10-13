<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Integrations\Headers;
use Gecka\WP\Plugin\Security\Integrations\Integration;

it('lists the security headers, HSTS over HTTPS only and when asked', function () {
    expect(array_keys(Headers::list(true, false, true)))->toBe(['X-Content-Type-Options', 'Referrer-Policy', 'X-Frame-Options', 'Content-Security-Policy'])
        ->and(Headers::list(true, true, false))->not->toHaveKey('Strict-Transport-Security')
        ->and(Headers::list(true, true, true)['Strict-Transport-Security'])->toBe('max-age=15552000')
        ->and(Headers::list(false, true, true))->toBe(['Strict-Transport-Security' => 'max-age=15552000'])
        ->and(Headers::list(false, false, true))->toBe([]);
});

it('sends them on the front, the admin and the login screen', function (string $hook) {
    expect(has_action($hook, [gecka_security()->integration(Headers::class), 'send']))->toBe(Integration::PRIORITY);
})->with(['send_headers', 'admin_init', 'login_init']);

it('leaves the frames of an embed to the other sites, and the headers sent already alone', function () {
    $wanted = Headers::list(true, true, true);

    expect(array_keys(Headers::toSend($wanted, [], true)))->toBe(['X-Content-Type-Options', 'Referrer-Policy', 'Strict-Transport-Security'])
        ->and(array_keys(Headers::toSend($wanted, ['strict-transport-security', 'X-FRAME-OPTIONS'], false)))->toBe(['X-Content-Type-Options', 'Referrer-Policy', 'Content-Security-Policy']);
});

it('holds the frames back for an embed asked until the query tells it renders one', function () {
    if (headers_sent()) {
        $this->markTestSkipped('The runner has sent its output already.');
    }

    $headers = new Headers(gecka_security());
    $wp = new \WP();
    $wp->query_vars = ['embed' => '1'];

    $headers->send($wp);
    $held = has_action('template_redirect', [$headers, 'frames']);
    remove_action('template_redirect', [$headers, 'frames'], Integration::PRIORITY);

    $wp->query_vars = [];
    $headers->send($wp);

    expect($held)->toBe(Integration::PRIORITY)
        ->and(has_action('template_redirect', [$headers, 'frames']))->toBeFalse();
});

it('records the headers the server sends on its own, asked of the home page without its own', function () {
    $asked = '';
    $recognised = null;
    add_filter('pre_http_request', function ($pre, $args, $url) use (&$asked, &$recognised) {
        $asked = $url;
        // The request under way carries the token the transient holds: a page served then sees the probe.
        $_GET[Headers::PROBE] = (string) Scope::transient(Headers::PROBE_TOKEN);
        $recognised = Headers::isProbe();

        return ['response' => ['code' => 200], 'headers' => ['strict-transport-security' => 'max-age=1', 'x-frame-options' => 'DENY', 'content-type' => 'text/html', strtolower(Headers::PROOF) => $_GET[Headers::PROBE]], 'body' => ''];
    }, 10, 3);

    expect(Headers::probe())->toBe(['x-frame-options', 'strict-transport-security'])
        ->and(Headers::server())->toBe(['x-frame-options', 'strict-transport-security'])
        ->and($asked)->toContain(Headers::PROBE . '=')
        ->and($recognised)->toBeTrue()
        // Once the probe is over, the same token opens nothing, nor does a made-up one.
        ->and(Headers::isProbe())->toBeFalse();

    $_GET[Headers::PROBE] = '1';
    expect(Headers::isProbe())->toBeFalse();
    unset($_GET[Headers::PROBE]);

    remove_all_filters('pre_http_request');
    add_filter('pre_http_request', static fn() => new WP_Error('http_request_failed', 'down'));

    expect(Headers::probe())->toBeNull()
        ->and(Headers::server())->toBe(['x-frame-options', 'strict-transport-security']);

    remove_all_filters('pre_http_request');
    Scope::deleteOption(Headers::SERVER_OPTION);
});

it('ignores a response that does not carry the token of the probe back, its headers being maybe its own', function () {
    unset($_GET[Headers::PROBE]);
    add_filter('pre_http_request', static fn() => ['response' => ['code' => 200], 'headers' => ['x-frame-options' => 'SAMEORIGIN', strtolower(Headers::PROOF) => 'stale'], 'body' => '']);

    expect(Headers::probe())->toBeNull()
        ->and(Headers::server())->toBe([]);

    security_settings(['security_headers' => false, 'hsts' => false]);

    expect(Headers::probe())->toBe(['x-frame-options']);

    remove_all_filters('pre_http_request');
    Scope::deleteOption(Headers::SERVER_OPTION);
    security_settings(['security_headers' => true, 'hsts' => false]);
});

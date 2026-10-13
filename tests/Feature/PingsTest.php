<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Integrations\Integration;
use Gecka\WP\Plugin\Security\Integrations\Pings;

it('refuses pingbacks and trackbacks by default', function () {
    $settings = gecka_security()->settings()->all();

    expect($settings['pingback_disabled'])->toBeTrue()
        ->and($settings['trackback_disabled'])->toBeTrue();
});

it('takes the pingback methods out of XML-RPC, with the header announcing them', function () {
    $pings = new Pings(gecka_security());

    expect($pings->dropPingback(['pingback.ping' => 'this:pingback_ping', 'pingback.extensions.getPingbacks' => 'this:pingback_extensions_getPingbacks', 'wp.getPosts' => 'this:wp_getPosts']))->toBe(['wp.getPosts' => 'this:wp_getPosts'])
        ->and($pings->dropPingbackHeader(['X-Pingback' => 'https://example.com/xmlrpc.php', 'Content-Type' => 'text/html']))->toBe(['Content-Type' => 'text/html'])
        ->and($pings->dropPingback(false))->toBeFalse();
});

it('hooks the refusals ahead of the default priority', function (string $hook) {
    global $wp_filter;

    expect(array_keys($wp_filter[$hook]->callbacks ?? []))->toContain(Integration::PRIORITY);
})->with(['xmlrpc_methods', 'wp_headers', 'pre_trackback_post']);

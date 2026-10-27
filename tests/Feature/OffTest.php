<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Integrations\Editor;
use Gecka\WP\Plugin\Security\Integrations\Enumeration;
use Gecka\WP\Plugin\Security\Integrations\Headers;
use Gecka\WP\Plugin\Security\Integrations\LastLogin;
use Gecka\WP\Plugin\Security\Integrations\Login;
use Gecka\WP\Plugin\Security\Integrations\LoginAlerts;
use Gecka\WP\Plugin\Security\Integrations\Logins;
use Gecka\WP\Plugin\Security\Integrations\NewNetworks;
use Gecka\WP\Plugin\Security\Integrations\Pings;
use Gecka\WP\Plugin\Security\Integrations\XmlRpc;
use Gecka\WP\Plugin\Security\Settings;

/*
 * A protection switched off costs nothing on a request: it hooks nothing,
 * so no code of it runs past the one reading of the settings.
 */
it('hooks nothing when switched off', function (string $class, array $keys) {
    global $wp_filter;

    $stored = (array) Scope::option(Settings::OPTION, []);
    Scope::saveOption(Settings::OPTION, array_fill_keys($keys, false) + $stored);
    gecka_security()->flush();

    $hooks = static fn(): array => array_map(static fn(\WP_Hook $hook): int => array_sum(array_map('count', $hook->callbacks)), $wp_filter);
    $before = $hooks();

    (new $class(gecka_security()))->setup();

    $after = $hooks();
    Scope::saveOption(Settings::OPTION, $stored);
    gecka_security()->flush();

    expect($after)->toBe($before);
})->with([
    'brute force' => [Login::class, ['bruteforce']],
    'enumeration' => [Enumeration::class, ['author_archives', 'rest_users', 'oembed_author', 'sitemap_users', 'login_errors']],
    'XML-RPC' => [XmlRpc::class, ['xmlrpc_disabled']],
    'pings' => [Pings::class, ['pingback_disabled', 'trackback_disabled']],
    'headers' => [Headers::class, ['security_headers', 'hsts']],
    'editor' => [Editor::class, ['file_edit_disabled']],
    'logins' => [Logins::class, ['log_logins']],
    'last login' => [LastLogin::class, ['last_login']],
    'new networks' => [NewNetworks::class, ['alert_new_network']],
    'login alerts' => [LoginAlerts::class, ['alert_logins']],
]);

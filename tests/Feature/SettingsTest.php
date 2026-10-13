<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Admin\SettingsPage;
use Gecka\WP\Plugin\Security\Integrations\Headers;
use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Settings;

afterEach(function () {
    $GLOBALS['wp_settings_errors'] = [];
    remove_all_filters('pre_http_request');
});

beforeEach(function () {
    Scope::deleteOption(Settings::OPTION);
    gecka_security()->flush();
    $this->settings = gecka_security()->settings();
});

it('fills the gaps with the defaults', function () {
    Scope::saveOption(Settings::OPTION, ['max_failures' => 3]);
    gecka_security()->flush();

    expect($this->settings->get('max_failures'))->toBe(3)
        ->and($this->settings->get('lockout_minutes'))->toBe(20)
        ->and($this->settings->get('reserved_names'))->toBe(Settings::RESERVED_NAMES);
});

it('cleans a posted form: bounds, lists, and boxes left unticked', function () {
    $clean = $this->settings->sanitize([
        'form' => 'settings',
        'max_failures' => '0',
        'lockout_minutes' => '99999',
        'trusted_proxies' => "10.0.0.0/8\njunk",
        'safelist' => '203.0.113.5, 2001:db8::/32',
        'reserved_names' => "Admin\nroot\n\nadmin",
        'ip_source' => 'x_forwarded_for',
        'bruteforce' => '1',
    ]);

    expect($clean['max_failures'])->toBe(1)
        ->and($clean['lockout_minutes'])->toBe(1440)
        ->and($clean['trusted_proxies'])->toBe(['10.0.0.0/8'])
        ->and($clean['safelist'])->toBe(['203.0.113.5', '2001:db8::/32'])
        ->and($clean['reserved_names'])->toBe(['admin', 'root'])
        ->and($clean['ip_source'])->toBe('x_forwarded_for')
        ->and($clean['bruteforce'])->toBeTrue()
        ->and($clean['author_archives'])->toBeFalse();
});

it('keeps the address the server saw when a header is named without a trusted proxy', function () {
    $clean = $this->settings->sanitize(['form' => 'settings', 'ip_source' => 'x_real_ip', 'trusted_proxies' => '']);

    expect($clean['ip_source'])->toBe('remote_addr');
});

it('refuses a trusted proxy network covering a large part of the addresses', function () {
    $clean = $this->settings->sanitize(['form' => 'settings', 'ip_source' => 'x_real_ip', 'trusted_proxies' => "0.0.0.0/1\n128.0.0.0/1\n10.0.0.0/8"]);

    expect($clean['trusted_proxies'])->toBe(['10.0.0.0/8'])
        ->and($clean['ip_source'])->toBe('x_real_ip');
});

it('refuses a safelist network covering a large part of the addresses', function () {
    $clean = $this->settings->sanitize(['form' => 'settings', 'safelist' => "::/0\n203.0.113.0/24"]);

    expect($clean['safelist'])->toBe(['203.0.113.0/24']);
});

it('leaves the boxes of another form as stored', function () {
    Scope::saveOption(Settings::OPTION, ['author_archives' => false]);
    gecka_security()->flush();

    $clean = $this->settings->sanitize(['max_failures' => 4]);

    expect($clean['author_archives'])->toBeFalse()
        ->and($clean['max_failures'])->toBe(4)
        ->and($clean['rest_users'])->toBeFalse()
        ->and($clean['xmlrpc_disabled'])->toBeFalse()
        ->and($clean['pingback_disabled'])->toBeTrue()
        ->and($clean['trackback_disabled'])->toBeTrue();
});

it('tells a reserved name whatever its case', function () {
    expect($this->settings->isReserved(' Admin '))->toBeTrue()
        ->and($this->settings->isReserved('writer'))->toBeFalse();
});

it('asks to check the privacy policy when a setting its text depends on changes', function () {
    // Set up in the admin only, where the settings are saved.
    (new SettingsPage(gecka_security()))->setup();
    $GLOBALS['wp_settings_errors'] = [];
    Scope::saveOption(Settings::OPTION, ['max_failures' => 3] + $this->settings->defaults());
    Scope::saveOption(Settings::OPTION, ['max_failures' => 4] + $this->settings->defaults());

    expect(get_settings_errors())->toBe([]);

    Scope::saveOption(Settings::OPTION, ['log_unknown_logins' => true] + $this->settings->defaults());
    $notice = get_settings_errors()[0];

    expect($notice['code'])->toBe('settings_updated')
        ->and($notice['type'])->toBe('success')
        ->and($notice['message'])->toStartWith('Settings saved.')
        ->and($notice['message'])->toContain(Scope::network() ? 'privacy policies of the sites' : 'privacy policy of the site')
        ->and($notice['message'])->toContain('options-privacy.php?tab=policyguide');

    // Beside another notice, the request stands alone: WordPress then says nothing of the save.
    $GLOBALS['wp_settings_errors'] = [];
    add_settings_error(Settings::OPTION, 'safelist', 'Refused.');
    Scope::saveOption(Settings::OPTION, ['events_days' => 60] + $this->settings->defaults());

    expect(array_column(get_settings_errors(), 'code'))->toBe(['safelist', 'privacy_policy']);

    $GLOBALS['wp_settings_errors'] = [];
});

it('probes the headers of the server when the first save switches those of the plugin', function () {
    $probes = 0;
    add_filter('pre_http_request', function ($pre, $args, $url) use (&$probes) {
        $probes += (int) str_contains((string) $url, Headers::PROBE);

        return new WP_Error('http_request_failed', 'down');
    }, 10, 3);

    Scope::saveOption(Settings::OPTION, ['max_failures' => 3]);
    Scope::deleteOption(Settings::OPTION);
    Scope::saveOption(Settings::OPTION, ['security_headers' => false]);

    expect($probes)->toBe(1);

    remove_all_filters('pre_http_request');
    $GLOBALS['wp_settings_errors'] = [];
});

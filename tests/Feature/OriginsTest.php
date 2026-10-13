<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Origins;
use Gecka\WP\Plugin\Security\Schema;
use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Stats;

beforeEach(function () {
    $this->origins = gecka_security()->origins();
    $this->origins->reset();
    gecka_security()->events()->clear();
    $GLOBALS['gecka_security_geolocation'] = null;
    $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
});

afterEach(function () {
    unset($GLOBALS['gecka_security_geolocation'], $_SERVER['HTTP_USER_AGENT']);
});

it('tells the system a user agent names', function (string $agent, string $system) {
    expect(Origins::system($agent))->toBe($system);
})->with([
    ['Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)', 'ipados'],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)', 'ios'],
    ['Mozilla/5.0 (Linux; Android 14; Pixel 8)', 'android'],
    ['Mozilla/5.0 (X11; CrOS x86_64 15633.69.0)', 'chromeos'],
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)', 'macos'],
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'windows'],
    ['Mozilla/5.0 (X11; Linux x86_64)', 'linux'],
    ['python-requests/2.31', 'other'],
    ['', ''],
]);

it('counts the system alone without a geolocation', function () {
    do_action('gecka_security_event', Events::FAILED, '203.0.113.5', '', 'login_form', '', []);

    expect($this->origins->top(Origins::SYSTEM, 7, Origins::ATTEMPTS))->toBe([['value' => 'windows', 'name' => '', 'hits' => 1]])
        ->and($this->origins->top(Origins::COUNTRY, 7, Origins::ATTEMPTS))->toBe([])
        ->and($this->origins->top(Origins::NETWORK, 7, Origins::ATTEMPTS))->toBe([]);
});

it('counts the country and the network the geolocation gives, never the address', function () {
    global $wpdb;

    $GLOBALS['gecka_security_geolocation'] = [
        '203.0.113.5' => ['country' => 'NC', 'asn' => 17480, 'organization' => 'CANL'],
        '198.51.100.7' => ['country' => 'DE', 'asn' => 3320, 'organization' => 'Deutsche Telekom AG'],
    ];

    do_action('gecka_security_event', Events::FAILED, '203.0.113.5', '', 'login_form', '', []);
    do_action('gecka_security_event', Events::BLOCKED, '203.0.113.5', '', 'login_form', '', []);
    do_action('gecka_security_event', Events::FAILED, '198.51.100.7', '', 'xmlrpc', '', []);
    do_action('gecka_security_event', Events::FAILED, '10.0.0.1', '', 'login_form', '', []);
    do_action('gecka_security_event', Events::LOGIN, '198.51.100.7', 'editor', 'login_form', '', []);

    expect($this->origins->top(Origins::COUNTRY, 7, Origins::ATTEMPTS))->toBe([
        ['value' => 'NC', 'name' => '', 'hits' => 2],
        ['value' => '', 'name' => '', 'hits' => 1],
        ['value' => 'DE', 'name' => '', 'hits' => 1],
    ])
        ->and($this->origins->top(Origins::NETWORK, 7, Origins::ATTEMPTS)[0])->toBe(['value' => '17480', 'name' => 'CANL', 'hits' => 2])
        ->and($this->origins->top(Origins::COUNTRY, 7, [Events::LOGIN]))->toBe([['value' => 'DE', 'name' => '', 'hits' => 1]])
        ->and($this->origins->total(Origins::COUNTRY, 7, Origins::ATTEMPTS))->toBe(4)
        ->and((int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM %i WHERE value LIKE '%%.%%' OR value LIKE '%%:%%'", Schema::origins())))->toBe(0);
});

it('counts the attempts and the logins only', function () {
    do_action('gecka_security_event', Events::ACCOUNT, '203.0.113.5', 'editor', 'other', 'account.password', []);
    do_action('gecka_security_event', Events::BREACHED, '203.0.113.5', 'editor', 'login_form', 'breached.seen', []);
    do_action('gecka_security_event', Events::LOCKOUT, '203.0.113.5', 'editor', 'login_form', 'lockout.short', []);
    do_action('gecka_security_event', Events::FAILED, '', '', 'login_form', '', []);

    expect($this->origins->total(Origins::SYSTEM, 7, array_keys(Events::types())))->toBe(0);
});

it('counts a failed login through the protections', function () {
    $GLOBALS['gecka_security_geolocation'] = ['203.0.113.5' => ['country' => 'NC', 'asn' => 17480, 'organization' => 'CANL']];
    $GLOBALS['pagenow'] = 'wp-login.php';
    $_SERVER['REQUEST_METHOD'] = 'POST';
    from_ip('203.0.113.5');
    static::factory()->user->create(['user_login' => 'editor', 'user_pass' => 'correct horse']);

    wp_authenticate('editor', 'wrong');

    $GLOBALS['pagenow'] = 'index.php';
    unset($_SERVER['REQUEST_METHOD']);
    from_ip('127.0.0.1');

    expect($this->origins->top(Origins::COUNTRY, 7, Origins::ATTEMPTS))->toBe([['value' => 'NC', 'name' => '', 'hits' => 1]]);
});

it('counts every refusal past the limit of the hour, as the statistics do', function () {
    security_settings(['resets_per_hour' => 1]);
    from_ip('203.0.113.31');
    $requests = gecka_security()->integration(\Gecka\WP\Plugin\Security\Integrations\Requests::class);

    foreach ([1, 2, 3, 4] as $attempt) {
        $requests->forget();
        $requests->limited('reset');
    }

    from_ip('127.0.0.1');
    \Gecka\WP\Plugin\Security\Throttle::clear();
    security_settings(['resets_per_hour' => 5]);

    expect($this->origins->total(Origins::SYSTEM, 7, [Events::LIMITED]))->toBe(3)
        ->and(gecka_security()->events()->countsByType(['type' => Events::LIMITED]))->toBe([Events::LIMITED => 1]);
});

it('folds the networks of a day past the most seen into one row, today left alone', function () {
    $yesterday = (new DateTimeImmutable('today', wp_timezone()))->modify('-1 day')->format('Y-m-d');

    foreach ([[$yesterday, 10], [$yesterday, 8], [$yesterday, 5], [$yesterday, 2], [$yesterday, 1], [Stats::since(1), 1], [Stats::since(1), 1]] as $i => [$day, $hits]) {
        Scope::db()->insert(Schema::origins(), ['day' => $day, 'facet' => Origins::NETWORK, 'value' => (string) (64500 + $i), 'type' => Events::FAILED, 'name' => 'AS' . $i, 'hits' => $hits]);
    }

    $this->origins->foldNetworks(2);
    $this->origins->foldNetworks(2);

    $rows = Scope::db()->get_results(Scope::db()->prepare('SELECT value, hits FROM %i WHERE day = %s ORDER BY hits DESC', Schema::origins(), $yesterday));

    expect(array_map(static fn($row) => [$row->value, (int) $row->hits], $rows))->toBe([['64500', 10], ['64501', 8], [Origins::OTHER_NETWORKS, 8]])
        ->and($this->origins->total(Origins::NETWORK, 2, Origins::ATTEMPTS))->toBe(28);
});

it('drops the old counters, those of the logins with the journal, and every one on a reset', function () {
    global $wpdb;

    $day = static fn(int $ago): string => (new DateTimeImmutable('today', wp_timezone()))->modify("-$ago days")->format('Y-m-d');
    $this->origins->record(Origins::SYSTEM, 'linux', Events::FAILED);

    foreach ([[40, Events::FAILED], [400, Events::FAILED], [40, Events::LOGIN], [10, Events::LOGIN]] as [$ago, $type]) {
        $wpdb->insert(Schema::origins(), ['day' => $day($ago), 'facet' => Origins::SYSTEM, 'value' => 'linux', 'type' => $type, 'name' => '', 'hits' => 1]);
    }

    $this->origins->purge(365, 30);

    expect($this->origins->total(Origins::SYSTEM, 3650, Origins::ATTEMPTS))->toBe(2)
        ->and($this->origins->total(Origins::SYSTEM, 3650, [Events::LOGIN]))->toBe(1);

    $this->origins->reset();

    expect($this->origins->total(Origins::SYSTEM, 7, Origins::ATTEMPTS))->toBe(0);
});

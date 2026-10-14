<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Access;
use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Admin\SiteHealth;

beforeEach(function () {
    $this->health = new SiteHealth(gecka_security());
});

afterEach(fn() => from_ip('127.0.0.1'));

it('adds its tests and its section', function () {
    $tests = $this->health->tests(['direct' => []]);
    $info = $this->health->information([]);

    expect(array_keys($tests['direct']))->toBe(['gecka_security_address', 'gecka_security_bruteforce', 'gecka_security_schedule', 'gecka_security_registration', 'gecka_security_ssl_admin'])
        ->and(array_keys($tests['async']))->toBe(['gecka_security_pwned', 'gecka_security_exposure', 'gecka_security_headers'])
        ->and($info['gecka-security']['fields']['protections']['value'])->toContain('Brute force');
});

it('answers the asynchronous tests under the action the script of Site Health calls', function () {
    // Set up in the admin and WP-Cron only, where Site Health runs.
    $this->health->setup();

    expect(SiteHealth::action('gecka_security_headers'))->toBe('wp_ajax_health-check-gecka-security_headers')
        ->and(has_action('wp_ajax_health-check-gecka-security_pwned'))->toBeTrue()
        ->and(has_action('wp_ajax_health-check-gecka-security_exposure'))->toBeTrue()
        ->and(has_action('wp_ajax_health-check-gecka-security_headers'))->toBeTrue();
});

it('warns when every visitor has the same address', function () {
    from_ip('127.0.0.1');
    expect($this->health->testAddress()['status'])->toBe('recommended');

    from_ip('203.0.113.5');
    expect($this->health->testAddress()['status'])->toBe('good');
});

it('flags a private address with no proxy trusted', function () {
    from_ip('10.0.0.8');
    expect($this->health->testAddress()['status'])->toBe('critical');

    security_settings(['ip_source' => 'x_forwarded_for', 'trusted_proxies' => ['10.0.0.8']]);
    $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5';
    gecka_security()->flush();
    expect($this->health->testAddress()['status'])->toBe('good');

    unset($_SERVER['HTTP_X_FORWARDED_FOR']);
    security_settings(['ip_source' => 'remote_addr', 'trusted_proxies' => []]);
});

it('warns when the brute-force protection is off', function () {
    security_settings(['bruteforce' => false]);
    expect($this->health->testBruteForce()['status'])->toBe('recommended');

    security_settings(['bruteforce' => true]);
    expect($this->health->testBruteForce()['status'])->toBe('good');
});

it('warns when anyone can register with a role above subscriber', function () {
    registrations_open(true);
    update_option('default_role', 'editor');

    expect($this->health->testRegistration()['status'])->toBe('critical')
        ->and($this->health->testRegistration()['actions'])->toContain('options-general.php');

    update_option('default_role', 'subscriber');

    expect($this->health->testRegistration()['status'])->toBe('good');

    registrations_open(false);
    update_option('default_role', 'editor');

    expect($this->health->testRegistration()['status'])->toBe('good');

    update_option('default_role', 'subscriber');
});

it('tells whether the breach service answers', function () {
    security_settings(['pwned_passwords' => true]);
    add_filter('pre_http_request', static fn() => ['response' => ['code' => 200], 'body' => "ABC:1\r\n"]);

    expect($this->health->testPwned()['status'])->toBe('good');

    remove_all_filters('pre_http_request');
    add_filter('pre_http_request', static fn() => new WP_Error('http_request_failed', 'down'));

    expect($this->health->testPwned()['status'])->toBe('recommended');

    remove_all_filters('pre_http_request');
    security_settings(['pwned_passwords' => false]);

    expect($this->health->testPwned()['status'])->toBe('recommended')
        ->and($this->health->testPwned()['label'])->toContain('not checked')
        ->and($this->health->testPwned()['actions'])->toContain('page=gecka-security');
});

it('flags the admin not forced over HTTPS on a site that has it', function () {
    expect($this->health->testSslAdmin(true, false)['status'])->toBe('recommended')
        ->and($this->health->testSslAdmin(true, true)['status'])->toBe('good')
        ->and($this->health->testSslAdmin(false, false)['status'])->toBe('good');
});

it('tells which security headers reach the visitors, from the server or from the plugin', function () {
    // The probe is answered as the home page would, its token carried back.
    add_filter('pre_http_request', static function ($pre, $args, $url) {
        parse_str((string) wp_parse_url($url, PHP_URL_QUERY), $query);

        return ['response' => ['code' => 200], 'headers' => ['strict-transport-security' => 'max-age=1', strtolower(\Gecka\WP\Plugin\Security\Integrations\Headers::PROOF) => (string) ($query[\Gecka\WP\Plugin\Security\Integrations\Headers::PROBE] ?? '')], 'body' => ''];
    }, 10, 3);
    security_settings(['security_headers' => true, 'hsts' => false]);

    $result = $this->health->testHeaders();

    expect($result['status'])->toBe('good')
        ->and($result['description'])->toContain('strict-transport-security')
        ->and($result['description'])->toContain('x-frame-options');

    security_settings(['security_headers' => false]);

    $result = $this->health->testHeaders();

    expect($result['status'])->toBe('recommended')
        ->and($result['label'])->toContain('X-Content-Type-Options');

    remove_all_filters('pre_http_request');
    security_settings(['security_headers' => true]);
    Scope::deleteOption(\Gecka\WP\Plugin\Security\Integrations\Headers::SERVER_OPTION);
});

it('asks the site for readme.html, license.txt and the listing of the uploads', function () {
    $asked = [];
    add_filter('pre_http_request', function ($pre, $args, $url) use (&$asked) {
        $asked[] = $url;

        if (str_ends_with($url, 'readme.html')) {
            return ['response' => ['code' => 200], 'body' => '<html>WordPress</html>'];
        }

        if (str_ends_with($url, 'uploads/')) {
            return ['response' => ['code' => 200], 'body' => '<title>Index of /uploads</title>'];
        }

        return ['response' => ['code' => 404], 'body' => ''];
    }, 10, 3);

    $result = $this->health->testExposure();
    remove_all_filters('pre_http_request');

    expect($result['status'])->toBe('recommended')
        ->and($result['label'])->toContain('readme.html')
        ->and($result['label'])->toContain('uploads')
        ->and($result['label'])->not->toContain('license')
        ->and($asked)->toHaveCount(3);

    add_filter('pre_http_request', static fn() => ['response' => ['code' => 404], 'body' => '']);

    expect($this->health->testExposure()['status'])->toBe('good');

    remove_all_filters('pre_http_request');
});

it('checks the countries only when the settings name some, and tells Gecka Geolocation in the Info tab', function () {
    expect($this->health->tests([]))->not->toHaveKey('direct.gecka_security_countries');

    security_settings(['countries_mode' => Access::DENY, 'countries' => ['RU']]);
    $info = $this->health->information([])['gecka-security']['fields'];

    expect($this->health->tests([])['direct'])->toHaveKey('gecka_security_countries')
        ->and($this->health->testCountries()['status'])->toBe('good')
        ->and($info['countries']['value'])->toBe('all but RU')
        ->and($info['geolocation']['debug'])->toBe('active');

    security_settings(['countries_mode' => '', 'countries' => []]);
});

it('tells a visitor on the machine of the server from every visitor seen as the loopback', function () {
    $page = new \Gecka\WP\Plugin\Security\Admin\SettingsPage(gecka_security());
    $banner = static function () use ($page): string {
        ob_start();
        $page->warnUnprotected();

        return (string) ob_get_clean();
    };

    // The server sees everyone as the loopback: nothing can be locked out.
    from_ip('127.0.0.1');

    expect(gecka_security()->clientIp()->onServer())->toBeFalse()
        ->and($banner())->toContain('Nothing is locked out');

    // A trusted proxy gives the loopback: the visitor is on the server itself.
    security_settings(['ip_source' => 'x_forwarded_for', 'trusted_proxies' => ['10.0.0.8']]);
    $_SERVER['HTTP_X_FORWARDED_FOR'] = '127.0.0.1';
    from_ip('10.0.0.8');

    expect(gecka_security()->clientIp()->onServer())->toBeTrue()
        ->and($this->health->testAddress()['status'])->toBe('good')
        ->and($banner())->toBe('');

    unset($_SERVER['HTTP_X_FORWARDED_FOR']);
    security_settings(['ip_source' => 'remote_addr', 'trusted_proxies' => []]);
    from_ip('127.0.0.1');
});

it('leaves the address test out where no visitor is, WP-Cron and WP-CLI', function () {
    add_filter('wp_doing_cron', '__return_true');
    $tests = $this->health->tests(['direct' => [], 'async' => []]);
    remove_filter('wp_doing_cron', '__return_true');

    expect($tests['direct'])->not->toHaveKey('gecka_security_address')
        ->and($tests['direct'])->toHaveKey('gecka_security_bruteforce')
        ->and($this->health->tests(['direct' => [], 'async' => []])['direct'])->toHaveKey('gecka_security_address');
});

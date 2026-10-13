<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Integrations\Requests;

beforeEach(function () {
    // The counters change with the hour: a test is kept from straddling one.
    if (time() % HOUR_IN_SECONDS > HOUR_IN_SECONDS - 5) {
        sleep(HOUR_IN_SECONDS - time() % HOUR_IN_SECONDS);
    }

    security_settings(['resets_per_hour' => 2, 'registrations_per_hour' => 2]);
    gecka_security()->events()->clear();
});

afterEach(function () {
    from_ip('127.0.0.1');
});

it('refuses the password resets of an address past the limit of the hour, once in the journal', function () {
    from_ip('203.0.113.21');
    $codes = [];

    foreach ([1, 2, 3, 4] as $attempt) {
        gecka_security()->integration(Requests::class)?->forget();
        $errors = new WP_Error();
        do_action_ref_array('lostpassword_post', [&$errors, get_user_by('id', 1)]);
        $codes[] = $errors->get_error_code();
    }

    expect($codes)->toBe(['', '', Requests::ERROR, Requests::ERROR])
        ->and(gecka_security()->events()->countsByType(['type' => Events::LIMITED]))->toBe([Events::LIMITED => 1])
        ->and(gecka_security()->events()->entries(1, 1)[0]->detail)->toBe('limited.reset')
        ->and(Events::describe(gecka_security()->events()->entries(1, 1)[0]))->toBe('password resets: more than 2 an hour');
});

it('refuses the registrations of an address past the limit, and never a safelisted one', function () {
    from_ip('203.0.113.22');
    $codes = [];

    foreach ([1, 2, 3] as $attempt) {
        gecka_security()->integration(Requests::class)?->forget();
        $codes[] = apply_filters('registration_errors', new WP_Error(), 'someone', 'someone@example.com')->get_error_code();
    }

    expect($codes)->toBe(['', '', Requests::ERROR]);

    security_settings(['safelist' => ['203.0.113.23']]);
    from_ip('203.0.113.23');

    foreach ([1, 2, 3, 4] as $attempt) {
        gecka_security()->integration(Requests::class)?->forget();
        expect(apply_filters('registration_errors', new WP_Error(), 'someone', 'someone@example.com')->has_errors())->toBeFalse();
    }

    security_settings(['safelist' => []]);
});

it('gives a known and an unknown account the same answer once the resets are limited', function () {
    from_ip('203.0.113.24');
    $requests = gecka_security()->integration(Requests::class);
    $known = get_user_by('id', 1);
    $codes = [];

    foreach ([$known, false, $known, false] as $user) {
        $requests->forget();
        $errors = new WP_Error();
        do_action_ref_array('lostpassword_post', [&$errors, $user]);
        $codes[] = $errors->get_error_code();
    }

    expect($codes)->toBe(['', '', Requests::ERROR, Requests::ERROR])
        ->and(gecka_security()->events()->countsByType(['type' => Events::LIMITED]))->toBe([Events::LIMITED => 1]);
});

it('counts the requests in one statement, whatever the order of the callers', function () {
    $throttle = gecka_security()->throttle();

    expect($throttle->hit('reset', '203.0.113.25'))->toBe(1)
        ->and($throttle->hit('reset', '203.0.113.25'))->toBe(2)
        ->and($throttle->hit('register', '203.0.113.25'))->toBe(1)
        ->and($throttle->hit('reset', '203.0.113.26'))->toBe(1);

    \Gecka\WP\Plugin\Security\Throttle::clear();

    expect($throttle->hit('reset', '203.0.113.25'))->toBe(1);
});

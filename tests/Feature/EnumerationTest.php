<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Integrations\Enumeration;

beforeEach(function () {
    security_settings(['rest_users' => true]);
    gecka_security()->lockouts()->clear();
    $this->author = static::factory()->user->create(['user_login' => 'writer', 'role' => 'author']);
    $this->subscriber = static::factory()->user->create(['user_login' => 'member', 'role' => 'subscriber']);
    gecka_security()->events()->clear();
    $this->post = static::factory()->post->create_and_get(['post_author' => $this->author]);
    wp_set_current_user(0);
});

it('answers the archive of an author with a 404 to a visitor', function () {
    $GLOBALS['wp_query'] = new WP_Query(['author' => $this->author]);
    expect(is_author())->toBeTrue();

    (new Enumeration(gecka_security()))->authorArchive();

    expect(is_404())->toBeTrue()
        ->and(gecka_security()->events()->countsByType())->toBe([Events::ENUMERATION => 1])
        ->and(gecka_security()->events()->entries(1, 1)[0]->way)->toBe('author')
        ->and(gecka_security()->events()->entries(1, 1)[0]->username)->toBe('');
});

it('leaves the archive of an author to a logged-in user', function () {
    wp_set_current_user($this->author);

    $GLOBALS['wp_query'] = new WP_Query(['author' => $this->author]);
    (new Enumeration(gecka_security()))->authorArchive();

    expect(is_404())->toBeFalse()
        ->and(gecka_security()->events()->count())->toBe(0);
});

it('answers the archive of an author with a 404 to a subscriber', function () {
    wp_set_current_user($this->subscriber);

    $GLOBALS['wp_query'] = new WP_Query(['author' => $this->author]);
    (new Enumeration(gecka_security()))->authorArchive();

    expect(is_404())->toBeTrue()
        ->and(gecka_security()->events()->countsByType())->toBe([Events::ENUMERATION => 1])
        ->and(gecka_security()->events()->entries(1, 1)[0]->username)->toBe('member')
        ->and(apply_filters('redirect_canonical', home_url('/author/writer/'), home_url('/?author=' . $this->author)))->toBeFalse();
});

it('leaves a subscriber its own archive', function () {
    wp_set_current_user($this->subscriber);

    $GLOBALS['wp_query'] = new WP_Query(['author' => $this->subscriber]);
    (new Enumeration(gecka_security()))->authorArchive();

    expect(is_404())->toBeFalse()
        ->and(gecka_security()->events()->count())->toBe(0);
});

it('lets the capability that sees the accounts be filtered', function () {
    wp_set_current_user($this->subscriber);
    expect(Enumeration::canList())->toBeFalse();

    add_filter('gecka_security_enumeration_capability', $read = fn() => 'read');
    $byRead = Enumeration::canList();
    remove_filter('gecka_security_enumeration_capability', $read);

    wp_set_current_user($this->author);
    add_filter('gecka_security_enumeration_capability', $none = fn() => '');
    $byNone = Enumeration::canList();
    remove_filter('gecka_security_enumeration_capability', $none);

    expect($byRead)->toBeTrue()
        ->and($byNone)->toBeFalse()
        ->and(Enumeration::canList())->toBeTrue();
});

it('does not redirect ?author=N to the archive', function () {
    $GLOBALS['wp_query'] = new WP_Query(['author' => $this->author]);

    expect(apply_filters('redirect_canonical', home_url('/author/writer/'), home_url('/?author=' . $this->author)))->toBeFalse();
});

it('refuses the users route of the REST API to a visitor', function () {
    $enumeration = new Enumeration(gecka_security());
    $enumeration->setup();

    $response = rest_do_request(new WP_REST_Request('GET', '/wp/v2/users'));

    expect($response->get_status())->toBe(401)
        ->and(gecka_security()->events()->entries(1, 1)[0]->way)->toBe('rest_users');

    $response = rest_do_request(new WP_REST_Request('GET', '/wp/v2/users/' . $this->author));
    expect($response->get_status())->toBe(401);

    $response = rest_do_request(new WP_REST_Request('GET', '/wp/v2/posts'));
    expect($response->get_status())->toBe(200);

    remove_filter('rest_pre_dispatch', [$enumeration, 'restUsers'], Enumeration::PRIORITY);
});

it('leaves the users route to a logged-in user', function () {
    $enumeration = new Enumeration(gecka_security());
    $enumeration->setup();
    wp_set_current_user($this->author);

    expect(rest_do_request(new WP_REST_Request('GET', '/wp/v2/users'))->get_status())->toBe(200);

    remove_filter('rest_pre_dispatch', [$enumeration, 'restUsers'], Enumeration::PRIORITY);
});

it('refuses the users route to a subscriber, its own routes kept', function () {
    $enumeration = new Enumeration(gecka_security());
    $enumeration->setup();
    wp_set_current_user($this->subscriber);

    $list = rest_do_request(new WP_REST_Request('GET', '/wp/v2/users'))->get_status();
    $other = rest_do_request(new WP_REST_Request('GET', '/wp/v2/users/' . $this->author))->get_status();
    $me = rest_do_request(new WP_REST_Request('GET', '/wp/v2/users/me'))->get_status();
    $own = rest_do_request(new WP_REST_Request('GET', '/wp/v2/users/' . $this->subscriber))->get_status();
    $passwords = rest_do_request(new WP_REST_Request('GET', '/wp/v2/users/' . $this->subscriber . '/application-passwords'))->get_status();

    remove_filter('rest_pre_dispatch', [$enumeration, 'restUsers'], Enumeration::PRIORITY);

    expect($list)->toBe(403)
        ->and($other)->toBe(403)
        ->and(gecka_security()->events()->entries(1, 1)[0]->username)->toBe('member')
        ->and($me)->toBe(200)
        ->and($own)->toBe(200)
        ->and($passwords)->not->toBeIn([401, 403]);
});

it('leaves the author out of the oEmbed data and the users out of the sitemap', function () {
    expect(apply_filters('oembed_response_data', ['title' => 'Post', 'author_name' => 'writer', 'author_url' => 'x'], $this->post, 600, 338))->not->toHaveKeys(['author_name', 'author_url'])
        ->and(apply_filters('wp_sitemaps_add_provider', new stdClass(), 'users'))->toBeFalse()
        ->and(apply_filters('wp_sitemaps_add_provider', new stdClass(), 'posts'))->toBeInstanceOf(stdClass::class);
});

it('gives a failed login one message, its code kept', function () {
    from_ip('203.0.113.5');
    $unknown = wp_authenticate('nobody', 'wrong');
    $wrong = wp_authenticate('writer', 'wrong');
    from_ip('127.0.0.1');

    expect($unknown->get_error_code())->toBe('invalid_username')
        ->and($wrong->get_error_code())->toBe('incorrect_password')
        ->and($unknown->get_error_message())->toBe($wrong->get_error_message())
        ->and($wrong->get_error_message())->not->toContain('writer');
});

it('gives a password reset of an unknown account the same message as a known one', function () {
    $errors = apply_filters('lostpassword_errors', new WP_Error('invalidcombo', 'There is no account with that username or email address.'), false);

    expect($errors->get_error_message())->not->toContain('no account');
});

it('looks an account up as retrieve_password() does', function () {
    static::factory()->user->create(['user_login' => 'reader', 'user_email' => 'reader@example.org']);

    expect(Enumeration::accountExists('reader'))->toBeTrue()
        ->and(Enumeration::accountExists('reader@example.org'))->toBeTrue()
        ->and(Enumeration::accountExists('nobody'))->toBeFalse()
        ->and(Enumeration::accountExists('nobody@example.org'))->toBeFalse();
});

it('refuses the users route of the REST API whatever its case', function () {
    security_settings(['rest_users' => true]);
    $enumeration = new Enumeration(gecka_security());
    $enumeration->setup();
    $request = new WP_REST_Request('GET', '/wp/v2/USERS');

    $result = apply_filters('rest_pre_dispatch', null, rest_get_server(), $request);

    expect($result)->toBeInstanceOf(WP_Error::class)
        ->and($result->get_error_data()['status'] ?? 0)->toBe(401);
});

it('sends a password reset of an unknown account where a known one goes, once the other checks passed', function () {
    $enumeration = gecka_security()->integration(Enumeration::class);
    $GLOBALS['pagenow'] = 'wp-login.php';
    $_SERVER['REQUEST_METHOD'] = 'POST';

    $_POST['user_login'] = 'nobody';
    $unknown = $enumeration->lostPasswordTarget(new WP_Error(), false);
    // A captcha, the gate or the limit of the hour refused it: the error shows, as for a known account.
    $refused = $enumeration->lostPasswordTarget(new WP_Error('gecka_antispam', 'Refused.'), false);
    $_POST['user_login'] = 'writer';
    $known = $enumeration->lostPasswordTarget(new WP_Error(), get_user_by('login', 'writer'));
    $_POST['user_login'] = 'nobody';
    $_REQUEST['redirect_to'] = 'https://example.org/after';
    $redirected = $enumeration->lostPasswordTarget(new WP_Error(), false);

    // Neither form: a reset asked from elsewhere is left to WordPress.
    $GLOBALS['pagenow'] = 'index.php';
    $elsewhere = $enumeration->lostPasswordTarget(new WP_Error(), false);

    // The form of WooCommerce, without WooCommerce loaded: left to it.
    $_POST['wc_reset_password'] = 'true';
    $woo = $enumeration->lostPasswordTarget(new WP_Error(), false);

    unset($_POST['user_login'], $_POST['wc_reset_password'], $_REQUEST['redirect_to'], $_SERVER['REQUEST_METHOD']);

    expect($unknown)->toBe('wp-login.php?checkemail=confirm')
        ->and($refused)->toBeNull()
        ->and($known)->toBeNull()
        ->and($redirected)->toBe('https://example.org/after')
        ->and($elsewhere)->toBeNull()
        ->and($woo)->toBeNull()
        ->and(gecka_security()->events()->countsByType())->toBe([Events::ENUMERATION => 2])
        ->and(has_action('lostpassword_post', [$enumeration, 'lostPassword']))->toBe(99);
});

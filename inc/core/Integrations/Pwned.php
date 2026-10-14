<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

use Gecka\WP\Plugin\Security\Admin\SettingsPage;
use Gecka\WP\Plugin\Security\Plugin;
use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Value;

/**
 * Passwords that appear in known data breaches: refused when set or
 * changed, and a user who logs in with one is warned until they change
 * it. The check goes through the Pwned Passwords service of Have I Been
 * Pwned by k-anonymity: the first five characters of the SHA-1 of the
 * password leave the site, the service answers with every known suffix
 * of that prefix, and the comparison is made here. Neither the password,
 * nor the login, nor the address of the visitor is sent.
 *
 * The service unreachable, a password is let through: nothing here may
 * lock a site because a third party is down. On login, the verdict is
 * kept with a fingerprint of the stored hash, so that a password is
 * checked once a month at most, and only once the password proved right.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Pwned extends Integration
{
    /**
     * Code of the error added when a password is refused.
     */
    public const ERROR = 'gecka_security_pwned';

    /**
     * User meta holding the verdict of the last check.
     */
    public const META = 'gecka_security_pwned';

    /**
     * Range endpoint of Pwned Passwords, the five first characters of the
     * hash appended.
     */
    private const ENDPOINT = 'https://api.pwnedpasswords.com/range/';

    /**
     * Seconds a verdict holds on login.
     */
    private const RECHECK = 30 * DAY_IN_SECONDS;

    /**
     * Seconds given to the service.
     */
    private const TIMEOUT = 2;

    /**
     * Transient set while the service is down, to spare every login the
     * wait.
     */
    public const DOWN = 'gecka_security_pwned_down';

    /**
     * Seconds the service is left alone after a failure.
     */
    private const REST = 10 * MINUTE_IN_SECONDS;

    /**
     * Digests of the passwords this request checked, by account: kept in
     * memory for the rehash that follows a login, never stored.
     *
     * @var array<int, string>
     */
    private array $checked = [];

    /**
     * Always available: it needs nothing beyond WordPress.
     *
     * @return bool
     */
    public function available(): bool
    {
        return true;
    }

    /**
     * Hooks the password checks and the warnings up, when the setting is
     * on.
     *
     * @return void
     */
    public function setup(): void
    {
        if (! $this->plugin->settings()->enabled('pwned_passwords')) {
            return;
        }

        add_action('user_profile_update_errors', [$this, 'profile'], self::PRIORITY, 3);
        add_action('validate_password_reset', [$this, 'reset'], self::PRIORITY, 2);
        // After the gates of the registration: a refused one asks nothing of the service.
        add_filter('woocommerce_registration_errors', [$this, 'registration'], 20);
        add_action('woocommerce_save_account_details_errors', [$this, 'account'], self::PRIORITY, 2);
        // After the brute-force gate: a locked-out address gets no check.
        add_filter('wp_authenticate_user', [$this, 'login'], 40, 2);
        add_action('wp_set_password', [$this, 'rehashed'], 10, 2);
        add_action('admin_notices', [$this, 'notice']);
        add_action('network_admin_notices', [$this, 'notice']);
        add_action('woocommerce_account_content', [$this, 'accountNotice'], self::PRIORITY);
    }

    /**
     * Checks the password typed on the profile screen, or by an
     * administrator creating an account.
     *
     * @param mixed $errors Errors of the profile form, added to in place.
     * @param mixed $update Whether an existing account is updated; unused.
     * @param mixed $user   Carries the new password in clear, when one was typed.
     *
     * @return void
     */
    public function profile(mixed $errors, mixed $update, mixed $user): void
    {
        if ($errors instanceof \WP_Error && is_object($user) && ! empty($user->user_pass)) {
            $this->refuse($errors, Value::string($user->user_pass));
        }
    }

    /**
     * Checks the password typed on the reset form, of WordPress (pass1) or
     * of WooCommerce (password_1).
     *
     * @param mixed $errors Errors of the reset form, added to in place.
     * @param mixed $user   The account being reset, or an error; unused.
     *
     * @return void
     */
    public function reset(mixed $errors, mixed $user): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- WordPress checked the reset key before this hook; a password is compared, neither stored nor printed.
        $password = isset($_POST['pass1']) ? Value::string(wp_unslash($_POST['pass1'])) : (isset($_POST['password_1']) ? Value::string(wp_unslash($_POST['password_1'])) : '');

        if ($errors instanceof \WP_Error && $password !== '') {
            $this->refuse($errors, $password);
        }
    }

    /**
     * Checks the password typed on the registration form of WooCommerce,
     * once the registration passed every other check.
     *
     * @param mixed $errors Errors of the registration.
     *
     * @return mixed The errors, a breached password added.
     */
    public function registration(mixed $errors): mixed
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- WooCommerce checked its nonce before this hook; a password is compared, neither stored nor printed.
        $password = isset($_POST['password']) ? Value::string(wp_unslash($_POST['password'])) : '';

        if ($errors instanceof \WP_Error && ! $errors->has_errors() && $password !== '') {
            $this->refuse($errors, $password);
        }

        return $errors;
    }

    /**
     * Checks the password typed on the account screen of WooCommerce.
     *
     * @param mixed $errors Errors of the account form, added to in place.
     * @param mixed $user   The account being saved, as WooCommerce builds it; unused.
     *
     * @return void
     */
    public function account(mixed $errors, mixed $user): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- WooCommerce checked its nonce before this hook; a password is compared, neither stored nor printed.
        $password = isset($_POST['password_1']) ? Value::string(wp_unslash($_POST['password_1'])) : '';

        if ($errors instanceof \WP_Error && $password !== '') {
            $this->refuse($errors, $password);
        }
    }

    /**
     * Checks the password of a login that proved right, once a month, and
     * records a breached one in the journal.
     *
     * @param mixed $user     The account, or the error of an earlier check.
     * @param mixed $password Password typed, in clear.
     *
     * @return mixed The account or the error, untouched.
     */
    public function login(mixed $user, mixed $password): mixed
    {
        if (! $user instanceof \WP_User || ! is_string($password) || $password === '') {
            return $user;
        }

        $meta = (array) get_user_meta($user->ID, self::META, true);
        $fingerprint = self::fingerprint($user);

        if (($meta['hash'] ?? '') === $fingerprint && Value::int($meta['checked'] ?? 0) > time() - self::RECHECK) {
            return $user;
        }

        if (! wp_check_password($password, (string) $user->user_pass, $user->ID)) {
            return $user;
        }

        $count = $this->count($password);

        if ($count === null) {
            return $user;
        }

        update_user_meta($user->ID, self::META, ['hash' => $fingerprint, 'pwned' => $count, 'checked' => time()]);
        $this->checked[$user->ID] = hash('sha256', $password);

        if ($count > 0) {
            $this->record(Events::BREACHED, $user->user_login, 'breached.seen', params: ['count' => $count]);
        }

        return $user;
    }

    /**
     * Follows a password stored again unchanged: WordPress rehashes an
     * outdated hash once the login checked it, after this plugin took the
     * fingerprint of the old one. A password that changed keeps the old
     * fingerprint, and with it no verdict.
     *
     * @param mixed $password The password, in clear.
     * @param mixed $userId   Id of the account.
     *
     * @return void
     */
    public function rehashed(mixed $password, mixed $userId): void
    {
        $userId = Value::int($userId);

        if (! isset($this->checked[$userId]) || ! is_string($password) || ! hash_equals($this->checked[$userId], hash('sha256', $password))) {
            return;
        }

        $user = get_userdata($userId);
        $meta = get_user_meta($userId, self::META, true);

        if ($user instanceof \WP_User && is_array($meta)) {
            $meta['hash'] = self::fingerprint($user);
            update_user_meta($userId, self::META, $meta);
        }
    }

    /**
     * Warns the user logged in with a breached password until they change
     * it, on the dashboard, the profile and the screens of the plugin: the
     * rest of the admin stays free of it.
     *
     * @return void
     */
    public function notice(): void
    {
        $user = wp_get_current_user();
        $screen = function_exists('get_current_screen') ? get_current_screen() : null;

        if (! $screen || ! (in_array($screen->base, ['dashboard', 'profile'], true) || SettingsPage::current())) {
            return;
        }

        if (! $user->exists() || ! self::breached($user)) {
            return;
        }

        wp_admin_notice(
            sprintf('%s <a href="%s">%s</a>', esc_html(self::warning()), esc_url(get_edit_profile_url()), esc_html__('Change it now.', 'gecka-security')),
            ['type' => 'warning', 'dismissible' => false],
        );
    }

    /**
     * The same warning on the account screen of WooCommerce, for the
     * customers who never see the admin.
     *
     * @return void
     */
    public function accountNotice(): void
    {
        $user = wp_get_current_user();

        if (! $user->exists() || ! self::breached($user) || ! function_exists('wc_print_notice') || ! function_exists('wc_customer_edit_account_url')) {
            return;
        }

        wc_print_notice(sprintf('%s <a href="%s">%s</a>', esc_html(self::warning()), esc_url(Value::string(wc_customer_edit_account_url())), esc_html__('Change it now.', 'gecka-security')), 'notice');
    }

    /**
     * Times a password was seen in known breaches
     *
     * @param string $password Password, in clear; only the first five characters of its SHA-1 are sent.
     *
     * @return int|null Null when the service did not answer, or is resting after a failure.
     */
    public function count(string $password): ?int
    {
        if (Scope::transient(self::DOWN)) {
            return null;
        }

        $hash = strtoupper(sha1($password));
        $response = wp_remote_get(self::ENDPOINT . substr($hash, 0, 5), [
            'timeout' => self::TIMEOUT,
            'headers' => ['Add-Padding' => 'true'],
            'user-agent' => 'Gecka Security/' . Plugin::VERSION,
        ]);

        if (is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 200) {
            Scope::setTransient(self::DOWN, 1, self::REST);

            return null;
        }

        $suffix = substr($hash, 5);

        foreach (preg_split('/\R/', wp_remote_retrieve_body($response)) ?: [] as $line) {
            [$known, $hits] = array_pad(explode(':', trim($line), 2), 2, '0');

            if (strtoupper($known) === $suffix) {
                return (int) $hits;
            }
        }

        return 0;
    }

    /**
     * Whether the password of the account was found breached at its last
     * check, and has not changed since
     *
     * @param \WP_User $user The account.
     *
     * @return bool
     */
    public static function breached(\WP_User $user): bool
    {
        $meta = (array) get_user_meta($user->ID, self::META, true);

        return ($meta['hash'] ?? '') === self::fingerprint($user) && Value::int($meta['pwned'] ?? 0) > 0;
    }

    /**
     * Refuses a breached password.
     *
     * @param \WP_Error $errors   Errors of the form, added to in place.
     * @param string    $password Password typed, in clear.
     *
     * @return void
     */
    private function refuse(\WP_Error $errors, string $password): void
    {
        $count = $this->count($password);

        if ($count) {
            /* translators: %s: number of times the password was seen in breaches */
            $errors->add(self::ERROR, sprintf(_n('This password appears in known data breaches, %s time. Choose another one.', 'This password appears in known data breaches, %s times. Choose another one.', $count, 'gecka-security'), number_format_i18n($count)));
        }
    }

    /**
     * A fingerprint of the stored hash of the password, telling a change
     * without keeping anything of the password
     *
     * @param \WP_User $user Account whose stored hash is fingerprinted.
     *
     * @return string
     */
    private static function fingerprint(\WP_User $user): string
    {
        return hash('sha256', (string) $user->user_pass);
    }

    /**
     * The warning a user with a breached password gets
     *
     * @return string
     */
    private static function warning(): string
    {
        return __('Your password appears in known data breaches: anyone can try it.', 'gecka-security');
    }
}

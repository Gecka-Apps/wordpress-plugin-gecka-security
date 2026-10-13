<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

use Gecka\WP\Plugin\Security\Access;
use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Request;

/**
 * The gate of the logins: the brute-force protection counts the logins an
 * address fails, on every way in, and refuses its logins, registrations
 * and password resets while it is locked out; the blocklist and the
 * countries of the settings refuse them for good (Access). The safelist
 * lets an address through both.
 *
 * The gate sits on two hooks. wp_authenticate_user fires once the account
 * is found, before the password is checked: a locked-out address is refused
 * there, ahead of a captcha or a second factor. authenticate at
 * GATE_PRIORITY runs after every handler, those of WordPress at 20 and 30
 * and those of other plugins, as an LDAP or single sign-on one: it refuses
 * what the first hook never saw, a login on an account that does not exist
 * or an application password, and it beats any handler that would have let
 * the login in. It has to come after them: the password handler of
 * WordPress ignores an error it is given and checks the password anyway.
 * The cookie handler, which wp_signon() adds at 30, only acts on an empty
 * login, which the gate leaves alone.
 *
 * An application password on the REST API takes neither hook: WordPress
 * checks it from determine_current_user, and reports a failure through an
 * action of its own. The gate unhooks that check for a locked-out address,
 * and the failures are counted from the action.
 *
 * Failures are never cleared by a successful login: on a site open to
 * registration, a bot owning one account would log into it between two
 * runs of guesses and never reach the maximum. They expire with the window.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Login extends Integration
{
    /**
     * Code of the error a locked-out address gets.
     */
    public const ERROR = 'gecka_security_locked';

    /**
     * Code of the error an address of the blocklist or of a country refused
     * gets.
     */
    public const REFUSED = 'gecka_security_refused';

    /**
     * Seconds the refusals of one address, login and reason fold into one
     * row of the journal.
     */
    private const REFUSALS_FOLD = HOUR_IN_SECONDS;

    /**
     * Priority of the gate on authenticate: after every handler that could
     * let a login in, the very last slot left to the site.
     */
    public const GATE_PRIORITY = PHP_INT_MAX - 1;

    /**
     * What a failed login on a reserved name no account carries counts for.
     */
    public const RESERVED_WEIGHT = 2;

    /**
     * Whether the attempt of this request was already recorded as refused.
     *
     * @var bool
     */
    private bool $recorded = false;

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
     * Hooks the gate up when the brute-force protection is on or the
     * settings refuse some addresses, and the count of failures with the
     * brute-force protection.
     *
     * @return void
     */
    public function setup(): void
    {
        $settings = $this->plugin->settings();
        $bruteforce = $settings->enabled('bruteforce');

        if (! $bruteforce && ! $settings->restricts()) {
            return;
        }

        if ($bruteforce) {
            add_action('wp_login_failed', [$this, 'failed'], self::PRIORITY, 2);
            add_action('application_password_failed_authentication', [$this, 'failedApplicationPassword'], self::PRIORITY);
        }

        add_filter('wp_authenticate_user', [$this, 'gateUser'], self::PRIORITY);
        add_filter('authenticate', [$this, 'gate'], self::GATE_PRIORITY, 2);
        add_filter('determine_current_user', [$this, 'gateApplicationPassword'], 15);
        add_action('lostpassword_post', [$this, 'gateLostPassword'], self::PRIORITY);
        add_filter('registration_errors', [$this, 'gateErrors'], self::PRIORITY);
        add_filter('woocommerce_registration_errors', [$this, 'gateErrors'], self::PRIORITY);
        add_filter('wpmu_validate_user_signup', [$this, 'gateSignup'], self::PRIORITY);
        add_filter('login_message', [$this, 'message'], self::PRIORITY);
    }

    /**
     * Seconds left of the lockout of the visitor, 0 when none applies: with
     * the brute-force protection off, an address the server cannot vouch
     * for, or one on the safelist.
     *
     * @return int
     */
    public function remaining(): int
    {
        $ip = $this->plugin->clientIp();

        if (! $this->plugin->settings()->enabled('bruteforce') || ! $ip->reliable() || $ip->safelisted()) {
            return 0;
        }

        return $this->plugin->lockouts()->remaining($ip->key());
    }

    /**
     * Why the settings refuse the visitor for good, null when they do not:
     * an address the server cannot vouch for is never refused, nor is one
     * on the safelist.
     *
     * @return array{reason: string, country: string}|null As Access::refusal() gives it.
     */
    public function refusal(): ?array
    {
        $ip = $this->plugin->clientIp();
        $settings = $this->plugin->settings();

        if (! $settings->restricts() || ! $ip->reliable() || $ip->safelisted()) {
            return null;
        }

        return Access::refusal($ip->get(), $settings->strings('blocklist'), $settings->string('countries_mode'), $settings->strings('countries'));
    }

    /**
     * Whether the gate refuses the visitor now, for good or for the time of
     * a lockout
     *
     * @return bool
     */
    public function refuses(): bool
    {
        return $this->refusal() !== null || $this->remaining() > 0;
    }

    /**
     * Lets the next refusal be recorded, as in a new request.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->recorded = false;
    }

    /**
     * Refuses the login of a refused or locked-out address once its
     * account is found.
     *
     * @param mixed $user The account, or an error.
     *
     * @return mixed The refusal for a refused or locked-out address, the value given otherwise.
     */
    public function gateUser(mixed $user): mixed
    {
        return $this->refuse($user instanceof \WP_User ? $user->user_login : '') ?? $user;
    }

    /**
     * Refuses the login of a refused or locked-out address, whatever the
     * handlers of WordPress made of it.
     *
     * @param mixed $user     The account, an error, or null.
     * @param mixed $username Login tried, empty for a cookie.
     *
     * @return mixed The refusal for a refused or locked-out address, the value given otherwise.
     */
    public function gate(mixed $user, mixed $username = ''): mixed
    {
        if (! is_string($username) || $username === '') {
            return $user;
        }

        return $this->refuse($username) ?? $user;
    }

    /**
     * Counts a failed login, and locks the address out at the maximum.
     *
     * @param mixed $username Login tried.
     * @param mixed $error    Why it failed.
     *
     * @return void
     */
    public function failed(mixed $username, mixed $error = null): void
    {
        $username = is_string($username) ? $username : '';
        $codes = $error instanceof \WP_Error ? $error->get_error_codes() : [];

        if (array_intersect($codes, self::ignoredCodes())) {
            return;
        }

        // The weight does not depend on an account carrying the name: a
        // lockout coming sooner or later would tell whether it exists.
        $reservedName = $this->plugin->settings()->isReserved($username);
        $reserved = $reservedName && ! username_exists($username);
        $username = $this->loginKept($username);
        $this->record($reserved ? Events::RESERVED : Events::FAILED, $username, implode(', ', $codes));

        $ip = $this->plugin->clientIp();

        // A failure while the address is locked out comes from a request
        // that got past the gate before the lockout, or from a check the
        // gate does not cover: it is in the journal, and counts for nothing.
        if (! $ip->reliable() || $ip->safelisted() || $this->plugin->lockouts()->remaining($ip->key()) > 0) {
            return;
        }

        $lockout = $this->plugin->lockouts()->fail($ip->key(), $reservedName ? self::RESERVED_WEIGHT : 1);

        if ($lockout === null) {
            return;
        }

        $this->record(Events::LOCKOUT, $username, $lockout['long'] ? 'lockout.long' : 'lockout.short');

        /**
         * Fires when an address is locked out.
         *
         * @param string $ip       Address of the visitor.
         * @param int    $until    When the lockout ends, as a timestamp.
         * @param bool   $long     Whether it is the long lockout, after repeated ones.
         * @param string $username Login the last failure tried, empty when it names neither an account nor a reserved name and log_unknown_logins is off.
         */
        do_action('gecka_security_lockout', $ip->get(), $lockout['until'], $lockout['long'], $username);
    }

    /**
     * Counts an application password refused on the REST API. On XML-RPC,
     * wp_login_failed counts the same attempt.
     *
     * @param mixed $error Why it failed.
     *
     * @return void
     */
    public function failedApplicationPassword(mixed $error = null): void
    {
        // On XML-RPC, wp_login_failed follows for the same attempt.
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            return;
        }

        $username = isset($_SERVER['PHP_AUTH_USER']) && is_scalar($_SERVER['PHP_AUTH_USER']) ? sanitize_user(wp_unslash((string) $_SERVER['PHP_AUTH_USER'])) : '';

        $this->failed($username, $error);
    }

    /**
     * Keeps WordPress from checking an application password sent by a
     * refused or locked-out address: its check is unhooked for the request,
     * so the password is neither verified nor counted as a success.
     *
     * @param mixed $userId User id found so far, or false.
     *
     * @return mixed The user id, untouched.
     */
    public function gateApplicationPassword(mixed $userId): mixed
    {
        if (empty($_SERVER['PHP_AUTH_USER']) || $this->refuse(sanitize_user(Request::serverRaw('PHP_AUTH_USER'))) === null) {
            return $userId;
        }

        remove_filter('determine_current_user', 'wp_validate_application_password', 20);

        return $userId;
    }

    /**
     * Refuses the registration or the password reset of a refused or
     * locked-out address.
     *
     * @param mixed $errors Errors of the registration or the password reset, added to in place.
     *
     * @return mixed The errors.
     */
    public function gateErrors(mixed $errors): mixed
    {
        if (! $errors instanceof \WP_Error) {
            return $errors;
        }

        $refusal = $this->refuse();

        if ($refusal !== null) {
            $errors->add($refusal->get_error_code(), $refusal->get_error_message());
        }

        return $errors;
    }

    /**
     * Refuses the sign-up of a refused or locked-out address on a network,
     * through wp-signup.php. The same validation serves the accounts an
     * administrator creates in the admin, left alone.
     *
     * @param mixed $result What wpmu_validate_user_signup() found, its errors under errors.
     *
     * @return mixed The result, the refusal added to its errors.
     */
    public function gateSignup(mixed $result): mixed
    {
        if (! is_admin() && is_array($result)) {
            $this->gateErrors($result['errors'] ?? null);
        }

        return $result;
    }

    /**
     * Refuses the password reset of a refused or locked-out address.
     *
     * @param mixed $errors Errors of the password reset, added to in place.
     *
     * @return void
     */
    public function gateLostPassword(mixed $errors): void
    {
        $this->gateErrors($errors);
    }

    /**
     * Tells a refused or locked-out visitor on the login screen before the
     * form, so that no password is typed in vain.
     *
     * @param mixed $message Message shown above the login form.
     *
     * @return mixed The message, the refusal appended for a refused or locked-out visitor.
     */
    public function message(mixed $message): mixed
    {
        if (Request::isLoginScreenPost()) {
            return $message;
        }

        $remaining = $this->remaining();
        $text = $this->refusal() !== null ? self::refusedText() : ($remaining > 0 ? self::text($remaining) : '');

        if ($text === '') {
            return $message;
        }

        return (is_string($message) ? $message : '') . sprintf('<div id="login_error" class="notice notice-error"><p>%s</p></div>', esc_html($text));
    }

    /**
     * The error a locked-out visitor gets
     *
     * @param int $remaining Seconds left.
     *
     * @return string
     */
    public static function text(int $remaining): string
    {
        /* translators: %s: how long is left, as "20 mins" or "1 hour" */
        return sprintf(__('Too many failed login attempts. Try again in %s.', 'gecka-security'), human_time_diff(time(), time() + max($remaining, MINUTE_IN_SECONDS)));
    }

    /**
     * The error a refused visitor gets, the same whatever the reason
     *
     * @return string
     */
    public static function refusedText(): string
    {
        return __('Logins from your address are not allowed.', 'gecka-security');
    }

    /**
     * Errors that are not a wrong guess: the refusals of this plugin, an
     * empty form, and the refusals of other checks on the same form.
     *
     * @return string[]
     */
    public static function ignoredCodes(): array
    {
        $codes = [self::ERROR, self::REFUSED, 'empty_username', 'empty_password', 'gecka_antispam', 'cap_captcha_failed'];

        /**
         * Filters the error codes a failed login is not counted for.
         *
         * @param string[] $codes Codes of WP_Error that do not count as a failure.
         */
        return (array) apply_filters('gecka_security_ignored_errors', $codes);
    }

    /**
     * The error of a refused or locked-out address, its attempt recorded
     * once per request. A refusal for good folds with those of the hour on
     * the same address and reason, under the login only when it names an
     * account or a reserved name: a bot varying the login makes one row. A
     * refusal during a lockout folds with those of the lockout.
     *
     * @param string $username Login tried, if any.
     *
     * @return \WP_Error|null Null when the address is neither refused nor locked out.
     */
    private function refuse(string $username = ''): ?\WP_Error
    {
        $refusal = $this->refusal();
        $remaining = $refusal === null ? $this->remaining() : 0;

        if ($refusal === null && $remaining <= 0) {
            return null;
        }

        if (! $this->recorded) {
            $this->recorded = true;

            if ($refusal !== null) {
                $this->fold(Events::REFUSED, self::REFUSALS_FOLD, $this->loginNamed($username), 'refused.' . $refusal['reason'], params: $refusal['country'] !== '' ? ['country' => $refusal['country']] : []);
            } else {
                $this->bump(Events::BLOCKED, Events::LOCKOUT, $this->loginKept($username));
            }
        }

        return $refusal !== null
            ? new \WP_Error(self::REFUSED, esc_html(self::refusedText()))
            : new \WP_Error(self::ERROR, esc_html(self::text($remaining)));
    }
}

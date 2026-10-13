<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Request;

/**
 * The requests that cost without failing, limited per address and per
 * hour: a password reset sends a mail and a registration creates an
 * account, so neither counts as a failure, and a robot could repeat them
 * without end. Past the limit, the request is refused with a plain
 * message, the first refusal of the hour goes in the journal and every
 * one in the statistics. An address that cannot be read, or on the
 * safelist, is never limited.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Requests extends Integration
{
    /**
     * Code of the error added when a request is refused.
     */
    public const ERROR = 'gecka_security_limited';

    /**
     * What was decided for each kind in this request, so that the forms
     * asking twice get one answer and one line in the journal.
     *
     * @var array<string, bool>
     */
    private array $decided = [];

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
     * Limits the password resets and the registrations, when the setting is
     * on.
     *
     * @return void
     */
    public function setup(): void
    {
        if (! $this->plugin->settings()->enabled('limit_requests')) {
            return;
        }

        // After the brute-force gate, which refuses a locked-out address first.
        add_action('lostpassword_post', [$this, 'lostPassword'], self::PRIORITY + 1, 2);
        add_filter('registration_errors', [$this, 'registration'], self::PRIORITY + 1, 2);
        add_filter('woocommerce_registration_errors', [$this, 'registration'], self::PRIORITY + 1, 2);
        add_filter('wpmu_validate_user_signup', [$this, 'signup'], self::PRIORITY + 1);
    }

    /**
     * Refuses a password reset past the limit of the hour.
     *
     * @param mixed $errors Errors of the password reset, added to in place.
     * @param mixed $user   The account asked for, when it exists.
     *
     * @return void
     */
    public function lostPassword(mixed $errors, mixed $user = null): void
    {
        if ($errors instanceof \WP_Error && $this->limited('reset', $user instanceof \WP_User ? $user->user_login : '')) {
            $errors->add(self::ERROR, __('Too many password reset requests from your address. Try again in an hour.', 'gecka-security'));
        }
    }

    /**
     * Refuses a registration past the limit of the hour.
     *
     * @param mixed $errors Errors of the registration.
     * @param mixed $login  The login asked for.
     *
     * @return mixed The errors, the refusal added past the limit.
     */
    public function registration(mixed $errors, mixed $login = ''): mixed
    {
        if ($errors instanceof \WP_Error && $this->limited('register', is_string($login) ? $login : '')) {
            $errors->add(self::ERROR, __('Too many registrations from your address. Try again in an hour.', 'gecka-security'));
        }

        return $errors;
    }

    /**
     * Refuses a sign-up on a network past the limit of the hour, through
     * wp-signup.php. The same validation serves the accounts an
     * administrator creates in the admin, never limited.
     *
     * @param mixed $result What wpmu_validate_user_signup() found, its errors under errors and the login under user_name.
     *
     * @return mixed The result, the refusal added to its errors past the limit.
     */
    public function signup(mixed $result): mixed
    {
        if (! is_admin() && is_array($result)) {
            $this->registration($result['errors'] ?? null, $result['user_name'] ?? '');
        }

        return $result;
    }

    /**
     * Lets the next call decide anew, as a new request would.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->decided = [];
    }

    /**
     * Counts a request of a kind for the address, and tells whether it
     * passes the limit of the hour. Decided once a request: a form asking
     * twice gets the same answer.
     *
     * @param string $kind     The counter: reset or register.
     * @param string $username Login the request names, if any.
     *
     * @return bool
     */
    public function limited(string $kind, string $username = ''): bool
    {
        if (isset($this->decided[$kind])) {
            return $this->decided[$kind];
        }

        $ip = $this->plugin->clientIp();

        if ($ip->get() === '' || ! $ip->reliable() || $ip->safelisted()) {
            return $this->decided[$kind] = false;
        }

        $count = $this->plugin->throttle()->hit($kind, $ip->key());
        $limit = $this->plugin->settings()->int($kind === 'reset' ? 'resets_per_hour' : 'registrations_per_hour');

        if ($count <= $limit) {
            return $this->decided[$kind] = false;
        }

        if ($count === $limit + 1) {
            $this->record(Events::LIMITED, $this->loginKept($username), 'limited.' . $kind, params: ['limit' => $limit]);
        } else {
            $this->counted(Events::LIMITED, $ip->get(), '', Request::vector(), 'limited.' . $kind, ['limit' => $limit]);
        }

        return $this->decided[$kind] = true;
    }
}

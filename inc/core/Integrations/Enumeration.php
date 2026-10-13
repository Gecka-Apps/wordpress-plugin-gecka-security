<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Request;
use Gecka\WP\Plugin\Security\Value;

/**
 * Keeps the logins of the site to itself: the places WordPress lists its
 * accounts to anyone, and the messages that tell a login from a password.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Enumeration extends Integration
{
    /**
     * Errors of a login that tell whether the login or the password was
     * wrong, given one message instead.
     */
    public const LOGIN_CODES = ['invalid_username', 'incorrect_password', 'invalid_email', 'invalidcombo'];

    /**
     * Errors of a password reset that tell whether the account exists.
     */
    public const LOST_PASSWORD_CODES = ['invalidcombo', 'invalid_email'];

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
     * Hooks each enumeration protection whose setting is on.
     *
     * @return void
     */
    public function setup(): void
    {
        $settings = $this->plugin->settings();

        if ($settings->enabled('author_archives')) {
            add_action('template_redirect', [$this, 'authorArchive'], 1);
            add_filter('redirect_canonical', [$this, 'authorRedirect'], self::PRIORITY);
        }

        if ($settings->enabled('rest_users')) {
            add_filter('rest_pre_dispatch', [$this, 'restUsers'], self::PRIORITY, 3);
        }

        if ($settings->enabled('oembed_author')) {
            add_filter('oembed_response_data', [$this, 'oembed'], self::PRIORITY);
        }

        if ($settings->enabled('sitemap_users')) {
            add_filter('wp_sitemaps_add_provider', [$this, 'sitemap'], self::PRIORITY, 2);
        }

        if ($settings->enabled('login_errors')) {
            add_filter('authenticate', [$this, 'maskLogin'], 99);
            add_filter('lostpassword_errors', [$this, 'maskLostPassword'], 99);
            // After the captcha, the brute-force gate and the limit of the hour.
            add_action('lostpassword_post', [$this, 'lostPassword'], 99, 2);
            add_filter('xmlrpc_login_error', [$this, 'maskXmlrpc'], self::PRIORITY);
        }
    }

    /**
     * Answers the archive of an author with a 404 to a visitor, whether it
     * was asked by slug or by ?author=N.
     *
     * @return void
     */
    public function authorArchive(): void
    {
        global $wp_query;

        if (! is_author() || is_user_logged_in()) {
            return;
        }

        $this->record(Events::ENUMERATION, '', Value::string(get_query_var('author_name')) ?: Value::string(get_query_var('author')), 'author');

        if ($wp_query instanceof \WP_Query) {
            $wp_query->set_404();
        }

        status_header(404);
        nocache_headers();
    }

    /**
     * Keeps WordPress from redirecting ?author=N to the archive of the
     * author, whose address holds the login.
     *
     * @param mixed $redirect Address WordPress would redirect to, or false.
     *
     * @return mixed False for a visitor asking an author, the address otherwise.
     */
    public function authorRedirect(mixed $redirect): mixed
    {
        if (! is_user_logged_in() && (get_query_var('author') || get_query_var('author_name'))) {
            return false;
        }

        return $redirect;
    }

    /**
     * Refuses the users routes of the REST API to a visitor.
     *
     * @param mixed $result  Response short-circuiting the dispatch, null to let it run.
     * @param mixed $server  The REST server; unused.
     * @param mixed $request The request dispatched.
     *
     * @return mixed A rest_forbidden error for a visitor on a users route, the result otherwise.
     */
    public function restUsers(mixed $result, mixed $server, mixed $request): mixed
    {
        if ($result !== null || is_user_logged_in() || ! $request instanceof \WP_REST_Request) {
            return $result;
        }

        if (! preg_match('#^/wp/v2/users(?:/|$)#i', $request->get_route())) {
            return $result;
        }

        $this->record(Events::ENUMERATION, '', $request->get_route(), 'rest_users');

        return new \WP_Error('rest_forbidden', __('Sorry, you are not allowed to list users.', 'gecka-security'), ['status' => rest_authorization_required_code()]);
    }

    /**
     * Leaves the author out of the oEmbed data of a post.
     *
     * @param mixed $data oEmbed data of the post.
     *
     * @return mixed The data, author_name and author_url left out.
     */
    public function oembed(mixed $data): mixed
    {
        if (is_array($data)) {
            unset($data['author_name'], $data['author_url']);
        }

        return $data;
    }

    /**
     * Leaves the users out of the sitemap.
     *
     * @param mixed $provider Provider WordPress is adding.
     * @param mixed $name     Name of the provider.
     *
     * @return mixed False for the users provider, the provider otherwise.
     */
    public function sitemap(mixed $provider, mixed $name): mixed
    {
        return $name === 'users' ? false : $provider;
    }

    /**
     * Gives the errors of a login one message, whether the login or the
     * password was wrong.
     *
     * @param mixed $user The account, an error, or null.
     *
     * @return mixed The account, the error or null, the error rewritten in place.
     */
    public function maskLogin(mixed $user): mixed
    {
        if ($user instanceof \WP_Error) {
            self::mask($user, self::LOGIN_CODES, __('The login or the password is incorrect.', 'gecka-security'));
        }

        return $user;
    }

    /**
     * Sends a password reset asked for an account that does not exist where
     * one asked for an existing account goes, on the lost-password form of
     * wp-login.php or of WooCommerce. Runs after the other checks of the
     * form, a captcha, the brute-force gate, the limit of the hour: their
     * errors read the same for any account, and an unknown account gets
     * none the known one would not get.
     *
     * @param mixed $errors Errors of the password reset so far.
     * @param mixed $user   The account asked for, false when none matches.
     *
     * @return void
     */
    public function lostPassword(mixed $errors, mixed $user = false): void
    {
        $target = $this->lostPasswordTarget($errors, $user);

        if ($target === null) {
            return;
        }

        wp_safe_redirect($target);
        exit;
    }

    /**
     * Where a password reset goes when it names no account and no check
     * refused it: the confirmation screen of its form, the event recorded.
     * Null leaves it to WordPress: an existing account, an error to show,
     * or a reset asked from elsewhere than the two forms.
     *
     * @param mixed $errors Errors of the password reset so far.
     * @param mixed $user   The account asked for, false when none matches.
     *
     * @return string|null
     */
    public function lostPasswordTarget(mixed $errors, mixed $user = false): ?string
    {
        if ($user instanceof \WP_User || ! $errors instanceof \WP_Error || $errors->has_errors()) {
            return null;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Read as the form handlers read it: wp-login.php has no nonce on this form, WooCommerce checked its own; only recorded, escaped on display.
        $login = isset($_POST['user_login']) && is_string($_POST['user_login']) ? trim(wp_unslash($_POST['user_login'])) : '';

        if ($login === '') {
            return null;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Tells the form of WooCommerce, whose nonce WooCommerce checked.
        if (isset($_POST['wc_reset_password'])) {
            if (! function_exists('wc_get_account_endpoint_url')) {
                return null;
            }

            $target = add_query_arg('reset-link-sent', 'true', wc_get_account_endpoint_url('lost-password'));
        } elseif (Request::isLoginScreenPost()) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Read as wp-login.php reads it; wp_safe_redirect() validates the target.
            $redirect = ! empty($_REQUEST['redirect_to']) && is_string($_REQUEST['redirect_to']) ? wp_unslash($_REQUEST['redirect_to']) : '';
            $target = $redirect !== '' ? $redirect : 'wp-login.php?checkemail=confirm';
        } else {
            return null;
        }

        $this->record(Events::ENUMERATION, $this->loginKept($login), 'enumeration.lost_password');

        return $target;
    }

    /**
     * Whether a login or an email address names an account, as
     * retrieve_password() looks it up
     *
     * @param string $login Login or e-mail address typed.
     *
     * @return bool
     */
    public static function accountExists(string $login): bool
    {
        return (bool) get_user_by(str_contains($login, '@') ? 'email' : 'login', $login);
    }

    /**
     * Gives the errors of a password reset one message, whether the account
     * exists or not.
     *
     * @param mixed $errors Errors of the password reset.
     *
     * @return mixed The errors, rewritten in place.
     */
    public function maskLostPassword(mixed $errors): mixed
    {
        if ($errors instanceof \WP_Error) {
            self::mask($errors, self::LOST_PASSWORD_CODES, __('If an account matches, a message with a link to reset the password was sent to its email address.', 'gecka-security'));
        }

        return $errors;
    }

    /**
     * Gives a failed XML-RPC login one message.
     *
     * @param mixed $error Error XML-RPC answers a failed login with.
     *
     * @return mixed A new 403 error for an IXR_Error, the value otherwise.
     */
    public function maskXmlrpc(mixed $error): mixed
    {
        if ($error instanceof \IXR_Error) {
            return new \IXR_Error(403, __('The login or the password is incorrect.', 'gecka-security'));
        }

        return $error;
    }

    /**
     * Replaces the message of errors, their codes kept.
     *
     * @param \WP_Error $errors  Errors rewritten in place.
     * @param string[]  $codes   Codes whose messages are replaced.
     * @param string    $message Message given instead, plain text.
     *
     * @return void
     */
    private static function mask(\WP_Error $errors, array $codes, string $message): void
    {
        foreach (array_intersect($errors->get_error_codes(), $codes) as $code) {
            $errors->remove($code);
            $errors->add($code, esc_html($message));
        }
    }
}

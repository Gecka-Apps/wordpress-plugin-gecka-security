<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * What the request is: where a login came in from, and whether a browser is
 * behind it.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Request
{
    /**
     * The login form of wp-login.php, or wp_login_form() on a page.
     */
    public const LOGIN_FORM = 'login_form';

    /**
     * The login form of the WooCommerce account page or checkout.
     */
    public const WOOCOMMERCE = 'woocommerce';

    /**
     * A call of xmlrpc.php.
     */
    public const XMLRPC = 'xmlrpc';

    /**
     * A request of the REST API, authenticated with an application password.
     */
    public const REST = 'rest';

    /**
     * Anything else: a login form of a plugin, a script calling wp_signon().
     */
    public const OTHER = 'other';

    /**
     * Whether the request is for the REST API, told from the request itself
     * when WordPress has not named it yet: the application passwords are
     * checked before REST_REQUEST is defined.
     *
     * @return bool
     */
    public static function isRest(): bool
    {
        if (defined('REST_REQUEST') && REST_REQUEST) {
            return true;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only tells the way in.
        if (isset($_GET['rest_route'])) {
            return true;
        }

        $prefix = function_exists('rest_get_url_prefix') ? rest_get_url_prefix() : 'wp-json';
        $path = Value::string(wp_parse_url(self::server('REQUEST_URI'), PHP_URL_PATH));
        $base = rtrim(Value::string(wp_parse_url(home_url('/'), PHP_URL_PATH)), '/') . '/' . $prefix;

        return $path === $base || str_starts_with($path, $base . '/');
    }

    /**
     * The way a login came in
     *
     * @return string One of the constants.
     */
    public static function vector(): string
    {
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            return self::XMLRPC;
        }

        if (self::isRest()) {
            return self::REST;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Only tells which form is posting, WooCommerce checks its nonce.
        if (isset($_POST['woocommerce-login-nonce'])) {
            return self::WOOCOMMERCE;
        }

        return self::isLoginScreenPost() ? self::LOGIN_FORM : self::OTHER;
    }

    /**
     * A request of wp-login.php, the page of the login, registration and
     * lost password forms
     *
     * @return bool
     */
    public static function isLoginScreen(): bool
    {
        return ($GLOBALS['pagenow'] ?? '') === 'wp-login.php';
    }

    /**
     * A POST to wp-login.php, the target of its forms and of wp_login_form().
     *
     * @return bool
     */
    public static function isLoginScreenPost(): bool
    {
        return self::isLoginScreen()
            && strtoupper(self::server('REQUEST_METHOD')) === 'POST';
    }

    /**
     * A variable of the query string as plain text, empty when missing.
     * Unchecked by a nonce: callers read a choice of display with it, or
     * check the nonce of their action first.
     *
     * @param string $key Name of the variable.
     *
     * @return string
     */
    public static function query(string $key): string
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- See the description.
        return isset($_GET[$key]) && is_scalar($_GET[$key]) ? sanitize_text_field(wp_unslash((string) $_GET[$key])) : '';
    }

    /**
     * A server variable as plain text, empty when missing
     *
     * @param string $key Name of the variable, as REMOTE_ADDR.
     *
     * @return string
     */
    public static function server(string $key): string
    {
        return isset($_SERVER[$key]) && is_scalar($_SERVER[$key]) ? sanitize_text_field(wp_unslash((string) $_SERVER[$key])) : '';
    }

    /**
     * A server variable unslashed only, for the caller to sanitize as its
     * use asks: an address keeps its encoded characters, which plain text
     * would drop.
     *
     * @param string $key Name of the variable, as REQUEST_URI.
     *
     * @return string
     */
    public static function serverRaw(string $key): string
    {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- See the description.
        return isset($_SERVER[$key]) && is_scalar($_SERVER[$key]) ? wp_unslash((string) $_SERVER[$key]) : '';
    }
}

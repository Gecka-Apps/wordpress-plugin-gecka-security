<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * Where the plugin keeps what it keeps: the site, or the whole network of
 * a multisite. The accounts of a network are shared by its sites, so a
 * lockout, a counter, a setting or a journal row of one site holds for
 * all of them: the tables take the base prefix, the options and the
 * transients those of the network, the screens go to the network admin,
 * and the daily task runs on the main site.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Scope
{
    /**
     * Whether the plugin works for a network
     *
     * @return bool
     */
    public static function network(): bool
    {
        return is_multisite();
    }

    /**
     * Prefix of the tables: the base one, which a single site shares
     * with its only site
     *
     * @return string
     */
    public static function prefix(): string
    {
        return self::db()->base_prefix;
    }

    /**
     * The database of WordPress
     *
     * @return \wpdb
     */
    public static function db(): \wpdb
    {
        /** @var \wpdb $wpdb */
        global $wpdb;

        return $wpdb;
    }

    /**
     * The capability the screens ask for unless filtered
     *
     * @return string
     */
    public static function capability(): string
    {
        return self::network() ? 'manage_network_options' : 'manage_options';
    }

    /**
     * An option of the site, or of the network
     *
     * @param string $name    Name of the option.
     * @param mixed  $default Value returned when the option does not exist.
     *
     * @return mixed
     */
    public static function option(string $name, mixed $default = false): mixed
    {
        return self::network() ? get_site_option($name, $default) : get_option($name, $default);
    }

    /**
     * Saves an option of the site, or of the network.
     *
     * @param string $name     Name of the option.
     * @param mixed  $value    Value saved.
     * @param bool   $autoload Whether a site loads it with every request; a network option is read on demand.
     *
     * @return void
     */
    public static function saveOption(string $name, mixed $value, bool $autoload = false): void
    {
        if (self::network()) {
            update_site_option($name, $value);
        } else {
            update_option($name, $value, $autoload);
        }
    }

    /**
     * Deletes an option of the site, or of the network.
     *
     * @param string $name Name of the option.
     *
     * @return void
     */
    public static function deleteOption(string $name): void
    {
        self::network() ? delete_site_option($name) : delete_option($name);
    }

    /**
     * A transient of the site, or of the network
     *
     * @param string $name Name of the transient.
     *
     * @return mixed False when there is none.
     */
    public static function transient(string $name): mixed
    {
        return self::network() ? get_site_transient($name) : get_transient($name);
    }

    /**
     * Sets a transient of the site, or of the network.
     *
     * @param string $name    Name of the transient.
     * @param mixed  $value   Value kept.
     * @param int    $seconds Lifetime, in seconds.
     *
     * @return void
     */
    public static function setTransient(string $name, mixed $value, int $seconds): void
    {
        self::network() ? set_site_transient($name, $value, $seconds) : set_transient($name, $value, $seconds);
    }

    /**
     * Deletes a transient of the site, or of the network.
     *
     * @param string $name Name of the transient.
     *
     * @return void
     */
    public static function deleteTransient(string $name): void
    {
        self::network() ? delete_site_transient($name) : delete_transient($name);
    }

    /**
     * Runs a callback on the main site of the network, where the daily
     * task is scheduled, or on the only site
     *
     * @param callable $callback Called with no argument.
     *
     * @return mixed What the callback returns.
     */
    public static function onMainSite(callable $callback): mixed
    {
        if (! self::network() || is_main_site()) {
            return $callback();
        }

        switch_to_blog(get_main_site_id());

        try {
            return $callback();
        } finally {
            restore_current_blog();
        }
    }

    /**
     * A time in the date and time formats and the time zone of the site
     *
     * @param int|null $timestamp Unix timestamp; now when null.
     *
     * @return string
     */
    public static function dateTime(?int $timestamp = null): string
    {
        return Value::string(wp_date(Value::string(get_option('date_format')) . ' ' . Value::string(get_option('time_format')), $timestamp));
    }

    /**
     * Name of the site, or of the network
     *
     * @return string
     */
    public static function name(): string
    {
        $name = self::network() ? Value::string(get_network()?->site_name) : Value::string(get_option('blogname'));

        return wp_specialchars_decode($name, ENT_QUOTES);
    }

    /**
     * E-mail address of the administrator of the site, or of the network
     *
     * @return string
     */
    public static function adminEmail(): string
    {
        return Value::string(self::option('admin_email'));
    }

    /**
     * Address of the home of the site, or of the main site of the network
     *
     * @return string
     */
    public static function home(): string
    {
        return self::network() ? network_home_url('/') : home_url('/');
    }

    /**
     * Address of a screen of the admin, or of the network admin
     *
     * @param string $path Path within the admin, as admin.php?page=gecka-security.
     *
     * @return string
     */
    public static function adminUrl(string $path): string
    {
        return self::network() ? network_admin_url($path) : admin_url($path);
    }
}

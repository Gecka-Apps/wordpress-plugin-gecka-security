<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

use Gecka\WP\Plugin\Security\Admin\EventsView;
use Gecka\WP\Plugin\Security\Admin\LockoutsView;
use Gecka\WP\Plugin\Security\Admin\SettingsPage;
use Gecka\WP\Plugin\Security\Integrations\Headers;
use Gecka\WP\Plugin\Security\Integrations\NewNetworks;
use Gecka\WP\Plugin\Security\Integrations\Pwned;

/**
 * What the plugin leaves on a site, or on a network: four tables, three
 * options and the request counters in the options table, three transients,
 * a daily event on the main site, and, on the users, the screen options of
 * its lists, the verdict on their password and the networks they logged in
 * from. Deleting the plugin removes all of it.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Setup
{
    /**
     * Option holding the versions of the plugin and of its tables whose
     * setup ran on a site, as 1.0.0/4.
     */
    public const VERSION_OPTION = 'gecka_security_version';

    /**
     * Daily event purging the old events, counters and addresses.
     */
    public const PURGE_EVENT = 'gecka_security_purge';

    /**
     * Hooks the state changes of the plugin up.
     *
     * @param string $file Main file of the plugin.
     *
     * @return void
     */
    public static function hooks(string $file): void
    {
        register_activation_hook($file, [self::class, 'activate']);
        register_deactivation_hook($file, [self::class, 'deactivate']);
    }

    /**
     * Sets the plugin up on the site, or on the network. On a multisite the
     * accounts are shared by every site, so the plugin works for the whole
     * network and is activated for it: the plugin header says so to the
     * plugins screen, and an activation asked for one site is refused.
     *
     * @param bool $networkWide Whether the plugin is activated for the whole network.
     *
     * @return void
     */
    public static function activate(bool $networkWide = false): void
    {
        if (is_multisite() && ! $networkWide) {
            wp_die(
                esc_html__('Gecka Security protects the whole network: activate it for the network, from the network admin.', 'gecka-security'),
                '',
                ['back_link' => true],
            );
        }

        self::install(Plugin::VERSION);
    }

    /**
     * Stops the event and has the setup run again on the next activation.
     *
     * @param bool $networkWide Whether the plugin is deactivated for the whole network; unused.
     *
     * @return void
     */
    public static function deactivate(bool $networkWide = false): void
    {
        Scope::onMainSite(static fn() => wp_clear_scheduled_hook(self::PURGE_EVENT));
        Scope::deleteOption(self::VERSION_OPTION);
    }

    /**
     * Runs the setup again when the version changed, which covers a plugin
     * updated by Composer; otherwise schedules the daily task again when it
     * went missing.
     *
     * @param string $version Version of the plugin.
     *
     * @return void
     */
    public static function upgrade(string $version): void
    {
        if (Scope::option(self::VERSION_OPTION) !== self::installed($version)) {
            self::install($version);
        } elseif (is_admin() || wp_doing_cron()) {
            // Not on the front: on a network, the check switches to the
            // main site, which no visitor's request should pay for.
            self::schedule();
        }
    }

    /**
     * What the option records once the setup ran: the versions of the plugin
     * and of its tables
     *
     * @param string $version Version of the plugin.
     *
     * @return string
     */
    public static function installed(string $version): string
    {
        return $version . '/' . Schema::VERSION;
    }

    /**
     * Creates the tables, the options every request reads, autoloaded, and
     * schedules the purge. A missing option would cost a query on every
     * request, where no persistent object cache remembers its absence.
     *
     * @param string $version Version of the plugin.
     *
     * @return void
     */
    public static function install(string $version): void
    {
        Schema::install();
        self::schedule();

        foreach ([Settings::OPTION, Headers::SERVER_OPTION] as $option) {
            if (Scope::option($option, false) === false) {
                Scope::saveOption($option, [], true);
            }
        }

        Scope::saveOption(self::VERSION_OPTION, self::installed($version), true);
    }

    /**
     * Schedules the daily purge on the main site of a network, unless it is
     * scheduled already.
     *
     * @return void
     */
    private static function schedule(): void
    {
        Scope::onMainSite(static function (): void {
            if (! wp_next_scheduled(self::PURGE_EVENT)) {
                wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::PURGE_EVENT);
            }
        });
    }

    /**
     * Removes the tables, the options, the transients, the request counters
     * and the event, and what the plugin keeps on the users: the screen
     * options of its lists, the verdict on their password and the networks
     * they logged in from.
     *
     * @return void
     */
    public static function uninstall(): void
    {
        Scope::onMainSite(static fn() => wp_clear_scheduled_hook(self::PURGE_EVENT));
        Schema::drop();

        Scope::deleteOption(Settings::OPTION);
        Scope::deleteOption(self::VERSION_OPTION);
        Scope::deleteOption(Headers::SERVER_OPTION);

        foreach ([Events::LOGINS_CACHE, Pwned::DOWN, Headers::PROBE_TOKEN] as $transient) {
            Scope::deleteTransient($transient);
        }

        self::deleteUserOptions();
    }

    /**
     * Drops what the plugin keeps on the users, the rows per page and the
     * hidden columns of its lists, the verdict on their password and the
     * networks they logged in from, and the request counters.
     *
     * @return void
     */
    private static function deleteUserOptions(): void
    {
        $wpdb = Scope::db();

        delete_metadata('user', 0, EventsView::PER_PAGE_OPTION, '', true);
        delete_metadata('user', 0, LockoutsView::PER_PAGE_OPTION, '', true);
        delete_metadata('user', 0, Pwned::META, '', true);
        delete_metadata('user', 0, NewNetworks::META, '', true);
        Throttle::clear();

        foreach ([SettingsPage::PAGES['events'], SettingsPage::PAGES['lockouts']] as $slug) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Run once, when the plugin is deleted.
            foreach ((array) $wpdb->get_col($wpdb->prepare('SELECT umeta_id FROM %i WHERE meta_key LIKE %s', $wpdb->usermeta, 'manage%' . $wpdb->esc_like($slug) . '%columnshidden')) as $id) {
                delete_metadata_by_mid('user', (int) $id);
            }
        }
    }
}

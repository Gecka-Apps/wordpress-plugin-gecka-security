<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Plugin Name: Gecka Security
 * Plugin URI: https://github.com/Gecka-Apps/wordpress-plugin-gecka-security
 * Description: Locks out addresses that fail too many logins on every way in, hides the list of accounts, refuses the logins bots try first, and keeps a journal and statistics of it all. Nothing leaves the server but the breached-password check, which can be switched off.
 * Version: 1.1.1
 * Author: Gecka
 * Author URI: https://gecka.nc
 * License: GPL-3.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Requires at least: 6.8
 * Requires PHP: 8.2
 * Text Domain: gecka-security
 * Domain Path: /languages/
 * Network: true
 */

declare(strict_types=1);

defined('ABSPATH') || exit;

use Gecka\WP\Plugin\Security\Plugin;
use Gecka\WP\Plugin\Security\Setup;

if (! class_exists('\Gecka\WP\Plugin\Security\Plugin')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

/**
 * The plugin instance, built on the first call.
 *
 * @return Plugin
 */
function gecka_security(): Plugin
{
    /** @var Plugin|null $plugin */
    static $plugin = null;

    if (! $plugin) {
        $plugin = new Plugin(__FILE__);
    }

    return $plugin;
}

add_action(
    'plugins_loaded',
    static function (): void {
        gecka_security();
    },
);

// Ahead of the menu, which takes its translated titles on init at 5.
add_action(
    'init',
    static function (): void {
        load_plugin_textdomain('gecka-security', false, dirname(plugin_basename(__FILE__)) . '/languages'); // phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound -- The translations ship in the languages folder of the plugin.
    },
    0,
);

Setup::hooks(__FILE__);

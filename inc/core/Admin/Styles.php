<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Admin;

use Gecka\WP\Plugin\Security\Plugin;

/**
 * Style sheet and script of the screens of the plugin, and the style sheet
 * of the dashboard widget.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Styles
{
    /**
     * Handle of the style sheet and of the script.
     */
    public const HANDLE = 'gecka-security-admin';

    /**
     * Enqueues the style sheet and the script of the screens of the plugin.
     *
     * @return void
     */
    public static function enqueue(): void
    {
        self::style();
        wp_enqueue_script(self::HANDLE, gecka_security()->url('assets/admin.js'), [], Plugin::VERSION, ['in_footer' => true, 'strategy' => 'defer']);
    }

    /**
     * Enqueues the style sheet alone, for the dashboard widget.
     *
     * @return void
     */
    public static function style(): void
    {
        wp_enqueue_style(self::HANDLE, gecka_security()->url('assets/admin.css'), [], Plugin::VERSION);
    }
}

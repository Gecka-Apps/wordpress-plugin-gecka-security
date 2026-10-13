<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

/**
 * XML-RPC switched off: xmlrpc.php answers every call with a refusal, and
 * the pages stop advertising it. A bot uses it to try hundreds of passwords
 * in one request through system.multicall; Jetpack and the mobile app of
 * WordPress need it, which is why it is a setting, off by default.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class XmlRpc extends Integration
{
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
     * Switches XML-RPC off, when the setting is on.
     *
     * @return void
     */
    public function setup(): void
    {
        if (! $this->plugin->settings()->enabled('xmlrpc_disabled')) {
            return;
        }

        add_filter('xmlrpc_enabled', '__return_false');
        add_filter('wp_headers', [$this, 'dropPingbackHeader'], self::PRIORITY);
        remove_action('wp_head', 'rsd_link');
        add_action('init', [$this, 'refuse'], self::PRIORITY);
    }

    /**
     * Refuses a call of xmlrpc.php before it is parsed.
     *
     * @return void
     */
    public function refuse(): void
    {
        if (! defined('XMLRPC_REQUEST') || ! XMLRPC_REQUEST) {
            return;
        }

        status_header(403);
        nocache_headers();
        header('Content-Type: text/plain; charset=utf-8');
        echo esc_html__('XML-RPC is switched off on this site.', 'gecka-security');
        exit;
    }
}

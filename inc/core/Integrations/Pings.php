<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

use Gecka\WP\Plugin\Security\Value;

/**
 * Pingbacks and trackbacks refused, each by its own setting. Both let a
 * stranger make the site act without an account: a pingback has the server
 * fetch an address of the stranger's choosing, the usual way to bounce a
 * site into a denial of service or to probe the network behind it; a
 * trackback is a link notification that in practice only spam sends. The
 * pingback methods leave XML-RPC with the header announcing them, and
 * wp-trackback.php answers with a refusal before it fetches anything.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Pings extends Integration
{
    /**
     * The XML-RPC methods that receive pingbacks.
     */
    private const PINGBACK_METHODS = ['pingback.ping', 'pingback.extensions.getPingbacks'];

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
     * Refuses pingbacks and trackbacks, each by its setting.
     *
     * @return void
     */
    public function setup(): void
    {
        $settings = $this->plugin->settings();

        if ($settings->enabled('pingback_disabled')) {
            add_filter('xmlrpc_methods', [$this, 'dropPingback'], self::PRIORITY);
            add_filter('wp_headers', [$this, 'dropPingbackHeader'], self::PRIORITY);
        }

        if ($settings->enabled('trackback_disabled')) {
            add_action('pre_trackback_post', [$this, 'refuseTrackback'], self::PRIORITY);
        }
    }

    /**
     * Takes the pingback methods out of XML-RPC.
     *
     * @param mixed $methods XML-RPC methods, by name.
     *
     * @return mixed The methods, those of PINGBACK_METHODS left out.
     */
    public function dropPingback(mixed $methods): mixed
    {
        if (is_array($methods)) {
            foreach (self::PINGBACK_METHODS as $method) {
                unset($methods[$method]);
            }
        }

        return $methods;
    }

    /**
     * Refuses a trackback, in the response format of the protocol, before
     * wp-trackback.php looks the post up or fetches the source.
     *
     * @return void
     */
    public function refuseTrackback(): void
    {
        status_header(403);
        nocache_headers();
        $charset = Value::string(get_option('blog_charset'));

        header('Content-Type: text/xml; charset=' . $charset);
        echo '<?xml version="1.0" encoding="' . esc_attr($charset) . '"?' . ">\n";
        echo '<response><error>1</error><message>' . esc_html__('Trackbacks are refused on this site.', 'gecka-security') . '</message></response>';
        exit;
    }
}

<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * The way back in from the command line, for an administrator locked out
 * with everyone behind the same address.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Cli
{
    /**
     * The plugin instance.
     *
     * @var Plugin
     */
    private Plugin $plugin;

    /**
     * Keeps the plugin instance the command acts on.
     *
     * @param Plugin $plugin The plugin instance.
     */
    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    /**
     * Ends the lockout of an address, or of every address.
     *
     * ## OPTIONS
     *
     * [<ip>]
     * : The address to release. Every lockout ends when none is given.
     *
     * ## EXAMPLES
     *
     *     wp gecka-security unlock 203.0.113.5
     *     wp gecka-security unlock
     *
     * @param string[] $args Positional arguments: the address to release, if any.
     *
     * @return void
     */
    public function unlock(array $args): void
    {
        if ($args) {
            $released = $this->plugin->lockouts()->unlock([Network::key(Network::normalize((string) $args[0]) ?? (string) $args[0])]);
            /* translators: %d: number of addresses */
            \WP_CLI::success(sprintf(_n('%d address released.', '%d addresses released.', $released, 'gecka-security'), $released));

            return;
        }

        $this->plugin->lockouts()->clear();
        \WP_CLI::success(__('Every lockout ended, every failure forgotten.', 'gecka-security'));
    }
}

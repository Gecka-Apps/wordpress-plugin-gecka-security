<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * Base of the pieces the plugin hooks up.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
abstract class Base
{
    /**
     * The plugin the piece belongs to.
     *
     * @var Plugin
     */
    protected Plugin $plugin;

    /**
     * Keeps the plugin the piece belongs to.
     *
     * @param Plugin $plugin The plugin instance.
     */
    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    /**
     * Hooks the piece up.
     *
     * @return void
     */
    abstract public function setup(): void;
}

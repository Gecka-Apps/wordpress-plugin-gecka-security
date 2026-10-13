<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

/**
 * The theme and plugin editors of the admin switched off: a compromised
 * administrator account would use them to put PHP on the server. Done
 * through the capabilities, as DISALLOW_FILE_EDIT does, so that the menu
 * entries go with the screens; installs and updates stay possible.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Editor extends Integration
{
    /**
     * The capabilities the editors ask for.
     */
    private const CAPABILITIES = ['edit_plugins', 'edit_themes', 'edit_files'];

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
     * Denies the capabilities of the editors, when the setting is on.
     *
     * @return void
     */
    public function setup(): void
    {
        if (! $this->plugin->settings()->enabled('file_edit_disabled')) {
            return;
        }

        add_filter('map_meta_cap', [$this, 'refuse'], self::PRIORITY, 2);
    }

    /**
     * Denies the capabilities of the editors to everyone.
     *
     * @param mixed $caps Primitive capabilities the capability checked maps to.
     * @param mixed $cap  Capability checked.
     *
     * @return mixed do_not_allow for a capability of the editors, the primitive capabilities otherwise.
     */
    public function refuse(mixed $caps, mixed $cap): mixed
    {
        return in_array($cap, self::CAPABILITIES, true) ? ['do_not_allow'] : $caps;
    }
}

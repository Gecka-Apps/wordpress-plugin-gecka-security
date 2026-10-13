<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

use Gecka\WP\Plugin\Security\Value;

/**
 * The logins bots try first, refused to new accounts: WordPress reads them
 * from the illegal_user_logins filter when an account is registered or
 * created.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class ReservedNames extends Integration
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
     * Hooks the reserved names into the logins WordPress refuses.
     *
     * @return void
     */
    public function setup(): void
    {
        add_filter('illegal_user_logins', [$this, 'illegal'], self::PRIORITY);
    }

    /**
     * Adds the reserved names to the logins WordPress refuses.
     *
     * @param mixed $logins Logins WordPress refuses.
     *
     * @return mixed The logins refused, the reserved names added, as a list of strings.
     */
    public function illegal(mixed $logins): mixed
    {
        return array_values(array_unique(array_merge(Value::strings($logins), $this->plugin->settings()->strings('reserved_names'))));
    }
}

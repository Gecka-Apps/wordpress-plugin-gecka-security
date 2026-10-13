<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * Removes what the plugin left on the installation, when it is deleted.
 */

declare(strict_types=1);

defined('WP_UNINSTALL_PLUGIN') || exit;

require_once __DIR__ . '/vendor/autoload.php';

Gecka\WP\Plugin\Security\Setup::uninstall();

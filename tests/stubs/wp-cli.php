<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

// What the plugin calls of WP-CLI, for the static analysis: the real class
// comes with the wp binary.

declare(strict_types=1);

class WP_CLI
{
    public static function add_command(string $name, callable|object|string $callable, array $args = []): bool
    {
        return true;
    }

    public static function success(string $message): void {}
}

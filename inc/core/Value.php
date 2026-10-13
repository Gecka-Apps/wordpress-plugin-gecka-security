<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * Values read where PHP knows nothing of their type: rows of the database,
 * options, request variables, what a filter returns. Each comes out with
 * the type the code needs, as a cast would give it, an array or an object
 * giving the empty value instead of a notice.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
final class Value
{
    /**
     * An integer, 0 for what is not a number
     *
     * @param mixed $value Value read, cast when it is a scalar.
     *
     * @return int
     */
    public static function int(mixed $value): int
    {
        return is_scalar($value) ? (int) $value : 0;
    }

    /**
     * A string, empty for what is neither a scalar nor a stringable object
     *
     * @param mixed $value Value read, cast when it is a scalar or a stringable object.
     *
     * @return string
     */
    public static function string(mixed $value): string
    {
        return is_scalar($value) || $value instanceof \Stringable ? (string) $value : '';
    }

    /**
     * The strings of a list, what is not a scalar left out
     *
     * @param mixed $value A list, or anything else for none.
     *
     * @return list<string>
     */
    public static function strings(mixed $value): array
    {
        $strings = [];

        foreach (is_array($value) ? $value : [] as $item) {
            if (is_scalar($item)) {
                $strings[] = (string) $item;
            }
        }

        return $strings;
    }
}

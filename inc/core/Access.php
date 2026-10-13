<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * The addresses refused a login whatever they try: those of the blocklist,
 * and those of the countries the settings refuse, or do not allow, as Gecka
 * Geolocation tells the country of an address.
 *
 * An address whose country is unknown, a private one or one the database
 * has not, is never refused for its country: the rule would otherwise
 * refuse everyone the day the database is missing.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
final class Access
{
    /**
     * Refused for being on the blocklist.
     */
    public const ADDRESS = 'address';

    /**
     * Refused for its country.
     */
    public const COUNTRY = 'country';

    /**
     * Mode of the countries: only those listed log in.
     */
    public const ALLOW = 'allow';

    /**
     * Mode of the countries: those listed are refused.
     */
    public const DENY = 'deny';

    /**
     * Why an address is refused, if it is
     *
     * @param string   $ip        Address of the visitor.
     * @param string[] $blocklist Addresses and networks refused.
     * @param string   $mode      ALLOW, DENY, or empty when the countries are not checked.
     * @param string[] $countries Codes of the countries the mode applies to, in upper case.
     *
     * @return array{reason: string, country: string}|null The reason, ADDRESS or COUNTRY, and the country of the address when known; null when it is not refused.
     */
    public static function refusal(string $ip, array $blocklist, string $mode, array $countries): ?array
    {
        if ($ip === '') {
            return null;
        }

        if (Network::inList($ip, $blocklist)) {
            return ['reason' => self::ADDRESS, 'country' => ''];
        }

        if ($mode !== self::ALLOW && $mode !== self::DENY) {
            return null;
        }

        $country = self::country($ip);

        if ($country === '') {
            return null;
        }

        $listed = in_array($country, $countries, true);

        return ($mode === self::ALLOW ? ! $listed : $listed) ? ['reason' => self::COUNTRY, 'country' => $country] : null;
    }

    /**
     * The country of an address, as Gecka Geolocation tells it
     *
     * @param string $ip Address to look up.
     *
     * @return string Its code in upper case, empty when unknown or without Gecka Geolocation.
     */
    public static function country(string $ip): string
    {
        $record = self::geolocation() && $ip !== '' ? gecka_geolocation($ip) : null;

        return $record !== null ? strtoupper((string) $record->country()) : '';
    }

    /**
     * Whether the country of an address can be told: Gecka Geolocation is
     * active
     *
     * @return bool
     */
    public static function geolocation(): bool
    {
        return function_exists('gecka_geolocation');
    }

    /**
     * The country codes of a list typed one per line or separated by
     * commas, in upper case, each once; what is not two letters left out
     *
     * @param mixed $value A string, or a list.
     *
     * @return list<string>
     */
    public static function parseCountries(mixed $value): array
    {
        $entries = is_array($value) ? $value : preg_split('/[\s,;]+/', Value::string($value));
        $codes = array_map(static fn(mixed $code): string => strtoupper(trim(Value::string($code))), $entries ?: []);

        return array_values(array_unique(array_filter($codes, static fn(string $code): bool => (bool) preg_match('/^[A-Z]{2}$/', $code))));
    }
}

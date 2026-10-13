<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * Addresses and networks: reading them, comparing them, and the key an
 * address is watched under.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Network
{
    /**
     * Bits of an IPv6 address that identify a subscriber: a provider hands
     * out a /64 at least, and a bot rotates freely inside it.
     */
    private const IPV6_KEY_BITS = 64;

    /**
     * Shortest prefix of an IPv4 network a list accepts.
     */
    public const IPV4_MIN_BITS = 8;

    /**
     * Shortest prefix of an IPv6 network a list accepts.
     */
    public const IPV6_MIN_BITS = 16;

    /**
     * The networks that never reach a server from the Internet: a visitor
     * seen under one of them came through a proxy on the local network.
     */
    private const PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7', 'fe80::/10'];

    /**
     * An address in its canonical form, or null for anything else
     *
     * @param string $ip Address as received, with brackets, a port or a zone id, if any.
     *
     * @return string|null
     */
    public static function normalize(string $ip): ?string
    {
        $ip = trim($ip);

        // An IPv6 address may carry a zone id, and a client may send a port.
        if (str_starts_with($ip, '[')) {
            $ip = (string) preg_replace('/^\[([^\]]+)\].*$/', '$1', $ip);
        } elseif (substr_count($ip, ':') === 1) {
            $ip = (string) strstr($ip, ':', true);
        }

        $ip = (string) strstr($ip . '%', '%', true);

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $packed = inet_pton($ip);

        if ($packed === false) {
            return null;
        }

        // An IPv4 address carried in an IPv6 one, as ::ffff:203.0.113.5.
        if (strlen($packed) === 16 && substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            $packed = substr($packed, 12);
        }

        return (string) inet_ntop($packed);
    }

    /**
     * Whether an address can stand for a visitor: not empty, and neither
     * the loopback nor the unspecified address, which a server fronted by a
     * local proxy reports for everyone.
     *
     * @param string $ip A normalized address.
     *
     * @return bool
     */
    public static function isUsable(string $ip): bool
    {
        if ($ip === '' || $ip === '::' || $ip === '::1' || $ip === '0.0.0.0') {
            return false;
        }

        return ! str_starts_with($ip, '127.');
    }

    /**
     * Whether an address is a private one, as 10.0.0.0/8, 172.16.0.0/12,
     * 192.168.0.0/16 and their IPv6 counterparts
     *
     * @param string $ip A normalized address.
     *
     * @return bool
     */
    public static function isPrivate(string $ip): bool
    {
        return self::inList($ip, self::PRIVATE);
    }

    /**
     * Whether an address belongs to a network, written as an address or as
     * CIDR
     *
     * @param string $ip      A normalized address.
     * @param string $network An address or a network, as 203.0.113.0/24 or 2001:db8::/32.
     *
     * @return bool
     */
    public static function matches(string $ip, string $network): bool
    {
        [$subject, $bits] = array_pad(explode('/', trim($network), 2), 2, null);

        $subject = self::normalize((string) $subject);
        $packedIp = $subject === null ? false : inet_pton($ip);
        $packedSubject = $subject === null ? false : inet_pton($subject);

        if ($packedIp === false || $packedSubject === false || strlen($packedIp) !== strlen($packedSubject)) {
            return false;
        }

        $length = strlen($packedIp) * 8;
        $bits = $bits === null ? $length : (int) $bits;

        if ($bits < 0 || $bits > $length) {
            return false;
        }

        return self::prefix($packedIp, $bits) === self::prefix($packedSubject, $bits);
    }

    /**
     * Whether an address belongs to one of the networks of a list
     *
     * @param string   $ip       A normalized address.
     * @param string[] $networks Addresses or networks, as matches() reads them.
     *
     * @return bool
     */
    public static function inList(string $ip, array $networks): bool
    {
        foreach ($networks as $network) {
            if (self::matches($ip, $network)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The key an address is watched under: the address itself, or, for IPv6,
     * the /64 it belongs to
     *
     * @param string $ip A normalized address.
     *
     * @return string
     */
    public static function key(string $ip): string
    {
        $packed = inet_pton($ip);

        if ($packed === false || strlen($packed) !== 16) {
            return $ip;
        }

        return inet_ntop(self::prefix($packed, self::IPV6_KEY_BITS)) . '/' . self::IPV6_KEY_BITS;
    }

    /**
     * The addresses and networks of a list typed one per line or separated
     * by commas, the ill-formed ones left out
     *
     * @param mixed $value A string, or a list.
     *
     * @return string[]
     */
    public static function parseList(mixed $value): array
    {
        $entries = is_array($value) ? $value : preg_split('/[\s,;]+/', Value::string($value));
        $networks = [];

        foreach ($entries ?: [] as $entry) {
            $entry = trim(Value::string($entry));

            if ($entry === '') {
                continue;
            }

            [$address, $bits] = array_pad(explode('/', $entry, 2), 2, null);
            $address = self::normalize((string) $address);

            if ($address === null) {
                continue;
            }

            $length = strlen((string) inet_pton($address)) * 8;

            if ($bits !== null && (! ctype_digit($bits) || (int) $bits > $length)) {
                continue;
            }

            $networks[] = $bits === null ? $address : $address . '/' . (int) $bits;
        }

        return array_values(array_unique($networks));
    }

    /**
     * Whether a network spans a large part of the Internet: shorter than a
     * /8 for IPv4, a /16 for IPv6. A few such networks together cover every
     * address, which no trusted proxy or safelist entry may do.
     *
     * @param string $network An address or a network, as parseList() gives it.
     *
     * @return bool
     */
    public static function tooWide(string $network): bool
    {
        if (! str_contains($network, '/')) {
            return false;
        }

        [$address, $bits] = explode('/', $network, 2);

        return (int) $bits < (str_contains($address, ':') ? self::IPV6_MIN_BITS : self::IPV4_MIN_BITS);
    }

    /**
     * The networks of a list that are not too wide
     *
     * @param string[] $networks Networks, as parseList() gives them.
     *
     * @return string[]
     */
    public static function withoutTooWide(array $networks): array
    {
        return array_values(array_filter($networks, static fn(string $network): bool => ! self::tooWide($network)));
    }

    /**
     * The first bits of a packed address, the rest zeroed
     *
     * @param string $packed Address packed by inet_pton().
     * @param int    $bits   Leading bits kept.
     *
     * @return string
     */
    private static function prefix(string $packed, int $bits): string
    {
        $bytes = intdiv($bits, 8);
        $remainder = $bits % 8;
        $prefix = substr($packed, 0, $bytes);

        if ($remainder > 0) {
            $prefix .= chr(ord($packed[$bytes]) & (0xFF << (8 - $remainder)) & 0xFF);
            ++$bytes;
        }

        return str_pad($prefix, strlen($packed), "\0");
    }
}

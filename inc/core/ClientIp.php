<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

/**
 * The address of the visitor behind the request.
 *
 * REMOTE_ADDR is the only value the server vouches for. A forwarding header
 * is read only when the settings name it and the request comes from one of
 * the proxies the settings trust: anyone can send X-Forwarded-For, and a
 * site reading it blindly lets a bot pick the address it gets locked out
 * under, or get someone else locked out. X-Forwarded-For is read from the
 * right, past the trusted hops, so the proxy's own entry is the one that
 * counts and not what the client wrote before it.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class ClientIp
{
    /**
     * The address the server saw.
     */
    public const REMOTE_ADDR = 'remote_addr';

    /**
     * The headers a proxy may carry the address in, by the value of the
     * setting.
     */
    public const HEADERS = [
        'x_forwarded_for' => 'HTTP_X_FORWARDED_FOR',
        'x_real_ip' => 'HTTP_X_REAL_IP',
        'cf_connecting_ip' => 'HTTP_CF_CONNECTING_IP',
    ];

    /**
     * Settings naming the header, the trusted proxies and the safelist.
     *
     * @var Settings
     */
    private Settings $settings;

    /**
     * The address resolved for the request, an empty string when none is
     * usable, null while not resolved.
     *
     * @var string|null
     */
    private ?string $ip = null;

    /**
     * Keeps the settings the address is read with.
     *
     * @param Settings $settings Settings naming the header, the trusted proxies and the safelist.
     */
    public function __construct(Settings $settings)
    {
        $this->settings = $settings;
    }

    /**
     * The address of the visitor, or an empty string when the request
     * carries none that can be trusted
     *
     * @return string
     */
    public function get(): string
    {
        if ($this->ip === null) {
            $this->ip = $this->resolve();
        }

        return $this->ip;
    }

    /**
     * Whether the address can be acted upon: known, and not one a local proxy
     * gives to every visitor.
     *
     * @return bool
     */
    public function reliable(): bool
    {
        return Network::isUsable($this->get());
    }

    /**
     * Whether the visitors are hidden behind a proxy the settings do not
     * name: the address read is a private one while no proxy is trusted,
     * so a proxy on the local network stands in front of the server and
     * every visitor is seen under its address. Locking it out would lock
     * everyone out, and putting it on the safelist would let everyone in.
     *
     * @return bool
     */
    public function behindProxy(): bool
    {
        return Network::isPrivate($this->get()) && ! $this->settings->strings('trusted_proxies');
    }

    /**
     * Whether the visitor is on the machine of the server: a trusted proxy
     * gives the loopback as their address. Nobody else is seen under it, so
     * that visitor alone goes unwatched, where a loopback read with no
     * proxy would be every visitor's.
     *
     * @return bool
     */
    public function onServer(): bool
    {
        $ip = $this->get();
        $peer = Network::normalize(self::server('REMOTE_ADDR'));

        return $ip !== '' && ! Network::isUsable($ip) && $peer !== null
            && $this->settings->string('ip_source') !== self::REMOTE_ADDR
            && Network::inList($peer, $this->settings->strings('trusted_proxies'));
    }

    /**
     * Whether the visitor is on the safelist of the settings or of
     * GECKA_SECURITY_SAFELIST.
     *
     * @return bool
     */
    public function safelisted(): bool
    {
        return $this->get() !== '' && Network::inList($this->get(), array_merge($this->settings->strings('safelist'), self::constantSafelist()));
    }

    /**
     * The addresses GECKA_SECURITY_SAFELIST names in wp-config.php, for a
     * way back in that no setting can lose
     *
     * @return string[]
     */
    public static function constantSafelist(): array
    {
        return defined('GECKA_SECURITY_SAFELIST') && is_string(GECKA_SECURITY_SAFELIST) ? Network::parseList(GECKA_SECURITY_SAFELIST) : [];
    }

    /**
     * The key the visitor is watched under
     *
     * @return string
     */
    public function key(): string
    {
        return Network::key($this->get());
    }

    /**
     * Forgets the address resolved, after the settings or the request changed.
     *
     * @return void
     */
    public function flush(): void
    {
        $this->ip = null;
    }

    /**
     * Resolves the address from the request, as the settings say.
     *
     * @return string
     */
    private function resolve(): string
    {
        return self::read($this->settings->string('ip_source'), $this->settings->strings('trusted_proxies'));
    }

    /**
     * The address of the visitor of this request, read from a source and
     * trusted proxies given, as settings about to be saved would read it
     *
     * @param string   $source  Where the address is read: REMOTE_ADDR or a key of HEADERS.
     * @param string[] $proxies Addresses and networks of the trusted proxies.
     *
     * @return string The address, or an empty string when the request carries none that can be trusted.
     */
    public static function read(string $source, array $proxies): string
    {
        $peer = Network::normalize(self::server('REMOTE_ADDR'));

        if ($peer === null) {
            return '';
        }

        if (! isset(self::HEADERS[$source]) || $proxies === [] || ! Network::inList($peer, $proxies)) {
            return $peer;
        }

        $header = self::server(self::HEADERS[$source]);

        if ($header === '') {
            return '';
        }

        if ($source !== 'x_forwarded_for') {
            return Network::normalize($header) ?? '';
        }

        foreach (array_reverse(explode(',', $header)) as $hop) {
            $hop = Network::normalize($hop);

            if ($hop === null) {
                return '';
            }

            if (! Network::inList($hop, $proxies)) {
                return $hop;
            }
        }

        return '';
    }

    /**
     * A value of the server variables, as a string
     *
     * @param string $name Key of $_SERVER, as REMOTE_ADDR or HTTP_X_FORWARDED_FOR.
     *
     * @return string The value trimmed, empty when it is missing.
     */
    private static function server(string $name): string
    {
        return trim(Request::server($name));
    }
}

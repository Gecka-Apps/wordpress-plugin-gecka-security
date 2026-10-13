<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

// What the plugin calls of Gecka Geolocation, for the static analysis: the
// real functions come with that plugin, when it is installed.

declare(strict_types=1);

namespace Gecka\WP\Plugin\Geolocation {
    final class Record
    {
        public function country(): ?string
        {
            return null;
        }

        public function countryName(?string $locale = null): ?string
        {
            return null;
        }

        public function flagUrl(string $ratio = '4x3', bool $absolute = false): ?string
        {
            return null;
        }

        public function asn(): ?int
        {
            return null;
        }

        public function asOrganization(): ?string
        {
            return null;
        }
    }
}

namespace {
    function gecka_geolocation(?string $ip = null, ?string $provider = null): ?Gecka\WP\Plugin\Geolocation\Record
    {
        return null;
    }

    function gecka_geolocation_country_name(string $country, ?string $locale = null): ?string
    {
        return null;
    }

    function gecka_geolocation_flag_url(string $country, string $ratio = '4x3', bool $absolute = false): ?string
    {
        return null;
    }

    function gecka_geolocation_network_logo_url(int $asn, bool $absolute = false): ?string
    {
        return null;
    }

    /**
     * @return array{text: string, url: string|null}|null
     */
    function gecka_geolocation_credit(?string $provider = null): ?array
    {
        return null;
    }
}

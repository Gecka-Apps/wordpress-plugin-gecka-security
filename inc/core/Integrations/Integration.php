<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

use Gecka\WP\Plugin\Security\Base;
use Gecka\WP\Plugin\Security\Request;

/**
 * A protection: what it hooks into, and how it records what it saw.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
abstract class Integration extends Base
{
    /**
     * Priority of the checks on the hooks other plugins share: ahead of the
     * default, so that a refusal comes before a captcha is verified or a
     * remote service called.
     */
    public const PRIORITY = 5;

    /**
     * Whether what the protection needs is there.
     *
     * @return bool
     */
    abstract public function available(): bool;

    /**
     * The login typed, when it names an account or a reserved name, or
     * whatever it is with log_unknown_logins on; an empty string otherwise.
     * What names neither may be a password typed in the wrong field, which
     * the journal keeps only when told to.
     *
     * @param string $typed Login as typed in the form.
     *
     * @return string
     */
    protected function loginKept(string $typed): string
    {
        return $this->plugin->settings()->enabled('log_unknown_logins') ? $typed : $this->loginNamed($typed);
    }

    /**
     * The login typed, when it names an account or a reserved name; an
     * empty string otherwise, whatever log_unknown_logins says.
     *
     * @param string $typed Login as typed in the form.
     *
     * @return string
     */
    protected function loginNamed(string $typed): string
    {
        if ($typed === '') {
            return '';
        }

        return Enumeration::accountExists($typed) || $this->plugin->settings()->isReserved($typed) ? $typed : '';
    }

    /**
     * Records an event in the journal and the statistics.
     *
     * @param string      $type     One of the Events constants.
     * @param string      $username Login tried, if any.
     * @param string      $detail   A code Events::describe() words, or free text.
     * @param string|null $vector   The way in, that of the request when null.
     * @param array<string, mixed> $params What the code needs, if anything.
     *
     * @return void
     */
    protected function record(string $type, string $username = '', string $detail = '', ?string $vector = null, array $params = []): void
    {
        $ip = $this->plugin->clientIp()->get();
        $vector ??= Request::vector();

        $this->plugin->events()->record($type, $ip, $username, $vector, $detail, $params);
        $this->counted($type, $ip, $username, $vector, $detail, $params);
    }

    /**
     * Records an event as record() does, unless the journal holds the same
     * one, kind, key of the address, login, detail and parameters alike,
     * created within the last seconds given: that one is counted up
     * instead, the statistics and the action seeing every occurrence.
     *
     * @param string      $type     One of the Events constants.
     * @param int         $seconds  How far back the same event folds.
     * @param string      $username Login, if any.
     * @param string      $detail   A code Events::describe() words, or free text.
     * @param string|null $vector   The way in, that of the request when null.
     * @param array<string, mixed> $params What the code needs, if anything.
     *
     * @return void
     */
    protected function fold(string $type, int $seconds, string $username = '', string $detail = '', ?string $vector = null, array $params = []): void
    {
        $ip = $this->plugin->clientIp()->get();
        $vector ??= Request::vector();

        if (! $this->plugin->events()->bumpRecent($type, $ip, $username, $detail, $seconds, $params)) {
            $this->plugin->events()->record($type, $ip, $username, $vector, $detail, $params);
        }

        $this->counted($type, $ip, $username, $vector, $detail, $params);
    }

    /**
     * Records an event as record() does, unless the journal holds one of
     * the kind for the address since the event starting the series: that
     * one is counted up instead, the statistics and the action seeing
     * every occurrence.
     *
     * @param string      $type     One of the Events constants.
     * @param string      $after    The kind of event starting the series.
     * @param string      $username Login tried, if any.
     * @param string      $detail   A code Events::describe() words, or free text.
     * @param string|null $vector   The way in, that of the request when null.
     * @param array<string, mixed> $params What the code needs, if anything.
     *
     * @return void
     */
    protected function bump(string $type, string $after, string $username = '', string $detail = '', ?string $vector = null, array $params = []): void
    {
        $ip = $this->plugin->clientIp()->get();
        $vector ??= Request::vector();

        if (! $this->plugin->events()->bump($type, $ip, $after)) {
            $this->plugin->events()->record($type, $ip, $username, $vector, $detail, $params);
        }

        $this->counted($type, $ip, $username, $vector, $detail, $params);
    }

    /**
     * Counts an event in the statistics and tells the listeners, whether
     * the journal took a row for it or counted one up.
     *
     * @param string               $type     One of the Events constants.
     * @param string               $ip       Address of the visitor, empty when unknown.
     * @param string               $username Login tried, if any.
     * @param string               $vector   The way in.
     * @param string               $detail   A code Events::describe() words, or free text.
     * @param array<string, mixed> $params   What the code needs, if anything.
     *
     * @return void
     */
    protected function counted(string $type, string $ip, string $username = '', string $vector = '', string $detail = '', array $params = []): void
    {
        $this->plugin->stats()->record($vector, $type);

        /**
         * Fires when a protection recorded an event.
         *
         * @param string $type     The kind of event: failed, reserved, lockout, blocked, enumeration, login, breached, account, limited, refused.
         * @param string $ip       Address of the visitor, empty when unknown.
         * @param string $username Login tried, if any.
         * @param string $vector   The way in: login_form, xmlrpc, rest, woocommerce, other, author, rest_users.
         * @param string $detail   A code, as lockout.long or account.role_set, or free text.
         * @param array<string, mixed> $params The parameters of the code.
         */
        do_action('gecka_security_event', $type, $ip, $username, $vector, $detail, $params);
    }

    /**
     * Drops the header advertising the pingback endpoint of XML-RPC.
     *
     * @param mixed $headers Headers of the response, by name.
     *
     * @return mixed The headers, X-Pingback left out.
     */
    public function dropPingbackHeader(mixed $headers): mixed
    {
        if (is_array($headers)) {
            unset($headers['X-Pingback']);
        }

        return $headers;
    }
}

<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

use Gecka\WP\Plugin\Security\Integrations\LastLogin;
use Gecka\WP\Plugin\Security\Integrations\NewNetworks;
use Gecka\WP\Plugin\Security\Integrations\Pwned;

/**
 * The journal in the personal data tools of WordPress: the rows carrying
 * the login or the e-mail address of a person go out with their export,
 * and away with their erasure, together with the verdict kept on their
 * password, the date of their last login and the networks their account
 * logged in from. Rows are matched on the login typed, whatever its case,
 * which is what a visitor leaves behind, whether an account exists or not. The
 * address goes out with the logins the person made; an attempt on their
 * login may be someone else's, so its address stays here.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Privacy
{
    /**
     * Rows handled per call of the tools.
     */
    private const PER_PAGE = 500;

    /**
     * The kinds of event the person made themselves: their address is
     * theirs.
     */
    private const OWN = [Events::LOGIN, Events::BREACHED];

    /**
     * The plugin instance.
     *
     * @var Plugin
     */
    private Plugin $plugin;

    /**
     * Keeps the plugin whose journal the tools read.
     *
     * @param Plugin $plugin The plugin instance.
     */
    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    /**
     * Adds the exporter of the journal.
     *
     * @param mixed $exporters Exporters of the personal data tools, by id.
     *
     * @return mixed The exporters, that of the plugin added when they are an array.
     */
    public function exporters(mixed $exporters): mixed
    {
        if (is_array($exporters)) {
            $exporters['gecka-security'] = ['exporter_friendly_name' => __('Gecka Security', 'gecka-security'), 'callback' => [$this, 'export']];
        }

        return $exporters;
    }

    /**
     * Adds the eraser of the journal.
     *
     * @param mixed $erasers Erasers of the personal data tools, by id.
     *
     * @return mixed The erasers, that of the plugin added when they are an array.
     */
    public function erasers(mixed $erasers): mixed
    {
        if (is_array($erasers)) {
            $erasers['gecka-security'] = ['eraser_friendly_name' => __('Gecka Security', 'gecka-security'), 'callback' => [$this, 'erase']];
        }

        return $erasers;
    }

    /**
     * The journal rows of a person, a page at a time, the date of their
     * last login and the networks their account logged in from
     *
     * @param string $email E-mail address of the person.
     * @param int    $page  Page the tool asks for, from 1.
     *
     * @return array{data: array<int, array{group_id: string, group_label: string, group_description: string, item_id: string, data: array<int, array{name: string, value: string}>}>, done: bool}
     */
    public function export(string $email, int $page = 1): array
    {
        $rows = $this->plugin->events()->entries(max(1, $page), self::PER_PAGE, ['username' => self::logins($email)]);
        $data = [];

        foreach ($rows as $row) {
            $item = [
                ['name' => __('Date', 'gecka-security'), 'value' => Scope::dateTime((int) strtotime(Value::string($row->created) . ' UTC'))],
                ['name' => __('Event', 'gecka-security'), 'value' => Events::typeLabel(Value::string($row->type))],
                ['name' => __('Way in', 'gecka-security'), 'value' => Events::vectorLabel(Value::string($row->way))],
                ['name' => __('Login', 'gecka-security'), 'value' => Value::string($row->username)],
            ];

            if (in_array(Value::string($row->type), self::OWN, true)) {
                $item[] = ['name' => __('Address', 'gecka-security'), 'value' => Value::string($row->ip)];
            }

            // Who made an account change is someone else: left out.
            if (Value::string($row->detail) !== '') {
                $item[] = ['name' => __('Detail', 'gecka-security'), 'value' => Events::describe($row, false)];
            }

            if (Value::int($row->hits ?? 1) > 1) {
                $item[] = ['name' => __('Times', 'gecka-security'), 'value' => number_format_i18n(Value::int($row->hits))];
            }

            $data[] = [
                'group_id' => 'gecka-security',
                'group_label' => __('Security journal', 'gecka-security'),
                'group_description' => __('The logins, the refusals and the account changes Gecka Security recorded for this person. The address goes with the logins they made; an attempt on their login may be someone else\'s, its address is not given.', 'gecka-security'),
                'item_id' => 'gecka-security-event-' . Value::int($row->id),
                'data' => $item,
            ];
        }

        $user = get_user_by('email', $email);

        // The last login and the networks the account logged in from go
        // with the first page.
        if ($page <= 1 && $user instanceof \WP_User) {
            $last = LastLogin::time($user->ID);

            if ($last > 0) {
                $data[] = [
                    'group_id' => 'gecka-security-last-login',
                    'group_label' => __('Last login', 'gecka-security'),
                    'group_description' => __('The date of the last login of the account, which Gecka Security keeps for the administrators of the site.', 'gecka-security'),
                    'item_id' => 'gecka-security-last-login',
                    'data' => [
                        ['name' => __('Date', 'gecka-security'), 'value' => Scope::dateTime($last)],
                    ],
                ];
            }

            foreach (NewNetworks::networks($user->ID) as $asn => $network) {
                $data[] = [
                    'group_id' => 'gecka-security-networks',
                    'group_label' => __('Networks logged in from', 'gecka-security'),
                    'group_description' => __('The networks the account logged in from, which Gecka Security keeps to tell the person about a login from a new one.', 'gecka-security'),
                    'item_id' => 'gecka-security-network-' . $asn,
                    'data' => [
                        ['name' => __('Network', 'gecka-security'), 'value' => trim($network['name'] . ' AS' . $asn)],
                        ['name' => __('Country', 'gecka-security'), 'value' => Events::countryName($network['country'])],
                        ['name' => __('Last seen', 'gecka-security'), 'value' => Scope::dateTime($network['seen'])],
                    ],
                ];
            }
        }

        return ['data' => $data, 'done' => count($rows) < self::PER_PAGE];
    }

    /**
     * Deletes the journal rows of a person, the verdict kept on the password
     * of their account, the date of its last login and the networks it
     * logged in from, and takes their login out of the changes they made on
     * other accounts.
     *
     * @param string $email E-mail address of the person.
     * @param int    $page  Page the tool asks for; unused, every row goes in one call.
     *
     * @return array{items_removed: int, items_retained: bool, messages: string[], done: bool}
     */
    public function erase(string $email, int $page = 1): array
    {
        $logins = self::logins($email);
        $removed = $this->plugin->events()->deleteByLogin($logins) + $this->plugin->events()->forgetActor($logins);
        $user = get_user_by('email', $email);

        if ($user instanceof \WP_User) {
            foreach ([Pwned::META, LastLogin::META, NewNetworks::META] as $meta) {
                $removed += (int) delete_user_meta($user->ID, $meta);
            }
        }

        return ['items_removed' => $removed, 'items_retained' => false, 'messages' => [], 'done' => true];
    }

    /**
     * What a person may have typed as a login: their e-mail address, and
     * the login of their account when they have one
     *
     * @param string $email E-mail address of the person.
     *
     * @return string[]
     */
    private static function logins(string $email): array
    {
        $logins = [$email];
        $user = get_user_by('email', $email);

        if ($user instanceof \WP_User) {
            $logins[] = $user->user_login;
        }

        return array_values(array_unique(array_filter($logins)));
    }
}

<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Integrations;

use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Value;

/**
 * What changes on the accounts, in the journal: a creation, a role set,
 * added or removed, an e-mail address or a password changed, a deletion, a
 * super administrator granted or revoked, each with who did it. An attacker
 * who gets in creates a second administrator to stay: an administrator
 * created or promoted, or a super administrator granted, is also mailed to
 * the address of the site.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Accounts extends Integration
{
    /**
     * The role whose creation or grant is mailed.
     */
    private const ADMINISTRATOR = 'administrator';

    /**
     * An account created as administrator, for alert().
     */
    private const ALERT_CREATED = 'created';

    /**
     * An account given the administrator role, for alert().
     */
    private const ALERT_PROMOTED = 'promoted';

    /**
     * An account made super administrator of the network, for alert().
     */
    private const ALERT_SUPER_ADMIN = 'super_admin';

    /**
     * Who made a change when WP-CLI did: no login carries a colon.
     */
    public const CLI = ':cli';

    /**
     * Who made a change, once the data of that person was erased: no login
     * carries a colon.
     */
    public const ERASED = ':erased';

    /**
     * The roles added or removed, held back until the request ends, since
     * WordPress adds and removes roles on its way to setting one, and
     * when creating an account: those cases make one line each, not
     * three. The lines of another change flush them first, in order.
     *
     * @var array<int, array<int, array{string, string, array<string, mixed>, bool}>> Login, code, parameters and whether to alert, by account.
     */
    private static array $pending = [];

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
     * Hooks the account changes up, when they are logged or mailed.
     *
     * @return void
     */
    public function setup(): void
    {
        $settings = $this->plugin->settings();

        if (! $settings->enabled('log_accounts') && ! $settings->enabled('alert_admins')) {
            return;
        }

        add_action('user_register', [$this, 'registered'], self::PRIORITY);
        add_action('set_user_role', [$this, 'roleSet'], self::PRIORITY, 3);
        add_action('add_user_role', [$this, 'roleAdded'], self::PRIORITY, 2);
        add_action('remove_user_role', [$this, 'roleRemoved'], self::PRIORITY, 2);
        add_action('profile_update', [$this, 'updated'], self::PRIORITY, 2);
        add_action('after_password_reset', [$this, 'reset'], self::PRIORITY);

        if (is_multisite()) {
            add_action('granted_super_admin', [$this, 'superAdminGranted'], self::PRIORITY);
            add_action('revoked_super_admin', [$this, 'superAdminRevoked'], self::PRIORITY);
        }
        add_action('deleted_user', [$this, 'deleted'], self::PRIORITY, 3);
        add_action('shutdown', [$this, 'flush'], 0);
    }

    /**
     * Records an account created, the role changes held back for it
     * dropped, and mails the alert when it is an administrator.
     *
     * @param mixed $id Id of the new account.
     *
     * @return void
     */
    public function registered(mixed $id): void
    {
        $user = get_userdata(Value::int($id));

        if (! $user instanceof \WP_User) {
            return;
        }

        unset(self::$pending[$user->ID]);
        $this->note($user->user_login, 'account.created', ['roles' => array_values($user->roles)]);

        if (in_array(self::ADMINISTRATOR, $user->roles, true)) {
            $this->alert($user, self::ALERT_CREATED);
        }
    }

    /**
     * A role set in place of the others. WordPress sets the role of a new
     * account the same way, with no former role: that case is held back
     * and the creation that follows takes it over; an account that had no
     * role and is given one keeps its line, and its alert.
     *
     * @param mixed $id   Id of the account.
     * @param mixed $role Role set.
     * @param mixed $old  Roles the account had before.
     *
     * @return void
     */
    public function roleSet(mixed $id, mixed $role, mixed $old): void
    {
        $old = array_values(array_filter((array) $old, 'is_string'));
        $user = get_userdata(Value::int($id));

        if (! $user instanceof \WP_User) {
            return;
        }

        unset(self::$pending[$user->ID]);

        if (! $old) {
            self::$pending[$user->ID][] = [$user->user_login, 'account.role_set_none', ['role' => Value::string($role), 'actor' => self::actor()], $role === self::ADMINISTRATOR];

            return;
        }

        $this->note($user->user_login, 'account.role_set', ['role' => Value::string($role), 'old' => $old]);

        if ($role === self::ADMINISTRATOR && ! in_array(self::ADMINISTRATOR, $old, true)) {
            $this->alert($user, self::ALERT_PROMOTED);
        }
    }

    /**
     * Holds back a role added, until the request ends or another change is
     * noted.
     *
     * @param mixed $id   Id of the account.
     * @param mixed $role Role added.
     *
     * @return void
     */
    public function roleAdded(mixed $id, mixed $role): void
    {
        $user = get_userdata(Value::int($id));

        if (! $user instanceof \WP_User) {
            return;
        }

        self::$pending[$user->ID][] = [$user->user_login, 'account.role_added', ['role' => Value::string($role), 'actor' => self::actor()], $role === self::ADMINISTRATOR];
    }

    /**
     * Holds back a role removed, until the request ends or another change
     * is noted.
     *
     * @param mixed $id   Id of the account.
     * @param mixed $role Role removed.
     *
     * @return void
     */
    public function roleRemoved(mixed $id, mixed $role): void
    {
        $user = get_userdata(Value::int($id));

        if ($user instanceof \WP_User) {
            self::$pending[$user->ID][] = [$user->user_login, 'account.role_removed', ['role' => Value::string($role), 'actor' => self::actor()], false];
        }
    }

    /**
     * An e-mail address or a password changed.
     *
     * @param mixed $id  Id of the account.
     * @param mixed $old The account as it was.
     *
     * @return void
     */
    public function updated(mixed $id, mixed $old): void
    {
        $user = get_userdata(Value::int($id));

        if (! $user instanceof \WP_User || ! $old instanceof \WP_User) {
            return;
        }

        if ($user->user_email !== $old->user_email) {
            $this->note($user->user_login, 'account.email', ['from' => (string) $old->user_email, 'to' => (string) $user->user_email]);
        }

        if ($user->user_pass !== $old->user_pass) {
            $this->note($user->user_login, 'account.password');
        }
    }

    /**
     * Records a password reset through the lost-password form, made by the
     * person.
     *
     * @param mixed $user The account whose password was reset.
     *
     * @return void
     */
    public function reset(mixed $user): void
    {
        if ($user instanceof \WP_User) {
            $this->note($user->user_login, 'account.reset', [], false);
        }
    }

    /**
     * Records an account deleted.
     *
     * @param mixed $id       Id of the account deleted, logged when the account is not given.
     * @param mixed $reassign Id of the account its content went to, or null; unused.
     * @param mixed $user     The account as it was.
     *
     * @return void
     */
    public function deleted(mixed $id, mixed $reassign, mixed $user): void
    {
        $this->note($user instanceof \WP_User ? $user->user_login : Value::string($id), 'account.deleted');
    }

    /**
     * An account made super administrator of the network: the highest
     * right there is, noted and mailed as a new administrator is.
     *
     * @param mixed $id Id of the account.
     *
     * @return void
     */
    public function superAdminGranted(mixed $id): void
    {
        $user = get_userdata(Value::int($id));

        if ($user instanceof \WP_User) {
            $this->note($user->user_login, 'account.super_admin_granted');
            $this->alert($user, self::ALERT_SUPER_ADMIN);
        }
    }

    /**
     * Records the super administrator right of the network taken from an
     * account.
     *
     * @param mixed $id Id of the account.
     *
     * @return void
     */
    public function superAdminRevoked(mixed $id): void
    {
        $user = get_userdata(Value::int($id));

        if ($user instanceof \WP_User) {
            $this->note($user->user_login, 'account.super_admin_revoked');
        }
    }

    /**
     * Writes the role changes held back, and mails the alert of those that
     * make an administrator.
     *
     * @return void
     */
    public function flush(): void
    {
        $pending = self::$pending;
        self::$pending = [];

        foreach ($pending as $id => $notes) {
            foreach ($notes as [$login, $code, $params, $alert]) {
                $this->note($login, $code, $params, false);
                $user = $alert ? get_userdata((int) $id) : false;

                if ($user instanceof \WP_User) {
                    $this->alert($user, self::ALERT_PROMOTED);
                }
            }
        }
    }

    /**
     * Writes a change in the journal, after the roles held back.
     *
     * @param string               $login  Login of the account changed.
     * @param string               $code   The change, as account.role_set.
     * @param array<string, mixed> $params What the code needs.
     * @param bool                 $byWhom Whether to add who is making the change now; a change held back carries its own, and a reset is the person's.
     *
     * @return void
     */
    private function note(string $login, string $code, array $params = [], bool $byWhom = true): void
    {
        if (! $this->plugin->settings()->enabled('log_accounts')) {
            return;
        }

        $this->flush();

        if ($byWhom) {
            $params['actor'] = self::actor();
        }

        $this->record(Events::ACCOUNT, $login, $code, params: $params);
    }

    /**
     * Mails the address of the site, or of the network, about an
     * administrator created or promoted, or a super administrator granted.
     *
     * @param \WP_User $user The account created or promoted.
     * @param string   $what What happened: one of the ALERT_ constants.
     *
     * @return void
     */
    private function alert(\WP_User $user, string $what): void
    {
        if (! $this->plugin->settings()->enabled('alert_admins')) {
            return;
        }

        $site = Scope::name();
        $actor = Events::actorLabel(self::actor());
        $lines = [
            match ($what) {
                /* translators: 1: login, 2: who did it, 3: site name */
                self::ALERT_CREATED => sprintf(__('The account %1$s was created as administrator by %2$s on %3$s.', 'gecka-security'), $user->user_login, $actor, $site),
                /* translators: 1: login, 2: who did it, 3: site name */
                self::ALERT_SUPER_ADMIN => sprintf(__('The account %1$s was made super administrator of the network by %2$s on %3$s.', 'gecka-security'), $user->user_login, $actor, $site),
                /* translators: 1: login, 2: who did it, 3: site name */
                default => sprintf(__('The account %1$s was made administrator by %2$s on %3$s.', 'gecka-security'), $user->user_login, $actor, $site),
            },
            /* translators: %s: IP address */
            sprintf(__('From the address: %s', 'gecka-security'), $this->plugin->clientIp()->get() ?: __('unknown', 'gecka-security')),
            /* translators: %s: date and time */
            sprintf(__('On: %s', 'gecka-security'), Scope::dateTime()),
            '',
            __('If nobody you know did this, change the passwords of the administrators and look at the security journal.', 'gecka-security'),
            Scope::network() ? network_admin_url('users.php') : admin_url('users.php?role=administrator'),
        ];

        /* translators: 1: site name, 2: login */
        wp_mail(Scope::adminEmail(), sprintf(__('[%1$s] New administrator: %2$s', 'gecka-security'), $site, $user->user_login), implode("\n", $lines));
    }

    /**
     * Who is doing it: the account logged in, WP-CLI, or nobody, as on
     * the registration and reset forms
     *
     * @return string
     */
    private static function actor(): string
    {
        $user = wp_get_current_user();

        if ($user->exists()) {
            return $user->user_login;
        }

        if (defined('WP_CLI') && WP_CLI) {
            return self::CLI;
        }

        return '';
    }
}

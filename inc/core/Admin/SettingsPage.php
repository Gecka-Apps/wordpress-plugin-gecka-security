<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Admin;

use Gecka\WP\Plugin\Security\Access;
use Gecka\WP\Plugin\Security\Scope;
use Gecka\WP\AdminMenu\Menus;
use Gecka\WP\AdminMenu\Tab;
use Gecka\WP\Plugin\Security\Base;
use Gecka\WP\Plugin\Security\Events;
use Gecka\WP\Plugin\Security\Integrations\Headers;
use Gecka\WP\Plugin\Security\Network;
use Gecka\WP\Plugin\Security\Settings;
use Gecka\WP\Plugin\Security\Value;
use Gecka\WP\Plugin\Security\Request;

/**
 * The screens of the plugin: the statistics, the journal and the addresses
 * locked out under the shared Security menu, each as a tab another plugin
 * may add to; the settings under Settings > Security; and the actions their
 * buttons post.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class SettingsPage extends Base
{
    use Controls;

    /**
     * Slug of the shared menu. A plugin declaring the same slug shares it.
     */
    public const MENU = 'security';

    /**
     * Slug of the settings page, under Settings.
     */
    public const PAGE = 'gecka-security';

    /**
     * Slugs of the pages of the menu, by the name their tab is known under
     * in the plugin.
     */
    public const PAGES = [
        'stats' => 'security-stats',
        'events' => 'security-journal',
        'lockouts' => 'security-lockouts',
    ];

    /**
     * Slug of the tab of the plugin on each shared page.
     */
    public const TAB = 'gecka-security';

    /**
     * Periods offered on the statistics tab, in days.
     */
    public const PERIODS = [7, 30, 90, 365];

    /**
     * Settings the text suggested for the privacy policy depends on, each a
     * flag or a number.
     */
    private const PRIVACY_SETTINGS = ['log_logins', 'log_unknown_logins', 'log_accounts', 'pwned_passwords', 'alert_new_network', 'events_days'];

    /**
     * The Journal tab, set up when its page loads.
     *
     * @var EventsView|null
     */
    private ?EventsView $events = null;

    /**
     * The Lockouts tab, set up when its page loads.
     *
     * @var LockoutsView|null
     */
    private ?LockoutsView $lockouts = null;

    /**
     * Hooks the screens, the setting, the actions the buttons post, the
     * screen options, the links of the plugin row and the notice asking to
     * check the privacy policy.
     *
     * @return void
     */
    public function setup(): void
    {
        add_action('admin_init', [$this, 'registerSetting']);
        add_filter('option_page_capability_' . self::PAGE, static fn(): string => self::capability('settings'));
        add_action('network_admin_edit_' . self::PAGE, [$this, 'saveNetwork']);
        add_action('admin_init', [$this, 'privacyPolicy']);
        add_action('admin_post_gecka_security_reset_stats', [$this, 'resetStats']);
        add_action('admin_post_gecka_security_clear_events', [$this, 'clearEvents']);
        add_action('admin_post_gecka_security_unlock_all', [$this, 'unlockAll']);
        add_action('admin_post_gecka_security_safelist_me', [$this, 'safelistMe']);
        add_action('admin_post_gecka_security_reset_settings', [$this, 'resetSettings']);
        // The first save adds the option: the defaults stand for what it held.
        add_action('add_option_' . Settings::OPTION, fn(string $option, mixed $value) => $this->privacyOnSave([], $value), 10, 2);
        add_action('add_site_option_' . Settings::OPTION, fn(string $option, mixed $value) => $this->privacyOnSave([], $value), 10, 2);
        add_action('update_option_' . Settings::OPTION, fn(mixed $old, mixed $value) => $this->privacyOnSave($old, $value), 10, 2);
        add_action('update_site_option_' . Settings::OPTION, fn(string $option, mixed $value, mixed $old) => $this->privacyOnSave($old, $value), 10, 3);
        add_filter('set_screen_option_' . EventsView::PER_PAGE_OPTION, static fn($keep, $option, $value) => min(999, max(1, Value::int($value))), 10, 3);
        add_filter('set_screen_option_' . LockoutsView::PER_PAGE_OPTION, static fn($keep, $option, $value) => min(999, max(1, Value::int($value))), 10, 3);
        add_filter('plugin_action_links_' . plugin_basename($this->plugin->file()), [$this, 'actionLinks']);
        add_filter('network_admin_plugin_action_links_' . plugin_basename($this->plugin->file()), [$this, 'actionLinks']);

        // On init and not before: the titles are translated, and WordPress
        // loads a text domain from init on. Ahead of the default priority: the
        // plugin that owns the Security menu names it, the guests add to it.
        if (is_admin()) {
            add_action('init', [$this, 'declare'], 5);
        }
    }

    /**
     * Asks, in the notice of a save, to check the privacy policy when a
     * setting the text suggested for it depends on changed. The notice says
     * the settings were saved when nothing else is to be told, since
     * WordPress says it only when no notice is registered.
     *
     * @param mixed $old   Settings before the save, the defaults filling the gaps.
     * @param mixed $value Settings saved, the defaults filling the gaps.
     *
     * @return void
     */
    private function privacyOnSave(mixed $old, mixed $value): void
    {
        $defaults = $this->plugin->settings()->defaults();
        $old = array_merge($defaults, is_array($old) ? $old : []);
        $value = array_merge($defaults, is_array($value) ? $value : []);

        if (! self::privacyChanged($old, $value)) {
            return;
        }

        if (get_settings_errors()) {
            add_settings_error(Settings::OPTION, 'privacy_policy', self::privacyNotice(), 'info');
        } else {
            add_settings_error(Settings::OPTION, 'settings_updated', __('Settings saved.', 'gecka-security') . ' ' . self::privacyNotice(), 'success');
        }
    }

    /**
     * Whether a setting the text suggested for the privacy policy depends
     * on differs between two sets of settings
     *
     * @param array<mixed> $old   Settings before, every one of PRIVACY_SETTINGS set.
     * @param array<mixed> $value Settings after, every one of PRIVACY_SETTINGS set.
     *
     * @return bool
     */
    private static function privacyChanged(array $old, array $value): bool
    {
        foreach (self::PRIVACY_SETTINGS as $key) {
            if (Value::int($old[$key] ?? 0) !== Value::int($value[$key] ?? 0)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The sentence asking to check the privacy policy, with a link to its
     * guide
     *
     * @return string HTML, escaped.
     */
    private static function privacyNotice(): string
    {
        return wp_kses(
            sprintf(
                Scope::network()
                    /* translators: %s: address of the privacy policy guide */
                    ? __('Check that the privacy policies of the sites still match the new settings: the <a href="%s">text suggested for them</a> has changed.', 'gecka-security')
                    /* translators: %s: address of the privacy policy guide */
                    : __('Check that the privacy policy of the site still matches the new settings: the <a href="%s">text suggested for it</a> has changed.', 'gecka-security'),
                esc_url(admin_url('options-privacy.php?tab=policyguide')),
            ),
            ['a' => ['href' => []]],
        );
    }

    /**
     * Declares the menu, its pages and the settings page to the shared
     * admin menu. The menu and the pages are shared: another plugin naming
     * them adds its own tabs beside those of this plugin.
     *
     * @return void
     */
    public function declare(): void
    {
        $styles = function (): void {
            add_action('admin_enqueue_scripts', [Styles::class, 'enqueue']);
            add_action('all_admin_notices', [$this, 'warnUnprotected']);
        };

        $menu = Menus::menu(self::MENU)
            ->title(__('Security', 'gecka-security'))
            ->icon('dashicons-shield')
            ->position(71)
            ->network(Scope::network());

        $menu->page(self::PAGES['stats'])
            ->title(__('Statistics', 'gecka-security'))
            ->order(10)
            ->wide()
            ->tab(self::TAB)
            ->title(__('Security', 'gecka-security'))
            ->capability(self::capability('stats'))
            ->order(0)
            ->load($styles)
            ->render(fn() => (new StatsView($this->plugin))->render());

        $menu->page(self::PAGES['events'])
            ->title(__('Journal', 'gecka-security'))
            ->order(20)
            ->wide()
            ->tab(self::TAB)
            ->title(__('Security', 'gecka-security'))
            ->capability(self::capability('events'))
            ->order(0)
            ->load(function () use ($styles): void {
                $styles();
                $this->events = new EventsView($this->plugin);
                $this->events->load();
            })
            ->render(fn() => $this->events?->render());

        $menu->page(self::PAGES['lockouts'])
            ->title(__('Lockouts', 'gecka-security'))
            ->order(30)
            ->wide()
            ->tab(self::TAB)
            ->title(__('Security', 'gecka-security'))
            ->capability(self::capability('lockouts'))
            ->order(0)
            ->badge(fn(): int => $this->plugin->lockouts()->countActive())
            ->load(function () use ($styles): void {
                $styles();
                $this->lockouts = new LockoutsView($this->plugin, $this);
                $this->lockouts->load();
            })
            ->render(fn() => $this->lockouts?->render());

        Menus::options(self::PAGE)
            ->title(__('Security', 'gecka-security'))
            ->network(Scope::network())
            ->tab('settings')
            ->title(__('Settings', 'gecka-security'))
            ->capability(self::capability('settings'))
            ->load(function (Tab $tab) use ($styles): void {
                $styles();
                $screen = get_current_screen();

                if ($screen) {
                    Help::add($screen);
                }
            })
            ->render(fn() => $this->renderSettings());
    }

    /**
     * Capability a screen asks for, through the gecka_security_capability
     * filter: manage_options everywhere, manage_network_options on a
     * network, unless a developer opens a screen to someone else. The
     * journal and the lockouts hold the addresses of the visitors, which
     * is why nothing is open by default.
     *
     * @param string $screen stats, events, lockouts or settings.
     *
     * @return string
     */
    public static function capability(string $screen): string
    {
        $screen = isset(self::PAGES[$screen]) ? $screen : 'settings';

        /**
         * Filters the capability a screen of the plugin asks for.
         *
         * @param string $capability manage_options, or manage_network_options on a network.
         * @param string $screen     stats: the statistics page, the dashboard widget and the button resetting
         *                           the statistics; events: the journal, its deletions and the button clearing
         *                           it; lockouts: the lockouts page and the releases; settings: the settings
         *                           tab, the safelist button, the button restoring the defaults, the
         *                           safelist bulk action of the lockouts and the save from the network admin.
         */
        $capability = (string) apply_filters('gecka_security_capability', Scope::capability(), $screen);

        return $capability !== '' ? $capability : Scope::capability();
    }

    /**
     * Says on the pages of the plugin when the brute-force protection is on
     * but cannot act: the address of the visitor cannot be read, or every
     * visitor comes through a proxy the settings do not name. Site Health
     * says it too, but nobody reads Site Health every day.
     *
     * @return void
     */
    public function warnUnprotected(): void
    {
        $ip = $this->plugin->clientIp();

        // A visitor on the machine of the server is the only one seen under the loopback.
        if (! $this->plugin->settings()->enabled('bruteforce') || $ip->onServer() || ($ip->reliable() && ! $ip->behindProxy())) {
            return;
        }

        wp_admin_notice(
            sprintf(
                '%s <a href="%s">%s</a>',
                esc_html(
                    $ip->behindProxy()
                        /* translators: %s: IP address */
                        ? sprintf(__('Nothing is locked out: every visitor is seen under %s, the address of a proxy the settings do not name. Name the header that proxy sends and list its address among the trusted proxies.', 'gecka-security'), $ip->get())
                        : __('Nothing is locked out: the address of the visitor cannot be read with the current settings. Check the header the proxy sends and the trusted proxies.', 'gecka-security'),
                ),
                esc_url(admin_url('site-health.php')),
                esc_html__('Site Health says more.', 'gecka-security'),
            ),
            ['type' => 'warning', 'paragraph_wrap' => true],
        );
    }

    /**
     * Offers a paragraph for the privacy policy of the site, worded after
     * the settings of PRIVACY_SETTINGS.
     *
     * @return void
     */
    public function privacyPolicy(): void
    {
        $days = $this->plugin->settings()->int('events_days');

        wp_add_privacy_policy_content(
            __('Gecka Security', 'gecka-security'),
            wp_kses_post(
                wpautop(
                    sprintf(
                        $this->plugin->settings()->enabled('log_logins')
                            /* translators: %s: number of days */
                            ? _n('To protect the accounts of this site, the logins, failed or successful, are recorded on this server, with no external service: the IP address of the visitor, the login when it names an account, the way the login came in and the time. An address that fails too many logins is refused for a while. These records, and the daily counts of the successful logins by country, network and system, are deleted after %s day; only the daily counts of the failed attempts, with no address, are kept longer.', 'To protect the accounts of this site, the logins, failed or successful, are recorded on this server, with no external service: the IP address of the visitor, the login when it names an account, the way the login came in and the time. An address that fails too many logins is refused for a while. These records, and the daily counts of the successful logins by country, network and system, are deleted after %s days; only the daily counts of the failed attempts, with no address, are kept longer.', $days, 'gecka-security')
                            /* translators: %s: number of days */
                            : _n('To protect the accounts of this site, the logins that fail are recorded on this server, with no external service: the IP address of the visitor, the login tried when it names an account, the way the login came in and the time. An address that fails too many logins is refused for a while. These records are deleted after %s day; only daily counts, with no address, are kept longer.', 'To protect the accounts of this site, the logins that fail are recorded on this server, with no external service: the IP address of the visitor, the login tried when it names an account, the way the login came in and the time. An address that fails too many logins is refused for a while. These records are deleted after %s days; only daily counts, with no address, are kept longer.', $days, 'gecka-security'),
                        number_format_i18n($days),
                    ) . ($this->plugin->settings()->enabled('log_unknown_logins') ? ' ' . __('The login of a failed attempt is recorded even when it names no account.', 'gecka-security') : '')
                    . ($this->plugin->settings()->enabled('log_accounts') ? ' ' . __('The changes made to the accounts are recorded too, with who made them: a creation, a role, an e-mail address, the old one and the new, a password changed, a deletion.', 'gecka-security') : '')
                    . ($this->plugin->settings()->enabled('alert_new_network') ? "\n\n" . __('For an administrator, the networks their account logged in from are kept with it, with their country and the date last seen, so that a login from a new network is mailed to them.', 'gecka-security') : '')
                    . ($this->plugin->settings()->enabled('pwned_passwords') ? "\n\n" . __('When a password is set or used to log in, five characters of a hash of it are sent to the Have I Been Pwned service, to tell whether it appears in known data breaches; the password itself, the login and the address of the visitor are not sent.', 'gecka-security') : ''),
                ),
            ),
        );
    }

    /**
     * Url of a screen of the plugin
     *
     * @param string               $screen stats, events, lockouts or settings.
     * @param array<string, mixed> $args   Query arguments added to the address.
     *
     * @return string
     */
    public static function url(string $screen = 'stats', array $args = []): string
    {
        if ($screen === 'settings') {
            return Menus::options(self::PAGE)->url(null, $args);
        }

        return Menus::menu(self::MENU)->page(self::PAGES[$screen] ?? self::PAGES['stats'])->url(self::TAB, $args);
    }

    /**
     * Slug a GET form of a screen posts as its page, which is the slug of
     * the menu for its first page
     *
     * @param string $screen stats, events or lockouts.
     *
     * @return string
     */
    public static function pageSlug(string $screen): string
    {
        $query = [];
        wp_parse_str((string) wp_parse_url(self::url($screen), PHP_URL_QUERY), $query);

        return is_string($query['page'] ?? null) ? $query['page'] : (self::PAGES[$screen] ?? '');
    }

    /**
     * Registers the option of the settings, cleaned by Settings::sanitize().
     *
     * @return void
     */
    public function registerSetting(): void
    {
        register_setting(
            self::PAGE,
            Settings::OPTION,
            [
                'type' => 'array',
                'sanitize_callback' => [$this->plugin->settings(), 'sanitize'],
            ],
        );
    }

    /**
     * Adds a link to the settings in the row of the plugin.
     *
     * @param array<int|string, string> $links Links of the row of the plugin.
     *
     * @return array<int|string, string> The links, that of the settings first.
     */
    public function actionLinks(array $links): array
    {
        return array_merge(
            ['settings' => sprintf('<a href="%s">%s</a>', esc_url(self::url('settings')), esc_html__('Settings', 'gecka-security'))],
            $links,
        );
    }

    /**
     * Drops the counters of the statistics and of the origins, then goes
     * back to the statistics.
     *
     * @return void
     */
    public function resetStats(): void
    {
        $this->authorize('gecka_security_reset_stats', 'stats');
        $this->plugin->stats()->reset();
        $this->plugin->origins()->reset();

        wp_safe_redirect(self::url('stats', ['reset' => 'stats']));
        exit;
    }

    /**
     * Deletes every event, then goes back to the journal.
     *
     * @return void
     */
    public function clearEvents(): void
    {
        $this->authorize('gecka_security_clear_events', 'events');
        $this->plugin->events()->clear();

        wp_safe_redirect(self::url('events', ['done' => 0, 'op' => 'clear']));
        exit;
    }

    /**
     * Ends every lockout and forgets every failure, then goes back to the
     * lockouts.
     *
     * @return void
     */
    public function unlockAll(): void
    {
        $this->authorize('gecka_security_unlock_all', 'lockouts');
        $this->plugin->lockouts()->clear();

        wp_safe_redirect(self::url('lockouts', ['done' => 0, 'op' => 'clear']));
        exit;
    }

    /**
     * Adds the address of the administrator to the safelist, unless it
     * cannot be read or is that of a proxy every visitor comes through, then
     * goes back to the settings with the outcome.
     *
     * @return void
     */
    public function safelistMe(): void
    {
        $this->authorize('gecka_security_safelist_me', 'settings');

        $ip = $this->plugin->clientIp();
        $outcome = 'yes';

        if ($ip->get() === '') {
            $outcome = 'unread';
        } elseif ($ip->behindProxy()) {
            // The address of a proxy every visitor comes through: on the safelist, it lets everyone in.
            $outcome = 'proxy';
        } else {
            // The key the address is watched under: the /64 of an IPv6
            // one, whose last bits change as the system rotates them.
            $this->safelist([$ip->key()]);
        }

        wp_safe_redirect(self::url('settings', ['safelisted' => $outcome]));
        exit;
    }

    /**
     * Adds addresses to the safelist, and ends their lockouts.
     *
     * @param string[] $ips Addresses or networks to add.
     *
     * @return void
     */
    public function safelist(array $ips): void
    {
        $settings = $this->plugin->settings();
        $safelist = Network::parseList(array_merge($settings->strings('safelist'), $ips));

        $settings->merge(['safelist' => $safelist]);
        $this->plugin->flush();
        $this->plugin->lockouts()->unlock(array_map([Network::class, 'key'], Network::parseList($ips)));
    }

    /**
     * Puts the settings back to their defaults, then goes back to the
     * settings.
     *
     * @return void
     */
    public function resetSettings(): void
    {
        $this->authorize('gecka_security_reset_settings', 'settings');
        $settings = $this->plugin->settings();
        $privacy = self::privacyChanged($settings->all(), $settings->defaults());
        $settings->reset();

        wp_safe_redirect(self::url('settings', ['reset' => 'settings'] + ($privacy ? ['privacy' => 1] : [])));
        exit;
    }

    /**
     * Saves the settings posted from the network admin, where options.php
     * does not exist: the same sanitising, the errors kept for the page
     * the way options.php keeps them.
     *
     * @return void
     */
    public function saveNetwork(): void
    {
        $this->authorize(self::PAGE . '-options', 'settings');

        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- authorize() checked the nonce; sanitised by Settings::sanitize(), as options.php would.
        $this->plugin->settings()->save($this->plugin->settings()->sanitize(wp_unslash($_POST[Settings::OPTION] ?? [])));

        if (! get_settings_errors()) {
            add_settings_error(Settings::OPTION, 'settings_updated', __('Settings saved.', 'gecka-security'), 'success');
        }

        set_transient('settings_errors', get_settings_errors(), 30);
        wp_safe_redirect(self::url('settings', ['settings-updated' => 'true']));
        exit;
    }

    /**
     * Prints the settings form.
     *
     * @return void
     */
    private function renderSettings(): void
    {
        if (! current_user_can(self::capability('settings'))) {
            return;
        }

        $settings = $this->plugin->settings()->all();
        $name = Settings::OPTION;
        $ip = $this->plugin->clientIp();

        // Under the Settings menu, options-head.php has printed every notice.
        if (($GLOBALS['parent_file'] ?? '') !== 'options-general.php') {
            settings_errors($name);
        }

        if (sanitize_key(Request::query('reset')) === 'settings') {
            wp_admin_notice(__('Every setting is back to its default.', 'gecka-security') . (Request::query('privacy') !== '' ? ' ' . self::privacyNotice() : ''), ['type' => 'success', 'dismissible' => true]);
        }

        $outcome = sanitize_key(Request::query('safelisted'));

        if ($outcome !== '') {
            wp_admin_notice(
                match ($outcome) {
                    /* translators: %s: IP address, or the IPv6 network it belongs to */
                    'yes' => sprintf(__('%s is on the safelist.', 'gecka-security'), $ip->key()),
                    /* translators: %s: IP address */
                    'proxy' => sprintf(__('%s is a private address and no proxy is trusted: it is the address of a proxy every visitor comes through, and on the safelist it would let everyone in. Name the header the proxy sends and list its address among the trusted proxies first.', 'gecka-security'), $ip->get()),
                    default => __('Your address could not be read: nothing was added to the safelist.', 'gecka-security'),
                },
                ['type' => $outcome === 'yes' ? 'success' : 'error', 'dismissible' => true],
            );
        }

        printf('<form action="%s" method="post">', esc_url(Scope::network() ? network_admin_url('edit.php?action=' . self::PAGE) : admin_url('options.php')));
        settings_fields(self::PAGE);
        printf('<input type="hidden" name="%s[form]" value="settings">', esc_attr($name));

        printf('<h2>%s %s</h2>', esc_html__('Logins', 'gecka-security'), Help::link(Help::BRUTE_FORCE)); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Help::link().
        printf('<p>%s</p>', esc_html__('An address that fails too many logins is locked out for a while, on the login form, WooCommerce, XML-RPC and the REST API alike. Repeated lockouts bring a long one. The requests that cost without failing, a password reset or a registration, are limited by the hour.', 'gecka-security'));
        echo '<table class="form-table" role="presentation">';
        $this->checkboxRow('bruteforce', __('Lock out brute force', 'gecka-security'), (bool) $settings['bruteforce'], __('Count the failed logins of each address and refuse its logins, registrations and password resets while it is locked out.', 'gecka-security'), true);
        $this->numberRow('max_failures', __('Failures before a lockout', 'gecka-security'), Value::int($settings['max_failures']), __('failures', 'gecka-security'), __('A failed login on a reserved name counts double.', 'gecka-security'), 'bruteforce');
        $this->numberRow('failures_window', __('Failures are counted for', 'gecka-security'), Value::int($settings['failures_window']), __('minutes', 'gecka-security'), __('Failures older than this are forgotten. A successful login does not forget them: a bot owning one account would log into it between two runs of guesses.', 'gecka-security'), 'bruteforce');
        $this->numberRow('lockout_minutes', __('Lockout', 'gecka-security'), Value::int($settings['lockout_minutes']), __('minutes', 'gecka-security'), '', 'bruteforce');
        $this->numberRow('max_lockouts', __('Lockouts before a long one', 'gecka-security'), Value::int($settings['max_lockouts']), __('lockouts', 'gecka-security'), '', 'bruteforce');
        $this->numberRow('lockouts_window', __('Lockouts are counted for', 'gecka-security'), Value::int($settings['lockouts_window']), __('hours', 'gecka-security'), '', 'bruteforce');
        $this->numberRow('long_lockout_hours', __('Long lockout', 'gecka-security'), Value::int($settings['long_lockout_hours']), __('hours', 'gecka-security'), __('After it, the lockouts are counted from zero.', 'gecka-security'), 'bruteforce');
        $this->checkboxRow('limit_requests', __('Limit the requests', 'gecka-security'), (bool) $settings['limit_requests'], __('Refuse the password resets and the registrations of an address past a number an hour. Neither fails, so nothing else limits them: a robot could flood a mailbox with resets or fill the site with accounts.', 'gecka-security'), true);
        $this->numberRow('resets_per_hour', __('Password resets an hour', 'gecka-security'), Value::int($settings['resets_per_hour']), __('requests', 'gecka-security'), __('From one address.', 'gecka-security'), 'limit_requests');
        $this->numberRow('registrations_per_hour', __('Registrations an hour', 'gecka-security'), Value::int($settings['registrations_per_hour']), __('requests', 'gecka-security'), __('From one address.', 'gecka-security'), 'limit_requests');
        echo '</table>';

        printf('<h2>%s %s</h2>', esc_html__('Addresses', 'gecka-security'), Help::link(Help::ADDRESSES)); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Help::link().
        printf(
            '<p>%s</p>',
            esc_html(
                match (true) {
                    $ip->get() === '' => __('Your address cannot be read with the current settings.', 'gecka-security'),
                    /* translators: %s: IP address */
                    $ip->onServer() => sprintf(__('Your address, as the settings read it: %s, the server itself. You are browsing from its machine and are never locked out; the other visitors are watched under their own address.', 'gecka-security'), $ip->get()),
                    /* translators: %s: IP address */
                    default => sprintf(__('Your address, as the settings read it: %s', 'gecka-security'), $ip->get()),
                },
            ),
        );
        echo '<table class="form-table" role="presentation">';
        $this->selectRow('ip_source', __('Address of the visitor', 'gecka-security'), Value::string($settings['ip_source']), Settings::ipSources(), __('A header is read only when the request comes from one of the trusted proxies below, and the address the server saw is used otherwise: anyone can send a header.', 'gecka-security'));
        $this->textareaRow('trusted_proxies', __('Trusted proxies', 'gecka-security'), implode("\n", Value::strings($settings['trusted_proxies'])), __('Addresses or networks of the reverse proxy, the load balancer or the CDN in front of the site, as 203.0.113.5 or 2001:db8::/32. Required for a header to be read.', 'gecka-security'), true);
        $this->textareaRow(
            'safelist',
            __('Safelist', 'gecka-security'),
            implode("\n", Value::strings($settings['safelist'])),
            __('Addresses or networks never locked out. Put the office and the administrators here, so that a mistyped password never locks them out.', 'gecka-security'),
            true,
            // Submits the form printed after the settings, unless the script adds the address as a tag.
            sprintf(
                '<p><button type="submit" form="gecka-security-safelist-me" class="button" data-gecka-security-add="%s" data-gecka-security-target="gecka-security-safelist"%s%s>%s</button></p>',
                esc_attr($ip->get()),
                disabled($ip->get() === '' || $ip->safelisted() || $ip->behindProxy(), true, false),
                $ip->behindProxy() ? sprintf(' title="%s"', esc_attr__('A private address, with no proxy trusted: every visitor comes through it.', 'gecka-security')) : '',
                esc_html__('Add my address', 'gecka-security'),
            ),
        );
        $this->textareaRow('blocklist', __('Blocklist', 'gecka-security'), implode("\n", Value::strings($settings['blocklist'])), __('Addresses or networks refused a login, a registration and a password reset for good, on every way in. The safelist wins over it.', 'gecka-security'), true);
        $country = Access::country($ip->get());
        $this->selectRow(
            'countries_mode',
            __('Countries', 'gecka-security'),
            Value::string($settings['countries_mode']),
            [
                '' => __('Every country', 'gecka-security'),
                Access::ALLOW => __('Only the countries listed below', 'gecka-security'),
                Access::DENY => __('Every country but those listed below', 'gecka-security'),
            ],
            ! Access::geolocation()
                ? __('Needs the Gecka Geolocation plugin, which tells the country of an address: without it, the countries are not checked.', 'gecka-security')
                : ($country !== ''
                    /* translators: %s: country name */
                    ? sprintf(__('An address whose country is unknown is never refused for it. Your country: %s.', 'gecka-security'), Events::countryName($country))
                    : __('An address whose country is unknown is never refused for it.', 'gecka-security')),
            ! Access::geolocation(),
        );
        $this->textareaRow('countries', __('Countries listed', 'gecka-security'), implode("\n", Value::strings($settings['countries'])), __('Codes of two letters, as NC, FR or AU. The safelist lets an address in whatever its country.', 'gecka-security'), true, disabled: ! Access::geolocation());
        echo '</table>';

        printf('<h2>%s %s</h2>', esc_html__('Accounts', 'gecka-security'), Help::link(Help::RESERVED)); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Help::link().
        printf('<p>%s</p>', esc_html__('What an account may be called, what password it may carry, and who gets to be an administrator.', 'gecka-security'));
        echo '<table class="form-table" role="presentation">';
        $this->textareaRow('reserved_names', __('Logins refused', 'gecka-security'), implode("\n", Value::strings($settings['reserved_names'])), __('No account can be registered or created with them, and a failed login on one of them counts double. An account that already carries one keeps it.', 'gecka-security'), true);
        $this->checkboxRow('pwned_passwords', __('Breached passwords', 'gecka-security'), (bool) $settings['pwned_passwords'], __('Refuse a password that appears in known data breaches when it is set or changed, and warn a user who logs in with one. The check goes through Have I Been Pwned by k-anonymity: five characters of a hash of the password leave the site, nothing else, once a month per account at most. The service silent, the password goes through.', 'gecka-security'));
        $this->checkboxRow('alert_admins', __('New administrator alert', 'gecka-security'), (bool) $settings['alert_admins'], __('Mail the address of the site when an account is created as administrator or promoted to it. An intruder creates a second administrator to stay.', 'gecka-security'));
        $this->checkboxRow(
            'alert_new_network',
            __('New network alert', 'gecka-security'),
            (bool) $settings['alert_new_network'],
            __('Mail an administrator who logs in from a network their account never logged in from, with the country and the network: a stolen password shows there first. The first login of an account only learns its network.', 'gecka-security'),
            false,
            Access::geolocation() ? '' : __('Needs the Gecka Geolocation plugin, which tells the network of an address.', 'gecka-security'),
            ! Access::geolocation(),
        );
        $this->checkboxRow('alert_logins', __('Login alert', 'gecka-security'), (bool) $settings['alert_logins'], __('Mail every user at each of their logins, with the date, the address and the system, and the country and the network with Gecka Geolocation: the owner of an account sees a login they did not make. Logins with an application password are not mailed.', 'gecka-security'));
        echo '</table>';

        printf('<h2>%s %s</h2>', esc_html__('Account enumeration', 'gecka-security'), Help::link(Help::ENUMERATION)); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Help::link().
        printf('<p>%s</p>', esc_html__('WordPress lists its accounts to anyone in several places. A bot reads them there, then has only the passwords to guess.', 'gecka-security'));
        echo '<table class="form-table" role="presentation">';
        $this->checkboxRow('author_archives', __('Author archives', 'gecka-security'), (bool) $settings['author_archives'], __('Answer the archive of an author with a 404 to visitors, whether asked by its address or by ?author=1, and never redirect ?author=1 to it.', 'gecka-security'));
        $this->checkboxRow('rest_users', __('REST API users', 'gecka-security'), (bool) $settings['rest_users'], __('Refuse /wp/v2/users to visitors. Logged-in users keep it. Off by default: some plugins read it to show content, check the site after switching it on.', 'gecka-security'));
        $this->checkboxRow('oembed_author', __('oEmbed', 'gecka-security'), (bool) $settings['oembed_author'], __('Leave the author out of the oEmbed data of a post.', 'gecka-security'));
        $this->checkboxRow('sitemap_users', __('Sitemap', 'gecka-security'), (bool) $settings['sitemap_users'], __('Leave the users out of the sitemap of WordPress.', 'gecka-security'));
        $this->checkboxRow('login_errors', __('Login errors', 'gecka-security'), (bool) $settings['login_errors'], __('Give a failed login one message, whether the login or the password was wrong, on the login form, WooCommerce and XML-RPC; and a password reset one message, whether the account exists or not.', 'gecka-security'));
        echo '</table>';

        printf('<h2>%s</h2>', esc_html__('Exposed surface', 'gecka-security'));
        printf('<p>%s</p>', esc_html__('What the site answers and advertises beyond its pages, and what the browsers are told.', 'gecka-security'));
        echo '<table class="form-table" role="presentation">';
        $this->checkboxRow('xmlrpc_disabled', __('Switch XML-RPC off', 'gecka-security'), (bool) $settings['xmlrpc_disabled'], __('Refuse every call of xmlrpc.php. A bot tries hundreds of passwords in one call through it; Jetpack and the mobile app of WordPress need it.', 'gecka-security'));
        $this->checkboxRow('pingback_disabled', __('Refuse pingbacks', 'gecka-security'), (bool) $settings['pingback_disabled'], __('Drop the pingback methods of XML-RPC and the header announcing them. A pingback makes the server fetch an address a stranger chose: the usual way to bounce a site into a denial of service.', 'gecka-security'));
        $this->checkboxRow('trackback_disabled', __('Refuse trackbacks', 'gecka-security'), (bool) $settings['trackback_disabled'], __('Answer wp-trackback.php with a refusal before it fetches anything. A trackback is a link notification any stranger can send; spam fills it, nothing recent uses it.', 'gecka-security'));
        $server = Headers::server();
        $bundle = array_map('strtolower', array_keys(Headers::list(true, false, true)));
        $byServer = array_intersect($bundle, $server);
        $this->checkboxRow(
            'security_headers',
            __('Security headers', 'gecka-security'),
            (bool) $settings['security_headers'],
            __('Send X-Content-Type-Options, Referrer-Policy and a frame-ancestors policy with every response: the browser then neither guesses the type of a file, nor tells a third party the page it comes from, nor shows the site inside another. A header the server already sends is left alone.', 'gecka-security'),
            false,
            $byServer === []
                ? ''
                : (count($byServer) === count($bundle)
                    ? __('The server sends every one of them on its own: the setting has no effect.', 'gecka-security')
                    /* translators: %s: names of HTTP headers */
                    : sprintf(__('The server sends %s on its own; Gecka Security adds the others.', 'gecka-security'), implode(', ', $byServer))),
            count($byServer) === count($bundle),
        );
        $this->checkboxRow(
            'hsts',
            __('HSTS', 'gecka-security'),
            (bool) $settings['hsts'],
            __('Tell the browsers to reach the site over HTTPS only, for six months. For a site that will keep HTTPS: once sent, a browser holds it for the whole six months.', 'gecka-security'),
            false,
            in_array('strict-transport-security', $server, true) ? __('The server sends it on its own: the setting has no effect.', 'gecka-security') : '',
            in_array('strict-transport-security', $server, true),
        );
        $this->checkboxRow('file_edit_disabled', __('File editor', 'gecka-security'), (bool) $settings['file_edit_disabled'], __('Switch the theme and plugin editors of the admin off. A compromised administrator account would use them to put PHP on the server; installs and updates stay possible.', 'gecka-security'));
        echo '</table>';

        printf('<h2>%s</h2>', esc_html__('Journal and statistics', 'gecka-security'));
        echo '<table class="form-table" role="presentation">';
        $this->checkboxRow('log_logins', __('Successful logins', 'gecka-security'), (bool) $settings['log_logins'], __('Record each successful login in the journal, with the address, the way in and the roles of the account, application passwords included: where an administrator logging in from an unusual address shows.', 'gecka-security'));
        $this->checkboxRow('log_unknown_logins', __('Unknown logins', 'gecka-security'), (bool) $settings['log_unknown_logins'], __('Record the login of a failure even when it names no account, to see which names the bots try; a password typed in the login field is then kept too. Off, the journal keeps only the logins naming an account or a reserved name.', 'gecka-security'));
        $this->checkboxRow('log_accounts', __('Account changes', 'gecka-security'), (bool) $settings['log_accounts'], __('Record in the journal every account created or deleted, every role set, added or removed, every e-mail address or password changed, with who did it.', 'gecka-security'));
        $this->numberRow('events_days', __('Keep the journal', 'gecka-security'), Value::int($settings['events_days']), __('days', 'gecka-security'), __('The events with the address and the login tried. An address watched is forgotten once idle longer than the windows its failures and lockouts are counted for.', 'gecka-security'));
        $this->numberRow('stats_days', __('Keep the statistics', 'gecka-security'), Value::int($settings['stats_days']), __('days', 'gecka-security'), __('Only daily counts are kept, by way in and by kind, and by country, network and system: no address, no login.', 'gecka-security'));
        echo '</table>';

        // The other buttons belong to the forms printed after this one,
        // through their form attribute.
        echo '<p class="submit gecka-admin-buttons">';
        submit_button('', 'primary', 'submit', false);
        echo ' ';
        printf(
            '<button type="submit" form="gecka-security-reset-settings" class="button" onclick="return confirm(%s)">%s</button>',
            esc_attr((string) wp_json_encode(__('Put every setting back to its default? The safelist, the trusted proxies, the blocklist and the countries are emptied.', 'gecka-security'))),
            esc_html__('Restore the default settings', 'gecka-security'),
        );
        echo '</p></form>';

        foreach (['safelist_me', 'reset_settings'] as $action) {
            printf('<form method="post" action="%s" id="gecka-security-%s">', esc_url(admin_url('admin-post.php')), esc_attr(str_replace('_', '-', $action)));
            printf('<input type="hidden" name="action" value="gecka_security_%s">', esc_attr($action));
            wp_nonce_field('gecka_security_' . $action);
            echo '</form>';
        }
    }

    /**
     * Dies unless the current user holds the capability of the screen and
     * the request carries the nonce of the action.
     *
     * @param string $action Nonce action.
     * @param string $screen Screen whose capability is asked for: stats, events, lockouts or settings.
     *
     * @return void
     */
    private function authorize(string $action, string $screen): void
    {
        if (! current_user_can(self::capability($screen))) {
            wp_die(esc_html__('Sorry, you are not allowed to do that.', 'gecka-security'), 403);
        }

        check_admin_referer($action);
    }
}

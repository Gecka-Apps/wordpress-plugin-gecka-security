<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security;

use Gecka\WP\Plugin\Security\Admin\DashboardWidget;
use Gecka\WP\Plugin\Security\Admin\SettingsPage;
use Gecka\WP\Plugin\Security\Admin\SiteHealth;
use Gecka\WP\Plugin\Security\Integrations\Accounts;
use Gecka\WP\Plugin\Security\Integrations\Editor;
use Gecka\WP\Plugin\Security\Integrations\Enumeration;
use Gecka\WP\Plugin\Security\Integrations\Headers;
use Gecka\WP\Plugin\Security\Integrations\Integration;
use Gecka\WP\Plugin\Security\Integrations\Login;
use Gecka\WP\Plugin\Security\Integrations\LoginAlerts;
use Gecka\WP\Plugin\Security\Integrations\Logins;
use Gecka\WP\Plugin\Security\Integrations\NewNetworks;
use Gecka\WP\Plugin\Security\Integrations\Pings;
use Gecka\WP\Plugin\Security\Integrations\Pwned;
use Gecka\WP\Plugin\Security\Integrations\Requests;
use Gecka\WP\Plugin\Security\Integrations\ReservedNames;
use Gecka\WP\Plugin\Security\Integrations\XmlRpc;

/**
 * Plugin instance: the pieces it hooks up, and what they all need to know.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Plugin
{
    /**
     * Version of the plugin.
     */
    public const VERSION = '1.0.0';

    /**
     * Main file of the plugin.
     *
     * @var string
     */
    private string $file;

    /**
     * The settings of the plugin.
     *
     * @var Settings
     */
    private Settings $settings;

    /**
     * The address of the visitor, made on first use.
     *
     * @var ClientIp|null
     */
    private ?ClientIp $clientIp = null;

    /**
     * The addresses the brute-force protection watches, made on first use.
     *
     * @var Lockouts|null
     */
    private ?Lockouts $lockouts = null;

    /**
     * The journal, made on first use.
     *
     * @var Events|null
     */
    private ?Events $events = null;

    /**
     * The daily counters by way in and by kind, made on first use.
     *
     * @var Stats|null
     */
    private ?Stats $stats = null;

    /**
     * The daily counters by origin, made on first use.
     *
     * @var Origins|null
     */
    private ?Origins $origins = null;

    /**
     * The counters of requests, made on first use.
     *
     * @var Throttle|null
     */
    private ?Throttle $throttle = null;

    /**
     * The tests of Site Health, made on first use.
     *
     * @var SiteHealth|null
     */
    private ?SiteHealth $siteHealth = null;

    /**
     * The protections set up: those the settings switch on, available on
     * this site.
     *
     * @var Integration[]
     */
    private array $active = [];

    /**
     * Hooks the plugin up: the settings and what follows their save, the
     * counters by origin, the protections the settings switch on, the
     * screens in the admin, the setup check on init, the daily purge and
     * the WP-CLI command. A protection switched off is not loaded, nor are
     * the screens outside the admin; the journal and the counters are made
     * when first used.
     *
     * @param string $file Main file of the plugin.
     */
    public function __construct(string $file)
    {
        $this->file = $file;

        // The options every request reads, in one query on a network, where
        // no autoload brings them.
        if (Scope::network()) {
            wp_prime_network_option_caches(null, [Settings::OPTION, Setup::VERSION_OPTION, Integrations\Headers::SERVER_OPTION]);
        }

        $this->settings = new Settings();
        // The first save adds the option: the defaults stand for what it held.
        add_action('add_option_' . Settings::OPTION, fn(string $option, mixed $value) => $this->saved([], $value), 10, 2);
        add_action('add_site_option_' . Settings::OPTION, fn(string $option, mixed $value) => $this->saved([], $value), 10, 2);
        add_action('update_option_' . Settings::OPTION, fn(mixed $old, mixed $value) => $this->saved($old, $value), 10, 2);
        add_action('update_site_option_' . Settings::OPTION, fn(string $option, mixed $value, mixed $old) => $this->saved($old, $value), 10, 3);
        add_action('gecka_security_event', fn(string $type, string $ip) => $this->origins()->count($type, $ip), 10, 2);
        $this->active = [];

        foreach ($this->integrations() as $class => $on) {
            if (! $on) {
                continue;
            }

            $integration = new $class($this);

            if ($integration->available()) {
                $integration->setup();
                $this->active[] = $integration;
            }
        }

        // admin-ajax.php and admin-post.php are the admin too: the
        // asynchronous tests of Site Health run there.
        if (is_admin()) {
            (new SettingsPage($this))->setup();
            (new DashboardWidget($this))->setup();
            $this->siteHealth()->setup();
        }

        // The tests and the Info section of Site Health, and the exporter
        // and the eraser of the personal data tools, wherever they are
        // asked: the admin, the weekly check of WP-Cron, WP-CLI or another
        // tool. Their classes are loaded when they are.
        add_filter('site_status_tests', fn(mixed $tests): mixed => $this->siteHealth()->tests($tests));
        add_filter('debug_information', fn(mixed $info): mixed => $this->siteHealth()->information($info));
        add_filter('wp_privacy_personal_data_exporters', fn(mixed $exporters): mixed => (new Privacy($this))->exporters($exporters));
        add_filter('wp_privacy_personal_data_erasers', fn(mixed $erasers): mixed => (new Privacy($this))->erasers($erasers));

        add_action('init', fn() => Setup::upgrade(self::VERSION));
        add_action(
            Setup::PURGE_EVENT,
            function () {
                $this->events()->purge($this->settings->int('events_days'));
                $this->lockouts()->purge();
                $this->stats()->purge($this->settings->int('stats_days'));
                $this->origins()->purge($this->settings->int('stats_days'), $this->settings->int('events_days'));
                $this->origins()->foldNetworks();
                $this->throttle()->purge();
                Integrations\Headers::probe();
            },
        );

        if (defined('WP_CLI') && WP_CLI) {
            \WP_CLI::add_command('gecka-security', new Cli($this));
        }
    }

    /**
     * The protections of the plugin, each with whether the settings switch
     * it on. Decided here, before the class of a protection is loaded.
     *
     * @return array<class-string<Integration>, bool>
     */
    private function integrations(): array
    {
        $settings = $this->settings;
        $any = static fn(string ...$keys): bool => array_filter($keys, $settings->enabled(...)) !== [];

        return [
            Login::class => $any('bruteforce') || $settings->restricts(),
            Enumeration::class => $any('author_archives', 'rest_users', 'oembed_author', 'sitemap_users', 'login_errors'),
            ReservedNames::class => $settings->strings('reserved_names') !== [],
            XmlRpc::class => $any('xmlrpc_disabled'),
            Pings::class => $any('pingback_disabled', 'trackback_disabled'),
            Headers::class => $any('security_headers', 'hsts'),
            Editor::class => $any('file_edit_disabled'),
            Logins::class => $any('log_logins'),
            NewNetworks::class => $any('alert_new_network'),
            LoginAlerts::class => $any('alert_logins'),
            Pwned::class => $any('pwned_passwords'),
            Accounts::class => $any('log_accounts', 'alert_admins'),
            Requests::class => $any('limit_requests'),
        ];
    }

    /**
     * Follows a save of the settings: forgets those read and the address
     * resolved, and reads again which headers the server sends on its own
     * when the headers of the plugin are switched, since the probe tells
     * them apart from its own only while they are sent.
     *
     * @param mixed $old   Settings before the save, the defaults filling the gaps.
     * @param mixed $value Settings saved, the defaults filling the gaps.
     *
     * @return void
     */
    private function saved(mixed $old, mixed $value): void
    {
        $this->flush();

        $defaults = $this->settings->defaults();
        $old = array_merge($defaults, is_array($old) ? $old : []);
        $value = array_merge($defaults, is_array($value) ? $value : []);

        if (! empty($old['security_headers']) !== ! empty($value['security_headers']) || ! empty($old['hsts']) !== ! empty($value['hsts'])) {
            Integrations\Headers::probe();
        }
    }

    /**
     * Forgets the settings read and the address resolved, once the settings
     * were saved.
     *
     * @return void
     */
    public function flush(): void
    {
        $this->settings->flush();
        $this->clientIp?->flush();
    }

    /**
     * The settings of the plugin
     *
     * @return Settings
     */
    public function settings(): Settings
    {
        return $this->settings;
    }

    /**
     * The address of the visitor
     *
     * @return ClientIp
     */
    public function clientIp(): ClientIp
    {
        return $this->clientIp ??= new ClientIp($this->settings);
    }

    /**
     * The addresses the brute-force protection watches
     *
     * @return Lockouts
     */
    public function lockouts(): Lockouts
    {
        return $this->lockouts ??= new Lockouts($this->settings);
    }

    /**
     * The journal
     *
     * @return Events
     */
    public function events(): Events
    {
        return $this->events ??= new Events();
    }

    /**
     * The daily counters by way in and by kind
     *
     * @return Stats
     */
    public function stats(): Stats
    {
        return $this->stats ??= new Stats();
    }

    /**
     * The daily counters by origin
     *
     * @return Origins
     */
    public function origins(): Origins
    {
        return $this->origins ??= new Origins();
    }

    /**
     * The tests of Site Health
     *
     * @return SiteHealth
     */
    private function siteHealth(): SiteHealth
    {
        return $this->siteHealth ??= new SiteHealth($this);
    }

    /**
     * The counters of requests per address and per hour
     *
     * @return Throttle
     */
    public function throttle(): Throttle
    {
        return $this->throttle ??= new Throttle();
    }

    /**
     * One of the protections set up, by class
     *
     * @param class-string<Integration> $class Class of the protection.
     *
     * @return Integration|null Null when it is not set up.
     */
    public function integration(string $class): ?Integration
    {
        foreach ($this->active as $integration) {
            if ($integration instanceof $class) {
                return $integration;
            }
        }

        return null;
    }

    /**
     * Url of a file of the plugin
     *
     * @param string $relative Path from the directory of the plugin.
     *
     * @return string
     */
    public function url(string $relative = ''): string
    {
        return plugins_url($relative, $this->file);
    }

    /**
     * Main file of the plugin
     *
     * @return string
     */
    public function file(): string
    {
        return $this->file;
    }
}

<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

use Gecka\WP\AdminMenu\Menus;
use Gecka\WP\Plugin\Security\Admin\SettingsPage;
use Gecka\WP\Plugin\Security\Scope;

/*
 * The screens are declared to the shared admin menu while the plugin loads
 * in the admin: the suite loads it as a front request, so the declaration
 * is made here as the plugin makes it.
 */
beforeEach(function () {
    admin_user();
    set_current_screen(is_multisite() ? 'dashboard-network' : 'dashboard');
    (new SettingsPage(gecka_security()))->declare();
});

it('declares its pages under the shared Security menu and its settings under Settings', function () {
    $menu = Menus::menu(SettingsPage::MENU);
    $pages = $menu->pages();

    expect($menu->getTitle())->toBe('Security')
        ->and($menu->getIcon())->toBe('dashicons-shield')
        ->and(array_map(static fn($page) => $page->slug(), $pages))->toBe(array_values(SettingsPage::PAGES))
        ->and($pages[0]->tabs())->toHaveCount(1)
        ->and(Menus::options(SettingsPage::PAGE)->getTitle())->toBe('Security');
});

it('points every page at its own slug', function () {
    expect(SettingsPage::url('stats'))->toContain('admin.php?page=' . SettingsPage::PAGES['stats'])
        ->and(SettingsPage::url('stats'))->not->toContain('tab=')
        ->and(SettingsPage::url('events', ['s' => '203.0.113.5']))->toContain('admin.php?page=security-journal')
        ->and(SettingsPage::url('settings'))->toContain(is_multisite() ? 'network/settings.php?page=gecka-security' : 'options-general.php?page=gecka-security')
        ->and(SettingsPage::pageSlug('stats'))->toBe('security-stats')
        ->and(SettingsPage::pageSlug('lockouts'))->toBe('security-lockouts');
});

it('carries the addresses locked out as the badge of the Lockouts page', function () {
    gecka_security()->lockouts()->clear();

    for ($i = 0; $i < 5; $i++) {
        gecka_security()->lockouts()->fail('203.0.113.9');
    }

    expect(Menus::menu(SettingsPage::MENU)->page(SettingsPage::PAGES['lockouts'])->getBadge())->toBe(1)
        ->and(Menus::menu(SettingsPage::MENU)->getMenuTitle())->toContain('awaiting-mod">1</span>');
});

it('declares the menu ahead of the default priority of init, so that it names the menu', function () {
    $page = new SettingsPage(gecka_security());
    $page->setup();

    expect(has_action('init', [$page, 'declare']))->toBe(5);
});

it('asks manage_options for each of its tabs, manage_network_options on a network, whatever the menu asks', function () {
    expect(Menus::menu(SettingsPage::MENU)->page(SettingsPage::PAGES['stats'])->tab(SettingsPage::TAB)->getCapability())->toBe(Scope::capability())
        ->and(Menus::options(SettingsPage::PAGE)->tab('settings')->getCapability())->toBe(Scope::capability())
        ->and(Scope::capability())->toBe(is_multisite() ? 'manage_network_options' : 'manage_options');
});

it('lets the gecka_security_capability filter open a screen to another capability', function () {
    expect(SettingsPage::capability('stats'))->toBe(Scope::capability())
        ->and(SettingsPage::capability('nowhere'))->toBe(Scope::capability());

    add_filter('gecka_security_capability', static fn(string $capability, string $screen): string => $screen === 'stats' ? 'edit_posts' : $capability, 10, 2);

    expect(SettingsPage::capability('stats'))->toBe('edit_posts')
        ->and(SettingsPage::capability('events'))->toBe(Scope::capability());

    add_filter('gecka_security_capability', static fn(): string => '', 11);

    expect(SettingsPage::capability('stats'))->toBe(Scope::capability());

    remove_all_filters('gecka_security_capability');
});

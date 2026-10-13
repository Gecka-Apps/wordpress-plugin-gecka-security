<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

it('denies the file editors to an administrator, and nothing else', function () {
    admin_user();

    expect(current_user_can('edit_plugins'))->toBeFalse()
        ->and(current_user_can('edit_themes'))->toBeFalse()
        ->and(current_user_can('edit_files'))->toBeFalse()
        ->and(current_user_can('install_plugins'))->toBeTrue()
        ->and(current_user_can('update_plugins'))->toBeTrue()
        ->and(current_user_can('manage_options'))->toBeTrue();
});

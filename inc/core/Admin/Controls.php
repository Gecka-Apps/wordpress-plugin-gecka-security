<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace Gecka\WP\Plugin\Security\Admin;

use Gecka\WP\Plugin\Security\Settings;

/**
 * Rows of a settings form, and buttons posting an action to admin-post.php.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
trait Controls
{
    /**
     * Prints a row holding a number field, bounded by Settings::BOUNDS.
     *
     * @param string $key         Key of the setting, also its key in Settings::BOUNDS.
     * @param string $label       Label of the field.
     * @param int    $value       Current value.
     * @param string $unit        Unit printed after the field.
     * @param string $description Text below the field.
     * @param string $needs       Key of the switch that hides the row while off, empty for none.
     *
     * @return void
     */
    private function numberRow(string $key, string $label, int $value, string $unit, string $description, string $needs = ''): void
    {
        printf(
            '<tr%9$s><th scope="row"><label for="gecka-security-%1$s">%2$s</label></th><td><input type="number" class="small-text" id="gecka-security-%1$s" name="%3$s[%1$s]" value="%4$d" min="%5$d" max="%6$d" aria-describedby="gecka-security-%1$s-description">&nbsp;%7$s<p class="description" id="gecka-security-%1$s-description">%8$s</p></td></tr>',
            esc_attr($key),
            esc_html($label),
            esc_attr(Settings::OPTION),
            (int) $value,
            (int) Settings::BOUNDS[$key][0],
            (int) Settings::BOUNDS[$key][1],
            esc_html($unit),
            esc_html($description),
            $needs === '' ? '' : sprintf(' class="gecka-security-needs-%s"', esc_attr($needs)),
        );
    }

    /**
     * Prints a row holding a switch.
     *
     * @param string $key         Key of the setting, in the field name and the ids.
     * @param string $label       Heading of the row.
     * @param bool   $checked     Whether the switch is on.
     * @param string $description Text of the label beside the switch.
     * @param bool   $controls    Whether the switch hides the rows that need it while off.
     * @param string $note        Paragraph below the switch, empty for none.
     * @param bool   $locked      Whether the switch is disabled, a hidden field carrying its value when on.
     *
     * @return void
     */
    private function checkboxRow(string $key, string $label, bool $checked, string $description, bool $controls = false, string $note = '', bool $locked = false): void
    {
        // A locked box is shown as it is and cannot be changed; a hidden field carries its value, a disabled one being left out of the form.
        printf(
            '<tr><th scope="row" id="gecka-security-%3$s-label">%1$s</th><td>%8$s<label class="gecka-admin-toggle-label"><input type="checkbox" class="gecka-admin-toggle" name="%2$s[%3$s]" value="1" %4$s%6$s%9$s aria-labelledby="gecka-security-%3$s-label" aria-describedby="gecka-security-%3$s-description"> <span id="gecka-security-%3$s-description">%5$s</span></label>%7$s</td></tr>',
            esc_html($label),
            esc_attr(Settings::OPTION),
            esc_attr($key),
            checked($checked, true, false),
            esc_html($description),
            $controls ? sprintf(' data-gecka-security-controls="%s"', esc_attr($key)) : '',
            $note !== '' ? sprintf('<p class="description">%s</p>', esc_html($note)) : '',
            $locked && $checked ? sprintf('<input type="hidden" name="%s[%s]" value="1">', esc_attr(Settings::OPTION), esc_attr($key)) : '',
            $locked ? ' disabled' : '',
        );
    }

    /**
     * Prints a row holding a list, one entry per line.
     *
     * @param string $key         Key of the setting, in the field name and the ids.
     * @param string $label       Label of the field.
     * @param string $value       One entry per line.
     * @param string $description Text below the field.
     * @param bool   $tags        Whether the script draws the list as tags.
     * @param string $extra       HTML printed after the field, escaped by the caller.
     * @param bool   $disabled    Whether the field is shown only: left out of the form, the setting keeps its value.
     *
     * @return void
     */
    private function textareaRow(string $key, string $label, string $value, string $description, bool $tags = false, string $extra = '', bool $disabled = false): void
    {
        printf(
            '<tr><th scope="row"><label for="gecka-security-%1$s">%2$s</label></th><td><textarea class="large-text code" rows="4" id="gecka-security-%1$s" name="%3$s[%1$s]" aria-describedby="gecka-security-%1$s-description"%6$s%8$s>%4$s</textarea>%7$s<p class="description" id="gecka-security-%1$s-description">%5$s</p></td></tr>',
            esc_attr($key),
            esc_html($label),
            esc_attr(Settings::OPTION),
            esc_textarea($value),
            esc_html($description),
            // The script turns the list into tags, one entry at a time.
            $tags ? sprintf(' data-gecka-security-tags="1" data-gecka-security-remove="%s"', esc_attr__('Remove', 'gecka-security')) : '',
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- HTML the caller escaped.
            $extra,
            $disabled ? ' disabled' : '',
        );
    }

    /**
     * Prints a row holding a drop-down list.
     *
     * @param string                $key         Key of the setting, in the field name and the ids.
     * @param string                $label       Label of the field.
     * @param string                $value       Value selected.
     * @param array<string, string> $choices     Labels by value.
     * @param string                $description Text below the field.
     * @param bool                  $disabled    Whether the field is shown only: left out of the form, the setting keeps its value.
     *
     * @return void
     */
    private function selectRow(string $key, string $label, string $value, array $choices, string $description, bool $disabled = false): void
    {
        printf(
            '<tr><th scope="row"><label for="gecka-security-%1$s">%2$s</label></th><td><select id="gecka-security-%1$s" name="%3$s[%1$s]" aria-describedby="gecka-security-%1$s-description"%4$s>',
            esc_attr($key),
            esc_html($label),
            esc_attr(Settings::OPTION),
            $disabled ? ' disabled' : '',
        );

        foreach ($choices as $choice => $text) {
            printf('<option value="%s"%s>%s</option>', esc_attr($choice), selected($value, $choice, false), esc_html($text));
        }

        printf('</select><p class="description" id="gecka-security-%1$s-description">%2$s</p></td></tr>', esc_attr($key), esc_html($description));
    }

    /**
     * Prints a form holding only a button, which posts an action to
     * admin-post.php, followed by white space, as WordPress separates its
     * buttons. Several in a row go in a .gecka-admin-buttons block.
     *
     * @param string      $action  Action posted to admin-post.php, also the nonce action.
     * @param string      $label   Text of the button.
     * @param string|null $confirm Question asked before, if any.
     *
     * @return void
     */
    private function actionButton(string $action, string $label, ?string $confirm = null): void
    {
        printf('<form method="post" action="%s">', esc_url(admin_url('admin-post.php')));
        printf('<input type="hidden" name="action" value="%s">', esc_attr($action));
        wp_nonce_field($action);
        printf(
            '<button type="submit" class="button"%s>%s</button>',
            $confirm ? ' onclick="return confirm(' . esc_attr((string) wp_json_encode($confirm)) . ')"' : '',
            esc_html($label),
        );
        echo "</form>\n";
    }
}

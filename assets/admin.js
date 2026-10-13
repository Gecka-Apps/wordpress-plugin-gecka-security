/*
 * SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The settings screen. A switch carrying data-gecka-security-controls hides
 * the rows of class gecka-security-needs-<key> while it is off, the fields
 * staying in the form so that their values survive a save. A textarea
 * carrying data-gecka-security-tags, a list of one entry per line, is drawn
 * as tags: Enter or a comma adds what was typed, Backspace on an empty
 * input removes the last tag, and the textarea, kept out of sight, carries
 * the list to the form. A disabled one shows its tags only, nothing to type
 * nor to remove, and stays out of the form. A button carrying data-gecka-security-add adds its
 * value to the tags of data-gecka-security-target instead of submitting.
 */
(() => {
    document.querySelectorAll('[data-gecka-security-controls]').forEach((toggle) => {
        const rows = document.querySelectorAll('.gecka-security-needs-' + toggle.dataset.geckaSecurityControls);
        const apply = () => rows.forEach((row) => { row.hidden = !toggle.checked; });

        toggle.addEventListener('change', apply);
        apply();
    });

    const fields = {};

    document.querySelectorAll('textarea[data-gecka-security-tags]').forEach((source) => {
        const box = document.createElement('div');
        const list = document.createElement('span');
        const input = document.createElement('input');
        const label = document.querySelector(`label[for="${source.id}"]`);

        if (source.disabled) {
            box.className = 'gecka-security-tags is-disabled';
            box.setAttribute('role', 'group');
            box.setAttribute('aria-disabled', 'true');
            box.setAttribute('aria-label', label?.textContent || '');
            box.setAttribute('aria-describedby', source.getAttribute('aria-describedby') || '');
            box.append(...source.value.split(/[\n,]+/).map((value) => value.trim()).filter(Boolean).map((value) => {
                const tag = document.createElement('span');

                tag.className = 'gecka-security-tag';
                tag.textContent = value;

                return tag;
            }));
            source.hidden = true;
            source.insertAdjacentElement('afterend', box);

            return;
        }

        box.className = 'gecka-security-tags';
        list.className = 'gecka-security-tags-list';
        input.type = 'text';
        input.className = 'gecka-security-tags-input';
        input.id = source.id + '-input';
        input.autocomplete = 'off';
        input.spellcheck = false;
        input.setAttribute('aria-describedby', source.getAttribute('aria-describedby') || '');
        label?.setAttribute('for', input.id);

        const values = () => source.value.split(/[\n,]+/).map((value) => value.trim()).filter(Boolean);

        const set = (next) => {
            source.value = [...new Set(next)].join('\n');
            render();
        };

        const render = () => {
            list.replaceChildren(...values().map((value) => {
                const tag = document.createElement('span');
                const remove = document.createElement('button');

                tag.className = 'gecka-security-tag';
                tag.textContent = value;
                remove.type = 'button';
                remove.className = 'gecka-security-tag-remove';
                remove.setAttribute('aria-label', `${source.dataset.geckaSecurityRemove} ${value}`);
                remove.textContent = '×';
                remove.addEventListener('click', () => {
                    set(values().filter((kept) => kept !== value));
                    input.focus();
                });
                tag.append(remove);

                return tag;
            }));
        };

        const add = () => {
            const typed = input.value.split(/[\n,]+/).map((value) => value.trim()).filter(Boolean);

            if (typed.length) {
                set([...values(), ...typed]);
            }

            input.value = '';
        };

        input.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ',') {
                event.preventDefault();
                add();
            } else if (event.key === 'Backspace' && input.value === '') {
                set(values().slice(0, -1));
            }
        });
        input.addEventListener('blur', add);
        box.addEventListener('click', (event) => {
            if (event.target === box) {
                input.focus();
            }
        });

        box.append(list, input);
        source.hidden = true;
        source.insertAdjacentElement('afterend', box);
        render();

        fields[source.id] = (value) => set([...values(), value]);
    });

    document.querySelectorAll('[data-gecka-security-add]').forEach((button) => {
        const field = fields[button.dataset.geckaSecurityTarget];

        if (!field) {
            return;
        }

        button.addEventListener('click', (event) => {
            event.preventDefault();
            field(button.dataset.geckaSecurityAdd);
            button.disabled = true;
        });
    });
})();

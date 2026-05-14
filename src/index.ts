import joplin from 'api';
import {ContentScriptType, MenuItemLocation, SettingItemType, ToastType, ToolbarButtonLocation} from 'api/types';

let scriptIndex = 1;
const dialogs = joplin.views.dialogs;
const alert_duration = 3000;

joplin.plugins.register({
    onStart: async function () {
        await registerHighlightsOnlySettings();
        await loadHighlightsOnlyCSS();
        let enabled = await loadHighlightsOnlyScripts();
        await registerHighlightsOnlyToolbarButton(enabled);
        await registerHighlightsOnlyMenuItem();
    }
});

async function registerHighlightsOnlySettings() {
    // --- Settings voor toggle ---
    await joplin.settings.registerSection('highlightsOnlyDisplaySection', {
        label: 'Highlights-only toggler',
        iconName: 'fa fa-eye',
        description: 'Changes in the below settings will only come into effect after restarting Joplin.'
    });

    await joplin.settings.registerSettings({
        highlightsOnlyMode: {
            value: false,
            type: SettingItemType.Bool,
            section: 'highlightsOnlyDisplaySection',
            public: false,
            label: 'Highlight mode'
        }
    });
    await joplin.settings.registerSettings({
        loadUserCSS: {
            value: true,
            type: SettingItemType.Bool,
            section: 'highlightsOnlyDisplaySection',
            public: true,
            label: 'Load my custom CSS',
            description: 'Load custom CSS from highlights-only.css in the Joplin config folder; if this stylesheet exists, of course.'
        }
    });
    await joplin.settings.registerSettings({
        hideHeadings: {
            value: false,
            type: SettingItemType.Bool,
            section: 'highlightsOnlyDisplaySection',
            public: true,
            label: 'Hide headings in higlights-only display mode',
            description: 'If enabled, in highlights-only display mode headings will be hidden also.'
        }
    });
    await joplin.settings.registerSettings({
        hideImages: {
            value: true,
            type: SettingItemType.Bool,
            section: 'highlightsOnlyDisplaySection',
            public: true,
            label: 'Hide images in higlights-only display mode',
            description: 'If enabled, in highlights-only display mode images will be hidden also.'
        }
    });
    await joplin.settings.registerSettings({
        supportSummaryMarks: {
            value: true,
            type: SettingItemType.Bool,
            section: 'highlightsOnlyDisplaySection',
            public: true,
            label: 'Support summary-marks',
            description: 'If enabled, in highlights-only display mode, marks inside blockquotes will be treated as the crux or summaries of the note. They will be marked with the backgroundcolor tomato (but user can style this; see README).'
        }
    });
    await joplin.settings.registerSettings({
        highlightsOnlyHotkey: {
            value: "H",
            type: SettingItemType.String,
            section: 'highlightsOnlyDisplaySection',
            public: true,
            label: 'Hotkey',
            description: 'Don\'t enter a hotkey which has already been assigned to another Joplin or plugin command! If an invalid hotkey (no string, or length > 1) is entered here, hotkey will be disabled.'
        }
    });
    await joplin.settings.registerSettings({
        highlightsOnlyHotkeyAltEnabled: {
            value: true,
            type: SettingItemType.Bool,
            section: 'highlightsOnlyDisplaySection',
            public: true,
            label: 'Hotkey: combined with alt',
            description: 'If enabled, alt is required to trigger the hotkey. E.g. for hotkey H: if enabled: ctrl/command+alt+H; if disabled: ctrl/command+H.'
        }
    });
    await joplin.settings.registerSettings({
        refreshEditor: {
            value: true,
            type: SettingItemType.Bool,
            section: 'highlightsOnlyDisplaySection',
            public: true,
            label: 'Refresh Html Viewer upon mode change',
            description: 'If enabled, after a mode change the editor will be refreshed. This is a workaround to get the Html Viewer/Editor to update after a mode change. If you mainly work in the markdown editor, you could disable this, for more fluid mode change.'
        }
    });
    const noTextInfo = 'If no text given, no message will be shown.'
    await joplin.settings.registerSettings({
        activatedMessage: {
            value: 'highlights-only mode ACTIVATED',
            type: SettingItemType.String,
            section: 'highlightsOnlyDisplaySection',
            public: true,
            label: 'Message upon highlights-only mode activation',
            description: noTextInfo
        }
    });
    await joplin.settings.registerSettings({
        deactivatedMessage: {
            value: 'highlights-only mode DE-ACTIVATED',
            type: SettingItemType.String,
            section: 'highlightsOnlyDisplaySection',
            public: true,
            label: 'Message upon highlights-only mode de-activation',
            description: noTextInfo
        }
    });
    await joplin.settings.registerSettings({
        showHighlightsOnlyEnabledStatus: {
            value: true,
            type: SettingItemType.Bool,
            section: 'highlightsOnlyDisplaySection',
            public: true,
            label: 'Show highlights-only enabled status',
            description: 'If you enable this setting, on pages without highlights, when highlights-only mode has been enabled, that enabled-status will be shown by a tooltip at the top of the note.'
        }
    });
}

async function loadHighlightsOnlyCSS() {
    const installDir = await joplin.plugins.installationDir();

    //! here we load default CSS for .highlights-only-enabled:
    const showHighlightsOnlyModeEnabled = await joplin.settings.value('showHighlightsOnlyEnabledStatus');
    if (showHighlightsOnlyModeEnabled) {
        const showEnabledFilePath = installDir + '/show-highlights-only-enabled.css';
        await (joplin as any).window.loadNoteCssFile(showEnabledFilePath);
    }

    //* --- load CSS from custom user stylesheet highlights-only.css ---
    //! in this user stylesheet you can overrule the lay-out of .highlights-only-enabled:
    const noteCssFilePath = installDir + '/highlights-only.css';
    await (joplin as any).window.loadNoteCssFile(noteCssFilePath);

    const loadUserCSS = await joplin.settings.value('loadUserCSS');
    if (loadUserCSS) {
        const configDir = await joplin.settings.globalValues(['profileDir']);
        const fs = require('fs');
        if (fs.existsSync(configDir + '/highlights-only.css')) {
            await (joplin as any).window.loadNoteCssFile(configDir + '/highlights-only.css');
        }
    }
    const hideHeadings = await joplin.settings.value('hideHeadings');
    if (hideHeadings) {
        const hideHeadingsFilePath = installDir + '/hide-headings.css';
        await (joplin as any).window.loadNoteCssFile(hideHeadingsFilePath);
    }
    const hideImages = await joplin.settings.value('hideImages');
    if (hideImages) {
        const hideImagesFilePath = installDir + '/hide-images.css';
        await (joplin as any).window.loadNoteCssFile(hideImagesFilePath);
    }
    const summaryMarks = await joplin.settings.value('supportSummaryMarks');
    if (summaryMarks) {
        const summaryMarksFilePath = installDir + '/summary-colors.css';
        await (joplin as any).window.loadNoteCssFile(summaryMarksFilePath);
    }
}

async function loadHighlightsOnlyScripts() {
    let enabled = await joplin.settings.value('highlightsOnlyMode');
    if (enabled) {
        await joplin.contentScripts.register(
            ContentScriptType.MarkdownItPlugin,
            'highlightView',
            './highlightsOnly.js'
        );
    } else {
        await joplin.contentScripts.register(
            ContentScriptType.MarkdownItPlugin,
            'highlightViewUndo',
            './highlightsOnlyUndo.js'
        );
    }
    return enabled;
}

async function registerHighlightsOnlyToolbarButton(enabled: boolean) {
    let accelerator = await getHighlightsOnlyHotKey();
    if (accelerator !== "") {
        accelerator = ' (' + accelerator + ')';
    }
    await joplin.commands.register({
        name: 'toggleHighlightsOnlyView',
        label: 'Toggle highlights-only view' + accelerator,
        iconName: 'fa fa-eye',
        execute: async () => {
            enabled = !enabled;
            await joplin.settings.setValue('highlightsOnlyMode', enabled);

            const script = enabled ? './highlightsOnly.js' : './highlightsOnlyUndo.js';
            const message = enabled ? await joplin.settings.value('activatedMessage') : await joplin.settings.value('deactivatedMessage');
            await joplin.contentScripts.register(
                ContentScriptType.MarkdownItPlugin,
                'highlightView' + scriptIndex,
                script
            );
            if (message !== "") {
                const type = enabled ? ToastType.Success : ToastType.Error;
                await dialogs.showToast({
                    type: type,
                    message: message,
                    duration: alert_duration,
                });
            }
            scriptIndex = scriptIndex + 1;

            //* this setting is especially relevant for the Html Viewer (otherwise we would first have to navigate to another note and back, to see the changed mode):
            const refreshEditor = await joplin.settings.value('refreshEditor');
            if (refreshEditor) {
                await joplin.commands.execute('toggleEditors');
                await joplin.commands.execute('toggleEditors');
            }
        }
    });

    //* --- Toolbar button ---
    await joplin.views.toolbarButtons.create(
        'toggleHighlightsOnlyButton',
        'toggleHighlightsOnlyView',
        ToolbarButtonLocation.NoteToolbar
    );
}

async function getHighlightsOnlyHotKey() {
    let hotkey = await joplin.settings.value('highlightsOnlyHotkey');
    if (hotkey === "" || hotkey.length > 1) {
        return "";
    }
    hotkey = hotkey.toUpperCase();
    const alt = await joplin.settings.value('highlightsOnlyHotkeyAltEnabled') ? "+Alt" : "";
    return 'CmdOrCtrl' + alt + '+' + hotkey;
}

async function registerHighlightsOnlyMenuItem() {
    const accelerator = await getHighlightsOnlyHotKey();
    if (accelerator === "") {
        await joplin.views.menuItems.create('toggleHighlightsOnly', 'toggleHighlightsOnlyView', MenuItemLocation.Note);
        return;
    }
    await joplin.views.menuItems.create('toggleHighlightsOnly', 'toggleHighlightsOnlyView', MenuItemLocation.Note, {accelerator: accelerator});
}

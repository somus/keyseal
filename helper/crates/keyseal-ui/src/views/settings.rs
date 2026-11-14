//! The settings window.

use std::path::PathBuf;

use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::switch::Switch;
use gpui_kit::component::{ActiveTheme, Disableable, Sizable, h_flex, v_flex};
use gpui_kit::{
    AnyElement, AnyWindowHandle, App, AppContext, ClipboardItem, Context, FocusHandle, Global,
    Hsla, InteractiveElement, IntoElement, ParentElement, Render, SharedString,
    StatefulInteractiveElement, Styled, Task, TestSupportExt, Window, div, prelude::FluentBuilder,
    rgb, white,
};
use keyseal_core::doctor::{Driver, DriverState, Report, Status};
use keyseal_core::preferences::Preferences;
use keyseal_core::trust::{Record, TrustStore};

use super::job::set_always_show_details;
use super::widgets::{ScrollArea, field, group, icon, note, scrolling, secondary, window_frame};
use super::{CONTEXT, Cancel, open};
use crate::{Probe, native, strings};

/// The open settings window, which a second request focuses.
struct SettingsHandle(AnyWindowHandle);

impl Global for SettingsHandle {}

/// The settings window, while it is open.
pub(super) fn settings_window(cx: &mut App) -> Option<AnyWindowHandle> {
    let SettingsHandle(handle) = *cx.try_global::<SettingsHandle>()?;
    handle.update(cx, |_, _, _| ()).ok().map(|()| handle)
}

pub(crate) fn settings_open(cx: &mut App) -> bool {
    settings_window(cx).is_some()
}

pub(crate) fn open_settings(config_dir: PathBuf, log: fn(&str), probe: Probe, cx: &mut App) {
    if let Some(handle) = settings_window(cx) {
        let _ = handle.update(cx, |_, window, _| window.activate_window());
        return;
    }
    let (handle, _) = open(
        strings::SETTINGS_WINDOW_TITLE,
        560.,
        600.,
        log,
        cx,
        |window, cx| cx.new(|cx| SettingsWindow::new(config_dir, probe, window, cx)),
    );
    cx.set_global(SettingsHandle(handle));
}

/// KeySeal's colour, for its own mark in Settings. The windows otherwise
/// keep the platform's accent, or the integrator's.
const BRAND: u32 = 0x5e5686;

/// The About group's first row: KeySeal's mark, name and version.
fn about(cx: &App) -> AnyElement {
    h_flex()
        .px_3()
        .py_3()
        .gap_3()
        .child(
            div()
                .flex_none()
                .size_10()
                .rounded(cx.theme().radius_lg)
                .bg(rgb(BRAND))
                .flex()
                .items_center()
                .justify_center()
                .child(icon("keyseal").size_6().text_color(white())),
        )
        .child(
            v_flex()
                .child(
                    div()
                        .font_weight(native::look().heading_weight)
                        .child(strings::APP_NAME),
                )
                .child(
                    div()
                        .id("version")
                        .aria_label(SharedString::from(format!(
                            "{}: {}",
                            strings::VERSION,
                            keyseal_core::VERSION
                        )))
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(format!("{} {}", strings::VERSION, keyseal_core::VERSION))
                        .test_support(),
                ),
        )
        .into_any_element()
}

/// A section's heading above its group.
fn section(heading: &'static str, cx: &App) -> impl IntoElement {
    div()
        .px_1()
        .text_sm()
        .font_weight(native::look().heading_weight)
        .text_color(cx.theme().muted_foreground)
        .child(heading)
}

/// Trusted origins with Forget, the tokens and drivers, the signer's
/// preferences, the version and the config directory.
struct SettingsWindow {
    config_dir: PathBuf,
    records: Result<Vec<Record>, String>,
    preferences: Preferences,
    /// The switch whose change wasn't saved, and why.
    preferences_error: Option<(&'static str, String)>,
    probe: Probe,
    /// What the probe found; `None` while it runs.
    tokens: Option<Result<Report, String>>,
    /// The report is on the clipboard.
    copied: bool,
    /// The running probe, dropped with the window.
    _probing: Task<()>,
    focus: FocusHandle,
    /// Shows a scrollbar while the settings are taller than the window.
    scroll: ScrollArea,
}

impl SettingsWindow {
    pub(super) fn new(
        config_dir: PathBuf,
        probe: Probe,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let focus = cx.focus_handle();
        window.focus(&focus, cx);
        let records = TrustStore::new(&config_dir).list();
        let preferences = Preferences::load(&config_dir);
        let mut this = Self {
            config_dir,
            records,
            preferences,
            preferences_error: None,
            probe,
            tokens: None,
            copied: false,
            _probing: Task::ready(()),
            focus,
            scroll: ScrollArea::default(),
        };
        this.check_tokens(cx);
        this
    }

    /// Runs the probe on the background executor; it loads drivers, which
    /// can take seconds.
    fn check_tokens(&mut self, cx: &mut Context<Self>) {
        let probe = self.probe;
        self.tokens = None;
        self.copied = false;
        self._probing = cx.spawn(async move |this, cx| {
            let tokens = cx.background_executor().spawn(async move { probe() }).await;
            let _ = this.update(cx, |this, cx| {
                this.tokens = Some(tokens);
                cx.notify();
            });
        });
        cx.notify();
    }

    fn copy_diagnostics(&mut self, cx: &mut Context<Self>) {
        if let Some(Ok(report)) = &self.tokens {
            cx.write_to_clipboard(ClipboardItem::new_string(report.text.clone()));
            self.copied = true;
            cx.notify();
        }
    }

    fn save_preferences(&mut self, switch: &'static str, cx: &mut Context<Self>) {
        self.preferences_error = self
            .preferences
            .save(&self.config_dir)
            .err()
            .map(|error| (switch, error));
        cx.notify();
    }

    fn set_translucent_windows(&mut self, on: bool, cx: &mut Context<Self>) {
        self.preferences.translucent_windows = on;
        self.save_preferences("translucent-windows", cx);
        native::set_translucent_windows(on, cx);
    }

    fn set_always_show_details(&mut self, on: bool, cx: &mut Context<Self>) {
        self.preferences.always_show_details = on;
        self.save_preferences("always-show-details", cx);
        set_always_show_details(on, cx);
    }

    fn forget(&mut self, origin: &str, cx: &mut Context<Self>) {
        let store = TrustStore::new(&self.config_dir);
        self.records = store.forget(origin).and_then(|_| store.list());
        cx.notify();
    }
}

/// A row with an icon, a title and lines under it, read out as
/// "title: lines".
fn status_row(
    id: impl Into<SharedString>,
    icon_name: &'static str,
    tint: Hsla,
    title: impl Into<SharedString>,
    lines: Vec<SharedString>,
    cx: &App,
) -> AnyElement {
    let title = title.into();
    let label = if lines.is_empty() {
        title.clone()
    } else {
        SharedString::from(format!("{title}: {}", lines.join(", ")))
    };
    h_flex()
        .id(id.into())
        .aria_label(label)
        .items_start()
        .gap_3()
        .px_3()
        .py_2()
        .child(
            icon(icon_name)
                .size_4()
                .mt_0p5()
                .flex_none()
                .text_color(tint),
        )
        .child(
            v_flex()
                .flex_1()
                .min_w_0()
                .gap_0p5()
                .child(title)
                .children(lines.into_iter().map(|line| {
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(line)
                })),
        )
        .test_support()
        .into_any_element()
}

/// How a driver went, in plain words, then with `name` its file name, then
/// any reason.
fn driver_lines(driver: &Driver, name: bool) -> Vec<SharedString> {
    let (state, reason) = match &driver.state {
        DriverState::Used => (strings::DRIVER_USED, None),
        DriverState::NoToken => (strings::DRIVER_NO_TOKEN, None),
        DriverState::Failed(reason) => (strings::DRIVER_FAILED, Some(reason.clone())),
        DriverState::Missing => (strings::DRIVER_MISSING, None),
        DriverState::NotTried => (strings::DRIVER_NOT_TRIED, None),
        DriverState::Empty => (strings::STORE_EMPTY, None),
    };
    [
        Some(state.into()),
        name.then(|| driver.name.clone().into()),
        reason.map(Into::into),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The driver that tells most about a plugged-in token: the one used, else
/// one that failed, else one that loaded, else one installed.
fn token_driver<'a>(report: &'a Report, token: &str) -> Option<&'a Driver> {
    let rank = |driver: &&Driver| match driver.state {
        DriverState::Used => 0,
        DriverState::Failed(_) => 1,
        DriverState::NoToken | DriverState::Empty => 2,
        DriverState::NotTried => 3,
        DriverState::Missing => 4,
    };
    report
        .drivers
        .iter()
        .filter(|driver| driver.token.as_deref() == Some(token))
        .min_by_key(rank)
}

impl SettingsWindow {
    /// A switch with its label, what it does, and any error saving it.
    #[allow(clippy::too_many_arguments)]
    fn switch(
        &self,
        id: &'static str,
        icon_name: &'static str,
        label: &'static str,
        note: &'static str,
        checked: bool,
        set: fn(&mut Self, bool, &mut Context<Self>),
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let muted = cx.theme().muted_foreground;
        let error = self
            .preferences_error
            .as_ref()
            .filter(|(switch, _)| *switch == id)
            .map(|(_, error)| error.clone());
        h_flex()
            .px_3()
            .py_2()
            .gap_3()
            .items_start()
            .child(
                icon(icon_name)
                    .size_4()
                    .flex_none()
                    .mt_0p5()
                    .text_color(muted),
            )
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .gap_0p5()
                    .child(label)
                    .child(div().text_sm().text_color(muted).child(note))
                    .when_some(error, |this, error| {
                        this.child(div().text_sm().text_color(cx.theme().danger).child(error))
                    }),
            )
            .child(
                div().flex_none().child(
                    Switch::new(id)
                        .checked(checked)
                        .accessibility_label(label)
                        .on_change(cx.listener(move |this, on: &bool, _, cx| set(this, *on, cx))),
                ),
            )
            .into_any_element()
    }

    /// What the probe found: a summary, each plugged-in token with its
    /// driver, the other drivers that loaded or failed, then Refresh and
    /// Copy diagnostics.
    fn tokens(&self, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let muted = cx.theme().muted_foreground;
        let danger = cx.theme().danger;
        let mut rows = Vec::new();
        match &self.tokens {
            None => rows.push(status_row(
                "tokens-status",
                "hourglass",
                muted,
                strings::CHECKING_TOKENS,
                vec![],
                cx,
            )),
            Some(Err(message)) => rows.push(status_row(
                "tokens-status",
                "circle-alert",
                danger,
                strings::CHECK_FAILED,
                vec![message.clone().into()],
                cx,
            )),
            Some(Ok(report)) => {
                rows.push(match &report.status {
                    Status::Ready => status_row(
                        "tokens-status",
                        "circle-check",
                        cx.theme().success,
                        strings::TOKEN_READY,
                        vec![strings::TOKEN_READY_NOTE.into()],
                        cx,
                    ),
                    Status::NoToken => status_row(
                        "tokens-status",
                        "usb",
                        muted,
                        strings::NO_TOKEN_FOUND,
                        vec![strings::NO_TOKEN_NOTE.into()],
                        cx,
                    ),
                    Status::Failed(reason) => status_row(
                        "tokens-status",
                        "circle-alert",
                        danger,
                        strings::TOKEN_PROBLEM,
                        vec![reason.clone().into()],
                        cx,
                    ),
                });
                for token in report.devices.iter().filter_map(|d| d.token.as_deref()) {
                    let lines = match token_driver(report, token) {
                        Some(driver) => driver_lines(driver, true),
                        None => vec![strings::NO_DRIVER_LISTED.into()],
                    };
                    rows.push(status_row(
                        format!("token {token}"),
                        "usb",
                        muted,
                        token.to_owned(),
                        lines,
                        cx,
                    ));
                }
                for driver in report.drivers.iter().filter(|driver| {
                    driver.token.is_none()
                        && matches!(
                            driver.state,
                            DriverState::Used
                                | DriverState::NoToken
                                | DriverState::Failed(_)
                                | DriverState::Empty
                        )
                }) {
                    rows.push(status_row(
                        format!("driver {}", driver.detail),
                        "package",
                        muted,
                        driver.name.clone(),
                        driver_lines(driver, false),
                        cx,
                    ));
                }
            }
        }
        let checking = self.tokens.is_none();
        let checked = matches!(self.tokens, Some(Ok(_)));
        rows.push(
            h_flex()
                .gap_2()
                .pl_3()
                .pr_2()
                .py_2()
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .text_sm()
                        .text_color(muted)
                        .child(strings::DIAGNOSTICS_NOTE),
                )
                .child(
                    secondary(Button::new("refresh"), cx)
                        .small()
                        .flex_none()
                        .icon(icon("refresh-cw"))
                        .label(strings::REFRESH)
                        .loading(checking)
                        .disabled(checking)
                        .on_click(cx.listener(|this, _, _, cx| this.check_tokens(cx))),
                )
                .child(
                    secondary(Button::new("copy-diagnostics"), cx)
                        .small()
                        .flex_none()
                        .icon(icon("copy"))
                        .label(if self.copied {
                            strings::COPIED
                        } else {
                            strings::COPY_DIAGNOSTICS
                        })
                        .disabled(!checked)
                        .on_click(cx.listener(|this, _, _, cx| this.copy_diagnostics(cx))),
                )
                .into_any_element(),
        );
        rows
    }
}

impl Render for SettingsWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let sites: Vec<AnyElement> = match &self.records {
            Err(message) => vec![
                h_flex()
                    .gap_3()
                    .px_3()
                    .py_2()
                    .child(icon("circle-alert").size_4().text_color(cx.theme().danger))
                    .child(message.clone())
                    .into_any_element(),
            ],
            Ok(records) if records.is_empty() => vec![
                v_flex()
                    .items_center()
                    .gap_2()
                    .px_3()
                    .py_5()
                    .child(icon("globe").size_6().text_color(muted))
                    .child(note(strings::NO_TRUSTED_SITES, cx))
                    .into_any_element(),
            ],
            Ok(records) => records
                .iter()
                .map(|record| {
                    let origin = record.origin.clone();
                    h_flex()
                        .gap_3()
                        .pl_3()
                        .pr_2()
                        .py_1p5()
                        .child(icon("globe-lock").size_4().flex_none().text_color(muted))
                        .child(div().flex_1().min_w_0().child(record.origin.clone()))
                        .child(
                            Button::new(SharedString::from(format!("forget {origin}")))
                                .ghost()
                                .small()
                                .icon(icon("trash"))
                                .tooltip(strings::FORGET)
                                .accessibility_label(SharedString::from(format!(
                                    "{} {origin}",
                                    strings::FORGET
                                )))
                                .on_click(
                                    cx.listener(move |this, _, _, cx| this.forget(&origin, cx)),
                                ),
                        )
                        .into_any_element()
                })
                .collect(),
        };
        let signing = self.switch(
            "always-show-details",
            "eye",
            strings::ALWAYS_SHOW_DETAILS,
            strings::ALWAYS_SHOW_DETAILS_NOTE,
            self.preferences.always_show_details,
            Self::set_always_show_details,
            cx,
        );
        let tokens = self.tokens(cx);
        window_frame(&self.focus, CONTEXT, window, cx)
            .on_action(cx.listener(|_, _: &Cancel, window, _| window.remove_window()))
            .child(
                scrolling(
                    v_flex()
                        .id("settings")
                        .flex_1()
                        .overflow_y_scroll()
                        .track_scroll(&self.scroll)
                        .px_5()
                        .pt_4()
                        .pb_5()
                        .gap_2()
                        .child(section(strings::TRUSTED_SITES, cx))
                        .child(group(sites, cx))
                        .child(div().h_3())
                        .child(section(strings::TOKENS, cx))
                        .child(group(tokens, cx))
                        .child(div().h_3())
                        .child(section(strings::SIGNING, cx))
                        .child(group([signing], cx))
                        .when(native::glass_platform(), |this| {
                            let appearance = self.switch(
                                "translucent-windows",
                                "layers",
                                strings::TRANSLUCENT_WINDOWS,
                                strings::TRANSLUCENT_NOTE,
                                self.preferences.translucent_windows,
                                Self::set_translucent_windows,
                                cx,
                            );
                            this.child(div().h_3())
                                .child(section(strings::APPEARANCE, cx))
                                .child(group([appearance], cx))
                        })
                        .child(div().h_3())
                        .child(section(strings::ABOUT, cx))
                        .child(group(
                            [
                                about(cx),
                                field(
                                    "config-directory",
                                    "folder",
                                    strings::CONFIG_DIRECTORY,
                                    self.config_dir.display().to_string(),
                                    None,
                                    cx,
                                ),
                            ],
                            cx,
                        )),
                    &self.scroll,
                )
                .flex_1(),
            )
    }
}

#[cfg(test)]
mod tests {

    use gpui_kit::test::TestWindowExt;
    use gpui_kit::{AppContext, TestAppContext};
    use keyseal_core::origin::Origin;

    use keyseal_core::trust::TrustStore;

    use keyseal_core::doctor::Status;

    use crate::views::testing::{log, open_windows, probe, setup, temp_dir};

    use crate::strings;
    use crate::views::{open_settings, sample_report};

    #[gpui_kit::test]
    fn settings_window_forgets_origins(cx: &mut TestAppContext) {
        setup(cx);
        let dir = temp_dir("settings");
        let store = TrustStore::new(&dir);
        let url = url::Url::parse("https://dash.example.org/").unwrap();
        store.trust(&Origin::of_url(&url, false).unwrap()).unwrap();

        let settings_dir = dir.clone();
        cx.update(|cx| open_settings(settings_dir.clone(), log, probe, cx));
        // A second request focuses the open window.
        cx.update(|cx| open_settings(settings_dir, log, probe, cx));
        assert_eq!(open_windows(cx).len(), 1);
        let handle = open_windows(cx)[0];
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(
                window.find("version").label(),
                Some(format!("{}: {}", strings::VERSION, keyseal_core::VERSION).as_str())
            );
            window.click("forget https://dash.example.org", cx);
        })
        .unwrap();
        assert!(store.list().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[gpui_kit::test]
    fn settings_window_shows_the_tokens_and_copies_the_report(cx: &mut TestAppContext) {
        setup(cx);
        let dir = temp_dir("tokens");
        cx.update(|cx| open_settings(dir.clone(), log, probe, cx));
        let handle = open_windows(cx)[0];
        // The probe runs off the main thread; the window shows it's looking.
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(
                window.find("tokens-status").label(),
                Some(strings::CHECKING_TOKENS)
            );
            assert_eq!(window.find("refresh").disabled(), Some(true));
            assert_eq!(window.find("copy-diagnostics").disabled(), Some(true));
        })
        .unwrap();
        cx.run_until_parked();
        let report = sample_report(Status::Ready);
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(
                window.find("tokens-status").label(),
                Some(format!("{}: {}", strings::TOKEN_READY, strings::TOKEN_READY_NOTE).as_str())
            );
            assert_eq!(
                window.find("token HyperSecu HYP2003").label(),
                Some(
                    format!(
                        "HyperSecu HYP2003: {}, libcastle.dylib",
                        strings::DRIVER_USED
                    )
                    .as_str()
                )
            );
            // An installed driver that loaded shows; a missing one doesn't.
            assert!(
                window
                    .try_find("driver /usr/local/lib/libeTPkcs11.dylib [known drivers]")
                    .is_some()
            );
            assert!(
                window
                    .try_find("driver /usr/local/lib/libmtoken.dylib [known drivers]")
                    .is_none()
            );
            window.click("copy-diagnostics", cx);
        })
        .unwrap();
        let copied = cx.update(|cx| cx.read_from_clipboard().and_then(|item| item.text()));
        assert_eq!(copied, Some(report.text));
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("refresh", cx);
            window.render_frame(cx);
            assert_eq!(
                window.find("tokens-status").label(),
                Some(strings::CHECKING_TOKENS)
            );
        })
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

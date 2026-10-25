//! The platform's look: light or dark as the system is, its default accent,
//! type size, corner radii, window and grouped-box colours, and how a
//! dialog lays out its buttons. One layout serves every platform; these
//! tokens make it read as a macOS, Windows 11 or GNOME window. On macOS the
//! window is glass: the system's translucent window material shows through
//! a transparent title bar and background.

use gpui_kit::component::{ActiveTheme, Theme, ThemeMode};
use gpui_kit::{
    App, FontWeight, Global, Hsla, Pixels, TitlebarOptions, Window, WindowAppearance,
    WindowBackgroundAppearance, px, rgb, rgba,
};

/// How a dialog's buttons sit at its foot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Buttons {
    /// Right-aligned, the primary button last (macOS).
    TrailingPrimaryLast,
    /// Filling the foot in equal widths, the primary button first, on a
    /// band of their own (Windows 11's `ContentDialog`).
    BandPrimaryFirst,
    /// Filling the foot in equal widths, the primary button last
    /// (libadwaita's `AdwAlertDialog`).
    WidePrimaryLast,
}

/// One appearance's colours, each `0xrrggbbaa`.
#[derive(Clone, Copy)]
pub(crate) struct Palette {
    pub accent: u32,
    pub accent_hover: u32,
    pub accent_active: u32,
    pub on_accent: u32,
    /// The window behind everything; translucent over glass.
    pub window: u32,
    /// Grouped boxes, and the content of a window with a button band.
    pub group: u32,
    /// The button band's background, where the platform has one.
    pub band: u32,
    /// Borders and the dividers between a group's rows.
    pub separator: u32,
    /// Buttons other than the primary one.
    pub control: u32,
    pub control_border: u32,
    /// Field borders and radio outlines.
    pub input_border: u32,
    pub danger: u32,
    pub warning: u32,
    /// Labels and secondary text.
    pub muted_text: u32,
}

/// The platform's tokens.
pub(crate) struct Look {
    /// The body text size; every `text_*` size scales from it.
    pub font_size: f32,
    /// Buttons and fields.
    pub radius: f32,
    /// Grouped boxes and banners.
    pub radius_lg: f32,
    /// The narrowest a button gets.
    pub button_min_width: f32,
    pub buttons: Buttons,
    /// Headings: bold in macOS alerts and libadwaita, semibold in Windows
    /// 11. Fonts without a semibold face, such as Ubuntu, would otherwise
    /// fall back to regular.
    pub heading_weight: FontWeight,
    /// Alerts centre their heading and text, as macOS and libadwaita do;
    /// Windows aligns them to the leading edge.
    pub centered_alerts: bool,
    /// The window is glass: blurred, with its content under a transparent
    /// title bar `titlebar_height` tall. macOS only.
    pub glass: bool,
    pub titlebar_height: f32,
    pub light: Palette,
    pub dark: Palette,
}

const MAC: Look = Look {
    font_size: 13.,
    radius: 6.,
    radius_lg: 10.,
    button_min_width: 76.,
    buttons: Buttons::TrailingPrimaryLast,
    heading_weight: FontWeight::BOLD,
    centered_alerts: true,
    glass: true,
    titlebar_height: 28.,
    // System blue over the glass, grouped boxes a light frost of the same
    // glass. GPUI's glass is the blur alone, without the material's own
    // tint, so the window's tint is all that separates text from what's
    // behind it. Dark text stays readable on the grey a dark wallpaper
    // makes of a light 30% tint; light text washes out on a bright one, so
    // dark windows take 45%. Secondary text is a step stronger than
    // AppKit's for the same reason.
    light: Palette {
        accent: 0x007affff,
        accent_hover: 0x0068d9ff,
        accent_active: 0x0056b3ff,
        on_accent: 0xffffffff,
        window: 0xf2f2f24d,
        group: 0xffffff40,
        band: 0x00000000,
        separator: 0x0000001a,
        control: 0xffffffe6,
        control_border: 0x00000026,
        input_border: 0x00000040,
        danger: 0xd70015ff,
        warning: 0xc93400ff,
        muted_text: 0x3c3c43ff,
    },
    dark: Palette {
        accent: 0x0a84ffff,
        accent_hover: 0x2994ffff,
        accent_active: 0x0070d9ff,
        on_accent: 0xffffffff,
        window: 0x1e1e1e73,
        group: 0xffffff12,
        band: 0x00000000,
        separator: 0xffffff1f,
        control: 0xffffff29,
        control_border: 0xffffff14,
        input_border: 0xffffff4d,
        danger: 0xff453aff,
        warning: 0xff9f0aff,
        muted_text: 0xd1d1d6ff,
    },
};

const WINDOWS: Look = Look {
    font_size: 14.,
    radius: 4.,
    radius_lg: 8.,
    button_min_width: 120.,
    buttons: Buttons::BandPrimaryFirst,
    heading_weight: FontWeight::SEMIBOLD,
    centered_alerts: false,
    glass: false,
    titlebar_height: 0.,
    // Windows 11's default accent, the dialog layer and its footer.
    light: Palette {
        accent: 0x005fb8ff,
        accent_hover: 0x1a6fbfff,
        accent_active: 0x3380c6ff,
        on_accent: 0xffffffff,
        window: 0xffffffff,
        group: 0xf9f9f9ff,
        band: 0xf3f3f3ff,
        separator: 0x0000000f,
        control: 0xfbfbfbff,
        control_border: 0x0000001f,
        input_border: 0x00000066,
        danger: 0xc42b1cff,
        warning: 0x9d5d00ff,
        muted_text: 0x737373ff,
    },
    dark: Palette {
        accent: 0x60cdffff,
        accent_hover: 0x5bb9e6ff,
        accent_active: 0x56a6ccff,
        on_accent: 0x000000ff,
        window: 0x2b2b2bff,
        group: 0x323232ff,
        band: 0x202020ff,
        separator: 0xffffff15,
        control: 0x373737ff,
        control_border: 0xffffff17,
        input_border: 0xffffff66,
        danger: 0xff99a4ff,
        warning: 0xfce100ff,
        muted_text: 0xa3a3a3ff,
    },
};

const GNOME: Look = Look {
    // Adwaita Sans at 11pt.
    font_size: 14.67,
    radius: 6.,
    radius_lg: 12.,
    button_min_width: 96.,
    buttons: Buttons::WidePrimaryLast,
    heading_weight: FontWeight::BOLD,
    centered_alerts: true,
    glass: false,
    titlebar_height: 0.,
    // libadwaita's blue accent, window and card colours.
    light: Palette {
        accent: 0x3584e4ff,
        accent_hover: 0x4990e7ff,
        accent_active: 0x2a6ab7ff,
        on_accent: 0xffffffff,
        window: 0xfafafbff,
        group: 0xffffffff,
        band: 0xfafafbff,
        separator: 0x00000017,
        control: 0x0000001a,
        control_border: 0x00000000,
        input_border: 0x00000040,
        danger: 0xc01c28ff,
        warning: 0x9c6e03ff,
        muted_text: 0x737373ff,
    },
    dark: Palette {
        accent: 0x3584e4ff,
        accent_hover: 0x4990e7ff,
        accent_active: 0x2a6ab7ff,
        on_accent: 0xffffffff,
        window: 0x222226ff,
        group: 0x2e2e32ff,
        band: 0x222226ff,
        separator: 0xffffff17,
        control: 0xffffff1a,
        control_border: 0x00000000,
        input_border: 0xffffff4d,
        danger: 0xff7b63ff,
        warning: 0xf8e45cff,
        muted_text: 0xa3a3a3ff,
    },
};

/// This platform's look. The gallery takes another from `KEYSEAL_GALLERY_LOOK`
/// (`mac`, `windows` or `gnome`), to preview it on any machine.
pub(crate) fn look() -> &'static Look {
    #[cfg(feature = "gallery")]
    match std::env::var("KEYSEAL_GALLERY_LOOK").as_deref() {
        Ok("mac") => return &MAC,
        Ok("windows") => return &WINDOWS,
        Ok("gnome") => return &GNOME,
        _ => {}
    }
    if cfg!(target_os = "macos") {
        &MAC
    } else if cfg!(windows) {
        &WINDOWS
    } else {
        &GNOME
    }
}

/// Whether this platform's windows can be glass: macOS. Their title bar
/// is transparent either way, so glass can come and go in an open window.
pub(crate) fn glass_platform() -> bool {
    look().glass && cfg!(target_os = "macos")
}

/// Who has turned glass off: the signer in Settings, or the integrator's
/// manifest (`translucent: false`) while its job window shows.
struct Translucency {
    preferred: bool,
    brand: bool,
}

impl Global for Translucency {}

/// Whether windows are glass now: on macOS, unless the system's Reduce
/// transparency, the signer or the integrator asks for opaque windows.
fn glass(cx: &App) -> bool {
    let translucency = cx.try_global::<Translucency>();
    glass_platform()
        && !reduce_transparency()
        && translucency.is_none_or(|t| t.preferred && t.brand)
}

#[cfg(target_os = "macos")]
pub(crate) fn reduce_transparency() -> bool {
    objc2_app_kit::NSWorkspace::sharedWorkspace().accessibilityDisplayShouldReduceTransparency()
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn reduce_transparency() -> bool {
    false
}

fn background(cx: &App) -> WindowBackgroundAppearance {
    if glass(cx) {
        WindowBackgroundAppearance::Blurred
    } else {
        WindowBackgroundAppearance::Opaque
    }
}

/// Sets the signer's choice from Settings, and applies it to the windows
/// already open.
pub(crate) fn set_translucent_windows(preferred: bool, cx: &mut App) {
    let brand = cx.try_global::<Translucency>().is_none_or(|t| t.brand);
    cx.set_global(Translucency { preferred, brand });
    refresh(cx);
}

/// Matches every open window's background, and the theme, to [`glass`].
fn refresh(cx: &mut App) {
    tokens(cx);
    let background = background(cx);
    for window in cx.windows() {
        let _ = window.update(cx, |_, window, _| {
            window.set_background_appearance(background)
        });
    }
}

/// The palette the system's appearance calls for. Off glass, a palette's
/// translucent window colour would show black, so it is made opaque.
pub(crate) fn palette(cx: &App) -> &'static Palette {
    if cx.theme().is_dark() {
        &look().dark
    } else {
        &look().light
    }
}

/// `0xrrggbbaa`.
pub(crate) fn color(value: u32) -> Hsla {
    rgba(value).into()
}

pub(crate) fn font_size() -> Pixels {
    px(look().font_size)
}

/// The title bar and background a new window opens with: on macOS a
/// transparent title bar over a blurred window.
pub(crate) fn window_chrome(
    title: &'static str,
    cx: &App,
) -> (TitlebarOptions, WindowBackgroundAppearance) {
    (
        TitlebarOptions {
            title: Some(title.into()),
            appears_transparent: glass_platform(),
            ..Default::default()
        },
        background(cx),
    )
}

/// The space content leaves above it for a transparent title bar.
pub(crate) fn titlebar_inset() -> Pixels {
    px(if glass_platform() {
        look().titlebar_height
    } else {
        0.
    })
}

fn mode(appearance: WindowAppearance) -> ThemeMode {
    match appearance {
        WindowAppearance::Dark | WindowAppearance::VibrantDark => ThemeMode::Dark,
        WindowAppearance::Light | WindowAppearance::VibrantLight => ThemeMode::Light,
    }
}

/// The integrator's accent colour, `0xrrggbb`, while a job's window
/// shows. It takes the place of the platform's accent on the primary
/// button and the focus ring; the trust prompt never shows it.
struct BrandAccent(Option<u32>);

impl Global for BrandAccent {}

/// The colours a button in `accent` needs: hover, pressed and the text
/// on it, white or black by the accent's luminance.
fn accent_states(accent: u32) -> (Hsla, Hsla, Hsla, Hsla) {
    let [r, g, b] = [16, 8, 0].map(|shift| ((accent >> shift) & 0xff) as f32 / 255.);
    let linear = |c: f32| {
        if c <= 0.04045 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    let luminance = 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b);
    let base: Hsla = rgb(accent).into();
    let shade = |delta: f32| Hsla {
        l: (base.l + delta).clamp(0., 1.),
        ..base
    };
    // Black text from the luminance where it contrasts better than white.
    let on = if luminance > 0.179 {
        0x000000
    } else {
        0xffffff
    };
    (base, shade(0.06), shade(-0.08), rgb(on).into())
}

/// Shows `accent`, an integrator's `0xrrggbb`, on the primary button and
/// the focus ring, or the platform's accent again with `None`. With
/// `translucent` false the windows are opaque while the job shows.
pub(crate) fn set_brand(accent: Option<u32>, translucent: bool, cx: &mut App) {
    let preferred = cx.try_global::<Translucency>().is_none_or(|t| t.preferred);
    let unchanged = cx.try_global::<BrandAccent>().map(|brand| brand.0) == Some(accent)
        && cx.try_global::<Translucency>().is_none_or(|t| t.brand) == translucent;
    if unchanged {
        return;
    }
    cx.set_global(BrandAccent(accent));
    cx.set_global(Translucency {
        preferred,
        brand: translucent,
    });
    refresh(cx);
}

/// Matches the theme to `appearance` and puts the platform's tokens on it.
pub(crate) fn apply(appearance: WindowAppearance, cx: &mut App) {
    Theme::change(mode(appearance), None, cx);
    tokens(cx);
}

fn tokens(cx: &mut App) {
    let palette = palette(cx);
    let (accent, hover, active, on_accent) =
        match cx.try_global::<BrandAccent>().and_then(|brand| brand.0) {
            Some(brand) => accent_states(brand),
            None => (
                color(palette.accent),
                color(palette.accent_hover),
                color(palette.accent_active),
                color(palette.on_accent),
            ),
        };
    let glass = glass(cx);
    Theme::update(cx, |theme| {
        theme.font_size = font_size();
        theme.radius = px(look().radius);
        theme.radius_lg = px(look().radius_lg);
        theme.shadow = false;
        let window = color(palette.window);
        let colors = &mut theme.colors;
        colors.background = if glass { window } else { window.alpha(1.) };
        colors.primary = accent;
        colors.primary_hover = hover;
        colors.primary_active = active;
        colors.primary_foreground = on_accent;
        colors.button_primary = accent;
        colors.button_primary_hover = hover;
        colors.button_primary_active = active;
        colors.button_primary_foreground = on_accent;
        colors.ring = accent;
        colors.caret = accent;
        colors.selection = accent.opacity(0.3);
        colors.danger = color(palette.danger);
        colors.warning = color(palette.warning);
        colors.input = color(palette.input_border);
        colors.muted_foreground = color(palette.muted_text);
    });
}

/// Follows the system's appearance in `window` from now on. The gallery
/// takes `light` or `dark` from `KEYSEAL_GALLERY_APPEARANCE` instead.
pub(crate) fn follow_appearance(window: &mut Window, cx: &mut App) {
    #[cfg(feature = "gallery")]
    match std::env::var("KEYSEAL_GALLERY_APPEARANCE").as_deref() {
        Ok("light") => return apply(WindowAppearance::Light, cx),
        Ok("dark") => return apply(WindowAppearance::Dark, cx),
        _ => {}
    }
    apply(window.appearance(), cx);
    window
        .observe_window_appearance(|window, cx| apply(window.appearance(), cx))
        .detach();
}

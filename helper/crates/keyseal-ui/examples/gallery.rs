//! Opens one of the helper's windows with sample data:
//! `cargo run -p keyseal-ui --example gallery --features gallery -- <view>`.

fn main() {
    let view = std::env::args().nth(1).unwrap_or_default();
    if !keyseal_ui::GALLERY_VIEWS.contains(&view.as_str()) {
        eprintln!("views: {}", keyseal_ui::GALLERY_VIEWS.join(", "));
        std::process::exit(2);
    }
    keyseal_ui::gallery(&view);
}

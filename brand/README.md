# Brand

KeySeal's mark is a hardware token merged with a seal: a token body with a seal impression and a plug.

| File | Use |
| --- | --- |
| `keyseal-mark.svg` | The mark alone, one colour (`currentColor`), 24 by 24. The helper's Settings window bundles a copy as `helper/crates/keyseal-ui/icons/keyseal.svg` |
| `keyseal-icon.svg` | App icon on Apple's grid (an 824 px plate on a 1024 px canvas), for macOS, Linux and documentation |
| `keyseal-icon-windows.svg` | App icon for Windows, with a larger plate, since Windows icons have no margin |

The colour is `#5E5686`, with the mark in white on it.

## Where the brand appears

The helper is white-label, so the brand stays on KeySeal's own surfaces: the app icon, the About section of Settings, the README and the download pages. The helper's windows use the platform's accent colour, or the integrator's `accentColor`, never KeySeal's, and a job window without an integrator logo shows a neutral icon.

## Regenerating the icons

`scripts/make-icons.sh` turns the SVGs into `helper/packaging/macos/AppIcon.icns`, `helper/packaging/windows/keyseal.ico` and `helper/packaging/linux/keyseal.svg`. It needs macOS with `rsvg-convert` and ImageMagick (`brew install librsvg imagemagick`). Commit the results.

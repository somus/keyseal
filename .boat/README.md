# PR evidence for KeySeal

A maintainer's PR carries evidence from `boat-kit verify --pr <n>` in its description. boat-kit is the maintainers' own tool, in their private agent-config repository, whose README covers it; a contributor without it relies on CI, which runs the same tests. Push first: the sandboxes check the commit out from origin.

- **Tests.** The helper's Rust tests run on the head with SoftHSM, as in CI, together with `bun test` and the signing service's tests. Arguments filter the Rust tests: `boat-kit verify --pr 12 softhsm`. A runner that fails before its tests run, on a build error or a test file that doesn't load, fails the run instead of leaving its tests out of the evidence. The end-to-end test is left to CI.
- **Helper windows.** For a change to what the helper shows, pass `--scenario <file>`: the helper windows to screenshot, in two sandboxes at once, one on the merge base and one on the head. Each opens from the gallery's sample data (`cargo run -p keyseal-ui --example gallery --features gallery -- <view>`) on the sandbox's X display, rendered through software Vulkan.

## The scenario

A text file with one window per line: the gallery view, then optionally the look (`gnome`, `mac` or `windows`; default `gnome`) and the appearance (`light` or `dark`; default `light`). Blank lines and `#` comments are skipped. Keep it out of the repository.

```text
pin
pin mac dark
trust windows
settings-driver-failed
```

- The views are `GALLERY_VIEWS` in `helper/crates/keyseal-ui/src/views.rs`. A view the branch adds fails on the merge base, which marks it as new.
- Pick every look the change affects: the mac and windows looks are drawn by the same code, so they show in Linux sandboxes too.
- The shots show the gallery's sample data, not a live job. A change to what a real job puts in a window needs the sample data in `views.rs` to cover it.

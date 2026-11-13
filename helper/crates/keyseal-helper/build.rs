//! Embeds the Windows icon and version information (`keyseal.rc`) in
//! `keyseal.exe`.

fn main() {
    println!("cargo:rerun-if-changed=keyseal.rc");
    println!("cargo:rerun-if-changed=../../packaging/windows/keyseal.ico");
    let macros = [
        concat!("KEYSEAL_VERSION_MAJOR=", env!("CARGO_PKG_VERSION_MAJOR")),
        concat!("KEYSEAL_VERSION_MINOR=", env!("CARGO_PKG_VERSION_MINOR")),
        concat!("KEYSEAL_VERSION_PATCH=", env!("CARGO_PKG_VERSION_PATCH")),
        concat!("KEYSEAL_VERSION=\"", env!("CARGO_PKG_VERSION"), "\""),
    ];
    let compiled = embed_resource::compile("keyseal.rc", macros);
    // A Windows host has rc.exe, so a release built there always carries the
    // icon. A cross build without llvm-rc goes without it.
    if cfg!(windows) {
        compiled.manifest_required().unwrap();
    } else {
        compiled.manifest_optional().unwrap();
    }
}

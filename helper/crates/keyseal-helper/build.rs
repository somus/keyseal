//! Embeds the Windows icon (`keyseal.rc`) in `keyseal.exe`.

fn main() {
    println!("cargo:rerun-if-changed=keyseal.rc");
    println!("cargo:rerun-if-changed=../../packaging/windows/keyseal.ico");
    let compiled = embed_resource::compile("keyseal.rc", embed_resource::NONE);
    // A Windows host has rc.exe, so a release built there always carries the
    // icon. A cross build without llvm-rc goes without it.
    if cfg!(windows) {
        compiled.manifest_required().unwrap();
    } else {
        compiled.manifest_optional().unwrap();
    }
}

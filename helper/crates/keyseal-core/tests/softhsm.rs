//! A second job in the same process loads the driver again; it is still
//! started, since it is never finalised. Runs when `KEYSEAL_SOFTHSM_MODULE`
//! names libsofthsm2, like the other SoftHSM suites.

#[path = "../../../testing/softhsm.rs"]
mod fixture;

use std::path::Path;

use keyseal_core::token::Module;

#[test]
fn a_driver_loads_twice_in_one_process() {
    let Ok(module) = std::env::var("KEYSEAL_SOFTHSM_MODULE") else {
        eprintln!("skipped: set KEYSEAL_SOFTHSM_MODULE to libsofthsm2 to run");
        return;
    };
    // SoftHSM won't start without a readable token directory.
    let dir = std::env::temp_dir().join(format!("keyseal-core-softhsm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let conf = fixture::softhsm_conf(&dir, "tokens");
    // SAFETY: the only test in this binary, and no other thread reads the
    // environment while it is set.
    unsafe { std::env::set_var("SOFTHSM2_CONF", &conf) };

    let path = Path::new(&module);
    for _ in 0..2 {
        if let Err(error) = Module::load(path) {
            panic!("{}", error.0);
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

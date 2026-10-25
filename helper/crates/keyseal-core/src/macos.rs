//! macOS glue. A browser opens a `keyseal://` link by asking Launch Services,
//! which starts `KeySeal.app` and hands it the link as an Apple Event, not an
//! argument. [`launch_url`] reads that event for the headless helper; the
//! GUI receives the same event through GPUI's open-URLs callback instead.

use std::cell::RefCell;
use std::ffi::c_void;
use std::path::Path;
use std::time::{Duration, Instant};

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{DefinedClass, MainThreadMarker, MainThreadOnly, define_class, msg_send};
use objc2_app_kit::{NSApplication, NSApplicationDelegate, NSEventMask};
use objc2_foundation::{
    NSArray, NSDate, NSDefaultRunLoopMode, NSObject, NSObjectProtocol, NSString, NSURL,
};

/// The app bundle `exe` runs from: `KeySeal.app/Contents/MacOS/keyseal`.
pub fn bundle(exe: &Path) -> Option<&Path> {
    exe.ancestors()
        .nth(3)
        .filter(|path| path.extension().is_some_and(|ext| ext == "app"))
}

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn LSRegisterURL(url: *const c_void, update: u8) -> i32;
}

/// Registers `bundle` with Launch Services now, which is what makes its
/// `CFBundleURLTypes` claim `keyseal://`.
pub fn register(bundle: &Path) -> Result<(), String> {
    let path = bundle.to_str().ok_or("The app path isn't valid UTF-8.")?;
    let url = NSURL::fileURLWithPath(&NSString::from_str(path));
    // NSURL is toll-free bridged to CFURLRef.
    let status = unsafe { LSRegisterURL(Retained::as_ptr(&url).cast(), 1) };
    if status != 0 {
        return Err(format!("Launch Services refused {path} (status {status})."));
    }
    Ok(())
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "KeySealLinkDelegate"]
    #[ivars = RefCell<Option<String>>]
    struct LinkDelegate;

    unsafe impl NSObjectProtocol for LinkDelegate {}

    unsafe impl NSApplicationDelegate for LinkDelegate {
        #[unsafe(method(application:openURLs:))]
        fn open_urls(&self, _application: &NSApplication, urls: &NSArray<NSURL>) {
            let first = urls.firstObject().and_then(|url| url.absoluteString());
            if let Some(url) = first {
                self.ivars().replace(Some(url.to_string()));
            }
        }
    }
);

/// The link this launch was opened with, waiting up to `wait` for the
/// event. `None` when the app was opened another way, or off the main
/// thread.
pub fn launch_url(wait: Duration) -> Option<String> {
    let mtm = MainThreadMarker::new()?;
    let app = NSApplication::sharedApplication(mtm);
    let delegate = LinkDelegate::alloc(mtm).set_ivars(RefCell::new(None));
    let delegate: Retained<LinkDelegate> = unsafe { msg_send![super(delegate), init] };
    app.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    app.finishLaunching();
    let deadline = Instant::now() + wait;
    let link = loop {
        if let Some(link) = delegate.ivars().take() {
            break Some(link);
        }
        if Instant::now() >= deadline {
            break None;
        }
        // Apple Events are dispatched while AppKit waits for an event.
        let until = NSDate::dateWithTimeIntervalSinceNow(0.1);
        let event = unsafe {
            app.nextEventMatchingMask_untilDate_inMode_dequeue(
                NSEventMask::Any,
                Some(&until),
                NSDefaultRunLoopMode,
                true,
            )
        };
        if let Some(event) = event {
            app.sendEvent(&event);
        }
    };
    app.setDelegate(None);
    link
}

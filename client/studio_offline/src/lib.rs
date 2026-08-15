use minhook_sys::*;
use windows::{
    Win32::Foundation::*, Win32::System::Console::*, Win32::System::Memory::*,
    Win32::System::SystemServices::*,
};

extern "C" {
    fn freopen_s(
        stream: *mut *mut std::ffi::c_void,
        filename: *const i8,
        mode: *const i8,
        old_stream: *mut std::ffi::c_void,
    ) -> i32;
    fn __acrt_iob_func(idx: u32) -> *mut std::ffi::c_void;
}

mod hooks;
mod patterns;
mod scanner;

#[no_mangle]
extern "system" fn DllMain(_hmod: HMODULE, reason: u32, _reserved: *mut std::ffi::c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH
        && (std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("OFFLINE_STUDIO")
            .exists()
            || std::env::args().any(|arg| arg == "--offline"))
    {
        unsafe {
            let _ = AllocConsole();
            let mut f = std::ptr::null_mut();
            let stdin_file = __acrt_iob_func(0);
            let stdout_file = __acrt_iob_func(1);
            let _ = freopen_s(
                &mut f,
                c"CONIN$".as_ptr() as _,
                c"r".as_ptr() as _,
                stdin_file,
            );
            let _ = freopen_s(
                &mut f,
                c"CONOUT$".as_ptr() as _,
                c"w".as_ptr() as _,
                stdout_file,
            );
            println!("Starting Studio-Offline");

            MH_Initialize();

            if let Some(addr) = scanner::aob_scan(patterns::URL_ONCOMPONENT) {
                MH_CreateHook(
                    addr as _,
                    hooks::hook_test as _,
                    &raw mut hooks::ORIGINAL as *mut _ as *mut _,
                );
                MH_EnableHook(addr as _);
                println!("FromComponents: 0x{addr:x}");
            }

            if let Some(trustcheck_addr) = scanner::aob_scan(patterns::TRUSTCHECK) {
                MH_CreateHook(
                    trustcheck_addr as _,
                    hooks::trustcheck_hook as _,
                    &raw mut hooks::OG_TC as *mut _ as *mut _,
                );
                MH_EnableHook(trustcheck_addr as _);
                println!("TrustCheck: 0x{trustcheck_addr:x}");
            }

            if let Some(httprequest_addr) = scanner::aob_scan(patterns::HTTP_REQUEST_URL) {
                MH_CreateHook(
                    httprequest_addr as _,
                    hooks::nottrusted_hook as _,
                    &raw mut hooks::ORIGINAL_HTTP_NT as *mut _ as *mut _,
                );
                MH_EnableHook(httprequest_addr as _);
                println!("HttpRequest_notTrusted: 0x{httprequest_addr:x}");
            }

            // AsyncHttpQueue trust check: the hooked TrustCheck (above) is a
            // different function; this one builds `{}: Trust check failed` for
            // non-whitelisted URLs like http://localhost/... Patch the
            // `test al,al` at +17 to `mov al,1` so the `jne` success path is
            // always taken.
            println!("Patching AsyncHttpQueue trust check...");
            if let Some(async_trust_addr) = scanner::aob_scan(patterns::ASYNC_TRUST_CHECK) {
                println!("Found AsyncHttpQueue trust check at 0x{async_trust_addr:x}");
                let test_addr = async_trust_addr + 17;
                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                let _ = VirtualProtect(
                    test_addr as *const _,
                    2,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                );
                *(test_addr as *mut u8) = 0xB0;
                *(test_addr as *mut u8).add(1) = 0x01;
                let _ = VirtualProtect(test_addr as *const _, 2, old_protect, &mut old_protect);
                println!("Patched test al,al -> mov al,1 at 0x{test_addr:x}");
            } else {
                println!("Failed to find AsyncHttpQueue trust check pattern");
            }

            // The fetcher (0x14234E590) throws "Error fetching latest place version"
            // at 0x14234EC00 before any HTTP when its 8th stack arg != 0 (caller 2,
            // content types 2/4/10) and no version could be resolved. NOP the
            // `jne 0x14234ec00` at 0x14234E994 so it falls through to build the
            // /v1/asset/?id=%lld URL and call the dispatcher (real HTTP).
            println!("Patching latest-place-version throw...");
            if let Some(fetcher_addr) = scanner::aob_scan(patterns::FETCHER_JNE_THROW) {
                println!("Found fetcher jne at 0x{fetcher_addr:x}");
                let jne_addr = fetcher_addr + 7;
                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                let _ = VirtualProtect(
                    jne_addr as *const _,
                    6,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                );
                for i in 0..6 {
                    *(jne_addr as *mut u8).add(i) = 0x90;
                }
                let _ = VirtualProtect(jne_addr as *const _, 6, old_protect, &mut old_protect);
                println!("NOPed fetcher jne at 0x{jne_addr:x}");
            } else {
                println!("Failed to find fetcher jne pattern");
            }

            println!("Redirecting latest-place-version URL...");
            if let Some((base, size)) = scanner::get_module_info("RobloxStudioBeta.exe") {
                let old_url = "https://data.%1/Data/Upload.ashx?assetid=%2";
                if let Some(url_addr) = scanner::scan_string(base, size, old_url) {
                    println!("Found latest-place-version URL at 0x{url_addr:x}");
                    let replacement = "http://localhost/Data/Upload.ashx?a=%1&b=%2";
                    assert_eq!(old_url.len(), replacement.len());
                    let ptr = url_addr as *mut u8;
                    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                    let _ = VirtualProtect(
                        ptr as *const _,
                        replacement.len(),
                        PAGE_EXECUTE_READWRITE,
                        &mut old_protect,
                    );
                    std::ptr::copy_nonoverlapping(
                        replacement.as_ptr(),
                        ptr,
                        replacement.len(),
                    );
                    let _ =
                        VirtualProtect(ptr as *const _, replacement.len(), old_protect, &mut old_protect);
                    println!("Patched latest-place-version URL -> {replacement}");
                } else {
                    println!("Failed to find latest-place-version URL");
                }
            }

            // i don't know why the security cookie check is failing so let's just patch it
            println!("Applying Security Cookie Patch...");
            if let Some((base, size)) = scanner::get_module_info("RobloxStudioBeta.exe") {
                let s = "[FLog::StudioCookieManager] Security cookie is cached so we proceed saving now.";
                if let Some(str_addr) = scanner::scan_string(base, size, s) {
                    println!("Found \"{s}\" at 0x{str_addr:x}");
                    if let Some(xref) = scanner::scan_xref(base, size, str_addr) {
                        println!("Found XREF at 0x{xref:x}");
                        if let Some(jz_addr) =
                            scanner::find_jz_from_cmp_backwards_for_the_security_cookie(xref)
                        {
                            println!("Found JZ at 0x{jz_addr:x}");

                            let ptr = jz_addr as *mut u8;
                            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                            let _ = VirtualProtect(
                                ptr as *const _,
                                2,
                                PAGE_EXECUTE_READWRITE,
                                &mut old_protect,
                            );

                            if *ptr == 0x74 {
                                *ptr = 0x75;
                                println!("Patched JZ to JNZ");
                            } else if *ptr == 0x0F && *ptr.add(1) == 0x84 {
                                *ptr.add(1) = 0x85;
                                println!("Patched JZ to JNZ");
                            } else {
                                println!("Patching failed.");
                            }

                            let _ =
                                VirtualProtect(ptr as *const _, 2, old_protect, &mut old_protect);
                        } else {
                            println!("Failed to find JZ instruction");
                        }
                    } else {
                        println!("Failed to find XREF to string");
                    }
                } else {
                    println!("Failed to find string");
                }
            }
        }
    }
    TRUE
}

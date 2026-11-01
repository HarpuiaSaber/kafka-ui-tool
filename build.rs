fn main() {
    slint_build::compile("ui/app.slint").expect("failed to compile Slint UI");

    println!("cargo:rerun-if-changed=assets/kafka-message-tool.ico");
    println!("cargo:rerun-if-changed=assets/kafa-ui-tool.rc");

    // build-windows.bat loads the Visual Studio environment, including rc.exe.
    if cfg!(windows) {
        let output =
            std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("kafa-ui-tool.res");
        let compiled = std::process::Command::new("rc.exe")
            .args(["/nologo", "/fo"])
            .arg(&output)
            .arg("assets\\kafa-ui-tool.rc")
            .status()
            .is_ok_and(|status| status.success());
        if compiled {
            println!("cargo:rustc-link-arg={}", output.display());
        } else if std::env::var("PROFILE").as_deref() == Ok("release") {
            panic!("rc.exe must compile assets/kafa-ui-tool.rc for a release build");
        } else {
            println!("cargo:warning=rc.exe unavailable; executable icon resource was not embedded");
        }
    }
}

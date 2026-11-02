use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    slint_build::compile("ui/app.slint").expect("failed to compile Slint UI");

    println!("cargo:rerun-if-changed=assets/kafka-message-tool.ico");

    // build-windows.bat loads the Visual Studio environment, including rc.exe.
    if cfg!(windows) {
        let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is not set"));
        let version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION is not set");
        let mut parts = version.split('.').map(|part| {
            part.parse::<u16>()
                .expect("package version must have numeric parts")
        });
        let (major, minor, patch) = (
            parts.next().expect("package version must have a major part"),
            parts.next().expect("package version must have a minor part"),
            parts.next().expect("package version must have a patch part"),
        );
        let icon_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest path is not set"))
            .join("assets/kafka-message-tool.ico")
            .to_string_lossy()
            .replace('\\', "/");
        let resource = format!(
            r#"IDI_APP_ICON ICON "{icon_path}"

1 VERSIONINFO
FILEVERSION {major},{minor},{patch},0
PRODUCTVERSION {major},{minor},{patch},0
FILEOS 0x4L
FILETYPE 0x1L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName", "MBBank\0"
            VALUE "FileDescription", "Kafka UI Tool\0"
            VALUE "FileVersion", "{version}.0\0"
            VALUE "InternalName", "kafka-ui-tool\0"
            VALUE "OriginalFilename", "kafka-ui-tool.exe\0"
            VALUE "ProductName", "Kafka UI Tool\0"
            VALUE "ProductVersion", "{version}.0\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
"#
        );
        let resource_path = out_dir.join("version.rc");
        let output = out_dir.join("version.res");
        fs::write(&resource_path, resource).expect("could not write Windows version resource");
        let compiled = Command::new("rc.exe")
            .args(["/nologo", "/fo"])
            .arg(&output)
            .arg(&resource_path)
            .status()
            .is_ok_and(|status| status.success());
        if compiled {
            println!("cargo:rustc-link-arg={}", output.display());
        } else if std::env::var("PROFILE").as_deref() == Ok("release") {
            panic!("rc.exe must compile the Windows version resource for a release build");
        } else {
            println!("cargo:warning=rc.exe unavailable; executable icon resource was not embedded");
        }
    }
}

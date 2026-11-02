# Kafka UI Tool

Windows-first Kafka explorer built with Rust, Slint, Tokio, and rdkafka. It
does not use a WebView.

## Build on Windows

Install Rust, Visual Studio Build Tools with the **Desktop development with
C++** workload, CMake, and Strawberry Perl. The release build uses bundled
OpenSSL, so CMake and Perl must be available. The first build can take several
minutes while native dependencies compile.

Double-click `build-windows.bat`, or run it from Command Prompt. It runs
release tests, builds the executable, and writes `dist/kafka-ui-tool.zip`.
The receiving Windows x64 machine does not need Rust; it may need the Microsoft
Visual C++ Redistributable for x64.

## VM and VDI

Normal Windows machines use Slint's default renderer. On a VM/VDI where GPU
rendering is unavailable, open Command Prompt in the extracted app directory:

```bat
set SLINT_BACKEND=software
kafka-ui-tool.exe
```

The setting affects only that terminal. You may create a separate local batch
file with those two commands for the virtual machine; do not change the normal
release build or application source to force software rendering.

## Development checks

Agents normally run tests only when asked. User-operated full packaging is
`build-windows.bat`. For a source-only check, run `cargo fmt --check` and
`cargo test`.

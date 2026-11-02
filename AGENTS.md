# Project agent guide

## Purpose

This is a Windows-first Kafka explorer built with Rust, Slint, Tokio, and
rdkafka. Keep changes focused on the user's request. Do not initialize Git or
create commits unless the user explicitly asks.

## Build and verification

- The user prefers to build and package the application themselves. Do not run
  `build-windows.bat`, `cargo build --release`, `package.ps1`, or open the app
  unless explicitly requested.
- For source changes, an agent may run `cargo fmt --check` and focused or full
  `cargo test` when the user permits it. State clearly if compilation was not
  run.
- `build-windows.bat` is the user-operated Windows release path. It runs
  release tests, builds with `target-nmake`, and creates `dist/kafka-ui-tool.zip`.
- The first Windows release build can take several minutes because rdkafka uses
  bundled OpenSSL. Do not claim a build succeeded without its actual output.

## Runtime rules

- Keep Kafka I/O off Slint's UI thread. Use Tokio work and marshal UI updates
  back through the Slint event loop.
- Keep passwords, SASL secrets, and private-key passwords only in memory. Do
  not add them to source, logs, documentation examples, or packages.
- Normal Windows machines use Slint's default renderer. Do not add a renderer
  fallback to application code or alter the normal build for VM/VDI support.
- A VM/VDI user may set `SLINT_BACKEND=software` in their own terminal or batch
  file before launching the executable. This is an operator choice, not a
  default application behavior.

## Current connection architecture

- Profiles are stored per Windows user in `%LOCALAPPDATA%\Kafka UI Tool\connections.dat`, encrypted with current-user DPAPI. The first run migrates the legacy `Kafa UI Tool` directory when no new directory exists. Never log plaintext secrets.
- Portable export is plaintext JSON containing passwords and embedded certificate/key material; retain its explicit warning.
- Supported modes: PLAINTEXT, SSL, SASL/PLAIN, SASL/SCRAM-SHA-256, and SASL/SCRAM-SHA-512. SSL/SASL_SSL require a CA; client certificates and keys must be paired.
- The window icon is initialized by `ui/app.slint` before native window creation; retain both the embedded PNG for Slint and the ICO resource for packaged Windows executables. SASL validation is field-specific: username and password errors must remain separate.
- Keep exactly one active Kafka session. The current workspace uses short-lived metadata probes; a future live explorer must cancel/drop the previous session before switching connections.
- Explorer work must keep topic metadata cached per active session and refresh it asynchronously. A refresh removes deleted topics; if the removed topic is selected, cancel its work and replace its detail view with a clear unavailable state.
- Message searches are bounded and cancellable: scan at most 10,000 records per partition, apply filters before sorting and local pagination, and discard stale results. Never make the UI thread wait for Kafka work.
- The sandbox can lack a loaded Windows profile, so manually verify real DPAPI under a normal Windows user. Test-only protectors stay behind `cfg(test)`.

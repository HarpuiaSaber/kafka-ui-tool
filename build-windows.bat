@echo off
setlocal
cd /d "%~dp0"

set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if exist "%VCVARS%" goto vcvars_found
echo Khong tim thay Visual Studio Build Tools: %VCVARS%
goto fail

:vcvars_found
call "%VCVARS%" >nul
if errorlevel 1 goto fail

set "PATH=C:\Program Files\CMake\bin;C:\Strawberry\perl\bin;%PATH%"
set "CMAKE_GENERATOR=NMake Makefiles"
where cmake >nul 2>&1
if errorlevel 1 (
    echo Khong tim thay CMake.
    goto fail
)
where perl >nul 2>&1
if errorlevel 1 (
    echo Khong tim thay Perl.
    goto fail
)
where cargo >nul 2>&1
if errorlevel 1 (
    echo Khong tim thay Rust Cargo.
    goto fail
)

echo [1/3] Chay test Release...
cargo test --release --locked --target-dir target-nmake
if errorlevel 1 goto fail

echo [2/3] Build Release...
cargo build --release --locked --target-dir target-nmake
if errorlevel 1 goto fail

echo [3/3] Dong goi ZIP...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0package.ps1" -TargetDir target-nmake
if errorlevel 1 goto fail

echo Hoan tat. File ZIP moi nam trong thu muc dist.
pause
exit /b 0

:fail
echo Build dung do co loi. Xem thong bao o tren.
pause
exit /b 1

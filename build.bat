@echo off
rem shellcode2pwsh5 release build script
rem
rem Usage:   build.bat [version]
rem Example: build.bat 1.0.0
rem
rem Produces a stripped, standalone shellcode2pwsh5.exe in this directory.
rem Requires Go 1.21+ in PATH.
rem
rem The version string is stamped into the binary and reported by
rem "shellcode2pwsh5 --version". When no version is given the value of the
rem version variable in main.go is used as-is.

setlocal
cd /d "%~dp0"

where go >nul 2>&1
if errorlevel 1 (
    echo [ERROR] "go" was not found in PATH. Install Go 1.21+ first.
    exit /b 1
)

set "VERSION=%~1"
if not "%VERSION%"=="" (
    set "LDFLAGS=-s -w -X main.version=%VERSION%"
) else (
    set "LDFLAGS=-s -w"
)

set "GOOS=windows"
set "GOARCH=amd64"
set "CGO_ENABLED=0"

if not "%VERSION%"=="" (
    echo Building shellcode2pwsh5 v%VERSION% ...
) else (
    echo Building shellcode2pwsh5 ...
)

go build -trimpath -buildvcs=false -ldflags "%LDFLAGS%" -o shellcode2pwsh5.exe .
if errorlevel 1 (
    echo [ERROR] build failed.
    exit /b 1
)

for %%F in (shellcode2pwsh5.exe) do echo [OK] shellcode2pwsh5.exe  %%~zF bytes
exit /b 0

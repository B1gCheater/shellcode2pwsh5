@echo off
rem shellcode2pwsh5 release build script
rem
rem Usage:   build.bat [version]
rem Example: build.bat 1.0.0
rem
rem Produces a stripped, standalone bin2pwsh5.exe in this directory.
rem Requires Go 1.21+ in PATH.

setlocal
cd /d "%~dp0"

where go >nul 2>nul
if errorlevel 1 (
    echo [ERROR] "go" was not found in PATH. Install Go 1.21+ first.
    exit /b 1
)

set "VERSION=%~1"
if "%VERSION%"=="" set "VERSION=1.0.0"

set "GOOS=windows"
set "GOARCH=amd64"
set "CGO_ENABLED=0"

echo Building shellcode2pwsh5 v%VERSION% ...
go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=%VERSION%" -o shellcode2pwsh5.exe .
if errorlevel 1 (
    echo [ERROR] build failed.
    exit /b 1
)

for %%F in (shellcode2pwsh5.exe) do echo [OK] shellcode2pwsh5.exe  %%~zF bytes
exit /b 0

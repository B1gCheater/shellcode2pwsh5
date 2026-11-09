package main

import (
	"bytes"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// The reflective loader (PowerSploit, BSD 3-Clause) and its license notice are
// compiled in from psloader.go, which tools/psloader generates. No external
// asset is needed to build this package.

func hasPESignature(payload []byte) bool {
	if len(payload) < 64 || !bytes.HasPrefix(payload, []byte("MZ")) {
		return false
	}
	offset := uint64(binary.LittleEndian.Uint32(payload[0x3c:]))
	return offset >= 64 && offset <= uint64(len(payload)-4) &&
		bytes.Equal(payload[offset:offset+4], []byte("PE\x00\x00"))
}

func inspectPE(payload []byte) (string, string, error) {
	image, err := pe.NewFile(bytes.NewReader(payload))
	if err != nil {
		return "", "", fmt.Errorf("invalid PE image: %w", err)
	}
	defer image.Close()
	if image.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 ||
		len(image.Sections) == 0 {
		return "", "", fmt.Errorf("expected an executable PE image with sections")
	}
	kind := "exe"
	if image.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		kind = "dll"
	}

	var arch string
	var headerSize uint32
	var directories [16]pe.DataDirectory
	switch hdr := image.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if image.Machine == pe.IMAGE_FILE_MACHINE_I386 {
			arch = "x86"
		}
		directories = hdr.DataDirectory
		headerSize = hdr.SizeOfHeaders
	case *pe.OptionalHeader64:
		if image.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
			arch = "x64"
		}
		directories = hdr.DataDirectory
		headerSize = hdr.SizeOfHeaders
	}
	if arch == "" {
		return "", "", fmt.Errorf("expected a native x86 or x64 PE image with a matching optional header")
	}
	if headerSize == 0 || uint64(headerSize) > uint64(len(payload)) {
		return "", "", fmt.Errorf("PE headers extend beyond the input file or have zero size")
	}
	if directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0 {
		return "", "", fmt.Errorf("managed PE images are unsupported")
	}
	for _, section := range image.Sections {
		if section.Size != 0 && uint64(section.Offset)+uint64(section.Size) > uint64(len(payload)) {
			return "", "", fmt.Errorf("PE section %q extends beyond the input file", section.Name)
		}
	}
	return kind, arch, nil
}

func buildPECore(kind, arch string, payload []byte, sha string, verify bool, target string, exeArgs []string) string {
	info := archInfo[arch]
	arch64 := "$false"
	if info.is64 {
		arch64 = "$true"
	}
	verifyBlock := ""
	if verify {
		verifyBlock = verifyPayload
	}
	meta := fmt.Sprintf("$B2P_TYPE='%s';$B2P_ARCH='%s';$B2P_SIZE=%d\n$B2P_SHA256='%s'",
		kind, arch, len(payload), sha)
	prelude := strings.NewReplacer(
		"@MARKER@", marker+"\n"+peRuntimeCheck, "@META@", meta, "@ARCH64@", arch64,
		"@ARCHNAME@", arch, "@ARCH_HINT@", info.hint,
		"@B64@", wrapB64(payload), "@VERIFY@", verifyBlock,
	).Replace(localPrelude)
	loader := "<#\n" + reflectiveLoaderLicense + "\n#>\n" + reflectiveLoader + "\n"

	if target == "" {
		argOption := ""
		if len(exeArgs) != 0 {
			encoded := base64.StdEncoding.EncodeToString([]byte(windowsCommandLine(exeArgs)))
			argOption = " -ExeArgs ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + "')))"
		}
		return prelude + loader + strings.Replace(peLocalRun, "@EXE_ARGS@", argOption, 1)
	}
	return prelude + loader + matchTarget +
		"$B2P_TARGET = '" + escapePSLiteral(target) + "'\n" + peRemoteRun
}

// Windows treats runs of backslashes specially before a quote. Quote each
// argument, doubling those runs before literal quotes and the closing quote.
func windowsCommandLine(args []string) string {
	var command strings.Builder
	for i, arg := range args {
		if i != 0 {
			command.WriteByte(' ')
		}
		command.WriteByte('"')
		slashes := 0
		for j := 0; j < len(arg); j++ {
			switch arg[j] {
			case '\\':
				slashes++
				continue
			case '"':
				slashes = 2*slashes + 1
			}
			command.WriteString(strings.Repeat("\\", slashes))
			command.WriteByte(arg[j])
			slashes = 0
		}
		command.WriteString(strings.Repeat("\\", 2*slashes))
		command.WriteByte('"')
	}
	return command.String()
}

const peRuntimeCheck = `if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion -lt [version]'5.1') {
    [Console]::Error.WriteLine('B2P: PE loading requires Windows PowerShell 5.1 (powershell.exe).')
    exit 4
}`

const peLocalRun = `try {
    Invoke-ReflectivePEInjection -PEBytes $sc -DoNotZeroMZ -ErrorAction Stop@EXE_ARGS@
} catch {
    [Console]::Error.WriteLine('B2P: PE load failed: ' + $_.Exception.Message)
    exit 4
}
exit 0
`

const peRemoteRun = `$targets = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Id -ne $PID -and (B2PI-MatchTarget $B2P_TARGET $_.ProcessName)
})
if ($targets.Count -eq 0) {
    [Console]::Error.WriteLine('B2P: no matching target process')
    exit 5
}
$loaded = 0
$failed = 0
$failCode = 0
foreach ($process in $targets) {
    try {
        Invoke-ReflectivePEInjection -PEBytes $sc -ProcId $process.Id -DoNotZeroMZ -ErrorAction Stop
        $loaded++
    } catch {
        [Console]::Error.WriteLine('B2P: DLL load failed for PID ' + $process.Id + ': ' + $_.Exception.Message)
        if ($failCode -eq 0) { $failCode = 4 }
        $failed++
    }
}
if ($loaded -eq 0) {
    if ($failCode -eq 0) { $failCode = 4 }
    exit $failCode
}
if ($failed -gt 0) {
    [Console]::Error.WriteLine('B2P: warning: ' + $failed + ' of ' + $targets.Count + ' matching processes could not be loaded (see above), continuing after ' + $loaded + ' successful load(s)')
}
exit 0
`

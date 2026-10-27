# shellcode2pwsh5

Convert a raw shellcode binary into a self-contained Windows PowerShell script.

`shellcode2pwsh5` is a small Go command-line utility for authorized security research, malware analysis, and controlled red-team testing. It packages a shellcode payload into a generated `.ps1`, `.bat`, or `.cmd` file so the payload can be decoded and invoked by Windows PowerShell 5.1 without a separate payload file at runtime.

> **Authorization required:** Use this project only in systems and environments that you own or are explicitly authorized to test. Generated files execute native code and may be detected or blocked by endpoint security software. Do not use them to access systems, data, or networks without permission.

## Features

- Generate PowerShell (`.ps1`) or command-shell wrappers (`.bat` and `.cmd`).
- Two execution modes: run the payload inside the PowerShell process itself, or inject it into matching processes with `--process`.
- Target x86 or x64 Windows PowerShell processes.
- Optionally embed a SHA-256 integrity check that runs before execution.
- Optionally control console visibility for authorized, unattended test environments.
- Produce a standalone Go utility with no third-party Go dependencies.

## Execution modes

### Local (default)

Without `--process` the generated script allocates memory in its own process, copies the payload in, changes the protection from read/write to read/execute and starts it on a thread. The script exits with the payload's exit code.

### Remote (`--process`)

With `--process <pattern>` the generated script finds every running process whose image name matches the pattern, writes the payload into each of their address spaces and starts it there with `CreateRemoteThread`:

```
OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> VirtualProtectEx(RX) -> CreateRemoteThread
```

All matching targets are injected before the script waits for the remote threads, so a long-running payload in one target never keeps the remaining targets from being injected. The script exits with the exit code of the first remote thread that finished.

#### Target matching

The pattern is compared against the process image name without its extension, case-insensitively. The match is a plain substring test: the pattern may appear anywhere in the name.

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `666` | `666.exe`, `06660.exe`, `69.666_.exe` | `66.exe`, `66.6.exe` |
| `service` | `services.exe`, `windows_services.exe` | `serv1ce.exe` |
| `explorer` | `windows_explorer.exe` | `xplorer.exe` |

Only one `--process` pattern may be given; passing it twice is an error.

#### Constraints

- The payload bitness must match the bitness of the target process. A 32-bit payload cannot run in a 64-bit process and the other way round. The script checks this per target and reports a mismatch instead of crashing the target.
- A 32-bit PowerShell cannot inject into a 64-bit process at all, so the generated script must run under a 64-bit PowerShell for 64-bit targets.
- Targets that need elevated rights are reached through `SeDebugPrivilege`, which the script enables when possible. Protected Process Light (PPL) targets such as some antivirus processes reject injection regardless.
- The payload must be position-independent. Convert a PE file with a tool such as `donut` before feeding it to this utility.

#### Examples

```bat
REM inject into every notepad.exe
shellcode2pwsh5 -i payload.bin -f bat -p notep

REM inject into every process whose name contains "explorer" at a name boundary
shellcode2pwsh5 -i payload.bin -f ps1 -p explorer

REM inject and return immediately without waiting for the remote threads
shellcode2pwsh5 -i payload.bin -f bat -p notep --detach

REM inject and give up waiting after 10 seconds
shellcode2pwsh5 -i payload.bin -f bat -p notep --timeout 10000
```

## Runtime requirements

Generated scripts target **Windows PowerShell 5.1** (`powershell.exe`) and require the .NET Framework facilities used by PowerShell's `Add-Type` implementation. They are not intended for PowerShell 7, PowerShell Core, Linux, or macOS.

The current release supports raw shellcode payloads only. The `-type` option currently accepts `shellcode`; other payload types are not implemented.

## Build

Build requirements:

- Windows
- Go 1.21 or later

From the project directory, run:

```bat
build.bat
```

The script creates `shellcode2pwsh5.exe` in the project directory. An optional version string can be supplied to stamp the binary:

```bat
build.bat 1.0.0
```

You can also build directly with Go:

```bat
go build -trimpath -buildvcs=false -ldflags "-s -w" -o shellcode2pwsh5.exe .
```

## Integrity checks

When enabled, the generated script checks the decoded payload's expected size and SHA-256 digest before execution. This can detect accidental truncation or modification. Because the expected digest is stored in the generated script itself, it does not prove who created the script or provide a digital signature.

## Security considerations

- Generated scripts execute machine code. Inspect the input and generated output, and test only in an isolated, authorized environment.
- Console visibility is a presentation setting, not a security boundary. Use it only where concealment is explicitly approved by the environment owner.
- SHA-256 checking detects changes relative to the embedded value; it does not authenticate the publisher.
- The generated script contains the payload as Base64 text. Treat it as executable code and protect it accordingly.
- Remote injection uses a well-known API sequence (`OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) that endpoint security products monitor closely. Generated scripts are more likely to be flagged or blocked than the local variant.

## Exit codes

The payload's own exit code is passed through when the payload thread was allowed to finish. Container errors use these codes:

| Code | Meaning |
| --- | --- |
| 2 | payload data or marker damaged |
| 3 | architecture mismatch |
| 4 | memory API failure |
| 5 | no process matched the target pattern |
| 6 | target process could not be opened |
| 7 | timed out waiting for the payload thread |

## Project status

This project is a focused shellcode packager and runner. It does not provide payload generation, persistence, or network transport.

In local mode the generated script allocates memory, copies the payload, changes the memory protection from read/write to read/execute, and starts it on a thread. In remote mode it does the same inside the address space of every matching target process and starts the payload there with `CreateRemoteThread`.

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE) for the full text.

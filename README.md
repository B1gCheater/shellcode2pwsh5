# shellcode2pwsh5

Convert a raw shellcode binary into a self-contained Windows PowerShell script.

`shellcode2pwsh5` is a small Go command-line utility for authorized security research, malware analysis, and controlled red-team testing. It packages a shellcode payload into a generated `.ps1`, `.bat`, or `.cmd` file so the payload can be decoded and invoked by Windows PowerShell 5.1 without a separate payload file at runtime.

> **Authorization required:** Use this project only in systems and environments that you own or are explicitly authorized to test. Generated files execute native code and may be detected or blocked by endpoint security software. Do not use them to access systems, data, or networks without permission.

## Features

- Generate PowerShell (`.ps1`) or command-shell wrappers (`.bat` and `.cmd`).
- Target x86 or x64 Windows PowerShell processes.
- Optionally embed a SHA-256 integrity check that runs before execution.
- Optionally control console visibility for authorized, unattended test environments.
- Produce a standalone Go utility with no third-party Go dependencies.

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

## Project status

This project is a focused shellcode packager and runner. It does not provide payload generation, persistence, network transport, or process injection features. The generated script allocates memory, copies the payload, changes the memory protection from read/write to read/execute, and starts it on a thread.

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE) for the full text.

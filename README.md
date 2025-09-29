Xenos
=====

Windows dll injector. Based on Blackbone library - https://github.com/DarthTon/Blackbone

## Command-line usage

Xenos now ships as a pure command-line tool. The GUI components have been removed, and all
configuration is supplied through CLI switches. The binary accepts one or more DLLs to inject
and exposes the core Blackbone-powered injection modes (LoadLibrary, manual map, kernel
assisted techniques, etc.).

```
xenos64.exe --dll C:\path\to\module.dll --process tf_win64.exe --mode manual --method normal
```

Common switches:

- `--dll <path>` / `--inject <path>` – add a DLL to the injection list (repeatable).
- `--process <name|path>` – set the target executable name or full path.
- `--pid <id>` – attach directly to a running process by PID.
- `--mode <existing|new|manual>` – choose how the process is obtained (attach, spawn, or
	wait for manual launch).
- `--method <normal|manual|kernel-thread|kernel-apc|kernel-mmap|kernel-driver>` – choose the
	injection technique.
- `--init <export>` / `--init-args <text>` – call a specific initialization routine after the
	module is mapped.
- `--delay <ms>` / `--period <ms>` – delay injection or stagger multiple images.
- `--mmap-flags <mask>` – provide manual-map configuration flags.

Interrupting the process with `Ctrl+C` while waiting for a manual launch gracefully cancels the
pending injection attempt.

## Features ##

- Supports x86 and x64 processes and modules
- Kernel-mode injection feature (driver required)
- Manual map of kernel drivers (driver required)
- Injection of pure managed images without proxy dll
- Windows 7 cross-session and cross-desktop injection
- Injection into native processes (those having only ntdll loaded)
- Calling custom initialization routine after injection
- Unlinking module after injection
- Injection using thread hijacking
- Injection of x64 images into WOW64 process
- Image manual mapping
- Injection profiles

Manual map features:
- Relocations, import, delayed import, bound import
- Hiding allocated image memory (driver required)
- Static TLS and TLS callbacks
- Security cookie
- Image manifests and SxS
- Make module visible to GetModuleHandle, GetProcAddress, etc.
- Support for exceptions in private memory under DEP
- C++/CLI images are supported (use 'Add loader reference' in this case)

Supported OS: Win7 - Win10 x64

## License ##
Xenos is licensed under the MIT License. Dependencies are under their respective licenses.

[![Build status](https://ci.appveyor.com/api/projects/status/eu6lpbla89gjgy5m?svg=true)](https://ci.appveyor.com/project/DarthTon/xenos)
# Anva - Analyzing Non-Volatile Applications
Anva allows the monitoring of userland programs by executing them within the same virtual address space.

Anva features a self-made PE Loader that mimics Windows' PE Loader (found in NTDLL.DLL) and manually maps the target program into Anva's address space.

The tool spoofs internal structures (eg. PEB) to mimic a bare metal environment.

Anva supports:
  - [x] Both x86 and x64 PE formats
  - [x] VMProtect support
  - [x] Fixed and relocatable base address
  - [x] Sections with correct memory protection 
  - [x] Imports with DLL loading
  - [x] SEH handlers against exceptions
  - [x] TLS and TLS callbacks
  - [x] PEB setup
  - [x] Console, window and DLL applications.

Anva is powered by [MinHook](https://github.com/TsudaKageyu/minhook) for both its 32-bit and 64-bit trampoline hook implementations. Anva uses tramp-hooks to monitor specific WinAPI and NTAPI calls and respond accordingly (this mechanism can be modified to use instrumentation callback for better results).

Anva can be used in different domains:
  - Malware analysis
  - Reverse engineering
  - Protection unpacking
  - API monitoring
  - CRC bypassing

This is just a POC, always use a Virtual Machine while executing malicious software with Anva.

Anva running a VMProtect'd game:
![image-modified](https://github.com/nbs32k/anva/assets/68382500/1eafb652-4423-4182-b3f0-bbf63798c35d)

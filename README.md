# Anva - Analyzing Non-Volatile Applications
Anva allows the monitoring of userland programs through running it within the same virtual address space.

Anva consists of a self-made PE Loader that mimics Windows' PE Loader (situated in NTDLL.DLL) to manual map the target program into the same virtual address space as Anva. This is needed so Anva has shared memory access with the target.

Anva tricks the newly mapped program into thinking it runs freely on bare metal by manipulating system structures like PEB.

Anva supports:
  - [x] Both x86 and x64 PE formats
  - [x] VMProtect support
  - [x] Fixed and relocatable base address
  - [x] Sections with correct memory protection 
  - [x] Imports with DLL loading
  - [x] SEH handlers against exceptions
  - [x] TLS and TLS callbacks
  - [x] PEB setup
  - [x] Supports console, window and DLL applications.

Anva is powered by [MinHook](https://github.com/TsudaKageyu/minhook) for both x86 and x64 trampoline hooks. Anva uses tramp-hooks to monitor specific WinAPI and NTAPI calls and respond accordingly, but this mechanism can be modified to use instrumentation callback for better results.

Anva can be used in different domains:
  - Malware analysis
  - Reverse engineering
  - Protection unpacking
  - API monitoring
  - CRC bypassing

Always use a Virtual Machine for Malware Analysis while running Anva because Anva does not come with full sandboxing techniques by default.

Anva running a VMProtect'd game:
![image-modified](https://github.com/nbs32k/anva/assets/68382500/1eafb652-4423-4182-b3f0-bbf63798c35d)

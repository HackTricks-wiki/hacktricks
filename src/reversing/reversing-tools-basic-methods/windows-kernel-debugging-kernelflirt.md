# Windows Kernel Debugging with KernelFlirt

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt is a Windows x64 debugger for controlled reverse-engineering labs. A host-side WPF UI or `KfConsole.exe` sends commands to `KfRelay.exe` in a test-signed Windows VM. The relay translates them into `DeviceIoControl` requests for `KernelFlirt.sys`, which provides memory, register, breakpoint, execution-control, and kernel-module operations. The driver also modifies the kernel debugging path with a `KdpStub`/`KdTrap` inline hook, so use it only in a disposable VM.<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

The relay is a privileged debugging boundary rather than a normal remote service. Keep TCP `31337` on an isolated host-only network and never expose the test-signed driver or relay to an untrusted network.<sup>[[1]](#references)</sup>

Related Windows exploitation techniques:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Lab setup and first stop

Builds require Windows 10/11 x64, Visual Studio 2022 with C++, WDK 10.0.26100.0 or later, and .NET 9. Load the driver and relay inside the VM, then connect from the host. The UI can open a remote EXE or SYS and the **Kernel Modules** view can place breakpoints in already-loaded drivers.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Use `KfLoader.exe unload` when the lab is finished. The console supports an unconnected REPL, direct local-device access, and relay access; only relay mode implements the deterministic `open` workflow described below.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

A minimal console workflow is:<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

Addresses are expressions. Bare numbers are hexadecimal, and expressions may use registers, arithmetic, dereferences such as `[rsp]`, and symbols such as `ntdll!NtCreateFile`. Symbol breakpoints should be added only after `open` or `attach` has enumerated modules and loaded their PDBs.<sup>[[2]](#references)</sup>

## Deterministic entry-point trapping with `EB FE`

Relay-side `open` creates the target suspended, saves its first entry-point bytes, writes `EB FE`, resumes the entry thread, and polls until its instruction pointer reaches that address. `EB FE` is a two-byte short jump back to itself, so it traps execution without relying on delivery of a user-mode debug exception. The relay then restores the original bytes and leaves the target stopped at its entry point.<sup>[[2]](#references)</sup>

This pattern is also useful when an early loader path must be observed before normal debugger setup completes.<sup>[[2]](#references)</sup>

1. Create the process suspended and resolve its actual entry point after image mapping.
2. Save the original entry-point bytes and replace them with the two-byte self-loop.
3. Resume the entry thread and poll its instruction pointer until it reaches the patched address.
4. Suspend the target and restore the exact original bytes before analysis continues.

The technique is deliberately intrusive. If the debugger or relay exits before restoration, the target can remain spinning. KernelFlirt local mode does not provide relay-side entry patching; start the process manually and use `attach <pid>` instead.<sup>[[2]](#references)</sup>

## Choose the breakpoint primitive

KernelFlirt exposes several breakpoint mechanisms with different side effects. The following commands let an analyst switch primitives when packed code rewrites itself, executable pages are read-only, or software breakpoint bytes are integrity-checked.<sup>[[1]](#references)[[2]](#references)</sup>

| Primitive | Command | Mechanism and use |
| --- | --- | --- |
| Software | `bp <expr>` | MDL-backed `INT3`; can instrument RX `.text` pages |
| Conditional software | `bp <expr> if <condition>` | Evaluates on every hit and resumes silently when false |
| Hardware execute | `ba e1 <expr>` | Uses one of DR0-DR3 without changing code bytes |
| Hardware data | `ba w4 <expr>` / `ba r8 <expr>` | Watches writes or reads/writes of 1, 2, 4, or 8 bytes |
| Guard page | `bm <expr> [size]` | Uses `PAGE_GUARD` for a memory-range breakpoint |
| Temporary | `g <expr>`, `p`, or `o` | Run-to-address, step-over, and step-out helper breakpoint |

Use `bl` to distinguish software, hardware, memory, and temporary entries, and `bc <address|handle|all>` to remove them. Hardware slots are scarce and apply through debug-register state, while guard pages cover a larger range but trigger on unrelated accesses to the same page.

## Native x64 versus WoW64 stepping

Native x64 single-step sets the processor trap flag through `IOCTL_KF_SINGLE_STEP`. Step Over decodes the current instruction and places temporary breakpoints at its possible next addresses. Step Out reads the return address from the top of the current stack. At a function prologue that stack assumption may be wrong, so prefer a known internal breakpoint.<sup>[[2]](#references)</sup>

The `KdTrap` hook does not catch 32-bit exceptions in the same way. For WoW64 targets, the debugger decodes the instruction with Iced, writes `EB FE` at the calculated next `EIP`, and polls thread instruction pointers. Consequently, `g <address>` is unavailable for WoW64, and a plain `g` blocks the console until a breakpoint is reached. Set a reachable breakpoint first and avoid an indefinite run because `Ctrl+C` terminates the console rather than cancelling the poll.<sup>[[2]](#references)</sup>

## Memory, register, and symbol-assisted analysis

The console can combine a symbolic stop with memory inspection and a controlled patch. Search calls accept byte wildcards, ASCII, or UTF-16 and are capped at 4 MB with at most 256 reported matches. Allocation and protection commands map to the driver's allocate, free, and protect IOCTLs.<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

PDB loading reads each remote module's PE debug directory, extracts its RSDS identifier, finds the matching PDB through DbgHelp/SymSrv, and verifies that it loaded as a PDB. Place private PDBs next to the target on the relay machine or add their directory to `_NT_SYMBOL_PATH` on the host.<sup>[[2]](#references)</sup>

## Kernel-backed anti-debug state changes

Kernel access allows the debugger to remove indicators that a user-mode debugger cannot reliably hide. Apply one change at a time, confirm the target check, and revert the corresponding hook before ending the session.<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- `clr_debug_port` clears `EPROCESS.DebugPort`.
- `clr_thread_hide` removes `HideFromDebugger` from target threads.
- `ntqsi on` spoofs `NtQuerySystemInformation` class `0x23` (`SystemKernelDebuggerInformation`).
- `spoof on` makes user-mode reads of `KUSER_SHARED_DATA.KdDebuggerEnabled` see false while retaining the kernel state required by the trap mechanism.
- `stats` checks hook counters and the recorded `KiDebugRoutine`, `KdpStub`, and `KdTrap` state.

These operations change process and kernel state. A crash, stale inline hook, incorrect structure offset, or unfinished patch restoration can destabilize the VM, which is why snapshots and an isolated test-signing environment are mandatory.<sup>[[1]](#references)</sup>

## References

- [1] [KernelFlirt repository and main documentation](https://github.com/AkaTorich/KernelFlirt)
- [2] [KernelFlirt console reference](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)

{{#include ../../banners/hacktricks-training.md}}

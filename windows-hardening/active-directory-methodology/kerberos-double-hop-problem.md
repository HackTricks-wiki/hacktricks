# Problema de Doble Salto de Kerberos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al **grupo de telegram** o **sígueme** en **Twitter** **🐦** [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción

El problema de "Doble Salto" de Kerberos ocurre cuando un atacante intenta utilizar **autenticación Kerberos a través de dos** **saltos**, por ejemplo usando **PowerShell**/**WinRM**.

Cuando ocurre una **autenticación** a través de **Kerberos**, las **credenciales** **no se almacenan** en la **memoria**. Por lo tanto, si ejecutas mimikatz, **no encontrarás las credenciales** del usuario en la máquina aunque esté ejecutando procesos.

Esto se debe a que al conectarse con Kerberos, se siguen estos pasos:

1. El Usuario1 proporciona credenciales y el **controlador de dominio** devuelve un **TGT** de Kerberos al Usuario1.
2. El Usuario1 utiliza el **TGT** para solicitar un **ticket de servicio** para **conectarse** al Servidor1.
3. El Usuario1 **se conecta** al **Servidor1** y proporciona el **ticket de servicio**.
4. El **Servidor1** **no tiene** las **credenciales** de Usuario1 en caché ni el **TGT** de Usuario1. Por lo tanto, cuando Usuario1 desde Servidor1 intenta iniciar sesión en un segundo servidor, no puede **autenticarse**.

### Delegación sin restricciones

Si la **delegación sin restricciones** está habilitada en la PC, esto no sucederá ya que el **Servidor** obtendrá un **TGT** de cada usuario que acceda a él. Además, si se utiliza la delegación sin restricciones, probablemente se pueda **comprometer el Controlador de Dominio** desde allí.\
[Más información en la página de delegación sin restricciones](unconstrained-delegation.md).

### CredSSP

Otra opción sugerida a los **administradores de sistemas** para evitar este problema, que es [**notablemente insegura**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), es el **Proveedor de Soporte de Seguridad de Credenciales**. Habilitar CredSSP ha sido una solución mencionada en varios foros a lo largo de los años. Según Microsoft:

_"La autenticación de CredSSP delega las credenciales de usuario desde la computadora local a una computadora remota. Esta práctica aumenta el riesgo de seguridad de la operación remota. Si la computadora remota se ve comprometida, cuando se pasan las credenciales a ella, las credenciales se pueden utilizar para controlar la sesión de red."_

Si encuentras que **CredSSP está habilitado** en sistemas de producción, redes sensibles, etc., se recomienda deshabilitarlo. Una forma rápida de **verificar el estado de CredSSP** es ejecutando `Get-WSManCredSSP`. Lo cual se puede ejecutar de forma remota si WinRM está habilitado.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Soluciones alternativas

### Invocar Comando <a href="#invoke-command" id="invoke-command"></a>

Este método es una especie de _"trabajar con"_ el problema del doble salto, no necesariamente resolverlo. No depende de ninguna configuración y simplemente puedes ejecutarlo desde tu máquina de ataque. Básicamente es un **`Invoke-Command`** anidado.

Esto ejecutará **`hostname`** en el **segundo servidor:**
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
También podrías tener una **sesión de PS** establecida con el **primer servidor** y simplemente **ejecutar** el **`Invoke-Command`** con `$cred` desde allí en lugar de anidarla. Aunque, ejecutarlo desde tu caja de ataque centraliza las tareas:
```powershell
# From the WinRM connection
$pwd = ConvertTo-SecureString 'uiefgyvef$/E3' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
# Use "-Credential $cred" option in Powerview commands
```
### Registrar la Configuración de la Sesión de PSSession

Si en lugar de usar **`evil-winrm`** puedes usar el cmdlet **`Enter-PSSession`**, entonces puedes usar **`Register-PSSessionConfiguration`** y reconectarte para evitar el problema de doble salto:
```powershell
# Register a new PS Session configuration
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
# Restar WinRM
Restart-Service WinRM
# Get a PSSession
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
# Check that in this case the TGT was sent and is in memory of the PSSession
klist
# In this session you won't have the double hop problem anymore
```
### Reenvío de puertos <a href="#portproxy" id="portproxy"></a>

Dado que tenemos permisos de Administrador Local en el objetivo intermedio **bizintel: 10.35.8.17**, puedes agregar una regla de reenvío de puertos para enviar tus solicitudes al servidor final/tercero **secdev: 10.35.8.23**.

Puedes usar rápidamente **netsh** para crear una línea de comando y agregar la regla.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
```
Entonces **el primer servidor** está escuchando en el puerto 5446 y reenviará las solicitudes que lleguen al puerto 5446 a **el segundo servidor** en el puerto 5985 (también conocido como WinRM).

Luego, abre un agujero en el firewall de Windows, lo cual también se puede hacer con una línea de comando netsh rápida.
```bash
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
Ahora establezcamos la sesión, la cual nos llevará al **primer servidor**.

<figure><img src="../../.gitbook/assets/image (3) (5) (1).png" alt=""><figcaption></figcaption></figure>

#### winrs.exe <a href="#winrsexe" id="winrsexe"></a>

Las solicitudes de **Portforwarding WinRM** también parecen funcionar al usar **`winrs.exe`**. Esta puede ser una mejor opción si estás consciente de que PowerShell está siendo monitoreado. El siguiente comando devuelve "secdev" como resultado de `hostname`.
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
Como `Invoke-Command`, esto se puede scriptear fácilmente para que el atacante simplemente emita comandos del sistema como argumento. Un ejemplo genérico de script por lotes _winrm.bat_:

<figure><img src="../../.gitbook/assets/image (2) (6) (2).png" alt=""><figcaption></figcaption></figure>

### OpenSSH <a href="#openssh" id="openssh"></a>

Este método requiere [instalar OpenSSH](https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH) en el primer servidor. La instalación de OpenSSH para Windows se puede hacer **completamente a través de la CLI** y no lleva mucho tiempo, ¡además no se detecta como malware!

Por supuesto, en ciertas circunstancias puede que no sea factible, demasiado engorroso o represente un riesgo general de OpSec.

Este método puede ser especialmente útil en una configuración de caja de salto, con acceso a una red de otro modo inaccesible. Una vez establecida la conexión SSH, el usuario/atacante puede lanzar tantas `New-PSSession` como sea necesario contra la red segmentada sin enfrentarse al problema del doble salto.

Cuando se configura para usar **Autenticación de Contraseña** en OpenSSH (no claves o Kerberos), el **tipo de inicio de sesión es 8** también conocido como _Inicio de sesión de texto claro en red_. Esto no significa que tu contraseña se envíe en texto claro, de hecho está encriptada por SSH. Al llegar, se desencripta en texto claro a través de su [paquete de autenticación](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera?redirectedfrom=MSDN) para que tu sesión pueda solicitar más TGT jugosos.

Esto permite que el servidor intermedio solicite y obtenga un TGT en tu nombre para almacenarlo localmente en el servidor intermedio. Tu sesión puede entonces usar este TGT para autenticarse (PS remoto) en servidores adicionales.

#### Escenario de Instalación de OpenSSH

Descarga la última [versión comprimida de OpenSSH desde github](https://github.com/PowerShell/Win32-OpenSSH/releases) en tu máquina de ataque y muévela (o descárgala directamente en la caja de salto).

Descomprime el archivo zip donde desees. Luego, ejecuta el script de instalación - `Install-sshd.ps1`

<figure><img src="../../.gitbook/assets/image (2) (1) (3).png" alt=""><figcaption></figcaption></figure>

Por último, solo agrega una regla de firewall para **abrir el puerto 22**. Verifica que los servicios SSH estén instalados y arráncalos. Ambos servicios deben estar en ejecución para que SSH funcione.

<figure><img src="../../.gitbook/assets/image (1) (7).png" alt=""><figcaption></figcaption></figure>

Si recibes un error de `Restablecimiento de conexión`, actualiza los permisos para permitir que **Todos: Leer y Ejecutar** en el directorio raíz de OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Referencias

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

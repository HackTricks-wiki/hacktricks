# Problema de Doble Salto de Kerberos

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Introducción

El problema de "Doble Salto" de Kerberos aparece cuando un atacante intenta utilizar **autenticación Kerberos a través de dos** **saltos**, por ejemplo usando **PowerShell**/**WinRM**.

Cuando ocurre una **autenticación** a través de **Kerberos**, las **credenciales** **no** se almacenan en la **memoria**. Por lo tanto, si ejecutas mimikatz, no encontrarás las credenciales del usuario en la máquina aunque esté ejecutando procesos.

Esto se debe a que al conectarse con Kerberos, se siguen estos pasos:

1. El Usuario1 proporciona credenciales y el **controlador de dominio** devuelve un **TGT** de Kerberos al Usuario1.
2. El Usuario1 utiliza el **TGT** para solicitar un **ticket de servicio** para **conectarse** al Servidor1.
3. El Usuario1 **se conecta** al **Servidor1** y proporciona el **ticket de servicio**.
4. El **Servidor1** **no** tiene las **credenciales** de Usuario1 en caché ni el **TGT** de Usuario1. Por lo tanto, cuando Usuario1 desde Servidor1 intenta iniciar sesión en un segundo servidor, no puede **autenticarse**.

### Delegación no restringida

Si la **delegación no restringida** está habilitada en la PC, esto no sucederá ya que el **Servidor** obtendrá un **TGT** de cada usuario que acceda a él. Además, si se utiliza la delegación no restringida, probablemente se pueda **comprometer el Controlador de Dominio** desde allí.\
[Más información en la página de delegación no restringida](unconstrained-delegation.md).

### CredSSP

Otra forma de evitar este problema, que es [**notablemente insegura**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), es el **Proveedor de Soporte de Seguridad de Credenciales**. Según Microsoft:

> La autenticación de CredSSP delega las credenciales de usuario de la computadora local a una computadora remota. Esta práctica aumenta el riesgo de seguridad de la operación remota. Si la computadora remota se ve comprometida, cuando se pasan las credenciales a ella, las credenciales se pueden utilizar para controlar la sesión de red.

Se recomienda encarecidamente que **CredSSP** esté deshabilitado en sistemas de producción, redes sensibles y entornos similares debido a preocupaciones de seguridad. Para determinar si **CredSSP** está habilitado, se puede ejecutar el comando `Get-WSManCredSSP`. Este comando permite **verificar el estado de CredSSP** e incluso puede ejecutarse de forma remota, siempre que **WinRM** esté habilitado.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Soluciones alternativas

### Invocar Comando

Para abordar el problema del doble salto, se presenta un método que implica un `Invoke-Command` anidado. Esto no resuelve el problema directamente, pero ofrece una solución alternativa sin necesidad de configuraciones especiales. El enfoque permite ejecutar un comando (`hostname`) en un servidor secundario a través de un comando PowerShell ejecutado desde una máquina atacante inicial o a través de una sesión de PS previamente establecida con el primer servidor. Así es como se hace:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
### Registrar la Configuración de la Sesión de PS

Una solución para evitar el problema de doble salto implica usar `Register-PSSessionConfiguration` con `Enter-PSSession`. Este método requiere un enfoque diferente al de `evil-winrm` y permite una sesión que no sufre la limitación del doble salto.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### Reenvío de puertos

Para los administradores locales en un objetivo intermedio, el reenvío de puertos permite enviar solicitudes a un servidor final. Utilizando `netsh`, se puede agregar una regla para el reenvío de puertos, junto con una regla de firewall de Windows para permitir el puerto reenviado.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` se puede utilizar para reenviar solicitudes de WinRM, potencialmente como una opción menos detectable si la supervisión de PowerShell es una preocupación. El siguiente comando demuestra su uso:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

La instalación de OpenSSH en el primer servidor habilita una solución alternativa para el problema de doble salto, particularmente útil para escenarios de caja de salto. Este método requiere la instalación de CLI y la configuración de OpenSSH para Windows. Cuando se configura para la Autenticación de Contraseña, esto permite que el servidor intermedio obtenga un TGT en nombre del usuario.

#### Pasos de Instalación de OpenSSH

1. Descargar y mover el archivo zip de la última versión de OpenSSH al servidor de destino.
2. Descomprimir y ejecutar el script `Install-sshd.ps1`.
3. Agregar una regla de firewall para abrir el puerto 22 y verificar que los servicios de SSH estén en ejecución.

Para resolver errores de `Conexión restablecida`, es posible que sea necesario actualizar los permisos para permitir que todos tengan acceso de lectura y ejecución en el directorio de OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Referencias

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

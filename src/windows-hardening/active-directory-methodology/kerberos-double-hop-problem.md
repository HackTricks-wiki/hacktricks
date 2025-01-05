# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Introducción

El problema de "Double Hop" de Kerberos aparece cuando un atacante intenta usar **Kerberos authentication across two** **hops**, por ejemplo usando **PowerShell**/**WinRM**.

Cuando ocurre una **authentication** a través de **Kerberos**, las **credentials** **no están** almacenadas en **memoria.** Por lo tanto, si ejecutas mimikatz **no encontrarás credentials** del usuario en la máquina incluso si está ejecutando procesos.

Esto se debe a que al conectarse con Kerberos estos son los pasos:

1. User1 proporciona credentials y el **domain controller** devuelve un **TGT** de Kerberos a User1.
2. User1 usa el **TGT** para solicitar un **service ticket** para **connect** a Server1.
3. User1 **connects** a **Server1** y proporciona el **service ticket**.
4. **Server1** **no tiene** las **credentials** de User1 almacenadas o el **TGT** de User1. Por lo tanto, cuando User1 desde Server1 intenta iniciar sesión en un segundo servidor, **no puede autenticarse**.

### Delegación No Restringida

Si la **unconstrained delegation** está habilitada en la PC, esto no sucederá ya que el **Server** **obtendrá** un **TGT** de cada usuario que acceda a él. Además, si se utiliza la delegación no restringida, probablemente puedas **comprometer el Domain Controller** desde él.\
[**Más información en la página de delegación no restringida**](unconstrained-delegation.md).

### CredSSP

Otra forma de evitar este problema que es [**notablemente insegura**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) es **Credential Security Support Provider**. De Microsoft:

> La autenticación CredSSP delega las credentials del usuario desde la computadora local a una computadora remota. Esta práctica aumenta el riesgo de seguridad de la operación remota. Si la computadora remota es comprometida, cuando se pasan las credentials a ella, las credentials pueden ser utilizadas para controlar la sesión de red.

Se recomienda encarecidamente que **CredSSP** esté deshabilitado en sistemas de producción, redes sensibles y entornos similares debido a preocupaciones de seguridad. Para determinar si **CredSSP** está habilitado, se puede ejecutar el comando `Get-WSManCredSSP`. Este comando permite la **verificación del estado de CredSSP** e incluso puede ser ejecutado de forma remota, siempre que **WinRM** esté habilitado.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Soluciones alternativas

### Invocar Comando

Para abordar el problema del doble salto, se presenta un método que involucra un `Invoke-Command` anidado. Esto no resuelve el problema directamente, pero ofrece una solución alternativa sin necesidad de configuraciones especiales. El enfoque permite ejecutar un comando (`hostname`) en un servidor secundario a través de un comando de PowerShell ejecutado desde una máquina atacante inicial o a través de una PS-Session previamente establecida con el primer servidor. Así es como se hace:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativamente, se sugiere establecer una PS-Session con el primer servidor y ejecutar el `Invoke-Command` usando `$cred` para centralizar tareas.

### Registrar la Configuración de PSSession

Una solución para el problema del doble salto implica usar `Register-PSSessionConfiguration` con `Enter-PSSession`. Este método requiere un enfoque diferente al de `evil-winrm` y permite una sesión que no sufre de la limitación del doble salto.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Para los administradores locales en un objetivo intermedio, el reenvío de puertos permite que las solicitudes se envíen a un servidor final. Usando `netsh`, se puede agregar una regla para el reenvío de puertos, junto con una regla de firewall de Windows para permitir el puerto reenviado.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` se puede utilizar para reenviar solicitudes de WinRM, potencialmente como una opción menos detectable si la supervisión de PowerShell es una preocupación. El comando a continuación demuestra su uso:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Instalar OpenSSH en el primer servidor permite una solución para el problema de doble salto, particularmente útil para escenarios de jump box. Este método requiere la instalación y configuración de OpenSSH para Windows a través de la CLI. Cuando se configura para la Autenticación por Contraseña, esto permite que el servidor intermedio obtenga un TGT en nombre del usuario.

#### Pasos de Instalación de OpenSSH

1. Descargue y mueva el último zip de la versión de OpenSSH al servidor objetivo.
2. Descomprima y ejecute el script `Install-sshd.ps1`.
3. Agregue una regla de firewall para abrir el puerto 22 y verifique que los servicios SSH estén en funcionamiento.

Para resolver errores de `Connection reset`, es posible que sea necesario actualizar los permisos para permitir que todos tengan acceso de lectura y ejecución en el directorio de OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Referencias

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)


{{#include ../../banners/hacktricks-training.md}}

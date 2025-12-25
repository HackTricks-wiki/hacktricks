# Kerberos: problema de doble salto

{{#include ../../banners/hacktricks-training.md}}


## Introducción

El problema "Double Hop" de Kerberos aparece cuando un atacante intenta usar **autenticación Kerberos a través de dos** **hops**, por ejemplo usando **PowerShell**/**WinRM**.

Cuando una **autenticación** ocurre mediante **Kerberos**, las **credenciales** **no** se almacenan en **memoria.** Por lo tanto, si ejecutas mimikatz no **encontrarás credenciales** del usuario en la máquina aunque esté ejecutando procesos.

Esto es porque al conectarse con Kerberos los pasos son:

1. User1 proporciona credenciales y el **controlador de dominio** devuelve un Kerberos **TGT** a User1.
2. User1 usa el **TGT** para solicitar un **service ticket** para **conectarse** a Server1.
3. User1 **se conecta** a **Server1** y proporciona el **service ticket**.
4. **Server1** **no** tiene las **credenciales** de User1 en caché ni el **TGT** de User1. Por lo tanto, cuando User1 desde Server1 intenta iniciar sesión en un segundo servidor, no puede **autenticarse**.

### Unconstrained Delegation

Si la **unconstrained delegation** está habilitada en el PC, esto no ocurrirá ya que el **Server** **obtendrá** un **TGT** de cada usuario que lo acceda. Además, si se usa unconstrained delegation probablemente puedas **comprometer el Domain Controller** a partir de ello.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Another way to avoid this problem which is [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) is **Credential Security Support Provider**. De Microsoft:

> CredSSP authentication delegates the user credentials from the local computer to a remote computer. This practice increases the security risk of the remote operation. If the remote computer is compromised, when credentials are passed to it, the credentials can be used to control the network session.

Se recomienda encarecidamente que **CredSSP** esté deshabilitado en sistemas de producción, redes sensibles y entornos similares debido a las preocupaciones de seguridad. Para determinar si **CredSSP** está habilitado, se puede ejecutar el comando Get-WSManCredSSP. Este comando permite **comprobar el estado de CredSSP** y puede incluso ejecutarse de forma remota, siempre que **WinRM** esté habilitado.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** mantiene el TGT del usuario en la estación de trabajo de origen mientras permite que la sesión RDP solicite nuevos tickets de servicio Kerberos en el siguiente salto. Habilita **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** y selecciona **Require Remote Credential Guard**, luego conéctate con `mstsc.exe /remoteGuard /v:server1` en lugar de recurrir a CredSSP.

Microsoft rompió RCG para el acceso multi-hop en Windows 11 22H2+ hasta las actualizaciones acumulativas de abril de 2024 (KB5036896/KB5036899/KB5036894). Actualiza el cliente y el servidor intermedio o el segundo salto seguirá fallando. Comprobación rápida de hotfix:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Con esas builds instaladas, el RDP hop puede satisfacer los desafíos Kerberos en sistemas aguas abajo sin exponer secretos reutilizables en el primer servidor.

## Soluciones alternativas

### Invoke Command

Para abordar el problema de double hop, se presenta un método que implica un `Invoke-Command` anidado. Esto no resuelve el problema directamente, pero ofrece una solución alternativa sin requerir configuraciones especiales. El enfoque permite ejecutar un comando (`hostname`) en un servidor secundario mediante un comando de PowerShell ejecutado desde la máquina atacante inicial o a través de una PS-Session previamente establecida con el primer servidor. Así es como se hace:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Como alternativa, se sugiere establecer una PS-Session con el primer servidor y ejecutar `Invoke-Command` usando `$cred` para centralizar tareas.

### Register PSSession Configuration

Una solución para evitar el problema de double hop implica usar `Register-PSSessionConfiguration` con `Enter-PSSession`. Este método requiere un enfoque diferente al de `evil-winrm` y permite una sesión que no sufre la limitación de double hop.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Para administradores locales en un objetivo intermedio, PortForwarding permite enviar solicitudes a un servidor final. Usando `netsh`, se puede añadir una regla para port forwarding, junto con una regla del firewall de Windows para permitir el puerto reenviado.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` puede usarse para reenviar solicitudes WinRM, potencialmente como una opción menos detectable si la monitorización de PowerShell es una preocupación. El siguiente comando demuestra su uso:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Instalar OpenSSH en el primer servidor permite una solución alternativa al problema del double-hop, especialmente útil en escenarios de jump box. Este método requiere instalación vía CLI y la configuración de OpenSSH para Windows. Cuando se configura con Password Authentication, esto permite que el servidor intermedio obtenga un TGT en nombre del usuario.

#### Pasos de instalación de OpenSSH

1. Descarga y mueve el archivo zip de la última versión de OpenSSH al servidor objetivo.
2. Descomprime y ejecuta el script `Install-sshd.ps1`.
3. Agrega una regla de firewall para abrir el puerto 22 y verifica que los servicios SSH estén en ejecución.

Para resolver errores `Connection reset`, puede ser necesario actualizar los permisos para permitir que Everyone tenga acceso de lectura y ejecución en el directorio OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Avanzado)

**LSA Whisperer** (2024) expone la llamada de paquete `msv1_0!CacheLogon` para que puedas inicializar un *network logon* existente con un NT hash conocido en lugar de crear una sesión nueva con `LogonUser`. Al inyectar el hash en la sesión de logon que WinRM/PowerShell ya abrió en hop #1, ese host puede autenticarse en hop #2 sin almacenar credenciales explícitas ni generar eventos 4624 adicionales.

1. Obtén ejecución de código dentro de LSASS (o bien deshabilita/abusa de PPL o ejecútalo en una VM de laboratorio que controles).
2. Enumera las sesiones de logon (p. ej. `lsa.exe sessions`) y captura el LUID correspondiente a tu contexto de remoting.
3. Precalcula el NT hash y pásalo a `CacheLogon`, luego límpialo cuando termines.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Tras inicializar la semilla de caché, vuelva a ejecutar `Invoke-Command`/`New-PSSession` desde el hop #1: LSASS reutilizará el hash inyectado para satisfacer los desafíos Kerberos/NTLM del segundo hop, eludiendo limpiamente la restricción de double hop. El intercambio es una telemetría más pesada (ejecución de código en LSASS), por lo que guárdelo para entornos de alta fricción donde CredSSP/RCG estén prohibidos.

## Referencias

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}

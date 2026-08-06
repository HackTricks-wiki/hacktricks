# Problema de Double Hop de Kerberos

{{#include ../../banners/hacktricks-training.md}}


## Introducción

El problema de "Double Hop" de Kerberos aparece cuando un atacante intenta utilizar **autenticación Kerberos a través de dos** **hops**, por ejemplo, utilizando **PowerShell**/**WinRM**.

Cuando se produce una **autenticación** mediante **Kerberos**, las **credenciales** **no** se almacenan en la **memoria.** Por lo tanto, si ejecutas mimikatz **no encontrarás las credenciales** del usuario en la máquina, incluso aunque esté ejecutando procesos.

Esto ocurre porque, al conectarse con Kerberos, estos son los pasos:<sup>[[1]](#references)</sup>

1. El Usuario1 proporciona las credenciales y el **controlador de dominio** devuelve un **TGT** de Kerberos al Usuario1.
2. El Usuario1 utiliza el **TGT** para solicitar un **service ticket** para **conectarse** al Servidor1.
3. El Usuario1 se **conecta** al **Servidor1** y proporciona el **service ticket**.
4. El **Servidor1** **no** tiene las **credenciales** del Usuario1 almacenadas ni el **TGT** del Usuario1. Por lo tanto, cuando el Usuario1 intenta iniciar sesión desde el Servidor1 en un segundo servidor, **no puede autenticarse**.

### Unconstrained Delegation

Si **unconstrained delegation** está habilitada en el PC, esto no ocurrirá, ya que el **servidor** **obtendrá** un **TGT** de cada usuario que acceda a él. Además, si se utiliza unconstrained delegation, probablemente podrás **comprometer el controlador de dominio** desde este equipo.\
[**Más información en la página de unconstrained delegation**](unconstrained-delegation.md).

### CredSSP

Otra forma de evitar este problema, que es [**notablemente insegura**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), es **Credential Security Support Provider**. Según Microsoft:

> La autenticación CredSSP delega las credenciales del usuario desde el equipo local a un equipo remoto. Esta práctica aumenta el riesgo de seguridad de la operación remota. Si el equipo remoto se ve comprometido cuando se le pasan las credenciales, estas pueden utilizarse para controlar la sesión de red.

Se recomienda encarecidamente deshabilitar **CredSSP** en sistemas de producción, redes sensibles y entornos similares debido a problemas de seguridad. Para determinar si **CredSSP** está habilitado, se puede ejecutar el comando `Get-WSManCredSSP`. Este comando permite **comprobar el estado de CredSSP** e incluso puede ejecutarse de forma remota, siempre que **WinRM** esté habilitado.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** mantiene el TGT del usuario en la estación de trabajo de origen, mientras permite que la sesión RDP solicite nuevos tickets de servicio Kerberos en el siguiente salto. Habilita **Configuración del equipo > Plantillas administrativas > Sistema > Delegación de credenciales > Restringir la delegación de credenciales a servidores remotos** y selecciona **Requerir Remote Credential Guard**; después, conéctate con `mstsc.exe /remoteGuard /v:server1` en lugar de recurrir a CredSSP.

Microsoft rompió RCG para el acceso multi-hop en Windows 11 22H2+ hasta las **actualizaciones acumulativas de abril de 2024** (KB5036896/KB5036899/KB5036894). Aplica los parches al cliente y al servidor intermediario o el segundo salto seguirá fallando.<sup>[[5]](#references)</sup> Comprobación rápida del hotfix:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Con esas builds instaladas, el salto RDP puede satisfacer los desafíos de Kerberos posteriores sin exponer secretos reutilizables en el primer servidor.

## Soluciones alternativas

### Invoke Command

Para abordar el problema del double hop, se presenta un método que implica un `Invoke-Command` anidado. Esto no resuelve el problema directamente, pero ofrece una solución alternativa sin necesidad de configuraciones especiales. El enfoque permite ejecutar un comando (`hostname`) en un servidor secundario mediante un comando de PowerShell ejecutado desde una máquina atacante inicial o a través de una PS-Session establecida previamente con el primer servidor. Así se hace:<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Como alternativa, se sugiere establecer una PS-Session con el primer servidor y ejecutar `Invoke-Command` usando `$cred` para centralizar las tareas.

### Registrar la configuración de PSSession

Una solución para evadir el problema de double hop consiste en usar `Register-PSSessionConfiguration` con `Enter-PSSession`. Este método requiere un enfoque diferente al de `evil-winrm` y permite disponer de una sesión que no sufre la limitación de double hop.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Para los administradores locales de un objetivo intermediario, el reenvío de puertos permite enviar solicitudes a un servidor final. Mediante `netsh`, se puede añadir una regla para el reenvío de puertos, junto con una regla del firewall de Windows para permitir el puerto reenviado.<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` puede utilizarse para reenviar solicitudes de WinRM, posiblemente como una opción menos detectable si la monitorización de PowerShell es una preocupación.<sup>[[2]](#references)</sup> El comando siguiente demuestra su uso:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Instalar OpenSSH en el primer servidor permite solucionar el problema de double-hop, lo que resulta especialmente útil en escenarios de jump box. Este método requiere la instalación y configuración de OpenSSH para Windows mediante la CLI. Cuando se configura para `Password Authentication`, permite que el servidor intermediario obtenga un TGT en nombre del usuario.<sup>[[2]](#references)</sup>

#### Pasos para instalar OpenSSH

1. Descarga y mueve el archivo zip de la versión más reciente de OpenSSH al servidor objetivo.
2. Descomprímelo y ejecuta el script `Install-sshd.ps1`.
3. Añade una regla de firewall para abrir el puerto 22 y verifica que los servicios SSH estén en ejecución.

Para resolver los errores `Connection reset`, puede ser necesario actualizar los permisos para permitir que todos tengan acceso de lectura y ejecución al directorio de OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Avanzado)

**LSA Whisperer** (2024) expone la llamada de paquete `msv1_0!CacheLogon`, lo que permite sembrar un *network logon* existente con un hash NT conocido en lugar de crear una sesión nueva con `LogonUser`. Al inyectar el hash en la sesión de logon que WinRM/PowerShell ya abrió en el salto #1, ese host puede autenticarse en el salto #2 sin almacenar credenciales explícitas ni generar eventos 4624 adicionales.<sup>[[6]](#references)</sup>

1. Obtén ejecución de código dentro de LSASS (deshabilitando/abusando de PPL o ejecutándolo en una VM de laboratorio que controles).
2. Enumera las sesiones de logon (por ejemplo, `lsa.exe sessions`) y captura el LUID correspondiente a tu contexto de remoting.
3. Precalcula el hash NT y pásalo a `CacheLogon`; después, elimínalo cuando termines.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Después del cache seed, vuelve a ejecutar `Invoke-Command`/`New-PSSession` desde el salto #1: LSASS reutilizará el hash inyectado para satisfacer los desafíos de Kerberos/NTLM del segundo salto, evitando eficazmente la restricción del double hop. La contrapartida es una telemetría más intensa (ejecución de código en LSASS), así que resérvalo para entornos con muchas restricciones en los que CredSSP/RCG no estén permitidos.

## Referencias

- [1] [Descripción del double hop de Kerberos - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Soluciones alternativas para Kerberos Double-Hop](https://posts.slayerlabs.com/double-hop/)
- [3] [Otra solución para la remoting de PowerShell en varios saltos](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Resolver el problema de PowerShell en varios saltos sin usar CredSSP](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [9 de abril de 2024: KB5036896 (compilación del sistema operativo 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}

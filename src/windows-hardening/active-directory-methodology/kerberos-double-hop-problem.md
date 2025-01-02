# Kerberos Double Hop Problemi

{{#include ../../banners/hacktricks-training.md}}


## Giriş

Kerberos "Double Hop" problemi, bir saldırganın **Kerberos kimlik doğrulamasını iki** **atlama** üzerinden kullanmaya çalıştığında ortaya çıkar; örneğin **PowerShell**/**WinRM** kullanarak.

Bir **kimlik doğrulaması** **Kerberos** üzerinden gerçekleştiğinde, **kimlik bilgileri** **bellekte** **önbelleğe alınmaz.** Bu nedenle, eğer mimikatz çalıştırırsanız, kullanıcı makinede işlem çalıştırıyor olsa bile **kimlik bilgilerini bulamazsınız.**

Bu, Kerberos ile bağlanırken izlenen adımlar nedeniyle olur:

1. User1 kimlik bilgilerini sağlar ve **alan denetleyicisi** User1'e bir Kerberos **TGT** döner.
2. User1, **Server1**'e bağlanmak için bir **hizmet bileti** talep etmek üzere **TGT**'yi kullanır.
3. User1 **Server1**'e **bağlanır** ve **hizmet biletini** sağlar.
4. **Server1**, User1'in kimlik bilgilerini veya User1'in **TGT**'sini **önbelleğe almaz.** Bu nedenle, User1 Server1'den ikinci bir sunucuya giriş yapmaya çalıştığında, **kimlik doğrulaması yapılamaz.**

### Sınırsız Delegasyon

Eğer PC'de **sınırsız delegasyon** etkinleştirilmişse, bu durum gerçekleşmez çünkü **Sunucu**, ona erişen her kullanıcının **TGT**'sini **alır.** Dahası, sınırsız delegasyon kullanılıyorsa, muhtemelen **Alan Denetleyicisi'ni** ele geçirebilirsiniz.\
[**Sınırsız delegasyon sayfasında daha fazla bilgi**](unconstrained-delegation.md).

### CredSSP

Bu problemi önlemenin bir diğer yolu, [**özellikle güvensiz**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) olan **Kimlik Bilgisi Güvenlik Destek Sağlayıcısı**dır. Microsoft'tan:

> CredSSP kimlik doğrulaması, kullanıcı kimlik bilgilerini yerel bilgisayardan uzak bir bilgisayara devreder. Bu uygulama, uzak işlemin güvenlik riskini artırır. Uzak bilgisayar ele geçirilirse, kimlik bilgileri ona iletildiğinde, bu kimlik bilgileri ağ oturumunu kontrol etmek için kullanılabilir.

Güvenlik endişeleri nedeniyle, **CredSSP**'nin üretim sistemlerinde, hassas ağlarda ve benzeri ortamlarda devre dışı bırakılması şiddetle önerilir. **CredSSP**'nin etkin olup olmadığını belirlemek için `Get-WSManCredSSP` komutu çalıştırılabilir. Bu komut, **CredSSP durumunu kontrol etmeye** olanak tanır ve **WinRM** etkinse uzaktan bile çalıştırılabilir.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Çözümler

### Invoke Command

Çift sıçrama sorununu ele almak için, iç içe bir `Invoke-Command` içeren bir yöntem sunulmaktadır. Bu, sorunu doğrudan çözmez ancak özel yapılandırmalara ihtiyaç duymadan bir çözüm sunar. Bu yaklaşım, bir komutun (`hostname`) birincil saldırı makinesinden veya ilk sunucu ile daha önce kurulmuş bir PS-Session üzerinden bir ikincil sunucuda çalıştırılmasına olanak tanır. İşte nasıl yapıldığı:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatif olarak, ilk sunucu ile bir PS-Session kurmak ve `$cred` kullanarak `Invoke-Command` çalıştırmak, görevleri merkezileştirmek için önerilmektedir.

### PSSession Yapılandırmasını Kaydet

Çift sıçrama sorununu aşmanın bir çözümü, `Enter-PSSession` ile `Register-PSSessionConfiguration` kullanmaktır. Bu yöntem, `evil-winrm`'den farklı bir yaklaşım gerektirir ve çift sıçrama kısıtlamasından etkilenmeyen bir oturum sağlar.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Yerel yöneticiler için ara hedefte, port yönlendirme, isteklerin nihai bir sunucuya gönderilmesine olanak tanır. `netsh` kullanarak, yönlendirilmiş portu izin vermek için bir Windows güvenlik duvarı kuralının yanı sıra port yönlendirme için bir kural eklenebilir.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe`, PowerShell izleme bir endişe ise daha az tespit edilebilir bir seçenek olarak WinRM isteklerini iletmek için kullanılabilir. Aşağıdaki komut, kullanımını göstermektedir:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

İlk sunucuya OpenSSH yüklemek, özellikle jump box senaryoları için yararlı olan double-hop sorununa bir çözüm sağlar. Bu yöntem, Windows için OpenSSH'nin CLI ile yüklenmesini ve yapılandırılmasını gerektirir. Şifre Kimlik Doğrulaması için yapılandırıldığında, bu, aracılık sunucusunun kullanıcı adına bir TGT almasına olanak tanır.

#### OpenSSH Yükleme Adımları

1. En son OpenSSH sürüm zip dosyasını indirin ve hedef sunucuya taşıyın.
2. Zip dosyasını açın ve `Install-sshd.ps1` betiğini çalıştırın.
3. Port 22'yi açmak için bir güvenlik duvarı kuralı ekleyin ve SSH hizmetlerinin çalıştığını doğrulayın.

`Connection reset` hatalarını çözmek için, OpenSSH dizininde herkesin okuma ve çalıştırma erişimine izin vermek için izinlerin güncellenmesi gerekebilir.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Referanslar

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)


{{#include ../../banners/hacktricks-training.md}}

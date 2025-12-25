# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Giriş

Kerberos "Double Hop" sorunu, bir saldırganın örneğin **PowerShell**/**WinRM** kullanarak **Kerberos kimlik doğrulamasını iki** **hop** boyunca kullanmaya çalıştığında ortaya çıkar.

Bir **kimlik doğrulama** **Kerberos** aracılığıyla gerçekleştiğinde, **kimlik bilgileri** belleğe **önbelleğe alınmaz.** Bu nedenle, mimikatz çalıştırırsanız kullanıcı makinede işlem çalıştırıyor olsa bile kullanıcının **kimlik bilgilerini** bulamazsınız.

Bunun nedeni, Kerberos ile bağlanırken adımların şu şekilde olmasıdır:

1. User1 kimlik bilgilerini sağlar ve **domain controller** User1'e bir Kerberos **TGT** döndürür.
2. User1, **Server1**'e **bağlanmak** için bir **service ticket** talep etmek amacıyla **TGT** kullanır.
3. User1 **Server1**'e **bağlanır** ve **service ticket** sunar.
4. **Server1**'de User1'in **kimlik bilgileri** veya User1'in **TGT**'si önbelleğe alınmaz. Bu nedenle, Server1 üzerinden User1 ikinci bir sunucuya giriş yapmaya çalıştığında **kimlik doğrulaması yapamaz**.

### Unconstrained Delegation

Eğer PC'de **unconstrained delegation** etkinse, bu durum meydana gelmez çünkü **Server** ona erişen her kullanıcının **TGT**'sini alır. Ayrıca, unconstrained delegation kullanıldığında muhtemelen bu yolla **Domain Controller**'ı ele geçirebilirsiniz.\
[**Daha fazla bilgi için unconstrained delegation sayfasına bakın**](unconstrained-delegation.md).

### CredSSP

Bu sorundan kaçınmanın bir diğer yolu, [**özellikle güvensiz**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) olan **Credential Security Support Provider**'dır. Microsoft'tan:

> CredSSP kimlik doğrulaması, kullanıcı kimlik bilgilerini yerel bilgisayardan uzak bir bilgisayara devreder. Bu uygulama uzak işlemin güvenlik riskini artırır. Uzak bilgisayar ele geçirilirse, kimlik bilgileri ona aktarıldığında, kimlik bilgileri ağ oturumunu kontrol etmek için kullanılabilir.

Güvenlik endişeleri nedeniyle, **CredSSP**'nin üretim sistemlerinde, hassas ağlarda ve benzeri ortamlarda devre dışı bırakılması kuvvetle tavsiye edilir. **CredSSP**'nin etkin olup olmadığını belirlemek için `Get-WSManCredSSP` komutu çalıştırılabilir. Bu komut, **CredSSP durumunun kontrol edilmesine** olanak tanır ve **WinRM** etkin olduğu sürece uzaktan bile çalıştırılabilir.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** kullanıcının TGT'sini kaynak iş istasyonunda tutarken, RDP oturumunun bir sonraki hop'ta yeni Kerberos service ticket'ları istemesine yine de izin verir. Etkinleştirin **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** ve **Require Remote Credential Guard**'ı seçin, sonra CredSSP'ye geri dönmek yerine `mstsc.exe /remoteGuard /v:server1` ile bağlanın.

Microsoft, Windows 11 22H2+ üzerinde çoklu-hop erişimi için RCG'yi **Nisan 2024 toplu güncellemelerine** (KB5036896/KB5036899/KB5036894) kadar bozdu. İstemciyi ve aradaki sunucuyu yamayın yoksa ikinci hop yine başarısız olur. Hızlı hotfix kontrolü:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Bu build'ler yüklendiğinde, RDP hop ilk sunucuda yeniden kullanılabilir sırları açığa çıkarmadan aşağı yöndeki Kerberos taleplerini karşılayabilir.

## Geçici Çözümler

### Invoke Command

Double hop sorununu ele almak için, iç içe geçmiş bir `Invoke-Command` içeren bir yöntem sunulmaktadır. Bu doğrudan problemi çözmez ancak özel yapılandırmalar gerektirmeden bir geçici çözüm sunar. Bu yaklaşım, ilk saldırgan makineden yürütülen bir PowerShell komutu veya ilk sunucuyla önceden kurulmuş bir PS-Session üzerinden, ikincil bir sunucuda `hostname` gibi bir komutun çalıştırılmasına izin verir. İşte nasıl yapıldığı:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatif olarak, ilk sunucu ile bir PS-Session kurup görevleri merkezileştirmek için `Invoke-Command`'ı `$cred` ile çalıştırmak önerilir.

### Register PSSession Configuration

double hop problem'i aşmak için bir çözüm, `Register-PSSessionConfiguration` ile `Enter-PSSession` kullanmaktır. Bu yöntem `evil-winrm`'den farklı bir yaklaşım gerektirir ve double hop sınırlamasından muzdarip olmayan bir oturum sağlar.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Aracı bir hedefteki yerel yöneticiler için, port forwarding isteklerin nihai bir sunucuya gönderilmesine izin verir. `netsh` kullanılarak port forwarding için bir kural eklenebilir; ayrıca yönlendirilen portu izin veren bir Windows firewall kuralı eklenmelidir.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` WinRM isteklerini iletmek için kullanılabilir; PowerShell izleme bir endişe ise muhtemelen daha az tespit edilebilir bir seçenek olabilir. Aşağıdaki komut kullanımını göstermektedir:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

İlk sunucuya OpenSSH kurmak, özellikle jump box senaryoları için double-hop sorununa bir çözüm yolu sağlar. Bu yöntem, OpenSSH for Windows'un CLI ile kurulmasını ve yapılandırılmasını gerektirir. `Password Authentication` için yapılandırıldığında, bu aradaki sunucunun kullanıcı adına bir `TGT` almasına izin verir.

#### OpenSSH Kurulum Adımları

1. En son OpenSSH sürümünün zip dosyasını indirip hedef sunucuya taşıyın.
2. Zip'i açıp `Install-sshd.ps1` betiğini çalıştırın.
3. Port 22'yi açmak için bir güvenlik duvarı kuralı ekleyin ve SSH servislerinin çalıştığını doğrulayın.

`Connection reset` hatalarını çözmek için, OpenSSH dizinine herkesin okuma ve çalıştırma erişimi verecek şekilde izinlerin güncellenmesi gerekebilir.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Gelişmiş)

**LSA Whisperer** (2024) `msv1_0!CacheLogon` paket çağrısını ortaya çıkarır; böylece yeni bir oturum oluşturmak yerine `LogonUser` ile mevcut bir *network logon*'u bilinen bir NT hash ile doldurabilirsiniz. Hash'i hop #1'de WinRM/PowerShell'in zaten açtığı oturumun içine enjekte ederek, o host açık kimlik bilgileri saklamadan veya ek 4624 olayları oluşturmadan hop #2'ye kimlik doğrulayabilir.

1. LSASS içinde kod çalıştırma elde edin (ya PPL'yi devre dışı bırakın/istismar edin ya da kontrolünüzdeki bir lab VM'de çalıştırın).
2. Oturumları listeleyin (örn. `lsa.exe sessions`) ve uzaktan bağlamınıza karşılık gelen LUID'i yakalayın.
3. NT hash'i önceden hesaplayın ve `CacheLogon`'a verin, işiniz bittiğinde temizleyin.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Cache seed işleminden sonra, hop #1'den `Invoke-Command`/`New-PSSession`'i tekrar çalıştırın: LSASS, enjekte edilen hash'i ikinci hop için Kerberos/NTLM challenge'larını karşılamak üzere yeniden kullanacak ve double hop kısıtlamasını temiz şekilde atlatacaktır. Dezavantajı daha yoğun telemetri (LSASS içinde kod yürütülmesi) olmasıdır; bu nedenle CredSSP/RCG'nin yasaklandığı yüksek sürtüşmeli ortamlarda kullanın.

## References

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}

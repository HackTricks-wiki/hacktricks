# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Introduction

Kerberos "Double Hop" problemi, bir saldırganın örneğin **PowerShell**/**WinRM** kullanarak **iki** **hop** üzerinden **Kerberos authentication** kullanmaya çalışmasıyla ortaya çıkar.

**Kerberos** üzerinden bir **authentication** gerçekleştiğinde, **credentials** **memory** içinde önbelleğe alınmaz. Bu nedenle mimikatz çalıştırırsanız, kullanıcı process çalıştırıyor olsa bile makinede kullanıcının **credentials** bilgilerini **bulamazsınız**.

Bunun nedeni, Kerberos ile bağlantı kurulurken şu adımların izlenmesidir:<sup>[[1]](#references)</sup>

1. User1 **credentials** bilgilerini sağlar ve **domain controller**, User1'a bir Kerberos **TGT** döndürür.
2. User1, Server1'a **connect** olmak için **TGT** kullanarak bir **service ticket** ister.
3. User1, **Server1'a connect** olur ve **service ticket** sağlar.
4. **Server1**, User1'ın **credentials** bilgilerini veya User1'ın **TGT**'sini önbelleğe almış **değildir**. Bu nedenle User1, Server1 üzerinden ikinci bir sunucuya login olmaya çalıştığında **authenticate** olamaz.

### Unconstrained Delegation

PC'de **unconstrained delegation** etkinse bu durum gerçekleşmez; çünkü **Server**, kendisine erişen her kullanıcının bir **TGT**'sini **alır**. Ayrıca, unconstrained delegation kullanılıyorsa muhtemelen buradan **Domain Controller'ı compromise** edebilirsiniz.\
[**unconstrained delegation sayfasında daha fazla bilgi**](unconstrained-delegation.md).

### CredSSP

Bu sorunu önlemenin [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) başka bir yolu **Credential Security Support Provider** kullanmaktır. Microsoft'a göre:

> CredSSP authentication, kullanıcının credentials bilgilerini local computer'dan remote computer'a delegate eder. Bu uygulama, remote operation'ın security riskini artırır. Remote computer compromise edilirse, credentials bilgileri kendisine iletildiğinde network session'ı kontrol etmek için kullanılabilir.

Güvenlik endişeleri nedeniyle production systems, sensitive networks ve benzer ortamlarda **CredSSP**'nin devre dışı bırakılması önemle önerilir. **CredSSP**'nin etkin olup olmadığını belirlemek için `Get-WSManCredSSP` komutu çalıştırılabilir. Bu komut, **CredSSP status kontrolü** yapılmasını sağlar ve **WinRM** etkin olduğu sürece remote olarak da çalıştırılabilir.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard**, kullanıcının TGT'sini kaynak iş istasyonunda tutarken RDP oturumunun bir sonraki hop'ta yeni Kerberos service ticket'ları istemesine yine de olanak tanır. **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** seçeneğini etkinleştirin ve **Require Remote Credential Guard** seçeneğini belirleyin; ardından CredSSP'ye geri dönmek yerine `mstsc.exe /remoteGuard /v:server1` ile bağlanın.

Microsoft, **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894) yayımlanana kadar Windows 11 22H2+ üzerinde çoklu hop erişimi için RCG'yi bozdu. İstemciye ve aracı sunucuya patch uygulayın; aksi takdirde ikinci hop yine başarısız olur.<sup>[[5]](#references)</sup> Hızlı hotfix kontrolü:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Bu build'ler kurulduğunda RDP hop'u, ilk sunucuda yeniden kullanılabilir secret'ları açığa çıkarmadan downstream Kerberos challenge'larını karşılayabilir.

## Workarounds

### Invoke Command

Double hop sorununu ele almak için iç içe bir `Invoke-Command` içeren bir yöntem sunulmuştur. Bu yöntem sorunu doğrudan çözmez, ancak özel yapılandırmalara ihtiyaç duymadan bir workaround sağlar. Bu yaklaşım, ilk saldırı makinesinden yürütülen bir PowerShell command'i veya ilk sunucuyla daha önce oluşturulmuş bir PS-Session üzerinden ikincil bir sunucuda bir command (`hostname`) çalıştırmaya olanak tanır. İşlem şu şekilde gerçekleştirilir:<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatif olarak, ilk sunucuyla bir PS-Session oluşturup `$cred` kullanarak `Invoke-Command` çalıştırmak, görevleri merkezileştirmek için önerilir.

### Register PSSession Configuration

double hop sorununu bypass etmek için bir çözüm, `Enter-PSSession` ile birlikte `Register-PSSessionConfiguration` kullanmaktır. Bu yöntem, `evil-winrm`'den farklı bir yaklaşım gerektirir ve double hop sınırlamasından etkilenmeyen bir session kullanılmasına olanak tanır.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Aradaki hedefteki yerel yöneticiler için port forwarding, isteklerin nihai sunucuya gönderilmesini sağlar. `netsh` kullanılarak port forwarding için bir kural eklenebilir; ayrıca yönlendirilen porta izin vermek üzere bir Windows firewall kuralı da eklenebilir.<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe`, WinRM isteklerini iletmek için kullanılabilir; PowerShell monitoring bir endişeyse potansiyel olarak daha az tespit edilebilir bir seçenek sunar.<sup>[[2]](#references)</sup> Aşağıdaki komut kullanımını gösterir:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

İlk sunucuya OpenSSH yüklemek, özellikle jump box senaryolarında kullanışlı olan double-hop sorununa yönelik bir geçici çözüm sağlar. Bu yöntem, OpenSSH for Windows'ın CLI üzerinden yüklenmesini ve yapılandırılmasını gerektirir. Password Authentication ile yapılandırıldığında, aracı sunucunun kullanıcı adına bir TGT almasına olanak tanır.<sup>[[2]](#references)</sup>

#### OpenSSH Installation Steps

1. En güncel OpenSSH sürümünün zip dosyasını indirin ve hedef sunucuya taşıyın.
2. Zip dosyasını açın ve `Install-sshd.ps1` script'ini çalıştırın.
3. 22 numaralı portu açmak için bir firewall kuralı ekleyin ve SSH servislerinin çalıştığını doğrulayın.

`Connection reset` hatalarını çözmek için, OpenSSH dizininde everyone kullanıcısına okuma ve çalıştırma erişimi vermek üzere izinlerin güncellenmesi gerekebilir.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Gelişmiş)

**LSA Whisperer** (2024), yeni bir oturum oluşturmak yerine mevcut bir *network logon* oturumuna bilinen bir NT hash'i yerleştirmenizi sağlayan `msv1_0!CacheLogon` package çağrısını açığa çıkarır. WinRM/PowerShell'in hop #1 üzerinde zaten açtığı logon session'a hash'i enjekte ederek bu host'un açık kimlik bilgilerini depolamadan veya ek 4624 event'leri oluşturmadan hop #2'ye authenticate olmasını sağlayabilirsiniz.<sup>[[6]](#references)</sup>

1. LSASS içinde code execution elde edin (PPL'yi devre dışı bırakarak/kötüye kullanarak veya kontrol ettiğiniz bir lab VM'sinde çalıştırarak).
2. Logon session'ları enumerate edin (ör. `lsa.exe sessions`) ve remoting context'inize karşılık gelen LUID'yi alın.
3. NT hash'i önceden hesaplayıp `CacheLogon`'a verin, ardından işiniz bittiğinde temizleyin.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Cache seed işleminden sonra hop #1 üzerinden `Invoke-Command`/`New-PSSession` komutlarını yeniden çalıştırın: LSASS, ikinci hop için Kerberos/NTLM challenge'larını karşılamak üzere inject edilmiş hash'i yeniden kullanacak ve double hop kısıtlamasını sorunsuz şekilde bypass edecektir. Bunun karşılığında daha yoğun telemetry (LSASS içinde code execution) oluşur; bu nedenle CredSSP/RCG kullanımının yasak olduğu, sürtünmenin yüksek olduğu ortamlar için saklayın.

## References

- [1] [Understanding Kerberos Double Hop - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Kerberos Double-Hop Workarounds](https://posts.slayerlabs.com/double-hop/)
- [3] [Another solution to multi-hop PowerShell remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Solve the PowerShell multi-hop problem without using CredSSP](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [April 9, 2024—KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}

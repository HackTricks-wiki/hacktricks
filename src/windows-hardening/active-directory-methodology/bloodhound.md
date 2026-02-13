# BloodHound & Diğer Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOT: Bu sayfa, Active Directory ilişkilerini **enumerate** ve **visualise** etmek için en kullanışlı yardımcı programlardan bazılarını gruplayıp sunar. Gizli **Active Directory Web Services (ADWS)** kanalı üzerinden toplama yapmak için yukarıdaki referansa bakın.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) gelişmiş bir **AD viewer & editor**dir ve şunları yapar:

* Dizin ağacını GUI ile gezinme
* Nesne özniteliklerini ve güvenlik tanımlayıcılarını düzenleme
* Çevrimdışı analiz için snapshot oluşturma / karşılaştırma

### Hızlı kullanım

1. Aracı başlatın ve herhangi bir domain kimlik bilgisiyle `dc01.corp.local`'a bağlanın.
2. `File ➜ Create Snapshot` yolunu izleyerek çevrimdışı bir snapshot oluşturun.
3. İzin sapmalarını tespit etmek için iki snapshot'ı `File ➜ Compare` ile karşılaştırın.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) etki alanından (ACLs, GPOs, trusts, CA templates …) çok sayıda artefakt çıkarır ve bir **Excel report** üretir.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (grafik görselleştirme)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) grafik teorisi + Neo4j kullanarak on-prem AD & Azure AD içindeki gizli ayrıcalık ilişkilerini ortaya çıkarır.

### Dağıtım (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Toplayıcılar

* `SharpHound.exe` / `Invoke-BloodHound` – yerel veya PowerShell varyantı
* `AzureHound` – Azure AD keşfi
* **SoaPy + BOFHound** – ADWS toplama (üstteki bağlantıya bakın)

#### Yaygın SharpHound modları
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
The collectors generate JSON which is ingested via the BloodHound GUI.

### Ayrıcalık ve oturum hakkı toplama

Windows **token privileges** (örn., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) DACL kontrollerini atlayabilir, bu yüzden bunları domain genelinde eşlemek ACL-only grafiklerin kaçırdığı yerel LPE kenarlarını açığa çıkarır. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` ve bunların `SeDeny*` karşılıkları) bir token daha var olmadan önce LSA tarafından uygulanır ve reddetmeler önceliklidir; bu nedenle yan hareketi (RDP/SMB/zamanlanmış görev/hizmet oturumu) maddi olarak sınırlar.

Mümkünse collector'ları yükseltilmiş olarak çalıştırın: UAC, etkileşimli adminler için filtrelenmiş bir token oluşturur (via `NtFilterToken`), hassas ayrıcalıkları kaldırır ve admin SID'lerini deny-only olarak işaretler. Eğer ayrıcalıkları yükseltilmemiş bir shell'den enumerate ederseniz, yüksek değerli ayrıcalıklar görünmez olacak ve BloodHound kenarları ingest etmeyecektir.

Şimdi iki tamamlayıcı SharpHound toplama stratejisi var:

- **GPO/SYSVOL ayrıştırması (sessiz, düşük ayrıcalıklı):**
1. LDAP üzerinden GPO'ları enumerate edin (`(objectCategory=groupPolicyContainer)`) ve her `gPCFileSysPath`'i okuyun.
2. SYSVOL'dan `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` dosyasını alın ve ayrıcalık/oturum hakkı isimlerini SID'lere eşleyen `[Privilege Rights]` bölümünü parse edin.
3. OU/site/domain üzerindeki `gPLink` ile GPO linklerini çözümleyin, linklenen konteynerlerdeki bilgisayarları listeleyin ve hakları o makinelere atfedin.
4. Avantaj: normal bir kullanıcı ile çalışır ve sessizdir; dezavantaj: sadece GPO ile uygulanmış hakları görür (yerel değişiklikler kaçırılır).

- **LSA RPC enumeration (gürültülü, doğru):**
- Hedefte local admin olan bir bağlamdan, Local Security Policy'yi açın ve atanmış principal'leri RPC üzerinden enumerate etmek için her ayrıcalık/oturum hakkı için `LsaEnumerateAccountsWithUserRight` çağrın.
- Avantaj: yerelde veya GPO dışında ayarlanmış hakları yakalar; dezavantaj: gürültülü ağ trafiği ve her hostta admin gereksinimi.

**Bu kenarlar tarafından ortaya çıkarılan örnek kötüye kullanım yolu:** `CanRDP` ➜ kullanıcınızın ayrıca `SeBackupPrivilege`'a sahip olduğu host ➜ filtrelenmiş tokenlardan kaçınmak için yükseltilmiş bir shell başlatın ➜ backup semantiğini kullanıp kısıtlayıcı DACL'lere rağmen `SAM` ve `SYSTEM` hive'larını okuyun ➜ dışarı çıkarın ve local Administrator NT hash'ini elde etmek için offline olarak `secretsdump.py` çalıştırın (lateral movement/privilege escalation için).

### Kerberoasting'i BloodHound ile Önceliklendirme

Hedefe yönelik roasting'i korumak için grafik bağlamını kullanın:

1. ADWS-uyumlu bir collector ile bir kez toplayın ve offline çalışın:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIP'i import edin, ele geçirilmiş principal'i owned olarak işaretleyin ve yerleşik sorguları (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) çalıştırarak admin/infra haklarına sahip SPN hesaplarını ortaya çıkarın.
3. SPN'leri blast radius'a göre önceliklendirin; kırmadan önce `pwdLastSet`, `lastLogon` ve izin verilen şifreleme tiplerini inceleyin.
4. Yalnızca seçili ticket'ları isteyin, offline kırın, sonra yeni erişimle BloodHound'u yeniden sorgulayın:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) **Group Policy Objects**'i enumerate eder ve yanlış yapılandırmaları öne çıkarır.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) Active Directory için bir **sağlık kontrolü** yapar ve risk puanlamalı bir HTML raporu oluşturur.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referanslar

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}

# BloodHound ve Diğer Active Directory Enumeration Araçları

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOT: Bu sayfa, Active Directory ilişkilerini **enumerate** ve **görselleştirmek** için en kullanışlı utility'lerden bazılarını gruplandırır. Stealthy **Active Directory Web Services (ADWS)** kanalı üzerinden collection için yukarıdaki reference'a bakın.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals), aşağıdakilere olanak sağlayan gelişmiş bir **AD görüntüleyici ve editörüdür**:

* Directory tree'yi GUI üzerinden browse etme
* Object attribute'larını ve security descriptor'larını düzenleme
* Offline analysis için Snapshot oluşturma / karşılaştırma

### Hızlı kullanım

1. Tool'u başlatın ve herhangi bir domain credential'ı ile `dc01.corp.local` adresine bağlanın.
2. `File ➜ Create Snapshot` üzerinden bir offline Snapshot oluşturun.
3. Permission drift'lerini tespit etmek için `File ➜ Compare` ile iki Snapshot'ı karşılaştırın.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon), bir domain'den geniş bir artefact seti (ACL'ler, GPO'lar, trust'lar, CA template'leri …) çıkarır ve bir **Excel report'u** oluşturur.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (grafik görselleştirme)

[BloodHound](https://github.com/SpecterOps/BloodHound), on-prem AD, Entra ID içindeki ve OpenGraph üzerinden içe aktardığınız ek attack-surface verilerindeki gizli privilege ilişkilerini ortaya çıkarmak için graph theory kullanır.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collector'lar

* `SharpHound.exe` / `Invoke-BloodHound` – native veya PowerShell varyantı
* `RustHound-CE` – Linux, macOS ve Windows için cross-platform CE collector'ı
* `NetExec --bloodhound` – Linux üzerinden hızlı, LDAP-driven collection
* `AzureHound` – Entra ID enumeration
* **SoaPy + BOFHound** – ADWS collection (üstteki linke bakın)

> BloodHound CE `v8+`, OpenGraph kullanıma sunulduğunda collector output format'ını değiştirdi. Legacy BloodHound veya daha eski CE kurulumlarından upgrade yaptıktan sonra, data'yı import etmeden önce güncel collector'larla discovery işlemini yeniden çalıştırın.

#### Yaygın SharpHound modları
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Collector'lar, BloodHound GUI üzerinden içe aktarılan JSON oluşturur.

#### Domain'e dahil olmayan bir Windows host'tan SharpHound

Operator VM'iniz hedef domain'e dahil değilse DNS'i bir DC'yi gösterecek şekilde ayarlayın, **network-only** bir shell başlatın, bir DC üzerindeki `SYSVOL`/`NETLOGON` paylaşımlarını görebildiğinizi doğrulayın ve ardından uzak domain'e karşı veri toplayın:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Bu, domain'e katılmaması gereken geçici jump box'lar veya operatör iş istasyonları için kullanışlıdır.

#### Linux/macOS üzerinden cross-platform collection
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE`, Windows olmayan bir host'tan CE uyumlu çıktı almak istediğinizde iyi bir varsayılan seçenektir. LDAP doğrulaması veya spraying için zaten `NetExec` kullanıyorsanız ve hızlı bir graph içe aktarımı istiyorsanız `NetExec` kullanışlıdır. AD dışı veri kümeleri için BloodHound OpenGraph, [ShareHound](../../network-services-pentesting/pentesting-smb/README.md) gibi collector'larla genişletilebilir.

### ADPathFinder (OpenGraph path önceliklendirme)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder), graph manuel olarak pivot edilemeyecek kadar büyük olduğunda BloodHound CE/OpenGraph üzerinde çalışır. Yalnızca bir principal'ın bir hedefe ulaşıp ulaşamayacağını sormak yerine, düşük ayrıcalıklı birçok kullanıcı ve bilgisayardan yüksek değerli nesnelere giden en kısa yolları hesaplar, aynı edge'leri yeniden kullanan yolları gruplandırır ve ilk olarak düzeltilmesi gereken ortak choke point'i ortaya çıkarır.
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
`MSSQLHound` ve `ConfigManBearPig` verileri içe aktarıldığında, tek bir bulgu [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) ve [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md) arasında ilerleyebilir; bunları ayrı ipuçları olarak bırakmak gerekmez. Ortak yol örneği:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Her edge'de **effective security context**'i takip edin. Bir path, normal bir kullanıcıdan başlamış olsa bile, herhangi bir geçiş privileged domain identity olarak çalıştırıldığı anda domain-critical hale gelir.
- Gruplandırılmış bulgular **choke-point remediation** için idealdir: tek bir SQL impersonation permission'ını, linked-server trust'ını, certificate-template abuse path'ini veya SCCM assignment'ını kaldırmak, aynı anda birçok shortest path'i ortadan kaldırabilir.
- "Medium" bulguları **graph context** ile yeniden önceliklendirin. SMB signing'in devre dışı olması, WebClient exposure, delegation hataları veya NTLM-relayable SQL server'lar; compromised node'un Domain Admins, Domain Controllers, CA'ler veya SCCM site server'larına onward path'leri olduğunda daha yüksek önceliği hak eder.
- Ayrıca `NTDS.dit` çıktınız ve bir hashcat potfile'ınız varsa, `--pwd` cracked password'ları BloodHound properties ile ilişkilendirir. Böylece ordinary password reuse ile privileged, Kerberoastable, AS-REP roastable veya path-relevant account'larda bulunan cracked creds'leri hızlıca ayırabilirsiniz.

### Privilege & logon-right collection

Windows **token privileges** (ör. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) DACL kontrollerini bypass edebilir. Bu nedenle bunların domain-wide olarak map edilmesi, yalnızca ACL kullanan graph'ların kaçırdığı local LPE edge'lerini ortaya çıkarır. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` ve bunların `SeDeny*` karşılıkları), bir token henüz mevcut olmadan önce LSA tarafından uygulanır ve deny kuralları önceliklidir. Bu nedenle lateral movement'ı (RDP/SMB/scheduled task/service logon) önemli ölçüde sınırlar.

Mümkün olduğunda **collectors'ı elevated olarak çalıştırın**: UAC, interactive admin'ler için (`NtFilterToken` aracılığıyla) filtered token oluşturur; hassas privilege'ları kaldırır ve admin SID'lerini deny-only olarak işaretler. Privilege'ları non-elevated bir shell'den enumerate ederseniz yüksek değerli privilege'lar görünmez olur ve BloodHound edge'leri ingest etmez.

Artık iki complementary SharpHound collection strategy mevcuttur:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. LDAP üzerinden (`(objectCategory=groupPolicyContainer)`) GPO'ları enumerate edin ve her birinin `gPCFileSysPath` değerini okuyun.
2. SYSVOL'den `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` dosyasını alın ve privilege/logon-right adlarını SID'lere map eden `[Privilege Rights]` bölümünü parse edin.
3. OU/site/domain üzerindeki `gPLink` kullanarak GPO link'lerini resolve edin, linked container'lar içindeki computer'ları listeleyin ve rights'ları bu machine'lere attribute edin.
4. Avantajı: normal bir kullanıcıyla çalışır ve sessizdir; dezavantajı: yalnızca GPO üzerinden push edilen rights'ları görür (local tweak'ler kaçırılır).

- **LSA RPC enumeration (noisy, accurate):**
- Target üzerinde local admin yetkisine sahip bir context'ten Local Security Policy'yi açın ve RPC üzerinden assigned principal'ları enumerate etmek için her privilege/logon right için `LsaEnumerateAccountsWithUserRight` çağırın.
- Avantajı: local olarak veya GPO dışında ayarlanan rights'ları da yakalar; dezavantajı: noisy network traffic oluşturur ve her host üzerinde admin gerektirir.

**Bu edge'lerle ortaya çıkarılabilecek örnek abuse path:** `CanRDP` ➜ kullanıcınızın aynı zamanda `SeBackupPrivilege` sahibi olduğu host ➜ filtered token'lardan kaçınmak için elevated bir shell başlatma ➜ restrictive DACL'lere rağmen backup semantics kullanarak `SAM` ve `SYSTEM` hive'larını okuma ➜ lateral movement/privilege escalation için exfiltrate etme ve local Administrator NT hash'ini offline olarak kurtarmak üzere `secretsdump.py` çalıştırma.

### Prioritising Kerberoasting with BloodHound

Roasting'i hedefli tutmak için graph context kullanın:

1. ADWS-compatible bir collector ile bir kez collect edin ve offline çalışın:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIP'i import edin, compromised principal'ı owned olarak işaretleyin ve admin/infra rights'a sahip SPN account'larını ortaya çıkarmak için yerleşik query'leri (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) çalıştırın.
3. SPN'leri blast radius'a göre önceliklendirin; cracking işleminden önce `pwdLastSet`, `lastLogon` ve izin verilen encryption type'ları inceleyin.
4. Yalnızca seçilen ticket'ları request edin, offline olarak crack edin ve ardından yeni access ile BloodHound'u yeniden query edin:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r), **Group Policy Objects**'ı enumerate eder ve misconfiguration'ları öne çıkarır.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) Active Directory için bir **sağlık kontrolü** gerçekleştirir ve risk puanlaması içeren bir HTML raporu oluşturur.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referanslar

- [BloodHound Community Edition v8, OpenGraph ile Yayında: Active Directory ve Entra ID Ötesinde Identity Attack Paths](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [ACL'lerin Ötesinde: BloodHound ile Windows Privilege Escalation Paths Eşleme](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [ADPathFinder: BloodHound CE'de OpenGraph Attack Path Mapping](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}

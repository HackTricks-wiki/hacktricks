# BloodHound ve Diğer Active Directory Enumeration Araçları

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOT: Bu sayfa, Active Directory ilişkilerini **enumerate** ve **visualise** etmek için en kullanışlı yardımcı programlardan bazılarını gruplandırır. Gizli **Active Directory Web Services (ADWS)** kanalı üzerinden collection için yukarıdaki referansa bakın.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals), aşağıdakilere olanak sağlayan gelişmiş bir **AD viewer & editor** aracıdır:

* Directory tree üzerinde GUI ile gezinme
* Object attribute'larını ve security descriptor'larını düzenleme
* Offline analysis için snapshot oluşturma / karşılaştırma

### Hızlı kullanım

1. Aracı başlatın ve herhangi bir domain credential'ı ile `dc01.corp.local` adresine bağlanın.
2. `File ➜ Create Snapshot` üzerinden offline snapshot oluşturun.
3. Permission drift'lerini tespit etmek için `File ➜ Compare` ile iki snapshot'ı karşılaştırın.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon), bir domain'den geniş bir artefact seti (ACL'ler, GPO'lar, trust'lar, CA template'leri …) çıkarır ve bir **Excel report** oluşturur.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (graf görselleştirme)

[BloodHound](https://github.com/SpecterOps/BloodHound), on-prem AD, Entra ID ve OpenGraph aracılığıyla içeri aktardığınız ek attack-surface verileri içindeki gizli yetki ilişkilerini ortaya çıkarmak için graf teorisini kullanır.<sup>[[1]](#references)</sup>

### Kurulum (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collector'lar

* `SharpHound.exe` / `Invoke-BloodHound` – native veya PowerShell varyantı
* `RustHound-CE` – Linux, macOS ve Windows için cross-platform CE collector'ı
* `NetExec --bloodhound` – Linux üzerinden hızlı, LDAP-driven collection
* `AzureHound` – Entra ID enumeration
* **SoaPy + BOFHound** – ADWS collection (yukarıdaki linke bakın)

> BloodHound CE `v8+`, OpenGraph kullanıma sunulduğunda collector output formatını değiştirdi. Legacy BloodHound veya daha eski CE kurulumlarından upgrade yaptıktan sonra, data'yı import etmeden önce güncel collector'larla discovery işlemini yeniden çalıştırın.<sup>[[1]](#references)</sup>

#### Yaygın SharpHound modları
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Collector'lar, BloodHound GUI üzerinden alınan JSON dosyaları oluşturur.

#### Domain'e dahil olmayan bir Windows host üzerinden SharpHound

Operator VM'iniz hedef domain'e dahil değilse DNS'i bir DC'yi gösterecek şekilde yapılandırın, **network-only** bir shell başlatın, bir DC üzerinde `SYSVOL`/`NETLOGON` kaynaklarını görebildiğinizi doğrulayın ve ardından uzak domain'e karşı collection gerçekleştirin:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Bu, domain'e dahil edilmemesi gereken geçici jump box'lar veya operator workstation'ları için kullanışlıdır.

#### Linux/macOS'tan çapraz platform veri toplama
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE`, Windows olmayan bir host'tan CE uyumlu çıktı istediğinizde iyi bir varsayılandır.<sup>[[2]](#references)</sup> LDAP doğrulaması veya spraying için zaten `NetExec` kullanıyorsanız ve hızlı bir graph import istiyorsanız `NetExec` kullanışlıdır. AD dışı veri kümeleri için BloodHound OpenGraph, [ShareHound](../../network-services-pentesting/pentesting-smb/README.md) gibi collector'larla genişletilebilir.<sup>[[1]](#references)</sup>

### ADPathFinder (OpenGraph yol önceliklendirmesi)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder), graph manuel olarak pivot yapılamayacak kadar büyük olduğunda BloodHound CE/OpenGraph üzerinde çalışır. Yalnızca bir principal'ın bir hedefe ulaşıp ulaşamayacağını sormak yerine, çok sayıda düşük ayrıcalıklı kullanıcı ve bilgisayardan yüksek değerli nesnelere ve gruplara giden en kısa yolları hesaplar, aynı edge'leri yeniden kullanan yolları gruplandırır ve önce düzeltilmesi gereken ortak choke point'i ortaya çıkarır.<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
`MSSQLHound` ve `ConfigManBearPig` verileri içe aktarıldığında, tek bir bulgu [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) ve [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md) arasında ilerleyebilir; bunları ayrı izler olarak bırakmak yerine.<sup>[[4]](#references)</sup> Paylaşılan yol örneği:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Her edge'de **etkin güvenlik bağlamını** takip edin. Bir yol, normal bir kullanıcıdan başlamış olsa bile, geçişlerden biri ayrıcalıklı bir domain kimliğiyle çalıştırıldığı anda domain açısından kritik hale gelir.
- Gruplanmış bulgular **darboğaz giderimi** için idealdir: tek bir SQL impersonation iznini, linked-server trust ilişkisini, certificate-template abuse yolunu veya SCCM assignment'ını kaldırmak, aynı anda birçok en kısa yolu ortadan kaldırabilir.
- "Medium" bulguları **graph context** ile yeniden önceliklendirin. SMB signing devre dışı, WebClient exposure, delegation hataları veya NTLM-relayable SQL server'lar; ele geçirilmiş node'un Domain Admins, Domain Controllers, CA'ler veya SCCM site server'larına devam eden yolları varsa daha yüksek önceliği hak eder.
- Ayrıca `NTDS.dit` çıktınız ve bir hashcat potfile'ınız varsa, `--pwd` cracked password'ları BloodHound özellikleriyle ilişkilendirir; böylece normal password reuse ile privileged, Kerberoastable, AS-REP roastable veya path-relevant account'lara ait cracked creds'leri hızlıca ayırabilirsiniz.

### Privilege & logon-right collection

Windows **token privileges** (ör. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) DACL kontrollerini bypass edebilir. Bu nedenle bunların domain genelinde haritalanması, yalnızca ACL kullanan graph'ların kaçırdığı local LPE edge'lerini ortaya çıkarır. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` ve bunların `SeDeny*` karşılıkları), bir token henüz mevcut olmadan önce LSA tarafından uygulanır ve deny kuralları önceliklidir. Bu nedenle lateral movement'ı (RDP/SMB/scheduled task/service logon) doğrudan sınırlar.<sup>[[3]](#references)</sup>

Mümkün olduğunda **collector'ları elevated** çalıştırın: UAC, interactive admin'ler için (`NtFilterToken` aracılığıyla) filtered token oluşturur; hassas privilege'ları kaldırır ve admin SID'lerini deny-only olarak işaretler. Privilege'ları non-elevated bir shell'den enumerate ederseniz yüksek değerli privilege'lar görünmez olur ve BloodHound edge'leri ingest edemez.<sup>[[3]](#references)</sup>

Günümüzde birbirini tamamlayan iki SharpHound collection stratejisi vardır:<sup>[[3]](#references)</sup>

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. LDAP üzerinden (`(objectCategory=groupPolicyContainer)`) GPO'ları enumerate edin ve her bir `gPCFileSysPath` değerini okuyun.
2. SYSVOL'dan `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` dosyasını alın ve privilege/logon-right adlarını SID'lere eşleyen `[Privilege Rights]` bölümünü parse edin.
3. OU/site/domain üzerindeki `gPLink` aracılığıyla GPO link'lerini resolve edin, linked container'larda bulunan computer'ları listeleyin ve bu hakları ilgili machine'lere atfedin.
4. Avantajı: normal bir kullanıcıyla çalışır ve sessizdir; dezavantajı: yalnızca GPO üzerinden uygulanan hakları görür (local değişiklikler gözden kaçar).

- **LSA RPC enumeration (noisy, accurate):**
- Target üzerinde local admin olan bir context'ten Local Security Policy'yi açın ve atanmış principal'ları RPC üzerinden enumerate etmek için her privilege/logon right için `LsaEnumerateAccountsWithUserRight` çağırın.
- Avantajı: local olarak veya GPO dışında ayarlanmış hakları da yakalar; dezavantajı: gürültülü network trafiği oluşturur ve her host üzerinde admin yetkisi gerektirir.

**Bu edge'lerle ortaya çıkarılabilecek örnek abuse path:** `CanRDP` ➜ kullanıcınızın aynı zamanda `SeBackupPrivilege` sahibi olduğu host ➜ filtered token'lardan kaçınmak için elevated bir shell başlatın ➜ kısıtlayıcı DACL'lere rağmen `SAM` ve `SYSTEM` hive'larını okumak için backup semantics kullanın ➜ bunları exfiltrate edin ve local Administrator NT hash'ini lateral movement/privilege escalation için kurtarmak üzere `secretsdump.py`'yi offline çalıştırın.<sup>[[3]](#references)</sup>

### BloodHound ile Kerberoasting'e öncelik verme

Roasting işlemini hedefli tutmak için graph context kullanın:

1. ADWS-compatible bir collector ile bir kez collect edin ve offline çalışın:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIP'i import edin, ele geçirilmiş principal'ı owned olarak işaretleyin ve admin/infra haklarına sahip SPN account'larını ortaya çıkarmak için yerleşik query'leri (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) çalıştırın.
3. SPN'leri blast radius'a göre önceliklendirin; cracking işleminden önce `pwdLastSet`, `lastLogon` ve izin verilen encryption type'ları inceleyin.
4. Yalnızca seçilen ticket'ları request edin, offline crack edin, ardından yeni access ile BloodHound'u yeniden query edin:
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

[PingCastle](https://www.pingcastle.com/documentation/) Active Directory'nin **sağlık kontrolünü** gerçekleştirir ve risk puanlaması içeren bir HTML raporu oluşturur.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referanslar

- [1] [BloodHound Community Edition v8, OpenGraph ile Yayında: Active Directory ve Entra ID Ötesinde Identity Attack Paths](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [ACL'lerin Ötesinde: BloodHound ile Windows Privilege Escalation Paths Haritalama](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: BloodHound CE'de OpenGraph Attack Path Mapping](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}

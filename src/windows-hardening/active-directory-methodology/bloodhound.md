# BloodHound & Zana Nyingine za Active Directory Enumeration

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: Ukurasa huu unaweka pamoja baadhi ya utilities muhimu zaidi za **ku-enumerate** na **ku-visualise** mahusiano ya Active Directory. Kwa collection kupitia channel fiche ya **Active Directory Web Services (ADWS)**, angalia reference iliyo hapo juu.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) ni **AD viewer & editor** ya hali ya juu inayowezesha:

* Kuvinjari directory tree kupitia GUI
* Kuhariri object attributes & security descriptors
* Kuunda / kulinganisha snapshots kwa ajili ya offline analysis

### Matumizi ya haraka

1. Anzisha tool na uunganishe kwenye `dc01.corp.local` ukitumia domain credentials zozote.
2. Unda offline snapshot kupitia `File ➜ Create Snapshot`.
3. Linganisha snapshots mbili kwa `File ➜ Compare` ili kugundua permission drifts.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) hukusanya artefacts nyingi kutoka kwenye domain (ACLs, GPOs, trusts, CA templates …) na kutoa **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (taswira ya grafu)

[BloodHound](https://github.com/SpecterOps/BloodHound) hutumia nadharia ya grafu kufichua mahusiano yaliyofichika ya mamlaka ndani ya on-prem AD, Entra ID, na data yoyote ya ziada ya attack-surface unayoingiza kupitia OpenGraph.<sup>[[1]](#references)</sup>

### Usambazaji (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – lahaja ya native au PowerShell
* `RustHound-CE` – collector wa CE wa cross-platform kwa Linux, macOS, na Windows
* `NetExec --bloodhound` – collection ya haraka inayoendeshwa na LDAP kutoka Linux
* `AzureHound` – enumeration ya Entra ID
* **SoaPy + BOFHound** – collection ya ADWS (angalia link iliyo juu)

> BloodHound CE `v8+` ilibadilisha muundo wa output ya collector wakati OpenGraph ilipoanzishwa. Baada ya kufanya upgrade kutoka BloodHound ya legacy au installs za zamani za CE, endesha tena discovery kwa kutumia collectors za sasa kabla ya ku-import data.<sup>[[1]](#references)</sup>

#### Modi za kawaida za SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
The collectors hutengeneza JSON ambayo huingizwa kupitia GUI ya BloodHound.

#### SharpHound kutoka kwenye Windows host ambayo haijaunganishwa kwenye domain

Ikiwa operator VM yako haijaunganishwa kwenye target domain, elekeza DNS kwenye DC, anza shell ya **network-only**, thibitisha kwamba unaweza kuona `SYSVOL`/`NETLOGON` kwenye DC, kisha collect dhidi ya remote domain:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Hii ni muhimu kwa jump boxes za matumizi ya muda au operator workstations ambazo hazipaswi kujiunga na domain.

#### Ukusanyaji wa cross-platform kutoka Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` ni chaguo zuri la msingi unapohitaji output inayooana na CE kutoka kwenye host isiyo ya Windows.<sup>[[2]](#references)</sup> `NetExec` ni rahisi unapo tayari kuitumia kwa LDAP validation au spraying na unataka import ya haraka ya graph. Kwa datasets zisizo za AD, BloodHound OpenGraph inaweza kupanuliwa kwa collectors kama vile [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).<sup>[[1]](#references)</sup>

### ADPathFinder (kuweka kipaumbele kwa njia za OpenGraph)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) hufanya kazi juu ya BloodHound CE/OpenGraph wakati graph ni kubwa sana kuweza kufanya pivot kwa mkono. Badala ya kuuliza tu ikiwa principal mmoja anaweza kufikia target moja, huhesabu njia fupi zaidi kutoka kwa users na computers wengi wenye privileges ndogo hadi kwenye objects na groups zenye thamani kubwa, huweka pamoja paths zinazotumia edges zilezile, na kuonyesha choke point ya pamoja inayopaswa kurekebishwa kwanza.<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Data za `MSSQLHound` na `ConfigManBearPig` zikiwa zimeingizwa, finding moja inaweza kuunganisha [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md), na [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md) badala ya kuziacha kama leads tofauti.<sup>[[4]](#references)</sup> Mfano wa path iliyoshirikiwa:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Fuatilia **effective security context** katika kila edge. Path huwa muhimu kwa domain mara tu transition moja inapotekelezwa kama domain identity yenye privileges, hata kama ilianza kutoka kwa user wa kawaida.
- Findings zilizowekwa katika makundi zinafaa kwa **choke-point remediation**: kuondoa permission moja ya SQL impersonation, linked-server trust, certificate-template abuse path, au SCCM assignment kunaweza kuondoa shortest paths nyingi kwa wakati mmoja.
- Panga upya findings za "medium" kwa kutumia **graph context**. SMB signing ikiwa imezimwa, WebClient exposure, delegation mistakes, au NTLM-relayable SQL servers zinastahili kipaumbele cha juu zaidi wakati node iliyo-compromise ina onward paths kwenda kwa Domain Admins, Domain Controllers, CAs, au SCCM site servers.
- Ikiwa pia una output ya `NTDS.dit` na hashcat potfile, `--pwd` hu-correlate passwords zilizopasuliwa na properties za BloodHound, hivyo unaweza kutenganisha haraka password reuse ya kawaida na cracked creds zilizo kwenye privileged, Kerberoastable, AS-REP roastable, au path-relevant accounts.

### Ukusanyaji wa privilege na logon-right

Windows **token privileges** (k.m., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) zinaweza kupita ukaguzi wa DACL, hivyo kuzipanga katika domain nzima huonyesha local LPE edges ambazo graphs za ACL-only hazioni. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` na counterparts zao za `SeDeny*`) hutekelezwa na LSA kabla token haijapatikana, na denies hupewa kipaumbele, hivyo zinaathiri moja kwa moja lateral movement (RDP/SMB/scheduled task/service logon).<sup>[[3]](#references)</sup>

**Endesha collectors zikiwa elevated** inapowezekana: UAC huunda filtered token kwa interactive admins (kupitia `NtFilterToken`), huondoa sensitive privileges na kuweka admin SIDs kama deny-only. Ukienumerate privileges kutoka kwenye shell isiyo-elevated, privileges zenye thamani kubwa hazitaonekana na BloodHound haitazingiza edges hizo.<sup>[[3]](#references)</sup>

Mikakati miwili inayokamilishana ya SharpHound collection sasa ipo:<sup>[[3]](#references)</sup>

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Enumerate GPOs kupitia LDAP (`(objectCategory=groupPolicyContainer)`) na usome kila `gPCFileSysPath`.
2. Fetch `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` kutoka SYSVOL na parse sehemu ya `[Privilege Rights]` inayopanga majina ya privilege/logon-right kwa SIDs.
3. Resolve GPO links kupitia `gPLink` kwenye OUs/sites/domains, list computers zilizo kwenye linked containers, na atribue rights hizo kwa machines hizo.
4. Faida: inafanya kazi na user wa kawaida na ni quiet; hasara: inaona tu rights zinazosukumwa kupitia GPO (local tweaks hazionekani).

- **LSA RPC enumeration (noisy, accurate):**
- Kutoka kwenye context yenye local admin kwenye target, fungua Local Security Policy na uite `LsaEnumerateAccountsWithUserRight` kwa kila privilege/logon right ili ku-enumerate assigned principals kupitia RPC.
- Faida: inakusanya rights zilizowekwa locally au nje ya GPO; hasara: noisy network traffic na inahitaji admin kwenye kila host.

**Mfano wa abuse path unaoonyeshwa na edges hizi:** `CanRDP` ➜ host ambapo user wako pia ana `SeBackupPrivilege` ➜ anza elevated shell ili kuepuka filtered tokens ➜ tumia backup semantics kusoma `SAM` na `SYSTEM` hives licha ya restrictive DACLs ➜ exfiltrate na uendeshe `secretsdump.py` offline ili kurecover local Administrator NT hash kwa lateral movement/privilege escalation.<sup>[[3]](#references)</sup>

### Kuweka kipaumbele kwa Kerberoasting kwa BloodHound

Tumia graph context ili roasting ibaki targeted:

1. Collect mara moja kwa ADWS-compatible collector na ufanye kazi offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Import ZIP, weka compromised principal kama owned, na endesha built-in queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) ili kuonyesha SPN accounts zenye admin/infra rights.
3. Panga SPNs kwa blast radius; kagua `pwdLastSet`, `lastLogon`, na allowed encryption types kabla ya cracking.
4. Request selected tickets pekee, crack offline, kisha u-query BloodHound tena kwa access mpya:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) hu-enumerate **Group Policy Objects** na kuangazia misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) hufanya **ukaguzi wa afya** wa Active Directory na hutengeneza ripoti ya HTML yenye uwekaji alama wa hatari.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Marejeleo

- [1] [BloodHound Community Edition v8 yazinduliwa ikiwa na OpenGraph: Njia za mashambulizi ya utambulisho zaidi ya Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [Zaidi ya ACLs: Kuchora ramani ya njia za privilege escalation za Windows kwa kutumia BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: Kuchora ramani ya njia za mashambulizi ya OpenGraph katika BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}

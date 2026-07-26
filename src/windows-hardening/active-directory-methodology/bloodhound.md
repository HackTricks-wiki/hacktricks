# BloodHound na Zana Nyingine za Enumeration za Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> KUMBUKA: Ukurasa huu unaweka pamoja baadhi ya utilities muhimu zaidi za **enumerate** na **visualise** mahusiano ya Active Directory. Kwa ajili ya collection kupitia channel ya **Active Directory Web Services (ADWS)** yenye stealthy, angalia reference iliyo hapo juu.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) ni **AD viewer & editor** ya hali ya juu inayowezesha:

* Kuvinjari directory tree kupitia GUI
* Kuhariri object attributes na security descriptors
* Kuunda / kulinganisha snapshots kwa ajili ya offline analysis

### Matumizi ya haraka

1. Anzisha tool na u-connect kwenye `dc01.corp.local` ukitumia credentials zozote za domain.
2. Unda offline snapshot kupitia `File ➜ Create Snapshot`.
3. Linganisha snapshots mbili kwa `File ➜ Compare` ili kugundua permission drifts.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) hutoa seti kubwa ya artefacts kutoka kwenye domain (ACLs, GPOs, trusts, CA templates …) na kutengeneza **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (graph visualisation)

[BloodHound](https://github.com/SpecterOps/BloodHound) hutumia nadharia ya graphu kufichua mahusiano yaliyofichika ya privileges ndani ya on-prem AD, Entra ID, na data yoyote ya ziada ya attack surface unayoingiza kupitia OpenGraph.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Wakusanyaji

* `SharpHound.exe` / `Invoke-BloodHound` – variant ya native au PowerShell
* `RustHound-CE` – collector ya CE ya cross-platform kwa Linux, macOS, na Windows
* `NetExec --bloodhound` – collection ya haraka inayoendeshwa na LDAP kutoka Linux
* `AzureHound` – enumeration ya Entra ID
* **SoaPy + BOFHound** – collection ya ADWS (tazama link iliyo juu)

> BloodHound CE `v8+` ilibadilisha format ya output ya collector wakati OpenGraph ilipoletwa. Baada ya kufanya upgrade kutoka BloodHound ya zamani au installs za CE za awali, endesha tena discovery kwa kutumia collectors za sasa kabla ya ku-import data.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Collectors hutengeneza JSON ambayo huingizwa kupitia BloodHound GUI.

#### SharpHound kutoka kwenye Windows host ambayo haijaunganishwa kwenye domain

Ikiwa operator VM yako haijaunganishwa kwenye target domain, elekeza DNS kwenye DC, anza shell ya **network-only**, thibitisha kuwa unaweza kuona `SYSVOL`/`NETLOGON` kwenye DC, kisha kusanya taarifa kutoka kwenye remote domain:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Hii ni muhimu kwa jump boxes zinazoweza kutupwa au vituo vya kazi vya waendeshaji ambavyo havipaswi kuunganishwa kwenye domain.

#### Ukusanyaji wa cross-platform kutoka Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` ni chaguo zuri la msingi unapohitaji output inayooana na CE kutoka kwa host isiyo ya Windows. `NetExec` ni rahisi unapo tayari kuitumia kwa LDAP validation au spraying na unataka graph import ya haraka. Kwa datasets zisizo za AD, BloodHound OpenGraph inaweza kupanuliwa kwa collectors kama vile [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### ADPathFinder (kipaumbele cha njia za OpenGraph)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) hutumia BloodHound CE/OpenGraph pale graph inapokuwa kubwa sana kuifanyia pivot kwa mikono. Badala ya kuuliza tu ikiwa principal mmoja anaweza kufikia target moja, huhesabu shortest paths kutoka kwa users na computers wengi wenye privileges ndogo hadi kwenye objects zenye thamani kubwa, hupanga pamoja paths zinazotumia edges zilezile, na kuonyesha choke point inayoshirikiwa ambayo inapaswa kurekebishwa kwanza.
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
With `MSSQLHound` na `ConfigManBearPig` data iliyoingizwa, finding moja inaweza kuvuka [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md), na [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md) badala ya kuziacha kama leads tofauti. Mfano wa njia iliyoshirikiwa:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Fuatilia **effective security context** kwenye kila kiungo. Njia huwa muhimu kwa domain mara tu transition moja inapotekelezwa kama domain identity yenye privileges, hata ikiwa ilianza kutoka kwa user wa kawaida.
- Findings zilizopangwa kwa makundi zinafaa kwa **choke-point remediation**: kuondoa ruhusa moja ya SQL impersonation, linked-server trust, certificate-template abuse path, au SCCM assignment kunaweza kuangusha shortest paths nyingi kwa wakati mmoja.
- Panga upya findings za "medium" kwa kutumia **graph context**. SMB signing ikiwa imezimwa, WebClient exposure, makosa ya delegation, au SQL servers zinazoweza kuathiriwa na NTLM relay zinastahili kipaumbele cha juu zaidi wakati node iliyoathiriwa ina onward paths kwenda kwa Domain Admins, Domain Controllers, CAs, au SCCM site servers.
- Ikiwa pia una output ya `NTDS.dit` na hashcat potfile, `--pwd` inahusianisha passwords zilizocrackiwa na BloodHound properties ili uweze kutenganisha haraka password reuse ya kawaida na creds zilizocrackiwa za accounts zenye privileges, Kerberoastable, AS-REP roastable, au zinazohusiana na paths.

### Ukusanyaji wa Privilege & logon-right

Windows **token privileges** (k.m., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) zinaweza kupita ukaguzi wa DACL, hivyo kuzimap domain-wide hufichua local LPE edges ambazo graphs za ACL-only hukosa. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` na counterparts zake za `SeDeny*`) hutekelezwa na LSA kabla token haijakuwepo, na denies hupewa kipaumbele, hivyo hudhibiti kwa kiasi kikubwa lateral movement (RDP/SMB/scheduled task/service logon).

**Endesha collectors zikiwa elevated** inapowezekana: UAC huunda filtered token kwa interactive admins (kupitia `NtFilterToken`), ikiondoa sensitive privileges na kuweka admin SIDs kama deny-only. Ukienumerate privileges kutoka kwenye shell isiyo-elevated, privileges zenye thamani kubwa hazitaonekana na BloodHound haitameza edges hizo.

Mikakati miwili inayokamilishana ya SharpHound collection sasa ipo:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Enumerate GPOs kupitia LDAP (`(objectCategory=groupPolicyContainer)`) na usome kila `gPCFileSysPath`.
2. Pata `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` kutoka SYSVOL na parse sehemu ya `[Privilege Rights]` inayomap privilege/logon-right names kwenda kwenye SIDs.
3. Resolve GPO links kupitia `gPLink` kwenye OUs/sites/domains, orodhesha computers zilizo kwenye linked containers, kisha attribution rights hizo kwa machines hizo.
4. Faida: inafanya kazi kwa user wa kawaida na ni quiet; hasara: inaona tu rights zinazosukumwa kupitia GPO (local tweaks hazionekani).

- **LSA RPC enumeration (noisy, accurate):**
- Kutoka kwenye context yenye local admin kwenye target, fungua Local Security Policy na uite `LsaEnumerateAccountsWithUserRight` kwa kila privilege/logon right ili kuenumerate principals waliopewa rights kupitia RPC.
- Faida: inakamata rights zilizowekwa locally au nje ya GPO; hasara: noisy network traffic na inahitaji admin kwenye kila host.

**Example abuse path inayofichuliwa na edges hizi:** `CanRDP` ➜ host ambapo user wako pia ana `SeBackupPrivilege` ➜ anzisha elevated shell ili kuepuka filtered tokens ➜ tumia backup semantics kusoma `SAM` na `SYSTEM` hives licha ya restrictive DACLs ➜ exfiltrate na uendeshe `secretsdump.py` offline ili kurecover local Administrator NT hash kwa lateral movement/privilege escalation.

### Kuweka kipaumbele kwa Kerberoasting na BloodHound

Tumia graph context ili kuifanya roasting iwe targeted:

1. Fanya collection mara moja kwa ADWS-compatible collector na ufanye kazi offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Import ZIP, weka compromised principal kama owned, kisha endesha built-in queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) ili kufichua SPN accounts zenye admin/infra rights.
3. Panga SPNs kwa blast radius; kagua `pwdLastSet`, `lastLogon`, na allowed encryption types kabla ya cracking.
4. Request selected tickets pekee, crack offline, kisha u-run BloodHound query tena ukiwa na access mpya:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) hu-enumerate **Group Policy Objects** na kuonyesha misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) hufanya **ukaguzi wa afya** wa Active Directory na hutengeneza ripoti ya HTML yenye tathmini ya hatari.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Marejeleo

- [BloodHound Community Edition v8 Yazinduliwa ikiwa na OpenGraph: Njia za Mashambulizi ya Utambulisho Zaidi ya Active Directory na Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Zaidi ya ACLs: Kuchora Njia za Windows za Privilege Escalation kwa kutumia BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [ADPathFinder: OpenGraph Attack Path Mapping katika BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}

# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: Ukurasa huu unagawanya baadhi ya zana zenye manufaa zaidi za **enumerate** na kuonyesha kwa macho mahusiano ya Active Directory. Kwa ukusanyaji kupitia njia fiche ya **Active Directory Web Services (ADWS)** angalia rejea hapo juu.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) ni **AD viewer & editor** ya hali ya juu inayoruhusu:

* Kupekua mti wa saraka kupitia GUI
* Kuhariri sifa za vitu & security descriptors
* Kuunda snapshot / kulinganisha kwa uchambuzi wa offline

### Matumizi ya haraka

1. Anzisha zana na uungane na `dc01.corp.local` ukitumia credentials zozote za domain.
2. Unda offline snapshot kupitia `File ➜ Create Snapshot`.
3. Linganisha snapshots mbili kwa `File ➜ Compare` ili kuona permission drifts.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) hutoa seti kubwa ya artefacts kutoka kwenye domain (ACLs, GPOs, trusts, CA templates …) na hutengeneza **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (graph visualisation)

[BloodHound](https://github.com/SpecterOps/BloodHound) hutumia graph theory kufichua hidden privilege relationships ndani ya on-prem AD, Entra ID, na data yoyote ya extra attack-surface unayoingiza kupitia OpenGraph.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Watozaji

* `SharpHound.exe` / `Invoke-BloodHound` – toleo la asili au la PowerShell
* `RustHound-CE` – mtozaji wa CE wa majukwaa mtambuka kwa Linux, macOS, na Windows
* `NetExec --bloodhound` – ukusanyaji wa haraka unaoendeshwa na LDAP kutoka Linux
* `AzureHound` – uorodheshaji wa Entra ID
* **SoaPy + BOFHound** – ukusanyaji wa ADWS (angalia link juu)

> BloodHound CE `v8+` ilibadilisha fomati ya matokeo ya mtozaji wakati OpenGraph ilipoanzishwa. Baada ya kuboresha kutoka BloodHound ya zamani au usakinishaji wa CE wa zamani zaidi, endesha tena discovery kwa kutumia watozaji wa sasa kabla ya kuingiza data.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Wakusanyaji huzalisha JSON ambayo huingizwa kupitia BloodHound GUI.

#### SharpHound kutoka Windows host isiyounganishwa kwenye domain

Ikiwa operator VM yako haijaunganishwa kwenye target domain, elekeza DNS kwenda kwa DC, anzisha shell ya **network-only**, thibitisha unaweza kuona `SYSVOL`/`NETLOGON` kwenye DC, kisha kusanya dhidi ya remote domain:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Hii ni muhimu kwa disposable jump boxes au operator workstations ambazo hazipaswi kuwa domain-joined.

#### Cross-platform collection from Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` ni default nzuri unapohitaji output inayooana na CE kutoka host isiyo ya Windows. `NetExec` ni rahisi unapokuwa tayari unaitumia kwa LDAP validation au spraying na unataka graph import ya haraka. Kwa datasets zisizo za AD, BloodHound OpenGraph inaweza kupanuliwa kwa collectors kama [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### Ukusanyaji wa privilege & logon-right

Windows **token privileges** (mf. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) zinaweza bypass DACL checks, hivyo kuzi-map domain-wide hufichua local LPE edges ambazo ACL-only graphs hukosa. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` na `SeDeny*` counterparts zake) zinatekelezwa na LSA kabla token haijakuwepo, na denies huwa na kipaumbele, hivyo kwa kweli huzuia lateral movement (RDP/SMB/scheduled task/service logon).

**Endesha collectors elevated** inapowezekana: UAC huunda filtered token kwa interactive admins (kupitia `NtFilterToken`), huondoa sensitive privileges na kuweka admin SIDs kama deny-only. Ukienumerate privileges kutoka non-elevated shell, high-value privileges hazitaonekana na BloodHound haitameza edges.

Sasa kuna mikakati miwili ya complementary ya SharpHound collection:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Enumerate GPOs kupitia LDAP (`(objectCategory=groupPolicyContainer)`) na soma kila `gPCFileSysPath`.
2. Fetch `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` kutoka SYSVOL na parse sehemu ya `[Privilege Rights]` inayomapa majina ya privilege/logon-right kwa SIDs.
3. Resolve GPO links kupitia `gPLink` kwenye OUs/sites/domains, orodhesha computers ndani ya linked containers, na atribyuti rights hizo kwa mashine hizo.
4. Faida: hufanya kazi kwa normal user na ni kimya; hasara: huona tu rights zilizosukumwa kupitia GPO (local tweaks hukosa).

- **LSA RPC enumeration (noisy, accurate):**
- Kutoka context yenye local admin kwenye target, fungua Local Security Policy na piga `LsaEnumerateAccountsWithUserRight` kwa kila privilege/logon right ili enumerate assigned principals kupitia RPC.
- Faida: hukamata rights zilizowekwa locally au nje ya GPO; hasara: noisy network traffic na hitaji la admin kwenye kila host.

**Mfano wa abuse path unaoonekana kupitia edges hizi:** `CanRDP` ➜ host ambapo user wako pia ana `SeBackupPrivilege` ➜ anza elevated shell ili kuepuka filtered tokens ➜ tumia backup semantics kusoma `SAM` na `SYSTEM` hives licha ya restrictive DACLs ➜ exfiltrate na endesha `secretsdump.py` offline ili kupata local Administrator NT hash kwa lateral movement/privilege escalation.

### Kuweka kipaumbele Kerberoasting kwa BloodHound

Tumia graph context ili roasting ibaki targeted:

1. Collect mara moja kwa ADWS-compatible collector na fanya kazi offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Import ZIP, weka compromised principal kama owned, na endesha built-in queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) ili kutoa SPN accounts zenye admin/infra rights.
3. Weka kipaumbele SPNs kwa blast radius; kagua `pwdLastSet`, `lastLogon`, na allowed encryption types kabla ya cracking.
4. Omba tickets zilizochaguliwa tu, crack offline, kisha re-query BloodHound na access mpya:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) hutambua **Group Policy Objects** na kuonyesha misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) hufanya **health-check** ya Active Directory na huzalisha ripoti ya HTML yenye risk scoring.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Marejeo

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}

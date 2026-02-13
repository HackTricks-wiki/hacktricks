# BloodHound & Zana Nyingine za Active Directory Enumeration

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> KUMBUKUMBU: Ukurasa huu unaorodhesha baadhi ya zana muhimu zaidi za **enumerate** na **visualise** mahusiano ya Active Directory. Kwa ukusanyaji kupitia njia ya kimyakimya ya **Active Directory Web Services (ADWS)** angalia rejea hapo juu.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) ni **AD viewer & editor** ya kiwango cha juu inayoruhusu:

* Kupeleleza mti wa directory kwa GUI
* Kuhariri sifa za vitu & maelezo ya usalama
* Uundaji wa snapshot / kulinganisha kwa uchambuzi usio mtandaoni

### Matumizi ya haraka

1. Anzisha zana na uunganishe kwenye `dc01.corp.local` kwa kutumia vyeti vyovyote vya domain.
2. Tengeneza snapshot isiyo mtandaoni kupitia `File ➜ Create Snapshot`.
3. Linganisha snapshot mbili na `File ➜ Compare` ili kubaini mabadiliko ya ruhusa.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) huvuta seti kubwa ya vitu vinavyokusanywa kutoka kwa domain (ACLs, GPOs, trusts, CA templates …) na hutengeneza **ripoti ya Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (uonyeshaji wa grafu)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) inatumia nadharia ya grafu + Neo4j kufunua mahusiano ya ruhusa yaliyofichika ndani ya on-prem AD & Azure AD.

### Usanidi (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Wakusanyaji

* `SharpHound.exe` / `Invoke-BloodHound` – toleo la asili au la PowerShell
* `AzureHound` – uchunguzi wa Azure AD
* **SoaPy + BOFHound** – ukusanyaji wa ADWS (see link at top)

#### Hali za kawaida za SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Wakusanyaji wanazalisha JSON ambayo huingizwa kupitia BloodHound GUI.

### Ukusanyaji wa ruhusa na haki za kuingia

Windows **token privileges** (mfano, `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) zinaweza kuepuka ukaguzi wa DACL, hivyo kuziweka ramani katika domain nzima kunaonyesha edges za LPE za eneo ambazo grafu zinazotegemea ACL pekee haziona. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` na wenzao wa `SeDeny*`) zinatimizwa na LSA kabla token hata kuwepo, na marufuku zinaipa kipaumbele, hivyo zinazuia kwa kiasi kusogea upande (RDP/SMB/scheduled task/service logon).

Endesha wakusanyaji kwa hali ya elevated unapoweza: UAC huunda filtered token kwa interactive admins (kupitia `NtFilterToken`), ikitoa privileges nyeti na kuonyesha admin SIDs kama deny-only. Ikiwa utaorodhesha privileges kutoka kwa shell isiyo elevated, privileges zenye thamani kubwa zitakuwa hazionekani na BloodHound haitenga edges hizo.

Sasa kuna mikakati miwili ya kukusanya kwa SharpHound inayokamiliana:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Orodhesha GPOs kupitia LDAP (`(objectCategory=groupPolicyContainer)`) na soma kila `gPCFileSysPath`.
2. Pata `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` kutoka SYSVOL na changanua sehemu ya `[Privilege Rights]` ambayo inaonyesha majina ya privilege/logon-right kwa SIDs.
3. Tatua viungo vya GPO kupitia `gPLink` kwenye OUs/sites/domains, orodhesha kompyuta katika containers zilizounganishwa, na atribua haki hizo kwa mashine hizo.
4. Faida: hufanya kazi na mtumiaji wa kawaida na ni kimya; hasara: inaona haki zilizopelekwa kupitia GPO tu (marekebisho ya ndani hayatafahamika).

- **LSA RPC enumeration (noisy, accurate):**
- Kutoka kwa muktadha ulio na local admin kwenye lengo, fungua Local Security Policy na itumie `LsaEnumerateAccountsWithUserRight` kwa kila privilege/logon right ili kuorodhesha principals waliopewa kwa RPC.
- Faida: inakamata haki zilizowekwa kwa ndani au nje ya GPO; hasara: trafiki ya mtandao ni noisy na inahitaji admin kwenye kila host.

Mfano wa njia ya matumizi mabaya inayochipuka kutokana na edges hizi: `CanRDP` ➜ host ambapo mtumiaji wako pia ana `SeBackupPrivilege` ➜ anzisha shell iliyoinuliwa ili kuepuka filtered tokens ➜ tumia semantics za backup kusoma SAM na SYSTEM hives licha ya DACL kali ➜ toza nje na endesha `secretsdump.py` offline ili kupata NT hash ya Administrator ya eneo kwa ajili ya kusogea upande/kuongezeka kwa ruhusa.

### Kuweka kipaumbele Kerberoasting kwa kutumia BloodHound

Tumia muktadha wa grafu ili kuendelea kuchoma kwa kulenga:

1. Kukusanya mara moja kwa collector inayotegemea ADWS na fanya kazi offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Ingiza ZIP, alama principal iliyodukuliwa kama owned, na endesha queries zilizojengwa (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) ili kuibua akaunti za SPN zenye haki za admin/infra.
3. Weka kipaumbele SPNs kwa blast radius; angalia `pwdLastSet`, `lastLogon`, na allowed encryption types kabla ya kuvunja.
4. Ombia tiketi zilizochaguliwa tu, vunja offline, kisha ulizia BloodHound tena na access mpya:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) inatafutiza **Group Policy Objects** na inaonyesha misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) hufanya ukaguzi wa afya wa Active Directory na inazalisha ripoti ya HTML yenye ukadiriaji wa hatari.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Marejeo

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}

# BloodHound & Ander Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> LET WEL: Hierdie blad groepeer sommige van die nuttigste hulpmiddels om **enumerate** en **visualise** Active Directory verhoudings. Vir versameling oor die stealthy **Active Directory Web Services (ADWS)** kanaal, kyk die verwysing hierbo.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) is 'n gevorderde **AD viewer & editor** wat toelaat:

* GUI-blaai deur die gidsboom
* Wysig van objekattribuutte & security descriptors
* Skep en vergelyk snapshots vir offline-analise

### Kort gebruik

1. Begin die hulpmiddel en verbind met `dc01.corp.local` met enige domeinbewyse.
2. Skep 'n offline snapshot via `File ➜ Create Snapshot`.
3. Vergelyk twee snapshots met `File ➜ Compare` om veranderinge in toestemmings op te spoor.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) onttrek 'n groot stel artefakte uit 'n domein (ACLs, GPOs, trusts, CA templates …) en lewer 'n **Excel-verslag**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (grafiekvisualisering)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) gebruik grafteorie + Neo4j om verborge privilege relationships binne on-prem AD & Azure AD te onthul.

### Ontplooiing (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Versamelaars

* `SharpHound.exe` / `Invoke-BloodHound` – inheemse of PowerShell-weergawe
* `AzureHound` – Azure AD enumeration
* **SoaPy + BOFHound** – ADWS collection (sien skakel bo)

#### Algemene SharpHound-modusse
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Die versamelaars genereer JSON wat deur die BloodHound GUI ingelees word.

### Privilegie- en aanmeldregversameling

Windows **token privileges** (bv. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) kan DACL-kontroles omseil, so om dit domeinwyd in kaart te bring ontbloot plaaslike LPE-rande wat slegs-ACL-grafieke mis. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` en hul `SeDeny*` eweknieë) word deur LSA afgedwing voordat ’n token selfs bestaan, en weierings het prioriteit, so dit beheer materiaal laterale beweging (RDP/SMB/geskeduleerde taak/service aanmelding).

**Run collectors elevated** waar moontlik: UAC skep ’n gefilterde token vir interaktiewe admins (via `NtFilterToken`), verwyder sensitiewe privileges en merk admin SIDs as deny-only. As jy privileges uit ’n nie-geëlevateerde shell enumereer, sal hoë-waarde privileges onsigbaar wees en BloodHound sal nie die rande inlees nie.

Twee aanvullend-ontwerpte SharpHound-versamelingsstrategieë bestaan nou:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Enumereer GPOs oor LDAP (`(objectCategory=groupPolicyContainer)`) en lees elke `gPCFileSysPath`.
2. Haal `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` vanaf SYSVOL en parse die `[Privilege Rights]` afdeling wat privilegie-/aanmeld-regname na SIDs map.
3. Los GPO-links op via `gPLink` op OUs/sites/domains, lys rekenaars in die gekoppelde houers, en ken die regte aan daardie masjiene toe.
4. Voordeel: werk met ’n normale gebruiker en is stil; nadeel: sien slegs regte wat via GPO gedruk is (lokale aanpassings word gemis).

- **LSA RPC enumeration (noisy, accurate):**
- Vanuit ’n konteks met local admin op die teiken, open die Local Security Policy en roep `LsaEnumerateAccountsWithUserRight` vir elke privilege/aanmeldreg om toegewezen prinsipale oor RPC te enumereer.
- Voordeel: vang regte wat plaaslik of buite GPO gestel is; nadeel: lawaaierige netwerkverkeer en adminvereiste op elke gasheer.

**Voorbeeld misbruikpad wat deur hierdie rande ontbloot word:** `CanRDP` ➜ gasheer waar jou gebruiker ook `SeBackupPrivilege` het ➜ begin ’n geëlevateerde shell om gefilterde tokens te vermy ➜ gebruik backup-semantiek om `SAM` en `SYSTEM` hives te lees ondanks beperkende DACLs ➜ exfiltreer en hardloop `secretsdump.py` offline om die plaaslike Administrator NT-hash te herstel vir laterale beweging/privilege-escalasie.

### Prioritiseer Kerberoasting met BloodHound

Gebruik graf-konteks om roasting geteikend te hou:

1. Versamel een keer met ’n ADWS-compatible collector en werk offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Import die ZIP, merk die gekompromitteerde principal as owned, en hardloop ingeboude queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) om SPN-rekeninge met admin/infra-regte te identifiseer.
3. Prioritiseer SPNs volgens blast radius; hersien `pwdLastSet`, `lastLogon`, en toegelate enkripsietipes voordat jy kraak.
4. Versoek slegs geselekteerde tickets, kraak offline, en her-voer navraag in BloodHound met die nuwe toegang:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumereer **Group Policy Objects** en beklemtoon miskonfigurasies.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) voer 'n **gesondheidskontrole** van Active Directory uit en genereer 'n HTML-verslag met risikobepaling.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Verwysings

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}

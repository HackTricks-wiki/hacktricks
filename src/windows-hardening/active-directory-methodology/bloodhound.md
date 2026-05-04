# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: Ova stranica grupiše neke od najkorisnijih alata za **enumerate** i **visualise** Active Directory odnosa.  Za prikupljanje preko stealthy **Active Directory Web Services (ADWS)** kanala pogledajte referencu iznad.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) je napredni **AD viewer & editor** koji omogućava:

* GUI pregled stabla direktorijuma
* Uređivanje atributa objekata & security descriptors
* Kreiranje/uspoređivanje snapshot-ova za offline analizu

### Quick usage

1. Pokrenite alat i povežite se na `dc01.corp.local` sa bilo kojim domain credentials.
2. Kreirajte offline snapshot preko `File ➜ Create Snapshot`.
3. Usporedite dva snapshot-a sa `File ➜ Compare` da biste uočili permission drifts.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) izvlači veliki skup artefakata iz domena (ACLs, GPOs, trusts, CA templates …) i generiše **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (grafička vizualizacija)

[BloodHound](https://github.com/SpecterOps/BloodHound) koristi teoriju grafova da otkrije skrivene odnose privilegija unutar on-prem AD, Entra ID, i bilo koje dodatne attack-surface podatke koje ubacite kroz OpenGraph.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – native ili PowerShell varijanta
* `RustHound-CE` – cross-platform CE collector za Linux, macOS, i Windows
* `NetExec --bloodhound` – brza LDAP-driven kolekcija sa Linuxa
* `AzureHound` – Entra ID enumeracija
* **SoaPy + BOFHound** – ADWS kolekcija (vidi link na vrhu)

> BloodHound CE `v8+` je promenio format izlaza collectora kada je stigao OpenGraph. Nakon nadogradnje sa legacy BloodHound ili starijih CE instalacija, ponovo pokreni discovery sa trenutnim collectorima pre importa podataka.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Kolektori generišu JSON koji se učitava preko BloodHound GUI.

#### SharpHound sa Windows hosta koji nije pridružen domenu

Ako vaša operator VM nije pridružena ciljnom domenu, podesite DNS na DC, pokrenite **network-only** shell, proverite da li možete da vidite `SYSVOL`/`NETLOGON` na DC, i zatim prikupite podatke protiv udaljenog domena:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Ovo je korisno za disposable jump boxes ili operator workstations koji ne bi trebalo da budu domain-joined.

#### Cross-platform collection from Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` je dobar default kada želiš CE-compatible output sa non-Windows hosta. `NetExec` je praktičan kada ga već koristiš za LDAP validation ili spraying i želiš brz graph import. Za non-AD datasets, BloodHound OpenGraph može da se proširi collector-ima kao što je [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### Prikupljanje privilege & logon-right

Windows **token privileges** (npr. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) mogu da zaobiđu DACL checks, pa njihovo mapiranje širom domena otkriva local LPE edges koje ACL-only grafovi propuštaju. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` i njihovi `SeDeny*` ekvivalenti) enforced su od strane LSA pre nego što token uopšte postoji, a deny pravila imaju prioritet, pa stvarno ograničavaju lateral movement (RDP/SMB/scheduled task/service logon).

**Pokreći collectore elevated** kada je moguće: UAC kreira filtered token za interactive admin-e (preko `NtFilterToken`), uklanjajući sensitive privileges i obeležavajući admin SIDs kao deny-only. Ako radiš enumerate privileges iz non-elevated shell-a, high-value privileges neće biti vidljivi i BloodHound neće ingestovati edges.

Sada postoje dve komplementarne SharpHound strategije prikupljanja:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Enumeriši GPO-e preko LDAP-a (`(objectCategory=groupPolicyContainer)`) i pročitaj svaki `gPCFileSysPath`.
2. Preuzmi `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` iz SYSVOL i parsiraj `[Privilege Rights]` sekciju koja mapira privilege/logon-right nazive na SIDs.
3. Resolve GPO links preko `gPLink` na OUs/sites/domains, izlistaj računare u povezanim container-ima i pripiši rights tim mašinama.
4. Prednost: radi sa normalnim user-om i tiho je; mana: vidi samo rights koje je gurnuo GPO (local tweaks se propuštaju).

- **LSA RPC enumeration (noisy, accurate):**
- Iz konteksta sa local admin pravima na targetu, otvori Local Security Policy i pozovi `LsaEnumerateAccountsWithUserRight` za svaki privilege/logon right da bi preko RPC-a enumerisao dodeljene principals.
- Prednost: hvata rights podešene lokalno ili van GPO-a; mana: bučan network traffic i admin requirement na svakom hostu.

**Primer abuse path-a koji otkrivaju ovi edges:** `CanRDP` ➜ host gde tvoj user takođe ima `SeBackupPrivilege` ➜ pokreni elevated shell da izbegneš filtered tokens ➜ koristi backup semantics da pročitaš `SAM` i `SYSTEM` hives uprkos restrictive DACLs ➜ exfiltrate i pokreni `secretsdump.py` offline da povratiš lokalni Administrator NT hash za lateral movement/privilege escalation.

### Prioritising Kerberoasting sa BloodHound

Koristi graph context da roasting ostane targetiran:

1. Prikupi jednom sa ADWS-compatible collector-om i radi offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importuj ZIP, označi kompromitovani principal kao owned, i pokreni built-in queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) da izdvojiš SPN naloge sa admin/infra pravima.
3. Prioritizuj SPN-ove po blast radius-u; proveri `pwdLastSet`, `lastLogon`, i dozvoljene encryption types pre cracking-a.
4. Zatraži samo izabrane tikete, crackuj offline, pa ponovo query-uj BloodHound sa novim access-om:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumeriše **Group Policy Objects** i ističe misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) obavlja **health-check** Active Directory i generiše HTML izveštaj sa ocenjivanjem rizika.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Reference

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}

# BloodHound i drugi Active Directory Enumeration alati

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NAPOMENA: Ova stranica grupiše neke od najkorisnijih utilitija za **enumerate** i **vizualizaciju** Active Directory odnosa. Za prikupljanje preko stealthy kanala **Active Directory Web Services (ADWS)** pogledajte referencu iznad.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) je napredni **AD viewer & editor** koji omogućava:

* GUI pregled stabla direktorijuma
* Uređivanje atributa objekata i bezbednosnih deskriptora
* Kreiranje snapshot-a / poređenje za offline analizu

### Brza upotreba

1. Pokrenite alat i povežite se na `dc01.corp.local` koristeći bilo koje podatke za prijavu domena.
2. Kreirajte offline snapshot putem `File ➜ Create Snapshot`.
3. Uporedite dva snapshot-a sa `File ➜ Compare` da biste uočili promene u privilegijama.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) izvlači veliki skup artefakata iz domena (ACLs, GPOs, trusts, CA templates …) i proizvodi **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (vizualizacija grafa)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) koristi teoriju grafova + Neo4j da otkrije skrivene odnose privilegija u on-prem AD & Azure AD.

### Raspoređivanje (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Sakupljači

* `SharpHound.exe` / `Invoke-BloodHound` – nativna ili PowerShell varijanta
* `AzureHound` – Azure AD enumeracija
* **SoaPy + BOFHound** – prikupljanje iz ADWS (pogledaj link na vrhu)

#### Uobičajeni režimi SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
The collectors generate JSON which is ingested via the BloodHound GUI.

### Privilege & logon-right collection

Windows **token privileges** (e.g., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) mogu zaobići DACL provere, tako da njihovo mapiranje po domenu otkriva lokalne LPE veze koje grafovi koji se oslanjaju samo na ACL-ove propuštaju. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` and their `SeDeny*` counterparts) sprovodi LSA pre nego što token uopšte postoji, i deny pravila imaju prioritet, pa značajno ograničavaju lateralni pokret (RDP/SMB/scheduled task/service logon).

**Pokrećite collectore elevated** kad je moguće: UAC kreira filtered token za interaktivne admine (preko `NtFilterToken`), skida osetljive privilegije i označava admin SIDs kao deny-only. Ako enumerišete privilegije iz non-elevated shel-a, visokovredne privilegije će biti nevidljive i BloodHound neće ingest-ovati veze.

Postoje dve komplementarne SharpHound strategije prikupljanja:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Enumerišite GPOs preko LDAP-a (`(objectCategory=groupPolicyContainer)`) i pročitajte svaki `gPCFileSysPath`.
2. Preuzmite `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` iz SYSVOL i parsirajte sekciju `[Privilege Rights]` koja mapira imena privilegija/logon-rights na SIDs.
3. Rešavajte GPO linkove preko `gPLink` na OU-ovima/sites/domains, navedite računare u povezanим kontejnerima i atribuirajte prava tim mašinama.
4. Prednost: radi sa normalnim korisnikom i neupadljiv je; mana: vidi samo prava koja su primenjena putem GPO (lokalne izmene se propuštaju).

- **LSA RPC enumeration (noisy, accurate):**
- Iz konteksta sa lokalnim adminom na cilju, otvorite Local Security Policy i pozovite `LsaEnumerateAccountsWithUserRight` za svaku privilegiju/logon right da enumerišete dodeljene principe preko RPC-a.
- Prednost: hvata prava postavljena lokalno ili van GPO; mana: bučan mrežni saobraćaj i potreban admin na svakom hostu.

**Example abuse path surfaced by these edges:** `CanRDP` ➜ host where your user also has `SeBackupPrivilege` ➜ start an elevated shell to avoid filtered tokens ➜ use backup semantics to read `SAM` and `SYSTEM` hives despite restrictive DACLs ➜ exfiltrate and run `secretsdump.py` offline to recover the local Administrator NT hash for lateral movement/privilege escalation.

### Prioritising Kerberoasting with BloodHound

Use graph context to keep roasting targeted:

1. Collect once with an ADWS-compatible collector and work offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Import the ZIP, mark the compromised principal as owned, and run built-in queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) to surface SPN accounts with admin/infra rights.
3. Prioritise SPNs by blast radius; review `pwdLastSet`, `lastLogon`, and allowed encryption types before cracking.
4. Request only selected tickets, crack offline, then re-query BloodHound with the new access:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumerates **Group Policy Objects** and highlights misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) obavlja **health-check** Active Directory-a i generiše HTML izveštaj sa ocenom rizika.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Reference

- [HackTheBox Mirage: Lančovanje NFS Leaks, zloupotreba Dynamic DNS-a, NATS Credential Theft, JetStream Secrets i Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Iza ACLs: mapiranje putanja za Privilege Escalation na Windows uz pomoć BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}

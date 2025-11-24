# BloodHound & Ostali alati za enumeraciju Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NAPOMENA: Ova stranica grupiše neke od najkorisnijih utiliteta za **enumeraciju** i **vizualizaciju** odnosa u Active Directory. Za prikupljanje preko prikrivenog kanala Active Directory Web Services (ADWS) pogledajte referencu iznad.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) je napredni **AD preglednik i uređivač** koji omogućava:

* GUI pregled stabla direktorijuma
* Uređivanje atributa objekata i security descriptors
* Kreiranje snapshot-a / poređenje za offline analizu

### Brza upotreba

1. Pokrenite alat i povežite se na `dc01.corp.local` pomoću bilo kojih akreditiva domena.
2. Kreirajte offline snapshot preko `File ➜ Create Snapshot`.
3. Uporedite dva snapshota preko `File ➜ Compare` da biste uočili promene u dozvolama.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) izdvaja veliki skup artefakata iz domena (ACLs, GPOs, trusts, CA templates …) i generiše **Excel izveštaj**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (vizualizacija grafa)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) koristi teoriju grafova + Neo4j da otkrije skrivene relacije privilegija unutar lokalnog (on-prem) AD i Azure AD.

### Raspoređivanje (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Kolektori

* `SharpHound.exe` / `Invoke-BloodHound` – nativna ili PowerShell varijanta
* `AzureHound` – Azure AD enumeracija
* **SoaPy + BOFHound** – prikupljanje preko ADWS (pogledajte link na vrhu)

#### Uobičajeni SharpHound modovi
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Kolektori generišu JSON koji se učitava preko BloodHound GUI.

---

## Prioritizacija Kerberoasting-a uz BloodHound

Kontekst grafa je ključan da se izbegne bučan, neselektivni roasting. Lagan tok rada:

1. **Sakupite sve jednom** koristeći ADWS-kompatibilan kolektor (npr. RustHound-CE) tako da možete raditi offline i uvježbavati puteve bez ponovnog diranja DC-a:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Uvezi ZIP, označi kompromitovani principal kao owned**, zatim pokreni ugrađene upite kao što su *Kerberoastable Users* i *Shortest Paths to Domain Admins*. Ovo odmah ističe naloge koji nose SPN sa korisnim članstvima u grupama (Exchange, IT, tier0 servisni nalozi, itd.).
3. **Prioritise by blast radius** – fokusiraj se na SPN-ove koji kontrolišu deljenu infrastrukturu ili imaju admin rights, i proveri `pwdLastSet`, `lastLogon`, i dozvoljene tipove enkripcije pre nego što trošiš cracking cycles.
4. **Request only the tickets you care about**. Tools like NetExec can target selected `sAMAccountName`s so that each LDAP ROAST request has a clear justification:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, zatim odmah ponovo pošaljite upit BloodHound-u kako biste isplanirali post-exploitation sa novim privilegijama.

Ovakav pristup održava visok odnos signala i šuma, smanjuje detektabilan obim (bez masovnih SPN zahteva) i osigurava da svaki cracked ticket vodi ka smislenim koracima za eskalaciju privilegija.

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumeriše **Group Policy Objects** i ističe nepravilne konfiguracije.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) izvršava **proveru stanja** Active Directory-a i generiše HTML izveštaj sa ocenom rizika.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Извори

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}

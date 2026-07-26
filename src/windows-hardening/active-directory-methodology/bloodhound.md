# BloodHound i drugi alati za enumeraciju Active Directory-ja

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NAPOMENA: Ova stranica objedinjuje neke od najkorisnijih alata za **enumeraciju** i **vizuelizaciju** odnosa u Active Directory-ju. Za prikupljanje podataka preko stealthy kanala **Active Directory Web Services (ADWS)** pogledajte gorenavedenu referencu.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) je napredni **AD viewer & editor** koji omogućava:

* GUI pregledanje stabla direktorijuma
* Uređivanje atributa objekata i security descriptor-a
* Kreiranje i poređenje snapshot-a za offline analizu

### Brza upotreba

1. Pokrenite alat i povežite se na `dc01.corp.local` koristeći bilo koje domain credentials.
2. Kreirajte offline snapshot pomoću `File ➜ Create Snapshot`.
3. Uporedite dva snapshot-a pomoću `File ➜ Compare` da biste uočili promene permissions-a.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) izdvaja veliki skup artefakata iz domain-a (ACL-ove, GPO-ove, trusts, CA templates …) i generiše **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (vizuelizacija grafova)

[BloodHound](https://github.com/SpecterOps/BloodHound) koristi teoriju grafova za otkrivanje skrivenih odnosa privilegija unutar on-prem AD-a, Entra ID-a i svih dodatnih podataka o attack surface-u koje unesete putem OpenGraph-a.

### Instalacija (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Sakupljači

* `SharpHound.exe` / `Invoke-BloodHound` – native ili PowerShell varijanta
* `RustHound-CE` – cross-platform CE sakupljač za Linux, macOS i Windows
* `NetExec --bloodhound` – brzo LDAP-driven prikupljanje sa Linuxa
* `AzureHound` – enumeracija Entra ID-a
* **SoaPy + BOFHound** – ADWS prikupljanje (pogledajte link na vrhu)

> BloodHound CE `v8+` je promenio format izlaza sakupljača kada je OpenGraph uveden. Nakon nadogradnje sa legacy BloodHound-a ili starijih CE instalacija, ponovo pokrenite discovery pomoću aktuelnih sakupljača pre uvoza podataka.

#### Uobičajeni SharpHound režimi
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
The collectors generate JSON which is ingested via the BloodHound GUI.

#### SharpHound sa Windows hosta koji nije pridružen domenu

Ako vaš operator VM nije pridružen ciljnom domenu, usmerite DNS na DC, pokrenite **network-only** shell, proverite da možete da vidite `SYSVOL`/`NETLOGON` na DC-u, a zatim prikupljajte podatke iz udaljenog domena:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Ovo je korisno za privremene jump box uređaje ili operatorske radne stanice koje ne bi trebalo pridružiti domenu.

#### Prikupljanje podataka sa više platformi iz Linux/macOS-a
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` je dobar podrazumevani izbor kada želite CE-kompatibilan izlaz sa hosta koji nije Windows. `NetExec` je praktičan kada ga već koristite za LDAP validation ili spraying i želite brzi import grafa. Za skupove podataka koji nisu AD, BloodHound OpenGraph može da se proširi collectorima kao što je [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### ADPathFinder (prioritizacija putanja u OpenGraph-u)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) se koristi iznad BloodHound CE/OpenGraph-a kada je graph prevelik za ručno pivotiranje. Umesto da samo proverava da li jedan principal može da dođe do jedne mete, on izračunava najkraće putanje od velikog broja korisnika i računara sa niskim privilegijama do objekata visoke vrednosti, grupiše putanje koje ponovo koriste iste edges i prikazuje zajedničko usko grlo koje prvo treba sanirati.
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Sa uvezenim podacima iz `MSSQLHound` i `ConfigManBearPig`, jedan nalaz može da poveže [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) i [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md), umesto da ih ostavi kao odvojene tragove. Primer zajedničke putanje:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Pratite **efektivni bezbednosni kontekst** na svakoj ivici. Putanja postaje kritična za domen čim se jedna tranzicija izvrši kao privilegovani identitet domena, čak i ako je započela od običnog korisnika.
- Grupisani nalazi su idealni za **remedijaciju uskih grla**: uklanjanje jedne SQL impersonation dozvole, poverenja linked-servera, putanje za zloupotrebu certificate template-a ili SCCM dodele može istovremeno ukloniti mnoge najkraće putanje.
- Ponovo odredite prioritet „medium“ nalazima uz pomoć **konteksta grafa**. Onemogućeni SMB signing, izloženost WebClient-a, greške u delegaciji ili SQL serveri podložni NTLM-relay-u zaslužuju veći prioritet kada kompromitovani čvor ima dalje putanje do Domain Admins, Domain Controllers, CA ili SCCM site servera.
- Ako takođe imate `NTDS.dit` output i hashcat potfile, `--pwd` povezuje crackovane lozinke sa BloodHound svojstvima, pa možete brzo razlikovati običnu ponovnu upotrebu lozinki od crackovanih kredencijala na privilegovanim, Kerberoastable, AS-REP roastable ili za putanju relevantnim nalozima.

### Prikupljanje privilegija i prava prijavljivanja

Windows **token privileges** (npr. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) mogu zaobići DACL provere, pa njihovo mapiranje širom domena otkriva lokalne LPE ivice koje grafovi zasnovani samo na ACL-ovima ne prikazuju. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` i njihovi `SeDeny*` pandani) sprovodi LSA pre nego što token uopšte postoji, a zabrane imaju prednost, pa ona direktno određuju lateralno kretanje (RDP/SMB/scheduled task/service logon).

**Pokrenite collectore sa povišenim privilegijama** kada je moguće: UAC kreira filtrirani token za interaktivne administratore (putem `NtFilterToken`), uklanjajući osetljive privilegije i označavajući admin SID-ove kao deny-only. Ako privilegije nabrajate iz ne-elevated shell-a, privilegije visoke vrednosti neće biti vidljive i BloodHound neće uneti te ivice.

Sada postoje dve komplementarne SharpHound strategije za prikupljanje:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Nabrojte GPO-ove putem LDAP-a (`(objectCategory=groupPolicyContainer)`) i pročitajte `gPCFileSysPath` za svaki od njih.
2. Preuzmite `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` iz SYSVOL-a i parsirajte odeljak `[Privilege Rights]`, koji povezuje nazive privilegija/logon prava sa SID-ovima.
3. Rešite GPO linkove putem `gPLink` na OU-ovima/site-ovima/domenima, izlistajte računare u povezanim kontejnerima i dodelite ta prava tim mašinama.
4. Prednost: radi sa običnim korisnikom i tih je; nedostatak: vidi samo prava prosleđena putem GPO-a (lokalne izmene ostaju neotkrivene).

- **LSA RPC enumeration (noisy, accurate):**
- Iz konteksta sa local admin privilegijama na meti, otvorite Local Security Policy i pozovite `LsaEnumerateAccountsWithUserRight` za svaku privilegiju/logon pravo da biste putem RPC-a nabrojali dodeljene principe.
- Prednost: obuhvata prava postavljena lokalno ili izvan GPO-a; nedostatak: bučan mrežni saobraćaj i zahtev za administratorskim pravima na svakom hostu.

**Primer abuse putanje koju ove ivice mogu otkriti:** `CanRDP` ➜ host na kojem vaš korisnik takođe ima `SeBackupPrivilege` ➜ pokrenite elevated shell da biste izbegli filtrirane tokene ➜ upotrebite backup semantics za čitanje `SAM` i `SYSTEM` hive-ova uprkos restriktivnim DACL-ovima ➜ eksfiltrirajte ih i offline pokrenite `secretsdump.py` da biste povratili NT hash lokalnog Administrator naloga za lateralno kretanje/eskalaciju privilegija.

### Određivanje prioriteta za Kerberoasting uz BloodHound

Koristite kontekst grafa kako bi roasting ostao ciljan:

1. Prikupite podatke jednom pomoću ADWS-compatible collectora i radite offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importujte ZIP, označite kompromitovani principal kao owned i pokrenite ugrađene upite (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) da biste otkrili SPN naloge sa admin/infra pravima.
3. Odredite prioritet SPN-ovima prema blast radius-u; pregledajte `pwdLastSet`, `lastLogon` i dozvoljene tipove enkripcije pre crackovanja.
4. Zatražite samo odabrane tikete, crackujte ih offline, a zatim ponovo izvršite upit u BloodHound-u sa novim pristupom:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) nabraja **Group Policy Objects** i ističe pogrešne konfiguracije.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) obavlja **health-check** Active Directory-ja i generiše HTML izveštaj sa procenom rizika.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Reference

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [ADPathFinder: OpenGraph Attack Path Mapping in BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}

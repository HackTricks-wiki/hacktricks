# BloodHound i drugi alati za enumeraciju Active Directory-ja

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NAPOMENA: Ova stranica grupiše neke od najkorisnijih alatki za **enumeraciju** i **vizuelizaciju** odnosa u Active Directory-ju.  Za prikupljanje podataka putem stealthy kanala **Active Directory Web Services (ADWS)** pogledajte gornju referencu.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) je napredni **AD viewer i editor** koji omogućava:

* GUI pregledanje stabla direktorijuma
* Izmenu atributa objekata i security descriptor-a
* Kreiranje snapshot-a / poređenje za offline analizu

### Brza upotreba

1. Pokrenite alat i povežite se na `dc01.corp.local` pomoću bilo kojih domain kredencijala.
2. Kreirajte offline snapshot putem `File ➜ Create Snapshot`.
3. Uporedite dva snapshot-a pomoću `File ➜ Compare` da biste uočili promene dozvola.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) izvlači veliki skup artefakata iz domena (ACL-ove, GPO-ove, trust-ove, CA template-ove …) i generiše **Excel izveštaj**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (vizuelizacija grafa)

[BloodHound](https://github.com/SpecterOps/BloodHound) koristi teoriju grafova za otkrivanje skrivenih odnosa privilegija unutar on-prem AD-a, Entra ID-a i svih dodatnih podataka o attack-surface-u koje unesete putem OpenGraph-a.<sup>[[1]](#references)</sup>

### Implementacija (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Kolektori

* `SharpHound.exe` / `Invoke-BloodHound` – native ili PowerShell varijanta
* `RustHound-CE` – cross-platform CE kolektor za Linux, macOS i Windows
* `NetExec --bloodhound` – brza LDAP-driven kolekcija sa Linuxa
* `AzureHound` – enumeracija Entra ID-ja
* **SoaPy + BOFHound** – ADWS kolekcija (pogledajte link na vrhu)

> BloodHound CE `v8+` je promenio format izlaza kolektora kada je uveden OpenGraph. Nakon nadogradnje sa legacy BloodHound-a ili starijih CE instalacija, ponovo pokrenite discovery pomoću aktuelnih kolektora pre uvoza podataka.<sup>[[1]](#references)</sup>

#### Uobičajeni SharpHound režimi
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Kolektori generišu JSON koji se učitava putem BloodHound GUI-ja.

#### SharpHound sa Windows hosta koji nije pridružen domenu

Ako vaša operatorska VM nije pridružena ciljnom domenu, usmerite DNS na DC, pokrenite **network-only** shell, proverite da možete da pristupite `SYSVOL`/`NETLOGON` na DC-u, a zatim prikupljajte podatke iz udaljenog domena:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Ovo je korisno za privremene jump box mašine ili operatorske radne stanice koje ne bi trebalo da budu domain-joined.

#### Cross-platform prikupljanje sa Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` je dobar podrazumevani izbor kada želite CE-kompatibilan izlaz sa hosta koji nije Windows.<sup>[[2]](#references)</sup> `NetExec` je praktičan kada ga već koristite za LDAP validaciju ili spraying i želite brz uvoz grafa. Za skupove podataka koji nisu iz AD-a, BloodHound OpenGraph može da se proširi collector-ima kao što je [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).<sup>[[1]](#references)</sup>

### ADPathFinder (prioritizacija putanja u OpenGraph-u)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) radi iznad BloodHound CE/OpenGraph-a kada je graf prevelik za ručno pivotiranje. Umesto da samo utvrđuje da li jedan principal može da dođe do jednog targeta, računa najkraće putanje od velikog broja korisnika i računara sa niskim privilegijama do objekata visoke vrednosti, grupiše putanje koje koriste iste edges i prikazuje zajedničku choke point tačku koju prvo treba remedijirati.<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Sa uvezenim podacima `MSSQLHound` i `ConfigManBearPig`, jedan nalaz može povezati [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) i [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md), umesto da ih ostavi kao zasebne tragove.<sup>[[4]](#references)</sup> Primer zajedničke putanje:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Pratite **efektivni bezbednosni kontekst** na svakoj vezi. Putanja postaje kritična za domen čim se jedan prelaz izvrši kao privilegovani identitet domena, čak i ako je počela od običnog korisnika.
- Grupisana otkrića su idealna za **remedijaciju uskih grla**: uklanjanje jedne SQL impersonation dozvole, poverenja linked servera, putanje za zloupotrebu certificate template-a ili SCCM dodele može odjednom ukloniti mnoge najkraće putanje.
- Ponovo odredite prioritet "srednjim" nalazima uz **kontekst grafa**. Onemogućen SMB signing, izloženost WebClient-a, greške u delegaciji ili SQL serveri podložni NTLM-relay-u zaslužuju viši prioritet kada kompromitovani čvor ima dalje putanje do Domain Admins, Domain Controllers, CA ili SCCM site servera.
- Ako takođe imate izlaz `NTDS.dit` i hashcat potfile, `--pwd` povezuje crackovane lozinke sa BloodHound svojstvima, tako da možete brzo razlikovati običnu ponovnu upotrebu lozinki od crackovanih kredencijala na privilegovanim, Kerberoastable, AS-REP roastable ili za putanju relevantnim nalozima.

### Prikupljanje privilegija i prava prijavljivanja

Windows **token privilegije** (npr. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) mogu zaobići DACL provere, pa njihovo mapiranje širom domena otkriva lokalne LPE veze koje grafovi zasnovani samo na ACL-ovima ne prikazuju. **Prava prijavljivanja** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` i njihovi `SeDeny*` ekvivalenti) sprovodi LSA pre nego što token uopšte postoji, a zabrane imaju prednost, zbog čega značajno ograničavaju lateralno kretanje (RDP/SMB/scheduled task/service logon).<sup>[[3]](#references)</sup>

**Pokrenite collectore sa povišenim privilegijama** kada je to moguće: UAC kreira filtrirani token za interaktivne administratore (putem `NtFilterToken`), uklanjajući osetljive privilegije i označavajući administratorske SID-ove kao deny-only. Ako privilegije enumerišete iz ne-povišenog shell-a, privilegije visoke vrednosti biće nevidljive, pa BloodHound neće uneti te veze.<sup>[[3]](#references)</sup>

Dve komplementarne SharpHound strategije prikupljanja sada postoje:<sup>[[3]](#references)</sup>

- **GPO/SYSVOL parsiranje (neupadljivo, sa malim privilegijama):**
1. Enumerišite GPO-ove preko LDAP-a (`(objectCategory=groupPolicyContainer)`) i pročitajte svaki `gPCFileSysPath`.
2. Preuzmite `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` iz SYSVOL-a i parsirajte odeljak `[Privilege Rights]`, koji povezuje nazive privilegija/prava prijavljivanja sa SID-ovima.
3. Razrešite GPO veze pomoću `gPLink` na OU-ovima/site-ovima/domenima, izlistajte računare u povezanim kontejnerima i dodelite ta prava tim mašinama.
4. Prednost: radi sa običnim korisnikom i neupadljivo je; mana: prikazuje samo prava prosleđena putem GPO-a (lokalne izmene se propuštaju).

- **LSA RPC enumeracija (bučna, precizna):**
- Iz konteksta sa lokalnim admin pravima na ciljnom računaru, otvorite Local Security Policy i pozovite `LsaEnumerateAccountsWithUserRight` za svaku privilegiju/pravo prijavljivanja kako biste preko RPC-a enumerisali dodeljene principal-e.
- Prednost: obuhvata prava postavljena lokalno ili izvan GPO-a; mana: bučan mrežni saobraćaj i zahtev za administratorskim pravima na svakom hostu.

**Primer abuse path-a koji ove veze mogu otkriti:** `CanRDP` ➜ host na kojem vaš korisnik takođe ima `SeBackupPrivilege` ➜ pokrenite povišeni shell da biste izbegli filtrirane tokene ➜ koristite backup semantiku za čitanje `SAM` i `SYSTEM` hive-ova uprkos restriktivnim DACL-ovima ➜ eksfiltrirajte ih i pokrenite `secretsdump.py` offline da biste povratili NT hash lokalnog Administrator-a za lateralno kretanje/eskalaciju privilegija.<sup>[[3]](#references)</sup>

### Određivanje prioriteta Kerberoasting-a pomoću BloodHound-a

Koristite kontekst grafa kako bi roasting ostao ciljan:

1. Prikupite podatke jednom pomoću collectora kompatibilnog sa ADWS-om i radite offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Uvezite ZIP, označite kompromitovani principal kao owned i pokrenite ugrađene upite (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) da biste otkrili SPN naloge sa administratorskim/infra pravima.
3. Odredite prioritet SPN-ovima prema blast radius-u; proverite `pwdLastSet`, `lastLogon` i dozvoljene tipove enkripcije pre crackovanja.
4. Zatražite samo odabrane tickete, crackujte ih offline, a zatim ponovo upitajte BloodHound sa novim pristupom:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumeriše **Group Policy Objects** i ističe pogrešne konfiguracije.
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

- [1] [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: OpenGraph Attack Path Mapping in BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}

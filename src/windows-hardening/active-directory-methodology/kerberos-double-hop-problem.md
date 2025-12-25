# Problem Kerberos Double Hop

{{#include ../../banners/hacktricks-training.md}}


## Wprowadzenie

Problem "Kerberos Double Hop" pojawia się, gdy atakujący próbuje użyć **uwierzytelniania Kerberos na dwóch** **skokach**, na przykład używając **PowerShell**/**WinRM**.

Gdy **uwierzytelnienie** odbywa się przez **Kerberos**, **poświadczenia** **nie** są zapisywane w **pamięci.** W związku z tym, jeśli uruchomisz mimikatz, **nie znajdziesz poświadczeń** użytkownika na maszynie nawet jeśli uruchomione są jego procesy.

Dzieje się tak, ponieważ przy łączeniu przez Kerberos kroki są następujące:

1. User1 podaje poświadczenia, a **kontroler domeny** zwraca użytkownikowi Kerberos **TGT**.
2. User1 używa **TGT** aby zażądać **service ticket** do **połączenia** z Server1.
3. User1 **łączy się** z **Server1** i przekazuje **service ticket**.
4. **Server1** **nie** ma w pamięci **poświadczeń** User1 ani **TGT** User1. W związku z tym, gdy User1 z Server1 próbuje zalogować się na drugi serwer, **nie może się uwierzytelnić**.

### Unconstrained Delegation

Jeżeli na komputerze włączona jest **unconstrained delegation**, to nie wystąpi ten problem, ponieważ **Server** otrzyma **TGT** każdego użytkownika, który się do niego łączy. Co więcej, jeżeli używana jest unconstrained delegation, prawdopodobnie można z tego **skompro­mitować kontroler domeny**.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Innym sposobem obejścia tego problemu, który jest [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), jest **Credential Security Support Provider**. Z Microsoft:

> Uwierzytelnianie CredSSP deleguje poświadczenia użytkownika z komputera lokalnego do komputera zdalnego. Ta praktyka zwiększa ryzyko bezpieczeństwa operacji zdalnej. Jeśli komputer zdalny zostanie skompromitowany, po przekazaniu mu poświadczeń, poświadczenia mogą zostać użyte do przejęcia sesji sieciowej.

Zaleca się wyłączenie **CredSSP** na systemach produkcyjnych, w sieciach wrażliwych i podobnych środowiskach ze względu na obawy o bezpieczeństwo. Aby sprawdzić, czy **CredSSP** jest włączony, można uruchomić polecenie `Get-WSManCredSSP`. Polecenie to umożliwia **sprawdzenie statusu CredSSP** i może być wykonywane zdalnie, pod warunkiem że **WinRM** jest włączony.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** przechowuje TGT użytkownika na stacji roboczej źródłowej, jednocześnie pozwalając sesji RDP na żądanie nowych biletów usługi Kerberos na kolejnym hoście. Włącz **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** i wybierz **Require Remote Credential Guard**, następnie połącz się za pomocą `mstsc.exe /remoteGuard /v:server1` zamiast polegać na CredSSP.

Microsoft zepsuł RCG dla dostępu multi-hop w Windows 11 22H2+ aż do **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894). Zainstaluj poprawki na kliencie i serwerze pośredniczącym, w przeciwnym razie drugi skok zakończy się niepowodzeniem. Szybkie sprawdzenie hotfixa:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Po zainstalowaniu tych wersji skok RDP może zaspokoić downstream Kerberos challenges bez ujawniania sekretów możliwych do ponownego użycia na pierwszym serwerze.

## Obejścia

### Invoke Command

Aby rozwiązać problem double hop, przedstawiono metodę wykorzystującą zagnieżdżony `Invoke-Command`. Nie rozwiązuje ona problemu bezpośrednio, ale oferuje obejście bez konieczności specjalnych konfiguracji. Podejście pozwala wykonać polecenie (`hostname`) na drugim serwerze poprzez polecenie PowerShell uruchomione z początkowej maszyny atakującej lub przez wcześniej ustanowioną PS-Session z pierwszym serwerem. Oto jak to się robi:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatywnie zaleca się ustanowienie PS-Session z pierwszym serwerem i uruchomienie `Invoke-Command` używając `$cred` w celu scentralizowania zadań.

### Register PSSession Configuration

Rozwiązaniem pozwalającym obejść problem double hop jest użycie `Register-PSSessionConfiguration` razem z `Enter-PSSession`. Ta metoda wymaga innego podejścia niż `evil-winrm` i pozwala na sesję, która nie jest dotknięta ograniczeniem double hop.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Dla lokalnych administratorów na intermediary target, port forwarding umożliwia wysyłanie żądań do final server. Używając `netsh`, można dodać regułę dla port forwarding, wraz z regułą Windows firewall umożliwiającą dostęp do przekierowanego portu.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` może być użyty do przekazywania żądań WinRM, potencjalnie jako mniej wykrywalna opcja, jeśli monitorowanie PowerShell stanowi problem. Poniższe polecenie ilustruje jego użycie:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Zainstalowanie OpenSSH na pierwszym serwerze umożliwia obejście problemu double-hop, szczególnie przydatne w scenariuszach z jump box. Metoda ta wymaga instalacji przez CLI i konfiguracji OpenSSH for Windows. Po skonfigurowaniu Password Authentication, pozwala to serwerowi pośredniczącemu uzyskać TGT w imieniu użytkownika.

#### OpenSSH kroki instalacji

1. Pobierz i przenieś najnowszy plik zip wydania OpenSSH na docelowy serwer.
2. Rozpakuj i uruchom skrypt `Install-sshd.ps1`.
3. Dodaj regułę zapory, aby otworzyć port 22 i zweryfikuj, że usługi SSH działają.

Aby rozwiązać błędy `Connection reset`, może być konieczne zaktualizowanie uprawnień, aby nadać grupie everyone prawo odczytu i wykonywania w katalogu OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Zaawansowane)

**LSA Whisperer** (2024) udostępnia wywołanie pakietu `msv1_0!CacheLogon`, dzięki czemu możesz zaszczepić istniejące *network logon* znanym NT hashem zamiast tworzyć nową sesję przy użyciu `LogonUser`. Poprzez wstrzyknięcie hasha do sesji logowania, którą WinRM/PowerShell już otworzył na hop #1, ten host może uwierzytelniać się do hop #2 bez przechowywania jawnych poświadczeń lub generowania dodatkowych zdarzeń 4624.

1. Uzyskaj wykonanie kodu wewnątrz LSASS (albo wyłącz/wykorzystaj PPL, albo uruchom na laboracyjnej VM, którą kontrolujesz).
2. Wymień sesje logowania (np. `lsa.exe sessions`) i przechwyć LUID odpowiadający twojemu kontekstowi zdalnemu.
3. Wstępnie oblicz NT hash i przekaż go do `CacheLogon`, a następnie usuń go po zakończeniu.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Po cache seed uruchom ponownie `Invoke-Command`/`New-PSSession` z hop #1: LSASS ponownie użyje wstrzykniętego hasha, aby spełnić wyzwania Kerberos/NTLM dla drugiego hopu, co pozwoli ładnie ominąć ograniczenie double hop. Kosztem jest większa telemetria (wykonywanie kodu w LSASS), więc stosuj to w środowiskach o wysokim oporze, gdzie CredSSP/RCG są niedozwolone.

## Referencje

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}

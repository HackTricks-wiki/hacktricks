# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Wprowadzenie

Problem Kerberos „Double Hop” pojawia się, gdy attacker próbuje użyć **uwierzytelniania Kerberos przez dwa** **hopy**, na przykład przy użyciu **PowerShell**/**WinRM**.

Gdy **uwierzytelnianie** odbywa się przez **Kerberos**, **credentials** **nie są** przechowywane w **pamięci.** Dlatego po uruchomieniu mimikatz **nie znajdziesz credentials** użytkownika na maszynie, nawet jeśli uruchamia on procesy.

Dzieje się tak, ponieważ podczas łączenia się z użyciem Kerberos wykonywane są następujące kroki:<sup>[[1]](#references)</sup>

1. User1 przekazuje credentials, a **domain controller** zwraca User1 bilet Kerberos **TGT**.
2. User1 używa **TGT**, aby zażądać **service ticket** do **połączenia** z Server1.
3. User1 **łączy się** z **Server1** i przekazuje **service ticket**.
4. **Server1** **nie ma** zapisanych w pamięci **credentials** User1 ani jego **TGT**. Dlatego gdy User1 z Server1 próbuje zalogować się do drugiego serwera, **nie jest w stanie się uwierzytelnić**.

### Unconstrained Delegation

Jeśli na komputerze włączono **unconstrained delegation**, to się nie wydarzy, ponieważ **Server** **otrzyma** **TGT** każdego użytkownika, który uzyskuje do niego dostęp. Co więcej, jeśli używane jest unconstrained delegation, prawdopodobnie możesz **przejąć Domain Controller** z jego pomocą.\
[**Więcej informacji na stronie unconstrained delegation**](unconstrained-delegation.md).

### CredSSP

Innym sposobem uniknięcia tego problemu, który jest [**wyjątkowo niebezpieczny**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), jest **Credential Security Support Provider**. Według Microsoft:

> Uwierzytelnianie CredSSP przekazuje credentials użytkownika z komputera lokalnego do komputera zdalnego. Praktyka ta zwiększa ryzyko bezpieczeństwa zdalnej operacji. Jeśli komputer zdalny zostanie przejęty, credentials przekazane do tego komputera mogą zostać użyte do kontrolowania sesji sieciowej.

Zdecydowanie zaleca się wyłączenie **CredSSP** w systemach produkcyjnych, wrażliwych sieciach i podobnych środowiskach ze względów bezpieczeństwa. Aby sprawdzić, czy **CredSSP** jest włączony, można uruchomić polecenie `Get-WSManCredSSP`. Polecenie to umożliwia **sprawdzenie statusu CredSSP** i może być wykonane zdalnie, pod warunkiem że **WinRM** jest włączony.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** przechowuje TGT użytkownika na źródłowej stacji roboczej, jednocześnie umożliwiając sesji RDP żądanie nowych biletów usług Kerberos w następnym hopie. Włącz **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** i wybierz **Require Remote Credential Guard**, a następnie połącz się za pomocą `mstsc.exe /remoteGuard /v:server1` zamiast przechodzić awaryjnie na CredSSP.

Microsoft uniemożliwił działanie RCG w dostępie multi-hop w Windows 11 22H2+ do czasu wydania **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894). Zainstaluj poprawki na kliencie i serwerze pośredniczącym, w przeciwnym razie drugi hop nadal będzie kończył się niepowodzeniem.<sup>[[5]](#references)</sup> Szybkie sprawdzenie hotfixa:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Przy zainstalowanych tych kompilacjach skok RDP może obsługiwać dalsze żądania Kerberos bez ujawniania możliwych do ponownego użycia sekretów na pierwszym serwerze.

## Obejścia

### Invoke Command

Aby rozwiązać problem podwójnego skoku, przedstawiono metodę wykorzystującą zagnieżdżone `Invoke-Command`. Nie rozwiązuje ona problemu bezpośrednio, ale oferuje obejście niewymagające specjalnej konfiguracji. Podejście to umożliwia wykonanie polecenia (`hostname`) na dodatkowym serwerze za pośrednictwem polecenia PowerShell uruchomionego z początkowej maszyny atakującej lub za pośrednictwem wcześniej ustanowionej sesji PS-Session z pierwszym serwerem. Oto jak to zrobić:<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatywnie sugeruje się ustanowienie PS-Session z pierwszym serwerem i uruchomienie `Invoke-Command` przy użyciu `$cred` w celu centralizacji zadań.

### Rejestracja konfiguracji PSSession

Rozwiązanie umożliwiające obejście problemu double hop polega na użyciu `Register-PSSessionConfiguration` wraz z `Enter-PSSession`. Ta metoda wymaga innego podejścia niż `evil-winrm` i pozwala na utworzenie sesji, której nie dotyczy ograniczenie double hop.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Dla lokalnych administratorów na pośrednim celu port forwarding umożliwia wysyłanie żądań do finalnego serwera. Za pomocą `netsh` można dodać regułę port forwarding, a także regułę zapory systemu Windows zezwalającą na przekazywanie ruchu przez ten port.<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` może być używany do przekazywania żądań WinRM, potencjalnie jako mniej wykrywalna opcja, jeśli monitorowanie PowerShell stanowi problem.<sup>[[2]](#references)</sup> Poniższe polecenie pokazuje jego użycie:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Instalacja OpenSSH na pierwszym serwerze umożliwia obejście problemu double-hop, szczególnie przydatne w scenariuszach jump box. Ta metoda wymaga instalacji z poziomu CLI oraz skonfigurowania OpenSSH dla Windows. Po skonfigurowaniu opcji Password Authentication serwer pośredniczący może uzyskać TGT w imieniu użytkownika.<sup>[[2]](#references)</sup>

#### Kroki instalacji OpenSSH

1. Pobierz najnowsze wydanie OpenSSH w formacie zip i przenieś je na docelowy serwer.
2. Rozpakuj archiwum i uruchom skrypt `Install-sshd.ps1`.
3. Dodaj regułę zapory sieciowej otwierającą port 22 i sprawdź, czy usługi SSH są uruchomione.

Aby rozwiązać błędy `Connection reset`, może być konieczna aktualizacja uprawnień w celu zezwolenia wszystkim na odczyt i wykonywanie w katalogu OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Zaawansowane)

**LSA Whisperer** (2024) udostępnia wywołanie pakietu `msv1_0!CacheLogon`, dzięki czemu można zasilić istniejące *logowanie sieciowe* znanym hashem NT zamiast tworzyć nową sesję za pomocą `LogonUser`. Wstrzykując hash do sesji logowania, którą WinRM/PowerShell już otworzył na hop #1, ten host może uwierzytelnić się do hop #2 bez przechowywania jawnych poświadczeń ani generowania dodatkowych zdarzeń 4624.<sup>[[6]](#references)</sup>

1. Uzyskaj możliwość wykonywania kodu wewnątrz LSASS (wyłączając/wykorzystując PPL albo uruchamiając kod na kontrolowanej przez siebie laboratoryjnej maszynie wirtualnej).
2. Wylicz sesje logowania (np. `lsa.exe sessions`) i przechwyć LUID odpowiadający Twojemu kontekstowi zdalnego dostępu.
3. Wstępnie oblicz hash NT i przekaż go do `CacheLogon`, a po zakończeniu wyczyść go.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Po zainicjowaniu cache'u ponownie uruchom `Invoke-Command`/`New-PSSession` z hop #1: LSASS ponownie użyje wstrzykniętego hasha, aby obsłużyć wyzwania Kerberos/NTLM dla drugiego hopa, skutecznie omijając ograniczenie double hop. Kompromisem jest intensywniejsza telemetria (wykonywanie kodu w LSASS), dlatego zachowaj tę metodę dla środowisk z dużymi ograniczeniami, w których CredSSP/RCG są niedozwolone.

## Referencje

- [1] [Zrozumienie Kerberos Double Hop - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Obejścia Kerberos Double-Hop](https://posts.slayerlabs.com/double-hop/)
- [3] [Inne rozwiązanie problemu wielokrotnego zdalnego użycia PowerShell](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Rozwiązanie problemu wielokrotnego użycia PowerShell bez korzystania z CredSSP](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [9 kwietnia 2024 — KB5036896 (kompilacja systemu operacyjnego 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}

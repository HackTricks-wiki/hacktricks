# Problem podwójnego skoku Kerberos

{{#include ../../banners/hacktricks-training.md}}


## Wprowadzenie

Problem "podwójnego skoku" Kerberos pojawia się, gdy atakujący próbuje użyć **uwierzytelniania Kerberos przez dwa** **skoki**, na przykład używając **PowerShell**/**WinRM**.

Gdy **uwierzytelnienie** odbywa się przez **Kerberos**, **poświadczenia** **nie są** buforowane w **pamięci.** Dlatego, jeśli uruchomisz mimikatz, **nie znajdziesz poświadczeń** użytkownika na maszynie, nawet jeśli uruchamia on procesy.

Dzieje się tak, ponieważ podczas łączenia z Kerberos wykonuje się następujące kroki:

1. Użytkownik1 podaje poświadczenia, a **kontroler domeny** zwraca Kerberos **TGT** do Użytkownika1.
2. Użytkownik1 używa **TGT** do zażądania **biletu usługi** w celu **połączenia** z Serwerem1.
3. Użytkownik1 **łączy się** z **Serwerem1** i podaje **bilet usługi**.
4. **Serwer1** **nie ma** **poświadczeń** Użytkownika1 buforowanych ani **TGT** Użytkownika1. Dlatego, gdy Użytkownik1 z Serwera1 próbuje zalogować się do drugiego serwera, **nie może się uwierzytelnić**.

### Nieograniczona delegacja

Jeśli **nieograniczona delegacja** jest włączona w PC, to nie wystąpi, ponieważ **Serwer** **otrzyma** **TGT** każdego użytkownika, który uzyskuje do niego dostęp. Co więcej, jeśli używana jest nieograniczona delegacja, prawdopodobnie możesz **skompromentować kontroler domeny** z tego.\
[**Więcej informacji na stronie dotyczącej nieograniczonej delegacji**](unconstrained-delegation.md).

### CredSSP

Innym sposobem na uniknięcie tego problemu, który jest [**wyraźnie niebezpieczny**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), jest **Dostawca wsparcia bezpieczeństwa poświadczeń**. Z Microsoftu:

> Uwierzytelnianie CredSSP deleguje poświadczenia użytkownika z lokalnego komputera do zdalnego komputera. Ta praktyka zwiększa ryzyko bezpieczeństwa zdalnej operacji. Jeśli zdalny komputer zostanie skompromitowany, gdy poświadczenia są do niego przekazywane, poświadczenia mogą być używane do kontrolowania sesji sieciowej.

Zaleca się, aby **CredSSP** był wyłączony w systemach produkcyjnych, wrażliwych sieciach i podobnych środowiskach z powodu obaw o bezpieczeństwo. Aby sprawdzić, czy **CredSSP** jest włączony, można uruchomić polecenie `Get-WSManCredSSP`. To polecenie pozwala na **sprawdzenie statusu CredSSP** i może być nawet wykonywane zdalnie, pod warunkiem, że **WinRM** jest włączony.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Workarounds

### Invoke Command

Aby rozwiązać problem podwójnego skoku, przedstawiona jest metoda polegająca na zagnieżdżonym `Invoke-Command`. Nie rozwiązuje to problemu bezpośrednio, ale oferuje obejście bez potrzeby specjalnych konfiguracji. Podejście to pozwala na wykonanie polecenia (`hostname`) na drugim serwerze za pomocą polecenia PowerShell wykonanego z początkowej maszyny atakującej lub przez wcześniej ustanowioną sesję PS z pierwszym serwerem. Oto jak to zrobić:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatywnie, sugeruje się nawiązanie sesji PS z pierwszym serwerem i uruchomienie `Invoke-Command` z użyciem `$cred` w celu centralizacji zadań.

### Rejestracja konfiguracji PSSession

Rozwiązanie do obejścia problemu podwójnego skoku polega na użyciu `Register-PSSessionConfiguration` z `Enter-PSSession`. Ta metoda wymaga innego podejścia niż `evil-winrm` i pozwala na sesję, która nie cierpi z powodu ograniczenia podwójnego skoku.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Dla lokalnych administratorów na pośrednim celu, przekierowanie portów pozwala na wysyłanie żądań do docelowego serwera. Używając `netsh`, można dodać regułę dla przekierowania portów, obok reguły zapory systemu Windows, aby zezwolić na przekierowany port.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` może być używany do przekazywania żądań WinRM, potencjalnie jako mniej wykrywalna opcja, jeśli monitorowanie PowerShell jest problemem. Poniższe polecenie demonstruje jego użycie:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Zainstalowanie OpenSSH na pierwszym serwerze umożliwia obejście problemu podwójnego skoku, szczególnie przydatne w scenariuszach z jump box. Ta metoda wymaga instalacji i konfiguracji OpenSSH dla Windows za pomocą CLI. Gdy jest skonfigurowana do uwierzytelniania hasłem, pozwala to pośredniemu serwerowi uzyskać TGT w imieniu użytkownika.

#### Kroki instalacji OpenSSH

1. Pobierz i przenieś najnowszą wersję OpenSSH w formacie zip na docelowy serwer.
2. Rozpakuj i uruchom skrypt `Install-sshd.ps1`.
3. Dodaj regułę zapory, aby otworzyć port 22 i zweryfikuj, czy usługi SSH działają.

Aby rozwiązać błędy `Connection reset`, może być konieczne zaktualizowanie uprawnień, aby umożliwić wszystkim dostęp do odczytu i wykonania w katalogu OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Odniesienia

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)


{{#include ../../banners/hacktricks-training.md}}

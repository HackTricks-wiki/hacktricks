# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}


## Jak to działa

**Smbexec** to narzędzie używane do zdalnego wykonywania poleceń na systemach Windows, podobne do **Psexec**, ale unika umieszczania jakichkolwiek złośliwych plików na docelowym systemie.

### Kluczowe punkty dotyczące **SMBExec**

- Działa poprzez tworzenie tymczasowej usługi (na przykład "BTOBTO") na docelowej maszynie, aby wykonywać polecenia za pomocą cmd.exe (%COMSPEC%), bez zrzucania jakichkolwiek binariów.
- Pomimo swojego dyskretnego podejścia, generuje dzienniki zdarzeń dla każdego wykonanego polecenia, oferując formę nieinteraktywnego "shella".
- Polecenie do połączenia za pomocą **Smbexec** wygląda tak:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Wykonywanie poleceń bez binariów

- **Smbexec** umożliwia bezpośrednie wykonywanie poleceń za pomocą binPaths usługi, eliminując potrzebę fizycznych binariów na docelowym systemie.
- Metoda ta jest przydatna do wykonywania jednorazowych poleceń na docelowym systemie Windows. Na przykład, połączenie jej z modułem `web_delivery` Metasploit pozwala na wykonanie ładunku odwrotnego Meterpreter skierowanego na PowerShell.
- Tworząc zdalną usługę na maszynie atakującego z binPath ustawionym na uruchomienie podanego polecenia przez cmd.exe, możliwe jest pomyślne wykonanie ładunku, osiągając callback i wykonanie ładunku z nasłuchiwaczem Metasploit, nawet jeśli wystąpią błędy odpowiedzi usługi.

### Przykład poleceń

Tworzenie i uruchamianie usługi można zrealizować za pomocą następujących poleceń:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Aby uzyskać więcej szczegółów, sprawdź [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Odniesienia

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


{{#include ../../banners/hacktricks-training.md}}

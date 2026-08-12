# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Jak to działa

Service Control Manager Remote Protocol (SCMR) to protokół oparty na RPC, służący do konfigurowania i kontrolowania usług Windows na zdalnym komputerze. Przy wystarczających uprawnieniach operator może utworzyć lub ponownie skonfigurować usługę, której ścieżka binarna zawiera polecenie, a następnie uruchomić tę usługę, aby zdalnie wykonać polecenie.<sup>[[1]](#references)</sup>

Jeśli nie określono konta usługi, `CreateService` używa `LocalSystem`, które ma rozległe uprawnienia lokalne. Wyjaśnia to duży wpływ udanego SCM execution. Nie wyłącza ono automatycznie UAC ani Microsoft Defender: wywołujący nadal potrzebuje zdalnych uprawnień SCM, a mechanizmy kontroli endpointów mogą sprawdzać usługę lub payload albo je blokować.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Narzędzia

**SharpMove** obsługuje uwierzytelnione zdalne wykonanie za pośrednictwem SCM oraz kilku innych mechanizmów Windows. Poniższy przykład wybiera jego akcję SCM, tworzy usługę o nazwie `WindowsDebug` i wskazuje na payload znajdujący się już na zdalnym hoście.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - omówienie zdalnego protokołu Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - konto LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - funkcja `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}

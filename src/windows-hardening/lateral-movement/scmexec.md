# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Jak to działa

Service Control Manager Remote Protocol (SCMR) to protokół oparty na RPC, służący do konfigurowania i kontrolowania usług Windows na komputerze zdalnym. Przy wystarczających uprawnieniach operator może utworzyć lub ponownie skonfigurować usługę, której ścieżka binarna zawiera polecenie, a następnie uruchomić tę usługę, aby zdalnie wykonać polecenie.<sup>[[1]](#references)</sup>

## Narzędzia

**SharpMove** obsługuje uwierzytelnione zdalne wykonywanie poleceń za pośrednictwem SCM oraz kilku innych mechanizmów Windows. Poniższy przykład wybiera jego akcję SCM, tworzy usługę o nazwie `WindowsDebug` i wskazuje na payload, który znajduje się już na zdalnym hoście.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Omówienie zdalnego protokołu Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}

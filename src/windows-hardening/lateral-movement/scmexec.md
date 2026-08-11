# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Jinsi Inavyofanya Kazi

Service Control Manager Remote Protocol (SCMR) ni protocol inayotegemea RPC kwa ajili ya kusanidi na kudhibiti huduma za Windows kwenye kompyuta ya mbali. Kwa ruhusa za kutosha, operator anaweza kuunda au kusanidi upya huduma ambayo binary path yake ina command, kisha kuanzisha huduma hiyo ili kutekeleza command kwa mbali.<sup>[[1]](#references)</sup>

## Zana

**SharpMove** inasaidia remote execution iliyothibitishwa kupitia SCM na mechanisms nyingine kadhaa za Windows. Mfano ufuatao huchagua SCM action yake, huunda huduma yenye jina `WindowsDebug`, na kuielekeza kwenye payload ambayo tayari ipo kwenye remote host.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Muhtasari wa Itifaki ya Service Control Manager ya Mbali](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}

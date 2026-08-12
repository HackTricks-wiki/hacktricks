# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Jinsi Inavyofanya Kazi

Service Control Manager Remote Protocol (SCMR) ni protocol ya RPC-based ya kusanidi na kudhibiti Windows services kwenye kompyuta ya mbali. Kwa permissions za kutosha, operator anaweza kuunda au kusanidi upya service ambayo binary path yake ina command, kisha kuanzisha service hiyo ili kutekeleza command hiyo kwa mbali.<sup>[[1]](#references)</sup>

Ikiwa service account haijaainishwa, `CreateService` hutumia `LocalSystem`, ambayo ina local privileges nyingi. Hii inaeleza impact kubwa ya SCM execution iliyofanikiwa. Hailazimishi kuzima UAC au Microsoft Defender: caller bado anahitaji remote SCM rights, na endpoint controls zinaweza kukagua au kuzuia service au payload.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Zana

**SharpMove** inasaidia authenticated remote execution kupitia SCM na Windows mechanisms nyingine kadhaa. Mfano ufuatao huchagua SCM action yake, huunda service inayoitwa `WindowsDebug`, na kuielekeza kwenye payload ambayo tayari ipo kwenye remote host.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Muhtasari wa Service Control Manager Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - akaunti ya LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - function ya `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}

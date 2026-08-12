# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Kako funkcioniše

Service Control Manager Remote Protocol (SCMR) je protokol zasnovan na RPC-u za konfigurisanje i kontrolisanje Windows services na udaljenom računaru. Uz dovoljne dozvole, operator može da kreira ili ponovo konfiguriše service čija binarna putanja sadrži komandu, a zatim da pokrene taj service kako bi se komanda izvršila na udaljenom računaru.<sup>[[1]](#references)</sup>

Ako nalog service-a nije naveden, `CreateService` koristi `LocalSystem`, koji ima široke lokalne privilegije. Ovo objašnjava veliki uticaj uspešnog SCM izvršavanja. Ono samo po sebi ne onemogućava UAC ili Microsoft Defender: pozivalac i dalje mora da ima udaljena SCM prava, a endpoint kontrole mogu da pregledaju ili blokiraju service ili payload.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Alati

**SharpMove** podržava autentifikovano udaljeno izvršavanje putem SCM-a i nekoliko drugih Windows mehanizama. Sledeći primer bira njegovu SCM akciju, kreira service pod nazivom `WindowsDebug` i usmerava ga na payload koji je već prisutan na udaljenom hostu.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - pregled Service Control Manager Remote Protocol protokola](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - LocalSystem nalog](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - funkcija `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}

# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Hoe dit werk

The Service Control Manager Remote Protocol (SCMR) is 'n RPC-gebaseerde protokol vir die konfigurasie en beheer van Windows-dienste op 'n afgeleë rekenaar. Met voldoende toestemmings kan 'n operateur 'n diens skep of herkonfigureer waarvan die binêre pad 'n command bevat, en dan daardie diens start om die command op afstand uit te voer.<sup>[[1]](#references)</sup>

As geen diensrekening gespesifiseer word nie, gebruik `CreateService` `LocalSystem`, wat uitgebreide plaaslike voorregte het. Dit verduidelik die groot impak van suksesvolle SCM-execution. Dit deaktiveer nie inherent UAC of Microsoft Defender nie: die caller benodig steeds remote SCM-regte, en endpoint-kontroles kan die diens of payload inspekteer of blokkeer.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Gereedskap

**SharpMove** ondersteun geverifieerde remote execution deur SCM en verskeie ander Windows-meganismes. Die volgende voorbeeld kies sy SCM-aksie, skep 'n diens genaamd `WindowsDebug`, en wys dit na 'n payload wat reeds op die remote host teenwoordig is.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Oorsig van die Service Control Manager Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - LocalSystem-rekening](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - `CreateService`-funksie](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}

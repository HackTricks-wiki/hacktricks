# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Hoe dit werk

Die Service Control Manager Remote Protocol (SCMR) is ’n RPC-gebaseerde protokol vir die konfigurasie en beheer van Windows-dienste op ’n afgeleë rekenaar. Met voldoende toestemmings kan ’n operateur ’n diens skep of herkonfigureer waarvan die binêre pad ’n opdrag bevat, en dan daardie diens begin om die opdrag op afstand uit te voer.<sup>[[1]](#references)</sup>

## Nutsgoed

**SharpMove** ondersteun geverifieerde afgeleë uitvoering deur SCM en verskeie ander Windows-meganismes. Die volgende voorbeeld kies sy SCM-aksie, skep ’n diens genaamd `WindowsDebug` en wys dit na ’n payload wat reeds op die afgeleë gasheer beskikbaar is.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Oorsig van die Service Control Manager Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}

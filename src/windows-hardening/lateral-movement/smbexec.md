# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}


## Hoe Dit Werk

**Smbexec** is 'n hulpmiddel wat gebruik word vir afstandsopdraguitvoering op Windows-stelsels, soortgelyk aan **Psexec**, maar dit vermy om enige kwaadwillige lêers op die teikenstelsel te plaas.

### Sleutelpunte oor **SMBExec**

- Dit werk deur 'n tydelike diens (byvoorbeeld, "BTOBTO") op die teikenmasjien te skep om opdragte via cmd.exe (%COMSPEC%) uit te voer, sonder om enige binêre lêers te laat val.
- Ten spyte van sy stil benadering, genereer dit gebeurtenislogboeke vir elke uitgevoerde opdrag, wat 'n vorm van nie-interaktiewe "shell" bied.
- Die opdrag om te verbind met **Smbexec** lyk soos volg:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Uitvoering van Opdragte Sonder Binaries

- **Smbexec** stel direkte opdrag uitvoering deur diens binPaths in, wat die behoefte aan fisiese binaries op die teiken uitskakel.
- Hierdie metode is nuttig vir die uitvoering van eenmalige opdragte op 'n Windows-teiken. Byvoorbeeld, om dit te kombineer met Metasploit se `web_delivery` module stel dit in staat om 'n PowerShell-gefokusde omgekeerde Meterpreter payload uit te voer.
- Deur 'n afstanddiens op die aanvaller se masjien te skep met binPath ingestel om die verskafde opdrag deur cmd.exe uit te voer, is dit moontlik om die payload suksesvol uit te voer, wat 'n terugroep en payload uitvoering met die Metasploit luisteraar bereik, selfs al gebeur diens respons foute.

### Opdragte Voorbeeld

Die skep en begin van die diens kan bereik word met die volgende opdragte:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Vir verdere besonderhede, kyk [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Verwysings

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


{{#include ../../banners/hacktricks-training.md}}

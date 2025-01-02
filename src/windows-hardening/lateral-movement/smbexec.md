# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Kry 'n hacker se perspektief op jou webtoepassings, netwerk en wolk**

**Vind en rapporteer kritieke, exploiteerbare kwesbaarhede met werklike besigheidsimpak.** Gebruik ons 20+ pasgemaakte gereedskap om die aanvaloppervlak te karteer, sekuriteitskwessies te vind wat jou toelaat om bevoegdhede te verhoog, en gebruik geoutomatiseerde eksploit om noodsaaklike bewyse te versamel, wat jou harde werk in oortuigende verslae omskep.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Hoe dit Werk

**Smbexec** is 'n hulpmiddel wat gebruik word vir afstandsopdraguitvoering op Windows-stelsels, soortgelyk aan **Psexec**, maar dit vermy om enige kwaadwillige lêers op die teikenstelsel te plaas.

### Sleutelpunte oor **SMBExec**

- Dit werk deur 'n tydelike diens (byvoorbeeld, "BTOBTO") op die teikenmasjien te skep om opdragte via cmd.exe (%COMSPEC%) uit te voer, sonder om enige binêre lêers te laat val.
- Ten spyte van sy stil benadering, genereer dit gebeurtenislogs vir elke opdrag wat uitgevoer word, wat 'n vorm van nie-interaktiewe "shell" bied.
- Die opdrag om te verbind met **Smbexec** lyk soos volg:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Uitvoering van Opdragte Sonder Binaries

- **Smbexec** stel direkte opdrag uitvoering deur diens binPaths in, wat die behoefte aan fisiese binaries op die teiken uitskakel.
- Hierdie metode is nuttig om eenmalige opdragte op 'n Windows-teiken uit te voer. Byvoorbeeld, om dit te kombineer met Metasploit se `web_delivery` module stel jou in staat om 'n PowerShell-gefokusde omgekeerde Meterpreter payload uit te voer.
- Deur 'n afstanddiens op die aanvaller se masjien te skep met binPath ingestel om die verskafde opdrag deur cmd.exe uit te voer, is dit moontlik om die payload suksesvol uit te voer, wat callback en payload uitvoering met die Metasploit listener bereik, selfs al gebeur diens responsfoute.

### Opdragte Voorbeeld

Die skep en begin van die diens kan met die volgende opdragte gedoen word:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Vir verdere besonderhede, kyk na [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Verwysings

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Kry 'n hacker se perspektief op jou webtoepassings, netwerk en wolk**

**Vind en rapporteer kritieke, exploiteerbare kwesbaarhede met werklike besigheidsimpak.** Gebruik ons 20+ pasgemaakte gereedskap om die aanvaloppervlak te karteer, sekuriteitskwessies te vind wat jou toelaat om bevoegdhede te verhoog, en gebruik geoutomatiseerde eksploit om noodsaaklike bewyse te versamel, wat jou harde werk in oortuigende verslae omskakel.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{{#include ../../banners/hacktricks-training.md}}

